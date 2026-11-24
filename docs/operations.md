# 生产运维基线

本文是 v1 服务端部署的最小运维基线，不把“能启动”当成生产验收。当前仍未完成外部安全审计、原生 Linux x86_64 全量/release、容量与长稳测试；完整门禁见 [生产可用性评估](production-readiness.md)，威胁与部署约束见 [威胁模型](threat-model.md)。

## v1 支持面

- 角色：仅服务端协议入口；不包含 TUN、redirect/tproxy、客户端订阅或规则集。
- 平台：Linux x86_64 为主，Linux ARM64 为次；macOS ARM64 仅开发验证。Windows 不在 v1 范围。
- 部署：systemd、非 root、文件证书、外部 ACME（certbot/lego）或手工续期。
- 协议：只承诺已有官方互通和负向测试的组合。实验项和“已实现待集中验收”项不得写入生产承诺。
- 管理面：仅回环监听、Bearer token、Prometheus `/metrics`；不兼容完整面板 API。

## 安装

创建专用用户和目录，不要把 token、私钥放进 world-readable 文件：

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin dubhe
sudo install -d -o root -g dubhe -m 0750 /etc/dubhe
sudo install -o root -g root -m 0755 dubhe /usr/local/bin/dubhe
sudo install -o root -g dubhe -m 0640 config.json /etc/dubhe/config.json
```

如果使用 `api.token_file`，文件必须由运行用户持有且权限为 `0600`；启动时权限不安全会直接失败：

```sh
printf '%s\n' 'replace-with-a-random-visible-ascii-token' \
  | sudo tee /etc/dubhe/api.token >/dev/null
sudo chown dubhe:dubhe /etc/dubhe/api.token
sudo chmod 0600 /etc/dubhe/api.token
```

证书和私钥同样应只允许运行用户读取；Unix 下 TLS 私钥若允许组或其他用户读取，
启动/检查会失败（要求 0600）。不要通过命令行参数传递 token 或私钥。

安装 systemd unit：

```sh
sudo install -m 0644 packaging/systemd/dubhe.service \
  /etc/systemd/system/dubhe.service
sudo systemctl daemon-reload
sudo systemctl enable --now dubhe
```

unit 默认清空 capability、禁止新特权、只允许 AF_INET/AF_INET6/AF_UNIX。若必须绑定低于 1024 的端口，只添加 `CAP_NET_BIND_SERVICE`，不要放开整个 capability 集合。`ProtectSystem=strict`、`ProtectHome=true`、`PrivateTmp=true` 和 `SystemCallFilter=@system-service` 需在目标内核/发行版上先做启动冒烟；若受限环境导致运行失败，应逐项定位，不要整体关闭。

## 配置与检查

```sh
/usr/local/bin/dubhe check -c /etc/dubhe/config.json
/usr/local/bin/dubhe run -c /etc/dubhe/config.json
```

`check` 不绑定端口，但会读取证书、密钥和 `api.token_file`；权限错误会失败。配置变更后先运行 `check`，再决定 `reload` 或 `restart`。

## 管理面

配置示例：

```json
{
  "api": {
    "listen": "127.0.0.1:9090",
    "token_file": "/etc/dubhe/api.token"
  }
}
```

```sh
curl -fsS -H "Authorization: Bearer $(cat /etc/dubhe/api.token)" \
  http://127.0.0.1:9090/healthz
curl -fsS -H "Authorization: Bearer $(cat /etc/dubhe/api.token)" \
  http://127.0.0.1:9090/metrics
```

`/metrics` 是 Prometheus 文本格式，当前包含进程存活、构建版本、连接/TCP/UDP/gRPC/XHTTP 活动量、上下行业务字节、丢弃和拒绝计数。它不包含目标地址、凭据或业务载荷。`/stats` 为 JSON，`/connections` 和 `DELETE /connections/{id}` 用于活动 TCP 连接查看与关闭；管理 API 只支持回环监听。

### 管理 API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 存活探针，固定返回 `{"status":"ok"}`；**不表示新配置已生效** |
| GET | `/status` | 配置应用状态：`active_revision` / `active_deployment_id` / `last_apply` |
| GET | `/stats` | 全局计数快照（JSON） |
| GET | `/stats/users` | 按入口+用户计数，含 `quota_bytes` / `expires_at_ms` |
| POST | `/stats/users/reset` | 清零计数；`?inbound=` / `?user=` 缩小范围，**省略即清全部** |
| POST | `/stats/users/limits` | 设置准入配额/到期；显式给 `inbound` + `user` 时会先建条目 |
| GET | `/metrics` | Prometheus 文本；只读，其他方法返回 405 |
| GET | `/connections` | 活动 TCP 连接列表（含目标元数据） |
| DELETE | `/connections/{id}` | 关闭单条连接 |
| DELETE | `/connections` | 关闭全部连接 |

响应语义：

- `{"updated":0}` 表示**没有匹配的计数条目**。只给 `user=` 或只给 `inbound=`
  时不会新建条目；两项都给才会新建。
- 配额与到期是**准入控制**：只拒绝新连接，不断开已建立连接；计数与限额都不
  持久化，重启后归零。
- `/connections` 的条目有目标地址；这个 token 因此等同于「可读取用户访问了
  哪里」。只应放在面板后端，不要下发到浏览器。

### 一次变更的标准顺序

面板或运维改配置时按这个顺序，避免「发出信号就当成功」：

1. 面板侧串行化：同一个配置文件只允许一项变更在途。
2. 生成新的 `deployment_id` 写入候选配置（可选，但面板强烈建议；手写配置可省略）。
3. `dubhe check -c <candidate>`；失败就不要替换。
4. 读一次 `GET /status`，记下基线 `instance_id` 与 `last_apply.attempt`。
5. 同目录临时文件 + `rename` 原子替换，保证读者不会看到半份 JSON。
6. 发 `SIGHUP`。
7. 限时轮询 `GET /status` 到终态，按 `api.md` 第 6 节判定。
8. 用真实业务连接做冒烟（新用户/新路由是否按预期工作）。

回退之后磁盘上很可能仍是那份坏候选，**必须恢复上次良好文件**；不要靠再发一次
`SIGHUP` 修复。

### 重载契约（面板接入必须知道）

`SIGHUP` 有三条不同路径，结果不能都显示成「已生效」：

| 情况 | 行为 | 已建立连接 |
|---|---|---|
| 配置内容与磁盘一致 | 只做证书轮换（`reload_tls`） | 保持原证书 |
| `inbounds`/`limits`/`api`/`nw3_egress`/`reverse_bridges` **未变** | 原子替换路由、DNS、嗅探、出站（`reload_hot`） | 继续用握手时的旧快照 |
| 上述任一变化、存在 UDP 监听或反向 Portal | 停止旧实例后重新绑定（`reload_stop` → `bind`） | **全部断开** |

- 校验失败（`check` 或解析失败）时**旧实例继续运行**，新配置不生效。
- 重新绑定时若新配置绑定失败，会尝试重新绑定旧配置；面板不能假设「返回成功」
  就等于「新配置在跑」。
- 用 `GET /status` 确认生效：`last_apply.result == "applied"`、`instance_id` 未变、
  `active_deployment_id` 等于本次提交的标签。`rolled_back` 是**部署失败**。
  完整字段、错误码与面板确认算法见[管理 API 与配置应用契约](api.md)。
- `/healthz` 的 200 **不能**用来补判成功，它只说明进程在。

## 日志

默认 JSON 日志写 stderr，由 journald 收集和轮转：

```sh
journalctl -u dubhe -f
```

默认不记录密码、摘要、私钥、业务载荷和目标地址。不要为了排障把完整配置或 `.test-artifacts` 内容贴进工单；这些目录可能包含凭据和临时私钥。

## 证书续期

v1 推荐外部 ACME 客户端，不把 ACME 账户或 DNS API 凭据放进本进程：

```sh
# certbot 示例：续期成功后触发 reload
certbot renew --quiet --deploy-hook 'systemctl reload dubhe'
```

当前 SIGHUP/reload 只覆盖部分 TCP/TLS 入口的证书轮换。QUIC、mKCP、REALITY 和 ShadowTLS 的证书变更仍需完整重启；如果这些入口承载生产流量，应在维护窗口执行：

```sh
sudo systemctl restart dubhe
```

`reload` 失败时旧实例继续运行；`restart` 会中断现有连接。上线前需按业务可接受的停机窗口确定策略。

## 启停与故障

- `systemctl stop` 发送 SIGTERM；进程先停止新连接，等待 `shutdown_timeout_ms`，再取消活跃流并释放 UDP 套接字。
- `systemctl kill -s HUP` 或 `systemctl reload` 重新读取配置；配置校验失败时保持旧实例。
- `Restart=on-failure` 会在异常退出后重启；连续失败受 `StartLimitBurst` 限制，避免无限崩溃循环。
- 不要用 `kill -9` 作为日常停止方式；它会跳过排空和资源释放。

## 升级与回滚

1. 保留上一版二进制和配置；配置 schema 当前为 `version: 1`。
2. 新二进制先 `check`，再在维护窗口 `systemctl restart`。
3. 观察 `/healthz`、`/metrics`、journald 错误和连接建立情况。
4. 失败时恢复上一版二进制和配置，再重启；不要只回滚二进制而保留不兼容的新配置。

签名、SBOM、可复现构建和正式发布流程见 [生产可用性评估](production-readiness.md)。

## 发布前检查

逐项核对成「有证据」或「未完成」。**未完成项不得对外写成已通过**；状态以
[兼容矩阵](compatibility-matrix.md) 与 [生产可用性评估](production-readiness.md) 为准，
本文只列操作步骤，不重复状态结论。

已具备：

- `tools/ci.sh` 与 `tools/supply-chain.sh` 可在本地运行；CI 覆盖 Linux x86_64、
  Linux ARM64、macOS ARM64 三个 runner 的 fmt、clippy `-D warnings`、全量测试与 release 构建。
- `cargo deny check` 的 advisories / bans / licenses / sources 全部通过，`deny.toml` 无 ignore。
- macOS ARM64 双目录可复现构建记录，见[可复现构建](reproducibility.md)。
- CycloneDX SBOM 已本地生成，见 [SBOM 记录](sbom.md)；**未签名、未随 release 上传**。

未完成（不得写成已通过）：

- 原生 Linux x86_64 的正式 release 产物：CI 已配置该平台，但仓库内没有对应产物。
- Windows 构建与运行：不在 v1 范围。
- systemd 非 root 启动、`kill -9` 自动重启、SIGTERM 排空、`/metrics` 抓取的实机演练：
  没有记录。
- 证书续期与配置回滚演练：没有记录。
- 正式发布流程（tag 触发、多平台产物上传、校验和公告）：尚未建立，见
  [开源项目补齐计划](oss-checklist.md)。

发布包中不得包含 `.test-artifacts/`、私钥、token 或业务日志。

