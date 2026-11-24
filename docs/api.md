# 管理 API 与配置应用契约

本文是**面板/CLI 作者**的契约源。运维流程见[运维基线](operations.md)，配置字段见[构建与运行](usage.md)。

管理 API 只监听回环地址，必须携带 `Authorization: Bearer <token>`。它**不**承诺兼容原版 3x-ui / s-ui / Clash 面板，也不提供在线用户增删改。

## 1. 认证、方法与状态码

| 项 | 约定 |
|---|---|
| 监听 | 只允许回环（`api.listen` 必须是回环地址，配置校验强制） |
| 认证 | 每个请求都要 `Authorization: Bearer <token>`；缺失或错误一律 `401`、**空响应体** |
| 缓存 | 所有响应都带 `Cache-Control: no-store` |
| 连接 | 一个请求一条连接，处理完即关闭；不支持 keep-alive、HTTP/2、请求体 |
| 期限 | 请求头 5 秒，管理面并发上限 32，不占用代理业务额度 |

`200` 表示**读取成功**，不代表部署成功。判定部署是否生效必须看 `/status` 的 `last_apply.result`。

## 2. 端点一览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 存活探针，固定 `{"status":"ok"}`。**不表示新配置已生效** |
| GET | `/status` | 配置应用状态（本文第 3 节） |
| GET | `/stats` | 全局计数快照 |
| GET | `/stats/users` | 按入口+用户的计数与限额 |
| POST | `/stats/users/reset` | 清零计数；`?inbound=` / `?user=` 缩小范围，**省略即清全部** |
| POST | `/stats/users/limits` | 设置准入配额/到期（见第 5 节） |
| GET | `/metrics` | Prometheus 文本；非 GET 返回 `405` |
| GET | `/connections` | 活动 TCP 连接列表 |
| DELETE | `/connections/{id}` | 关闭单条连接 |
| DELETE | `/connections` | 关闭全部连接 |

`/metrics` 与 `/status` 是只读端点，非 GET 返回 `405` + `Allow: GET`。

## 3. `GET /status`

### 响应示例

该进程已成功应用过两代配置；第 4 次重载改为另一版，新配置绑定失败，旧配置已恢复。

```json
{
  "api_version": 1,
  "instance_id": "7cd7e7ec795adf1a33ba4ee9a1673e68",
  "active_revision": 2,
  "active_deployment_id": "bb8fb088975d49778b335fad474c54a2",
  "last_apply": {
    "attempt": 4,
    "requested_deployment_id": "42a97cb72863426186629581fac76a84",
    "mode": "rebind",
    "result": "rolled_back",
    "error_code": "candidate_bind_failed"
  }
}
```

### 字段

| 字段 | 含义 |
|---|---|
| `api_version` | 本契约版本，当前固定 `1`。与配置文件的 `version` 无关 |
| `instance_id` | 进程级随机 32 位十六进制。进程重启后变化；热替换、重建、回退都不变 |
| `active_revision` | 进程内**已确认生效**的代数。首次启动成功为 `1` |
| `active_deployment_id` | 当前生效配置的 `deployment_id`；未配置时为 `null` |
| `last_apply` | 最近一次重载尝试；启动后到第一次重载前为 `null` |

`last_apply` 字段：

| 字段 | 含义 |
|---|---|
| `attempt` | 进程内第几次重载尝试，从 `1` 起。**信号可能被合并，它不是发信号次数** |
| `requested_deployment_id` | 本次候选配置的标签。候选 JSON 解析失败或读不到时为 `null` |
| `mode` | `validate` / `tls` / `metadata` / `hot` / `rebind` |
| `result` | `pending` / `applied` / `rejected` / `rolled_back` / `noop` |
| `error_code` | 成功与处理中为 `null`，否则为下表稳定码 |

### `mode`

| 值 | 含义 |
|---|---|
| `validate` | 候选配置读不到或未通过校验，未尝试应用 |
| `tls` | 业务配置完全相同，只轮换证书 |
| `metadata` | 只有 `deployment_id` 变化，业务配置未变 |
| `hot` | 零停机热替换（路由、DNS、嗅探、出站） |
| `rebind` | 停止旧实例后重新绑定 |

### `result`

| 值 | 含义 | 推进 `active_revision` |
|---|---|---|
| `pending` | 仍在处理 | 否 |
| `applied` | 已确认生效 | **看 `mode`**（见下） |
| `rejected` | 配置被拒绝，旧实例继续运行 | 否 |
| `rolled_back` | **新配置没生效**，旧配置已恢复服务 | 否 |
| `noop` | 无需动作（例如没有可轮换的 TLS 入口） | 否 |

**`rolled_back` 是部署失败，不是成功。** `200` + `rolled_back` 的组合必须按失败处理。

哪些 `mode` 会推进 `active_revision`：

| `mode` | 推进 | 原因 |
|---|---|---|
| `hot` / `metadata` / `rebind` + `applied` | 是 | 运行配置换成新的一版 |
| `tls` + `applied` | **否** | 只重载证书，配置没换 |
| `validate` / `noop` / `rejected` / `rolled_back` | 否 | 配置没有生效 |

所以 `tls / applied` 之后 `active_revision` 与 `active_deployment_id` **保持不变**——
正常续证不能让面板以为部署身份丢了。

### `error_code`

| 值 | 触发 |
|---|---|
| `config_unreadable` | 配置文件读不到 |
| `config_invalid` | JSON 无效，或未通过 `check` 校验 |
| `deployment_id_reused` | 复用了当前非空标签但改了业务内容 |
| `hot_apply_failed` | 热替换本身报错 |
| `tls_reload_failed` | 证书轮换报错 |
| `candidate_bind_failed` | 新配置绑定失败，已回退旧配置 |

`rejected` 不附带底层错误原文、配置内容、文件路径或密钥；排障看服务端日志。

### 503：状态不可用

嵌入式库调用（`Server::bind` 直接 `run`，未附加重载协调器）没有可信的版本信息，已认证请求返回：

```json
{"error_code":"apply_status_unavailable"}
```

HTTP 状态 `503`。它表示**无法回答**，不是「还没应用过配置」。CLI `dubhe run` 始终可用：
Unix 有 SIGHUP 重载协调器；非 Unix 没有重载路径，但启动状态仍然可信
（`active_revision: 1`、`last_apply: null`）。

## 4. 状态转换

| 触发 | `mode/result/error_code` | `active_*` |
|---|---|---|
| 文件读不到 | `validate / rejected / config_unreadable` | 保留 |
| JSON 无效或校验失败 | `validate / rejected / config_invalid` | 保留 |
| 复用当前标签但改业务 | `validate / rejected / deployment_id_reused` | 保留 |
| 证书轮换成功 | `tls / applied / null` | **不推进** |
| 没有可轮换入口 | `tls / noop / null` | 不推进 |
| 证书轮换报错 | `tls / rejected / tls_reload_failed` | 保留 |
| 只换标签 | `metadata / applied / null` | 推进，记新标签 |
| 热替换成功 | `hot / applied / null` | 推进 |
| 热替换报错 | `hot / rejected / hot_apply_failed` | 保留 |
| 需要重建 | 先 `rebind / pending` | 保留 |
| 重建成功 | `rebind / applied / null`（新监听就绪后提交） | 推进 |
| 重建失败，旧配置恢复 | `rebind / rolled_back / candidate_bind_failed` | 保留 |
| 新旧配置都绑定失败 | 进程退出，API 通常已消失；日志含稳定码 `rollback_failed` | — |

**`pending` 期间不能假设旧监听在线。** 重绑会先停旧实例。`applied` 直到新监听 `ready` 才提交，所以看到 `applied` 时端口已可用。

**连续重载有屏障**：重建或回退后，内核会先等新监听 `ready` 提交终态，再接受下一次 `SIGHUP`。等待期间仍响应退出信号。所以不会出现「B 已经在服务、状态却仍称 A 生效」。

## 5. 其他端点的副作用

### `POST /stats/users/limits`

`?quota_bytes=` / `?expires_at_ms=`（unix 毫秒）。

- **准入控制**：配额用尽或到期后拒绝该账户的**新连接**，不断开已建立的连接。
- 显式给出 `inbound` 与 `user` 时会**先建条目**；只给其一则只更新已存在的匹配条目。
- `{"updated":0}` 表示**没有匹配条目**，限额没有保存。
- 配额、到期、计数都**不持久化**，重启归零。面板必须在启动/重载后重新下发。

### `POST /stats/users/reset`

不带过滤条件会清**全部**用户计数。`since_ms` 移到当前时刻。

清零与并发累加之间有极小竞态（`store` 与 `fetch_add` 之间的字节可能丢失），与 Xray `StatsService` 语义一致：重置是运维动作，不追求逐字节精确。

### `/connections`

条目包含目标地址，因此这个 token 等价于「可读取用户访问了哪里」。**只应放在面板后端，不要下发到浏览器。**

## 6. 面板确认算法

面板部署一次配置的推荐顺序：

1. 面板侧串行化：同一配置文件只允许**一项部署在途**。
2. 生成新的 `deployment_id`（32 位小写十六进制随机值），写入候选配置。
3. 先跑 `dubhe check -c <candidate>`；失败就不要提交。
4. 读 `GET /status`，记下基线 `instance_id` 与 `last_apply.attempt`。
5. 同目录临时文件 + `rename` 原子替换配置文件。
6. 发 `SIGHUP`。
7. 限时轮询 `GET /status`，直到 `attempt > 基线` 且 `result != pending`。
8. 确认成功的**全部条件**：
   - `instance_id` 与基线相同（进程没换）；
   - `result == "applied"`；
   - `active_deployment_id == 本次新 ID`。
9. 用**真实业务连接**做冒烟（新用户/新路由是否按预期工作）。

超过期限没有确认成功，按「未确认」处理。失败示例：

| 观察 | 判定 |
|---|---|
| `instance_id` 变了 | 进程重启过，这次提交的确认丢失 |
| `result == "rejected"` | 提交被拒，旧配置仍在跑 |
| `result == "rolled_back"` | **部署失败**，旧配置已恢复 |
| `active_deployment_id` 不等于新 ID | 被另一次提交覆盖，或没轮到本次 |
| 一直 `pending` / API 不可达 | 未确认，见下 |

`/healthz` 返回 200 **不能**用来补判成功。

### 重绑期间的管理口

改 `api.listen` 或 token 时，管理口会先消失再出现。适配器应按已知的新旧两组地址与凭据限时确认。本次配置关闭 API 时，不能用同一 API 自证成功，必须显式选择带外业务验收。

### 回退之后

`rolled_back` 只恢复旧**配置**，不恢复旧会话、连接计数器或进程内限额。此时磁盘上很可能仍是那份坏候选，**必须恢复上次良好文件**，不要靠再发一次 SIGHUP 修复。

## 7. 与上游对照

| | Xray | sing-box | dubhe |
|---|---|---|---|
| 传输 | 仅 gRPC | Clash REST/WS + gRPC | 最小 HTTP/1.1 |
| 认证 | 无内置（靠监听与路由） | `secret` → Bearer，可为空 | 必须 Bearer |
| 在线用户增删 | `HandlerService.AlterInbound` | 无（Clash API 只管 selector） | **无**（本期不做） |
| 路由热改 | `RoutingService` | `PATCH /configs` 仅 mode | 改文件 + SIGHUP |
| 配置生效确认 | 以 gRPC 调用返回为准 | `PUT /configs` 是空实现 | **`GET /status`** |
| 主动触发重载 | 无（重启进程） | 无 | 无（本期不做） |

dubhe 刻意不模拟 Clash REST：sing-box 自己也在向 `service.api` 迁移，而 s-ui 是通过**进程内**调用管理内核的，模拟 REST 也接不上。

## 8. 未实现（明确边界）

- `GET /config/schema`：表单校验应随 release 发布静态 JSON Schema，不需要访问运行中的特权管理口；跨字段约束以 `dubhe check` 为准。
- `GET /config/effective`：面板已持有期望配置，用 `active_deployment_id` 确认即可；递归脱敏容易随协议新增字段而失效。
- `POST /reload`：会让持 Bearer 的程序触发全实例排空与重绑，新增攻击面而没有解决新需求。
- 在线用户热更新：现有指纹包含整个 `inbounds`，用户变更必然重建。要做需要先定义持久来源、协议覆盖、旧会话处置与重启一致性。
