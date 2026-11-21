# 官方客户端真实互通验证

记录日期：2026-11-04。平台：macOS ARM64。

本页保留第一阶段Trojan构建的历史证据。当前Shadowsocks批次已在新构建重新执行24项Shadowsocks及旧九项Trojan/VLESS/XUDP，完整33项、87场景全部通过，见[本批验收](shadowsocks-acceptance.md)；不覆盖或扩大下列历史结论。

## 当前结论

三个固定官方客户端均已完成真实互通测试：**3 项通过、0 失败**，每项分别包含正常 TCP/UDP、错误密码拒绝与不受信任证书拒绝三个场景。下载、官方 API SHA-256 校验及版本验证见 [reference-clients.md](reference-clients.md)。这些结果只证明本报告指定的 Trojan over TCP+TLS 有效认证转发组合，不证明 fallback、包装、复用或其他协议。

| 官方客户端 | 固定版本 | 下载校验 / version | TCP 互通 | UDP 互通 | 错误密码 TCP / UDP 拒绝 | 正常证书校验及错误信任拒绝 |
| --- | --- | --- | --- | --- | --- | --- |
| Mihomo | v1.19.33 | 通过 | 通过 | 通过 | 通过 / 通过 | 通过；错误信任仅测试 TCP |
| sing-box | v1.14.4 | 通过 | 通过 | 通过 | 通过 / 通过 | 通过；错误信任仅测试 TCP |
| Xray | v26.10.31 | 通过 | 通过 | 通过 | 通过 / 通过 | 通过；错误信任仅测试 TCP |

最近一次完整运行耗时 6.65 秒，命令退出码 0。每个正常场景包含 2 个 UDP 目标、3 个数据报，服务端单向业务计数各为 67 字节；错误密码及错误信任场景的上下行计数均为 0，目标未收到流量。产物中的错误信任 `udp_rejected:false` 表示该场景没有执行 UDP 断言，不是 UDP 证书验证被绕过。

### 执行与审批历史

1. 准备子会话的代理运行最初被审批器拒绝；当时只有版本命令范围，未绕过限制。该阶段的 `--no-run` 成功不计互通成功。
2. 主会话随后通过问题工具收集到官方客户端受控运行及回环测试的直接选择，在该阶段实际运行测试并保存下列日志和产物。
3. 收尾时尝试再次运行三个下载客户端，被当前审批器拒绝；没有重试绕过，也没有执行该轮客户端测试。收尾改为核对已有日志、结果和构建摘要，并运行不启动下载客户端的普通回归。

当前结论依据第 2 步的已完成运行，不把第 3 步记为成功。最新 macOS release 摘要与此前构建一致；此后只新增/修正回归测试和文档，生产代码没有变化。完整构建标识见 [acceptance.md](acceptance.md)。

## 已实现的测试

测试文件为 [tests/reference_clients.rs](../tests/reference_clients.rs)，三个入口均带 `#[ignore = "需要已校验官方客户端"]`：

- `mihomo_trojan_tcp_udp_authentication`
- `sing_box_trojan_tcp_udp_authentication`
- `xray_trojan_tcp_udp_authentication`

测试从环境变量 `REFERENCE_CLIENTS_MANIFEST` 指定的路径读取客户端；未指定时使用项目 `.test-artifacts/reference-clients.json`。执行前要求对应条目为 `ready`、官方摘要已校验、版本与平台匹配，并重新计算二进制 SHA-256 与 manifest 比较。缺失 manifest、缺失条目、错误摘要、配置错误和启动失败都会使显式运行的测试失败，不会通过提前返回伪装成功。

每个客户端依次运行三个独立场景，服务器均使用本项目 `Server`，仅启用本机 Trojan TLS 入口，默认路由为 `direct`。

| 场景 | 测试行为与成功判据 |
| --- | --- |
| 正常凭据和信任 | 通过参考客户端本地 SOCKS5 CONNECT 执行二进制 TCP 回显；通过 UDP ASSOCIATE 在同一关联中发送三个数据报，覆盖两个本机 UDP 目标并再次返回第一个目标；响应地址、来源和载荷必须一致，项目服务端必须记录双向转发字节。 |
| 错误密码 | 保持证书和服务器不变，仅修改参考客户端 Trojan 密码。TCP 必须收到 SOCKS 拒绝或明确关闭；UDP 不得到达目标或回送客户端。服务端拒绝计数必须增长，转发字节必须保持零，目标不得收到连接或数据。 |
| 不受信任证书 | 使用正确密码，但信任另一张独立生成的证书。TCP 必须被拒绝或关闭，服务端必须观察到拒绝，目标不得收到连接。该控制用于确认信任配置没有退化为跳过校验。 |

TCP/UDP 数据由独立 SOCKS 测试端经官方客户端编码为 Trojan，与本项目服务端互通；测试未调用生产 Trojan 编解码器来构造这些请求。使用已有 `tests/common/mod.rs` 的证书、回显和服务器辅助代码，没有修改该文件。

## 证书验证设置

证书由 `rcgen` 生成，SAN 为 `localhost`，连接地址为 `127.0.0.1`，TLS 服务名固定为 `localhost`。每个场景保存独立的信任证书文件，均保持证书验证开启；不修改系统信任库。

| 客户端 | 固定版本配置 |
| --- | --- |
| Mihomo | 根配置 `tls.custom-certifactes` 中嵌入测试证书 PEM，Trojan 出站 `sni: localhost`、`skip-cert-verify: false`。环境变量关闭系统和内嵌信任根，仅加载测试指定证书。注意 `custom-certifactes` 是上游该版本的实际字段拼写。 |
| sing-box | Trojan 出站 `tls.enabled: true`、`tls.server_name: localhost`、`tls.insecure: false`，使用 `tls.certificate_path` 指定测试信任证书。 |
| Xray | Trojan TLS 出站 `serverName: localhost`、`allowInsecure: false`、`disableSystemRoot: true`，`certificates` 使用测试 `certificateFile`、`usage: verify` 和 `oneTimeLoading: true`。 |

字段依据固定版本官方源码核查：

- [Mihomo v1.19.33 config/config.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/config/config.go)、[component/ca/config.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/component/ca/config.go)、[adapter/outbound/trojan.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/trojan.go)。
- [sing-box v1.14.4 option/tls.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/tls.go)。
- [Xray v26.10.31 infra/conf/transport_security.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/transport_security.go)。

## 运行与保留产物

获得相应运行授权后，执行命令如下。

```sh
cd $PROJECT_ROOT
cargo test --locked --test reference_clients -- --ignored --nocapture
```

仅编译、不执行客户端的检查命令如下。

```sh
cargo test --locked --test reference_clients --no-run
```

每个测试会创建 `.test-artifacts/interop-<client>-<random>/` 并打印该路径。场景子目录保存 `client.json`、`server.json`、`client.log`、测试证书和测试私钥；汇总状态保存在 `result.json`。配置、证书、私钥和日志文件按 `0600` 创建，顶层产物目录由 tempfile 创建；测试不向普通输出打印密码或配置。产物保留供失败定位，包含仅用于本机测试的凭据，不应作为公共日志发布。

每个参考客户端只绑定 `127.0.0.1` 的动态高端口，只向本项目回环 TLS 入口转发。工作目录独立且在启动时为空，环境不继承系统代理变量。Mihomo 禁用 DNS、TUN、NTP、嗅探、进程查找、地理数据自动更新和外部 UI，不使用 GEOIP/GEOSITE 或远程 provider，地理数据备用 URL 也固定到回环地址。

客户端由 RAII 进程守卫管理，正常返回、错误、panic 和总测试超时均执行 kill/wait；正常场景结束后还检查原 TCP/UDP 监听端口可重新绑定。每个测试总时限为 60 秒；该互通测试不安装服务、不修改系统代理，也不操作 Docker。

最近一次完整运行产物（均已核对 `result.json` 的 `status:passed`）：

- Mihomo：`.test-artifacts/interop-mihomo-Cnimeo/`
- sing-box：`.test-artifacts/interop-sing-box-jtbhdi/`
- Xray：`.test-artifacts/interop-xray-H7OyVa/`

该轮命令日志为会话任务 `buw59d8te.output`，明确记录 3 passed / 0 failed。运行的是本项目 0.1.0 的测试 profile 库服务端（不是启动 release 子进程），Rust/Cargo 1.95.0、macOS ARM64、固定 Cargo.lock。相同生产输入的 release 构建与源码摘要见 [验收记录](acceptance.md)。没有 Git commit 可引用，不能把这些摘要描述成可复现构建证明。

| 官方客户端 | 解压后二进制 SHA-256 |
|---|---|
| Mihomo v1.19.33 | `f3e8ae41397c08cbf900ce1f7c8a168285d29954e9bca5d84d69a2b2561adfe9` |
| sing-box v1.14.4 | `6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2` |
| Xray v26.10.31 | `9ddc3b0d912a8539285918e4fead4b60bbc449acdb639450ba068bc7efb983b7` |

来源、归档摘要、tag commit 见 [参考客户端基线](reference-clients.md)。归档与官方 API digest 一致不等于发布者签名验证，`signature_verified` 仍为 false。后续任何版本、构建或协议组合变化都必须重新验证，不能直接继承本表结论。
