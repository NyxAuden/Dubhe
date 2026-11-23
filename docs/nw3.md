# NW3（Nowhere Protocol v3）Portal 入站、出口选择与 Egress 出口

状态：**Portal 入站、Portal 的 `out` 出口选择（`direct`/`egress`/SOCKS5）与 Egress 出口服务均已实现，已通过全目标编译检查**；已用 vendored Nowhere 上游 `VectorClient`/`Vector`（不是本仓库自建客户端）完成 5 项本机回环：Portal `out=direct` 的 TCP/UDP、Portal `out=egress` + Egress 的 TCP/UDP，以及 `nw3-vector` 出站经 Portal 的 TCP。已用官方 Nowhere v3.3.0（macos/aarch64）完成 Vector→本内核 Portal、`nw3-vector`→官方 Portal 的 TCP/UDP 双向互通，以及官方 Egress 注册到本内核 Portal、本内核 `nw3_egress` 注册到官方 Portal 的 TCP/UDP 交叉组合（morph=1、真实证书 pin、UDP 使用显式 `/udp:PORT` QUIC 载体）；未执行官方 Anywhere 客户端、Morph 认证负例、无可用 Egress 的超时失败、三平台与 release 验证。本页描述的线格式来自固定 Nowhere 3.3.0 源码，不宣称超出该源码的行为。

## 来源与许可

NW3 线格式、TLS/QUIC 承载、认证、Morph 伪装与转发逻辑**直接复用** [Nowhere](https://github.com/NodePassProject/Nowhere) 3.3.0 的源码（`vendor/nowhere`，GPL-3.0-only），本仓库因此整体采用 GPL-3.0-only。本内核只新增配置到 Portal/Egress URL 的适配层（`src/transport/nw3.rs`）与运行生命周期接入。

复用时对 `vendor/nowhere` 做了最小本地适配（含 VectorClient TCP/UDP 公共 API），见该目录 `KERNEL-ADAPTER.md`；既有生命周期适配包括：

- `Cargo.toml`：`quinn` 固定为 `0.11.11`、`quinn-proto` 固定为 `0.11.16`，与本仓库既有版本一致。
- `src/portal/runtime/mod.rs`：新增 `Portal::run_with_stop(CancellationToken)`，允许由本内核的停止令牌驱动，不安装进程信号处理。原有 `run()` 行为不变。
- `src/egress/runtime.rs`：新增 `Egress::run_with_stop(CancellationToken)`，与 Portal 相同的嵌入方式；原有 `run()` 行为不变。

## 配置

```json
{
  "type": "nw3",
  "tag": "nw3-in",
  "listen": "0.0.0.0:2000",
  "key": "0123456789abcdef0123456789abcdef",
  "morph": true,
  "out": "direct",
  "certificate": "/etc/ssl/fullchain.pem",
  "private_key": "/etc/ssl/private/key.pem"
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `tag` | 是 | 入站标识，用于统计与地址查询 |
| `listen` | 是 | 同一端口同时承载 TCP（TLS 1.3）与 QUIC；端口不得为 0 |
| `key` | 是 | 共享密钥，必须恰好 32 个**小写**十六进制字符 |
| `morph` | 否 | 默认 `true`；Morph 线格式伪装，必须与客户端一致 |
| `out` | 否 | 默认 `direct`：Portal 自行连接目标；`egress`：交给注册到本 Portal 的 Egress；`USER:PASS@HOST:PORT` 或 `HOST:PORT`：SOCKS5 上游 |
| `dial` / `dial4` / `dial6` | 否 | 直连出站的源地址绑定（`auto` 或具体 IP），三者互斥；`out=egress` 时禁止 |
| `rate` / `etar` | 否 | 源→目标 / 目标→源限速（Mbps），0 或省略为不限速 |
| `certificate` / `private_key` | 否 | 必须成对配置；配置后使用真实证书（`tls=2`） |

配置校验在 `Config::validate` 中完成：密钥长度与字符集、端口非 0、证书与私钥成对、`dial`/`dial4`/`dial6` 互斥、`out=egress` 与 `dial` 系列互斥，以及 SOCKS5 `out` 的基本结构（凭据、主机、端口与 `%XX` 转义）。端点细节（IPv4/IPv6 字面量、`auto` 等）与证书本身在 `Server::check`/`bind` 时由 Nowhere 的解析器与本内核的 PEM 加载器各自校验。

## NW3 Egress 出口服务

Egress 是 Nowhere 的另一类独立服务：**没有本地监听**，主动连接远端 Portal、以共享密钥注册为可用出口，然后把 Portal 分配的目标连接直接拨出。它不是入站，因此放在配置顶层：

```json
{
  "nw3_egress": {
    "tag": "nw3-exit",
    "endpoint": "portal.example.com:443",
    "key": "0123456789abcdef0123456789abcdef",
    "sni": "portal.example.com",
    "morph": true
  }
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `tag` | 是 | 日志与服务标识 |
| `endpoint` | 是 | `host:port`（QUIC）、`host/tcp:port`（TLS）或 `host/udp:port`（QUIC）；禁止 `?`、`#`、`@`、空白 |
| `key` | 是 | 与 Portal 一致的 32 个小写十六进制字符 |
| `sni` | 否 | TLS 校验名；`none` 关闭 SNI |
| `pin` | 否 | 证书 SHA-256 指纹；`none` 交回系统 CA |
| `morph` | 否 | 默认 `true`，必须与 Portal 一致 |
| `dial` / `dial4` / `dial6` | 否 | 源地址绑定，三者互斥 |
| `rate` / `etar` | 否 | 源→目标 / 目标→源限速（Mbps），0 或省略为不限速 |

URL 映射为 `egress://KEY@ENDPOINT?morph=..&sni=..&pin=..&dial..&rate=..&etar=..`；端点语法与选项最终由 Nowhere 的 `Egress::new` 与客户端配置解析器校验。`Server::check` 会实际构造一次 `Egress`，因此端点/密钥/证书选项错误在检查阶段即可发现。

Egress 与 Portal 一样是独立子系统：**不经过本内核 route/outbounds，也不计入本内核统计与限额**
> **认证失败的可观测性**：NW3 的共享密钥认证在 `vendor/nowhere` 内部完成，
> 不做逐次 `ctx.stats.reject()` 打点，因此 `/metrics` 的
> `dubhe_rejected_total` **不包含 NW3 的认证失败**。
>
> **2026-11-24 变更**：`out` 为 `direct`（默认）时，内核会注入一个
> **仅供本进程使用**的 loopback SOCKS5 入口（tag `__nw3_internal`），并把
> Portal 的 `out` 指向它。因此 NW3 的业务流量现在会经过本内核的
> `route` / `limits` / 统计——`route.rules` 对 NW3 生效，业务字节计入
> `/stats` 与 `/stats/users`。
>
> 为什么走 loopback 而不是改 vendor：`Outlet` / `OutboundDialer` 都是
> `pub(crate)`，注入 dialer 要长期维护 GPL 分叉；而 `out=` 指向任意 SOCKS5
> 端点是 Nowhere 的公开契约。代价是多一次回环往返（实测 SOCKS5 转发
> 延迟 +0.235ms）。
>
> 边界：
> - 用户显式配置了 `out`（`egress` 或 `HOST:PORT`）时不注入，尊重原行为。
> - 内部入口不写入配置、不参与 `dubhe export`、不计入热重载指纹。
> - NW3 自己的 `rate` / `etar` 仍由 Portal 执行，不并入本内核的 `limits`。
> - **认证失败仍不计入 `dubhe_rejected_total`**：认证在 `vendor/nowhere`
>   内部完成，本内核看不到。日志里可用 Nowhere 的 `SilentRejections` 排查。
（这与 Nowhere 自身的 Egress 角色一致）；日志同样走 `nowhere::Logger`。本地 IPC 遥测按 Nowhere 的 `InstanceRole::Egress` 注册。

## Portal 的出口选择（`out`）

`out` 支持三种取值，本内核把它们直接映射到 Nowhere Portal URL 的 `out` 查询参数：

- `direct`（默认）：Portal 自行解析并连接目标，可用 `dial`/`dial4`/`dial6` 控制源地址。
- `egress`：Portal 不再自己连接目标，而是通过 Egress 注册队列把每条 Flow 交给一个 Egress。
- `USER:PASS@HOST:PORT` 或 `HOST:PORT`：把目标连接交给 SOCKS5 上游。`@` 与第一个 `:` 是结构分隔符；凭据内部若需要这些字符必须写成 `%40`/`%3A`，单独的 `%` 写成 `%25`。凭据不会出现在本内核的 `Debug` 输出中（只显示 `socks`）。

`out=egress` 的配置示例：

```json
{
  "type": "nw3",
  "tag": "nw3-in",
  "listen": "0.0.0.0:2000",
  "key": "0123456789abcdef0123456789abcdef",
  "out": "egress"
}
```

完整闭环由两部分组成：Portal 以 `out=egress` 运行，另有一个 Egress（可以是本内核同一配置里的顶层 `nw3_egress`，也可以是远端 Nowhere 实例）用同一共享密钥连接该 Portal 并注册。注册成功后，Portal 按 FIFO 把 Flow 交给可用 Egress；Egress 断开时由 `Registration` 的 `Drop` 自动摘除。

- **不回落直连**：`out=egress` 且没有可用 Egress 时，Flow 在 Nowhere 的 `flow_setup_timeout`（`NOW_FLOW_SETUP_TIMEOUT`）后失败，不会改用 `direct`。
- **不经过本内核**：被分配的 Flow 由 Egress 侧拨出，仍**不经过本内核的 route/outbounds、统计与限额**；本内核只负责把 `out` 写进 URL。
- **SOCKS 上游**：本内核的 Portal `out` 支持 `direct`、`egress` 和 Nowhere 的 SOCKS 端点；未知取值在配置解析阶段拒绝。
- **`dial` 冲突**：Nowhere 禁止 `out=egress` 与 `dial`/`dial4`/`dial6` 同时出现；本内核已透传 `dial`/`dial4`/`dial6`，因此该组合由 Nowhere 侧拒绝。

## URL 映射

| 配置 | Portal URL |
|---|---|
| 无证书 | `portal://KEY@HOST:PORT?tls=1&morph=0/1&out=..[&dial..][&rate..][&etar..]` |
| 有证书 | `portal://KEY@HOST:PORT?tls=2&crt=..&key=..&morph=0/1&out=..[&dial..][&rate..][&etar..]` |

- `tls=1`：Portal 启动时生成一次性自签名证书，并在自己的启动日志中打印证书 SHA-256 指纹；客户端必须以 `pin=<sha256>` 固定该指纹，否则没有域名信任链可校验。
- `tls=2`：使用配置的证书与私钥；Nowhere 会按 `NOW_RELOAD_INTERVAL`（默认 1 小时）重载证书文件。
- 查询值统一用 `%XX` 编码（空格为 `%20`，不是 `+`），但 SOCKS5 `out` 的结构字符 `:`、`@`、`[`、`]` 与已有 `%XX` 转义保持原样，以匹配 Nowhere 的解码方式。
- 查询参数由 `url` crate 编码，因此证书路径中的空格、非 ASCII 字符可用。

## 传输与协议行为

- ALPN 固定为 `nw3`；TCP 与 QUIC 都必须 TLS 1.3，0-RTT 关闭（`max_early_data_size = 0`）。
- 认证使用共享密钥派生的连接级凭证；Morph 在 TLS/QUIC 之下再做共享密钥掩码。TCP 的 Morph 需要 64 字节认证 prelude，UDP 的 Morph 需要 12 字节 prelude，均由 Nowhere 实现。
- TLS 下每个 Flow 独占一条连接；QUIC 下共享连接，TCP 用流、UDP 用流加 DATAGRAM。
- 未认证的连接在 Portal 内部按来源 IP 做准入限制，默认连接上限 1024 条 Flow。

## 与本内核其余入口的差异

NW3 **不是一个接入本内核转发链的入站**，而是把 Nowhere 的 Portal 作为独立子系统嵌入同一进程：

- **自行绑定端口**：TCP 与 UDP 都在 `run()` 阶段由 Portal 绑定，不在 `Server::bind` 阶段。因此 `local_addr` 返回的是配置值；端口被占用、证书不可读等问题会在启动进入 `ready` 之后才暴露为监听任务失败，而不是绑定阶段失败。
- **自行出站**：`out=direct`（默认）时由 Nowhere 的 `OutboundDialer` 直接解析并连接；`out=egress` 时交给注册到该 Portal 的 Egress；SOCKS5 上游时由 Nowhere 的 SOCKS 客户端转发。三者都**不经过本内核的 `outbounds`、`route`、`reject`、DNS 解析策略，也不计入本内核的流量统计与连接限额**。需要按本内核路由规则限制目标时，当前无法用 NW3 满足。
- **独立日志**：`nowhere::Logger` 直接按自己的格式写 stdout/stderr，不经 `tracing` 结构化输出，也不受本内核日志配置控制。
- **本地 IPC**：Portal 会在 `$TMPDIR/nowhere-telemetry-<uid>`（权限 0700）下建立每实例的 Unix 套接字与注册表文件，供 Nowhere 自带的 `status`/telemetry 访问。多个 NW3 入站各有独立实例 ID。IPC 建立失败只记录一行错误，不影响服务。
- **运行时调优**：`NOW_*` 环境变量（握手超时、UDP 空闲、关闭超时、证书重载间隔等）由 Nowhere 自行读取，本内核配置不覆盖它们。

## 生命周期

- `Server::bind` 构造 `Portal`（校验密钥、加载/生成证书、解析端点），但**不绑定**端口。
- `Server::run` 为每个 Portal 启动任务，读取本内核的停止令牌；停止时 Portal 取消自己的监听、等待 Flow 排空（`NOW_SHUTDOWN_TIMEOUT`，默认 5 秒）后返回。
- 超过本内核 `limits.shutdown_timeout_ms` 仍未退出时，强制阶段直接丢弃 Portal future，其内部任务随之停止。
- Portal 不安装进程信号处理；SIGINT/SIGTERM 仍由本内核统一处理。
- Egress 由 `Server::run` 以同样方式启动：连接远端 Portal、注册、拨出目标；停止令牌取消时结束连接维护并按 Nowhere 的关闭超时排空。Egress 失败（例如持续无法注册）不会让整个内核退出，只记录 Nowhere 日志并退避重连。

## 不支持

- Vector 客户端已通过 vendored `VectorClient` 接入为 `nw3-vector` 出站（TCP/UDP）；本机 Vector↔Portal 回环和官方 v3.3.0 Vector 的 TCP/UDP 互通均已执行，官方 Anywhere 客户端未做。Portal 的 `out=direct`/`egress`/SOCKS5 上游已接入（见上节）；SOCKS5 上游只支持 Nowhere 的 `[USER:PASS@]HOST:PORT` 写法，不支持 `socks5://`、`socks4://` 等 URL 形式。
- Egress 只支持单实例、单共享密钥；不支持 `NOW_EGRESS_TLS_POOL_MAX` 等 Nowhere 环境变量以外的本内核配置。
- Portal 入站仍只暴露 `HOST:PORT` 同端口监听；Vector 出站已接受上游 `HOST/tcp:PORT`/`HOST/udp:PORT` 显式载波；Portal 分离监听及 `*` 通配主机未开放。
- 每个入站只有一条共享密钥，不支持多用户/多密钥。
- `rate`/`etar` 由 Nowhere 的 Portal 限速器实现；本内核只透传，不提供额外的统计或配额。
- 不支持 0-RTT。

## 本机回环证据

`tests/nw3.rs` 使用 `vendor/nowhere` 的 `VectorClient` 直接连接本内核 `nw3` Portal：

- `nw3_portal_relays_tcp_with_vendored_vector_client`：Portal `out=direct`、真实证书 + pin、TCP echo；
- `nw3_portal_relays_udp_with_vendored_vector_client`：同一 Portal 经上游 `Vector` SOCKS UDP ASSOCIATE 转发 UDP echo；
- `nw3_portal_egress_relays_tcp_with_vendored_vector_client`：Portal `out=egress`，同配置顶层 `nw3_egress` 注册为出口，再由 Vector 客户端经 Portal 转发 TCP；
- `nw3_portal_egress_relays_udp_with_vendored_vector_client`：同一 Egress 路径转发 UDP；
- `nw3_vector_outbound_relays_tcp_through_portal`：`nw3-vector` 出站经本内核 Portal 转发 TCP。

上述五项通过；本批另增 `nw3-vector` UDP 出站的显式 TLS/QUIC 载波、双目标/空包、错误密钥与拒绝路由测试。UDP API 只调用原上游 open_udp，报文未改（见 vendor/nowhere/KERNEL-ADAPTER.md）。

## 官方 Nowhere v3.3.0 互通证据

固定官方二进制 `nowhere-v3.3.0 macos/aarch64`，真实 TLS 证书 + `pin`、`morph=1`、
`127.0.0.1` 回环；UDP 组合在 Vector/Egress URL 中显式使用 `/udp:PORT`（QUIC），
Portal 为同端口 TCP TLS + QUIC。TCP 用本机 HTTP GET 校验正文；UDP 用独立 Python
SOCKS5 UDP ASSOCIATE 客户端向本机 UDP echo 发送并校验回包，客户端侧不使用本内核
生产编解码器。

| 方向 | 组合 | TCP | UDP |
| --- | --- | --- | --- |
| 官方客户端 → 本内核 | 官方 Vector → 本内核 Portal `out=direct` | 通过 | 通过 |
| 本内核 → 官方服务端 | 本内核 `nw3-vector` → 官方 Portal `out=direct` | 通过 | 通过 |
| 官方客户端 → 本内核 | 官方 Egress 注册到本内核 Portal `out=egress` | 通过 | 通过 |
| 本内核 → 官方服务端 | 本内核 `nw3_egress` 注册到官方 Portal `out=egress` | 通过 | 通过 |

官方 Anywhere 客户端、Morph 认证负例、无可用 Egress 时的超时失败语义与三平台/
release 尚未验证。

## 依赖

| 依赖 | 版本 | 许可 | 说明 |
|---|---|---|---|
| `nowhere` | 3.3.0（`vendor/nowhere`） | GPL-3.0-only | 协议与 Portal 实现 |
| `url` | `2` | MIT OR Apache-2.0 | 直接依赖，构造 Portal URL；与 nowhere 使用同一版本族 |

`vendor/nowhere` 自身依赖 `rcgen 0.14.10`、`rustls-native-certs 0.8.5`、`sha2 0.11.1`、`chacha20 0.10.2` 等，与根 package 的 `rcgen 0.13.2`、`sha2 0.10` 并存（Cargo 允许多版本）。`Cargo.lock` 现已包含 `nowhere`、h3 系列与 `quinn-proto` 条目，`cargo check --all-targets` 已通过。

Nowhere 3.3.0 及其新增传递依赖是否满足本项目声明的 MSRV 1.91 **尚未验证**；这是首次集中构建时必须确认的门禁项，不能用上游 README 的“stable toolchain”代替。

## 验收缺口

已通过编译检查并执行根项目 Portal/Egress/Vector TCP/UDP 回环（见上节）；完整 vendor 专项与官方客户端验证仍有缺口。下列是完整验收清单，已覆盖部分不等于全项完成：

1. `rustfmt`/clippy；
2. 密钥格式、证书模式、端口占用的配置负向用例；
3. 本机自身回环：使用 `vendor/nowhere` 的 Vector 侧构造本机回环，验证 TCP/UDP、Morph 开/关、`tls=1` 指纹固定与 `tls=2` 证书；
4. 停止语义：正常停止排空、强制停止、端口占用导致的启动失败；
5. 与官方 Anywhere 客户端的有限组合、官方 Nowhere 的 Morph 认证负例，以及三平台与 MSRV 结果；
6. Egress 出口与 `out=egress`：验证 Egress 注册、出口接管、无可用 Egress 时的超时失败（且不回落直连）、断线重连与停止。本内核的 Portal 与 Egress 两端均已实现，可用一个本内核实例开 Portal、另一个实例开 Egress 组成回环；与官方 Nowhere v3.3.0 的交叉组合已执行（官方 Egress→本内核 Portal、本内核 Egress→官方 Portal，TCP/UDP），见上节。
7. `out` 的 SOCKS5 上游：对回环 SOCKS5 服务验证无认证/有认证、IPv6 端点、错误凭据与不可达上游；验证 `dial` 家族在 `direct` 下生效、在 `egress` 下被配置层拒绝，以及 `rate`/`etar` 的透传。
