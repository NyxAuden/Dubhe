# Dubhe 服务端代理内核

一个用 Rust 写的服务端代理内核：目标是在服务器上用**一个进程**替代并列部署的
多个协议内核，让现有 Clash / sing-box / V2Ray 系客户端直接连上来。

> Dubhe is a Rust server-side proxy kernel. It aims to replace multiple protocol
> kernels on a server with a single process. Not released yet — see the
> [compatibility matrix](docs/compatibility-matrix.md) for the exact verified subset.

## 当前状态

项目仍为未发布开发版本。状态只在下文两个文件里维护，本 README 不重复断言：

| 类别 | 说明 |
|---|---|
| 已验收 | 有固定官方客户端互通证据、负向用例与平台记录的协议组合 |
| 已实现待集中验收 | 代码完成、本机回环通过，但缺完整客户端/平台矩阵；可以用，证据不完整 |
| 明确不做 | TUN / redirect / tproxy、出站 BIND、系统级透明代理 |

- 逐项状态与证据：[服务端兼容矩阵](docs/compatibility-matrix.md)
- 已实现待验收的能力：[实验能力清单](docs/experimental.md)
- 协议的权威来源与参照差异：[协议与功能的上游归属](docs/protocol-ownership.md)
- 上游事实与证据等级：[上游事实核对](docs/upstream-facts.md)
- 生产边界与未完成项：[生产可用性评估](docs/production-readiness.md)
- 开源补齐清单与排期：[开源项目补齐计划](docs/oss-checklist.md)
- 常见问题：[故障排查](docs/faq.md)　·　代码结构：[架构概览](docs/architecture.md)
- 从 Xray / sing-box 迁入：[迁移指南](docs/migration.md)
- 生成客户端配置：`dubhe export` → Xray / sing-box / Mihomo / Anywhere AJSON

---

- 原生 Rust 服务端，同一进程运行多个 SOCKS5、Trojan/TLS、VLESS/TLS、VLESS/REALITY、VMess/REALITY、Trojan/REALITY、Shadowsocks、VMess（可选TLS）、Snell、Hysteria2、TUIC、ShadowTLS v3 及 VLESS/VMess/Trojan WS/WSS、gRPC（HTTP/2）入口；ShadowTLS v3 另提供无目标 `shadowtls` 出站 detour，供其他 TCP 代理经 `via` 使用；生产运行不依赖其他内核可执行文件。
- Shadowsocks AEAD2017/2022：六方法原生 TCP/UDP、两 AES2022 单层 EIH 多用户已验收；macOS ARM64、Linux ARM64、Linux x86_64（QEMU）普通回归各 **209项通过、0失败、33项忽略**，vendor各25项通过。三家固定官方客户端的 **24项 Shadowsocks 及旧九项回归全部通过，共87个场景**；官方矩阵另行显式执行，不将ignored计为通过。x86_64的QEMU编译器局部设置及警告边界见 [Shadowsocks 验收](docs/shadowsocks-acceptance.md)。
- SOCKS5：CONNECT、UDP ASSOCIATE 与 BIND（监听控制连接本机 IP、接受一次入站连接）；无认证或用户名密码认证。默认禁止无认证非回环监听；不支持 UDP 分片。BIND 是本内核扩展，Xray/sing-box 的 SOCKS 入站不提供。
- Trojan over TCP+TLS：多用户认证、TCP/UDP 转发，TLS 1.2/1.3；旧入口仍必填 TLS。WebSocket/WSS 使用独立 `trojan-ws` 入口，不支持 fallback、gRPC 和复用扩展。
- VLESS/TLS：UUID 多用户认证、TCP/原生 UDP；命令 3 与 `v1.mux.cool` 目标进入 Mux.Cool，TCP 会话始终可用，UDP 多会话默认准入，可用 `xudp: false` 关闭。Mux 为**已实现待集中验收**，不沿用旧 XUDP 外部验收结论。
- 共享 Direct/Reject、系统或显式配置 DNS 与静态 hosts、确定性路由（精确/后缀/关键字域名、CIDR、端口、入口、网络）、半关闭、有界 UDP 关联、资源预算、超时、结构化日志和有期限停机。
- 严格原生 JSON 配置，以及 `check`、`run`、`version` CLI；未知字段和未实现能力会报错，不静默降级。

第一阶段历史验证记录（2026-11-04，具体旧构建摘要见验收报告；新增 VLESS 后的当前回归另见 [VLESS 验收](docs/vless-acceptance.md)）：

| 项目 | 结果与边界 |
|---|---|
| macOS ARM64 | 73 项普通测试通过；fmt、check、严格 Clippy、release 构建通过 |
| Linux ARM64 | 容器内实际运行 73 项普通测试通过 |
| Linux x86_64 | QEMU 仿真容器内实际运行 73 项普通测试通过，不是原生性能证明 |
| Trojan/TLS 外部互通 | Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31 的 macOS ARM64 构建，各通过 TCP/UDP、错误密码拒绝及不受信任证书拒绝 |

上表是第一阶段历史构建结果。此前独立 VLESS/XUDP 验收构建在 macOS ARM64、Linux ARM64、Linux x86_64（QEMU）各通过117项普通测试；九项官方客户端测试另行显式执行，9 passed / 0 failed。普通测试中的 ignored 不算通过。具体组合、身份与证书信任负向范围、构建摘要见 [VLESS 验收](docs/vless-acceptance.md)；第一阶段历史证据见 [验收记录](docs/acceptance.md) 和 [互通报告](docs/interop-report.md)。

VLESS v0 + 标准 TLS 的 UUID 认证、TCP 与原生固定目标 UDP 已完成有限外部验收：三家 TCP、sing-box/Xray 原生 UDP。命令 3 现按上游语义解析为完整 Mux.Cool（VLESS/VMess 共用实现，TCP 会话不要求 `xudp`）；Mux 内的 UDP New/GlobalID 默认准入，入站显式 `xudp:false` 时该 UDP 会话返回 End/Error。旧 XUDP 仅 UDP 验收见 [本批验收记录](docs/vless-acceptance.md)，不能推导 TCP Mux 兼容；Mux 线协议与限制见 [Mux 说明](docs/mux.md)。固定 Mihomo 的 UDP 需要开启 XUDP。

**标准TLS上的Vision已接入开发实现；Xray v26.10.31 双向与 Mihomo v1.19.33、sing-box v1.14.4 客户端 VLESS Vision TCP/UDP 有限组合已通过，三平台集中验收未完成**，包括本地验证的双向Direct，见[Vision说明](docs/vision.md)；不继承旧构建的兼容结论。**VMess AEAD已实现待集中验收**，含TCP/可选TLS、security3/4/策略允许的5、原生UDP/显式XUDP和packetaddr；Xray 双向 VMess/TLS 与 Mihomo VMess/TLS TCP/UDP 有限组合已通过，其余独立金样及回环不等于官方客户端互通，安全边界见[VMess说明](docs/vmess.md)。**REALITY 已实现待集中验收**：独立 `vless-reality`/`vmess-reality`/`trojan-reality`、固定目标回落、普通/混合组及可选ML-DSA；REALITY 现可组合到 VLESS/VMess/Trojan 的 gRPC、XHTTP 入口（与证书互斥，XHTTP/3 除外）；与上游一致，WebSocket/HTTPUpgrade 不组合 REALITY；21/29 开发任务完成，见[REALITY说明](docs/reality.md)和[开发证据](docs/reality-development.md)；其余8项官方客户端、平台、精确MSRV、release及最终报告集中验收未完成。**REALITY 出站已增量接入 `vless`/`vmess`/`trojan`**，支持 X25519 与 X25519MLKEM768，可选 `mldsa65Verify` 校验服务端 ML-DSA-65 扩展，仅允许 RAW/gRPC/XHTTP 承载；本机 VLESS 纯 TCP（两种目标组）、VLESS Vision+REALITY、VLESS 原生 UDP、ML-DSA 校验与三协议 REALITY-over-gRPC 回环通过，WS/HTTPUpgrade 组合在配置阶段拒绝；已与官方 Xray v26.10.31 完成 VLESS（含 Vision）、VMess、Trojan REALITY 的 RAW 双向 TCP 本机互通，以及 VLESS/VMess/Trojan 的 REALITY-over-gRPC 与 REALITY-over-XHTTP 双向；三平台、MSRV、release 等其余验收未完成。**WebSocket/WSS 已实现待集中验收（19/27）**：VLESS无flow、VMess AEAD、Trojan的TCP/UDP及所属显式扩展，含默认/custom header与path early-data；同一输入30条开发命令全部退出0，577次测试执行通过、7次忽略不计通过，见[使用边界](docs/websocket.md)和[开发证据](docs/websocket-development.md)。Xray 双向 VLESS/WSS 与 Mihomo VLESS/WSS TCP/UDP 有限组合已通过；Close不提供通用透明TCP半关闭，其余官方/三平台/MSRV/release仍未验收。**gRPC/HTTP2 已实现待集中验收（开发14/33）**：独立 `vless-grpc`/`vmess-grpc`/`trojan-grpc`，支持single与multiMode、明文prior-knowledge与真实TLS（ALPN h2），复用既有TCP/原生UDP/XUDP/packetaddr/Trojan逐包UDP；本地25项入站测试通过，边界说明见[gRPC说明](docs/grpc.md)；已与官方 Xray v26.10.31 完成 VLESS（single/multiMode）、VMess、Trojan 的 gRPC/TLS 双向 TCP、VLESS XUDP over gRPC UDP（single/multiMode）及 VLESS/REALITY-over-gRPC 双向，其余官方矩阵、三平台、MSRV、release 与最终报告未做。**XHTTP 与 HTTPUpgrade 已实现待集中验收**：三协议独立入口，XHTTP 支持 auto/stream-one/stream-up/packet-up、h1/h2/h2c、真实TLS、headers/cookie、会话TTL与上限；HTTPUpgrade 为一次性 Upgrade 后裸字节流。本地22项XHTTP入站与6项XHTTP出站测试通过，另有HTTPUpgrade 6项入站测试，见[XHTTP说明](docs/xhttp.md)与[HTTPUpgrade说明](docs/httpupgrade.md)；另新增 XHTTP/3（QUIC，`xhttp.h3: true`）承载，复用同一会话与模式语义，已编译并通过 2 项本机 h3 回环测试（stream-one、packet-up）；已与官方 Xray v26.10.31 完成 VLESS/XHTTP TLS 四种模式（含 XUDP UDP）、VLESS/REALITY-over-XHTTP 及 VLESS/HTTPUpgrade TLS（含 XUDP UDP）双向本机互通，其余官方矩阵、三平台、MSRV、release 未验收。**HTTP/Mixed 与 Naive 已实现待集中验收**（[说明](docs/http.md)）；Naive H2/H3 支持 `padding` 能力头与首8块PaddedData；`h3:true` 同端口开启QUIC普通CONNECT，本内核H1入站裸流对齐固定forwardproxy，不能外推sing-box；原生Naive H1/H2/H3出站已接普通CONNECT/Basic/TLS/ALPN，H1默认裸流或显式`h1_padding`对齐sing-box首8块，H2/H3按响应协商首8块padding。可选标准UoT v2默认false，H1需显式padding模式及支持UoT的上游；H1/H2可TCP链式，H3独立QUIC。H1入站默认裸流不变，另补显式`h1_padding:true`的sing-box正式首8块填充/UoT（[入站记录](docs/naive-h1-inbound-development.md)）；HTTP连接池与Cronet指纹等价仍未提供（[H2/H3历史记录](docs/naive-outbound-development.md)、[H1记录](docs/naive-h1-outbound-development.md)），**VLESS/Trojan fallback 稳定子集已实现待集中验收**（[说明](docs/fallback.md)）。**AnyTLS 已实现待集中验收**：正式padding方案、客户端cmd6更新及每出站TCP/UoT共享factory、服务端自定义原文下发已接入，出站另补默认空闲会话池、递增ID/控制帧与整流FIN、TCP/UoT共池及链式/热替换/停机回收（[说明](docs/anytls.md)、[padding记录](docs/anytls-padding-development.md)、[池记录](docs/anytls-pool-development.md)），**UoT（VLESS/VMess/AnyTLS 及 Naive H2/H3及显式填充H1入站，Shadowsocks/AnyTLS 与显式 Naive 出站）已实现待集中验收**（[说明](docs/uot.md)）。**Mux.Cool（TCP + xudp 门控的 UDP）已实现待集中验收**，见 [Mux 说明](docs/mux.md)，不写为已测试。**Snell v4/v5/v6、Hysteria2、TUIC v5、ShadowTLS v3、NW3 Portal 入站已实现待集中验收**（[Snell](docs/snell.md)、[Hysteria2](docs/hysteria2.md)、[TUIC](docs/tuic.md)、[ShadowTLS](docs/shadowtls.md)、[NW3](docs/nw3.md)）；ShadowTLS v3 另新增 3 项本机回环测试（认证经 detour 转发、未认证回落、SNI 映射）；NW3 直接复用固定 Nowhere 3.3.0 源码（项目因此为 GPL-3.0-only），由 Portal 自行绑定 TCP/QUIC 并自行出站（默认直连，也可交给 Egress 或 SOCKS5 上游），不经过本内核 route/outbounds/统计；已用 vendored Nowhere 上游 Vector 客户端完成 5 项本机回环（Portal direct TCP/UDP、Portal Egress TCP/UDP、`nw3-vector` 出站 TCP），并用官方 Nowhere v3.3.0 完成 Vector→本内核 Portal、`nw3-vector`→官方 Portal、官方 Egress→本内核 Portal、本内核 `nw3_egress`→官方 Portal 的 TCP/UDP 有限组合，仍未做 Anywhere 官方客户端与多平台验证；五者均已编译；ShadowTLS 完成 sing-box v1.14.4（darwin/arm64）双向本机互通，Shadowsocks 2022 EIH 出站与 Hysteria2 出站带宽协商也完成 sing-box 服务端本机互通，sing-box 客户端 VLESS Vision、Trojan/TLS、Hysteria2（含 salamander/gecko obfs）/TUIC v5/AnyTLS/Snell v4/v6/Naive H2/H3 到本内核入站的 TCP/UDP（部分为 UoT v2），以及 WireGuard endpoint（外层回环、内层 10.66.0.x、helper 目标改写）到本内核 WireGuard 入站的 TCP/UDP 已通过；Mihomo 客户端已通过 Hysteria2/TUIC/Snell v5/AnyTLS TCP/UDP 及 ShadowTLS 插件 TCP 有限组合，其余真实客户端验证仍未执行，Hysteria2 已接入带宽协商，Brutal 已完成逐包 ACK、ACK 回调 RTT 和 quinn Cubic 委托；独立 pacing 与逐包 loss 仍受 quinn API 限制（见[核查](docs/hysteria2-brutal-alignment.md)，不实现 BBR profile 与 rade proxy 类型），TUIC 入站与出站均支持 `congestion_control`（cubic/new_reno/bbr）及显式 0-RTT（默认关闭）；出站仅提前Connect元数据/Heartbeat，业务仍等完整握手与标准exporter认证写入，不自动重放，见[记录](docs/tuic-outbound-modern-development.md)，Snell v6 已支持 default/shaped、unshaped 与 unsafe-raw，不支持 QUIC 与 HTTP-TLS obfs，ShadowTLS 不支持 v1/v2，其 `detour` 只接受同配置内的明文 TCP 入站。**VLESS Encryption（`mlkem768x25519plus`）已实现待集中验收**：入站已接入 `vless`、`vless-reality`、`vless-ws`、`vless-grpc`、`vless-xhttp`、`vless-httpupgrade`、`vless-quic`、`vless-kcp`、`vless-http`；出站新增 `encryption` 字段（TCP/UDP，native/xorpub/random，1-RTT/0-RTT），支持 `native`/`xorpub`/`random`、X25519 与 ML-KEM-768 认证密钥及中继链、1-RTT/0-RTT 票据与 padding；与 `fallbacks` 互斥；Vision flow 已可组合；已通过全目标编译与库测试；已与官方 Xray v26.10.31 的 X25519/ML-KEM-768 认证对完成 VLESS/TLS 双向本机互通，官方客户端 `.0rtt` 重连已实际进入 0-RTT（1232→32 长度块），三平台/MSRV/release 未验收，见[说明](docs/vless-encryption.md)。**Mux 的 GlobalID 跨承载 1 分钟续接已实现待集中验收**（见 [Mux 说明](docs/mux.md)）。**NW3 Egress 出口服务与 Portal 的 `out` 出口选择已实现待集中验收**（顶层 `nw3_egress` 主动连接 Portal 注册为出口；`nw3` 入站的 `out` 可选 `direct`/`egress`/SOCKS5 上游，并透传 `dial`/`rate`/`etar`；不经过本内核路由/统计，见 [NW3 说明](docs/nw3.md)）。**dokodemo-door 入站已支持 TCP 与 UDP**（`network` 可为 `tcp`/`udp`/`tcp,udp`；`tcp,udp` 共享同一监听端口，UDP 按客户端源地址独立关联并受 `limits` 约束，路由到不受支持的 UDP 出站时失败关闭；TCP 可选 TLS SNI / HTTP/1.1 Host 首包嗅探，见[说明](docs/dokodemo.md)）。**全站首包嗅探已实现待集中验收**：顶层 `sniffing` 为 VLESS 明文 TCP、VMess TCP、Trojan TCP、SOCKS5 CONNECT 与 Shadowsocks TCP 提供 TLS SNI / HTTP/1.1 Host 识别，已读字节原样回放；默认只影响路由，`dest_override` 才改写拨号目标，默认超时 300ms；UDP 关联对 QUIC Initial 解出 SNI 后只用于选路；Vision/REALITY 内层流、Mux.Cool 的 TCP 子流、xudp 数据报与 QUIC 合并包已纳入，见[嗅探说明](docs/sniffing.md)。**上游出站已实现待集中验收**：SOCKS5（CONNECT + UDP ASSOCIATE）、HTTP CONNECT、VLESS v0（含可选 `xtls-rprx-vision`）、VMess AEAD（security 3/4）、Trojan（必须 TLS 或 REALITY）、Shadowsocks AEAD（含 2022）与无目标 ShadowTLS v3 detour；TCP 单跳与多跳链式均可用，可选到上游的 TLS（显式 PEM 信任锚）或 REALITY（VLESS/VMess/Trojan）与 VLESS/VMess/Trojan 的 WebSocket/WSS、gRPC（single/multi、真实 TLS ALPN h2）、HTTPUpgrade、XHTTP、mKCP 与 QUIC 包装（mKCP 已与 Xray v26.10.31 完成双向本机互通）；ShadowTLS 只能经 `via` 与 endpoint 一致的内层 TCP 代理组合，不终端路由、不支持 UDP；SOCKS5、VLESS、VMess、Trojan、Shadowsocks、Hysteria2 与 TUIC 出站支持原生 UDP，AnyTLS 出站通过 UoT v2 承载 UDP，TCP/UoT按正式流ID共用空闲会话池（VMess 为固定目标命令 2 隧道）；WireGuard/NW3 Vector 已补 UDP 出站（逐目标会话，保留空包，受 MTU/上游容量限制），普通 HTTP CONNECT 的 UDP 仍失败关闭；本机回环互通测试通过（含 VLESS/VMess/Trojan TLS、VLESS/VMess WS、Trojan WSS、gRPC single/multi/over-TLS、Shadowsocks AEAD、VLESS/VMess/Trojan/Shadowsocks UDP 与双跳链式），见[出站说明](docs/outbound.md)。**零停机配置热重载已实现待集中验收**：入口、limits、API 与 NW3 Egress 未变化且无 UDP 监听器时，SIGHUP 原子替换路由/DNS/嗅探/出站配置，不重启监听且保留既有连接；其余变化仍完整重启。**反向 Mux Portal/Bridge 已实现待集中验收**：VLESS 命令 4 注册 Mux 客户端隧道，普通流量经 `reverse` 出站打开会话；顶层 `reverse_bridges` 引用标准 VLESS 出站主动拨入 Portal 并运行 Mux 服务端，断线重连；Mux 隧道支持 TCP/UDP 会话，含 Control 心跳与有界资源；本机明文 TCP、Vision 命令 4 与 Mux UDP 回环通过，见[反向 Mux 说明](docs/reverse.md)。**出站组 `selector`（静态）与 `urltest`（周期探测延迟切换）已实现待集中验收**：成员递归解析、循环拒绝；`urltest` 经成员拨号 `probe`，按最低延迟与容差选择，全部失败保持当前成员；定向单元/回环测试已运行，官方客户端与三平台未验收。**WireGuard 出站已实现待集中验收**：`wireguard` 出站复用 boringtun 0.7.1（Noise_IK 握手与封装）与 smoltcp 0.14.0（隧道内 IPv4/IPv6 与 TCP 用户态栈），支持 IPv4/IPv6 本地地址、PSK、MTU 与持久保活；每个出站共享一条 UDP 隧道，TCP 连接映射为隧道内独立 TCP，UDP 映射为独立目标 socket；已通过 1 项本机双 endpoint 回环测试（真实握手 + TCP echo），见[出站说明](docs/outbound.md)。**WireGuard 服务端入站（UDP，无 TUN）已实现待集中验收**：新增 `type: "wireguard"` 入站，boringtun 作为 Noise_IK responder，smoltcp 终止隧道内 TCP/UDP，再经 route/direct 出站转发；支持 IPv4/IPv6 本机隧道地址、每 peer `allowed_ips` 源 ACL、PSK、keepalive、peer/连接/关联/队列/握手速率上限与空闲清理；TCP/UDP 均复用内核路由与已有上游中继，空闲后保留重放保护、停机回收子任务；已通过本机完整 Config + `Server::bind` 回环集成测试（真实握手 + TCP/UDP echo），未与官方 WireGuard 客户端互通，见[说明](docs/wireguard-server.md)。**Snell v4/v5/v6 TCP/UDP-over-stream出站已补齐开发实现**：复用正式记录codec，v6 default/unshaped/unsafe-raw，延迟首应答、零块FIN、逐目标UDP、空包/双栈、容量与预算回收、TCP链式本机回归通过，v4/v5入站与出站另补HTTP/TLS obfs（非真实TLS/WS、v6不叠加），见[obfs记录](docs/snell-obfs-development.md)；另补默认关闭的TCP顺序池（根/链式先取池、双向零块、有界排空及热替换/停机回收），见[池记录](docs/snell-reuse-development.md)；QUIC仍待补（见[基础出站记录](docs/snell-outbound-development.md)）。**尚未实现** 出站 BIND 与系统级 TUN/redirect/tproxy，因此现在还不能连接 Anywhere，也不能完整替代 Xray/sing-box/Nowhere。ShadowTLS v3 出站为无目标 detour（只能经 `via`、不支持 UDP，见[说明](docs/shadowtls.md)）。Shadowsocks 出站新增 UoT v2，并可按 `iPSK:uPSK` 链连接上游；服务端只终止单层 EIH，插件仍未实现。NW3 Vector TCP/UDP 出站已接入并通过本机 TLS/QUIC 回环；官方 Nowhere v3.3.0 的 Vector/Portal 与 Egress 交叉 TCP/UDP 有限组合已通过，Anywhere 客户端仍未验证。

## 构建与运行

仓库 `rust-toolchain.toml` 固定 Rust 1.91.0；声明 MSRV 1.91；macOS ARM64 在精确 Rust 1.91.0 上的当前全量为 `cargo test --locked --all-targets` 1465 通过、0 失败、42 忽略，并完成 release 构建（`0.1.0`）；Rust 1.95.0 的历史全量为 1383 通过、0 失败、42 忽略。Linux ARM64 已在 Colima（4 CPU / 8 GiB，ARM64）中的 `rust:1.91-bookworm` 镜像完成全量测试（上次实测 1389 通过、0 失败、42 忽略，本批新增用例如未重跑不计入）与 release 构建（`0.1.0`，33,144,056 字节，SHA-256 `7ec912b1b93e6e8327fc814309c7bb0713f34674b0c4e8d2970b891e108f3405`）；Linux x86_64 check 通过，但 QEMU 下全量 cargo fork/exec 偶发死锁，未取得可信全量结果、未构建 x86_64 release。这不等于 Linux x86_64、Windows 或可发布 release 验收。历史三平台口径为 macOS ARM64、Linux ARM64、Linux x86_64（QEMU），不含 Windows。历史Shadowsocks验收输入已在 Linux ARM64 用精确 Rust1.91.0 和1.91.1分别完成全目标编译检查（含AWS-LC原生编译），不覆盖新增Vision/VMess/REALITY/WS输入，也不等于 Linux 各架构 MSRV 全量运行测试完成。普通测试还需要系统 `curl`；AWS-LC需要原生C/汇编工具链，详见 [依赖门禁](docs/shadowsocks-dependency-gate.md)。

```sh
cargo build --locked --release
./target/release/dubhe version
./target/release/dubhe check -c "examples/socks5.json"
./target/release/dubhe run -c "examples/socks5.json"
```

SOCKS5 示例只监听 `127.0.0.1:1080`。Ctrl+C 或 SIGTERM 触发有期限排空和资源清理。Unix 下 SIGHUP 在配置文件内容未变时只轮换 TCP/TLS 入口证书，不重启监听、不中断既有连接；配置变化会先尝试零停机热重载（入口、limits、API 与 NW3 Egress 不变且无 UDP 监听器时），不满足条件才完整重启（详见[使用说明](docs/usage.md)）。Trojan 示例必须先替换证书/私钥绝对路径及随机密码，不能直接作为公网部署配置。

完整说明、默认限额、日志与已知限制见 [构建与运行](docs/usage.md)；`target/` 体积构成与清理方式见 [构建产物体积](docs/build-size.md)。本程序不修改系统代理、防火墙或系统 DNS，不自动安装服务。

## 阅读顺序

1. [构建与运行](docs/usage.md)
2. [第一阶段验收记录](docs/acceptance.md) / [官方客户端互通](docs/interop-report.md)
3. [服务端兼容矩阵](docs/compatibility-matrix.md)
4. [可替代内核范围评估](docs/replacement-assessment.md)
5. [生产可用性门禁](docs/production-readiness.md) / [运维基线](docs/operations.md) / [可复现构建](docs/reproducibility.md) / [威胁模型](docs/threat-model.md) / [失败关闭矩阵](docs/fail-closed-matrix.md) / [fuzz 记录](docs/fuzzing.md) / [SBOM](docs/sbom.md)
6. [分阶段路线](docs/roadmap.md)
7. [领域术语](CONTEXT.md) / [上游源码研究](docs/source-research.md)
8. [架构设计](openspec/changes/establish-server-kernel-foundation/design.md)
9. [实施任务](openspec/changes/establish-server-kernel-foundation/tasks.md)

只做服务端、Rust 核心、编译期模块扩展、主流协议优先、持续跟进上游当前能力。不包装外部内核子进程，不开发终端客户端或运营平台；线协议互通不等于原样导入各家配置或兼容全部管理 API。

## OpenSpec 与后续阶段

本项目使用 OpenSpec 1.12.0。`establish-server-kernel-foundation`、`add-vless-tls-inbound`及`add-shadowsocks-aead-inbound`均已完成各自有限范围验收；Shadowsocks变更为 **40/40任务完成**，结果见[本批报告](docs/shadowsocks-acceptance.md)。所有资料保留在`openspec/changes/`，未自动归档。

```sh
openspec status --change establish-server-kernel-foundation
openspec validate establish-server-kernel-foundation --strict --no-interactive
```

Shadowsocks本批完成后，按独立变更补齐 VLESS 扩展、REALITY/Vision、VMess、Hysteria2、TUIC、NW3 的 Vector 客户端及其他当前服务端能力；NW3 Portal 入站与 Egress 出口已接入。各批次范围有限，不代表缩减长期覆盖目标。

## 许可与参考

本项目采用 **GPL-3.0-only**，见根目录 `LICENSE`。原因是 NW3 Portal 直接复用 [Nowhere](https://github.com/NodePassProject/Nowhere) 3.3.0 的 GPL-3.0-only 源码（`vendor/nowhere`），分发时须同时提供对应源码与许可文本。Cargo 设置 `publish=false`。未移植 Xray-core 与 sing-box 的 Go 实现；Nowhere 的 Rust 源码为整包复用，本地修改记录在 [THIRD-PARTY.md](THIRD-PARTY.md)。Shadowsocks 使用保留 MIT 许可、来源和可复现补丁的 Rust 协议依赖，不能把参考或换语言视为免除许可义务。依赖基线见 [dependency-baseline.md](docs/dependency-baseline.md)。

当前验收不构成全面安全审计或生产容量证明；尚未做长时间稳定性测试、生产部署或正式发布。不要公开 `.test-artifacts/`，其中包含本机测试凭据和临时私钥。
