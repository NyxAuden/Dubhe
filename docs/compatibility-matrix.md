# 服务端兼容矩阵

> ## 证据口径更正（2026-11-21）
>
> 本文件此前多处写有「已与官方 X 客户端双向互通」的完成态措辞。经全仓核对，
> **仓库内真正 fork 并驱动第三方客户端二进制的测试只有 `tests/reference_clients.rs`，
> 且 `enum Protocol` 的变体数量有限**（另加 Shadowsocks 的宏生成用例）。
>
> - **有可复现第三方客户端证据的协议**（2026-11-21 起逐项补齐）：
>   Trojan、VLESS（含 XUDP）、**VLESS Vision**、Shadowsocks、VMess、
>   Hysteria2、TUIC、Snell v4、AnyTLS、Naive、**ShadowTLS v3**（内层 SS2022）。
>   客户端不支持时（Xray 无 hysteria2/tuic/snell/anytls/shadowtls，
>   Mihomo 无 naive）用例**显式报告跳过**，不计为通过。
> - **Naive**：sing-box 用例已跑通（valid / wrong-password /
>   untrusted-certificate）。曾因 Chromium 网络栈的证书有效期限制阻塞，
>   已改测试证书为显式一年期；另因上游硬编码 `RemoteIsDomain: true`
>   导致连 `[::1]`，测试侧改用双栈监听。
> - **VLESS 承载组合**（2026-11-22 补齐，三方客户端 × 三场景）：
>   WS/WSS、gRPC、HTTPUpgrade 三家全通过；XHTTP 为 Mihomo + Xray
>   （sing-box 无 xhttp transport）；V2Ray HTTP(h2) 为 Mihomo + sing-box；
>   旧 QUIC 为 sing-box（Mihomo 无该分支，Xray v26 已移除该 transport）。
>   **mKCP 三家客户端均无可用证据**：Mihomo 源码无 kcp 分支、sing-box
>   transport 无 kcp、Xray v26.10.31 出站实测零发包（日志
>   `entering state 1 at 0` 即关闭）。内核 mKCP 由 `tests/kcp.rs` 10 项
>   本机回环覆盖，不声称与官方客户端互通。
> - **VLESS Encryption**（2026-11-22）：Xray v26.10.31 客户端三场景通过
>   （valid / wrong-uuid / untrusted-certificate）。密钥不再需要手工填——
>   服务端 `decryption` 可确定性推导客户端 `encryption`（X25519 标量乘、
>   ML-KEM-768 种子展开），已用 `xray vlessenc` + `xray x25519 -i` 官方输出
>   逐字节核对。sing-box/Mihomo 的 VLESS 出站无该字段，用例显式跳过。
> - **REALITY**（2026-11-22）：Xray v26.10.31 客户端 valid / wrong-uuid
>   通过（TCP）。2026-11-23 复跑发现约 50% 概率失败，**已定位并修复**：
>   REALITY 要求 target 的加密 flight 形态满足 `RecordPlan`——首条
>   加密记录 `> 512` 字节时必须是 1 条聚合记录，否则必须正好 4 条
>   （EE / Certificate / CertificateVerify / Finished）。测试用的 target
>   发出恰好 512 字节的首记录，落进「必须 4 条」分支却只发了 1 条，
>   `collect_template` 一直等第 2 条直到握手超时。修复是让测试 target 用
>   带 2 KiB 证书扩展的证书，使首条记录稳定超过 512（不是放宽校验：
>   真实 CDN 的 flight 本就满足约束）。修复后连跑 10 次 10 通过。
>   **只对 Xray 生成用例，这不是偷懒而是协议事实**：
>   sing-box 的 `common/tls/reality_client.go` 主动把 X25519MLKEM768 从
>   `SupportedCurves`/`KeyShare` 里过滤掉，而本内核与 Xray 服务端都硬要求
>   该 hybrid share（缺了直接回落）；Mihomo 默认也移除，需非默认开关
>   `support-x25519mlkem768: true`。所以「三家 REALITY 矩阵」在协议层
>   不成立，不能写成三家都通过。
> - **REALITY 出站**（2026-11-22）：本内核出站 → 官方 Xray v26.10.31
>   REALITY 服务端，TCP 双向回显通过（`tests/reality_official_outbound.rs`）。
>   此前出站只有内核连内核的闭环，双方实现错误会互相抵消。
>   **排查中确认的一个上游行为**：Xray 的 `freedom` 出站对 vless 入站
>   默认应用 `defaultBlockPrivateRule`，即屏蔽 127.0.0.0/8 等私有地址。
>   本机回环测试必须给 freedom 配 `finalRules: [{action: allow, ip:
>   ["127.0.0.0/8"]}]`，否则会出现「REALITY 认证成功、服务端日志
>   accepted，但数据为零」的假象——这与内核实现无关，曾误判为内核缺陷。
> - **其余协议**（WireGuard、NW3 的官方二进制
>   方向）**只有本机回环测试**。正文中的「与官方客户端互通」均为历史人工
>   记录，当前工作区无可复现测试，亦无脚本可重跑。
>
> 判定标准与证据等级见 [上游事实核对](upstream-facts.md)。本文件下列各行的
> 状态已按此口径标注，未删除历史叙述但不再表示「已验收」。

## 代理协议与入口候选

| 能力 | 上游证据 | 目标客户端/用途 | 计划批次 | 当前状态/边界 |
|---|---|---|---|---|
| SOCKS5 CONNECT、UDP ASSOCIATE | Xray/SB S | 标准 curl TCP 客户端；独立 RFC UDP 测试端 | P1 | **有限兼容，已实测**；TCP/UDP、BIND、IPv4/IPv6/域名及资源回收见验收记录；不支持 UDP 分片 |
| Trojan over TCP+TLS（TCP/UDP 业务） | Xray/SB S；官方规格 D | Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31，macOS ARM64 官方构建 | P1 | **有限兼容，已实测**；TCP/UDP、错误密码与错误证书信任见互通报告；不含 fallback/包装/复用，无效认证直接关闭 |
| VLESS v0 + 标准 TLS，无 flow | Xray 固定请求/地址/UDP 源码 S | Mihomo v1.19.33 TCP/UDP；sing-box v1.14.4 / Xray v26.10.31 原生 TCP/UDP，macOS ARM64 | P2 | **有限兼容，已实测**；UUID/信任负向及构建证据见 [vless-acceptance.md](vless-acceptance.md) |
| VLESS + XUDP，仅 UDP 会话 | Xray Mux/XUDP、MetaCubeX sing-vmess 固定源码 S | Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31，macOS ARM64 | P2 | **有限兼容，旧 XUDP 路径已实测**；三家TCP/UDP两目标三报文、错误UUID及错误信任通过；内部多会话/隔离/回收见 [验收报告](vless-acceptance.md)。命令 3 现按上游语义路由到完整 Mux（TCP + xudp 门控的 UDP），**新 Mux 已实现待集中验收、未测试**，旧 XUDP 结论不推导 TCP Mux 兼容；GlobalID 跨承载 1 分钟续接已实现待集中验收 |
| Shadowsocks AEAD 2017 / 2022 | 固定规范、Xray/SB适配及Rust协议库源码 S | Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31，macOS ARM64；六单密钥方法及两AES单层EIH | P2 | **有限兼容，24项独立TCP/原生UDP互通全部通过，共60场景**；单密钥错误密码/合法长度错误PSK、EIH双用户及错误身份/未知用户均实测，负向零目标流量与零业务计量。同一新构建旧九项也全部通过，完整33项共87场景。macOS ARM64、Linux ARM64、Linux x86_64（QEMU）的Rust1.95普通回归各209通过/0失败/33忽略，vendor各25通过；Linux ARM64精确Rust1.91.0及1.91.1全目标check通过。x86_64使用编译器局部QEMU虚拟地址预留，有编译器探测警告，不是原生性能证明。范围与独立结果见[验收记录](shadowsocks-acceptance.md)及[依赖门禁](shadowsocks-dependency-gate.md)；另新增出站 `iPSK:uPSK` EIH 本机回环及与 sing-box v1.14.4 的 SS2022 EIH 本机 TCP 互通，但不扩称插件/多级 iPSK 中继链/官方全矩阵 |
| VMess AEAD 当前模式 | 固定Xray/sing-vmess及Mihomo实际依赖源码 S | 目标为Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31；Xray 双向 VMess/TLS 与 Mihomo 客户端 VMess/TLS TCP/UDP 已执行 | P2 | **已实现待集中验收（上述官方有限组合通过）**：security3/4、实际TLS或显式准许的5（wire5 非 Xray v26.10.31 上游组合，属扩展）、M/P及默认关闭A、TCP/原生UDP、命令3 Mux（TCP + xudp 门控的 UDP）和packetaddr；独立金样与受控回环不等于官方兼容。认证长度跨方向nonce、16位计数、空包/最大载荷及排除项见[VMess说明](vmess.md)，依赖见[门禁](vmess-dependency-gate.md) |
| Hysteria2 | SB D+C；Xray 当前文档 D | 对应 QUIC 客户端 | P3 | **已实现待集中验收**；新增 3 项本机回环测试（认证、TCP、UDP），并修复 `RecvMeta::stride` 死循环与认证后 h3 连接提前关闭；QUIC ALPN h3、HTTP/3 认证、TCP 流、UDP DATAGRAM 分片重组、salamander/gecko obfs；服务端 `up_mbps`/`down_mbps` 与客户端 `Hysteria-CC-RX` 协商，出站已接 `hysteria2.up_mbps/down_mbps`、认证后按 `min(服务端接收带宽, 本端上行)` 设置客户端 Brutal，并已与 sing-box v1.14.4 服务端本机 TCP 互通、与 Mihomo v1.19.33 及官方 sing-box v1.14.4 客户端完成入站 TCP/UDP 本机互通，sing-box 的 salamander/gecko obfs 也已完成 TCP/UDP；Brutal 已部分对齐：逐包 ACK、ACK 回调 RTT、quinn Cubic 委托完成；独立 pacer 与逐包 loss 仍受 quinn API 限制（见[核查](hysteria2-brutal-alignment.md)，`ignoreClientBandwidth` 回退 auto）；不实现 BBR profile、masquerade 的 proxy 类型、realm，见[说明](hysteria2.md) |
| TUIC | SB D+C | 对应 QUIC 客户端 | P3 | **已实现待集中验收**；新增 3 项本机回环测试（认证、TCP、UDP）；QUIC/TLS 1.3、UUID+TLS exporter 认证、TCP 中继、native datagram 与逐消息单向流两种 UDP 承载、分片与 Dissociate；入站与出站均支持 `congestion_control`（cubic/new_reno/bbr）及 `zero_rtt_handshake`（默认关闭，有票据才尝试early）；出站仅提前Connect元数据/Heartbeat，业务等完整握手及标准exporter认证写入，明确拒绝仅重建元数据流，不自动重放业务；见[开发记录](tuic-outbound-modern-development.md)；不实现已舍弃的 udp-over-stream，另与 Mihomo v1.19.33 与官方 sing-box v1.14.4 客户端完成入站 TCP/UDP 本机互通，见[说明](tuic.md) |
| NW3（Portal 入站） | 固定 Nowhere 3.3.0 源码 S（GPL-3.0-only 直接复用） | Anywhere/Nowhere 兼容客户端 | P4 | **已实现待集中验收，已通过全目标编译检查**；TLS 1.3 与 QUIC 同端口、ALPN `nw3`、共享密钥认证、Morph 默认开启、`tls=1` 自签名/`tls=2` 真实证书；Portal 自行绑定并自行出站，**不经过本内核 route/outbounds/统计/限额**；**Portal 的 `out` 出口选择已实现待集中验收**（`direct`/`egress`/SOCKS5 上游 `[USER:PASS@]HOST:PORT`，以及 `dial`/`rate`/`etar` 透传），**Egress 出口服务已实现待集中验收**（顶层 `nw3_egress`，主动连接远端 Portal 并注册为出口）；Vector TCP/UDP 出站已接入，支持上游显式 TLS/QUIC 载波；Portal 分离监听与多用户配置尚未开放；已用 vendored Nowhere 上游 Vector 客户端完成 5 项本机回环（Portal direct TCP/UDP、Portal Egress TCP/UDP、`nw3-vector` 出站 TCP），已用官方 Nowhere v3.3.0（macos/aarch64）完成 Vector→本内核 Portal、`nw3-vector`→官方 Portal 的 TCP/UDP 双向互通，以及官方 Egress 注册到本内核 Portal、本内核 `nw3_egress` 注册到官方 Portal 的 TCP/UDP 交叉组合（morph=1、真实证书 pin、UDP 显式 `/udp:PORT` QUIC 载体）；仍未做官方 Anywhere、Morph 认证负例、无可用 Egress 超时与多平台验证，见[说明](nw3.md) |
| HTTP CONNECT、Mixed | Xray/SB S | 标准代理客户端 | P5 | **已实现待集中验收**；CONNECT、绝对 URI 改写、Basic 认证、Mixed 端口探测与 SOCKS5 共用身份，见[说明](http.md)；无官方客户端矩阵 |
| Naive（TLS H1/H2/H3普通CONNECT） | 固定NaiveProxy发布与forwardproxy源码 S | 支持 Naive 的客户端 | P5 | **已实现待集中验收**；Basic认证，H2/H3按非空padding协商首8块PaddedData；`h3:true` 同端口TCP+UDP；本内核H1入站裸payload对齐固定forwardproxy，不外推sing-box。原生出站支持H1/H2/H3普通CONNECT、200/Basic/证书与ALPN校验，H1默认裸流或显式`h1_padding:true`对齐sing-box首8块，响应Padding无法自动区分；H2/H3协商首8块padding。显式UoT v2默认false，H1另需padding模式及支持UoT的上游。H1/H2可TCP链式，H3独立QUIC；Naive H2/H3入站识别正式UoT魔数，H1入站默认裸流不变，显式`h1_padding:true`另支持sing-box首8块及认证后UoT v2；见[H1入站记录](naive-h1-inbound-development.md)。连接池与Cronet/浏览器指纹等价未提供；见[说明](http.md)、[H2/H3历史记录](naive-outbound-development.md)与[H1记录](naive-h1-outbound-development.md)；已用 sing-box v1.14.4 Naive H2/H3 客户端完成 TCP 与 UoT v2 UDP 到本内核入站的本机互通（H3 使用 IPv6 回环），官方全矩阵与三平台未验收 |
| AnyTLS | 本地固定 `sagernet/sing-anytls` 源码 S | 支持该协议的客户端 | P5 | **已实现待集中验收**；真实 TLS、sha256 密码、握手 padding、多流、SYN/PSH/FIN/SYNACK/Settings/心跳；无原生 UDP，协议层 UoT v1/v2 目标可用；服务端支持可选`padding_scheme`原文及MD5下发，客户端默认30字节握手填充、正式Waste/stop/c及cmd6合法更新；每出站factory由TCP/UoT共享，输入/生成量有界；运行时另补默认空闲池、递增ID分派与持续控制帧，根/链式/TCP-UoT同池，整流FIN隔离、可配置30秒空闲检查/超时及最少保留、有限队列与热替换/停机回收，不擅改忙会话调度，无fallback，见[说明](anytls.md)、[padding记录](anytls-padding-development.md)与[池记录](anytls-pool-development.md)；Mihomo v1.19.33 与 sing-box v1.14.4 AnyTLS 客户端 TCP/UDP 本机互通通过，官方全矩阵与三平台未验收 |
| Snell v4/v5/v6 | 本地固定 `sagernet/sing-snell` 源码 S | 支持该协议的客户端与上游节点 | P5 | **入站与出站已实现待集中验收**；Argon2id/AES-128-GCM、CONNECT/CONNECT_V2/PING/UDP、v5 salt重放缓存；v6 default/shaped、unshaped、unsafe-raw。出站TCP按上游延迟核首应答，零块FIN与反向排空，UDP命令6逐目标会话/空包/双栈/容量及共享预算接线；TCP可链式；v4/v5入站与TCP/UDP-over-stream出站可选HTTP/TLS obfs，首头/记录有界且短写/取消保存状态，HTTP非WebSocket、TLS obfs非真实TLS，v6禁止叠加。TCP另有显式`reuse:true`顺序池（默认false），双向逻辑FIN后回池，10个空闲/等待项、180秒过期、30秒/0x80001字节排空边界；根与链中间跳先取池再拨号，UDP不取池，热替换/停机有界回收。QUIC未实现；本机证据见[基础出站记录](snell-outbound-development.md)、[obfs记录](snell-obfs-development.md)与[连接池记录](snell-reuse-development.md)，Mihomo v1.19.33 Snell v5 与 sing-box v1.14.4 Snell v4/v6 客户端 TCP/UDP 本机互通通过，v6 的 default/unshaped/unsafe-raw 三种 mode 与 v4 的 http/tls obfs 均已单独验证，官方全矩阵与三平台未验收 |
| ShadowTLS v3 | SB 显式入站/出站注册 S；固定 `sagernet/sing-shadowtls` v3 源码 S | 支持该协议的客户端与内层代理 | P5 | **入站与出站已实现待集中验收**；真实 TLS 握手伪装、HMAC-SHA1 认证、握手期 XOR/HMAC 与内层明文流；`detour` 仅支持同配置内 shadowsocks/snell/socks5/http/mixed/无TLS的vmess；新增 3 项服务端回环（认证经 detour 转发、未认证回落、SNI 映射）。出站为无目标 `type:"shadowtls"` detour：真实 TLS1.3（显式 CA/DNS SNI）、v3 SID/记录层、首个 ServerHello/HRR 一次性 seed、最小 rustls `allow_hrr` 放行；只能经另一 TCP 代理 `via` 引用且 endpoint 必须一致，不能终端路由/UDP，TLS1.2/ECH/early data/REALITY 叠加不支持；本机 SS-over-ShadowTLS、真实 HRR、错误密码、UDP 拒绝与配置负例已通过；另与官方 sing-box v1.14.4（darwin/arm64）双向本机互通通过（官方客户端→本内核服务端、本内核出站→官方服务端，v3+SS2022+真实 TLS1.3 伪装），期间修复连续多张 TLS1.3 NewSessionTicket 的旧链丢弃缺陷；另与 Mihomo v1.19.33 的 `ss + shadow-tls` 插件完成 TCP 本机互通（插件内 `skip-cert-verify`）；仅单版本/单平台/单配置形态，不是官方全矩阵验收；不支持 v1/v2 与内层 UDP；`handshake_for_server_name` 与 `wildcard_sni`（authed/all）已支持，见[说明](shadowtls.md) |
| WireGuard | Xray loader S；SB endpoint C | 端点/隧道能力 | P5 角色评估 | **出站与服务端入站均已实现待集中验收**；出站 boringtun + smoltcp、单 peer、TCP/UDP 经隧道、逐目标UDP与空包边界；服务端入站为 `type: "wireguard"` UDP 监听，boringtun responder + smoltcp 终止 TCP/UDP 后经 route/direct 转发，每 peer AllowedIPs 源 ACL，TCP/UDP 复用内核路由和已有上游中继，资源上限与空闲清理有界；空闲后保留重放保护，停机回收子任务；本机回环真实握手 + TCP/UDP echo 已通过，并用官方 sing-box v1.14.4 客户端完成外层回环、内层 10.66.0.x、helper 目标改写的 TCP/UDP 有限互通；多 peer/PSK/IPv6/异常路径未验收，见[出站说明](outbound.md)与[服务端说明](wireguard-server.md) |
| Hysteria 旧命名类型（v1） | SB 文档 D+C | 不适用 | 不做 | **明确不支持**（2026-11-06 决定只实现 Hysteria2）；旧 v1 协议已弃用，不纳入范围 |

## 传输、安全与协议扩展

| 能力 | 研究状态与约束 | 批次 |
|---|---|---|
| TCP + 标准 TLS | 已实现 rustls TLS 1.2/1.3，库测试及指定官方客户端正常验证证书；不自行实现密码学 | P1 已验收 |
| VLESS Vision + 标准 TLS1.3 | **开发实现，待集中验收**；用户flow、双向End/Direct及命令 3 Mux（TCP + `xudp` 门控 UDP，Vision body）已接入，本地真实内层TLS1.2/1.3和raw交接测试通过；Xray v26.10.31 双向 VLESS Vision、Mihomo v1.19.33 与 sing-box v1.14.4 客户端 VLESS Vision TCP/UDP 已通过，三平台结果尚无，不能沿用旧验收扩称兼容，见[Vision说明](vision.md)及[Mux说明](mux.md) | P2，必要本地检查先行，完整矩阵能力簇收尾 |
| REALITY + VLESS/VMess/Trojan | **服务端已实现待集中验收，21/29；出站已增量接入**；独立 vless-reality/vmess-reality/trojan-reality RAW 入口、普通/混合组、可选ML-DSA、有限模板/固定回落、VLESS TCP/UDP/Vision独立端已验证；VMess/Trojan RAW REALITY 复用各自认证与转发并已加入本机回环；REALITY 现可作为三协议 gRPC、XHTTP 的安全层（与证书互斥，XHTTP h3 除外）；与上游一致，WebSocket/HTTPUpgrade 不组合 REALITY。`vless`/`vmess`/`trojan` 出站可配置 `reality`，支持 X25519 与 X25519MLKEM768，可选 `mldsa65Verify` 校验服务端 ML-DSA-65 扩展，仅允许 RAW/gRPC/XHTTP，VLESS Vision 可与 REALITY 组合；本机 VLESS 纯 TCP（两种目标组）、VLESS Vision+REALITY、VLESS 原生 UDP、ML-DSA 校验与三协议 REALITY-over-gRPC 回环通过，WS/HTTPUpgrade 组合拒绝；与官方 Xray v26.10.31 完成 VLESS REALITY（无 flow 与 Vision）、VMess REALITY、Trojan REALITY 的双向 TCP 本机互通，期间修复 Ed25519 signature_algorithms 与目标 record 尺寸两处兼容缺陷；VLESS/VMess/Trojan 的 REALITY-over-gRPC 与 REALITY-over-XHTTP 双向均已通过，Xray VMess/Trojan REALITY-over-XHTTP 的 UDP 也已到本内核入站通过，三平台/MSRV/release 未验收，见[REALITY说明](reality.md)和[开发记录](reality-development.md) | P2，集中验收后置 |
| VLESS Encryption | **入站与出站均已实现待集中验收，已通过全目标编译与库测试**；入站为 `vless` TLS 明文路径，出站为 `vless` 的 `encryption` 字段；`native`/`xorpub`/`random`、X25519/ML-KEM-768 中继链、1-RTT/0-RTT 票据与 padding；TCP 与原生 UDP 出站均已回环；与 `fallbacks` 互斥；Vision flow 已可组合；入站已接入 REALITY（RAW/gRPC/XHTTP）及 WS/HTTPUpgrade/QUIC/mKCP/HTTP 承载（本机验证 WS/gRPC）；已与官方 Xray v26.10.31 X25519/ML-KEM-768 认证对完成 VLESS/TLS 双向本机互通，官方客户端 `.0rtt` 重连已实际进入 0-RTT（1232→32 长度块并被票据缓存接受），三平台/MSRV/release 未验收，见[说明](vless-encryption.md) | P2，独立验收 |
| WebSocket / WSS（HTTP/1.1） | **已实现待集中验收，19/27**；同输入30条开发命令全部0，577次测试执行通过、7忽略不计通过。三协议独立入口及header/custom/path early-data已接入；VLESS无flow TCP/原生UDP/显式XUDP、VMess AEAD含UDP扩展、Trojan TCP/UDP；Xray 双向 VLESS/WSS 与 Mihomo 客户端 VLESS/WSS TCP/UDP 已通过。Close不提供通用透明半关闭；其余组合没有本批官方矩阵，见[说明](websocket.md)及[开发记录](websocket-development.md) | P2，集中验收后置 |
| gRPC（HTTP/2） | **已实现待集中验收，开发14/33**；三协议独立入口`vless-grpc`/`vmess-grpc`/`trojan-grpc`，single与multiMode、明文prior-knowledge与真实TLS(ALPN h2)已接通；TCP/原生UDP/XUDP/packetaddr/Trojan逐包UDP复用既有实现。本地25项入站测试通过，边界见[gRPC说明](grpc.md)；与官方 Xray v26.10.31 完成 VLESS（single/multiMode）、VMess、Trojan 的 gRPC/TLS 双向 TCP 本机互通、Xray VLESS/gRPC TLS XUDP（single/multiMode）到本内核入站的 TCP/UDP，以及 VLESS/REALITY-over-gRPC 双向（出站改为响应头惰性等待，Trojan 服务端补 h2 ALPN），完整官方矩阵、三平台/MSRV/release 未验收 | P2，集中验收后置 |
| XHTTP | **已实现待集中验收**；三协议独立入口，auto/stream-one/stream-up/packet-up、h1 chunked、h2/h2c、真实TLS、headers/cookie、会话TTL与上限；本地13项入站测试通过，边界见[XHTTP说明](xhttp.md)；另新增 XHTTP/3（QUIC，`xhttp.h3: true`）承载，复用同一会话与模式语义，已编译并新增2项本机 h3 回环测试（stream-one、packet-up）；与官方 Xray v26.10.31 完成 VLESS/XHTTP TLS 四种模式、VLESS/REALITY-over-XHTTP 双向本机互通，以及 Xray VLESS/XHTTP TLS 四种模式的 XUDP 到本内核入站 TCP/UDP（服务端 `xudp:true`；`xudp:false` 时 UDP 按设计关闭）（修复 Referer/原文 padding、GET 先建会话、尾斜杠），sing-box/平台/MSRV/release 未验收 | P2 按组合分批 |
| HTTPUpgrade | **已实现待集中验收**；三协议独立入口，一次性 Upgrade 后裸字节流、early data、TLS 仅 http/1.1 ALPN；本地6项测试通过；与官方 Xray v26.10.31 完成 VLESS/HTTPUpgrade TLS 双向本机互通及 Xray XUDP UDP 到本内核入站，VMess/Trojan 与三平台/MSRV/release 未验收，见[HTTPUpgrade说明](httpupgrade.md) | P2 按组合分批 |
| QUIC stream / DATAGRAM | Nowhere 关键运行机制已读，不代表 TUIC/Hysteria2 可直接复用其状态机 | P3/P4 |
| XUDP、TCP mux、UoT | VLESS XUDP 的 UDP 会话已完成有限外部验收；UoT（VLESS/VMess）已实现待集中验收，见[uot.md](uot.md)；**Mux.Cool（VLESS/VMess 命令 3 与 `v1.mux.cool` 目标，TCP + xudp 门控的 UDP，含 GlobalID 跨承载 1 分钟续接；未复刻 Xray 对 Vision 账号拒绝非 XUDP TCP Mux 的 `isMuxAndNotXUDP` 限制，GlobalID 跨承载为本实现选择、不等同上游承诺）已实现待集中验收、未测试**，见[mux.md](mux.md)，不能由 XUDP/UoT 推导支持 | 随所属协议 |
| Nowhere Prelude / Morph / 认证 | 已读接入调用路径而非完整算法，NW3 Core 不包含全部实现扩展 | P4 |
| VLESS/Trojan fallback 子集 | **已实现待集中验收**；认证失败回放已消费字节、`dest`（裸端口、`host:port`、Unix 套接字绝对路径）/`xver` 0-2/`name`/`alpn`/`path` 匹配与通配回落、4096 字节回放上限 fail-closed；Unix 目标复用同一拨号/超时/PROXY 头路径并有本机回环测试；无VMess/REALITY fallback，见[fallback说明](fallback.md) | P2/P5 |

## 公共运行与服务端拓扑

| 能力 | 计划 |
|---|---|
| Direct/Reject、DNS、路由、日志/计量、有限资源和停机 | P1 的 Direct/Reject、系统 DNS、最小路由、日志/计量、有限资源和停机已验收；**已实现待集中验收**的扩展子集：顶层 `dns.servers`/`dns.hosts` 与路由 `domain_suffix`/`domain_keyword`。范围与默认值见 usage.md，不等价于上游全量运行能力 |
| 更丰富 DNS、规则集、解析后 IP 策略、嗅探、路由动作 | **部分已实现待集中验收**：顶层 `dns.servers`（UDP/DoT/DoH）/`dns.hosts` 与 `dns.rules` 域名分流，路由 `domain_suffix`/`domain_keyword` 与 `domain_strategy` 解析后 IP 规则；顶层 `sniffing` 在 VLESS 明文 TCP、VMess TCP、Trojan TCP、SOCKS5 CONNECT、Shadowsocks TCP（含 ShadowTLS 内层）识别 TLS SNI / HTTP/1.1 Host，默认只影响路由，`dest_override` 才改写拨号目标；dokodemo-door 保留其独立嗅探字段；UDP 关联对 QUIC v1/v2 Initial 解密取 SNI，只用于选路；DNS 已支持顺序失败回落与规则的 `race` 并发查询（首个成功结果生效），仍未实现完整 sing-box 规则动作引擎（evaluate/speculative/optimistic cache）；QUIC 0-RTT/非 Initial 包仍不嗅探、路由动作（block/route 等），不能标为等价于两家全量能力 |

## 出站、隧道与反向角色

| 能力 | 上游证据/实现 | 用途 | 批次 | 状态与边界 |
|---|---|---|---|---|
| 反向 Mux（Portal/Bridge） | Xray `app/reverse` S | Xray Bridge | P5 | **已实现待集中验收**；VLESS 命令 4 建立 Mux 客户端隧道，`reverse` 出站按目标打开会话；顶层 `reverse_bridges` 通过引用标准 VLESS 出站主动拨入 Portal 并运行 Mux 服务端，断线重连；每隧道 256 会话、每 portal 64 隧道，5 秒 Control 心跳；Mux 隧道支持 TCP/UDP 会话；account 级安全限制未实现；本机明文 TCP、Vision 命令 4 与 Mux UDP 回环 4 项通过，见[说明](reverse.md) |
| WireGuard 出站 | boringtun 0.7.1（BSD-3-Clause，Noise_IK）+ smoltcp 0.14.0（0BSD，用户态 IP/TCP/UDP 栈） | WireGuard 服务端（标准 UDP 51820） | P5 | **已实现待集中验收**；单 peer、IPv4/IPv6 隧道本地地址、可选 PSK/MTU/持久保活；TCP/UDP 经隧道，UDP逐目标socket与MTU检查；已有TCP与新增UDP双目标/空包/IPv6、错误密钥和资源回收本机测试；未与官方 WireGuard 实现、三平台或 MSRV 验收，见[说明](outbound.md) |
| 上游代理出站（SOCKS5 / HTTP / Naive / Snell / VLESS / VMess / Trojan / Shadowsocks / AnyTLS / ShadowTLS / Hysteria2 / TUIC / NW3 Vector / WireGuard ）与出站组 | **已实现待集中验收**；TCP 单跳与多跳链式转发；ShadowTLS v3 作为无目标 detour，仅经 `via` 与内层 TCP 代理组合，endpoint 必须一致且不能终端/UDP；SOCKS5 支持无认证与用户名/密码、UDP 经 UDP ASSOCIATE 中继（每关联最多一个上游，控制连接保活，`FRAG != 0` 丢弃）；VLESS（无 flow 或 Vision flow）、VMess AEAD（security 3/4）、Trojan 必须 TLS 或 REALITY、Shadowsocks AEAD（含 2022）与 AnyTLS 均支持 TCP；VMess 新增命令 2 固定目标原生 UDP（每目标一条隧道），VLESS（每目标隧道）、Trojan（逐包目标）、Shadowsocks（AEAD UDP）、Hysteria2 与 TUIC（QUIC DATAGRAM）支持原生 UDP，AnyTLS 通过 UoT v2 承载 UDP，Naive H2/H3及显式padding H1可启用UoT v2（默认false），其TCP支持H1/H2链式，H1裸/填充需显式匹配上游；Snell TCP/UDP-over-stream及顺序池另见协议行；HTTP 的 UDP **失败关闭**，WireGuard/NW3 Vector 已补UDP（逐目标会话，MTU/上游容量受限）；可选到上游的 TLS（显式 PEM 信任锚）与 VLESS/VMess/Trojan 的 WebSocket/WSS、gRPC（single/multi、TLS ALPN h2）、HTTPUpgrade、XHTTP（h1/h2/h3）、mKCP 与 QUIC 包装；`tests/outbound_protocols.rs` 20 项、`tests/outbound_udp.rs` 13 项、`tests/kcp_outbound_client.rs` 7 项、`tests/quic_outbound_client.rs` 5 项、`tests/xhttp_outbound_client.rs` 6 项与 `tests/outbound_transport_config.rs` 6 项本机回环/配置用例通过（含 VLESS Vision、WS/WSS、gRPC、XHTTP H1/H2/H3、六协议原生 UDP、AnyTLS UoT、Hysteria2/TUIC 分片与 native/quic、mKCP、V2Ray QUIC 与双跳链式）；出站组 `selector` 静态选择、`urltest` 周期 TCP 探测延迟切换（容差防抖、全部失败保持当前、成员不得嵌套 urltest）；无 BIND，见[说明](outbound.md) |

## 其他运行能力

- **Xray 的 VLESS 反向机制有两套，并存，不是新旧替代**（2026-11-23 核对 v26.10.31）：
  - `app/reverse`：`tunnel` 入站 + Portal/Bridge，固定域名 `v1.rvs.cool`；
    该模块在 v26.10.31 仍存在（`app/reverse/`），源码内无 deprecation 标记，
    实机加载 `tunnel` 入站也不产生弃用警告。**它不是「已废弃」**。
  - `users[].reverse: {tag}`：VLESS **命令 4**（`RequestCommandRvs = 0x04`），
    由官方文档《VLESS Reverse Proxy Examples》推荐，配置上把 `reverse.tag`
    分别呈现为出站（公网侧）与入站（内网侧）。
  本项目已实现命令 4 的 Portal 与 Bridge（见 `docs/reverse.md`）：
  - Portal 侧现在**同时接受** Xray 的 `users[].reverse.tag` 写法与既有的
    顶层 `reverse_bridges`；前者在配置解析阶段校验 tag 必须指向 `reverse` 出站。
  - 2026-11-23 用官方 Xray v26.10.31 作为 Bridge 主动拨入本内核 Portal，
    三次连续请求均双向回显通过（`tests/reverse_official_bridge.rs`）。
    该用例的 Portal 配置**故意不配 `v1.rvs.cool` 路由规则、默认路由指向
    `direct`**，因此只有真正读取了 `reverse.tag` 才能建立隧道。
- **Nowhere Portal/Egress**：源码 S；服务端角色包含主动回连，不需要开发终端用户 Vector 客户端
- **热更新、证书管理、管理接口**：**证书轮换已实现待集中验收**：SIGHUP 在配置内容不变时只原子替换 TCP/TLS 入口证书，不重启监听、已建立连接保持原证书。**零停机配置热重载已实现待集中验收**：入口/limits/API/NW3 Egress 未变化且无 UDP 监听器时原子替换路由、DNS、嗅探与出站配置，既有连接保持旧快照；监听器/limits 变化、反向 portal 或 UDP 入口仍完整重启。QUIC/mKCP/REALITY/ShadowTLS 证书不在此范围。管理/统计 API 提供 `/healthz`、`/stats`、`GET /connections` 与 `DELETE /connections/{id}`/`DELETE /connections`（活动 TCP 连接，含目标元数据与关闭句柄）；面板 API 的完整兼容仍属后续设计，内部原生能力不等于兼容所有面板 API
- **Linux x86_64/ARM64**：当前Shadowsocks构建两平台各209项普通测试及vendor25项通过，见[本批验收](shadowsocks-acceptance.md)；此前VLESS/XUDP两平台各117项是独立历史，见vless-acceptance.md。x86_64使用QEMU及编译器局部环境修正；平台普通测试不扩大为外部客户端互通矩阵或原生性能证明

## 已发现但不能静默扩大范围的项目

- 客户端 TUN、系统代理接管、终端进程/MAC 识别、UI：用户明确只做服务端，不纳入终端客户端产品范围。TUN/tproxy/redirect 本身是流量接入机制，不是远端代理协议。
- sing-box 的 SSH/Tor 见于出站表：不得虚构为其入站协议；需要服务端链式出口时再定义对应范围。
- DERP、Hysteria Realm、Cloudflared 以及 OpenConnect/OpenVPN/Tailscale endpoint：保持待分类，先核查服务端职责与构建条件。
- API/SSM API 可属于管理适配；resolved、CCM、OCM、OOMKiller、USBIP 等周边服务不能仅因出现在上游仓库就自动承诺全部实现。
- ShadowsocksR 与旧 WireGuard outbound 的报错 stub 不算能力；已废弃能力不作为保留目标。
- 客户端配置、订阅格式、分享链接及管理 API 的完全兼容未被用户列为核心需求，不能与协议互通混同。

## 已读注册清单（用于后续防遗漏，不等于产品承诺）

**Xray 配置 loader，S：**

- 入站：`tunnel/dokodemo-door`、`http`、`shadowsocks`、`mixed/socks`、`vless`、`vmess`、`trojan`、`wireguard`、`hysteria`、`tun`。
- 出站：`block/blackhole`、`loopback`、`direct/freedom`、`http`、`shadowsocks`、`socks`、`vless`、`vmess`、`trojan`、`hysteria`、`dns`、`wireguard`。
- 斜线表示该配置 loader 共用构造器的别名，不表明所有运行语义相同。最终二进制构成仍需构建变体核查。

**sing-box 显式注册，S：**

- 入站：`tun`、`redirect`、`tproxy`、`direct`、`socks`、`http`、`mixed`、`shadowsocks`、`snell`、`vmess`、`trojan`、`naive`、`shadowtls`、`vless`、`anytls`。
- 出站：`direct`、`bridge`、`block`、`selector`、`urltest`、`socks`、`http`、`shadowsocks`、`snell`、`vmess`、`trojan`、`tor`、`ssh`、`shadowtls`、`vless`、`anytls`。
- service：`api`、`resolved`、`ssm-api`。
- 条件注册 C：入站 QUIC/Cloudflared，出站 QUIC/Naive，endpoint WireGuard/OpenConnect/OpenVPN/Tailscale，service QUIC/DERP/CCM/OCM/OOMKiller/USBIP；未展开具体构建条件。

## 每项验收必须补齐的记录

每个兼容单元保存：协议/扩展版本、入站或出站/服务角色、传输/安全组合、TCP/UDP、客户端名称/版本/构建校验、上游提交、本项目构建、平台、测试命令、成功和负向结果、已知限制。缺失的记录保持未验证；配置被识别、编译成功、自有双方互测均不能单独证明对外兼容。
