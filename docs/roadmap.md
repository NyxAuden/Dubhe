# 分阶段实施路线

状态日期：2026-11-12。P0–P2 主体已落地：VLESS 基础 TLS/XUDP 与 Shadowsocks 指定组合已验收；Vision、VMess、REALITY、WS/WSS、gRPC、XHTTP/HTTPUpgrade、HTTP/Mixed、Naive、fallback、AnyTLS、UoT、Mux.Cool、Snell、Hysteria2、TUIC、ShadowTLS、NW3 Portal/Egress 均“已实现待集中验收”。P3–P5 已补 WireGuard 出站、VMess 出站原生 UDP、反向 Mux Portal/Bridge（含 TCP/UDP）与出站 XHTTP/mKCP/QUIC 包装；已补 WireGuard 用户态服务端代理角色；已补 WireGuard/NW3 Vector 出站 UDP，随后补Naive H3、Snell出站与TUIC出站CC/早期握手；仍需补齐其他正式协议角色、Brutal精确对齐、路由/DNS深度和系统级入口。用户已确认独立服务端、Rust 核心、协议模块扩展、分阶段交付和持续跟进上游；后续批次是路线，不是假称已完成的成果。

## P0：范围与可执行规格（已完成）

- 固定研究基线，读取关键结构而不是宣称全面源码审计。
- 建立领域词汇、兼容矩阵、架构设计和首个 OpenSpec change。
- 严格区分规划与实施；任务只有在行为实现并有验收证据时才勾选。

## P1：首个实际可运行的闭环（已完成）

对应 `establish-server-kernel-foundation`，不是只建立目录：

1. Rust 库与 CLI、严格原生 JSON 配置、生命周期及资源预算。
2. Direct/Reject、系统 DNS、最小路由、TCP 半关闭与 UDP 关联。
3. SOCKS5 TCP/UDP 作为诊断入口，不默认暴露无认证公网代理。
4. Trojan/TLS TCP/UDP，使用 Mihomo、sing-box、Xray 客户端模式做真实互操作。
5. 配置错误、认证失败、超时、并发限制、停机和资源清理测试。

选择 Trojan/TLS 的原因：能同时验证成熟客户端生态、TLS、认证、TCP、UDP 和公共转发层；不会先被 REALITY/Vision 的底层接口限制卡住。首版没有 fallback 和传输包装，必须公开限制，不宣称完整 Trojan 上游能力等价。

完成标准：不是能编译，而是规格场景与固定客户端矩阵的结果真实记录；平台缺失或跳过的项目不得算通过。

本阶段结果：macOS ARM64、Linux ARM64 和 Linux x86_64（QEMU）各 73 项普通测试通过；三个固定 macOS 官方客户端分别完成 Trojan TCP/UDP 互通和负向测试。构建与测试证据见 [验收记录](acceptance.md)，细分兼容范围见 [互通报告](interop-report.md)。未进行正式发布、生产部署或长期稳定性验收；OpenSpec 变更未自动归档。

## P2：主流协议与高耦合能力尽早验证

`add-vless-tls-inbound`已14/14完成有限验收，见[VLESS验收](vless-acceptance.md)；`add-shadowsocks-aead-inbound`已40/40完成指定六方法/双AES单层EIH验收，见[Shadowsocks验收](shadowsocks-acceptance.md)，均未归档。

`add-vless-vision-tls-inbound`开发段18/27已完成，新增用户flow、受控TLS记录及双向Continue/End/Direct；命令 3 现复用完整 Mux.Cool（TCP + `xudp` 门控 UDP），见[Mux说明](mux.md)。随后`add-vmess-aead-inbound`已接入AEAD头/正文、可选TLS、原生UDP及显式packetaddr/XUDP，详见[VMess说明](vmess.md)；其最终9项集中验收仍待执行。本地开发验证与真实内层TLS测试不等于官方客户端兼容证据，详见[Vision说明](vision.md)。按2026-11-05确认的节奏，集中实现多个模块，开发中保留必要编译、认证/数据/资源检查；昂贵三平台全量、固定客户端大矩阵及交付报告留到能力簇收尾。开发段完成即可继续下个已规划模块，未运行的最终验收保持待完成，不必每协议重复等待全套验收。

- 尽早做 VLESS + REALITY + Vision 的有界可行性验证：核实可用 TLS 后端、握手状态及底层连接访问要求，避免主架构冻结后返工。
- 分独立变更实现 VLESS 的有效基础组合、Shadowsocks 当前 AEAD/2022 组合、VMess 当前兼容模式。
- WebSocket/WSS已接入VLESS无flow、VMess AEAD及Trojan，含显式header/path early-data；已实现待集中验收（19/27），同输入30条开发命令全部退出0；说明与证据见[WebSocket](websocket.md)和[开发记录](websocket-development.md)。
- gRPC已接入三协议独立入口，含single/multiMode、明文prior-knowledge/真实TLS及既有TCP/UDP/XUDP/packetaddr；开发段14/33，本地25项入站测试通过，边界见[gRPC说明](grpc.md)；已与官方 Xray v26.10.31 完成 VLESS（single/multiMode）、VMess、Trojan 的 gRPC/TLS 与 REALITY-over-gRPC 双向本机互通，三平台/MSRV/release集中验收未做。XHTTP（三协议，auto/stream-one/stream-up/packet-up，h1/h2/h2c，真实TLS）与HTTPUpgrade（三协议）已接入，均为**已实现待集中验收**，本地13项与6项入站测试通过，见[XHTTP说明](xhttp.md)、[HTTPUpgrade说明](httpupgrade.md)。XHTTP/3（QUIC）已接入同一入口的 `xhttp.h3` 开关，依赖 `h3 =0.0.8`/`h3-quinn =0.0.10` 固定源码；已编译并通过 2 项本机 h3 回环测试（stream-one 与 packet-up），官方客户端/三平台/MSRV/release 集中验收未做。之后继续复用/UDP封装；每种组合单独列兼容单元，不建立任意层排列组合的承诺。
- REALITY/Vision 的性能优化与线协议正确性分开验收，不用缺少零拷贝等价推导为协议不能互通，也不声称普通 TLS 库天然兼容。
- 不给整个批次一个模糊“全支持”标记；每个模块单独可发布。

## P3：QUIC 原生服务端

- Hysteria2、TUIC 分别实现；共享适合共享的 QUIC 资源管理，不共享协议本身的认证状态机。服务端模块与运行入口已接入，状态为“已实现待集中验收”；两者原有各3项本机回环测试（认证/TCP/UDP），Hysteria2测试同时修复了UDP socket stride死循环与认证后h3连接提前关闭两个缺陷。TUIC入站与出站已接真实cubic/new_reno/bbr与默认关闭的显式0-RTT；出站仅提前Connect元数据/Heartbeat，完整握手后标准exporter认证，不自动重放业务，见[开发记录](tuic-outbound-modern-development.md)。Hysteria2完整Brutal逐包/pacing仍未完成，其余rade proxy/realm等边界见[hysteria2说明](hysteria2.md)与[tuic说明](tuic.md)。
- 验证 DATAGRAM、流控、分片、重组、会话归属、丢包/重连和有限资源行为。
- 拥塞控制与非标准 QUIC 行为单独研究并纳入验收，不能用默认 Quinn 替代后宣称全部等价。

## P4：Nowhere / Anywhere 互通

- NW3 TLS 与 QUIC 基础、认证与 Prelude/扩展：**Portal 入站已复用 Nowhere 3.3.0 的 GPL-3.0-only 源码实现待集中验收，已通过全目标编译检查**，TLS 1.3/QUIC 同端口、共享密钥认证、Morph 默认开启、自签名或真实证书，见[nw3 说明](nw3.md)。Portal 自行绑定并自行出站（默认直连，可 `out=egress` 或 SOCKS5 上游），不经过本内核 route/stats/limits。
- Egress 出口服务（顶层 `nw3_egress`）**已实现待集中验收，已通过全目标编译检查**：复用 Nowhere 3.3.0 的 Egress，主动连接远端 Portal、注册、拨出目标并断线重连；不经过本内核路由/统计。Portal 的 `out` 出口选择同样**已实现待集中验收**（`direct`、`egress`、SOCKS5 上游 `[USER:PASS@]HOST:PORT`，并透传 `dial`/`rate`/`etar`）；Vector 客户端与 Anywhere 侧未实现/未验证，见[nw3 说明](nw3.md)。
- 在实现协议的同时核查可获得的 Anywhere 构建与连接配置；测试缺失时明确未验证。
- NW3 Core、Portal 扩展和 Egress 作为不同兼容单元，先完成一项不代表全部完成。
- 当前以 `vendor/nowhere` 整包复用的方式接入 Portal 与 Egress，尚未拆分公共库；后续若要把 NW3 接入本内核路由/统计，需要抽取协议层而非继续整包嵌入。

## P5：扩大服务端覆盖与运维能力

- 根据上游角色与实际行为补齐 AnyTLS、ShadowTLS、Snell、WireGuard 等候选；以当前稳定版本事实为准，不根据名称直接认定支持范围。AnyTLS、Snell v4/v5 与 ShadowTLS v3 服务端已实现待集中验收（ShadowTLS 新增 3 项服务端本机回环测试：认证经 detour 转发、未认证回落、SNI 映射；出站另补无目标 `shadowtls` v3 detour、真实 TLS1.3/HRR、SS-over-ShadowTLS 与错误密码/终端/UDP/链不匹配失败关闭，见[说明](shadowtls.md)）；Snell v6 已接入 default/shaped、unshaped/unsafe-raw，并补v4/v5/v6 TCP及正式UDP-over-stream出站（逐目标/空包/双栈/预算，TCP链式和延迟首应答）；v4/v5入站与TCP/UDP-over-stream出站另补正式HTTP/TLS obfs（非真实TLS/WS，v6禁止叠加），见[obfs开发记录](snell-obfs-development.md)；另补默认关闭的TCP顺序连接池（双向零块、10项/180秒、有界排空、链式/热替换/停机），见[连接池记录](snell-reuse-development.md)；QUIC仍未完成，见[snell 说明](snell.md)和[基础出站记录](snell-outbound-development.md)；AnyTLS另补正式padding解析/生成、cmd6更新、TCP/UoT每出站共享factory与服务端自定义方案，另补默认空闲会话池与正式ID分派/控制帧、整流FIN、根/链式/TCP-UoT共池及有界空闲/停机回收，见[说明](anytls.md)、[padding记录](anytls-padding-development.md)与[池记录](anytls-pool-development.md)；ShadowTLS 仅支持 v3、`detour` 限于同配置明文 TCP 入站，见[说明](shadowtls.md)。
- VLESS Encryption（`mlkem768x25519plus`）**服务端已实现待集中验收，已通过全目标编译检查**：`vless` 入站明文 TCP/TLS 及 REALITY、WS、gRPC、XHTTP、HTTPUpgrade、mKCP、QUIC 承载，`native`/`xorpub`/`random`、X25519/ML-KEM-768 及中继链、1-RTT/0-RTT 票据与 padding；与 `fallbacks` 互斥；Vision flow 已可组合。实现基于 `ml-kem`/`ctr`/`aes-gcm`/`chacha20poly1305` 与 `vendor/blake3` 补丁，未自研密码学，见[说明](vless-encryption.md)。
- HTTP/Mixed、Naive 已实现待集中验收（见[说明](http.md)）；Naive 已补显式 `h3:true` 同端口普通CONNECT，H2/H3首8块padding及短写/取消/FIN、共享流与连接预算、慢头隔离和阻塞停机已有本机证据（见[开发记录](naive-h3-development.md)）。本内核H1入站裸流对齐固定forwardproxy，但sing-box v1.14.4 H1实际使用padding，不能一概而论。原生Naive H2/H3出站的普通CONNECT、Basic/TLS/ALPN、首8块padding及可选UoT v2见[历史记录](naive-outbound-development.md)；另补H1原生出站，默认裸流、显式`h1_padding`对齐sing-box首8块，H1 UoT需padding模式和支持UoT的上游，不改变默认裸H1入站；后续入站另补显式`h1_padding:true`的sing-box正式填充和UoT v2，见[入站记录](naive-h1-inbound-development.md)。H1/H2可TCP链式，H3独立QUIC；共享HTTP池仍待补，不等价Cronet指纹，当前验证进度见[H1记录](naive-h1-outbound-development.md)。VLESS/Trojan fallback 稳定子集已实现待集中验收（见[说明](fallback.md)）。
- 服务端上游出站 **已实现待集中验收**：SOCKS5 CONNECT/UDP ASSOCIATE、HTTP CONNECT、VLESS（含 Vision flow）/VMess/Trojan/Shadowsocks/AnyTLS/ShadowTLS v3 detour/Hysteria2/TUIC/WireGuard；TCP 支持单跳与多跳链式，VMess 新增固定目标原生 UDP（每目标一条命令 2 隧道），AnyTLS 新增 UoT v2，Hysteria2/TUIC 新增 QUIC DATAGRAM UDP；VLESS/VMess/Trojan 支持 WS/gRPC/HTTPUpgrade/XHTTP(h1/h2/h3)/mKCP/QUIC 承载；HTTP 的 UDP 失败关闭，WireGuard/NW3 Vector UDP 已接入，按目标隔离且受MTU/上游容量限制；见[出站说明](outbound.md)。出站组 **`selector`（静态）与 `urltest`（周期探测延迟切换）已实现待集中验收**，含成员递归解析、循环拒绝、探测失败保持当前成员与容差防抖动；开发期单元与回环切换测试已运行。**证书轮换已实现待集中验收**：SIGHUP 在配置内容不变时只原子替换 TCP/TLS 入口的证书与私钥，不重启监听、不中断既有连接；配置变化、QUIC/mKCP/REALITY/ShadowTLS 证书仍走完整重启。**零停机配置热重载已实现待集中验收**：入口、`limits`、API 与 NW3 Egress 未变化且没有 UDP 监听器时，SIGHUP 只原子替换路由、DNS、嗅探与出站配置（含重启 urltest 探测），已建立连接继续使用握手时的快照；监听器/limits 变化、存在反向 portal 或 UDP 入口时仍走完整重启。**WireGuard 出站已实现待集中验收**：boringtun + smoltcp，TCP/UDP 经隧道，UDP固定目标socket，见[出站说明](outbound.md)。**反向 Mux Portal/Bridge 已实现待集中验收**：VLESS 命令 4 建立 Mux 客户端隧道，普通流量经 `reverse` 出站打开会话；顶层 `reverse_bridges` 引用标准 VLESS 出站主动拨入 Portal 并运行 Mux 服务端，断线按 `reconnect_ms` 重连；含 Control 心跳与有界会话/隧道上限，本机明文 TCP、Vision 命令 4 与 Mux UDP 回环通过，见[反向 Mux 说明](reverse.md)。**已实现待集中验收**：DoT/DoH 与 `dns.rules` 域名分流、`domain_strategy` 的解析后 IP 规则、SIGHUP 配置/证书热重载、受保护的管理/统计 API（含活动 TCP 连接列表与按连接关闭）；dokodemo-door 的 TCP/UDP 固定目标转发与 TCP 首包嗅探（TLS SNI / HTTP/1.1 Host，仅该入站）；DNS/路由子集：顶层 `dns.servers`/`dns.hosts`、`dns.rules`（含 `race` 并发查询），路由 `domain_suffix`/`domain_keyword`。**全站首包嗅探已实现待集中验收**：顶层 `sniffing` 覆盖 VLESS 明文 TCP、VMess TCP、Trojan TCP、SOCKS5 CONNECT 与 Shadowsocks TCP，默认只影响路由、`dest_override` 才改写拨号目标，UDP 关联另支持 QUIC Initial SNI 选路；Mux.Cool 的 TCP 子流、xudp 数据报、Vision/REALITY 内层流与 QUIC 合并包已纳入同一策略，见[嗅探说明](sniffing.md)。
- WireGuard 服务端**已接入、待集中验收**：复用既有 boringtun + smoltcp，提供 UDP 入站、受让源地址 ACL、用户态 TCP/UDP 终止与内核路由/上游中继。空闲清理不重置重放高水位，停机取消拨号并回收子任务；模块17项与Config/runtime 3项本机测试通过，见[说明](wireguard-server.md)。两者都是用户态代理角色，非完整 L3 VPN，不修改系统网络；官方客户端、三平台、精确MSRV/release另行验收。
- DERP、Realm 等辅助服务先核查是否服务于目标代理部署；USBIP/系统 resolved 等上游周边功能保留待分类，不默认把“全协议服务端”扩成全部系统工具。
- 配置导入、面板 API、分享链接导出不因协议互通目标而自动成为首版需求。

## 持续维护

- 每次升级固定 tag/commit，记录上游协议、传输、角色及废弃变更。
- 正式发布优先跟进稳定基线；“最新”不是拉取开发分支就自动宣称兼容，也不是生产自动升级。
- 兼容矩阵同时记录客户端与服务端基线，持续跑回归、边界和资源测试。
- 上游废弃功能不长期兼容，但退出时明确说明受影响的配置与行为。
- 每个阶段在 OpenSpec 中独立提出、验证、实施和验收，不将整个长期项目塞进一个永不结束的变更。
