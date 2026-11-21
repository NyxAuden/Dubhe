# 官方上游内核本机互测记录（2026-11-13）

本记录只覆盖本机回环上的官方发布二进制，不表示公网、三平台或 release 已完成；
macOS ARM64 的 Rust 1.91.0/1.95.0 与 Linux ARM64 的 Rust 1.95 全量测试已另行
执行；Linux x86_64 的 check 已通过，但 QEMU 下 cargo fork/exec 偶发死锁使全量未能取得可信结果，Windows MSRV 未做。官方二进制放在 `/tmp` 独立目录，测试配置与证书不含生产凭据，
未进入仓库、未发布。

## 测试顺序

1. **sing-box**：固定版本同时提供服务端与客户端角色，覆盖 ShadowTLS、
   Shadowsocks、Hysteria2、TUIC、AnyTLS、Snell、Naive、WireGuard 等，
   且本机已有官方 v1.14.4 二进制，因此先做。
2. **Xray-core**：再做 VLESS/VMess/Trojan/Shadowsocks 及 TLS、REALITY、
   Vision、WS/gRPC/XHTTP 等核心传输矩阵。
3. **Mihomo**：作为常见客户端验证本内核服务端；不把客户端单侧结果当服务端兼容。
4. **NW3 / Nowhere**：最后用官方 Portal/Vector 客户端验证 NW3 角色；本批已完成
   官方 v3.3.0 的 Portal/Vector/Egress 有限组合，仍不等于 Anywhere 全矩阵。

## 已执行：sing-box v1.14.4

- 资产：`sing-box-1.14.4-darwin-arm64.tar.gz`
- SHA256：`0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838`
- 版本：`1.14.4`，revision `c005f35300ce76427dc285481ec5695f5b179cd2`
- 平台：macOS ARM64，所有目标 `127.0.0.1` 回环。早期 ShadowTLS 使用本机
  `openssl s_server` 作为真实 TLS 伪装目标（OpenSSL 4.1.0，自签 CA:FALSE/
  `localhost` 证书）；新增 AnyTLS、Snell、Naive、VLESS Vision、Trojan 组合使用
  同一 `localhost` 自签证书及本机 Python HTTP/UDP echo 目标，Naive 客户端通过
  `certificate_path` 显式信任该证书。Naive H3 的 sing-box/Cronet 客户端在
  `127.0.0.1` 配置下会先尝试 `::1` 并直接报 `quic protocol error`，本次将
  服务端与客户端都切到 `[::1]`/`::1` 回环后才取得通过结果；这是测试地址族
  选择，不是把 H3 失败扩称为协议不兼容。

### 结果

| 方向 | 组合 | 结果 |
| --- | --- | --- |
| 官方客户端 → 本内核 | sing-box ShadowTLS v3 outbound → 本内核 ShadowTLS 入站 + Shadowsocks 2022 detour | 通过 |
| 本内核 → 官方服务端 | 本内核 ShadowTLS v3 出站 → sing-box ShadowTLS 入站 + SS2022 detour | 通过 |
| 本内核 → 官方服务端 | 本内核 Shadowsocks 2022 `iPSK:uPSK` EIH 出站 → sing-box SS2022 EIH 入站 | 通过 |
| 本内核 → 官方服务端 | 本内核 Hysteria2 TCP 出站（`up_mbps/down_mbps=100`）→ sing-box Hysteria2 入站 | 通过 |
| 官方客户端 → 本内核 | sing-box Hysteria2 outbound → 本内核 Hysteria2 入站 | 通过（TCP/UDP） |
| 官方客户端 → 本内核 | sing-box Hysteria2 salamander/gecko obfs → 本内核 Hysteria2 入站 | 通过（TCP/UDP） |
| 官方客户端 → 本内核 | sing-box TUIC v5 outbound（native/quic UDP）→ 本内核 TUIC 入站 | 通过（TCP/UDP） |
| 官方客户端 → 本内核 | sing-box AnyTLS outbound → 本内核 AnyTLS 入站 | 通过（TCP/UoT v2） |
| 官方客户端 → 本内核 | sing-box Snell v4/v6 outbound → 本内核 Snell v4/v6 入站 | 通过（v4 HTTP/TLS obfs，v6 default/unshaped/unsafe-raw，TCP/UDP） |
| 官方客户端 → 本内核 | sing-box Naive H2 outbound（UoT v2）→ 本内核 Naive 入站 | 通过（TCP/UoT v2） |
| 官方客户端 → 本内核 | sing-box Naive H3 outbound（UoT v2）→ 本内核 Naive 入站（`h3:true`，IPv6 回环） | 通过（TCP/UoT v2） |
| 官方客户端 → 本内核 | sing-box VLESS Vision outbound（XUDP）→ 本内核 VLESS Vision 入站 | 通过（TCP/UDP） |
| 官方客户端 → 本内核 | sing-box Trojan/TLS outbound → 本内核 Trojan TLS 入站 | 通过（TCP/UDP） |
| 官方客户端 → 本内核 | sing-box WireGuard endpoint（多 peer、PSK、IPv4/IPv6 内层、服务端 helper 目标改写）→ 本内核 WireGuard 入站 | 通过（TCP/UDP；负向失败关闭另测） |

TCP 方向均通过本机 HTTP GET 实际校验响应正文；UDP 方向使用独立 Python
SOCKS5 UDP ASSOCIATE 客户端校验 echo 回包，不是只检查监听端口。

### WireGuard 入站扩展矩阵

2026-11-13 在同一 macOS ARM64 主机、同一 sing-box v1.14.4 二进制上补齐：

| 组合 | TCP | UDP | 备注 |
| --- | --- | --- | --- |
| 双 peer（不同静态密钥与 AllowedIPs） | 通过 | 通过 | 两个 mixed 客户端同时在线；服务端 API 记录 2 个 UDP 关联 |
| 服务端/客户端 PSK | 通过 | 通过 | `preshared_key` / `pre_shared_key` |
| IPv6 内层 `fd00:66::/64` | 通过 | 通过 | helper 将 `[fd00:66::1]:20100` 改写为 `127.0.0.1:20100` |
| 未知 peer | 失败关闭 | 失败关闭 | 握手不完成，无 echo、无业务字节 |
| 错误 PSK / 错误服务端公钥 | 失败关闭 | 失败关闭 | 同上 |
| 越界 `allowed_ips` 源地址 | 失败关闭 | 失败关闭 | 客户端握手成功，但服务端丢弃业务包；helper 零连接，未落到 direct |

外层 WireGuard UDP 仅监听 `127.0.0.1`，内层不使用回环地址；保留服务端 helper
`route-options` 目标改写。keepalive 以 1 秒间隔实测，空闲期约 120 秒观测到客户端
rekey（handshake initiation/response）；服务端 `peer_idle_timeout_secs=2` 清理
旧会话后，客户端约 15 秒重握手并恢复 UDP。负向场景同时确认 echo 零命中、helper
无目标连接、管理 API 业务字节为 0。详细命令、配置路径、时序与限制见
`docs/wireguard-server.md`。

该矩阵仍不等于完整官方兼容：未覆盖内核 `wg`/wireguard-tools、Mihomo 客户端、
Linux/Windows、外层 IPv6、MTU/分片、漫游、长稳与高并发。

### ShadowTLS 修复

官方服务端在 TLS 1.3 握手后连续下发两张 `NewSessionTicket`。原 `hmacIgnore`
只丢弃第一条旧链记录，第二条被误交给认证后 HMAC 链而失败。已改为与上游一致：
匹配时保留并推进旧链，连续丢弃所有旧链残留，首次不匹配才切换到
`server_random||"S"` 链；单测覆盖两条残留记录。修复后方向 B 通过。

## 尚未执行

- Mihomo 的 REALITY、TUIC 0-RTT、Snell v6 等其余协议组合与官方 Anywhere 客户端；官方 Nowhere 已完成 TCP/UDP 双向及 Egress 交叉组合，见后节。
- Hysteria2 的完整官方客户端矩阵、BBR profile、realm、端口跳跃、精确 Brutal
  pacing；当前已验证本内核出站对 sing-box 服务端，以及 sing-box/Mihomo 客户端
  到本内核入站的 TCP/UDP 有限组合。
- mKCP 已完成双向：Xray 客户端 → 本内核 `vless-kcp`，以及本内核 VLESS + mKCP
  出站 → Xray v26.10.31 服务端；Xray v26 已移除旧 QUIC transport，QUIC 只保留
  sing-box 形状，不能把 Xray 旧 QUIC 作为官方目标。
- Shadowsocks 多级 `iPSK1:iPSK2:uPSK` 中继链、插件、官方全矩阵。
- WireGuard 入站已完成 sing-box v1.14.4 客户端扩展矩阵：双 peer、PSK、IPv4/IPv6
  内层 TCP/UDP，未知 peer、错误 PSK/服务端公钥、越界 `allowed_ips` 源地址的失败
  关闭，以及 keepalive/rekey/空闲清理的报文级观察。外层仍只走 `127.0.0.1`，
  内层不使用回环地址，服务端通过 helper `route-options` 改写目标。内核 `wg`/
  wireguard-tools、Mihomo 客户端、Linux/Windows、MTU/分片、漫游、长稳与高并发
  仍未验收，不能扩称为完整官方兼容。
- sing-box v1.14.4 的 Snell 出站只有 v4/v6，v5 只验证了 Mihomo 客户端；v4、v6
  的其它 mode 与官方全矩阵仍未展开。
- MASQUE 已按用户要求从本内核删除；不再保留配置、运行时、测试、示例或开发记录，也不存在官方互通目标。


## 已执行：Xray-core v26.10.31

- 资产：`Xray-macos-arm64-v8a.zip`
- SHA256：`0a05dca3bd311b0bc5a89c7ce56350cab1e829e131e4b2bcd48eb304fac07e9a`
- 版本：`Xray 26.10.31`，revision `a4a3dff`，go1.27.3 darwin/arm64。

### 结果

| 方向 | 组合 | 结果 |
| --- | --- | --- |
| 官方客户端 → 本内核 | Xray VLESS/TLS → 本内核 VLESS TLS 入站 | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS/TLS 出站 → Xray VLESS TLS 入站 | 通过（修复应答头死锁后） |
| 官方客户端 → 本内核 | Xray VLESS/WSS → 本内核 VLESS-WS TLS 入站 | 通过（TCP/UDP/XUDP） |
| 本内核 → 官方服务端 | 本内核 VLESS/WSS 出站 → Xray VLESS WS TLS 入站 | 通过 |
| 官方客户端 → 本内核 | Xray Trojan/TLS → 本内核 Trojan TLS 入站 | 通过 |
| 本内核 → 官方服务端 | 本内核 Trojan/TLS 出站 → Xray Trojan TLS 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VMess/TLS → 本内核 VMess TLS 入站 | 通过 |
| 本内核 → 官方服务端 | 本内核 VMess/TLS 出站 → Xray VMess TLS 入站 | 通过（修复 38 字节应答头死锁后） |
| 官方客户端 → 本内核 | Xray VLESS Vision → 本内核 VLESS Vision 入站 | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS Vision 出站 → Xray VLESS Vision 入站 | 通过（Vision 应答头改为惰性消费后） |
| 官方客户端 → 本内核 | Xray VLESS/REALITY（无 flow）→ 本内核 `vless-reality` | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS/REALITY（无 flow）出站 → Xray REALITY 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VLESS Vision/REALITY → 本内核 `vless-reality` | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS Vision/REALITY 出站 → Xray REALITY 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VMess/REALITY → 本内核 `vmess-reality` | 通过 |
| 本内核 → 官方服务端 | 本内核 VMess/REALITY 出站 → Xray REALITY 入站 | 通过 |
| 官方客户端 → 本内核 | Xray Trojan/REALITY → 本内核 `trojan-reality` | 通过 |
| 本内核 → 官方服务端 | 本内核 Trojan/REALITY 出站 → Xray REALITY 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VLESS/gRPC TLS（single）→ 本内核 `vless-grpc` | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS/gRPC TLS 出站（single）→ Xray VLESS gRPC 入站 | 通过（响应头惰性等待后） |
| 官方客户端 → 本内核 | Xray VLESS/gRPC TLS（multiMode）→ 本内核 `vless-grpc` | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS/gRPC TLS 出站（multi）→ Xray VLESS gRPC 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VMess/gRPC TLS → 本内核 `vmess-grpc` | 通过 |
| 本内核 → 官方服务端 | 本内核 VMess/gRPC TLS 出站 → Xray VMess gRPC 入站 | 通过 |
| 官方客户端 → 本内核 | Xray Trojan/gRPC TLS → 本内核 `trojan-grpc` | 通过 |
| 本内核 → 官方服务端 | 本内核 Trojan/gRPC TLS 出站 → Xray Trojan gRPC 入站 | 通过（修复服务端 TLS ALPN h2 后） |
| 官方客户端 → 本内核 | Xray VLESS/gRPC TLS UDP（XUDP，single/multiMode）→ 本内核 `vless-grpc` | 通过（TCP/UDP） |
| 官方客户端 → 本内核 | Xray VMess/Trojan gRPC TLS UDP → 本内核 `vmess-grpc`/`trojan-grpc` | 通过（TCP/UDP） |
| 官方客户端 → 本内核 | Xray VLESS/REALITY-over-gRPC → 本内核 `vless-grpc` + REALITY | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS REALITY + gRPC 出站 → Xray REALITY gRPC 入站 | 通过（无 ALPN 时按 h2 prior-knowledge） |
| 官方客户端 → 本内核 | Xray VLESS/XHTTP TLS（auto/stream-one/stream-up/packet-up） | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS/XHTTP TLS（auto/stream-one/stream-up/packet-up） | 通过（尾斜杠与原文 padding 后） |
| 官方客户端 → 本内核 | Xray VLESS/XHTTP TLS UDP（auto/stream-one/stream-up/packet-up，XUDP，服务端 `xudp:true`） | 通过（TCP/UDP） |
| 官方客户端 → 本内核 | Xray VLESS/REALITY-over-XHTTP（auto） | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS REALITY + XHTTP 出站（auto） | 通过 |
| 官方客户端 → 本内核 | Xray VLESS/HTTPUpgrade TLS → 本内核 `vless-httpupgrade` | 通过（TCP/UDP/XUDP） |
| 本内核 → 官方服务端 | 本内核 VLESS/HTTPUpgrade TLS 出站 → Xray VLESS HTTPUpgrade 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VLESS Encryption（X25519 与 ML-KEM-768 认证）→ 本内核 `vless` `decryption` | 通过 |
| 本内核 → 官方服务端 | 本内核 VLESS Encryption 出站 → Xray VLESS 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VLESS Encryption `.0rtt` 重连 | 通过（首个 1-RTT，后续 0-RTT 长度块 32 被接受） |
| 官方客户端 → 本内核 | Xray VMess/REALITY-over-gRPC → 本内核 `vmess-grpc` + REALITY | 通过 |
| 本内核 → 官方服务端 | 本内核 VMess REALITY + gRPC 出站 → Xray REALITY gRPC 入站 | 通过 |
| 官方客户端 → 本内核 | Xray Trojan/REALITY-over-gRPC → 本内核 `trojan-grpc` + REALITY | 通过 |
| 本内核 → 官方服务端 | 本内核 Trojan REALITY + gRPC 出站 → Xray REALITY gRPC 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VMess/REALITY-over-XHTTP → 本内核 `vmess-xhttp` + REALITY | 通过（TCP/UDP） |
| 本内核 → 官方服务端 | 本内核 VMess REALITY + XHTTP 出站 → Xray REALITY XHTTP 入站 | 通过 |
| 官方客户端 → 本内核 | Xray Trojan/REALITY-over-XHTTP → 本内核 `trojan-xhttp` + REALITY | 通过（TCP/UDP） |
| 本内核 → 官方服务端 | 本内核 Trojan REALITY + XHTTP 出站 → Xray REALITY XHTTP 入站 | 通过 |
| 官方客户端 → 本内核 | Xray VLESS/mKCP（`security=none`）→ 本内核 `vless-kcp` | 通过（TCP/UDP/XUDP） |
| 本内核 → 官方服务端 | 本内核 VLESS + mKCP 出站 → Xray v26 mKCP 入站 | 通过（修复应答头同步预读死锁后） |

### 本批修复

1. **VLESS 应答头惰性消费**：新增 `VlessResponse`，请求头发送后立即允许写业务数据，
   首次读取时再校验版本并跳过 addons；修复与 Xray 的同步应答等待死锁。
2. **VMess 38 字节应答头惰性消费**：`handshake_request` 只写请求头，正文前用
   `SkipPrefix` 丢弃服务器固定应答；修复 Xray 服务端 flush 时序导致的死锁。
3. **VLESS Vision 应答头惰性消费**：新增 `Vision::client_lazy`，请求头写完后
   立即允许 Vision 业务帧，首次下行读取时再校验并跳过 VLESS 应答头；修复
   Vision 出站对 Xray 服务端的等待环。

两项均有单测：`vless_response_header_is_consumed_lazily_and_addons_are_skipped`
与 `skip_prefix_discards_fixed_response_header_before_body`。

### REALITY 修复

REALITY 双向测试固定目标为本机 TLS 1.3 服务，暴露并修复两处真实兼容问题：

1. **Ed25519 CertificateVerify**：REALITY 临时证书固定使用 Ed25519，但 Xray 客户端的
   Chrome/uTLS `signature_algorithms` 不声明 Ed25519。原实现据此错误回退到固定目标；
   现与 Xray 一致，REALITY 服务端强制 Ed25519 CertificateVerify。
2. **目标记录尺寸**：原实现要求本地 flight 的每个 record 与目标等长；目标
   EncryptedExtensions 不含 SNI ack 时槽位不足，连接被错误回退。现改为
   “目标槽位足够时模仿总长，不足时使用自然长度”，保持聚合/分槽形态，仍与
   Xray 不要求逐 record 等长一致。

修复后 VLESS REALITY（无 flow 与 Vision flow）、VMess REALITY 与 Trojan REALITY
的双向 TCP 均通过；REALITY-over-gRPC/XHTTP 的 TCP/UDP 已在后文补齐，三平台与
release 仍未验收，macOS ARM64 Rust 1.91.0 全量已在版本记录中单独执行。

### gRPC 修复

本内核 gRPC 出站原先在 `send_request` 后立即等待响应头，再写入 VLESS 请求。
Xray 的 gRPC 服务端在收到首个 Hunk 前不发送初始 metadata，形成等待环。现改为
首次读取时再等待并校验响应状态，允许业务 Hunk 先写出。VLESS single/multi、
VMess、Trojan 的 gRPC/TLS 双向均已通过。

另修复：`trojan-grpc` 的 TLS acceptor 未声明 `h2` ALPN，导致 Xray/本内核
Trojan gRPC 客户端握手后被拒绝；现与 VLESS/VMess gRPC 一致只通告 `h2`。
REALITY-over-gRPC 时 Xray 服务端可能不回显 ALPN，客户端现允许 h2 缺失并
按 HTTP/2 prior-knowledge 运行。

### XHTTP 修复

Xray 的 XHTTP 请求与本地旧实现有三处差异，均已修复：

1. `x_padding` 位于 `Referer` 的查询参数中，且按**原文长度**校验（常见为重复
   `X`）；原实现把整个 Referer 当 base64 解码。
2. Xray 的 GET 下行可能先于 POST 到达；无会话时 GET 现在建立待上行会话。
3. Xray 服务端按 `path/` 规范化；出站 stream-one 请求补尾斜杠，分离模式
   `path/session[/seq]` 保持不变。

修复后 TLS 上的 auto/stream-one/stream-up/packet-up、VLESS/REALITY-over-XHTTP
双向均通过。

### mKCP 修复

本内核 VLESS 出站曾对 mKCP 特判为同步预读 VLESS 应答头。Xray 服务端在目标
产生首包前不会写出应答头，形成“客户端等应答头 → SOCKS 不成功 → 目标收不到
请求 → 服务端不写应答头”的死锁；抓包中服务端只回 KCP ACK/PING，没有任何
DATA。现删除该特判，mKCP 与 TCP/WS 等流式承载一样在首次业务读取时惰性校验
应答头，SOCKS 建连不再等待。修复后本内核 VLESS + mKCP 出站 → Xray v26 服务端
通过；反方向 Xray 客户端 → 本内核 `vless-kcp` 也已通过。错误 seed 在 KCP 上
只能表现为后续无数据/超时，与上游客户端一致，不再要求 SOCKS 成功前失败。

### VLESS Encryption 与三协议 REALITY 承载

- Xray `vlessenc` 生成的 X25519 与 ML-KEM-768 认证对均完成 VLESS/TLS 双向：
  官方客户端 → 本内核 `vless.decryption`，本内核 `encryption` 出站 → Xray
  服务端。Xray 客户端使用 `.0rtt` 配置时，重连已实际进入 0-RTT：首个连接
  长度块为 1232，后续连接长度块为 32 且被本内核票据缓存接受（服务端 debug
  事件 `vless_encryption_0rtt`）；0-RTT 重放/过期路径仍由本地测试覆盖。
- VMess/Trojan 的 REALITY-over-gRPC 与 REALITY-over-XHTTP 均完成双向 TCP；
  共用已验证的 REALITY、gRPC、XHTTP 修复，不需要额外协议分叉。

### Xray 测试配置注意

- Xray v26 已移除 `allowInsecure`；本机自签证书使用
  `pinnedPeerCertSha256`（SHA256 十六进制）固定，不使用系统根证书。
- Xray `freedom` 默认阻止 private/loopback 目标；仅测试用 freedom 下标明
  `finalRules: [{"action":"allow","network":"tcp,udp","ip":["geoip:private"]}]`，
  这是测试目标策略，不是本内核行为。
- Xray 对 WebSocket 打印弃用警告；本批仅验证协议互通，不把弃用警告当兼容结论。

## 已执行：Mihomo v1.19.33

- 资产：`mihomo-darwin-arm64-v1.19.33.gz`
- SHA256：`060b64b0f2c9a310831db0fe4adb2878de67bfa606c311813c1f13966aa504b6`
- 版本：`Mihomo Meta v1.19.33 darwin arm64`，go1.26.10。
- 方向均为官方 Mihomo 客户端（`mixed-port` → 指定代理）→ 本内核对应入站；
  TCP 每项都通过本机 HTTP GET 校验正文 `xray-official-interop-ok`，UDP 另用
  独立 SOCKS5 UDP ASSOCIATE 客户端校验本机 UDP echo 回包。
- 测试用 `skip-cert-verify: true` 只用于本机自签证书；这不是生产信任配置。

| 组合 | 本内核入站 | TCP | UDP |
| --- | --- | --- | --- |
| Mihomo VLESS/TLS | VLESS TLS | 通过 | 通过 |
| Mihomo VLESS Vision | VLESS Vision（flow `xtls-rprx-vision`） | 通过 | 通过 |
| Mihomo VLESS/WSS | VLESS WS TLS（`/proxy`） | 通过 | 通过 |
| Mihomo Trojan/TLS | Trojan TLS | 通过 | 通过 |
| Mihomo VMess/TLS | VMess TLS | 通过 | 通过 |
| Mihomo Shadowsocks 2022 | `2022-blake3-aes-128-gcm` | 通过 | 通过 |
| Mihomo Hysteria2 | Hysteria2（`up/down=100 Mbps`） | 通过 | 通过 |
| Mihomo TUIC v5 | TUIC（`udp-relay-mode=native`） | 通过 | 通过 |
| Mihomo Snell v5 | Snell v5 | 通过 | 通过 |
| Mihomo AnyTLS | AnyTLS | 通过 | 通过 |
| Mihomo `ss + shadow-tls` 插件 | ShadowTLS v3 + SS2022 detour | 通过 | — |

- ShadowTLS 插件需把 `skip-cert-verify` 放在 `plugin-opts` 内（放在代理顶层
  不生效）；仅验证 TCP，内层 UDP 不在此组合范围。
- 尚未测试 Mihomo 的 REALITY、TUIC 0-RTT、Snell v6 等组合，也未把单协议结果
  外推为 Mihomo 全矩阵兼容。

## 已执行：Nowhere v3.3.0

- 资产：`nowhere-aarch64-apple-darwin.tar.gz`
- SHA256：`975f22565c9c3342ad7a45f973b7148a7bc361d76ca10fbe4e9f35c3e743c996`
- 版本：`nowhere-v3.3.0 macos/aarch64`。
- 所有组合使用真实 TLS 证书 + `pin`、`morph=1`、`127.0.0.1` 回环；UDP 组合
  在 Vector/Egress URL 中显式声明 `/udp:PORT`（QUIC 载体），Portal 仍为同端口
  TCP TLS + QUIC。
- 方向 A：官方 Nowhere Vector → 本内核 `nw3` Portal，`out=direct`。
- 方向 B：本内核 `nw3-vector` 出站 → 官方 Nowhere Portal，`out=direct`。
- Egress 方向 A：官方 Nowhere Egress 注册到本内核 `nw3` Portal（`out=egress`），
  官方 Vector 作为入口。
- Egress 方向 B：本内核顶层 `nw3_egress` 注册到官方 Nowhere Portal
  （`out=egress`），官方 Vector 作为入口。

| 方向 | 组合 | TCP | UDP |
| --- | --- | --- | --- |
| 官方客户端 → 本内核 | 官方 Vector → 本内核 Portal `out=direct` | 通过 | 通过 |
| 本内核 → 官方服务端 | 本内核 `nw3-vector` → 官方 Portal `out=direct` | 通过 | 通过 |
| 官方客户端 → 本内核 | 官方 Egress 注册到本内核 Portal `out=egress` | 通过 | 通过 |
| 本内核 → 官方服务端 | 本内核 `nw3_egress` 注册到官方 Portal `out=egress` | 通过 | 通过 |

- TCP 使用本机 HTTP GET 校验 `nowhere-official-interop-ok`；UDP 使用独立
  Python SOCKS5 UDP ASSOCIATE 客户端向本机 UDP echo 发送并校验回包，未使用
  本内核生产编解码器作为客户端侧判据。
- 首次方向 B 的失败是测试启动时序：Portal 在 HTTP 目标 57013 绑定前就拨号，
  得到 Connection refused；等待所有端口就绪后复跑通过，不是协议失败。
- 官方 Anywhere 客户端、Morph 认证负例、无可用 Egress 的超时失败与三平台/
  release 仍未验收。
