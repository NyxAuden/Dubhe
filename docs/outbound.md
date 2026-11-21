# 上游代理出站（含 Snell / AnyTLS / Hysteria2 / TUIC / NW3 / WireGuard）

状态：**已实现待集中验收**。SOCKS5/HTTP/VLESS/VMess/Trojan/Shadowsocks/WireGuard 出站已通过本机回环测试；XHTTP、mKCP、V2Ray QUIC 出站、AnyTLS UoT、VLESS/VMess/Trojan REALITY 与无目标 ShadowTLS v3 detour 也已通过全目标编译与对应本机回环用例。官方互测已完成 sing-box v1.14.4 的 ShadowTLS/SS2022 EIH/Hysteria2 出站，以及 VLESS Vision、Trojan/TLS、Hysteria2、TUIC v5、AnyTLS、Snell v6、Naive H2 客户端到本内核入站；Xray-core v26.10.31 的 VLESS/TLS、VLESS/WSS、Trojan/TLS、VMess/TLS、VLESS/VMess/Trojan REALITY（VLESS 含 Vision）、VLESS（single/multi）/VMess/Trojan gRPC/TLS、VLESS/REALITY-over-gRPC、VLESS/XHTTP TLS 四模式、VLESS/VMess/Trojan REALITY-over-gRPC/XHTTP、mKCP、VLESS Encryption（X25519/ML-KEM-768）与 VLESS/HTTPUpgrade TLS 双向本机回环（应答头惰性消费、gRPC/Trojan ALPN、XHTTP padding/会话修复后通过）；其余官方组合与三平台/MSRV/release 仍未验收。本页只描述当前代码行为。

## 范围

本内核目前支持以下出站：

| `type` | 行为 | UDP |
|---|---|---|
| `direct` | 直接解析并连接目标 | 支持 |
| `reject` | 拒绝该 Flow，不产生目标流量 | 支持（拒绝） |
| `socks5` | TCP 经 SOCKS5 CONNECT 转发；UDP 经 UDP ASSOCIATE 中继；可选 TLS | 支持 |
| `http` | TCP 经 HTTP/1.1 CONNECT 转发；可选 TLS | **不支持，失败关闭** |
| `naive` | 原生 TLS H1/H2/H3 普通 CONNECT；H1默认裸流或显式`h1_padding`，H2/H3协商首8块padding；每业务独立连接，非Cronet指纹等价 | 显式`naive.udp_over_tcp:true`走标准UoT v2；H1另需`h1_padding:true`及支持UoT的对端，默认失败关闭 |
| `vless` | TCP 经 VLESS v0；可配置 `flow: "xtls-rprx-vision"`（TLS 1.3 或 REALITY 裸承载）；原生 UDP（命令 2，每目标一条隧道）；可选 TLS 或 REALITY、WS/gRPC/HTTPUpgrade/XHTTP、mKCP 或 QUIC 承载与 VLESS Encryption | 支持（协议层固定目标数据报，可经可靠/QUIC 流） |
| `vmess` | TCP 经 VMess AEAD（security 3/4）转发；可选 TLS 或 REALITY、WS/gRPC/HTTPUpgrade/XHTTP、mKCP 或 QUIC 承载；原生 UDP 使用命令 2 固定目标隧道 | 支持（固定目标，每目标一条隧道；packetaddr 出站未实现） |
| `trojan` | TCP 经 Trojan 转发；原生 UDP（命令 3，逐包目标）；必须 TLS 或 REALITY；可选 WS/gRPC/HTTPUpgrade/XHTTP、mKCP 或 QUIC 承载 | 支持（逐包目标） |
| `shadowsocks` | TCP 经 Shadowsocks AEAD（含 2022）转发；原生 UDP 使用 vendored 客户端加密 | 支持（每包独立目标） |
| `wireguard` | TCP/UDP 经 WireGuard 隧道（boringtun + smoltcp 用户态栈）转发 | 支持（固定目标 socket，保留空包；受隧道 MTU 限制） |
| `anytls` | TCP 经 AnyTLS（TLS 上的密码认证与帧流）转发；UDP 经协议层 UoT v2 | 支持（UoT over TCP） |
| `shadowtls` | 无目标 ShadowTLS v3 detour：真实 TLS1.3 外观 + v3 记录层，返回内层 TCP；只能被其他代理出站经 `via` 引用 | **不支持，失败关闭** |
| `snell` | TCP 经 Snell v4/v5/v6 CONNECT_V2；复用正式记录codec，v6支持default/unshaped/unsafe-raw | 支持（命令6 UDP-over-stream，逐目标会话，保留空包） |
| `hysteria2` | TCP 经 Hysteria2 QUIC 连接（HTTP/3 认证 + 0x401 流）转发；UDP 经专用连接的 DATAGRAM 会话 | 支持（分片/重组） |
| `tuic` | TCP 经 TUIC v5 QUIC 连接（exporter 认证 + Connect 流）转发；UDP 经专用连接的 DATAGRAM 会话 | 支持（分片/重组） |
| `nw3-vector` | TCP/UDP 经 vendored Nowhere Vector（`vector://`，TLS/QUIC 载波）转发 | 支持（上游 UDP Flow；按目标隔离） |
| `selector` | 静态组：按 `default` 或第一项选择终端出站 | 随所选终端出站 |
| `urltest` | 延迟组：周期经各成员拨号 `probe`，选择延迟最低者 | 随所选终端出站 |

`reject` 的 UDP 语义是“拒绝该目标”，不是“支持 UDP 转发”。

`selector` 只做**静态选择**：没有探测或运行时切换；`urltest` 才按探测延迟动态切换。两者都是出站组，成员引用在启动时解析。

## 配置

```json
{
  "outbounds": [
    {
      "type": "socks5",
      "tag": "upstream",
      "endpoint": "127.0.0.1:1081",
      "username": "alice",
      "password": "change-me",
      "tls": { "ca_file": "/etc/ssl/private/proxy-ca.pem", "server_name": "proxy.example" }
    },
    { "type": "direct", "tag": "direct" },
    { "type": "reject", "tag": "reject" },
    { "type": "selector", "tag": "manual", "outbounds": ["upstream", "direct"], "default": "upstream" },
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["upstream", "direct"],
      "probe": "127.0.0.1:9",
      "interval_ms": 180000
    }
  ],
  "route": {
    "default": "direct",
    "rules": [{ "outbound": "upstream", "networks": ["tcp"] }]
  }
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `tag` | 是 | 路由引用的出站标识 |
| `type` | 是 | `direct`、`reject`、`socks5`、`http`、`naive`、`vless`、`vmess`、`trojan`、`shadowsocks`、`anytls`、`shadowtls`、`snell`、`hysteria2`、`tuic`、`nw3-vector`、`wireguard`、`selector`、`urltest` |
| `endpoint` | 代理类出站必需；`nw3-vector` 可省略 | `HOST:PORT` 或 `[IPv6]:PORT`；端口不得为 0；未加括号的 IPv6 拒绝。`nw3-vector` 的端点由 `vector://` URL 的主机/端口推导 |
| `username` / `password` | 否 | `socks5`/`http` 必须成对；`trojan`/`shadowsocks` 只用 `password`；非空、各不超过 255 字节、不含 `\0`/CR/LF；Naive Basic 用户名不得含冒号；Naive用户名和密码均必需 |
| `uuid` | `vless`/`vmess` 必需 | 标准 UUID |
| `encryption` | 否 | `vless` 的 VLESS Encryption 客户端配置；仅 32 字节 X25519 公钥或 1184 字节 ML-KEM-768 公钥，支持 `native`/`xorpub`/`random` 与 `1rtt`/`0rtt` |
| `security` | 否 | `vmess` 正文安全类型，缺省 3；只允许 3（AES-128-GCM）或 4（ChaCha20-Poly1305） |
| `transport` | 否 | 仅 `vless`/`vmess`/`trojan`：`ws`、`grpc`、`httpupgrade`、`xhttp`、`kcp`、`quic`；QUIC 与 XHTTP/3 必须配置 `tls`，REALITY 不能与 QUIC/UDP 底层承载组合。`xhttp` 支持 `http_version`（1.1/2/3，默认 2）、`mode`（auto/stream-one/stream-up/packet-up）、`headers`、`x_padding` 与 `max_post_bytes`；`kcp`/`quic` 复用入站参数对象 |
| `reality` | 否 | 仅 `vless`/`vmess`/`trojan`：服务端静态 X25519 公钥、SNI 与 shortId，见下节；与 `tls` 互斥，只可与 RAW、gRPC、XHTTP 组合；VLESS Vision 可与 REALITY 组合，但不能与 WebSocket、HTTPUpgrade、QUIC 或 mKCP 组合 |
| `transport.path` | 否 | WebSocket 路径，缺省 `/`，必须以 `/` 开头 |
| `transport.host` | 否 | WebSocket `Host` 头，缺省使用 `endpoint` 主机名；gRPC 禁止配置 |
| `transport.multi` | 否 | 仅 gRPC：使用 MultiHunk 批量编码，缺省 false |
| `naive` | `naive` 必需 | `http_version:"1.1"/"2"/"3"`（默认2）、`h1_padding`（默认false，仅H1可true）、有界`extra_headers`、`udp_over_tcp`（默认false、仅UoT v2；H1需padding模式）；根TLS/username/password必需，不与REALITY或通用transport混用；H3禁止via |
| `anytls` | 可省略，仅`type:anytls`适用 | 根`password`与`tls`必需；对象可配`disable_reuse`（默认false）、空闲检查/超时毫秒（默认各30000）、`min_idle_session`（默认0）；不得配置uuid/method/security/transport/encryption |
| `shadowtls` | `shadowtls` 必需 | 无目标 detour：根`password`（1–4096字节）与`tls`必需，`tls.server_name`必须显式DNS；只能作为其他TCP代理出站的`via`，不能终端路由、不能UDP；`via`目标`endpoint`必须与它一致；不得配置reality/uuid/flow/encryption/method/security/transport/udp_over_tcp/username/wireguard//hysteria2/tuic/snell/naive/anytls/url/组字段 |
| `snell` | `snell` 必需 | `psk`、`version`（4/5/6），可选`userkey`及仅v6的`mode`（default/unshaped/unsafe-raw）；v4/v5可选`obfs_mode:none/http/tls`、`obfs_host`、HTTP专属`obfs_uri`；不与根username/password、TLS/REALITY、transport混用；可选`reuse`（默认false，仅TCP顺序池）；v6+obfs及quic等未实现字段拒绝 |
| `nw3-vector` | `nw3-vector` 必需 | 完整 `vector://` URL；不得配置其他代理字段；TCP/UDP Flow 均接入，载波由上游 URL 选择 |
| `tuic` | `tuic` 必需 | `uuid`、`password` 与 `tls`；可选对象含`udp_relay_mode`、`congestion_control`、`zero_rtt_handshake`（默认false）；不得配置 method/security/transport/encryption/via |
| `hysteria2` | `hysteria2` 必需 | `password` 与 `tls`；可选 `hysteria2.obfs`（salamander/gecko）、`hysteria2.up_mbps`/`down_mbps`（0 或至少 0.524288 Mbps）；带宽通过 `Hysteria-CC-RX` 协商并配置客户端 Brutal；不得配置 uuid/method/security/transport/encryption/via |
| `wireguard` | `wireguard` 必需 | 隧道参数对象，见下节；其他出站禁止配置 |
| `method` | `shadowsocks` 必需 | 支持 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` 与三种 2022 方法 |
| `tls.ca_file` | 配 `tls` 时必需 | PEM 信任锚；启动时加载，不读取系统根证书 |
| `tls.server_name` | 否 | 证书校验名/SNI；省略时用 `endpoint` 的主机名，IP 端点按 IP 校验 |
| `via` | 否 | 链式出站的上一跳代理 tag；必须引用另一个代理类出站，禁止自引用与循环。`shadowtls` 只能作为上一跳 detour，自身不得再配置 `via`；引用它的出站 `endpoint` 必须与 ShadowTLS `endpoint` 一致 |
| `outbounds` | `selector`/`urltest` 必需 | 成员 tag 列表，1–32 项且不重复；成员必须是本配置中已存在的出站，可嵌套 `selector` |
| `default` | `selector` 否 | 必须是成员之一；省略时使用 `outbounds` 第一项；`urltest` 禁止配置 |
| `probe` | `urltest` 必需 | 探测目标 `HOST:PORT`；周期经各成员拨号该目标并测量 TCP 建连延迟 |
| `interval_ms` | `urltest` 否 | 探测周期，1000–86400000，默认 180000 |
| `tolerance_ms` | `urltest` 否 | 切换容差，0–60000，默认 50；当前成员在容差内不切换 |
| `probe_timeout_ms` | `urltest` 否 | 单成员单次探测超时，100–60000，默认 2000 |

`direct`/`reject` 配置 `endpoint`/`username`/`password`/`uuid`/`method`/`tls`/`reality`/`via`/`wireguard`、或配置组字段会被拒绝；代理类出站配置组字段同样被拒绝；`trojan` 必须配置 `tls` 或 `reality`，`vless`/`vmess` 可选 TLS 或 REALITY，`shadowsocks` 禁止 TLS/REALITY。`selector`/`urltest` 也不接受 `endpoint`/`username`/`password`/`tls`/`via`。

`selector`/`urltest` 的引用在启动时递归解析到终端出站；成员缺失、空列表、重复成员、`default` 不在成员内、自引用及任意深度的循环引用都会使配置校验失败。`urltest` 的成员不得再是 `urltest`（避免两跳探测语义）；经 `selector` 间接成环同样在配置阶段拒绝。配置校验与实际解析使用同一套规则，不依赖运行时兜底。

`urltest` 的行为：

- 启动后立即探测一轮，之后每 `interval_ms` 探测一轮；同一轮内各成员并发探测，单成员受 `probe_timeout_ms` 与全局 `dial_timeout_ms` 双重约束。
- 只建立 TCP 连接，不发送业务载荷；UDP 流复用同一选择结果，因此探测结果描述的是该成员到 `probe` 的 TCP 可达性与延迟。
- 探测失败的成员不参与选择；全部失败时保持当前成员。当前成员成功且与最优延迟之差不超过 `tolerance_ms` 时不切换，避免抖动。
- 未被任何路由规则或默认出站引用的 `urltest` 组不会探测。探测连接不计入业务上下行字节。

链式示例：`a.via = "b"`、`b.via = "c"` 表示先直连 `c`，经 `c` CONNECT `b`，再经 `b` CONNECT `a`，最后由 `a` CONNECT 业务目标。每一跳的 `tls` 只保护到该跳的连接；中间端点作为上一跳 CONNECT 的目标发送，域名解析由远端代理完成。链式仅支持可建立 TCP 隧道的前述协议；UDP 业务 Flow 仍返回 `Unsupported`，不会静默改走直连。mKCP/QUIC/XHTTP-H3 这类自带 UDP 套接字的承载只能作为链首的直连端点，不能嵌入上一跳 TCP 隧道。

`shadowtls` 是特殊 detour：它没有业务目标，只完成到自身 `endpoint` 的真实 TLS1.3 + v3 记录层；下游代理 `a.via = "stls"` 时，`a.endpoint` 必须等于 `stls.endpoint`，先由 ShadowTLS 返回内层 TCP，再由 `a` 自己的 TLS/传输/协议层继续握手。`stls` 自身不得配置 `via`（只允许一层 ShadowTLS），也不能出现在 `route.default`、规则目标或 `selector`/`urltest` 成员中。示例见 `docs/shadowtls.md`。

## 行为

- 路由先选出出站；`reject` 在产生任何目标流量前返回 `PermissionDenied`。
- 所有代理类出站先按 `endpoint` 解析并建立底层承载：TCP、mKCP 可靠流或 QUIC；配置 `tls` 时在底层流上完成 TLS（校验 `tls.server_name` 或端点主机名），配置 `reality` 时完成 REALITY 认证的 TLS 1.3 握手并验证服务端临时证书，再完成 HTTP/WS/gRPC/XHTTP 等传输适配与协议握手。Vision 的 TLS 1.3 受控记录层同样使用惰性应答头，在首次业务读取时切换。VLESS 写完请求头后不阻塞等待服务器 2 字节应答，首次业务读取时才校验并跳过应答头；Trojan 直接写入认证头；Shadowsocks 在已连接的流上建立 AEAD 记录层（返回新的包装流）。
- 上游握手与上游拨号都受 `limits.dial_timeout_ms` 约束；单地址尝试受 `dial_attempt_timeout_ms` 约束。
- 信任锚在 `check`/`run` 启动时加载；文件不可读、为空或无效会直接失败，不做回退。
- SOCKS5 的 UDP ASSOCIATE 在配置 `tls` 时，控制连接经 TLS；中继本身按 SOCKS5 规范仍是独立 UDP 套接字，不受 TLS 保护。
- 业务流量仍计入本内核的入站统计；上游代理自身的连接与限速不在本内核控制范围内。
- 支持 UDP 的出站：`socks5`、`vless`、`vmess`、`trojan`、`shadowsocks`、`anytls`、`snell`、`hysteria2`、`tuic`、`wireguard`、`nw3-vector`，以及显式启用UoT v2的`naive`。普通 `http` CONNECT 的 UDP 仍返回 `Unsupported`，不会私自换成 CONNECT-UDP 或静默直连。
- UDP 路由到共享 `Association` 的协议时，每个关联最多建立一个上游中继；同一关联内的目标变化不会重建中继，选到不同代理时该报文被拒绝。Hysteria2/TUIC 为每条 UDP 关联建立独立 QUIC 连接，避免同一连接上多个接收循环争抢 DATAGRAM。
- 支持共享中继的入口是 WireGuard 服务端隧道、SOCKS5 UDP ASSOCIATE、Trojan、VLESS 固定目标 UDP、UoT（含 AnyTLS 及 Naive H2/H3及显式填充H1流内UoT）与 Mux.Cool 的 UDP 会话；Shadowsocks 2022、VMess、Snell、Hysteria2/TUIC 的原生 UDP 入口分别由各自协议层处理。

## SOCKS5 细节

- SOCKS5 出站实现 CONNECT 与 UDP ASSOCIATE，不实现 BIND；VLESS/VMess/Trojan/Shadowsocks 出站同时支持原生 UDP，VMess 为命令 2 固定目标隧道。
- 认证方式协商为 `no-auth` 与 `username/password`（RFC 1929）；上游选择其他方式时失败。
- 目标地址按 IPv4、IPv6、域名三种 ATYP 编码；域名长度 1–255。
- 上游应答码非 0 或地址类型未知时失败。
- UDP ASSOCIATE 的控制 TCP 连接在关联存续期间保持开启，关联结束时随任务关闭，通知上游释放中继。
- UDP 报文使用 `RSV(2) FRAG(1) ATYP ADDR PORT DATA`；`FRAG != 0` 的分片直接丢弃，不重组。
- 中继应答的源地址写入回程报文头，因此客户端看到的源地址来自上游实际观察到的对端；域名与 IP 两种 ATYP 都接受。
- 中继地址为 `0.0.0.0`/`[::]` 时沿用控制连接的对端 IP；返回域名中继地址时失败关闭。
- 中继空闲超过 `limits.udp_idle_timeout_ms` 后连同控制连接一起回收。

## Naive 原生出站

```json
{
  "type": "naive",
  "tag": "up",
  "endpoint": "203.0.113.10:443",
  "username": "REPLACE_WITH_USER",
  "password": "REPLACE_WITH_RANDOM_PASSWORD",
  "tls": { "ca_file": "/etc/ssl/private/naive-ca.pem", "server_name": "proxy.example" },
  "naive": { "http_version": "2", "udp_over_tcp": false, "extra_headers": {} }
}
```

- 完整模板：默认H2的`examples/naive-outbound.json`、裸H1的`examples/naive-h1-outbound.json`和显式sing-box填充/UoT的`examples/naive-h1-padding-outbound.json`。`http_version` 支持字符串 `"1.1"`、`"2"`（默认）、`"3"`，不自动回退；必须显式TLS信任锚及Basic身份，用户名不得含冒号。
- 使用普通CONNECT，仅目标authority，不发送扩展`:protocol`、`:scheme`或`:path`。H1通告`http/1.1`，可接受无ALPN；H2/H3必须实际协商`h2`/`h3`。仅最终200成功；有限100/102/103临时响应可跳过，101和其他最终状态拒绝。证书、身份或状态失败不交付业务、不自动重放或直连回落。
- 请求均携带正式非空Padding。**H1默认裸流对齐固定forwardproxy**，即使200有Padding也不加/剥PaddedData；**显式`h1_padding:true`对齐sing-box v1.14.4 H1**，要求200有非空Padding，双向首8块填充、第9块裸字节。响应头无法自动区分这两种正式上游，配错会损坏流量；本内核H1入站默认仍为裸流，只有显式`h1_padding:true`才接受sing-box填充模式。本地选项不增加wire字段。
- H2/H3在200有非空Padding时启用双向首8块PaddedData，无头保持plain。读写拆包、取消与短写保存有界状态，flush/FIN实际推进且FIN后仍可读取反向响应。
- `extra_headers` 最多32项、单值2048字节、总预算4096字节；ASCII且无控制字符。禁止伪头、认证、Host/Padding、连接/内容帧字段和Cronet内部控制头覆盖，拒绝大小写重复。Debug只显示数量，不显示值；序列化仍含真实身份/头部，不可公开。
- 每业务独立连接、头8192字节。H1严格CRLF/HTTP1.1/64项头，最多4个临时响应且累计头≤8192，不预读首批业务；成功CONNECT后的Content-Length/Transfer-Encoding按RFC9110忽略。H1不派生任务，握手取消/超时直接销毁承载；H2/H3有限写队列8块×16KiB、流控/写期限及TaskTracker回收。H1/H2共用原TCP/TLS工厂，可在TCP链前后；H3独立QUIC，禁止TCP via任一侧。低层`outbound::connect`仍要求使用Context工厂。
- UDP默认拒绝；仅`naive.udp_over_tcp:true`使用正式UoT v2（魔数目标、isConnect/SOCKS目标、u16长度帧），每目标独立会话、空包/双栈、目标与队列字节预算；H1另需显式`h1_padding:true`及sing-box等实际支持UoT的对端，否则配置拒绝。它不是原生QUIC数据报，普通forwardproxy没有自动UoT能力。UDP via仍拒绝。
- 不提供共享HTTP连接池、Chromium/Cronet/uTLS指纹、ECH或特定Chromium拥塞控制等价。200在固定forwardproxy中可能早于目标拨号，不代表目标已经连接。H2/H3历史开发结果见[原批记录](naive-outbound-development.md)，H1当前验证进度与官方验收边界见[H1记录](naive-h1-outbound-development.md)。

## Snell 细节

```json
{
  "type": "snell",
  "tag": "up",
  "endpoint": "203.0.113.10:8388",
  "snell": {
    "psk": "REPLACE_WITH_RANDOM_PSK_12_TO_255_BYTES",
    "version": 6,
    "userkey": "REPLACE_WITH_USER_KEY",
    "mode": "default"
  }
}
```

模板：`examples/snell-outbound.json`，替换上游地址与随机凭据后使用。

- v4/v5 PSK 1..4096字节，v6 PSK 12..255字节；userkey可省略，显式非空时1..255字节。凭据Debug脱敏，配置序列化仍含真实凭据，不可发布。
- TCP使用正式CONNECT_V2与零块FIN，保留反向响应。**首应答可延迟到目标首个下行**，因此写入请求头/根SOCKS成功不等于上游已认证；第一次读取校验ReplyTunnel/ReplyError，损坏或拒绝应答不作为业务输出。每次接受有界记录，短写/Pending/取消保存状态，flush/FIN实际排空。
- UDP命令6先验证隧道应答，每目标独立记录会话，经共享Association限制目标/队列/字节；IP/端口过滤非目标回包，域名由上游解析。空数据报保留；v4/v5整记录最多16383字节，v6最多65535字节，含地址头，另受根`max_udp_payload`和外层载波容量限制。超限不截断、不私自分片。
- v4/v5 可配置 `obfs_mode: "http"` 或 `"tls"`；`obfs_host` 缺省分别为 `bing.com`/`cloudfront.net`，HTTP 可选 `obfs_uri`（缺省 `/`）。HTTP 只是一次 GET/101 外观头后裸字节，非 WebSocket；TLS obfs 按固定首消息与后续记录承载，非真实 TLS，不校验证书、不提供额外保密。v6 禁止叠加，`none` 禁止 host/URI，TLS obfs 禁止 URI；首头/记录有界且取消安全。成对模板见 `examples/snell-obfs.json` 与 `examples/snell-obfs-outbound.json`。
- TCP `reuse:true` 启用正式顺序池，默认 false；不增加 wire 字段，不是并发多路复用。保留记录 salt/nonce/整形和 obfs 首消息状态；每个新目标仍发 CONNECT_V2、校验其首应答。只有验证过首应答、已接受写/本地零块完成并收到对端逻辑零块才可复用，旧下行只在关闭后的排空阶段丢弃。未验证应答、坏 AEAD/应答、截断与失败写不能回池；失败不自动重放业务或回落直连。
- 池每出站独立，最多 10 个空闲/等待项，空闲 180 秒过期、20 秒清理；旧下行排空总期限 30 秒，累计丢弃达到 `0x80001` 字节即关闭。并发业务独占不同承载，UDP 始终独立新建，不取 TCP 池。
- TCP `via` 可将Snell（含 obfs/reuse）放在SOCKS5链前/后，根和链中间跳均先取池再决定按原链拨号；UDP `via` 仍明确不支持。热替换后新出站池隔离，旧已交付活流不因池销毁被误关；最终停机取消等待/空闲任务并等资源释放。低层 `outbound::connect` 已提供流而无运行时所有权，显式 reuse 会明确报错要求 `Context` 连接工厂，不静默当 false。
- QUIC 仍未实现，不能据出站接入宣称所有上游可选能力完成。
- 启用模板：`examples/snell-reuse-outbound.json`；v4/v5 可与适用 obfs 一起使用。普通模板仍缺省关闭池。
- 本机证据与真实失败/修复见[基础出站记录](snell-outbound-development.md)、[obfs记录](snell-obfs-development.md)与[连接池记录](snell-reuse-development.md)，不等同官方客户端兼容。Snell独立入站UDP驱动仍保留其原有上游路由限制；出站可用不推导所有入口均可用。

## WireGuard 细节

```json
{
  "type": "wireguard",
  "tag": "wg",
  "endpoint": "203.0.113.10:51820",
  "wireguard": {
    "private_key": "base64-32-bytes",
    "peer_public_key": "base64-32-bytes",
    "preshared_key": "base64-32-bytes",
    "address": ["10.66.0.2/32"],
    "mtu": 1420,
    "keepalive_secs": 25
  }
}
```

- 密钥必须是 32 字节 base64（标准或有填充形式均可）；`preshared_key` 可省略。
- `address` 是隧道内本地地址，数量受当前 smoltcp 接口容量限制（当前为1–2个）IPv4/IPv6 CIDR；目标地址必须与某个
  `address` 同地址族，否则连接失败关闭。
- `endpoint` 是对端 UDP 地址，可为主机名（首次拨号时解析）。隧道内目标完全由
  路由规则决定，不使用 AllowedIPs 过滤。
- `mtu` 范围 576–1500，缺省 1420；`keepalive_secs` 为 0 时禁用持久保活。
- 每个出站首次使用时建立一个 UDP 隧道与 smoltcp 接口；内核 TCP 连接映射为隧道内
  的独立 smoltcp TCP 连接。出站与所有流释放后驱动任务自动退出。
- **UDP 已接入**：每个目标在共享隧道栈上创建独立 smoltcp UDP socket，源地址过滤、空包边界、目标上限/队列预算与根 Association 共用；先完成真实 WireGuard 握手再接受发送。超过 MTU（减去 IP/UDP 头）的包返回错误，不截断、不回落直连。
- 握手使用 boringtun（Noise_IK），不新增自研密码原语；smoltcp 只提供用户态
  IP/TCP 栈，不修改系统路由或网卡。

## NW3 Vector 出站

```json
{"type":"nw3-vector","tag":"nw3","url":"vector://<key>@host:port?sni=...&pin=...&morph=1"}
```

- 复用 vendored Nowhere 的 `VectorClient`：TCP 或 QUIC 载波、TLS/QUIC、Morph、pin/sni 与按目标打开 TCP/UDP Flow。
- TCP 映射为 Vector TCP Flow，UDP 按目标打开原上游 UDP Flow（TLS/QUIC），不启用额外 SOCKS 监听器。显式 `/tcp:PORT`、`/udp:PORT` 与带端口 authority 的端点均按上游处理。
- 已有本机 Vector↔Portal TCP/UDP、双目标/空包与错误密钥回环；已与官方 Nowhere v3.3.0 Portal 完成 `nw3-vector` 的 TCP/UDP 互通（显式 `/udp:PORT` QUIC 载波、morph=1、pin）；Anywhere 客户端未验证，不能声称完整 NW3 客户端兼容。

## TUIC 出站

```json
{
  "type": "tuic",
  "tag": "tuic",
  "endpoint": "127.0.0.1:443",
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "password": "change-me",
  "tls": {"ca_file": "/etc/ssl/private/proxy-ca.pem", "server_name": "tuic.example"},
  "tuic": {"udp_relay_mode": "native", "congestion_control": "cubic", "zero_rtt_handshake": false}
}
```

- 每个出站共享一条 QUIC 连接；认证单向流发送 `v5/Authenticate/UUID/TLS exporter`，
  每个目标打开双向流发送 `v5/Connect/地址`。
- 默认不协商 ALPN，与 TUIC 服务端一致。
- UDP使用独立QUIC连接，`udp_relay_mode:native`为Packet DATAGRAM（MTU分片/重组），`quic`为每消息独立单向流；各自exporter认证与TCP连接独立。
- `congestion_control`支持cubic（默认）、new_reno/new-reno、bbr，均由锁定Quinn真实工厂执行；不支持bbr2等值，不静默降级。
- `zero_rtt_handshake`默认false；显式true且有票据时真实尝试0-RTT，TCP只提前Connect元数据，UDP只提前Heartbeat。业务仍在完整握手和标准Authenticate写入后发送；不伪造early exporter，不将认证帧已写称为远端已确认。
- 无票据正常完整握手；明确拒绝早期流时仅重建一次元数据流，不自动重放业务。0-RTT仍有重放风险，默认关闭且不承诺0-RTT业务延迟收益。
- endpoint按IPv4/IPv6最多两个缓存，活流/关联共享最后所有权，热替换旧出站不误关旧流；取消未交付连接有Drop guard，没有额外应用后台认证任务。
- 本机证据见[开发记录](tuic-outbound-modern-development.md)；Mihomo v1.19.33 客户端到本内核 TUIC 入站的 TCP/UDP 有限互通已通过，其余官方客户端/平台验收未做。

## Hysteria2 出站

```json
{
  "type": "hysteria2",
  "tag": "hy2",
  "endpoint": "127.0.0.1:443",
  "password": "change-me",
  "tls": {"ca_file": "/etc/ssl/private/proxy-ca.pem", "server_name": "hy2.example"},
  "hysteria2": {
    "obfs": {"type": "salamander", "password": "obfs-pass"},
    "up_mbps": 100,
    "down_mbps": 100
  }
}
```

- 每个出站共享一条 QUIC 连接；先以 HTTP/3 `POST https://hysteria/auth` 认证（状态 233），
  之后每个目标打开 QUIC 双向流并发送 `0x401` TCP 请求帧。
- 支持 salamander/gecko UDP 层混淆；TLS 必须提供显式 CA 与 ALPN `h3`。
- `up_mbps`/`down_mbps` 与官方出站同向：上行用于本端发送，下行通过
  `Hysteria-CC-RX` 告知服务端。认证响应回传服务端接收带宽后，客户端取
  `min(服务端带宽, up_mbps)` 配置 Brutal；`auto`/0 保持回退控制器。
  完整逐包/pacing 对齐和 BBR profile 仍未实现。
- UDP 使用独立 QUIC 连接上的 Hysteria2 DATAGRAM 会话；每条关联只运行一个接收循环，按 session/packet 过滤并重组分片。
- 本机 `tests/outbound_protocols.rs` 已覆盖 TCP 回显。

## AnyTLS 出站

```json
{
  "type": "anytls",
  "tag": "anytls",
  "endpoint": "127.0.0.1:443",
  "password": "change-me",
  "tls": {"ca_file": "/etc/ssl/private/proxy-ca.pem", "server_name": "anytls.example"}
}
```

- 必须 TLS；在 TLS 上发送 `sha256(password)`、握手 padding、Settings、SYN 与首个 PSH 目标。
- 运行时默认启用正式空闲会话池；每TLS一次前导/Settings、每目标递增ID，根出站与TCP链中间跳先取最新空闲会话，池空才沿原链拨号。并发不主动抢占忙会话；同会话多ID按标准分派，关闭一流不关其它ID，不复用耗尽的u32 ID、不自动重放业务。
- 可选`anytls`：`disable_reuse:false`，`idle_session_check_interval_ms:30000`，`idle_session_timeout_ms:30000`，`min_idle_session:0`。显式时间5001..86400000毫秒、保留数0..64；只保留已有空闲，不预拨；禁用复用时保留数必须0。缓存64项、每会话64流、每流4块读队列、会话64项写队列，慢流背压且停机可取消。
- 每出站共享正式padding scheme，TCP与UoT共池/方案；默认握手30字节、Settings含padding-md5，首批Settings/SYN/目标PSH合并整形，后台持续处理cmd6/ServerSettings/心跳/Alert。合法更新影响后续写/新握手，非法更新保留旧值，已stop计数不重启。
- AnyTLS FIN关闭整条逻辑流，不是TCP半关闭；本地FIN实际排空且只发一次，peer FIN不回送，已排队PSH先读完。peer FIN时尚有未flush写/屏障，shutdown返回错误而非误报成功。错误SYNACK限于该流，合法控制在有限队列暂满时有界等待，不立即毒化其它ID；Alert/结构/认证/传输失败关闭会话。已获v2的复用开流有3秒看门狗，下一完整帧头解除。链首DNS也只在池miss后的拨号工厂执行。热替换退休旧池保留活流，最终停机等资源回收。
- 模板`examples/anytls-pool-outbound.json`；低层`outbound::connect`已提供承载，保持独立单流，不声称执行了池复用。证据见[padding记录](anytls-padding-development.md)和[池记录](anytls-pool-development.md)。
- 无原生 UDP、无 fallback；路由到 AnyTLS 的 UDP 关联使用协议层 UoT v2：目标为 `sp.v2.udp-over-tcp.arpa` 的单条 AnyTLS 流承载逐包目标。根 `udp_over_tcp` 开关仅作用于 Shadowsocks，Naive 使用其对象内的独立开关；AnyTLS 固定使用 UoT v2。
- 本机 `tests/outbound_protocols.rs` 已覆盖 TCP 回显。

## HTTP CONNECT 细节

- 请求为 `CONNECT HOST:PORT HTTP/1.1`，带 `Host` 头；配置凭据时带 `Proxy-Authorization: Basic ...`。
- 只接受 2xx；其他状态码返回 `PermissionDenied`。
- 响应头逐字节读取，上限 8 KiB，避免把 CONNECT 之后的首批数据吞进缓冲区。
- 到上游的 TLS 由 `tls` 字段开启；TLS 内仍是明文 HTTP CONNECT 语义。

## VLESS / Trojan / Shadowsocks 细节

- **VLESS**：仅实现 v0、无 flow、TCP（命令 1），addons 为空；TCP/WS/mKCP 等
  流式承载写完请求头后都不阻塞等待应答，首次业务读取时再校验服务器
  `[版本, addons 长度]` 应答并跳过 addons；这是为了兼容官方 Xray 将应答与
  首帧数据合并/延迟 flush。mKCP 也遵循上游客户端语义：错误 seed 或不可达
  服务端表现为后续无数据/超时，而不是在 SOCKS 成功应答前失败；不能为提前
  判定认证失败而同步读取应答头，否则会与等待目标首包的 Xray 服务端死锁。
  目标地址使用 VLESS 的端口在前布局（1=IPv4、2=域名、3=IPv6）。
- **VMess**：仅实现 AEAD 请求头、TCP 命令 1 与 security 3/4；选项固定为 0，
  请求头写完即可写业务，首次正文读取时再丢弃服务器固定 38 字节应答。
  不得在返回前同步等待应答，否则会与官方 Xray 服务端形成等待环。
- **Trojan**：写入 `SHA-224(password)` 的 56 字节小写十六进制、CRLF、`0x01`、
  SOCKS5 风格地址与 CRLF；必须配置 TLS 或 REALITY，服务器不返回单独应答。
- **Shadowsocks**：在已连接的流上复用 vendored 客户端的 `ProxyClientStream` 建立
  AEAD 记录层；支持 2017 AEAD 与三种 2022 方法；TCP 与原生 UDP 均可用，
  服务端只终止单层 EIH，客户端可按 `iPSK:uPSK` 链连接。`iPSK:uPSK` 出站
  已与官方 sing-box v1.14.4 的 SS2022 EIH 入站完成本机 TCP 互通；多级
  `iPSK1:iPSK2:uPSK` 中继链仍未单独验收。
- **VLESS Vision**：`flow: "xtls-rprx-vision"` 要求 `tls` 或 `reality`，且不能与 `transport` 同时配置；可与 VLESS Encryption 组合；REALITY 时使用同一受控 TLS 1.3 记录层完成 REALITY 认证。客户端先完成受控握手、发送带 Vision addons 的 VLESS 请求；应答头在首次下行读取时惰性消费，然后进入 Vision 记录层，避免官方 Xray 等待首帧业务才 flush 的死锁。UDP 命令 2 不走 Vision。
- **REALITY**：`reality` 只支持 `vless`/`vmess`/`trojan`，必须给出 32 字节服务端 X25519 公钥、DNS 形式的 SNI 和多达 16 个十六进制字符的 shortId；与 `tls` 互斥，可与 VLESS Vision flow 组合，但不能与 WebSocket、HTTPUpgrade、QUIC/mKCP 等非 RAW/gRPC/XHTTP 承载组合。客户端在 ClientHello 的 32 字节 legacy session ID 内写入版本、时间戳与 shortId，密钥由 X25519 临时私钥与服务端静态公钥经 HKDF-SHA256 派生；同时支持 `X25519` 与 `X25519MLKEM768` 密钥交换。服务端临时证书只接受 HMAC-SHA512 绑定和 TLS 1.3 Ed25519 CertificateVerify，不接受 TLS 1.2、HRR、ECH、会话恢复或 early data。认证完成后仍按所选协议完成 VLESS/VMess/Trojan 握手；与上游一致，仅 gRPC/XHTTP 承载可作用于 REALITY 明文流，WebSocket/HTTPUpgrade 在配置阶段拒绝。ClientHello 由 rustls 生成，不做 uTLS/浏览器指纹模拟。可选 `mldsa65Verify` 为 base64 的 1952 字节 ML-DSA-65 公钥：配置后按 Xray 语义校验服务端临时证书第一个扩展对 `HMAC(authKey, Ed25519Pub || rawCH || rawSH)` 的签名；未配置时只做 HMAC 认证。
- **VMess UDP**：为每个目标建立一条命令 2 的固定目标隧道，正文块边界即数据报边界；VLESS/VMess 的 UDP 隧道都会先应用 `transport` 包装（WS/WSS/gRPC/HTTPUpgrade/XHTTP/mKCP/QUIC）。不实现出站 packetaddr/xudp 模式。
- **mKCP**：每条连接使用独立本地 UDP、随机非零 conv 与现有 KCP 驱动；TLS/WS/gRPC 等上层封装照常叠加。配置的 MTU 保持 Xray 的 KCP 语义（MSS=MTU-18）；发送分组另按完整 UDP 报文的上限约束，避免把大量分段聚成不可发送的大包。
- **QUIC（`sing-box v2ray-quic` 形状）**：TLS 1.3、ALPN `h3`，每条代理连接打开一条双向流，没有 Xray 旧 `quicSettings` 的额外加密/混淆层；UDP 命令仍作为上层协议帧在可靠流内传输。XHTTP/3 使用专用 QUIC 连接与 `h3` 客户端。
- **XHTTP**：H1 的 stream-up/packet-up 通过独立上下行连接实现，依赖逐跳连接工厂重开同一 via 链，不会绕过链式代理；H2/H3 在单连接内多路复用。所有版本的单块、队列与操作超时均有界。
- WebSocket 包装在协议握手前完成：先建立 TCP（配置 `tls` 时先 WSS/TLS），再执行 WS Upgrade，随后把协议字节流映射到二进制帧；服务端 Ping 会自动回复 Pong。
- gRPC 包装在协议握手前建立 h2 客户端连接并向 `transport.path` 发起双向流；single 模式使用 `Hunk`，`multi: true` 使用 `MultiHunk`；TLS 时自动协商 ALPN `h2`。
- 链式出站对上述协议同样有效：每一跳把下一跳的 `endpoint` 作为自己的目标，由远端
  完成该跳的连接。
- **HTTPUpgrade** 出站完成一次 HTTP/1.1 Upgrade 后直接使用原始字节流，无 WebSocket 帧层；本机 VLESS 回环通过。
- **WireGuard** 复用 boringtun 完成 Noise 握手与数据封装，smoltcp 提供隧道内
  IPv4/IPv6 TCP/UDP。`selector`/`urltest` 可包含 WireGuard
  成员，探测也经隧道建立 TCP。

## 安全与日志

- 密码不进入 `Debug` 输出；`Outbound` 与 `ProxyOutbound` 的调试输出只显示是否带认证。
- 配置错误信息不回显用户名或密码。
- 启用 `tls` 时用显式 `ca_file` 校验上游证书与 `server_name`；不读取系统根证书，也不提供跳过校验的开关。启用 `reality` 时不使用 CA，改为验证 REALITY 临时证书的 HMAC 与 Ed25519 CertificateVerify；校验失败即关闭，不回落到明文或其他安全层。两者都未启用时上游链路明文，`endpoint` 不应跨不可信网络。

## 验收缺口

`selector`/`urltest` 的单元测试与 `urltest` 回环切换测试已运行（`route::tests::selector_*`、`urltest_*`、`tests/urltest.rs`）；`tests/outbound_protocols.rs` 20 项、`tests/outbound_udp.rs` 13 项、`tests/kcp_outbound_client.rs` 7 项、`tests/quic_outbound_client.rs` 5 项、`tests/xhttp_outbound_client.rs` 6 项、`tests/outbound_transport_config.rs` 6 项与 `tests/reality_outbound.rs` 5 项本机回环/配置用例通过（含 VLESS/VMess/Trojan 的 TLS、VLESS Vision、VLESS Vision+REALITY、VLESS/VMess 明文 WS、Trojan WSS、gRPC single/multi/over-TLS、XHTTP H1 split/H2/H3 全部模式、Shadowsocks AEAD、VLESS/VMess/Trojan/Shadowsocks/AnyTLS UoT/Hysteria2/TUIC UDP、TUIC native/quic 两种 UDP 模式、VLESS/VMess UDP over WS、VLESS UDP over gRPC、mKCP 全掩码/seed/96KB、V2Ray QUIC 三协议 TCP/UDP 与流额度、双跳链式、VLESS REALITY 的 X25519 与混合组目标及原生 UDP、三协议 REALITY-over-gRPC）。外部官方组合已完成 Xray v26.10.31 的 VLESS/VMess/Trojan REALITY（VLESS 含 Vision）与 VLESS/gRPC TLS 单 Hunk 双向互通；其余外部代理、官方客户端、三平台与 MSRV 验收尚未执行。WireGuard 已通过一项本机
双 endpoint 回环测试（真实 Noise 握手 + 隧道内 TCP echo）。其后新增Snell基础出站/obfs/顺序池、TUIC出站可选能力及Naive H2/H3的开发结果分别见相应章节和批次记录，不混入上述历史数字。以下检查项在新增输入中仍需持续回归，不能将它们全部视作未执行或据旧结果推导已完成外部验收：

1. 编译与 `rustfmt`/clippy；
2. 配置正向/负向：缺失 endpoint、IPv6 括号、凭据成对与长度、`direct` 携带代理字段、`selector`/`urltest` 空/重复/缺失成员/`default` 越界/循环、`urltest` 缺少或非法 `probe`、成员嵌套 `urltest`；
3. 回环 SOCKS5 服务：无认证/有认证 CONNECT、域名与 IPv4/IPv6 目标、错误凭据、错误应答码；
4. 回环 HTTP 代理：200 与 407、Basic 头、响应头后紧跟业务数据不丢字节；
5. 路由：`reject` 不产生目标流量；`http` 的 UDP 目标被拒绝且不改走直连；
6. 回环 SOCKS5 UDP 中继：ASSOCIATE 握手、域名/IPv4/IPv6 目标、回程源地址、`FRAG != 0` 丢弃、控制连接关闭即回收；
7. 回环 TLS 上游：自签 CA 校验成功、错误 CA/错误 `server_name` 失败、TLS 上的 CONNECT 与 UDP ASSOCIATE；
8. 超时与半关闭行为。
