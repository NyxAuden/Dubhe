# HTTP/Mixed 与 Naive 入站边界（开发实现，待集中验收）

本页描述 HTTP、Mixed 与 Naive 三类“标准 HTTP 代理”入站的已实现行为与限制。它们与 `vless-*`/`vmess-*`/`trojan-*` 系列是不同产品面：前者可供 curl、浏览器等标准客户端直接使用，后者是专用代理协议。尚无官方客户端集中验收。

## HTTP 与 Mixed

### 入口与配置

- `type: "http"`：只接受 HTTP 代理请求（CONNECT 与绝对 URI）。
- `type: "mixed"`：同一端口先探测 SOCKS5 版本字节（`0x05`），否则按 HTTP 处理；配置 `users` 时 SOCKS5 与 HTTP 共用同一身份表。
- `http` 可选 `certificate`/`private_key` 启用 TLS，并协商 `h2` 或 `http/1.1`：h2 使用标准 CONNECT 流，h1 使用 HTTP/1.1 CONNECT。
- `mixed` 也可选 TLS；TLS 后支持 HTTP CONNECT 与 SOCKS5 CONNECT，SOCKS5 UDP ASSOCIATE/BIND 在 TLS Mixed 下失败关闭。
- 无认证（`users` 为空）且监听非回环地址时必须显式 `"allow_insecure": true`，否则配置加载失败。
- 模板见 `examples/http.json`、`examples/mixed.json`。

### 请求处理

- `CONNECT host:port HTTP/1.1` → 建立目标连接并返回 `200 Connection Established`，随后双向透传。
- 绝对 URI（`GET http://host/path HTTP/1.1`）→ 改写为 origin-form 后转发；强制 `Connection: close`，移除 `Proxy-*`、`Proxy-Authorization` 头。
- `Proxy-Authorization: Basic <base64(user:pass)>` 使用常量时间比较；缺失或错误返回 `407 Proxy Authentication Required`，并附 `Proxy-Authenticate: Basic realm="proxy"`。
- 明文 `http` 只支持 HTTP/1.1 请求行与头；TLS `http` 同时支持 HTTP/2 CONNECT。
- 请求头有大小上限，超限返回 400；不支持请求体转发的分块透传以外的流式升级。

### 明确不支持

- HTTPS 中间人（MITM）、证书伪造或解密。
- 通用反向代理、`Upgrade` 连接、WebSocket 代理透传。
- 透明代理/tproxy 接管、PAC 文件服务。

## Naive

### 入口与配置

- `type: "naive"`，`users` 与 `certificate`/`private_key` 均为必需；不提供明文入口。
- 真实 TLS 上同时通告 `h2` 与 `http/1.1`；`h2` 走 HTTP/2 CONNECT，`http/1.1` 走 HTTP/1.1 CONNECT。可选 `h3:true` 在同一实际端口绑定 UDP QUIC/H3，使用普通 CONNECT（不要求扩展 `:protocol`）。
- `h1_padding`默认false，裸H1对齐固定forwardproxy；显式true选择固定sing-box的首8块填充与UoT v2，必须与客户端模式一致，不靠Padding头自动猜测。只影响H1，H2/H3仍按能力头协商。
- 模板见`examples/naive.json`（裸H1默认）与`examples/naive-h1-padding.json`（显式填充）。

### 行为

- 每请求必须是 `CONNECT authority`；`authority` 支持域名、IPv4 与 `[IPv6]:port`。
- 认证只接受 `Proxy-Authorization: Basic`；失败返回 407。
- `h2` 下每个流独立建立目标连接并双向透传，连接级复用与多流并发受 `limits` 约束。
- `h2`/`h3` CONNECT 携带非空 `padding` 头时启用 Naive padding 扩展：200 响应回 30–61 字节 `Padding` 头，前16字节按固定上游字符集、其余为 `~`；双向前8块使用 `PaddedData`（u16be 原始长度、u8 padding 长度、数据、零填充），第9块起裸字节。未协商的客户端保持普通流。
- **本内核H1入站默认保持裸payload，对齐固定forwardproxy，而非所有Naive上游一概无padding。** `klzgrad/forwardproxy` 提交 `e747854e78743dba85c039b38ed185fb11d93667` 的H1 `serveHijack` 调用`dualStream(..., false)`；但sing-box v1.14.4的H1 `naiveConn`明确经过首8块padding。这两个上游都可能返回Padding头，不能自动推断模式。NaiveProxy基线发布为`v154.0.8037.49-5`，后续新增默认关闭的`h1_padding:true`入站，显式选择sing-box行为，保留旧裸模式；当前状态见[H1入站记录](naive-h1-inbound-development.md)。
- 普通目标拨号失败返回 502，认证通过且拨号成功返回 200。H2/H3 对已认证的正式 `sp.v2.udp-over-tcp.arpa:0` 识别 UoT v2：先返回 200，再读取标准 isConnect/目标与数据报帧，复用已有 UDP 路由和限额，不 DNS 查询/拨号该魔数；普通目标端口0仍拒绝。显式填充H1同样只识别精确v2魔数0端口：单一非空Padding、CONNECT与Basic均合法后返回200及正式Padding，头后早业务先回放到首8块codec，再读取标准UoT；默认裸H1/HTTP/Mixed不放宽。
- 仅作为 HTTP(S) 代理入口，不承载 VLESS/VMess/Trojan 帧。

### 明确不支持

- 明文Naive、裸H1上的UoT和裸/填充自动探测。H1入站需显式`h1_padding:true`才有正式填充/UoT；默认裸流不变。原生H1/H2/H3出站见[出站说明](outbound.md#naive-原生出站)，Chromium/Cronet指纹和共享HTTP池仍未提供。
- 浏览器/uTLS 指纹、前端站点的完整 application-fronting 或 Caddy 配置兼容。H3 QUIC只使用成熟依赖，不冒充Chrome网络栈。
- 与其它代理协议共用同一入口类型的隐式升级。

### 原生出站

`type:"naive"`出站要求用户名/密码、显式CA和`naive`对象，`http_version`为`"1.1"`、`"2"`（默认）或`"3"`。H1默认裸流对齐forwardproxy，显式`h1_padding:true`对齐sing-box v1.14.4首8块填充，不根据相同的响应Padding头猜测；H2/H3按非空响应Padding协商。仅200成功，严格有界头、TLS/ALPN与Basic。H1/H2可位于TCP链前后，H3独立QUIC。UDP默认关闭，显式`udp_over_tcp:true`只用正式UoT v2；H1必须另开`h1_padding`且匹配实际支持UoT的上游；连接本内核时双方均需显式填充模式，不可用于默认裸H1入站。不是原生QUIC数据报。额外头不可覆盖认证/伪头/帧字段。默认模板`examples/naive-outbound.json`，H1裸/填充模板分别`examples/naive-h1-outbound.json`、`examples/naive-h1-padding-outbound.json`。历史H2/H3结果见[原批记录](naive-outbound-development.md)，当前H1进度见[H1记录](naive-h1-outbound-development.md)；不称浏览器/Cronet等价。

## 证据

入站历史本地测试：`tests/http_proxy.rs`（明文 CONNECT、绝对 URI 改写、Mixed 分流、Basic 407、真实 TLS CONNECT、TLS h2 CONNECT、TLS Mixed 的 HTTP/SOCKS CONNECT）、`tests/naive.rs` 3项（H1认证、H2多流/padding），以及 `tests/naive_h3.rs` 9项。新增用例覆盖首8块/第9块、普通CONNECT、FIN半关闭、认证/路由拒绝、重复认证头/扩展伪头拒绝、H2/H3共享预算及释放后复用、慢请求头隔离、阻塞写停机与同端口三承载。`naive_padding` 文件内另有5项短写/Pending/取消/flush/截断测试，H3 writer有2项队列与完成确认测试；全量结果见[开发记录](naive-h3-development.md)。

H3与TCP入口共用全局 `limits.max_connections`、同入口 `max_handshakes` 及全局 `max_grpc_streams`，每连接按 `max_grpc_streams_per_connection` 限制流与未完成请求头任务；这两个流数字段沿用既有通用HTTP复用预算名称，不表示Naive变成gRPC。全局流预算耗尽时以 `H3_REQUEST_REJECTED` 复位请求，不拨目标；每连接超载失败关闭。请求头解码上限8192字节、读取有超时，QUIC每流接收窗口64KiB、连接收发窗口各1MiB。H3写队列固定8块、每块不超过16KiB，flush/FIN等待发送确认（不代表远端已收到），子任务由JoinSet/TaskTracker跟踪并随连接/停机回收。
