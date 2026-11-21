# UoT（UDP over TCP）

本文件描述本内核在 VLESS/VMess、AnyTLS 及 Naive H2/H3 入站内提供的 sing-box 风格 UoT 服务端承载，以及 Shadowsocks/AnyTLS/Naive 出站的 UoT 客户端承载。线格式以本地只读源码为准：

- `github.com/sagernet/sing@v0.9.7-0.20261023115459-5dc452e537bf/common/uot/protocol.go`
- `github.com/sagernet/sing@v0.9.7-0.20261023115459-5dc452e537bf/common/uot/server.go`
- `github.com/sagernet/sing@v0.9.7-0.20261023115459-5dc452e537bf/common/metadata/serializer.go`
- `github.com/sagernet/sing-box@v1.14.4/common/uot/router.go`
- `github.com/sagernet/sing-box@v1.14.4/protocol/vless/inbound.go`
- `github.com/sagernet/sing-box@v1.14.4/protocol/vmess/inbound.go`

## 魔数

| 版本 | 魔数域名 | 初始请求 | 逐包地址 |
| --- | --- | --- | --- |
| v2 | `sp.v2.udp-over-tcp.arpa` | 有 | 由 `isConnect` 决定 |
| legacy（v1） | `sp.udp-over-tcp.arpa` | 无 | 始终携带 |

魔数通过 VLESS/VMess 请求里的目标地址（`Host::Domain`）识别，不使用单独端口或配置项。本实现与 sing-box 一致使用精确字符串比较；大小写变体按普通目标处理。

## 版本 2 初始请求

在协议应答之后、第一个数据帧之前读取一次：

```
+-----------+---------------------------+
| isConnect | SOCKS5 地址               |
| 1 字节    | 类型 + 地址 + 端口        |
+-----------+---------------------------+
```

- `isConnect` 只接受 0/1。sing-box 使用 Go `binary.Read` 读取 bool，其他值会报错；本实现相同。
- SOCKS5 地址类型码：`0x01` IPv4（4 字节）、`0x04` IPv6（16 字节）、`0x03` 域名（1 字节长度 + 至多 255 字节 ASCII）。
- 端口为网络序 `u16`。端口 0 是合法占位值；非 connect 模式下初始目标仅作为元数据，实际逐包目标在后续帧中给出。
- 空域名、非 ASCII 域名、未知类型、截断地址都会终止承载。

legacy 版本没有初始请求，TCP 流从第一个逐包帧开始；`isConnect` 等价于 `false`，目标等价于 `0.0.0.0:0`。

## 逐包格式

### connect 模式（v2 且初始 `isConnect=1`）

```
+----------+----------------------+
| u16 长度 | 载荷                 |
+----------+----------------------+
```

所有数据报固定发送到初始请求中的目标；上下行都不携带地址。

### 非 connect 模式（v2 `isConnect=0` 与 legacy）

```
+----------------+----------+----------------------+
| UoT 地址       | u16 长度 | 载荷                 |
+----------------+----------+----------------------+
```

UoT 地址类型码与 SOCKS5 不同：

| 类型码 | 含义 | 后续字段 |
| --- | --- | --- |
| `0x00` | IPv4 | 4 字节地址 + `u16` 端口 |
| `0x01` | IPv6 | 16 字节地址 + `u16` 端口 |
| `0x02` | 域名 | 1 字节长度 + ASCII 域名 + `u16` 端口 |

上下行使用同一格式。服务端回包写入的是实际回环/解析后的源 IP（与 sing-box `AddrParser.WriteAddrPort(M.SocksaddrFromNet(addr))` 一致），通常不是客户端最初发送的域名。

### 空载荷

`u16 长度 = 0` 是合法数据报：读方向不会丢弃，写方向会生成仅含长度头的帧。零长度 UDP 数据报会正常转发，不延长空闲期限之外的额外语义。注意 VLESS 固定目标 UDP 承载会丢弃空帧，UoT 不做该丢弃。

## 协议应答顺序

1. VLESS：认证并解析请求后，先发送 2 字节空响应 `[0, 0]`，再读取 UoT 初始请求。
2. VLESS Vision：2 字节响应必须通过原始 TLS 明文发送；随后才用 Vision 包装流并进入 UoT。层级为“应答 → Vision → UoT”。
3. VMess：先发送 VMess 响应头，再建立加密 body 流，最后在 body 流中读取 UoT 初始请求/帧。VMess 响应头不属于 body 加密块。
4. Naive H2/H3：先完成 TLS/Basic 认证，普通 CONNECT 返回200，随后在双方协商的padding流中读取UoT；魔数不先经过DNS或目标TCP拨号，逐包业务仍经共享UDP路由/预算。

## 生效协议与入口

| 协议 | 生效条件 | 说明 |
| --- | --- | --- |
| VLESS | 命令为 Connect（1），目标为魔数域名 | TCP 命令；生效于标准 TLS、REALITY，以及 WebSocket、gRPC、XHTTP、HTTPUpgrade |
| VMess | 命令为 TCP（1），目标为魔数域名 | 生效于直接 TCP/标准 TLS，以及 WebSocket、gRPC、XHTTP、HTTPUpgrade |
| AnyTLS | 首个 PSH 的目标为魔数域名 | 服务端接受魔数目标的端口 0；普通目标仍拒绝端口 0。出站固定使用 UoT v2 |
| Naive H2/H3，或显式`h1_padding:true`的H1 | 已认证普通CONNECT目标为`sp.v2.udp-over-tcp.arpa:0`；填充H1另要求单一非空Padding | 先200再在正式padding流内读取UoT请求；仅v2显式占位，默认裸H1/HTTP/Mixed不变。出站需`naive.udp_over_tcp:true`，H1另需显式填充，每目标独立connect模式 |
| Trojan | 不生效 | sing-box Trojan 入站未安装 UoT router；本内核同样把魔数当作普通目标 |
| VLESS UDP 命令（2）/ 命令 3（当前完整 Mux.Cool） | 不生效 | 命令 2 走原有 VLESS UDP framing；命令 3 进入 Mux，见 [Mux 说明](mux.md) |
| VMess UDP/packetaddr | 不生效 | 继续走原有逐包 UDP/packetaddr 路径 |

VLESS/VMess/AnyTLS 的 UoT 识别只看目标域名，同一入站无需额外开关；Naive H2/H3 本批仅对已认证的精确 v2 魔数与端口0组合识别。普通目标不会进入 UoT。出站侧 Shadowsocks 的根 `udp_over_tcp` 固定使用 v2，AnyTLS 的 UDP 关联同样固定使用 v2；两者以单条流承载逐包目标。Naive使用独立的`naive.udp_over_tcp`开关（默认false），按固定目标独立H2/H3或显式填充H1普通CONNECT，v2 `isConnect=true`，后续帧仅有u16长度和原始payload。H1出站另需`h1_padding:true`以匹配sing-box等实际支持UoT的填充对端，裸H1启用UoT会配置失败；本内核H1入站默认裸流仍不识别UoT；后续显式`h1_padding:true`入站支持认证后精确v2魔数0端口，见[H1入站记录](naive-h1-inbound-development.md)，与出站证据独立。见[H1记录](naive-h1-outbound-development.md)。它不要求或注册私有context，普通forwardproxy也不因Naive TCP可用就自动具备UoT能力；见[出站开发记录](naive-outbound-development.md)。

## 资源边界

- 初始请求受 `handshake_timeout_ms` 约束；超时即关闭。
- 每帧长度先与 `max_udp_payload` 比较，再分配缓冲；线格式上限同时受 `u16`（65535）约束。
- UoT 与其它 UDP 承载共用 `udp_slots`、`udp_queue_packets`、`udp_bytes` 字节预算、`max_udp_targets` 和 `udp_idle_timeout_ms`。
- 域名字段最多 255 字节，必须是可打印 ASCII；空域名被拒绝。
- 半地址、半长度、半载荷及非法类型直接使承载结束，不会把后续字节误当作新帧。

## 明确不支持

- 跨连接会话：UoT 线格式没有会话/流 ID，一条 TCP 连接就是一次 UDP 关联；连接断开即结束，不能续接。
- UDP 分片与重组：只透传系统 UDP 数据报边界；超过 `max_udp_payload` 或被网络分片的报文不做应用层重组。
- legacy 的 connect 模式：legacy 没有初始请求，因此始终为逐包地址模式。
- 版本协商：只识别上面两个魔数，不提供 v1/v2 协商或自动回退。
- 把 Trojan、VLESS UDP 命令、VMess UDP/packetaddr 解释为 UoT。

## 与 sing-box 的已知差异

- 魔数比较与 sing-box 一致，使用精确小写匹配。
- 读取侧对空域名/非 ASCII 域名直接报错；sing-box 的通用序列化器对空域名会让后续端口读取失步，本实现选择显式拒绝。
- VMess 头部策略要求非 packetaddr 的 TCP 目标端口非 0，因此经 VMess 使用 UoT 时初始目标端口需非 0；VLESS 允许端口 0。UoT 本身只按域名识别，不依赖端口。
- 本实现无论首个上行数据何时到达都会先发送协议应答；sing-box 的 VLESS/VMess 响应是首次写入时才生成。对客户端可见的顺序一致。
