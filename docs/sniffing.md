# 流式入站首包嗅探

顶层 `sniffing` 对支持流式读写的入站启用 TCP 首包嗅探，用于把域名送进路由规则匹配。语义参考 Xray-core 与 sing-box v1.14.4：嗅探只产生路由提示，**不是身份认证**，客户端可以伪造 SNI/Host。

```json
{
  "sniffing": {
    "enabled": true,
    "inbounds": ["vless-in", "trojan-in"],
    "dest_override": ["tls"],
    "route_only": false,
    "timeout_ms": 300
  }
}
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | `false` | 总开关；禁用时其余字段必须为空/默认 |
| `inbounds` | 全部 | 生效的入口 tag；空表示所有已接入的流式入口 |
| `dest_override` | 空 | 允许改写拨号目标的协议（`tls`/`http`；`quic` 仅用于 UDP 且不改写发送目标）；空表示只影响路由 |
| `route_only` | `false` | 置真时即使列出 `dest_override` 也只影响路由 |
| `timeout_ms` | `300` | 读取首包的期限，范围 10–10000 |

## 行为

1. 协议认证/请求头解析完成、建立上游连接之前，读取首包，直到识别出域名、判定不可识别、达到 8 KiB 或超过 `timeout_ms`。
2. 已读取的字节通过回放流原样交给后续转发，业务流不丢字节、不改变顺序。
3. 识别成功时用 `(域名, 原端口)` 参与路由选择；只有协议出现在 `dest_override` 且未设置 `route_only` 时，拨号目标才替换为该域名。否则仍拨号原始 IP/域名。
4. 识别失败回落到原始目标，连接继续。

UDP 关联没有可回放的流：对每个 QUIC Initial 数据报按 RFC 9001 派生请求方的 Initial 密钥、解密并提取 ClientHello SNI，只把域名交给路由选择；实际发送目标保持原 IP，避免同一关联的后续包在域名与 IP 之间切换。因此 `dest_override` 对 UDP 不生效，QUIC 嗅探天然是“只影响路由”。Mux.Cool 的 `xudp` 会话复用同一逻辑，出站选择使用嗅探域名，数据报仍发往帧内声明的目标。

支持的识别：单个完整 TLS 握手记录中的 ClientHello SNI、带 `Host` 头的 HTTP/1.1 请求，以及 QUIC v1/v2 单个未合并 Initial 包中的 SNI。跨记录分片的 ClientHello、HTTP/2 前言、IP 字面量 Host 不识别。端口保持入站请求里的值，不从 `Host` 头或 SNI 推断。

## 已接入入口

- `vless` 明文流（含 WS/WSS、gRPC、XHTTP、HTTPUpgrade、mKCP、V2Ray HTTP 承载）的 TCP `CONNECT`
- `vless-reality` 与 Vision flow：在 REALITY/Vision 解包后的内层字节流上嗅探；Vision 的 VLESS 应答先于出站拨号，与 Xray 一致
- `vmess` AEAD 的 TCP `CONNECT`（在解密后的正文流上嗅探）
- `trojan` 的 TCP `CONNECT`（含 WS、gRPC、XHTTP、HTTPUpgrade、mKCP、V2Ray HTTP 承载）
- `socks5` 的 `CONNECT`
- `shadowsocks` 的 TCP 流（含 ShadowTLS 内层）
- Mux.Cool 的 TCP 子流：在 New 之后、拨号之前按同一策略累积子流数据帧，
  识别出的域名参与选路；已累积字节在拨号成功后按原序写回上游。子流首次
  数据可能晚于 `timeout_ms` 到达，此时按未嗅探处理并直接拨号。
- Mux.Cool 的 UDP 会话（`xudp`）：每个数据报按 QUIC Initial SNI 选路，发送
  目标仍为该帧声明的地址。
- UDP 关联（SOCKS5、Trojan、VLESS/VMess UoT 与 XUDP、Shadowsocks）的 QUIC Initial 选路；共享 `Association` 的协议都生效

## 支持范围（2026-11-24 核实）

| 入站 | TCP 首包嗅探 | 依据 |
|---|---|---|
| VLESS / Vision / VMess / Trojan（各 TCP 承载） | ✅ | `src/runtime/serve.rs` |
| Shadowsocks | ✅ | `src/protocol/shadowsocks/mod.rs` |
| SOCKS5 CONNECT / Mux.Cool / dokodemo-door | ✅ | 各自入口 |
| **Hysteria2** | ✅（2026-11-24 新增） | `src/transport/hysteria2/mod.rs`，客户端通常随 TCPRequest 一起发首包 |
| **TUIC** | ✅（2026-11-24 新增） | `src/transport/tuic.rs`，同上 |
| AnyTLS / Snell / Naive H1/H2/H3 | ❌ **协议上做不到** | 见下 |

### 为什么 AnyTLS / Snell / Naive 不能嗅探

这三者的客户端都要**先收到服务端的成功应答**才发送业务数据：

| 协议 | 客户端等待的应答 | 代码位置 |
|---|---|---|
| AnyTLS | `SYNACK`（命令 7） | `src/transport/anytls.rs` 发 SYNACK 后才 `start_bridge` |
| Snell | `REPLY_TUNNEL`（0x00） | `src/protocol/snell.rs` `write_record(&[REPLY_TUNNEL])` 后才 `relay_tcp` |
| Naive | `200 Connection Established` | `src/transport/naive.rs`、`naive/h1.rs` 回 200 后才转发 |

服务端在连接上游之前**一个业务字节都读不到**，所以「先嗅探再选路」在这三个协议上
不成立。要在它们上面实现按域名分流，只有两条路，都不该选：

1. 先回成功应答、再嗅探、再选路——这样失败时无法再回 `502`/失败码，会把
   「目标不可达」变成「已连接后静默关闭」，改变对外语义。
2. 用 CONNECT 里的目标（本来就是域名）——那就已经有域名了，不需要嗅探。

因此这三项**不是未实现，是不该实现**。客户端在 CONNECT/请求里本来就带域名，
`domains`/`domain_suffix` 规则对它们直接生效；只有「客户端把域名解析成 IP 再发」
这一种情况嗅探才有价值，而那需要客户端配合，做不到。

## 未覆盖

- UoT 初始化请求帧与 Mux.Cool 控制帧本身没有业务首包；其后的 UDP 数据报
  仍按 QUIC Initial 选路。
- TUIC、Hysteria2 的 **UDP** 数据报仍由协议层直接处理，不经过共享 `Association`
  嗅探；只有它们的 TCP 流在 2026-11-24 补上了首包嗅探。
- QUIC 0-RTT 与非 Initial 包：只解密 Initial；合并数据报会按 Length 依次跳过非 Initial 包，最多检查 8 个。
- HTTP 代理入站的请求头本身已含目标，不再重复嗅探。
- `dokodemo-door` 有自己的 `sniffing` 字段，只影响该入口的固定目标。

## 代价与边界

- 客户端若等待服务端应答后才发送业务数据，会在启用嗅探时多等最多 `timeout_ms`。按连接计算，不缓存嗅探结果。
- 嗅探发生在协议认证成功之后，不能帮助拒绝未认证连接。
- `dest_override` 使用域名拨号会走内核 DNS（`dns.hosts` 优先），与直接使用域名目标一致。
