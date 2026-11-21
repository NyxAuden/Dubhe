# dokodemo-door 入站

状态：**已实现待集中验收**。TCP 与 UDP 均走本内核的路由与出站选择；UDP 的 `network` 组合、同端口绑定与资源回收已由本地回环测试覆盖，尚未与官方客户端或透明代理部署互通。

## 配置

```json
{
  "inbounds": [{
    "type": "dokodemo-door",
    "tag": "demo",
    "listen": "127.0.0.1:1234",
    "address": "192.0.2.10",
    "port": 53,
    "network": "udp"
  }]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `address` | 是 | 固定目标；IPv4/IPv6 字面量或域名，长度 1–255 |
| `port` | 是 | 固定目标端口，不得为 0 |
| `network` | 否 | `tcp`（默认）、`udp` 或 `tcp,udp`；大小写不敏感，允许逗号两侧空白；空项、未知项与重复项拒绝 |
| `sniffing` | 否 | TCP 首包嗅探；仅适用于含 TCP 的 `network`，且仅当 `address` 是 IP 字面量时生效 |

### 嗅探

```json
"sniffing": { "enabled": true, "dest_override": ["tls", "http"] }
```

| 字段 | 说明 |
|---|---|
| `enabled` | 默认 `true`；为 `false` 时不得设置 `dest_override` |
| `dest_override` | 非空、不得重复；当前支持 `tls`（ClientHello SNI）与 `http`（HTTP/1.1 `Host`） |

嗅探用 `peek` 观察首包，不消费字节，因此转发内容与未启用嗅探时完全一致。启用后按 `dest_override` **改写实际拨号目标域名**（端口保持配置值），与 Xray 的 `destOverride` 语义一致；它不是 `routeOnly`，当前 dokodemo 配置没有只影响路由而不改写拨号的开关。只接受单个完整 TLS 握手记录中的 ClientHello，以及带 `Host` 头的 HTTP/1.1 请求；跨记录分片、HTTP/2 前言、IP 字面量 Host、解析失败或超过 8 KiB 时回落到配置的固定目标。客户端可以伪造 SNI/Host 把固定 IP 目标改写到任意域名（端口固定），因此该功能只应在受控入口启用，不能当作身份认证或访问控制。

没有协议认证层；必须由监听地址和网络边界保证访问控制。不实现 `follow_redirect` 等系统级透明代理选项，也不接受从系统重定向获取原始目标。

## 行为

- **TCP**：接受连接后立即按 `address:port` 走路由，握手超时受 `limits.handshake_timeout_ms`、拨号受 `limits.dial_timeout_ms` 约束，随后双向搬运字节。
- **UDP**：按客户端源地址维护独立关联。每个关联一个直连上游套接字，或（路由选中 SOCKS5 上游时）一个 SOCKS5 UDP 中继；同一客户端源地址的后续报文复用该关联。
- **同端口**：`network` 含 `tcp` 时先绑定 TCP；含 `udp` 时在同一 TCP 端口上绑定 UDP，因此 `listen` 端口为 0 时两者仍共享内核选出的实际端口。纯 `udp` 只绑定 UDP。
- **路由**：UDP 的固定目标只选路一次；路由拒绝、HTTP 上游或链式出站等不受支持的 UDP 出站返回失败关闭——监听保持存活但丢弃数据报，不会静默改走直连或其它出站。
- **目标解析**：域名目标在启动时解析一次；解析失败时监听保持存活并丢弃数据报。DNS 记录/地址变化需要重启实例。
- **资源边界**：每个 UDP 关联占用一个 `limits.max_udp_associations` 额度；载荷超过 `limits.max_udp_payload` 丢弃；队列深度受 `limits.udp_queue_packets` 限制，字节预算受 `limits.udp_queue_bytes` 限制；关联空闲超过 `limits.udp_idle_timeout_ms` 后回收，关联结束后套接字、中继控制连接与额度一并释放。
- **SOCKS5 中继限制**：中继回程报文的分片与畸形报文直接丢弃，不重组；固定目标关联不依赖回程源地址。
- **计量**：TCP 计入 `tcp_flows`；UDP 每个关联计入 `udp_associations`；成功写出的载荷分别计入 `uplink`/`downlink`，超限或队列满计入 `dropped`。

## 验收缺口

1. 官方客户端/透明代理部署下的真实目标发现与转发；
2. UDP 关联在高并发源地址下的额度、回收与内存上界；
3. SOCKS5 上游中继的回程、分片丢弃与错误路径；
4. IPv6 监听、双栈与域名目标；
5. 三平台与精确 MSRV 运行测试。
