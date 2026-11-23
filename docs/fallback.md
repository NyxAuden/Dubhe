# VLESS/Trojan fallback 边界（开发实现，待集中验收）

本页描述认证失败后把原始字节转发到本地目标的 fallback 子集。该能力是 Xray fallback 的**稳定子集**，不是通用反向代理，也不是“认证失败一律吞掉”的容错开关。

## 配置

```json
{
  "type": "vless",
  "fallbacks": [
    { "dest": 8080 },
    { "dest": "127.0.0.1:8081", "path": "/api", "xver": 1 }
  ]
}
```

- 仅 `vless` 与 `trojan` 入口支持；`vmess` 不支持 fallback（VMess 认证失败不存在明文可回放语义）。
- `fallbacks` 最多 16 项，按声明顺序匹配，首个匹配项生效。
- `dest`：
  - 裸端口（1..65535）→ 固定目标 `127.0.0.1:<port>`；
  - `host:port` 字符串（IPv6 用 `[addr]:port`）；
  - 以 `/` 开头的 Unix 套接字绝对路径；配置只拒绝根路径、NUL 和超过
    1024 字节的路径，实际路径长度限制由平台在拨号时返回错误。Unix 套接字
    仅在 Unix 平台运行；其他平台编译保留该配置但运行返回 `Unsupported`。
- `xver`：`0`（默认）不发 PROXY 头，`1` 发 PROXY protocol v1 文本行，`2` 发 v2 二进制头。
- 匹配字段均为可选，缺省即通配：
  - `name`：TLS SNI，ASCII 大小写不敏感；
  - `alpn`：协商到的 ALPN 精确匹配；
  - `path`：首个 HTTP 请求行的路径，忽略 query；需以 `/` 开头。
- 每个匹配字段限 1..255 字节 ASCII 可见字符。

## 行为

1. 仅在 TLS 握手成功后、协议认证阶段判定失败时触发；TLS 握手失败不进入 fallback。
2. 只回放认证阶段**确实已消费**的字节，不重写、不解密、不补造。
3. 若存在带 `path` 的条目且已读字节中没有完整首行，会做一次最长 250ms 的有界补读；读不到则视为无 path。
4. 回放字节上限 4096；超限 fail-closed（直接关闭），不投递截断数据。
5. TCP 目标解析走同一 DNS 与拨号预算（`dial_timeout_ms`/`dial_attempt_timeout_ms`）；
   Unix 套接字目标直接按 `dial_timeout_ms` 拨号，不做 DNS 解析。
6. 建立目标连接后按 `xver` 先写 PROXY 头，再写回放字节，随后双向透传并计入计量；
   Unix 套接字与 TCP 目标使用同一行为，PROXY 头中的地址仍取自真实 TCP 对端与
   本地监听地址。
7. 没有任何条目匹配 → 连接关闭，不发送伪造成功响应。
8. 认证**成功**的连接完全不受 `fallbacks` 影响。

## 安全边界

- 认证失败不得半关闭 TLS（不发 `close_notify`），否则客户端会在回放前看到 EOF；实现为此使用不 shutdown 的读取路径。
- PROXY 头中的地址取自真实 TCP 对端与本地监听地址，不采信任何客户端自报字段。
- 混合地址族（如 v4 对端 + v6 本地）无法用单一 PROXY v2 地址块表达，此时发送 `LOCAL` 命令（`0x00`），不伪造地址。
- 回放是原样转发，因此目标服务必须被信任；不要把 fallback 指向不可信或公网服务。

## 明确不支持

- VMess fallback、REALITY fallback。
- **把失败流量交给另一个 TLS 入口**（例如 `vless` 的 fallback 指向本进程的
  `trojan` 入口）：回放的是 TLS 解密后的明文，对端读到的是密文，实测直接
  `InvalidData`。可以指向明文入口（`http` / `mixed` / `socks5`）、普通 Web 服务
  或 Unix 套接字。
- 按 SNI/ALPN 自动选择协议栈：`fallbacks` 只按配置里写的 `dest` 回放，不做协议嗅探。
- 依据 `Forwarded`/`X-Forwarded-*` 推断真实客户端。
- 官方客户端集中验收尚未执行。

## 证据

本地测试 `tests/fallback.rs` 覆盖：明文回放、合法 VLESS 不受影响、`xver=1` PROXY 行、
`name`/`alpn`/`path` 匹配与通配回落、Trojan fallback 回放，以及 Unix 套接字
`dest` 的真实 `UnixListener` 回环回放。模板见 `examples/vless-fallback.json`、`examples/trojan-fallback.json`。
