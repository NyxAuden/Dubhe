# 实验能力清单

这里列的是**代码已完成、但缺少完整验收矩阵**的能力。它们可以试用，但不构成兼容承诺。

判定标准见 [开源项目补齐计划](oss-checklist.md)：上游版本、方向、业务载荷、负向用例、
平台、构建六列全绿才算「已验收」；缺任何一列都留在这里。

## 入站与协议

| 能力 | 缺什么 |
|---|---|
| VLESS Vision | 三平台与完整官方客户端矩阵未跑完 |
| VLESS / VMess / Trojan REALITY | 21/29 开发任务；其余官方客户端与平台未验收 |
| VMess AEAD | 集中验收未做；Mihomo / Xray 有限组合通过 |
| WebSocket / WSS | 19/27；Close 不提供通用透明半关闭 |
| gRPC / HTTP2 | 开发 14/33；完整 headers/trailers 未覆盖 |
| XHTTP | 四种模式本机通过；`downloadSettings`、CDN 会话放置未实现 |
| HTTPUpgrade | 三协议入口本机通过；VMess/Trojan 官方组合未跑 |
| VLESS Encryption | 与 Xray 双向本机通过；三平台/MSRV/release 未验收 |
| Mux.Cool | 已实现；集中验收未做 |
| UoT v1/v2 | 已实现；集中验收未做 |
| Snell v4/v5/v6 | 客户端双向本机通过；官方全矩阵未做，QUIC 未实现 |
| Hysteria2 | Brutal 未完全对齐；realm/端口跳跃未实现 |
| TUIC v5 | 0-RTT 受上游限制；完整矩阵未做 |
| AnyTLS | 官方全矩阵未做 |
| ShadowTLS v3 | 仅 v3；不支持 v1/v2 与内层 UDP |
| Naive H1/H2/H3 | 官方全矩阵未做 |
| HTTP / Mixed | 无官方客户端矩阵 |
| WireGuard 入站 | 未与官方 WireGuard 客户端交叉验证 |
| NW3 Portal / Egress | 未做官方 Anywhere 客户端 |
| dokodemo-door | 本机回环通过；生产语义未验收 |
| VLESS / Trojan fallback | 稳定子集；完整回退语义未实现 |

## 出站与运行能力

| 能力 | 缺什么 |
|---|---|
| 上游代理出站（SOCKS5/HTTP/VLESS/VMess/Trojan/SS/Snell/AnyTLS/ShadowTLS/Hysteria2/TUIC/NW3/WireGuard） | 本机回环与部分官方组合通过；完整矩阵未做 |
| 出站组 `selector` / `urltest` | 单元与回环通过；官方客户端与三平台未做 |
| 反向 Mux Portal / Bridge | 本机回环通过；账户级安全限制未实现 |
| 零停机热重载 | 仅覆盖无 UDP 监听、无反向 portal 的场景 |
| 证书轮换 | 只覆盖 TCP/TLS 入口；QUIC/mKCP/REALITY/ShadowTLS 需重启 |
| 全站首包嗅探 | 只覆盖列出的流式入站；QUIC 0-RTT 与嵌套 QUIC 不解 |
| 按用户统计 | 覆盖 11 条 TCP 与 7 条 UDP 路径；WireGuard 与 SS 单密钥无身份 |

## 明确不做

- TUN / redirect / tproxy：这是客户端透明代理，不是服务端内核职责
- 出站 BIND
- 系统级 socket activation
- 完整 Xray/sing-box 配置运行时兼容（只提供一次性 `dubhe convert`）
- LTS 分支
