# 失败关闭证据矩阵（2026-11-14）

本矩阵把现有测试映射到“畸形输入、认证失败、重放、资源上限、取消/停机”五类失败路径。
它只列已有证据和缺口，不等于独立安全审计，也不把单个回环测试扩称为官方客户端矩阵。

## 证据矩阵

| 入口/组件 | 畸形长度/截断 | 认证/重放 | 资源上限 | 取消/停机 | 主要证据 |
|---|---|---|---|---|---|
| SOCKS5 / HTTP / Mixed | 有 | 有 | 有 | 有 | `tests/integration.rs`、`tests/http_proxy.rs`、`tests/resources.rs` |
| VLESS / Vision / XUDP | 有 | 有 | 有 | 有 | `tests/vless.rs`、`tests/vision.rs`、`tests/xudp.rs`、`tests/mux_cool.rs` |
| VMess AEAD / UDP | 有 | 有 | 有 | 有 | `tests/vmess.rs`、`tests/xudp.rs` |
| Trojan / TLS / WS / fallback | 有 | 有 | 有 | 有 | `tests/integration.rs`、`tests/httpupgrade.rs`、`tests/websocket_trojan.rs`、`tests/fallback.rs` |
| Shadowsocks AEAD/2022 | 有 | 有 | 有 | 有 | `tests/shadowsocks_udp_wire.rs`、`tests/shadowsocks_resources.rs`、`tests/shadowsocks_listener.rs` |
| REALITY / REALITY fallback | 有 | 有 | 有 | 有 | `tests/reality_inbound.rs`、`tests/reality_lifecycle.rs`、`tests/reality_boundaries.rs`、`tests/reality_fallback.rs` |
| WebSocket/WSS | 有 | 有 | 有 | 部分半关闭限制 | `tests/websocket_early.rs`、`tests/websocket_eof.rs`、`tests/websocket_alpn.rs` |
| gRPC / HTTP2 | 有 | 有 | 有 | 有 | `tests/grpc_inbound.rs`、`tests/grpc_library.rs` |
| XHTTP / HTTPUpgrade | 有 | 有 | 有 | 有 | `tests/xhttp.rs`、`tests/httpupgrade.rs`、`tests/xhttp_outbound_client.rs` |
| mKCP | 有 | 有 | 有 | 有 | `tests/kcp.rs`、`tests/kcp_outbound_client.rs` |
| Snell v4/v5/v6 | 有 | 有 | 有 | 有 | `tests/snell.rs`、`tests/snell_obfs.rs`、`tests/snell_reuse.rs` |
| Hysteria2 | 有 | 有 | 有 | 有 | `tests/hysteria2.rs` |
| TUIC v5 UDP/TCP | 有 | 有 | 有 | 有 | `tests/tuic.rs`、`tests/tuic_outbound_modern.rs` |
| ShadowTLS v3 | 有 | 有 | 有 | 有 | `tests/shadowtls.rs`、`tests/shadowtls_outbound.rs` |
| AnyTLS / UoT | 有 | 有 | 有 | 有 | `tests/anytls.rs`、`tests/anytls_pool.rs`、`tests/uot.rs` |
| Naive H1/H2/H3 | 有 | 有限 | 有 | 有 | `tests/naive.rs`、`tests/naive_h3.rs`、`tests/naive_outbound.rs` |
| WireGuard server | 有 | 有 | 有 | 有 | `tests/wireguard_server.rs` |
| NW3 Portal/Egress | 有 | 有 | 有 | 有限 | `tests/nw3.rs`、`tests/reverse_bridge.rs` |
| DNS / 路由 / 嗅探 | 有 | 不适用 | 有 | 有 | `tests/dns.rs`、`tests/sniffing.rs` |
| 管理 API | 有（400/401/405/404） | 有 | 有 | 有 | `tests/admin_api.rs` |
| TLS 证书/私钥加载 | 有 | 有（不匹配拒绝） | 不适用 | 有（重载） | `src/tls.rs` 单元测试、`tests/cert_reload.rs` |

“有”表示存在覆盖对应类别的回环测试；不代表已做独立审计、全平台或官方客户端矩阵。

## 明确缺口

1. **私钥/证书/配置文件权限**：`api.token_file` 已检查 0600；TLS 私钥现在也会拒绝
   组/其他用户可读（Unix），但配置文件权限仍依赖部署层，尚未 fail-closed。
2. **完整握手 fuzz**：当前 fuzz 覆盖配置、Vision、SOCKS5/HTTP 数据报、XUDP、VLESS/
   Trojan/Snell/TUIC 解析、XHTTP/gRPC/VMess header；未覆盖 Shadowsocks AEAD/2022 EIH、
   REALITY、XHTTP 会话、gRPC stream、mKCP、TUIC 状态机、WireGuard、ShadowTLS 的完整
   握手/状态机。
3. **长时间/并发故障注入**：没有 72 小时 soak、网络黑洞、证书过期、磁盘满、管理 API
   不可用等生产故障演练。
4. **平台**：Linux x86_64 原生全量、Windows、macOS x86_64 仍未完成。
5. **独立审计**：没有第三方审计、渗透测试或正式的威胁模型评审结论。

## 后续测试顺序

1. TLS 私钥/配置文件权限 fail-closed，并补负向测试。
2. 为上述缺口增加内部握手 harness/fuzz；每个入口至少覆盖截断、错误凭据、重放、并发上限。
3. 在 Linux ARM64 做 1–4 小时 soak，在原生 Linux x86_64 做最终矩阵。
4. 把本矩阵与 `docs/fuzzing.md`、官方互通记录一起提交审计。
