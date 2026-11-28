# 失败关闭证据矩阵（2026-11-14）

本矩阵把现有测试映射到“畸形输入、认证失败、重放、资源上限、取消/停机”五类失败路径。
它只列已有证据和缺口，不等于独立安全审计，也不把单个回环测试扩称为官方客户端矩阵。

## 进程级可用性：`accept()` 遇到可恢复错误不得退出

2026-11-24 实测发现并修复：`accept()` 返回 `EMFILE`（FD 耗尽）时，原实现
直接跳出 accept 循环，监听任务返回错误，主循环把整个 Server 停掉。

复现（`ulimit -n 128`，两个入站）：

| 版本 | 结果 |
|---|---|
| 修复前 | 118 条半开连接后，第二个入站 `ConnectionRefused`，进程 `EXIT=1` |
| 修复后 | 200 条半开连接进程仍存活；释放连接后第二个入站立即恢复响应 |
| Xray 26.10.31 对照 | 200 条后进程存活，第二个入站返回 503 |

含义：修复前**单个 IP 用一百多条半开连接就能让整台服务器上所有协议同时掉线**，
这是可被普通扫描器触发的拒绝服务。

现在的规则（`src/runtime/accept.rs` 的 `recoverable_accept_error`）：

| 错误 | 处理 |
|---|---|
| `EMFILE`(24) / `ENFILE`(23) | 计一次 `rejected`，退避 20ms 后重试 |
| `WouldBlock` / `Interrupted` / `ConnectionAborted` | 退避 20ms 后重试 |
| 其它（`PermissionDenied` / `AddrNotAvailable` 等） | 上报并停止 |

同时修正停机日志：两处 drain 循环原本都用 `"停止监听任务失败"` **覆盖**首个
错误，导致真正的根因（例如 `EMFILE`）从日志里消失；改为 `get_or_insert`，
保留首个错误。

仍未做：**按源 IP 的限速/失败退避**。现在只能靠全局 `max_connections` 与
每入口 `max_handshakes` 限制，单 IP 仍可占满这些名额（但不再能杀死进程）。

## 证据矩阵

| 入口/组件 | 畸形长度/截断 | 认证/重放 | 资源上限 | 取消/停机 | 主要证据 |
|---|---|---|---|---|---|
| SOCKS5 / HTTP / Mixed | 有 | 有 | 有 | 有 | `tests/integration.rs`、`tests/http_proxy.rs`、`tests/resources.rs` |
| VLESS / Vision / XUDP | 有 | 有 | 有 | 有 | `tests/vless.rs`、`tests/vision.rs`、`tests/xudp.rs`、`src/mux/tests.rs` |
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

1. **私钥/证书/配置文件权限**：`api.token_file` 与 TLS 私钥均已 fail-closed
   （0600，组/其他用户可读时拒绝启动）。**配置文件本身不在此列**：程序无法
   判断任意配置文件是否敏感（可能只含非机密字段），强制 0600 会破坏正常部署；
   该权限由部署层负责，属设计边界而非缺陷。若配置内含 `api.token` 明文或
   内联私钥，应改用 `token_file`/文件路径并确保 0600。
2. **完整握手 fuzz**：当前 fuzz 覆盖配置、Vision、SOCKS5/HTTP 数据报、XUDP、VLESS/
   Trojan/Snell/TUIC 解析、XHTTP/gRPC/VMess header；未覆盖 Shadowsocks AEAD/2022 EIH、
   REALITY、XHTTP 会话、gRPC stream、mKCP、TUIC 状态机、WireGuard、ShadowTLS 的完整
   握手/状态机。
3. **长时间/并发故障注入**：没有 72 小时 soak、网络黑洞、证书过期、磁盘满、管理 API
   不可用等生产故障演练。
4. **平台**：Linux x86_64 原生功能回归已完成（分批，test profile，静态 musl）；
   Windows、macOS x86_64 仍未完成。详见下方平台状态。
5. **独立审计**：没有第三方审计、渗透测试或正式的威胁模型评审结论。

## 平台状态

**Linux x86_64 原生功能回归已完成（分批，test profile，静态 musl）。**
测试产物在 macOS 交叉编译，在 Debian 11 x86_64、内核 `5.10.0-35-cloud-amd64`
的 1 vCPU VPS 上以非 root 身份原生执行。本轮主包 lib 与全部 82 个顶层集成
测试目标都有结果；按套件最终复验去重，**1709 通过、0 失败、91 忽略**。

- 分批执行：同套件以最后一次完整复验结果计入，首轮失败与复验映射保留在
  证据目录。因此「0 失败」指最终逐套件结果，**不是**「一次全量运行零失败」。
- 91 项忽略中有 81 项来自三个需官方对端的套件（`reference_clients` 79、
  `reality_official_outbound` 1、`reverse_official_bridge` 1）；其余 10 项是
  REALITY 系列的 Python cryptography/MLDSA 门禁、`resources` 与 lib 各 1 项。
  这些测试检测到依赖缺失后跳过，**不等于通过，也不算失败**。
- 本轮证据支持**默认功能回归**；官方对端互通与最终 release 工件另列验收。
- Windows、macOS x86_64 状态不变。

## 后续测试顺序

1. TLS 私钥/配置文件权限 fail-closed，并补负向测试。
2. 为上述缺口增加内部握手 harness/fuzz；每个入口至少覆盖截断、错误凭据、重放、并发上限。
3. 在 Linux ARM64 做 1–4 小时 soak；x86_64 默认功能回归已完成，发布前对实际
   release 工件再做一次非 root 原生冒烟（启动、一次允许转发、一次拒绝、正常停机）。
4. 把本矩阵与 `docs/fuzzing.md`、官方互通记录一起提交审计。
