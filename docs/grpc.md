# gRPC / HTTP2 入站边界（开发实现，待集中验收）

本页描述本仓库 gRPC 入站/出站的**已实现行为与明确限制**。开发段完成度14/33；已与官方 Xray v26.10.31 完成 VLESS（single 与 multiMode）、VMess、Trojan 的 gRPC/TLS 双向 TCP 本机互通、Xray VLESS/gRPC TLS XUDP 到本内核入站的 TCP/UDP，以及 VLESS/VMess/Trojan REALITY-over-gRPC 双向（出站改为响应头惰性等待；REALITY 无 ALPN 时按 h2 prior-knowledge）；本轮补充请求头/trailers 校验、出站 `user_agent`/`:authority`/initial window/keepalive 配置和失败关闭测试；完整官方矩阵、Linux x86_64、Windows、可发布 release 与最终报告均未执行；macOS ARM64 的 Rust1.91/1.95 与 Linux ARM64 的 Rust1.95 全量测试已通过。本地29项入站测试与4项出站gRPC单元测试通过，不等于完整官方兼容。

## 入口与配置

- 独立入口：`vless-grpc`、`vmess-grpc`、`trojan-grpc`。旧 `vless`/`vmess`/`trojan` 入口行为不变。
- `grpc.path` 必填，1..1024个ASCII可见字符，必须以 `/` 开头，不得包含 `#`/`?`。示例：`/GunService/Tun`。
- 导出用真客户端核对过的路径形式（2026-11-24，官方 Xray v26.10.31 / sing-box
  v1.14.4 / Mihomo v1.19.33，监听端口逐一确认属于测试进程）：
  `/GunService/Tun` 与 `/svc/TunMulti` 交给 Xray，`/GunService/Tun` 与
  `/svc/a/b` 交给 Mihomo，双路径节点（`path` + `multi_path`）以单流客户端
  交给 sing-box；`/svc/TunMulti` 导出到 sing-box 会明确拒绝。
- `dubhe convert` 把 Xray 的 `serviceName` 换算成完整路径（`/svc/a|b` →
  `/svc/a` + `/svc/b`，已用真 Xray 的 `multiMode` 客户端打 `/svc/b` 验证回环）：老式 `GunService` →
  `/GunService/Tun`、`/GunService/TunMulti`；新式 `/svc/单|多` → `/svc/单`、`/svc/多`
  （只在最后一个 `/` 之后解析 `|`）。同一条路径同时注册两种流（Xray 允许）无法在
  dubhe 里区分，转换会失败。
- `grpc.multi_path` 可选，规则同上；配置后该路径使用 MultiHunk（多个 `data` 项按顺序拼接），`grpc.path` 仍使用单 Hunk。
- VLESS gRPC 不接受 `flow`（Vision/REALITY 不组合）；命令 3/`v1.mux.cool` 进入完整 Mux，TCP 会话始终允许，`xudp`（默认开启）控制 Mux 内的 UDP 会话，见 [Mux 说明](mux.md)。
- VMess gRPC 必须提供真实 TLS 证书/私钥，或配置 `reality` 作为安全层；明文入口不提供（VMess 只信真实 TLS/REALITY）。
- VLESS/Trojan gRPC 可选TLS；无证书时必须显式 `"allow_insecure_transport": true`，只接受HTTP/2 prior-knowledge。
- 模板见 `examples/vless-grpc.json`、`vless-grpc-tls.json`、`vless-grpc-multi.json`、`vmess-grpc-tls.json`、`trojan-grpc.json`、`trojan-grpc-tls.json`；占位UUID/密码/证书路径必须先替换。

## 传输与安全

- 真实TLS只提供 `h2` ALPN，并要求实际协商到 `h2`；否则连接失败。
- 明文只允许HTTP/2 prior knowledge；`https` scheme 不表示加密，固定Mihomo/sing-box Lite构造在明文下仍可写 `https`，服务端不据此放宽任何认证。
- `te` 可缺省；出现时必须是单值 `trailers`（固定代理客户端兼容例外，不是通用gRPC规则）。官方 Xray 客户端实测发送 `te: trailers`；本内核入站接受缺省与单值 `trailers`。
- 拒绝 `content-length`、任意 `content-encoding`、非 `identity` 的 `grpc-encoding`；消息压缩flag必须为0。
- 仅POST、HTTP/2、完整路径、`content-type: application/grpc` 或 `application/grpc+proto` 进入RPC；应用头最多64项。`user-agent` 不参与准入，可由官方客户端自定义。
- `grpc-timeout` 接受1到8位数字加 `H/M/S/m/u/n`，只能提前该RPC的绝对期限；0表示立即到期。格式错误在准入阶段返回HTTP 400（官方grpc-go则返回RPC级错误，本项目未复制该差异）。
- 出站响应必须满足：HTTP 200、单值 `content-type: application/grpc`（或 `+子类型`）、无 `content-encoding`、`grpc-encoding` 仅 `identity`；`grpc-status` 必须存在且为十进制0。非0、重复、非数字或缺失均返回错误，不再把 trailers 当作成功 EOF。`grpc-message` 按 gRPC 百分号转义解码后进入错误文本。
- 支持 Trailers-Only 响应：`grpc-status` 位于初始HEADERS且stream结束；状态为0时按成功EOF处理，非0立即失败。
- 出站请求头：`content-type: application/grpc`、`te: trailers`；可选 `user_agent`（`chrome`/`firefox`/`edge` 映射为静态浏览器UA快照，`golang`/空值不发送，其他值原样发送）与 `authority`（缺省按Xray语义：显式配置 > TLS server_name > 明文域名不带端口 > 端点地址；REALITY未显式配置时回落端点地址）。
- 出站 `initial_windows_size` 映射为 h2 `SETTINGS_INITIAL_WINDOW_SIZE`；`idle_timeout` 启用周期PING（下限10秒），`health_check_timeout` 为PING应答超时（缺省20秒）。`permit_without_stream` 被接受，但当前每条h2连接只承载一个RPC，因此不改变行为。
- 官方 Xray v26.10.31 服务端在 VLESS 认证失败时实测返回 HTTP 200、初始HEADERS `grpc-status: 0`、空body（不是非0 trailers）；客户端随后由 VLESS 层 `UnexpectedEof` 失败关闭。本内核出站保持该行为，不伪造或改写官方状态。

## 资源与期限

- 全局 `limits.max_grpc_streams` 默认256，每连接 `max_grpc_streams_per_connection` 默认16（1..128）；后者同时作为H2 `MAX_CONCURRENT_STREAMS` 通告值。
- `grpc_streams` 计量已准入、尚未真正回收的RPC；`connections` 仍按物理TCP计一次。
- 每连接接收/发送窗口65535、最大帧16384、HPACK表4096、头列表8192、每流发送阈值65536。出站可把流的初始窗口调大，但不改变连接级窗口与动态BDP策略。
- 出站配置新增 `authority`、`user_agent`、`idle_timeout`、`health_check_timeout`、`permit_without_stream`、`initial_windows_size`；仅允许用于 `grpc`，非法值在配置校验阶段拒绝。入站配置不新增keepalive字段，官方Xray服务端 `idle_timeout`/`health_check_timeout` 的keepalive行为未实现。
- 结构护栏：9字节帧头、头块≤16384字节且≤8帧、控制帧每秒≤256、每driver poll最多32帧头/65536原始字节。
- 绝对期限：TLS/preface/首SETTINGS与ACK共享 `handshake_timeout_ms`；首HEADERS起点到完整认证共享同一期限；活动连接的任何不完整帧头/头块另受独立绝对计时器约束。
- stop后禁止新RPC准入，已有RPC在 `shutdown_timeout_ms` 内排空；期限到或force后才取消。

## 消息与半关闭

- 五字节前缀：flag=0，长度≤1MiB；single Hunk 的重复 `data` 取末值，MultiHunk 最多256项并按出现顺序拼接，空项跳过；空消息不表示EOF。
- 请求方向的END_STREAM只代表字节流EOF；目标先FIN时，请求方向仍可继续上行。
- 响应方向正常结束时发送 `grpc-status: 0` trailers；请求方向结束不要求对端立即关闭。
- 已发送HTTP 200后认证或业务失败的入站RPC会终止RST_STREAM，不发送伪造的 `grpc-status: 0`；官方Xray客户端实测看到 `RST_STREAM(CANCEL)` 并失败。准入阶段失败则使用HTTP状态码（如415/400/404），不进入200 RPC。
- 每次业务写最多16384字节，取得发送容量后才写；不做物理flush确认。
- 明文/TLS、single/multi、TCP/原生UDP、命令 3 Mux（TCP；`xudp` 门控 UDP）及 packetaddr 均已编写本地回环测试并通过定向运行；命令 3 在认证成功后先发送唯一成功响应，再进入 Mux。IPv6、跨承载重放与部分安全选项组合仍在集中验收范围。测试代码存在不等于新 Mux 已集中验收。

## 明确不支持

- HTTP/1.1 Upgrade、gRPC-Web、JSON/自定义编解码、消息压缩（request/response gzip 均不支持）。
- 请求trailers、通用metadata转发、任意grpc保留语义。
- VLESS Vision 与 gRPC 组合；REALITY 与 gRPC 是上游支持的组合，本仓库已接入。
- 入站 keepalive：不解析/不实现官方 `idle_timeout`、`health_check_timeout`；出站 `permit_without_stream` 仅为配置兼容，当前单RPC连接模型下无额外行为。
- 浏览器UA别名使用静态快照，不复制官方Xray按日期/CPU随机生成Chrome/Firefox/Edge版本的行为；需要精确指纹时应显式配置完整 `user_agent`。
- 入站配置仍使用本项目的 `path`/`multi_path`，不兼容官方 `grpcSettings` 的 `serviceName`/`multiMode` 键名。
- 已执行 Xray VLESS（single/multiMode）、VMess、Trojan 与 REALITY-over-gRPC 的有限组合；Mihomo/sing-box gRPC、完整官方矩阵与三平台/ MSRV/release 尚未执行，不得把本地回环或 HTTP 200 当作完整兼容。

## 已验证命令与结果（2026-11-13）

- `cargo test --locked --test grpc_inbound`：29通过，0失败（含缺省`te`+`grpc-encoding: identity`+自定义UA、认证失败不产生`grpc-status: 0`、配置字段接受/拒绝）。
- `cargo test --locked --lib outbound::tests::grpc_`：4通过（合法0 trailers、非0 trailers及`grpc-message`解码、缺失trailers、Trailers-Only错误、authority/user-agent）。
- `cargo build --locked`：通过。
- 官方Xray v26.10.31本机回环：Xray客户端→本内核入站（single/multi）与内核出站→Xray服务端（single/multi）均返回 `reality-official-interop-ok`；带 `user_agent=firefox`、`authority=localhost`、`idle_timeout=10`、`health_check_timeout=5`、`permit_without_stream=true`、`initial_windows_size=1048576` 的出站同样通过（运行超过一个PING周期）。
- 本机h2c捕获对比：官方客户端在显式 `user_agent` 时原样发送，`chrome`/`firefox`/`edge` 别名发送浏览器UA，`golang` 发送空UA；未配置时不发送UA。内核出站默认同样不发送UA，配置后逐字节对比路径/`content-type`/`te`/UA/`:authority` 一致。
- 官方服务端认证失败实测：HTTP 200 + 初始HEADERS `grpc-status: 0` + 空body；内核出站按成功gRPC EOF处理后由VLESS层 `UnexpectedEof` 失败关闭。非0或缺失trailers的失败关闭由单元测试覆盖。

## 证据

开发日志与测试记录保存在 `.test-artifacts/grpc-dev-l4x9k2m7/gate/`（非公开凭据目录，不应整体发布）。本轮官方对比配置与捕获输出位于 `/tmp/rpk-grpc-extra/`（临时验证材料，不随仓库发布）。
