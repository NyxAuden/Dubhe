# Snell v4/v5 HTTP/TLS obfs 对齐记录（2026-11-11）

变更：`align-snell-obfs`。本批补齐固定上游已有的 HTTP/TLS 外观承载，接入 Snell 入站、TCP 出站、UDP-over-stream 出站与 TCP 链式路径。v6 不提供该组合；QUIC 与出站顺序连接池不属于本批，不因 obfs 接入而标记完成。不新增依赖，不修改 vendor 或密码原语。

## 固定依据

- `github.com/sagernet/sing-snell@v0.0.0-20260904135315-bc5a12ac736f/obfs.go`
- SHA256：`49f65ed845a5148b533f052b99cf42b18821b4e41808368f6f6388e649032bac`
- sing-box v1.14.4 的 `protocol/snell/inbound.go`、`outbound.go` 与 `option/snell.go` 用于核对版本分派：入站注册 5/6、出站注册 4/6，只有 v4 记录客户端/v5 记录服务端接 obfs；v6 分派至 mode。
- 本内核已有 v4/v5 共享记录层，故对这两个版本提供同一正式 obfs；不据此声称固定 sing-box 注册了 v4 入站或 v5 出站，也不声称已执行 Surge 互通。
- 上游只读核查，未编译或执行上游。没有根据协议名臆造 v6+obfs 或 Snell QUIC。

## 线协议与外观边界

- HTTP 首个上行是 GET、Content-Length 与原始首次 payload，首个下行是一次 101 外观响应与 payload；后续直接传原字节。接收端按上游语义消费至首个 CRLFCRLF，不要求真实 HTTP Upgrade 或 WebSocket 帧。
- 客户端 HTTP key/User-Agent、服务端 101 外观响应均按进程固定；没有自造可选 wire 字段。上游日期使用本地时间却标 GMT，本实现使用 UTC 标 GMT；随机外观选择分布与写入分块也不承诺完全相同。**合法承载不等于浏览器、Surge 或上游指纹逐字节等价。**
- TLS 首上行 payload 位于 `0x8e`，最多 `0x400` 字节，之后为 9 字节 SNI 头、hostname 与固定 `0x42` 尾；记录/握手/扩展长度分别按 `0xd4`/`0xd0`/`0x4f` 加 hostname/payload 计算。
- TLS 首下行长度位于 `0x69`、payload 位于 `0x6b`；后续两方向均为 5 字节 application_data 外观记录，每条最多 `0x4000` 字节。
- TLS obfs **不是 TLS 握手**，没有证书认证、协商密钥或额外保密性。HTTP obfs **不是真实 WebSocket**。内层 Snell PSK、userkey、AEAD 与路由拒绝仍生效。

## 实施与资源

- `src/transport/snell_obfs.rs`：独立有界 Stream，首消息与后续记录、读游标、待写块与短写偏移由实例持有，无新后台任务。一次最多接受 16 KiB 业务，下一不同 buffer 必须先排空旧块；flush/shutdown 排空后推进底层，读方向也尝试推进已接受写。
- 首头拆包/Pending/取消不重建或重复首消息，空 ReadBuf 不消费。零长度 TLS 记录不是业务 EOF；每 poll 连续处理最多 32 条后让出。底层 WriteZero/错误与解码错误使流永久失败。
- HTTP 首头最多 8192 字节；TLS 首上行 1024、首下行/后续记录 16384，SNI 最多 253；超长与截断失败关闭。较上游宽松/无界读取更严格的检查是本地资源边界，不宣称接受任意无界非规范输入。
- 配置：v4/v5 `obfs_mode:none/http/tls`，v6 仅 none；出站 host 1–253 可见 ASCII、不得有斜杠/反斜杠/空白，HTTP URI 以 `/` 开头、最多 1024 可见 ASCII。none 禁止 host/URI，TLS 禁止 URI，凭据继续 Secret 脱敏。
- 入站 runtime/Prepared 在最外层只包装一次，并在服务边界类型擦除，避免所有入口 future 内联增长；出站初始化复用 Upstream 包装，TCP 与 UDP-over-stream 同一路径。所有记录高层写操作完成后实际 flush，避免缓冲首头/末块等到下一业务写而停滞。
- 内层 Snell 延迟首应答、零块 FIN、UDP 地址/空包与记录容量不变；TCP `via` 链两侧可用，UDP `via` 仍明确拒绝。
- 成对回环配置模板为 `examples/snell-obfs.json`、`examples/snell-obfs-outbound.json`；不修改现有默认 none/v6 模板。

## 开发验证

普通开发环境：macOS ARM64，Rust/Cargo 1.95.0；`CARGO_INCREMENTAL=0`，锁定离线。以下是本机开发证据，不是外部兼容验收。

1. 首轮 fmt、全目标 check 与定向回归退出 0：既有 Snell 入站 20 项、新 obfs 集成 6 项、基础出站 9 项、`cargo test --lib snell` 26 项通过（其余 623 项被过滤）。首轮仅含 6 项 obfs 模块测试；日志为本机会话任务 `b20dic7ct.output`。
2. 补首消息只写出 3 字节后取消、首 payload/SNI/尾/后续记录多个精确读取切点；`cargo test --lib transport::snell_obfs` **8 passed、0 failed、0 ignored，643 filtered**，退出 0。日志为本机会话任务 `b6zwa0u16.output`。
3. 随后补底层 WriteZero/ConnectionReset 的永久失败、载荷/尾部截断、超长 SNI/后续记录、错误记录类型及配置长度边界、两个示例 roundtrip，均已由本批最终集中回归覆盖。
4. 最终 `cargo fmt --all -- --check`、`cargo check --locked --offline --all-targets`、`cargo test --locked --offline` 全部退出 0；**1272 passed、0 failed、43 ignored**，75 个结果块（含 9 项 obfs 模块、6 项 obfs 集成）。日志：本机 `/tmp/rpk-snell-obfs-validation.goAHVP`。命令显式去除 `RUST_MIN_STACK`，使用默认线程栈；相较前批新增 15 项。该结果只覆盖本批收尾输入，不覆盖后续连接池等改动。

集成测试覆盖 v4/v5 × HTTP/TLS 的 96 KiB TCP、零块 FIN 后反向响应、UDP 双目标/空包/可用 IPv6、错误 userkey 不触达目标、路由拒绝、SOCKS5 链前后、部分首头停机与监听端口重用。模块测试另核固定首消息字段/偏移、20 KiB 编码分块、双角色回环、短写/取消/flush、空读/截断与失败状态。

回归结束后仅清理本项目 `target/debug/deps/*.rcgu.o`：1143 个文件、逻辑大小 5.96 GiB；保留库、测试二进制、日志与私有测试资产。清理后本机可用约 38 GiB。

现有编译警告仍存在，不以退出 0 表述为零警告。不设置全局 `RUST_MIN_STACK`、不删减失败场景或提高栈掩盖回归。

## 验收边界

官方 Snell/Surge/sing-box 客户端、三平台、精确 MSRV、release、长期容量与正式安全验收均未执行；本机双方互测及固定字段向量不能替代这些证据。不归档、Git 提交、发布，不修改系统代理/DNS/路由/防火墙，不操作 Colima/容器或系统缓存。私有测试资产与日志仅本机保留。
