# Naive 原生 H2/H3 出站对齐记录（2026-11-12）

变更：`align-naive-outbound`。本批是原生 Rust 的 HTTP/2 与 HTTP/3 普通 CONNECT 出站、Basic/TLS/首八块填充，以及固定上游公开的可选 UoT v2。不是 Chromium/Cronet 指纹、ECH、连接池、QUIC 0-RTT 或所有 NaiveProxy 可选功能的等价实现；H1 出站仍单独待补。

## 固定依据

- NaiveProxy 发布 `v154.0.8037.49-5`；`klzgrad/forwardproxy` 提交 `e747854e78743dba85c039b38ed185fb11d93667`，`forwardproxy.go` SHA256 `07b4e3e7cff3ea3d45e08e9016168b39400222d014d420f6ed26507461aafa6b`。H1 hijack 无 payload padding，H2/H3 在非空 Padding 协商后双向首8块 PaddedData，第9块起裸字节，见[入站批记录](naive-h3-development.md)。
- sing-box v1.14.4 的 `option/naive.go`、`protocol/naive/outbound.go`：正式 TCP 出站可选 QUIC、额外头和 UoT，未启用 UoT 时不提供 UDP；`protocol/naive/inbound.go` 使用正式 UoT Router，而非私有 UDP over HTTP 协议。
- 固定 `cronet-go@v0.0.0-20260912104727-0d28acc44093/naive_conn.go` SHA256 `c32bf867819dd773398da7506c25360be55cab887ac31237c1ab48c814b5aed3`：padding 头字符集/长度/后缀、首8块 u16be/u8/原始数据/零填充、最大65535原始长度；成功状态为200。
- sing-box `protocol/naive/outbound.go` SHA256 `78f808eca7d13e322e69222274660d25a6429767e66650c6466c079696f0178e`；上游仅只读核查，不编译或运行，不引入 Cronet 库或外核子进程。

## 实施边界

- `type:naive` + 必需 `naive` 对象，`http_version:"2"/"3"`（默认2）、可选 `extra_headers` 与 `udp_over_tcp`（默认false，仅UoT v2）。根用户名/密码及显式 PEM 信任锚必需，Basic 用户名不得含冒号；未知/不适用字段拒绝，不允许 insecure/REALITY/任意 transport 组合。
- 额外头最多32项、单值最多2048字节、字段总预算4096字节，ASCII且不得有控制字符；禁止伪头、认证/Host/Padding/连接与内容帧字段、Cronet内部控制头及大小写重名。Debug 只显示额外头数量，不回显其值；序列化仍包含真实配置，不应发布。
- H2 经既有 Context TCP/TLS/via 工厂，实际验证 ALPN h2；H3 使用独立 Quinn/TLS1.3，实际验证 ALPN h3，不嵌入 TCP via 链。每业务独立连接，不宣称共享池或 Cronet 的网络外观。
- 普通 CONNECT 只有目标 authority，不使用扩展 `:protocol`、`:scheme`、`:path`。请求非空 Padding，响应200且非空 Padding 才启用双向填充；无响应头保持原始流，重复 Padding 拒绝。
- 锁定 h3 0.0.8 客户端会错误补 scheme/path；生产适配只用公开 QUIC backend 在首 HEADERS 换为有界 RFC9204 无动态表字面字段，其余控制/响应/DATA 仍由成熟 h3 完成。不修改 vendor、不放宽服务端校验。
- 成熟 h2 API 的 DATA 入队不是 flush。把既有 XHTTP 的 Buf 消耗/底层 flush 观察器原语抽为共享 `h2_progress`，Naive 发送泵逐批确认真实排空、FIN亦确认；不能用 PING 或 send_data 返回代替排空证据。
- 写队列8块、每块最多16KiB，头上限8192、流接收窗口64KiB、连接接收窗口256KiB；H2发送泵逐批flush后才取下一块，QUIC另限发送窗口256KiB。QUIC peer uni3/bidi0、不启用DATAGRAM。短写/Pending/取消保存既有有界块与确认，读方向也推进已接受 padding 写，FIN只发一次且保留反向读取。
- 握手派生任务前建立 Drop guard，QUIC握手前登记端点与成熟Quinn内部驱动回收，错误CA/半握手取消也被 children 屏障覆盖。关闭先正常排空，超时后取消公开Runtime接口拥有的驱动并等其析构；不将wait_idle超时冒充回收完成。driver/writer不自持Context，错误存在通道之外，不能把发送错误伪装为正常EOF；已经成熟流确认的FIN/END_STREAM则保持读方向EOF，不受随后连接关闭改写。
- UDP：仅显式UoT v2，每目标专属普通CONNECT到 `sp.v2.udp-over-tcp.arpa:0`，`isConnect=true` + SOCKS目标、u16长度数据报。保留空包/双栈，不是私有QUIC数据报；接入共享Association目标/队列/字节预算。接收半帧保存在实例，发送开始后取消不可继续或补FIN。
- Naive H2/H3服务端只对已认证的正式魔数0端口占位识别UoT，进入已有UDP处理，不先DNS/拨目标。普通0端口仍拒绝，普通HTTP与H1历史payload行为不改变。
- H2可位于TCP链前后；普通HTTP CONNECT在读应答前补flush以支持有缓冲的上一跳。低层 `outbound::connect` 没有运行时任务所有权，Naive要求Context连接工厂，不假装忽略该需求。

## 开发验证状态

macOS ARM64，Rust/Cargo1.95.0，`CARGO_INCREMENTAL=0`，锁定离线且显式去除全局 `RUST_MIN_STACK`。前批 Snell 1289/0/43 只覆盖其当时输入，不覆盖本批改动。

- 首轮fmt、全目标check与定向回归退出0：15项Naive相关模块、7项新出站集成、3项旧Naive、9项旧Naive H3、6项XHTTP出站、19项既有代理出站通过。模块其余656项被过滤，不称全量；日志 `/tmp/rpk-naive-outbound-targeted.Dd3J3E`。
- 补H3无padding/首8块与第9块、重复头/错误状态/截断及慢头取消、padding背压独立读后，相关模块17项通过，退出0；日志 `/tmp/rpk-naive-outbound-boundaries.utLN7x`。
- 继续补错误/缺失ALPN和QUIC半握手取消：全目标check通过，模块 **18 passed、1 failed、0 ignored**；因前项失败，后续集成未执行。失败为取消半握手后children已空但UDP端口仍 `AddrInUse`：清理任务忽略2秒wait_idle超时，Quinn的驱动仍可能在排空期占用socket。日志 `/tmp/rpk-naive-outbound-final-targeted.mXaJU1`。
- 修复使用既有Quinn公开Runtime接口，把内部endpoint/connection驱动纳入TaskTracker；先正常关闭和排空，期限后取消驱动并等待future真实析构，不修改vendor、定时器、密码原语或端口断言。另补已确认FIN后的稳定EOF与无FIN关闭仍错误的独立测试。修复后相关模块 **20 passed、0 failed、0 ignored、656 filtered**，退出0，日志 `/tmp/rpk-naive-outbound-lifecycle-fixed.XwpXHJ`。该定向结果不是完整回归。
- 最终 `cargo fmt --all -- --check`、`cargo check --locked --offline --all-targets`、`cargo test --locked --offline` 全部退出0，**1309 passed、0 failed、43 ignored**，77个结果块；日志 `/tmp/rpk-naive-outbound-validation.GIDYsU`。相较前批新增20项（11客户端/UDP模块、2 padding模块、7集成），Naive相关模块现为20项。未设置更大的全局线程栈；该结果只覆盖本批收尾输入，不覆盖后续协议改动。

已编写并逐轮验证的范围包括：严格配置与示例roundtrip；独立H2/H3对端验证普通CONNECT、额外头、双向首8/第9、无padding响应、200/错误状态/重复头/截断；真实TLS与错误身份/CA零目标；大载荷、FIN后反向响应、H2链两侧、默认UDP拒绝、UoT双目标/空包/双栈/超限后会话继续、4字节预算回收、慢头取消、有限队列/确认取消及强停端口回收。最新新增用例只有拿到对应真实结果后才计入通过。

最终回归结束后仅清理本项目 `target/debug/deps/*.rcgu.o`：1174个文件、逻辑6.22GiB；保留库、测试二进制、日志与私有资产。清理后本机可用约38GiB。

现有 `unused`/`dead_code` 等编译警告保留，命令退出0不等于零警告。没有提高默认线程栈、降低报文容量或跳过认证/资源负向测试。

## 验收与操作边界

官方NaiveProxy/其他官方客户端、三平台、精确MSRV、release、长期容量和正式安全审计未执行。只声明记录在案的本机开发证据，不将双方自测或独立对端代替官方兼容。未新增核心依赖、修改Cargo锁文件或vendor/密码原语；不Git、归档、发布，不修改系统代理/DNS/路由/防火墙，不操作Colima/容器/系统缓存。私有测试凭据、私钥、日志保留本机。
