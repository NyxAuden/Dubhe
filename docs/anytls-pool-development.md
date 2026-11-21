# AnyTLS 正式出站会话池对齐记录（2026-11-12）

变更：`align-anytls-outbound-pool`。本批补固定上游的空闲会话选择、持续控制帧和正式ID分派，TCP与UoT共池；不把FIN改成TCP半关闭，不自造优先占用忙会话的并发调度算法，不增加wire字段、核心依赖、vendor补丁或密码原语。

## 固定上游与角色

`github.com/sagernet/sing-anytls@v0.0.0-20260902142641-43bb1cbea74e`，只读核client.go、session.go、stream.go、padding.go、anytls.go；不编译或运行上游。

| 文件 | SHA256 |
| --- | --- |
| client.go | `f363c781153cbeac9575540e6e189a5226735126c26c1ef22ed2c6e95a959636` |
| session.go | `e52cc8976c0caa07279cad01906bf2d29b0c03bf15111f58d763e22f9ab36935` |
| stream.go | `a3ed56ec20c2ef7bfe25e68e99e4093260552cc2ff7d8276a377171298e7068c` |

另核sing-box v1.14.4的option/anytls.go与protocol/anytls/outbound.go，公开空闲检查/超时/最少保留配置，TCP/UoT经同会话客户端建流。该版本实际依赖`github.com/anytls/sing-anytls v0.0.11`，**不能混称其使用上述sagernet提交**；本批实现固定已读协议与池语义，不以本地另一v0.0.13源码替代该依赖的官方互通证据。

- 上游takeIdleSession优先最新空闲会话，pool空才dial；并不优先把每个并发请求塞到忙TLS。
- TLS前导与Settings一次，每流递增u32 ID，SYN后PSH目标，非空SYNACK错误限于该流，FIN整流关闭且peer FIN不回送；未知/迟到ID不成为下一流业务。
- 默认空闲检查/超时各30秒、最少0项；保留已有空闲不主动预拨。上游≤5秒回默认，本内核对显式非法值拒绝而非默改。
- 复用会话已知v2时，从第2流开始3秒开流看门狗，下一完整帧头到达解除；不是必须等目标SYNACK或payload收全。

## 实施与公开安全边界

- `AnyTlsClientOptions`可省略，默认启用复用；字段为`disable_reuse`、`idle_session_check_interval_ms`/`idle_session_timeout_ms`（默认30000，显式5001..86400000）、`min_idle_session`（0..64，禁用复用时必须0）。模板`examples/anytls-pool-outbound.json`。
- 编译出站每实例独立Arc池/SharedScheme，根/链中间跳/UoT共用同池；只在池空时调用原TCP/TLS/via工厂，不绕路、不先拨号再丢弃。公开低层已提供流的`outbound::connect`仍是独立单流API，不假称执行了运行时池。
- 每session独立读/writer/watchdog任务、逐ID读队列与状态；Settings与首SYN/目标PSH同批整形，复用不重置padding计数。frame/address/前导helper与旧适配共享，不复制密码算法。
- 后台持续处理cmd6、ServerSettings、HeartRequest/Response与Alert；合法方案影响同出站后续写/新握手，非法更新保旧，已stop不重启；不输出不受信错误/告警正文。
- 本地最多64缓存会话、每会话64活流、每流4块读队列、会话64项写队列，PSH≤65535。慢流按上游背压，不无限排队/静默丢业务。关闭释放Pending保留的发送额度；满队列无法安排FIN时关闭整个有歧义session，不将其重新复用。
- write接受完整有界批次即返回业务长度，writer实际发送/flush；每流计数只在实际flush完成后解除未确认批次，flush/Close用完成确认，peer FIN到达不能把未排空写或取消的屏障误报成功。取消不虚报不同buffer，FIN只一次。写开始后的错误/超时/建流取消结束会话，不自动重放业务。
- 合法HeartRequest与错误SYNACK对应的标准控制回复，在读任务拥有的有界队列中等待，受写期限和会话/实例取消约束；队列暂满不立即毒化其它ID。Drop无法异步排FIN的失败关闭边界与此区分。
- 链首DNS仅在实际拨号工厂执行，DNS配置/缓存/查询预算以共享快照克隆，不强持有Context。独立回归证明健康中间会话命中时零DNS查询，池空仍查询受控NXDOMAIN并失败，绝不绕过解析器。
- peer FIN后读完已排队PSH再稳定EOF；随后session传输关闭不能抹掉已完成ID的数据。非peerFIN错误不能伪装EOF；FIN关闭整流，非TCP半关闭。
- 池/任务间不自持Context，session只弱引用Pool；显式热替换退休旧池关闭idle、活流独立完成后关闭，不再租旧池。全实例出站stop跨热重载共享，children屏障等真正socket/任务析构，不等30秒空闲期限。

## 开发验证与真实失败

环境：macOS ARM64，Rust/Cargo1.95.0，`CARGO_INCREMENTAL=0`、锁定离线、默认线程栈。

1. 首轮全目标check通过，AnyTLS相关模块 **28 passed、0 failed、0 ignored**（其余659被过滤）、旧AnyTLS集成15项通过；新池集成为 **5 passed、1 failed**。失败为测试把端口规则写成数字，项目格式实际是`{start,end}`对象，配置加载报字段类型不正确；未执行后续TCP/UDP出站与热替换用例。日志`/tmp/rpk-anytls-pool-targeted.zSFZLB`。
2. 仅修测试拒绝规则，未放宽生产配置或移除负向场景；新池6、旧AnyTLS15、旧TCP出站19、UDP出站13、热重载2项全部通过，退出0。日志`/tmp/rpk-anytls-pool-targeted-fixed.VZthwQ`。
3. 补取消复用开流、写队列满时Drop、64流/ID耗尽、peerFIN缓存排空，完善不回送FIN/失败flush边界；相关模块 **32 passed、0 failed、0 ignored、659 filtered**，新池集成6、既有TCP19、UDP13均通过，退出0。日志`/tmp/rpk-anytls-pool-boundaries.ASRs8G`。
4. 收尾补生产4字节UoT预算与停机回收、满下行背压、同端点不同编译出站隔离；全目标check、32项相关模块、8项池集成、15项既有AnyTLS、19项TCP出站、13项UDP出站及2项热重载均通过，退出0。日志`/tmp/rpk-anytls-pool-resources.jaR0vJ`。
5. 独立只读审查提出三项具体问题，均用最小回归真实复现：peer FIN下shutdown误确认未排空写、控制队列暂满升级为全会话故障、中间池命中前解析DNS导致健康会话复用失败。模块 **0 passed、2 failed**，链集成 **0 passed、1 failed**，没有过滤或删场景；日志`/tmp/rpk-anytls-pool-review-repro.wtlTMT`。
6. 修复增加每流已接受/实际flush完成的批次计数，未确认写或屏障遇peer FIN返回错误；合法控制由有所有权的读任务在期限/取消约束内等待有限队列，Drop无法排FIN仍保留失败关闭；DNS配置/缓存/预算可克隆为同一快照，解析延迟到原始拨号工厂执行，不强持有Context或在池命中前查询。修复后全目标check退出0，原失败模块 **2 passed、0 failed**、链集成 **1 passed、0 failed**（其余分别691/8被过滤），均退出0；日志`/tmp/rpk-anytls-pool-review-fixed.GfgPHn`。此处为定向结果，不能代替完整回归。
7. 最终 `cargo fmt --all -- --check`、`cargo check --locked --offline --all-targets`、`cargo test --locked --offline` 全部退出0；**1335 passed、0 failed、43 ignored**，78个结果块。日志`/tmp/rpk-anytls-pool-validation.teQF8K`。较前批新增26项（17池模块、9池集成），三项审查复现均包含在全量内；显式去除全局`RUST_MIN_STACK`，使用默认线程栈。结果只覆盖本批收尾输入，不覆盖后续协议改动。

审查过程例外：代理误调用自动技能，停止前曾尝试只读Git状态/仓库探测并得到非仓库错误；没有初始化、分支、提交或仓库修改，后续禁止继续Git/代理扩展。本批不能表述为全程没有尝试任何Git命令。

测试包含独立duplex对端的一次前导/Settings、不同ID目标与迟到帧隔离、多ID控制/数据、错误SYNACK不毒化其他ID、Alert/截断会话失败、无业务读取仍更新/应心跳、短写/Pending/取消/FIN精确一次、队列/缓存/流上限、虚拟时间回收/保留/watchdog、ID耗尽、池退休活流、取消建流无残留，以及完整Config/runtime/TLS/链式/UoT/认证负向/热替换的真实拨号计数与端口回收。

回归结束后仅清理本项目 `target/debug/deps/*.rcgu.o`：1190个、逻辑6.32GiB；库、测试二进制、日志和私有资产保留，清理后本机可用约38GiB。

前批Naive 1309/0/43只覆盖其当时输入；本批使用上面独立全量记录，不混用历史结果。现有编译警告保留，不以退出0称零警告；不提高全局`RUST_MIN_STACK`、删负向或降容量掩盖失败。

## 验收与操作边界

官方AnyTLS/sing-box客户端、三平台、精确MSRV、release、长期容量/稳定性及正式安全审计未执行；本机双方回环和独立对端不能替代官方兼容。不Git/归档/发布，不修改系统代理/DNS/路由/防火墙，不操作Colima/容器/系统缓存；私有测试凭据/私钥与日志保留本机。
