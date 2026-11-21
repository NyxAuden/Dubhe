# AnyTLS 正式 padding 方案对齐记录（2026-11-11）

变更：`align-anytls-padding-schemes`。本批为正式方案解析/客户端生成与更新/服务端自定义下发；出站连接池与多流仍独立待补，不把Waste帧正确解析当作全部AnyTLS客户端能力完成。

## 固定上游

`sing-anytls v0.0.0-20260902142641-43bb1cbea74e`，只读核查padding.go、settings.go、session.go、client.go、stream.go，不编译/运行上游。

| 文件 | SHA256 |
|---|---|
| padding.go | `c19cacecd2bb73593bfae33ea6af94e612181d55f14206000b1c0bb91a122d34` |
| session.go | `e52cc8976c0caa07279cad01906bf2d29b0c03bf15111f58d763e22f9ab36935` |

- 方案原始UTF-8文本按MD5声明，不排序/补换行；默认摘要`75cff2ad89aadf5e257059ee571ebe11`、握手填充30字节。
- settings逐行首个`=`切分，重复键最后一个覆盖；只规范u32十进制包号，未知键/无效区间忽略，反序区间交换。
- 区间上界不含；相同上下界为常量。`c`仅在待写数据耗尽时停止本批；packetCount从1开始，达到stop时当前会话永久关闭padding。负stop按上游i64→u32语义回绕。
- 客户端Settings/SYN/目标PSH为首批，初始不夹业务payload。服务端不打开同一套下行整形；命令6更新共享factory，非法更新保持旧值。
- Waste仍为正式7字节头`command0/id0/u16len`加零字节；按writePaddedLocked切分，业务存在和纯Waste分支的长度规则不同，不发明私有padding帧。

## 实施

- `anytls_padding`统一默认文本、解析、摘要与生成。随机区间用现有AWS-LC成熟随机源并拒绝采样；无新密码原语。
- 每出站独立`SharedScheme`，生产TCP与UoT共用Arc；cmd6完整帧到达并验证后更新快照，作用于后续写/新连接握手。当前单流按读取驱动更新，不宣称没有读操作时仍有后台实时消费。
- 默认客户端握手实际发送30字节零填充，Settings含client/padding-md5/v；首批合并后整形。pending按有界块列表与短写索引保存，write/flush/shutdown取消不重复接受新缓冲；FIN仍为AnyTLS整流关闭，不冒充TCP半关闭。
- 入站可选`padding_scheme`原始字符串，配置阶段验证；摘要不同时在ServerSettings前原样下发cmd6，一致不多发；省略保持默认方案。
- 服务端writer与桥接子任务加TaskTracker/取消所有者，强停不遗留detached writer/duplex/socket；既有认证/路由/统计仍复用。

### 公开资源上限

这些是本内核安全策略，不是把上游无限输入宣称为都兼容：

- 原文≤65535字节，与正式cmd6帧容量一致；握手首区间上界≤65535。
- 单区间大小≤256KiB；单包计划最多128项（含c），总有效计划项≤4096。
- 单包最坏生成填充（含Waste头）≤1MiB，业务输入≤一帧加有界首批头；不无界分配。
- 超界本地方案配置拒绝；超界/非法远端更新忽略并保留旧方案，日志不回显不受信正文。

## 验证与真实失败

本机macOS ARM64，Rust/Cargo 1.95.0，仅回环/内存验证。

1. 首次集中check发现锁定md-5 0.11输出Array不实现LowerHex，编译失败；改为逐字节小写十六进制编码。
2. 测试同时有digest 0.10/0.11两套trait，首次测试编译失败；显式引入md5::Digest修复，不升级依赖。
3. 修复后定向：AnyTLS入站14项、现有TCP出站19项、UDP出站13项、AnyTLS相关模块16项全部通过。覆盖默认/自定义MD5与原文、cmd6合法/非法/截断、握手更新、出站隔离、stop/c、短写/取消/flush/FIN及零容量读。
4. 补生产TCP+UoT共享factory与强停资源后，AnyTLS入站15项、相关模块17项全部通过（任务`byamztrxl.output`），退出0。生产两次TCP及UoT真实转发、远端更新在同出站共享且不串到另一出站、半帧强停回收writer/bridge均实测。首次集中全量在默认2MiB测试栈的既有REALITY UDP DNS/队列/强停用例栈溢出，进程SIGABRT，库测试块未正常结束，不能将途中ok行合计成完成结果。新增共享`connect_prepared`类型擦除边界，将多协议握手future仅在建连时堆分配，避免新AnyTLS路径逐层内联到所有入口；没有提高`RUST_MIN_STACK`。修复后原失败用例以默认线程栈定向重跑 **1 passed、0 failed**（任务`b2tk4vai0.output`），没有设置`RUST_MIN_STACK`；随后完整重跑已通过：

- `cargo fmt --all -- --check`：退出0。
- `CARGO_INCREMENTAL=0 cargo check --locked --offline --all-targets`：退出0；既有unused/dead-code等警告仍保留，不声称零警告。
- `CARGO_INCREMENTAL=0 cargo test --locked --offline`：**1257 passed、0 failed、43 ignored**，74个结果块，退出0；默认线程栈，原REALITY回归真实执行通过。日志：本机`/tmp/rpk-anytls-padding-validation-fixed.qBVkEj`。较前批1244新增13项（5方案、5客户端、3入站）。该结果对应AnyTLS收尾输入，不覆盖随后Snell obfs实施中的代码。
- 存储：原失败用例定向修复完成后清理1127个对象（逻辑5.81GiB）；最终全量结束后清理1111个`target/debug/deps/*.rcgu.o`（逻辑5.63GiB），可用约37GiB。保留源码/vendor/库与测试二进制/日志/私钥，不碰系统缓存与容器。

未新增依赖、修改vendor或密码原语；未执行Git/归档/发布、官方客户端/三平台/精确MSRV/release，也不修改系统代理/DNS/路由/防火墙。保留本地测试凭据/私钥，不发布。本机互测不等同官方兼容。
