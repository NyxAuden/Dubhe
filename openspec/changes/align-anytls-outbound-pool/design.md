## Context

见proposal.md。现有anytls_client提供单流适配及已验证frame/address/prologue/padding，不能仅让它固定id1反复重置来冒充池。服务端已有多流与UoT；根、链中间跳和UDP分别建流，必须统一使用编译出站的同一实例。Snell批已提供全实例出站取消token与热替换停池接口，可复用但不共用协议状态。

## Goals / Non-Goals

**Goals:** 正式ID分派、持续控制帧、固定上游空闲池策略、TCP/UoT共享、原链工厂和取消/热替换/停机资源证明。

**Non-Goals:** 非新并发调度算法、TCP半关闭或自动业务重放；不改服务端FIN语义，不新增依赖/vendor补丁/密码原语。低层已提供流的单会话API仍为独立连接，不伪报池复用，生产Context统一走新池。

## Decisions

- 增加可省略AnyTlsClientOptions：disable_reuse默认false、idle_session_check_interval_ms/idle_session_timeout_ms缺省30000；显式5001..86400000，min_idle_session默认0、0..64。上游<=5秒会回默认，本地显式非法值拒绝，不能默默忽略。
- 新池模块作为anytls_client子模块共享成熟前导/frame/address与padding算法。每session独立递增ID和PaddingState；每出站同一SharedScheme；Settings只一次，首Settings/SYN/目标PSH保持同批整形。
- Session拥有独立read与writer任务，stream map按ID持有限读队列与peer/error状态。writer单所有者顺序处理Open/Data/Flush/Close，完整有界批次接受即返回业务长度，flush/FIN通过oneshot确认；取消不虚报新buffer。任何半帧写失败关闭整个session，不继续使用nonce/边界。
- 读任务按完整头与payload解析，不在select重建栈上读游标；取消仅结束整个session。PSH每流4块缓冲、写队列64项，慢流背压沿固定上游阻塞session，不靠无限队列或静默丢业务。peerFIN关闭整流且不回送；SYNACK错误只关闭对应流，Alert/结构错误关闭会话。
- Pool按最新空闲优先（LIFO）选择。活流完成一次可将session回可用池，忙session不主动抢占；会话支持多个合法ID共存，不将这一能力解释为每个并发请求都必须同TLS。最大64缓存项，min_idle只保留现有空闲不预拨；超量关闭无活流项，活流session可draining至最后流结束。
- 根/链中间跳/UDP UoT通过共享Pool.connect和原承载factory建流；TCP身份与路由不变，UDP仍使用既有v2逐包目标framing。失败不自动重放业务，v2复用开流3秒watchdog按收到完整帧头解除，首流不启用。
- 任务持有session状态但不持Pool/Context，池条目与活流共享session；池退休设置draining、关闭idle，最后活流退出后关闭，避免引用环。全实例stop触发所有read/writer/cleanup退出，TaskTracker屏障等真实析构；Drop取消时已接受命令需么完成有界close，要么失败关闭session。
- 复用现有SharedScheme安全上限，cmd6后台即时更新作用于后续写及新握手，已stop计数不重启；ServerSettings记录v、HeartRequest回复9、Alert不输出对端正文。

## Risks / Trade-offs

- [旧流PSH/FIN到达新目标] → 不复用ID、u32耗尽后session关闭/退休，不把未知ID当当前业务，独立对端验证。
- [Drop异步FIN失去所有者] → 有界writer队列与确认、受tracker所有的回收，队列满时关闭session而非丢FIN后继续复用。
- [慢流无界队列或停机挂起] → 每流4项/会话64项、全实例取消、peer/local关闭解除发送等待、children屏障。
- [热替换误关旧活流或旧池继续用] → 显式退休旧池，活流独立状态继续完成，新调用不再租旧池。
