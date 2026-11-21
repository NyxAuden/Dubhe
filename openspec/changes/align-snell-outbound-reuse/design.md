## Context

见 proposal.md。现有 ClientStream 已拥有 Reader/Writer 与进行中的读写 future，正式零块可区分逻辑 EOF 和传输截断；服务端已顺序处理 CONNECT_V2。当前 Context 在建连前统一拨号，必须把取池放在拨号之前；链的中间跳也要沿相同工厂取池，不能丢掉已建立新流而谎称避免拨号。

## Goals / Non-Goals

**Goals:** v4/v5/v6、所有既有记录模式及适用 obfs、跨目标顺序复用、并发隔离、有界等待/空闲与全实例停机。

**Non-Goals:** 不提供并发多路复用、UDP 连接池、QUIC、自造认证确认或业务重放；不新增依赖、vendor 补丁或系统操作。低层 public outbound::connect 已提供承载而没有运行时任务所有权，显式 reuse 要求通过 Context 连接工厂，不静默忽略。

## Decisions

- 增加 `SnellClientOptions.reuse` 默认 false；每编译出站独立 Arc<Pool>，PartialEq 按实例身份，Debug 不显示凭据。UDP 按固定上游独立建连，不消费池。
- Pool 独占存储可复用 ClientStream，租借活流只持 Weak<Pool>，避免池→流→池引用环。旧出站销毁关闭空闲/等待项，但活流继续运行，最终关闭不再回旧池。
- 保留流 Reader/Writer 及底层 obfs；复用只重置逻辑首应答/缓存/FIN 状态、写正式下一 CONNECT_V2，记录 salt/nonce/profile 不重置。首应答仍可延迟；业务不在失败时自动重放。
- Drop 移交已验证首应答的会话给 TaskTracker 所有的排空任务，先完成已接受写并且只发送一次零块，再读至对端正式零块；丢弃旧下行达到 0x80001 或总排空 30 秒失败就关闭。未读首应答、写/读错误、半建连取消不回池。全双向正常结束可直接完成同一验证流程。
- 一个 10 permit 上限覆盖等待排空+ready 条目，超限直接关闭；ready FIFO、180 秒空闲过期，单个弱所有权清理器每 20 秒清理（与固定上游周期一致），取池时也剔除已过期项。不会每次租借留下一个 180 秒睡眠任务。
- Context 增加全实例出站资源取消 token，热重载与旧 Context 共享；最终 stop/force 后、children.close/wait 前取消。池本地 token 在 Pool Drop 取消；清理与排空任务都监听两者，不自持 Context/Pool。取消检查覆盖建连交付和回池竞态。
- 根 Context 与链式 tunnel factory 在池外保留原承载工厂，仅池空时才拨号；所有上游路径仍由原 via 建立。类型擦除保留在建连/回收边界，避免增大默认栈。

## Risks / Trade-offs

- [旧数据进入新目标] → 收到正式零块才入 ready，排空不交付业务，独立对端证明跨目标隔离。
- [关闭或取消留下 nonce/半记录歧义] → 不重建已拥有 future，排空完成后才复用，失败直接销毁，禁止自动业务重放。
- [池任务导致停机或热替换挂起] → Weak 所有权、池 token 与全实例 token，所有后台任务由现有 children 屏障等真实析构。
- [远端已关闭的空闲连接] → 下次写/首应答真实失败，不自动重放；错误流绝不回池。复用不能等同远端已认证确认。
- [上游无限排空/缓存资源] → 10 项、180 秒+20 秒周期、30 秒和 0x80001 字节明确本地边界，不把安全上限说成上游无限输入兼容。
