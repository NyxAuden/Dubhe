## Purpose

为服务端内核的 AnyTLS 出站补齐固定上游正式会话池和多流生命周期，以一次 TLS 身份前导和 Settings 承载独立递增流 ID，在 TCP 与 UoT 共用的出站实例中复用空闲会话、持续处理控制与填充更新，并保证关闭隔离、有限队列、超时与热替换/停机真实回收，不改客户端已知线协议或夸大并发调度兼容。

## ADDED Requirements

### Requirement: 正式会话与默认池

系统 SHALL 在AnyTLS运行时出站默认启用空闲会话复用，允许显式禁用和配置有界空闲检查/超时与最少保留数量；每TLS只发一次认证和Settings，每流使用不同递增ID、SYN与目标PSH，TCP/UoT同实例共池。

#### Scenario: 顺序并发与禁用

- **WHEN** 顺序/并发请求不同TCP或UDP目标，或显式disable_reuse
- **THEN** 顺序空闲会话可被真实复用，池空才沿原链拨号，并发不窃用忙逻辑流；不同ID控制/业务隔离，禁用时结束流即关会话，不发送私有wire字段。

### Requirement: 完整控制与关闭隔离

系统 MUST 持续处理PSH/SYNACK/FIN、ServerSettings、合法padding更新、HeartRequest与Alert；FIN关闭整流，peerFIN不回送，ID不复用，错误SYNACK仅终止对应流；认证/传输/结构/非空Alert错误终止会话且不把对端文本作为业务或日志。

#### Scenario: 迟到帧方案与失败

- **WHEN** 旧ID迟到PSH/FIN、新方案更新、心跳、错误SYNACK、截断或Alert
- **THEN** 不串目标，合法更新影响同出站后续写/新握手、非法更新保旧，心跳按标准应答，坏会话不回池、不重放业务；v2复用开流3秒内未收到完整帧头则关闭。

### Requirement: 有界收发与取消安全

系统 MUST 限制会话缓存最多64项、每会话64活流、每流4块读队列和64项写队列；被接受数据只写一次，flush/FIN确认实际排空，发送或建连取消不继续半帧、丢FIN后复用。正常slow流按上游背压，控制和业务不以无限缓存规避。

#### Scenario: 部分写读取及超载

- **WHEN** 短写/Pending/取消、慢读导致队列满或Drop无法排入关闭
- **THEN** 保存旧批次/帧游标或关闭有歧义会话，不认领新buffer，不影响已交付的其它合法流语义，不无界分配。

### Requirement: 原路径与生命周期证据

系统 SHALL 在根出站、TCP链的AnyTLS跳及UoT建流统一先取池后按原工厂拨号，热替换退休旧池但保留活流；最终停机 MUST 取消并等待所有会话/driver/定时回收与socket真实释放，不等完整空闲期。

#### Scenario: 超时热替换与停止

- **WHEN** 空闲超过配置期限、保留数生效、旧配置替换或停止实例
- **THEN** 只保留已有最少空闲不主动预拨，旧活流完成后不再回旧池，新池与身份隔离，任务/端口在期限内回收；本机开发结果与官方/平台/MSRV/release验收分开记录。
