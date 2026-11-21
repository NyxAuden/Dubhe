## Context

见proposal.md。已核固定sing-quic tuic/client.go的DialEarly、exporter Authenticate和cubic/new_reno/bbr选项，以及Quinn into_0rtt/ZeroRttAccepted API。标准exporter在完整握手后派生，不能用early exporter替换。现客户端每次新建endpoint，TCP仅复用活连接，UDP关联独立连接，导致票据无法提供实用重连路径。

## Goals / Non-Goals

**Goals:** 真实CC工厂、显式默认关闭0-RTT、可验证早期Connect元数据、拒绝后唯一重建、认证失败关闭和有界生命周期。

**Non-Goals:** 不提前发送非幂等业务载荷，不声称与quic-go各版本BBR实现完全等价，不修改vendor/依赖，不执行外部验收。

## Decisions

- 配置在既有tuic对象添加congestion_control与zero_rtt_handshake，CC解析复用既有modern模块；TLS配置按开关设置enable_early_data。CC写入每个真实TransportConfig，不用字符串记录冒充。
- 每出站按IPv4/IPv6最多缓存两个QUIC endpoint，复用同一TLS票据存储；连接仍按TCP共享/UDP关联隔离。活流共享endpoint所有权，配置热替换丢弃旧出站不会误关旧业务；最后所有者析构关闭endpoint，没有新常驻应用任务。
- 连接建立函数接受可选TCP Connect头：有票据且into_0rtt成功时先发Connect元数据，等待ZeroRttAccepted后用标准exporter发送Authenticate；仅明确accepted=false时重建元数据流。业务流只有该函数完成后交给调用方，故不自动重放业务。
- UDP业务不进入早期数据：可在early连接发送无副作用的正式Heartbeat，随后等待握手、写Authenticate，再建立native/quic业务收发器。锁定Quinn的待发送DATAGRAM队列在拒绝后有保留歧义，不发送首业务包后盲目重传。
- 连接/认证用调用方future与统一dial_timeout拥有，早期Connection用Drop guard失败/取消即close，不增加后台共享认证任务或自持Arc环；不把握手完成误当服务端已确认身份（TUIC无成功响应）。

## Risks / Trade-offs

- [0-RTT重放] → 默认false，只提前Connect元数据/Heartbeat，服务端仍需Authenticate；不向用户承诺天然防重放或0-RTT业务收益。
- [对端拒绝早期流] → 仅在明确accepted=false时丢弃旧流、重开一次；不重试证书错误、关闭、未知故障或业务。
- [endpoint生命周期] → 缓存按地址族有界、无应用后台任务，最后出站/活流所有者析构后关闭连接与endpoint；测试热替换旧流存活及端口回收。
- [TCP/UDP策略不一致] → 两类连接均从同一prepared策略创建，测试CC、无票据/有票据/拒绝、错误凭据/证书与UDP两载波。
