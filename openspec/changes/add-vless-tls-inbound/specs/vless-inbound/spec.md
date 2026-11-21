## Purpose

为现有客户端增加独立的 VLESS v0 over TCP+TLS 服务端接入，明确基础请求与数据报语义、身份和资源边界，并将真实外部互通与内部实现测试分别记录，避免把基础支持扩大为所有扩展支持。

## ADDED Requirements

### Requirement: 严格配置和 TLS 身份

入口 SHALL 使用标准 TLS 1.2/1.3，配置证书链、匹配私钥及非空用户列表。用户使用标准 36 字符 UUID（大小写等价）和唯一名称，重复 UUID MUST 拒绝；日志及 Debug 不得泄露 UUID。未知字段与未实现 flow/security/transport/mux 配置 SHALL 拒绝。原 SOCKS5/Trojan 配置保持兼容。

#### Scenario: 非法身份或扩展配置
- **WHEN** 配置包含非法或重复 UUID，或要求尚未实现的 Vision/REALITY
- **THEN** check/run 失败且不输出凭据原值，不开启监听

### Requirement: VLESS 基础请求与 TCP 响应

入口 SHALL 接受版本 0、16 字节 UUID、空 addons、TCP 命令 1 或 UDP 命令 2，目标端口大端在地址之前，地址类型 1/2/3 分别为 IPv4/域名/IPv6。显式开启 xudp 时另接受没有目标字段的命令3，仅用于下述 UDP 会话。认证失败、非零版本、非空 addons、不支持的命令、非法或截断地址 SHALL 终止请求且不连接目标。TCP SHALL 保留首段数据及半关闭，在成功拨号后发送一次响应头 `00 00`，响应头不计入业务字节。

#### Scenario: 合并或拆分请求
- **WHEN** 合法请求头和载荷合并或逐字节到达
- **THEN** 目标仅收到完整业务载荷，客户端收到一次响应头及完整回显

#### Scenario: 失败请求
- **WHEN** UUID 错误或请求含不支持命令、addons 或截断字段
- **THEN** 不拨号、不发送成功响应，连接在握手期限内终止

### Requirement: 原生固定目标 UDP

UDP SHALL 对一个请求中的固定目标传送数据报，帧为两字节大端载荷长度加载荷，没有逐帧地址。实现 SHALL 检查配置载荷上限后分配内存，完整读取帧后才转发；超长或截断帧终止关联。零长度帧 SHALL 被消费并丢弃计数，与上游基础路径不转发空数据报的限制一致；文档必须公开。每个关联只接受所连目标的回包，复用全局关联/排队字节预算，关闭、空闲及强制停机释放资源。

#### Scenario: 多帧与固定目标
- **WHEN** 同一关联的多个非空帧被拆分或合并传送
- **THEN** 每帧只发送一次到请求目标，回程逐帧保留边界，计量不含帧头

#### Scenario: 帧异常及停机
- **WHEN** 收到超长或截断帧、关联空闲或服务停止
- **THEN** 关联退出，名额和套接字可回收，不遗留半帧读取任务

### Requirement: 可选 XUDP 会话

VLESS 入口 SHALL 提供默认 false 的 xudp 开关。开启后命令3 SHALL 仅接受 UDP New/Keep/End/KeepAlive 帧；元数据为大端长度、会话编号、状态、选项及可选端口优先目标，元数据长度 SHALL 在4至512之间。New 必须带 UDP 目标，Keep 可覆盖本帧目标，无目标时沿用会话初始目标。回程 SHALL 使用相同会话编号的 Keep 并携带实际来源。TCP 网络、未知状态/选项、不合规尾部、未知 Keep 会话及重复 New SHALL 拒绝并关闭承载。End 对已关闭编号 SHALL 幂等。

每会话 SHALL 占用全局 UDP 名额并逐报文检查路由；载荷和队列 SHALL 有界。End、会话空闲、EOF、截断和停机 SHALL 释放套接字及任务。KeepAlive 可延长承载空闲，不能延长会话或创建会话。New+Data 可包含恰好8字节 GlobalID，仅消费而不跨连接共享状态；相同 GlobalID 或编号不得跨用户/连接合并。编号重用 SHALL 防止旧排队回包进入新会话。空载荷消费后丢弃计数。

#### Scenario: 多会话和逐帧目标
- **WHEN** 同一承载创建多个 UDP 会话，Keep 在多个目标之间切换
- **THEN** 回包保留各自编号、实际来源和载荷边界，路由逐包生效

#### Scenario: 隔离与资源回收
- **WHEN** End 后复用编号，或两个身份提供相同 GlobalID，或会话空闲及服务停止
- **THEN** 旧回包不能进入新会话或其他身份，空闲和关闭资源可回收

### Requirement: 支持状态与独立验证

支持声明 SHALL 限定于本规格基础组合及显式开启的 XUDP，非空 addons、TCP Mux、跨承载续接、Rvs、Vision、REALITY、VLESS Encryption 和传输包装仍明确未实现。独立 wire 测试 SHALL 覆盖正常/错误请求、半关闭、UDP 和资源边界；三家固定官方客户端另有显式测试。只有实际执行的结果能升级外部兼容状态，无法运行时保持待互通；既有 Trojan 结果不得用于证明 VLESS。

#### Scenario: 只有内部测试通过
- **WHEN** VLESS 内部测试成功但官方客户端未实际运行
- **THEN** 状态记录为已实现、待外部互通，不能标为已验证
