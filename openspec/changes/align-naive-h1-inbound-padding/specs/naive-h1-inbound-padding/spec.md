## Purpose

提供显式选择的 Naive HTTP/1.1 填充入站，使内核能够接受固定 sing-box 的正式首八块 PaddedData 与认证后的标准 UoT v2，同时保持已有 forwardproxy 裸 H1、普通 HTTP/Mixed 及 H2/H3 默认行为和证据边界不变，不自动猜测或自造协议扩展。

## ADDED Requirements

### Requirement: Explicit inbound H1 padding

Naive 入站 SHALL 提供默认 false 的 `h1_padding`。true SHALL 仅对 H1 启用正式首八块 PaddedData，第九块为裸字节；H2/H3 SHALL 保留现有能力协商。系统 MUST 不由相同的 Padding 请求头自动猜测裸/填充模式，不改变省略字段时的裸 H1。

#### Scenario: Defaults and protocol isolation

- **WHEN** 旧配置省略字段、显式开启字段，或在同端口使用H2/H3
- **THEN** 旧H1保持裸流，显式H1采用正式填充，H2/H3协商和共享预算不受模式字段改变

### Requirement: Authenticated CONNECT boundaries

显式填充 H1 SHALL 只接受合法 Basic 认证的 HTTP/1.1 CONNECT 和单一非空 Padding 请求头。系统 MUST 有界读取请求头并保留同批早业务；200响应头及正式Padding SHALL 在payload包装前实际flush，双向业务不得丢字节/重复。非法方法/头/认证 MUST 失败且不产生目标流量。

#### Scenario: Early padded payload and invalid requests

- **WHEN** 完整或半PaddedData与CONNECT头同批到达，或请求缺少/重复Padding、认证或使用非CONNECT
- **THEN** 合法早业务在200后精确读写，非法请求被拒绝且目标未连接、零业务计量

### Requirement: Standard H1 UoT role

显式填充 H1 SHALL 对认证后的精确 `sp.v2.udp-over-tcp.arpa:0` 进入正式UoT v2，200后读取初始请求，不DNS/拨号魔数。系统 SHALL 沿用真实UDP路由、多目标/空包/双栈、逐包地址或connect模式、关联/目标/队列/字节预算。默认裸H1、HTTP/Mixed和普通0端口 MUST 不因该能力被放宽。

#### Scenario: UDP targets and route rejection

- **WHEN** 合法填充H1使用正式UoT v2访问多个目标、空报文或被路由拒绝的目标
- **THEN** 数据报边界/目标正确、空包计额度，拒绝不直连；错误魔数/普通0端口及默认裸H1仍失败

### Requirement: Cancellation and resource evidence

系统 SHALL 复用连接/握手准入、超时、统计与实例取消，慢头不阻塞其它获准连接，半关闭排空反向数据。截断/取消/强停 SHALL 真实释放承载、UDP任务与预算，不留下独立所有者。系统 MUST 记录独立wire、本机生产回环与官方兼容验收的区别。

#### Scenario: Slow headers truncated frames and forced shutdown

- **WHEN** 请求头或payload截断、慢头取消，或者TCP/UDP背压期间停止实例
- **THEN** 未认证请求不建目标，成功连接不持握手permit，已接受写不丢或误确认；任务/端口/额度真实回收，结果只归属本批输入
