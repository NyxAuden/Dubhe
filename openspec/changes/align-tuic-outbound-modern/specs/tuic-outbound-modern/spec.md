## Purpose

为现有TUIC v5原生出站补齐明确的现代QUIC策略，使服务端链式出口能够选择真实拥塞控制与可选0-RTT握手，同时保留标准UUID/exporter认证、TCP/UDP载波语义、拒绝恢复及有界资源，不因配置可解析就宣称早期数据已生效。

## ADDED Requirements

### Requirement: 显式策略配置
系统 SHALL 允许TUIC出站选择cubic/new_reno/bbr及zero_rtt_handshake，缺省保持cubic与禁用0-RTT；无效选项 MUST 在启动前拒绝，不静默改用其他策略。

#### Scenario: 配置与实际生效
- **WHEN** 配置合法或非法TUIC现代参数
- **THEN** 合法策略作用于TCP与UDP的真实连接，非法参数失败关闭，旧配置保持有效。

### Requirement: 正规早期握手与认证
系统 SHALL 复用会话票据尝试真实0-RTT，无票据时执行完整握手；仅允许提前发送正式Connect元数据或Heartbeat，业务载荷须待握手及标准exporter Authenticate写入后发送，不伪造认证数据。

#### Scenario: 首连与恢复
- **WHEN** 显式启用0-RTT且分别无票据、有可用票据
- **THEN** 首连正常成功，恢复连接真实尝试early路径且认证线格式仍为v5 UUID+TLS exporter。

### Requirement: 拒绝与生命周期
系统 MUST 在明确0-RTT拒绝时只重建被拒绝的TCP元数据流，不自动重放业务；证书、身份、超时、取消和未知故障失败关闭，不回落direct，资源可有界回收。

#### Scenario: 对端拒绝0-RTT
- **WHEN** 对端拒绝已尝试的早期数据但完整握手成功
- **THEN** 标准认证及唯一TCP请求可继续，不产生重复目标业务或损坏旧流。

#### Scenario: 负向与停机
- **WHEN** 身份/证书错误、调用取消或内核停机
- **THEN** 目标不收到未授权业务，应用子任务与socket有界回收，保留0-RTT重放风险说明。
