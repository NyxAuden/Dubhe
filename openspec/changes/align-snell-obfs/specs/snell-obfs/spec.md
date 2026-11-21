## Purpose

为Snell固定上游存在的v4/v5 TCP记录承载补齐HTTP与TLS obfs双角色，使已有标准客户端和上游节点能在不改变内层身份/AEAD/目标语义的情况下转发TCP及UDP-over-stream，并对版本组合、头部长度、短写/取消、截断和资源回收提供可验证行为，不将外观封装称为真实TLS或WebSocket。

## ADDED Requirements

### Requirement: 显式正式组合
系统 SHALL 允许Snell v4/v5配置none/http/tls obfs，并仅在适用出站配置host/HTTP URI；v6与不适用字段组合 MUST 启动前拒绝，不静默忽略。

#### Scenario: 合法与错误组合
- **WHEN** 用户配置正式组合或v6+obfs、none+host、tls+URI及头注入
- **THEN** 正式组合实际接线，非法配置明确失败，不绕过内层身份与加密。

### Requirement: HTTP与TLS标准外观承载
系统 MUST 按固定上游首消息布局与后续记录规则编码/解码，不插入真实WebSocket帧、不依赖私有扩展，双向原始Snell字节完整保留。

#### Scenario: 双向与两种业务
- **WHEN** 使用HTTP或TLS obfs代理TCP或UDP-over-stream
- **THEN** 首头/首payload及后续数据往返正确，HTTP只处理首头，TLS按正式记录边界，空UDP仍保留。

### Requirement: 取消安全与失败关闭
系统 MUST 在短写/Pending/取消后保存首头与记录状态，被接受字节只出现一次；首头/记录/等待有界，畸形/截断/错误身份/路由拒绝不回落direct。

#### Scenario: 边界与停机
- **WHEN** 首头拆包、短写、取消、空读、超长/截断或停机
- **THEN** 不重复首消息、不丢业务、不无界分配，错误有界关闭且socket/任务回收。
