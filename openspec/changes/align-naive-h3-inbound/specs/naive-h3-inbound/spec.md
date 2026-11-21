## Purpose

在保持普通代理客户端可用和固定上游线格式的前提下，为Naive服务端补齐HTTP/3 CONNECT承载及协商padding，使认证、字节中继、路由拒绝与资源回收具有可复现的本机证据。

## ADDED Requirements

### Requirement: 正式H3承载
系统 SHALL 在显式启用H3后提供TLS1.3 QUIC H3普通CONNECT，不要求非Naive扩展协议头，不影响已有H1/H2。

#### Scenario: 同端口三承载
- **WHEN** 配置Naive H3入口
- **THEN** TCP H1/H2和UDP H3均可使用同一端口且正确认证转发。

### Requirement: Padding协议对齐
系统 MUST 仅在对端协商padding时帧化首8个双向数据块，之后裸字节；H1 payload按固定上游不启用padding，不发明格式。

#### Scenario: 边界与取消
- **WHEN** padding流发生拆包、短写、Pending或取消后flush
- **THEN** 每个被接受的业务字节只出现一次，帧边界不损坏，第9块正常裸传。

### Requirement: 认证路由与有界资源
系统 SHALL 在目标拨号前完成每请求Basic认证和路由判断，限制连接/握手/请求/缓冲，停止后回收子任务和监听端口。

#### Scenario: 错误身份或拒绝
- **WHEN** 凭据错误或目标命中reject
- **THEN** 返回非成功状态且目标零业务流量，不绕过策略。

#### Scenario: 停机
- **WHEN** 客户端保持空闲或阻塞写入时停机
- **THEN** 按有限超时取消并回收任务，UDP/TCP端口可复用。
