## Purpose

为服务端代理内核增加面向正式 Naive 节点的原生 HTTP/2 与 HTTP/3 普通 CONNECT 出站，使已接受的 TCP 及显式启用的标准 UoT v2 UDP 可以在证书和 Basic 认证、首八块填充、严格失败关闭及有界资源生命周期约束下转发，不将 Rust 网络栈误称为 Chromium/Cronet 指纹等价。

## ADDED Requirements

### Requirement: 严格配置与正式CONNECT

系统 SHALL 提供默认H2、显式H3的Naive出站，必须使用TLS信任锚、合法Basic凭据；只发送目标authority的普通CONNECT，不携带MASQUE伪头，不接受不适用字段或静默降级。

#### Scenario: 正确与非法配置

- **WHEN** 配置H2/H3、额外头、错误版本、缺TLS、伪头/认证头覆盖或H3嵌入TCP链
- **THEN** 合法组合实际接线，非法组合在运行前明确拒绝，凭据不出现在Debug输出。

### Requirement: 标准填充与认证失败关闭

系统 MUST 按非空Padding请求/响应协商双向首8块PaddedData，第9块起裸字节；只接受200响应，保持TLS证书与ALPN验证。错误身份、CA、状态、头部或截断不得交付为业务或回落直连。

#### Scenario: 独立对端与负向场景

- **WHEN** 上游接受或拒绝认证、缺padding响应、发送拆包填充/业务或非法状态
- **THEN** 首八块及裸字节边界正确，无协商保持原字节，坏身份/证书/响应不触达业务目标或产生下行业务计量。

### Requirement: 正式可选UoT与原路径

系统 SHALL 仅在显式启用时通过正式UoT v2魔数CONNECT与标准地址/长度帧代理UDP，保留空报文与双栈目标、共享目标/队列/字节预算。Naive H2/H3服务端按固定上游识别该协议目标；未启用UDP、普通HTTP或H3不适用链式组合 MUST 失败关闭。

#### Scenario: TCP链式与UDP隔离

- **WHEN** H2位于SOCKS5链前后，或显式UoT代理多个UDP目标/空包/IPv6
- **THEN** 原链路径不被绕过，UDP使用正式帧且目标隔离、预算回收，默认UDP拒绝而不伪造原生QUIC数据报协议。

### Requirement: 取消安全与有界生命周期

系统 MUST 有界处理请求/响应头、流窗口、读写缓存与等待；短写/Pending/取消不重复已接受数据，flush/FIN实际推进发送且保留独立反向读取。所有派生任务与QUIC端点在取消、失败和停机时有明确所有权并真实回收。

#### Scenario: 慢头阻塞与半关闭

- **WHEN** 头部拆包、发送背压/取消、FIN后反向响应、连接建立取消或强制停机
- **THEN** 不虚报新buffer、不丢游标、FIN只发送一次，错误不伪装EOF，任务和端口在期限内释放；开发证据与外部验收明确分开。
