## Purpose

界定首批真正可运行的 SOCKS5 诊断入口和 Trojan/TLS 服务端的外部行为，以现有协议客户端能够完成认证和 TCP/UDP 转发为目标，同时公开未覆盖选项，不把有限组合宣称成完整上游兼容。

## ADDED Requirements

### Requirement: SOCKS5 认证与暴露边界

SOCKS5 入口 SHALL 支持 RFC 1928 的无认证方法及 RFC 1929 用户名密码方法。无认证仅能在回环地址使用，除非配置显式允许不安全的非回环监听；用户名密码在 SOCKS5 中不具备传输加密，文档 SHALL 明确警示。配置密码认证时不得协商降级为无认证。

#### Scenario: 客户端未提供允许的认证方法
- **WHEN** 入口只允许用户名密码，而客户端仅提供无认证方法
- **THEN** 服务端返回无可接受认证方法并关闭连接，不连接目标

#### Scenario: 意外开放无认证代理
- **WHEN** 无认证入口监听非回环地址且没有显式不安全授权配置
- **THEN** 配置检查与启动失败，不开放监听

### Requirement: SOCKS5 CONNECT 与 UDP ASSOCIATE

SOCKS5 入口 SHALL 支持 CONNECT 和 UDP ASSOCIATE 的 IPv4、IPv6、域名目标，返回协议规定的成功或失败应答。UDP 关联 SHALL 随控制 TCP 连接关闭或空闲超时而回收；服务端只能接受所属客户端端点的数据报。BIND SHALL 返回不支持命令，非零 FRAG 数据报 SHALL 丢弃，文档明确不支持 SOCKS5 UDP 分片。

#### Scenario: TCP CONNECT 成功
- **WHEN** 客户端通过认证并请求可达的本地测试目标
- **THEN** 服务端在连接目标成功后返回成功应答，并完整双向转发

#### Scenario: UDP 控制连接关闭
- **WHEN** 客户端已经建立 UDP 关联并关闭其控制 TCP 连接
- **THEN** 关联和目标映射被清理，后续发送到该关联的 UDP 数据不会继续转发

#### Scenario: 其他客户端试图复用 UDP 关联
- **WHEN** 不属于该关联客户端端点的数据报到达其 UDP 入口
- **THEN** 数据报被丢弃，不访问报文指定的目标

### Requirement: Trojan 基础 TLS 认证

Trojan 入口 SHALL 使用真实 TLS 承载请求，支持配置证书链、私钥和多个用户密码，按 Trojan 定义的 SHA-224 十六进制摘要验证凭据并识别 CONNECT 与 UDP ASSOCIATE。TLS 仅允许 1.2 及以上版本，认证比较不得按匹配前缀提前返回。请求头 SHALL 支持被拆分到多个读取块，首段载荷不得丢失。

#### Scenario: 合法客户端完成 TCP 转发
- **WHEN** 固定版本的外部 Trojan 客户端信任服务端测试证书并提交正确密码及 TCP 请求
- **THEN** 客户端与测试目标成功交换数据，不需要修改客户端协议实现

#### Scenario: 认证失败
- **WHEN** TLS 已建立但客户端提交错误摘要、无效分隔符或不支持的命令
- **THEN** 服务端不连接请求目标并关闭连接，不生成协议未定义的成功响应

### Requirement: Trojan UDP 数据报转发

Trojan UDP 关联 SHALL 通过 TLS 内的 UDP 帧传送数据，使用每帧目标地址、两字节大端载荷长度和 CRLF 分隔，保持帧边界及来源地址；长度不包含地址、长度字段或分隔符。遇到截断帧、无效地址、错误分隔符或超过配置上限的帧 SHALL 结束相应关联且释放资源。

#### Scenario: 一次读取包含多帧
- **WHEN** 外部客户端连续发送两个 UDP 帧且它们在同一次底层读取中到达
- **THEN** 产生两个独立 UDP 数据报而不是拼接后的一个报文，并正确返回各自响应

#### Scenario: 帧分段到达
- **WHEN** 地址、长度字段和载荷分多次读取才完整到达
- **THEN** 服务端等待完整帧后只转发一次，且受握手或关联空闲期限约束

### Requirement: 公开首批兼容限制

首批支持声明 SHALL 限定为 SOCKS5 CONNECT/UDP ASSOCIATE 与 Trojan over TCP+TLS 的有效认证转发组合。Trojan 非协议流量 fallback、WebSocket/gRPC 包装、复用扩展及其他协议 SHALL 标为未实现；配置要求这些能力时必须失败，而不是忽略。Trojan 无效请求直接关闭与上游 fallback 行为不同，MUST 在兼容说明中单独列出。

#### Scenario: 配置请求 Trojan fallback
- **WHEN** 用户配置首版尚不支持的 fallback 选项
- **THEN** 检查失败并说明未实现，文档不得声称完整替换所有 Trojan 服务端部署
