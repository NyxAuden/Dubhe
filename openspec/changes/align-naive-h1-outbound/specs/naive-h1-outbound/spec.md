## Purpose

提供可显式选择的原生 Naive HTTP/1.1 出站，使已有服务端内核能够通过固定 forwardproxy 的裸隧道或固定 sing-box 的填充隧道连接上游；严格区分两种正式行为、可选 UoT、开发证据与官方互通验收，避免自动猜测 payload 导致业务损坏。

## ADDED Requirements

### Requirement: Explicit H1 profile

系统 SHALL 接受 `naive.http_version:"1.1"`，保持省略版本时默认 H2。系统 SHALL 提供默认 false 的 `h1_padding`，true 仅适用于 H1；其他版本配置 true MUST 被拒绝。H1 SHALL 复用必需的 Basic 身份、显式 CA 与严格额外头校验，不允许明文或任意传输组合。

#### Scenario: Version and profile validation

- **WHEN** 选择 H1 或省略版本，以及给 H2/H3 配置 h1_padding=true
- **THEN** H1 合法、省略版本仍为 H2，非法组合在配置阶段失败且调试输出不泄露密码或额外头值

### Requirement: H1 CONNECT and response boundaries

系统 SHALL 发送 HTTP/1.1 authority-form CONNECT、相同目标 Host、敏感 Basic 和非空 Padding 请求头，实际 flush 后才读取响应。系统 MUST 有界解析完整响应，仅最终 HTTP/1.1 200 成功；超限、截断、重复 Padding、协议错误、101 与非200最终状态 MUST 失败。系统 SHALL 保留同批首个隧道字节，不按成功 CONNECT 的 Content-Length 或 Transfer-Encoding 解释隧道。

#### Scenario: Early target bytes and invalid responses

- **WHEN** 对端把200头和业务同批写出，或发送不完整/超界/错误响应
- **THEN** 合法业务逐字节保留，非法响应不向调用者交付可用隧道、不重放请求

#### Scenario: Limited informational responses

- **WHEN** 对端先发送100、102或103，再发送最终200，或者反复发送临时头
- **THEN** 有限次数及累计8192字节预算内正确转入最终隧道，超过次数或累计预算失败关闭

### Requirement: Upstream-specific H1 payload

裸 H1 模式 SHALL 不加或剥除 PaddedData，即使200携带非空 Padding。显式 h1_padding=true SHALL 要求非空 Padding 响应并双向使用正式首八块 PaddedData，第九块开始为裸业务；系统 MUST 不自动探测或重试另一模式。

#### Scenario: Same response header with different profiles

- **WHEN** 两个独立正式对端均返回 Padding，分别以裸模式及显式填充模式建立连接
- **THEN** 裸模式业务不变，填充模式精确编解码首八块及第九块，缺少所需响应能力时显式填充模式失败

### Requirement: Runtime integration and optional UoT

系统 SHALL 在根出站及 TCP via 链中间跳按配置实际执行 H1，通告 http/1.1、接受无 ALPN并拒绝不匹配协商结果。H1 标准 UoT v2 SHALL 仅在显式 h1_padding=true 且 udp_over_tcp=true 时启用，沿用逐目标隔离、空包、队列与字节预算；裸 H1 启用 UoT MUST 在配置阶段拒绝。普通 forwardproxy MUST 不被声称具有 UoT能力；现有裸 H1 入站 MUST 不因本批而改变。

#### Scenario: Chains and UoT role

- **WHEN** H1 位于 TCP 链首/末，或显式填充H1经UoT处理多个目标和空报文
- **THEN** 所有连接按原路由/工厂执行，链不绕过上游，数据报边界/目标/额度保持；非法H3链及默认UDP拒绝不放宽

### Requirement: Cancellation and evidence

系统 SHALL 让握手取消/超时/拒绝销毁其承载，不产生脱离实例的任务；正常半关闭 SHALL 排空已接受写并保留反向数据，实例停机 SHALL 实际回收任务、端口及额度。系统 MUST 将独立对端/本机开发验证与官方客户端、三平台、精确MSRV/release验收区分记录。

#### Scenario: Slow headers and blocked payload shutdown

- **WHEN** 在半请求、慢响应、TLS握手或背压业务期间取消或停止实例
- **THEN** 已拥有承载真实释放、无隐式重试，已接受写不被误报到下一缓冲；本地开发结果只归属本批输入
