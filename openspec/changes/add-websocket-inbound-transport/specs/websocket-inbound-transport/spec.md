## Purpose

为现有代理客户端提供单一原生服务端内核中的 HTTP/1.1 WebSocket 与标准 TLS/WSS 接入，明确传输握手、早期数据、字节流与关闭语义、协议认证及有限资源边界，并将开发实现和真实官方客户端兼容证据分别验收。

## ADDED Requirements

### Requirement: 独立配置与显式安全组合

内核 SHALL 增加独立的 `vless-ws`、`vmess-ws`、`trojan-ws` 入站，接受各自原协议用户和已支持的业务选项，以及严格的 WebSocket 配置和成对可选 TLS 证书/私钥。未知字段、显式 null、缺半组 TLS、重复身份、畸形路径/Host、超出边界的限额或不支持的组合 MUST 在 check/run 联合准备时失败，且 check 不监听、不解析业务域名或拨号。VLESS/Trojan 的非 TLS WebSocket SHALL 仅在显式准许不安全传输时启用；VMess 的无正文加密 SHALL 仅依据实际协商完成的 TLS 或既有显式弱化策略允许，不因 HTTP Upgrade、Host 或转发头宣称加密。旧入口及其默认值 SHALL 保持兼容。

#### Scenario: 检查安全策略和旧配置
- **WHEN** 检查合法新入口、无 TLS 且未准许的 VLESS/Trojan、半组 TLS 或原有配置
- **THEN** 合法新配置和原有配置保持各自语义且不占端口；不安全或畸形新组合在监听前拒绝，不输出身份或私钥

#### Scenario: 非法层叠与空选项
- **WHEN** 新入口要求 Vision、REALITY、TCP mux、未知 early-data 模式、null 或不合规限额
- **THEN** 配置明确失败而非退回普通 flow、忽略选项或任意叠加承载

### Requirement: 有限 HTTP Upgrade 与路径准入

服务端 SHALL 接受符合所支持 HTTP/1.1 WebSocket 握手的 GET、版本13、合法随机键和 Upgrade/Connection token，并仅在配置路径及可选 Host 规则匹配时返回正确101。字段名和 token 的协议大小写规则 SHALL 按 HTTP/WebSocket 处理；关键单值字段的重复、歧义 Content-Length/Transfer-Encoding、携带 HTTP body、obs-fold、畸形 request-target、非法换行或超限头 MUST 拒绝。读取 SHALL 在头完成或声明超界时有限终止，不等待不可信超长头/body 完整到达。101只是承载建立，不是代理用户认证或业务目标连接成功。失败不得访问业务 DNS/目标、提供任意网页或转发客户端指定 HTTP 地址。

#### Scenario: 分片 Upgrade 与尾部帧
- **WHEN** 合法请求头逐字节到达，或头结束符后合并首个 WebSocket 帧
- **THEN** 正确完成101，头后字节仍恰一次送入帧处理，协议请求首载荷不丢失或重复

#### Scenario: HTTP 错误和超限慢客户端
- **WHEN** 路径/Host 错误、键/版本/关键字段异常，或请求头达到上限仍未完成、缓慢停滞
- **THEN** 返回有限无敏感内容的失败响应或关闭，受共享握手绝对期限约束；无业务 DNS/拨号及成功计量，许可最终归还

### Requirement: 显式有界 early-data 与字节所有权

服务端 SHALL 默认关闭 early-data，仅接受显式配置且固定上游实际定义的携带方式；开启后 SHALL 限制编码前后长度、校验对应 base64url 方言和重复/歧义字段，并在101后将解码结果作为协议前缀恰一次交付。路径中的客户端 early-data 阈值提示与真正携带字节 SHALL 区分，不能将任意 query 或转发头当成身份/载荷。不允许同时从多个位置拼出不明确的前缀。early-data SHALL 不绕过完整代理认证、时间/重放、命令/目标和路由策略，日志不得记录含早期数据的完整路径或头值。

#### Scenario: 前缀和首帧共同构成协议请求
- **WHEN** early-data 含完整或部分代理请求，剩余字节在首个或多个二进制帧内到达
- **THEN** 协议层按原顺序只消费一次，失败认证无目标访问；正确身份得到协议自己的响应，而非额外插入 VLESS 头或重复认证前缀

#### Scenario: 关闭或畸形 early-data
- **WHEN** 模式关闭仍发送携带头、字段重复、编码错误、长度超界或携带位置不符合显式配置
- **THEN** 握手有限拒绝，不静默丢掉数据后继续认证，不把编码秘密输出到日志

### Requirement: 二进制字节流与严格帧边界

承载 SHALL 按 WebSocket 规范处理客户端 masked 帧、无 mask 的服务端帧、二进制消息及 continuation、控制帧穿插和网络分片；消息/帧边界 SHALL 不改变上层代理字节流或 UDP 编码。文本消息、未协商 RSV/扩展、无效 opcode、错误 mask、非法 continuation、非最短长度编码、64位长度高位异常、控制帧分片/超长及配置帧/消息超限 MUST 有限拒绝。空二进制消息不代表协议 EOF。已声明超限的头 SHALL 在分配/等待全部载荷之前拒绝；允许的消息和输出缓冲均有明确上限，不承诺无限大单消息。

#### Scenario: 任意拆并及控制帧插入
- **WHEN** 一个代理头被拆成多个二进制消息/continuation，多个代理帧又合在同一消息且中间穿插 Ping/Pong
- **THEN** 上层只得到原始有序二进制字节，控制内容不进入目标或业务计量，UDP 边界由所属协议恢复

#### Scenario: 大长度声明及协议违规
- **WHEN** peer 只发送超限长度头、未 masked 数据、非法 RSV/opcode、text 或未闭合分片
- **THEN** 不按声明巨额分配，有限错误/关闭，部分不完整消息不伪造完整业务数据，已占缓冲及许可可回收

### Requirement: 背压与控制处理可前进

上下行 SHALL 具备有限缓冲和准确的 partial-write/Pending 游标；只有业务接口实际接受的字节能被业务计量。单方向网络背压 SHALL 不无故阻塞另一方向已可处理的数据或控制读取；Ping SHALL 触发相同载荷 Pong，控制输出可合并为有限待发状态而不按帧无限排队/生成任务。帧化、mask、HTTP/TLS、early-data 头及控制流量 MUST 不算业务字节；背压或取消 SHALL 不重复写出已接受业务。

#### Scenario: 下行背压仍有上行进展
- **WHEN** 客户端暂停读取造成下行阻塞，同时继续发送合法上行业务及 Ping
- **THEN** 在明确有限预算内上行仍可转发并处理控制输入，待发控制输出有界，恢复读后 payload 不重复、不丢失，计量不包含控制帧

#### Scenario: 精确 Pending 与短写
- **WHEN** 底层 write/flush 交替 Pending、短写或失败
- **THEN** 重试从正确游标继续，返回值和业务计量一致，不将未接受数据当成成功，也不保留无法回收的后台写任务

### Requirement: 关闭与截断的真实语义

承载 SHALL 完成规范的有限 Close/Pong 处理，发起关闭后拒绝新业务写，交付关闭前已完整接受的有序数据。无 Close 的底层 EOF、半帧、WSS 的真实 TLS 截断及协议错误 MUST 不伪装成正常 WebSocket Close。WebSocket Close 关闭整个会话，SHALL 不声明它提供 TCP 独立单向 FIN；上层已有结束标记保持其协议语义，但不得添加私有 EOF 消息冒充普通客户端支持。关闭遇到慢对端 SHALL 在有限期限内归还连接、关联及子任务。

#### Scenario: 正常 Close 和关闭后写
- **WHEN** 对端正常 Close 或本地首次请求 shutdown 尚在 Pending 时又出现业务写
- **THEN** 有限处理关闭握手，拒绝新写且不增加计量，关闭前完整数据不被重复或直接丢弃，最终退出而非永久等候

#### Scenario: TCP 半关闭需求与真实截断
- **WHEN** 目标只在客户端单向 FIN 后返回，或底层在半帧/缺 close_notify 时中断
- **THEN** 文档与测试明确前者不具备通用透明半关闭保证；后者返回真实错误而不是成功 EOF，不据此声称所有 TCP 应用可无差异迁移到 WS

### Requirement: VLESS 无 flow 的既有 TCP 和 UDP 语义

`vless-ws` SHALL 在承载建立后复用标准 UUID 认证、无 flow 的 TCP/原生固定目标 UDP及显式开启的 UDP-only XUDP，保留一次 VLESS 响应、首载荷、实际来源、逐包目标/路由、代次与 GlobalID 隔离。配置或 wire flow 不得降级为空 flow；认证失败、非法命令/扩展或 Reject SHALL 先于业务 DNS、拨号和协议成功响应。WebSocket 建立不产生额外业务目标访问。

#### Scenario: VLESS 三种业务路径
- **WHEN** 独立客户端在 WS/WSS 上分别请求 TCP、原生 UDP 和显式 XUDP
- **THEN** 首载荷和数据报内容正确，多个目标/会话不串流，只产生一次所属 VLESS 响应，IPv4/IPv6 及空包策略保持原协议边界

#### Scenario: 身份和 flow 负向
- **WHEN** Upgrade 成功后使用错误 UUID、非空 flow、关闭的 XUDP 或被拒绝的目标
- **THEN** 不访问业务 DNS/目标，不生成成功 VLESS 响应，不因101成功就绕过认证

### Requirement: VMess AEAD 的既有安全和 UDP 语义

`vmess-ws` SHALL 复用当前 AEAD AuthID、时间/重放、有限头、security/options 及双向正文状态机，支持原有 TCP、原生 UDP与显式 UDP-only XUDP/packetaddr。security5 的安全判断 SHALL 使用真实完成 TLS 的事实，实验性认证长度保持原默认关闭和公开局限；WebSocket 只消除自身帧边界，不能重置或推进多次正文计数/掩码序列。非法标签、头、扩展、认证或目标拒绝仍不得泄露未认证正文。

#### Scenario: AEAD 头正文跨消息
- **WHEN** 当前合法安全组合的 AEAD 头/正文跨 WebSocket 消息到达，原生 UDP/XUDP/packetaddr 与多个目标交换数据
- **THEN** 请求/响应、nonce/长度序列和包边界保持原语义，不发送 VLESS 响应，封装不进入业务计量

#### Scenario: 伪造加密和重复请求
- **WHEN** 明文 WS 客户端伪造转发头以请求默认不允许的 security5，或更换 WS 连接重放相同认证/正文材料
- **THEN** 不把转发头当作 TLS，安全策略和同 Server 重放预算照常生效，受控业务目标无不应有的访问

### Requirement: Trojan 的既有认证和 UDP 语义

`trojan-ws` SHALL 在 WS/WSS 字节流上复用既有多用户摘要认证、CONNECT/UDP ASSOCIATE、地址/CRLF、逐帧目标/来源与有界资源，不因 Upgrade 或 early-data 免除认证。非 TLS 模式的显式弱化 SHALL 公开其摘要和业务不具备传输保密性；错误凭据、分隔符、命令或超长/截断 UDP 帧 MUST 关闭而不进入 fallback。

#### Scenario: TCP 与逐包目标 UDP
- **WHEN** 合法 Trojan 头/首载荷/多个 UDP 帧被 WS 消息任意拆并
- **THEN** 目标只收到原始业务载荷，UDP 回包保留实际来源和边界，空包/大小策略及计量与原协议一致

#### Scenario: 认证失败不转为网页或回落
- **WHEN** Upgrade 后提交错误摘要或不合法 Trojan 请求
- **THEN** 不拨业务目标、不提供通用 fallback、不泄露摘要，也不把101当作代理认证成功

### Requirement: 共享预算与真实结束屏障

新承载 SHALL 与旧入口共享全局连接、每入口握手、DNS、UDP关联/目标/排队字节预算；TLS、Upgrade、early-data及代理认证 SHALL 使用单一绝对握手期限而不是每层重新获得全额时间。每连接的头、消息、输出、early-data、控制和任务数量 SHALL 有独立有限上界，不能用 UDP payload 预算冒充所有 transport 内存已覆盖。正常关闭、错误、半握手和停机 SHALL 经过 stop→drain→force→join及子任务真实结束屏障，联合准备失败归还所有未运行监听。

#### Scenario: 新旧入口竞争及取消
- **WHEN** 三种 WS/WSS 与旧 SOCKS5/VLESS/VMess/Trojan 竞争预算，存在慢 HTTP/半帧/阻塞 DNS/活跃 UDP 时取消
- **THEN** 不超共享限额、不无限生成任务或缓冲；force 后全部相关任务实际结束，许可、监听及目标映射端口可恢复

#### Scenario: 期限不逐层刷新
- **WHEN** peer 在 TLS、HTTP头和代理头阶段分别消耗部分握手时间
- **THEN** 各阶段合计仍受同一绝对截止时刻限制，不能通过跨层缓慢输入无限占握手槽

### Requirement: 独立开发证据与集中验收边界

开发 SHALL 包含独立原始 HTTP/帧夹具及非生产客户端、WS/WSS真实业务、各协议认证/数据/资源负向、格式/locked all-targets编译/严格Clippy和受影响旧路径回归，记录精确输入、命令、失败及未运行项。必要开发门禁完成后 SHALL 标为已实现待集中验收并允许下一独立模块；官方客户端组合、新平台全量、精确MSRV、release及最终报告仍保持未完成直到获准且实际执行。成熟依赖来源、许可、features、MSRV和公告须有可追溯门禁，不把静态可用、ignored、自有互测、旧输入或其他协议结果冒充新兼容证明。

#### Scenario: 开发完成而官方尚未运行
- **WHEN** 本批必要开发验证完成但官方 WS/WSS 矩阵未获准或未执行
- **THEN** 仅勾开发任务，不扩大旧官方授权或结果，矩阵按协议/承载/early-data/客户端真实支持逐项保留待验收

#### Scenario: 示例与秘密输出
- **WHEN** 替换回环示例占位值后真实check/启动/业务，或检查错误日志、Debug和失败响应
- **THEN** 示例按明确组合工作，不泄露 UUID、摘要、early-data、私钥或业务载荷，不公开整个测试工件目录，不给出公网外观调优或生产部署保证
