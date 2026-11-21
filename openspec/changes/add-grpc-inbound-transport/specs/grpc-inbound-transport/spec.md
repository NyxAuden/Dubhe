## Purpose

为现有代理客户端在单一原生服务端内核中提供明确的gRPC双向流接入，区分HTTP2连接、RPC、代理认证及业务流，保证消息和独立关闭方向正确、资源有限、跨流隔离与真实结束，并将开发可用和官方组合兼容分别验收。

## ADDED Requirements

### Requirement: 严格入口与真实安全事实

内核 SHALL 增加独立 `vless-grpc`、`vmess-grpc`、`trojan-grpc` 入口及严格gRPC配置，接受所属协议身份、原有受支持业务选项和成对可选TLS材料。未知字段、显式null、缺半组TLS、重复身份、畸形RPC服务配置或不支持的承载组合 MUST 在check/run联合准备时拒绝。check SHALL 不监听、解析业务域名或连接业务目标。旧类型及默认值 SHALL 保持其原契约；VLESS/Trojan明文接入必须显式准许，VMess无正文加密策略只能依据本入口真正完成TLS或所属显式弱化选项，不能信HTTP头或前置代理声明。

#### Scenario: 新配置与旧入口契约
- **WHEN** 检查合法新配置、半组证书、无准许的明文VLESS/Trojan或旧入口
- **THEN** 合法组合按自己的安全语义接受；非法组合在监听前失败，旧TLS/flow/默认开关不被放松，诊断不泄露身份或私钥

#### Scenario: 禁止任意层叠
- **WHEN** 新入口要求Vision、REALITY、未知RPC模式、early-data、TCP mux或未实现字段
- **THEN** 明确失败而不是忽略选项、降级为空flow或套用其他承载行为

### Requirement: 有限HTTP2和RPC准入

入口 SHALL 使用真正HTTP2及gRPC双向流，在合法的TLS协商或显式明文prior-knowledge连接上按固定上游仍可用的RPC方法接入，不把普通HTTP2 DATA等同于gRPC。方法、路径、内容类型和元数据 SHALL 有确定规则，错误方法/路径、歧义关键字段、非法伪头、压缩或其他不支持的协议语义 MUST 有限拒绝。HTTP响应头或gRPC承载建立 SHALL 不代表代理认证、路由或业务拨号成功；失败不得提供任意网页、通用RPC服务或业务DNS/目标访问。

#### Scenario: 合法RPC与错误路径
- **WHEN** 客户端建立合法HTTP2连接后提交符合配置的RPC，或提交错误方法、路径、内容类型、ALPN
- **THEN** 仅合法RPC进入代理字节流，错误组合有限失败且不触发业务目标；HTTP或gRPC元数据不授予代理身份

#### Scenario: 头部及控制资源边界
- **WHEN** 对端发送超过解压头限额、持续头续帧、超限并发stream或大量控制请求
- **THEN** 在明确帧/头/流数/处理预算内拒绝或施加背压，不按无界输入增加缓冲或任务，其他被允许流仍可有限前进

### Requirement: gRPC消息与代理字节流独立

承载 SHALL 正确解析gRPC五字节消息前缀和所支持protobuf载荷，明确压缩标志与声明长度上界；消息前缀、protobuf字段和代理头均可跨任意HTTP2 DATA分片到达。单DATA中的多消息及单消息中的多个代理包 SHALL 保持原始有序字节，空消息不得成为EOF，UDP边界由所属协议恢复。非法标志/长度、protobuf结构或截断 MUST 错误终止对应RPC，不将封装、未完成数据或另一RPC内容当作业务载荷。

#### Scenario: 任意跨层拆并
- **WHEN** 消息长度或protobuf字段逐字节到达，多个gRPC消息合并在DATA内，或代理认证/UDP包跨消息到达
- **THEN** 内层只收到原始顺序的业务字节且恰一次，不因HTTP2或gRPC边界丢字节、重放或改变UDP边界

#### Scenario: 巨大声明和部分消息结束
- **WHEN** 只收到超限消息声明，或流在半前缀、半protobuf字段、半payload时结束
- **THEN** 有限拒绝且不按声明巨额分配、不把部分消息伪造为成功业务；空合法消息与干净边界END_STREAM仍区分

### Requirement: 多RPC独立认证与资源准入

一条HTTP2连接 SHALL 可承载多个独立RPC，每个RPC单独执行完整代理认证、重放/安全策略和业务准入。物理连接、活动RPC、每入口握手、DNS和UDP关联/队列 SHALL 各有明确共享或局部限额；物理连接计量不得将RPC重复当成TCP连接，RPC不得借一条物理连接绕过全局活动RPC容量。同连接或跨连接的用户、协议状态、XUDP代次/GlobalID及响应 SHALL 隔离，单RPC认证失败/取消不得无故终止其他合法RPC。

#### Scenario: 同连接多个身份和请求
- **WHEN** 同一HTTP2连接同时请求不同身份、目标或业务类型，并包含一个认证失败或重放RPC
- **THEN** 每个合法RPC仅取得自己的目标和响应，非法RPC零业务访问，不污染其他RPC或重放池，物理连接及RPC活动计数准确

#### Scenario: 跨入口饱和与回收
- **WHEN** 新gRPC连接/RPC与旧入口竞争连接、握手、DNS或UDP资源，额度耗尽后释放其中一个RPC
- **THEN** 不超各自全局/局部限额，拒绝或背压有界；释放实际结束的RPC后额度可恢复，不能提前归还仍有子任务的名额

### Requirement: 背压与流控所有权

上下行 SHALL 有有限输入/输出缓冲、正确Pending/短写/取消游标和逐stream/connection流控。只有实际消费或按明确策略丢弃的数据才能归还对应接收容量，不能借提前无限归还流控额度积累消息。一个慢RPC或单方向写背压 SHALL 不无故阻止同RPC另一方向、连接控制处理及其他合法RPC可处理的数据；不按每帧产生无限任务或控制队列。

#### Scenario: 慢下行与另一方向进展
- **WHEN** 对端暂停读取一条RPC的下行，同时继续发上行并在另一RPC正常收发
- **THEN** 在固定缓冲及处理预算内可读上行与其他RPC仍前进，恢复后已接受载荷恰一次，窗口/许可最终归还

#### Scenario: Pending与取消不重复
- **WHEN** HTTP2发送额度不足、底层交替Pending/短写或RPC被取消
- **THEN** 返回值和业务计量对应真实接受数据，重试不重编码/重投已接受前缀；连接driver和RPC任务无遗留、无持锁跨等待导致的双向死锁

### Requirement: 独立结束方向与真实错误

承载 SHALL 区分请求END_STREAM、响应trailers/END_STREAM、RST_STREAM及连接GOAWAY/断开。完整gRPC消息边界的请求结束 SHALL 能结束代理读向并保留可用响应方向，使目标等待客户端FIN后返回的受支持TCP场景可真实完成；响应正常结束 SHALL 发送所属gRPC成功状态并拒绝新的响应业务写，而不伪造请求方向已结束。RST、半消息、非正常状态和缺少必要结束信息的连接/TLS截断 MUST 不冒充成功EOF。停止接新RPC、排空活动RPC和强停 SHALL 有界并保持其他已接受RPC的正确归属。

#### Scenario: 请求结束后目标才返回
- **WHEN** 客户端在完整消息边界结束请求方向，目标只在读到FIN后产生响应
- **THEN** 目标收到真实FIN、响应经仍可用方向完整返回并以正确trailers结束，不用私有EOF消息、WS式会话Close或过早RST替代

#### Scenario: 取消与GOAWAY
- **WHEN** 一条RPC被RST或服务端开始GOAWAY排空，同时还有合法活动RPC
- **THEN** 取消只结束规定范围且不伪造成功状态；停止接新RPC不直接丢弃已接受RPC，强停后全部相关任务及许可实际归还

### Requirement: 三协议原有业务和安全边界

三类入口 SHALL 在gRPC字节流上复用VLESS空flow认证/TCP/原生UDP/显式UDP-only XUDP、VMess AEAD/TCP/原生UDP/显式XUDP和packetaddr，以及Trojan多用户摘要/TCP/逐包UDP。协议响应次数、首载荷、服务器先发、地址来源、空包/载荷上界、逐目标路由和VMess同Server重放 SHALL 保持所属协议约定；不得加入其他协议响应前导。错误身份/标签/时间/flow/命令/未开启扩展或目标Reject MUST 先于对应业务DNS/拨号/发送及规定的协议成功响应。

#### Scenario: 明文与真实TLS业务
- **WHEN** 独立对端按允许策略在明文或真实TLS的三类入口请求TCP及UDP扩展
- **THEN** 首载荷、服务器先发、后续交换、IPv4/IPv6目标/来源及UDP包边界正确，HTTP2/gRPC封装不改变原有AEAD/重放/nonce或身份隔离

#### Scenario: 身份与逐目标负向
- **WHEN** 提交坏UUID/摘要/AEAD、非法flow/security/options或被拒绝的UDP目标
- **THEN** 仅按所属协议失败，零不应有业务DNS和网络，不把HTTP状态、同连接另一合法RPC或转发头当作成功认证

### Requirement: 绝对期限和真实结束屏障

TLS/HTTP2连接准备与RPC认证 SHALL 有明确的绝对期限和许可生命周期；RPC等待、认证及初始读取不得通过逐层刷新无限占槽。每连接/RPC的头、消息、输出、流控窗和任务 SHALL 有独立有限边界，不拿UDP载荷预算冒充全承载内存已覆盖。正常结束、坏认证、慢头/半消息、阻塞DNS、活跃UDP与停机 SHALL 经过真实任务结束屏障，联合准备失败不得遗留监听。

#### Scenario: 慢阶段和阻塞DNS强停
- **WHEN** 对端在TLS、HTTP2、RPC头/认证分别消耗时间，或在活跃RPC/UDP和阻塞DNS时停止服务
- **THEN** 不为每层重新获得完整期限；停止后无新RPC进入，有限排空/强停后连接driver、RPC及UDP子任务真实结束，预算和端口可恢复

#### Scenario: 后置准备失败
- **WHEN** 多入口联合准备后面的证书、参数或监听发生错误
- **THEN** 全量启动失败且没有部分ready服务，先前准备的监听和材料可回收，错误不反射秘密

### Requirement: 业务计量和证据分层

计量 SHALL 只包含业务接口实际成功接受的payload，不包含HTTP2、gRPC/protobuf、TLS、认证/响应、控制或flush。开发 SHALL 保存独立对端/金样、数据/认证/资源/关闭、CLI/示例和受影响旧路径的真实命令及输入；必要门禁通过后仅标已实现待集中验收。官方组合、三平台、精确MSRV、release及最终报告 MUST 在获准并实际执行后分别记结果，不把规划、依赖API、ignored、自有互测或旧WS结果充当新兼容证明。

#### Scenario: 计量、示例与秘密
- **WHEN** 替换回环模板占位后真实check/启动/业务，或检查错误响应/日志/Debug
- **THEN** 成功业务计量精确且不含封装，原模板无有效秘密不能误用；身份、私钥、完整元数据/请求和载荷不被反射，不公开整个私有工件目录

#### Scenario: 开发完成但集中验收未运行
- **WHEN** 必要本地开发门禁通过而新官方/平台/MSRV/release未获准或未执行
- **THEN** 仅勾真实完成的开发任务，集中验收保持待完成，不扩大旧授权，不声称完整Xray/sing-box/Nowhere替代
