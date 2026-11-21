## Purpose

为现有VLESS客户端提供标准TCP与TLS上的Vision服务端入口，明确用户flow、请求命令和实际TLS版本共同决定的准入、padding和Direct切换、缓冲与关闭所有权，防止把能解析配置或普通TLS转发误称为Vision兼容。

## ADDED Requirements

### Requirement: 显式用户flow与旧配置兼容

VLESS用户 SHALL 允许可选`flow`字符串，缺省或空字符串为既有无flow模式，唯一新增非空值为`xtls-rprx-vision`。null、其他类型、未知或历史flow、`xtls-rprx-vision-udp443`作为服务端用户flow MUST 拒绝；后者是参考客户端的本地策略选项，不是新的服务端线协议flow。flow SHALL 由已认证用户确定，不由客户端任意升级。混合同一监听的无flow和Vision用户 SHALL 可共存，用户名称/UUID唯一性、凭据脱敏、check无监听和未知字段拒绝行为保持。无flow旧配置及现有SOCKS5、Trojan、Shadowsocks行为 MUST 保持。

#### Scenario: 混合用户与非法flow
- **WHEN** 同一入口配置无flow和Vision用户，或提供未知flow/null/类型错误
- **THEN** 合法配置往返保留用户模式，非法配置在监听前失败且不回显UUID；缺省旧配置行为不变

### Requirement: 认证后的addons和命令准入

请求 SHALL 保持VLESS v0身份认证和有界addons长度。仅在用户配置允许时解析受支持的flow字段；非规范、重复或未知语义字段、畸形长度和截断 MUST 拒绝，不能通过删除非空addons伪装空flow。身份及完整请求准入失败 MUST 不连接目标、不发送成功响应。请求`xtls-rprx-vision` SHALL 要求对应Vision用户且实际外层TLS为1.3，仅接受TCP命令1和显式开启的UDP-only XUDP命令3；带Vision flow的原生UDP命令2 MUST 拒绝。

无flow用户 SHALL 保持既有空addons及允许命令行为。Vision用户的空请求flow SHALL 拒绝TCP，但允许基础原生UDP命令2，及在显式开启XUDP时的命令3；这些为空flow普通TLS路径，不挂Vision padding，不声称其为Vision Direct或要求其额外具备TLS1.3。命令3始终只允许UDP会话，不以识别前几个字节代替后续逐帧网络校验。`xudp:false` SHALL 拒绝所有命令3。

#### Scenario: flow和TLS版本不匹配
- **WHEN** 普通用户请求Vision、Vision用户以空flow请求TCP，或TLS1.2连接请求Vision
- **THEN** 在握手期限内拒绝，不拨号、不返回成功，也不退化为普通转发

#### Scenario: 两种UDP承载路径
- **WHEN** Vision用户使用空flow原生UDP/显式XUDP，或以Vision flow发送命令3
- **THEN** 前者保持无Vision包装的普通TLS UDP路径，后者在TLS1.3上先处理Vision再处理UDP-only XUDP；带Vision flow命令2及TCP mux均拒绝

### Requirement: Vision增量解包与有限padding

使用Vision的方向 SHALL 处理首个身份前缀和后续padding块，块格式为命令u8、内容长度大端u16、padding长度大端u16及相应字节。命令0 Continue SHALL 继续padding块，命令1 End SHALL 在消费当前块内容/padding后进入外层TLS无padding字节流，命令2 Direct SHALL 在同一边界后转为该方向原始字节流。内容、padding和身份前缀 MUST 不重复、不丢失，身份与padding不计业务字节。

解包 SHALL 对任意分片、多个块合并、零内容、最大u16长度及跨TLS记录边界保持同一语义；不得按一次read对应一个Vision块或完整TLS消息的假设工作。已识别Vision块的未知命令、截断头/内容/padding SHALL 终止该流，不转发未确认内容或退回猜测模式。首次前缀已明确不匹配用户UUID时，兼容透明路径 SHALL 保留已读字节，作为结束padding的外层TLS数据继续处理；仍可能匹配时 SHALL 有界等待足够字节，不因单次短读退回透明路径。身份不匹配不是第二次用户认证或Direct信号；身份选择只来自先前VLESS认证。这是本项目的透明策略，不声称三家接收器具有相同探测行为。

无进行中字段且处于初始空输入、完整Continue块之后的块边界或End/Direct后的EOF SHALL 正常结束读方向；部分匹配UUID、完整UUID后缺块头、半块头/正文/padding遇EOF SHALL 报截断。完整5字节头及当前正文/padding消费完成前 MUST 不提交End或Direct。

#### Scenario: 分片、合并和padding边界
- **WHEN** 身份前缀、块头、内容及padding逐字节到达，或多个块及End/Direct后的数据一次到达
- **THEN** 目标只收到按顺序完整的内容和切换后字节，padding不进入目标，不因分片改变状态

#### Scenario: 异常块和透明首数据
- **WHEN** 已识别Vision后收到未知命令/截断块，或首数据明确不匹配Vision身份前缀
- **THEN** 前者有限时失败，后者保留全部首字节走外层TLS无padding路径；两者均不能误切Direct或产生无界缓存

### Requirement: 下行封装和内层TLS识别

服务端 SHALL 对Vision请求的响应业务流生成参考客户端可解析的首身份前缀与padding块；VLESS响应头保持独立且只发送一次，不计业务字节。写入内容 SHALL 有界分块，长度字段不得溢出，随机padding使用成熟随机源。下行封装、内层TLS识别和上行解包 SHALL 不依赖调用者read/write分片大小。

仅在识别到满足固定基线条件的内层TLS1.3及允许套件0x1301/0x1302/0x1303/0x1304、完整ApplicationData记录边界时 SHALL 发出Direct；0x1305、未知套件、非TLS、内层TLS1.2或无法在有限检查预算内确定 SHALL 用End结束padding并继续外层TLS，不删除或改变业务内容。完整记录判定 SHALL 跨调用者写入边界跟踪，不能因一次短写改变结果。识别过程是本端发送策略，不实现新的TLS密码学，不解密用户内层TLS；上下行共享必要识别事实但切换状态独立。接收合法Direct SHALL 不依赖本端是否识别到内层TLS、套件或该块内容是否恰好组成完整TLS记录，不把某一参考实现的发送启发式变为额外接收拒绝条件。

#### Scenario: 非TLS、TLS1.2与TLS1.3
- **WHEN** 受控目标分别返回非TLS数据、内层TLS1.2、允许套件的TLS1.3，以及分片/无法完整识别的握手
- **THEN** 非Direct路径仍可正确转发，符合条件的TLS1.3走真实Direct，检查预算耗尽只结束padding，不吞掉业务或无限等待

#### Scenario: 短写与重试
- **WHEN** 封装块输出遇到Pending、部分写、背压、错误或取消
- **THEN** 已接受载荷不重复、不重计，原始字节不得越过尚未完成的最终外层TLS块；失败后不继续使用终止状态发送

### Requirement: 双向独立的TLS到原始流切换

从连接握手开始 SHALL 约束外层TLS输入，Vision判断当前解密结果前 MUST 不将后续可能属于Direct的字节交给外层TLS。Direct块与后续原始数据在同一次网络到达时 SHALL 全部保留，先交付当前块内容，再按已声明的尾部顺序交付剩余字节。不能以丢弃TLS缓冲、重连目标或继续将原始数据当外层TLS解密来实现切换。

读写方向 SHALL 独立转换；只读方向Direct时写方向仍能通过外层TLS响应，反之亦然。写方向 SHALL 完成Direct块、排空此前外层TLS密文并保留顺序后，才发送原始字节。TLS控制消息及已排队输出 SHALL 被显式处理：Direct提交前按TLS处理并排空，提交后不得将新生成的外层记录或告警混入原始写方向；无法安全处理的非法转换 SHALL 有限时关闭，不能悄悄丢弃业务或恢复外层TLS。Direct后不再发送该方向外层close_notify。

#### Scenario: 最后外层记录与首个原始记录同到
- **WHEN** 包含Direct的最后外层TLS记录与第一批原始字节合并到达，并在任意位置分片
- **THEN** 每个业务字节恰好交付一次，不越界解密，且另一方向继续保持自己的TLS/Direct状态

#### Scenario: 双向不同步切换与关闭
- **WHEN** 一方向已Direct，另一方向仍TLS，随后发生flush、TLS控制消息、单向EOF或取消
- **THEN** 状态与输出顺序明确，半关闭不提前中止另一方向，不向原始业务插入外层TLS告警，资源最终释放

### Requirement: UDP-only XUDP与端口语义

Vision封装的命令3 SHALL 解包成既有UDP-only XUDP帧，复用逐报文路由、实际来源、会话代次、关联/目标/队列/字节预算、空闲和stop/force/children回收。空flow的UDP/XUDP例外 SHALL 使用普通TLS对应路径，不运行Vision流状态机。不得将TCP mux、跨承载GlobalID续接或UoT混入此能力。

服务端 SHALL 不把参考客户端默认拒绝UDP/443的出站策略误实现成所有客户端/所有入口的全局端口禁令；转发仍受配置路由限制。最终互通 SHALL 在客户端允许的受控回环目标验证原生UDP或XUDP，单独记录UDP/443默认拒绝或显式允许策略，不靠跳过该场景宣称全部UDP支持。

#### Scenario: Vision下多个UDP目标及隔离
- **WHEN** 已启用XUDP的Vision承载创建多个会话、切换逐包目标并复用编号
- **THEN** 每帧保持边界和来源，身份/代次不串流量，禁止TCP会话且超限可回收；无效认证或拒绝路由不得触及目标

#### Scenario: 参考客户端UDP端口策略
- **WHEN** 官方客户端默认限制或显式允许UDP/443
- **THEN** 客户端本地拒绝与服务端拒绝分别记录，未到达服务端的包不计服务端认证/转发通过

### Requirement: 共享预算计量及有期限停机

Vision SHALL 共享既有全局TCP连接/每入口握手许可，TLS及VLESS认证共同受握手期限约束；流状态、输入记录、待写封装和内层识别 SHALL 各有明确上限，不为每包/每次poll创建任务或无界缓冲。业务计量 SHALL 只计成功交给业务目标或客户端流的载荷，不含VLESS头、UUID、Vision头/padding或外层TLS开销；部分写、发送失败及超限不得被高估。

结束、错误、半帧、慢消费及force停机 SHALL 释放任务、监听、目标连接和UDP许可，现有stop→有限排空→force→join/children屏障保持。用户态复制 SHALL 正确，不以尚未实现splice为理由放宽切换、计量或回收。

#### Scenario: 混合入口与背压强停
- **WHEN** Vision与无flow VLESS、Shadowsocks等入口并存，触发共享限额或在Direct前后慢读并停止服务
- **THEN** 限额全局生效、队列有界，已完成载荷计量精确，期限后所有任务结束且端口/许可可复用

### Requirement: 开发验证与能力簇验收分离

开发阶段 SHALL 执行编译、独立手写报文/状态测试、TLS记录边界实验、身份/flow/TLS版本负向及局部资源回收测试，不能把所有验证推迟到全部代码完成。完整普通回归、三平台/工具链验证和固定官方客户端矩阵 SHALL 集中在后续能力簇收尾执行；实现完成且必要检查通过后允许推进其他独立模块，但未执行的验收任务 SHALL 保持未完成，状态为已实现待验收。

最终官方目标 SHALL 分别固定Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31的macOS ARM64构建，核验普通文件、官方归档摘要及启动前SHA-256，仅受控回环、私有产物和可回收进程。TCP正向 SHALL 分别覆盖非TLS、内层TLS1.2和内层TLS1.3，以观测证明确实触发Direct而非全走End；UDP/XUDP按具体客户端能力独立记录，错误UUID、错误flow、TLS版本及证书信任负向分别记录。新的客户端执行范围 SHALL 单独获准，不继承旧Shadowsocks矩阵执行授权。

#### Scenario: 实现完成但集中验收未运行
- **WHEN** 开发必要检查通过，但三平台或官方矩阵尚未实际运行
- **THEN** 可以继续下一已规划模块，文档和任务仍记录待验收；不复用旧构建209项或33项结果冒充新构建完成

#### Scenario: 容器或外部运行不可用
- **WHEN** Linux容器环境未运行、工具链不可用或新的官方矩阵未获准执行
- **THEN** 明确列出对应阻塞并保留未执行，不删资源、改全局设置或换工具/代理绕过；本机其他已授权开发工作可继续
