## Purpose

让已有 REALITY 客户端通过明确版本和组合连接同一个原生服务端内核，并在 REALITY 与 VLESS 两层认证成功后使用既有 TCP、UDP 和 Vision 能力。该能力同时约束失败回落、秘密保护、有限资源、证据等级与兼容声明，避免将普通 TLS 实验或配置解析成功冒充完整协议支持。

## ADDED Requirements

### Requirement: 独立入口与严格配置

系统 SHALL 提供独立 `type:"vless-reality"` 入站，包含 `tag`、`listen`、既有 VLESS `users`/`flow`、默认关闭的 `xudp` 及必填 `reality` 对象。系统 MUST 拒绝标准证书字段、未知字段、显式 null、非法密钥、目标端口零、空 SNI/short ID 列表、重复身份或规范化后重复 short ID；既有 `vless` 仍要求标准证书与私钥，不接受隐含的安全承载降级。

`reality` SHALL 声明固定 `target`、静态 X25519 `private_key`、精确匹配的 `server_names`、hex 编码的 `short_ids`、默认 120000 毫秒且不可关闭的 `max_time_diff_ms`、可选三字节版本下/上界、可选 ML-DSA-65 种子及有限回落期限。short ID MUST 与 VLESS UUID/用户分离；hex 偶数长度不超过 16 字符，右补零至八字节，显式空串表示全零 ID，不暗中增加全零 ID。

#### Scenario: 旧入口和新入口并存
- **WHEN** 配置同时包含标准证书 VLESS、Vision、VMess 和合法的 `vless-reality`
- **THEN** 系统分别准备各自承载，旧入口无需修改，新入口只能在 REALITY 和 VLESS 准入均成功后使用业务能力。

#### Scenario: 非法配置与纯检查
- **WHEN** 执行 check，或配置包含半组/混合承载字段、规范化重复 short ID、时间窗零、非法种子、错误类型或未知字段
- **THEN** check 不监听、不 DNS、不连接目标、不启动探测；非法配置退出失败，诊断不泄露密钥、种子、UUID、short ID 或完整原始报文。

### Requirement: 有界原始 ClientHello 与认证输入

系统 SHALL 保存原始 TLS record 与去除 record 头后的完整 ClientHello 握手消息，支持跨记录分片及同记录尾部合并，任何消费过的字节均有唯一所有者。系统 MUST 在分配或进一步读取前检查记录、握手长度、总预读字节和记录数量，应用既有握手期限；无效结构、截断、重复关键扩展、超限或不支持的 early data/PSK 输入不得进入 VLESS 或触发固定目标拨号。

#### Scenario: 分片与尾部保留
- **WHEN** 相同合法 ClientHello 被逐字节分片、跨多条记录传递，或最后一条记录还含后续握手字节
- **THEN** 认证使用相同的完整握手消息；后续 TLS 或回落路径收到原始字节恰好一次，不丢失、不重复、不将 record 头纳入认证 AAD。

#### Scenario: 恶意长度或取消
- **WHEN** 输入声明过大长度、无限空记录、半条记录后停顿，或握手在任意读取点被取消
- **THEN** 系统在有限内存/时间内失败并关闭承载，无后台遗留读取、固定目标访问或业务计量。

### Requirement: 固定版本 Session ID 认证

系统 SHALL 按固定 REALITY 基线，使用服务端静态 X25519 与选定客户端 X25519 公钥产生 32 字节秘密，以 HKDF-SHA256 的 salt=`ClientHello.random[0..20]`、info=`REALITY` 派生 32 字节 AuthKey，再以 AES-256-GCM 和 nonce=`random[20..32]` 认证解密 32 字节 Session ID。AAD MUST 是完整原始 ClientHello 握手消息，其中 Session ID 的 32 字节内容临时置零，其长度及其他字节保持不变；供 TLS、回落和证书绑定使用的原文 MUST 保持密文 Session ID。

解密明文 SHALL 为三字节版本、一字节零保留位、四字节大端 Unix 秒和八字节 short ID；版本边界包含端点，SNI 与配置项精确匹配，时间比较以毫秒配置为准。该入口对保留位零的要求和非零时间窗为本项目明确的额外约束，不描述为上游已强制。

#### Scenario: 独立认证向量
- **WHEN** 使用独立已知 X25519 材料、random、原始 ClientHello 和 Session ID 金样
- **THEN** 服务端产生精确 AuthKey、nonce/AAD 并接受合法输入；错误密钥、AAD、标签、SNI、short ID、时间或版本不能获得 REALITY 应用承载。

#### Scenario: 毫秒和时间边界
- **WHEN** 客户端时间位于配置窗口端点、端点外一毫秒，或本机墙钟发生回退/严重前跳
- **THEN** 端点包含且越界拒绝；本地防护不因回退重新开放已失效窗口，异常时失败关闭，不修改系统时钟，也不把时间窗口称作永久重放保护。

### Requirement: 混合认证选择与独立 TLS 密钥协商

系统 SHALL 接受有效 X25519MLKEM768 share（1216 字节）在前且可选普通 X25519 share（32 字节）在后的固定版本输入；同时存在时认证优先使用普通 share，否则使用 hybrid share 的末 32 字节。系统 MUST 不向缺少 hybrid、错误长度、关键 share 重复或顺序无效的输入授予 REALITY 承载，并注明完整重复扫描是本项目更严格的解析策略；结构合法但缺少必需 share 的普通 TLS CH 仍可按固定目标回落，畸形/重复输入直接关闭。

TLS1.3 SHALL 按受支持的目标模板使用独立的服务端临时密钥协商 X25519 或 X25519MLKEM768；hybrid 的服务端 share 为 1088 字节 ML-KEM 密文加 32 字节 X25519 公钥，共享秘密顺序为 ML-KEM32 后接 X25519 32。认证静态密钥 MUST NOT 充当 TLS 临时密钥；收到 hybrid 不等于最终必须协商 hybrid。

#### Scenario: 两种合法认证选择
- **WHEN** 分别提交 hybrid-only 和 hybrid+普通 X25519，且两个 X25519 公钥刻意不同
- **THEN** 两者选择正确的认证材料；目标选择可用普通组或混合组时，最终 TLS 密钥协商与认证选择互不混淆。

#### Scenario: 不可完成的协商
- **WHEN** 目标选择客户端没有提供的 share、HelloRetryRequest、不受支持的组/套件或非 TLS1.3
- **THEN** 系统不伪造成功或改写为另一协商结果；未提交本地握手输出前按固定目标回落，提交后只能关闭，绝不交给 VLESS。

### Requirement: 有限精确重放防护

系统 SHALL 在同一 Server 实例的 REALITY 入口间共享独立容量，按静态服务端公钥与完整密文 Session ID 原始 ClientHello 的摘要识别精确重复；它 MUST 不复用或改变 SS/VMess 的容量与重放规则。通过结构、认证和本地策略后，系统 SHALL 在任何固定目标连接和昂贵签名前原子占位，保留至不能再通过原时间窗；后续失败或取消不撤销，容量满不驱逐有效条目，也不回落绕过。

#### Scenario: 并发重复和跨入口
- **WHEN** 多个入口使用同一静态公钥并发收到相同认证 ClientHello，或前一次握手占位后被取消
- **THEN** 至多一个请求继续固定目标连接，其余关闭；不同静态身份隔离，失败取消不立即释放精确重复保护。

#### Scenario: 饱和与到期
- **WHEN** 容量被不同合法 ClientHello 占满，随后发生时钟回退和正常到期
- **THEN** 满额请求失败关闭，条目及到期元数据始终有界；到期恢复容量，不声称跨进程、重启或永久精确保护。

### Requirement: 特殊证书与可选 ML-DSA 绑定

系统 SHALL 使用 Ed25519 公钥证书，其 X.509 `signatureValue` 的 64 字节为 `HMAC-SHA512(AuthKey, raw Ed25519公钥32)`；TLS CertificateVerify 仍 MUST 由对应 Ed25519 私钥正常签署 TLS transcript。正常公开信任证书不能代替 REALITY 身份证明。

配置 ML-DSA-65 种子时，系统 SHALL 在首个证书扩展（OID `0.0`）中放入对 `HMAC-SHA512(AuthKey, pub32 || 原始CH || 最终原始SH)` 的有效标准 ML-DSA-65 签名，使用无 record 头、含密文 SID 的 CH 及已替换服务端 share 的实际 SH。签名 MUST 与配置种子派生的 1952 字节公钥可验证；不要求不同合法随机签名逐字节相同，不能以此省略消息、context 和标准编码的互通验证。

#### Scenario: 基础证书与 TLS 签名分开验证
- **WHEN** 客户端使用正确 AuthKey 验证证书，并独立检查 CertificateVerify/Finished
- **THEN** 两层均有效才完成握手；改动证书公钥、HMAC 或 CertificateVerify 不会获得代理业务，即使普通 x509 信任可通过。

#### Scenario: ML-DSA 的实际绑定
- **WHEN** 启用 ML-DSA，并分别修改原始 CH、最终 SH、扩展顺序、签名或验证公钥
- **THEN** 合法组合验证通过，所有错误绑定失败；配置不可实现或无有效签名时拒绝准备或握手，不静默退为无 ML-DSA。

### Requirement: 配置目标模板与握手完成边界

系统 SHALL 只向管理员配置的固定 `target` 建立握手辅助连接，保留原始 ClientHello，验证目标提供的 TLS1.3 ServerHello、Session ID、套件、组和有界记录布局。有效路径 SHALL 使用目标模板、独立协商产生的本地服务端 share 和本地实际发送字节形成一致 transcript，而不是采用目标的 TLS 共享秘密、证书或应用数据。

系统 MUST 验证本地 TLS ClientFinished 后才交付应用；禁用 early data、票据及会话恢复，每条新连接重新认证。模板等待、握手记录生成与目标辅助连接均 MUST 有明确期限和所有者，不依赖无界后台探测表初始化。不能仅以普通 TLS＋特殊证书的成功实验满足本要求。

#### Scenario: 受控普通组与混合组模板
- **WHEN** 自持目标分别产生允许的普通 X25519 或 hybrid TLS1.3 ServerHello 及不同合法记录长度
- **THEN** 本地实际 SH 保留被允许的模板字段，替换后的 share 与本地派生秘密一致；接收端按实际 transcript 验证完成，目标密文不作为业务明文返回。

#### Scenario: 目标异常与伪完成
- **WHEN** 目标超时、在合法 SH 之前输出数据、给出畸形模板/超大布局，或客户端发送无效 ClientFinished
- **THEN** 系统不交付 VLESS；不存在等待探测表的无限挂起、未验证明文前递或完成标记提前。

### Requirement: 固定目标失败回落与不可逆提交

系统 SHALL 将结构可接受但认证/SNI/时间/版本策略不匹配的普通 TLS ClientHello 仅向固定目标原始转发，回落连接不得访问客户端 SNI 指向的任意地址。malformed、超限、精确重放、容量不足及 early data/PSK 明确拒绝不进入回落。有效认证但模板不可用时，系统 SHALL 仅在本地 TLS 输出尚未提交的情况下转交原始目标流；一旦提交本地输出，不得拼接两条 TLS 握手。

回落 SHALL 保留已读双向字节及 TCP 半关闭，受全局连接许可、空闲/总期限、有限缓冲和强停控制；不产生 VLESS 成功应答、不增加代理业务流/业务字节计量，不作为通用未认证代理。

#### Scenario: 错误认证访问范围
- **WHEN** 完整 ClientHello 的标签、SNI 或 short ID 不正确
- **THEN** 只有固定受控回落目标可以收到原始数据，任意业务目标均无连接，业务计量为零，返回内容完全来自固定目标而非 VLESS 解析。

#### Scenario: 短写、取消和提交后失败
- **WHEN** 已保存目标输入需要短写/重试，任一方向半关闭，或本地 SH 已写出后握手失败
- **THEN** 保存字节恰好一次交付，半关闭不截断反向排空；取消能回收双方 socket，而提交后的错误只能关闭，不混入回落目标握手。

### Requirement: VLESS 与 Vision 的两层准入

系统 SHALL 在 REALITY TLS1.3 完成后复用既有 VLESS UUID、flow 与命令检查。无 flow SHALL 支持 TCP、原生 UDP 和显式 UDP-only XUDP；Vision SHALL 支持 TCP 与既有 UDP-only XUDP 组合，不扩展为原生 cmd2 或 TCP mux。REALITY short ID 不授予 VLESS 身份或 flow 权限；成功 VLESS 应答仅一次，TCP 路由/连接成功后才发，UDP 服从现有限额准入。

#### Scenario: 业务组合
- **WHEN** 通过两层认证后分别发起无 flow TCP/原生 UDP/XUDP 或 Vision TCP/XUDP
- **THEN** 使用既有业务编码、半关闭、逐包路由、来源过滤及多会话隔离；XUDP 不跨承载续接，不重复 VLESS 响应。

#### Scenario: 两层认证不能互相代替
- **WHEN** REALITY 认证合法但 UUID/flow 错误，或请求被路由 Reject
- **THEN** 无业务 DNS/目标连接及 VLESS 成功响应；已发生的固定握手辅助连接单独记录，不误称全连接零网络 IO。

### Requirement: Vision 原始流交接保持正确

系统 SHALL 在 REALITY 承载上保持既有 Vision 单条 TLS record 输入、明文排空、逐方向 Direct、输出 flush 屏障、错误闩锁和 shutdown 后拒写行为；握手预读与辅助记录不得使首个 Direct 字节被误送外层 TLS 解密。外层提供者或握手钩子的变更不能自动视为本要求通过。

#### Scenario: 最后外层记录与 Direct 合并
- **WHEN** 最后一个 Vision 外层 TLS record 与首批 Direct 字节一次到达，且另一方向仍使用 TLS，写方向出现 Pending
- **THEN** 字节不丢失、不重复、不越界解密；读取不被无关写背压阻塞，最后外层记录在 Direct 字节前完成 flush。

#### Scenario: Direct 后半关闭与控制消息
- **WHEN** 任一方向 Direct 后关闭或遇到 TLS KeyUpdate/失败
- **THEN** 不向已切换的原始写方向插入外层 close_notify/控制记录；仍在 TLS 的方向保持正确错误和关闭语义，强停能真实结束所有子任务。

### Requirement: 共享资源、计量与安全依赖边界

系统 SHALL 将新入口的 accepted TCP、握手辅助目标、回落、密码操作和 UDP 子任务纳入现有有限生命周期；每条 accepted TCP 至多一条同时存活的固定目标辅助连接，不按字段/记录无限派生任务。系统 MUST 在 stop→drain→force→join 后归还连接/握手/UDP/排队预算并释放端口；代理计量只统计业务接口实际接受的载荷，不含 REALITY/TLS/VLESS/Vision 封装或回落。

系统 MUST 使用经过来源、许可、摘要、features、MSRV 与安全公告审查的成熟密码/TLS 依赖，不自研密码原语，不通过外部内核进程提供生产功能。任何新增握手钩子必须默认关闭、校验输入并保持普通 TLS 的默认安全检查；无法满足时不得以删减协议行为或忽略配置代替。

#### Scenario: 混合饱和与强停
- **WHEN** REALITY 的半头、目标阻塞、活跃回落、Vision 和 UDP 与旧入口共同耗尽许可，随后触发强停
- **THEN** 占用始终有界，后续请求按规则拒绝；所有辅助/业务 socket、队列、许可和被追踪任务最终真实归还，旧入口行为不退化。

#### Scenario: 依赖或补丁门禁失败
- **WHEN** 需要未经审查的替代 TLS 实现、更高 MSRV、额外许可代码，或当前钩子不能正确验证 Finished/transcript
- **THEN** 对应任务保持未完成并报告阻塞，不自行改变算法、采用来源不明 fork、安装全局 provider 或预写兼容通过。

### Requirement: 分阶段证据与兼容声明

系统 SHALL 将开发定向证据与官方客户端、三平台、精确 MSRV、最终 release 验收区分。开发阶段覆盖本能力的认证/报文/资源和受影响旧功能后可以推进下一独立模块，但 SHALL 仅标“已实现待集中验收”；全部规定集中验收完成才标本变更完成。

#### Scenario: 新能力与旧结果分离
- **WHEN** 基础 HMAC 实验、独立客户端或旧 Vision/VMess/SS 验收通过，但新官方矩阵尚未执行
- **THEN** 报告只承诺实际组合，记录模板/回落/ML-DSA/IPv6 等未覆盖项，不把旧 106/209/262/33 数字当作 REALITY 通过，也不使用旧 release。

#### Scenario: 官方客户端执行门禁
- **WHEN** 准备执行固定 Mihomo、sing-box 或 Xray 的 REALITY 矩阵
- **THEN** 先静态核查版本、实际依赖、配置和已校验二进制，再取得本批范围许可；未授权、不支持、未运行和客户端本身拒绝分别记录，不自动恢复容器、发布、归档或修改系统网络/权限。
