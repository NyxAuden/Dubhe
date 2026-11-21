## Context

动机见[proposal](proposal.md)，可验收行为见[spec](specs/websocket-inbound-transport/spec.md)。本批已进入实施：获准加入四个精确WS/HTTP新包，公共承载、三协议入口及独立回环端已接入，19项开发门禁已完成，整体19/27、已实现待集中验收，见[开发记录](../../../docs/websocket-development.md)；尚未运行本批官方客户端矩阵、三平台全量、精确MSRV或release。完成状态以[tasks](tasks.md)及真实开发记录为准。

以下为规划时核实的接点（行号和“没有WS”等描述属于实施前历史，不表示当前代码仍缺失）：

- `src/config.rs:32–105,130–148`：严格带标签入口；旧Trojan/VLESS必填TLS，VMess成对可选TLS，REALITY独立类型。没有WS配置或HTTP/WS专用预算。
- `src/runtime.rs:434–495,570–627`：Trojan/VLESS普通TLS及VMess已有成熟业务分派；协议解析接受通用异步流。WS应放在可选真实TLS之后、既有协议认证之前，不能复制DNS/路由/UDP内核。
- `src/runtime.rs:455–472`、`src/tls/vision.rs`：Vision持有Controlled并切到TLS下方原始IO，直接叠WS会越过其framing。本批静态拒绝该组合，不下长期绝对不可能的结论。
- `src/forward.rs:102–119`：现有TCP relay使用双向复制及单向shutdown，WS关闭不能借此冒称原生TCP半关闭。
- 当前lock没有tungstenite/tokio-tungstenite/http/httparse；本机只有0.29.0两个WS crate归档与http1.5.0、httparse1.10.1缓存，未校验、未解包。不能因有缓存就当已批准依赖。

### 固定上游事实（不是官方运行结果）

| 基线 | 已读取文件和行为 |
|---|---|
| Xray v26.10.31 / `a4a3dff5b20c2faae567b742c172c7b95e75c083` | `transport/internet/websocket/{hub,dialer,config,connection}.go`：服务端按URL.Path精确匹配；header early-data经`+→-`、`/→_`、删`=`后RawURLEncoding解码，成功非空时原值回显子协议。客户端实际发送RawURL；首写超过Ed时整包不放early-data，而非截取。写Binary；正常Close1000/无状态转EOF，其余错误保留。 |
| sing-box v1.14.4 / `c005f35300ce76427dc285481ec5695f5b179cd2` | `transport/v2raywebsocket/{server,client,conn}.go`：有header时按URL.Path匹配且从指定header取RawURL；无header时从RequestURI中去掉配置path前缀后RawURL解码。客户端在Path追加无padding RawURL，首包超过max时截取前缀，余下入帧；`Sec-WebSocket-Protocol`专门转Dialer.Protocols。server该调用点不主动回显子协议，不据此推断第三方ws库全部行为。 |
| Mihomo v1.19.33 / `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` | `transport/vmess/websocket.go:176–201,337–433,492–509`：early-data默认追加Path，非空header名写头，RawURL；首包截取max，余下入Binary；path的`ed` query会改为Sec-WebSocket-Protocol并移除该query项。普通Write发Binary，Close发送Close后关底层。文件亦含另一种无WebSocket-Key的httpupgrade，不能混入本批。 |

固定来源：[Xray服务端](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/websocket/hub.go)、[Xray客户端](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/websocket/dialer.go)、[sing-box服务端](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/transport/v2raywebsocket/server.go)、[sing-box首写](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/transport/v2raywebsocket/conn.go)、[Mihomo](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/vmess/websocket.go)。原始HTTP/WS实现只用于理解，不复制Go协议模块。只读下载分别保存在独立新空目录，API原文与解码源码分开放，Python `-I`，未执行其中代码。私有证据：`.test-artifacts/ws-source-static-kpzcfq7f/manifest.json`、`ws-source-followup-ykf_lby2/manifest.json`、`ws-final-source-94jrv2d1/manifest.json`，每项记录commit/path/SHA256。WebFetch曾有连接失败，后续实际取得GitHub公开API数据才形成上述结论，失败不算已读。

标准：[RFC6455](https://www.rfc-editor.org/rfc/rfc6455) §4–5、7。WS Close是连接级关闭，不定义独立单向FIN；客户端必须mask，服务端不mask；控制可插入分片且≤125字节；载荷长度用最短编码。

## Goals / Non-Goals

**Goals:** 以一个有限字节流承载复用三种协议；显式区分真实TLS、early-data方言及半关闭局限；在新旧入口共存时维持既有认证/路由/计量和结束屏障；必要本地检查先于继续下一模块。

**Non-Goals:** 不造任意transport组合框架，不在本批重构Controlled/REALITY，不提供HTTP网站/转发代理、压缩或私有EOF扩展。其他范围见proposal；未知外部互通不能用自有双方互测填补。

## Decisions

### D1. 独立入口与严格配置，不放松旧类型

新增`vless-ws`、`vmess-ws`、`trojan-ws`；共有`tag/listen/users/websocket`和成对可选`certificate/private_key`，沿用VMess的present-path规则拒显式null。证书出现即真实WSS；无证书是明文WS，不从Forwarded/X-Forwarded-Proto/Host推断TLS。对三种新入口设置用户数1..1024，身份/名称校验沿用所属协议。

- VLESS复用VlessUser但配置必须全部flow=None；保留`xudp:false`默认。wire非空flow拒绝。
- VMess沿用四布尔默认false：xudp、packetaddr、allow_insecure_body、allow_authenticated_length。旧重放池按同Server身份共享，不能为每个WS连接另造空池。
- VLESS/Trojan各有`allow_insecure_transport:false`，无TLS时必须显式true，即使listen回环。该开关不用于VMess，不允许混淆正文和传输安全。
- `websocket`必填严格对象，`path`必填；`host`可选但显式null/空拒；`early_data`缺省关闭，显式null拒。存在early_data时对象为`{mode:"header"|"path",max_bytes,header_name?}`，max_bytes必填1..8192；header模式header_name缺省`Sec-WebSocket-Protocol`，path模式出现header_name即错误。正文/私钥/early-data等不Debug，不记录完整HTTP URI或头。

替代方案：给旧入口添加任意transport且将TLS变可选，会改变已验收旧配置契约；全局通用layer堆叠会暗许Vision/REALITY错误组合。本批用三个显式兼容单元，后续是否统一另行设计，不预留动态ABI。

### D2. HTTP握手、路径与额外安全策略

用成熟HTTP parser解析一个有限请求，保留原始单值头计数以拒重复/歧义，再用成熟WS握手函数生成Accept和101，而不是手写SHA-1。不运行完整HTTP server，不接受keepalive上的第二个HTTP请求，不信任HTTP转发源地址。

- 只接受GET HTTP/1.1 origin-form；总头含结束符≤16384字节、头数≤64、request-target≤12288，固定每次小读。头外预读≤16384；总预读存储≤32768。未见终止符达到头上限立即拒，不能再等body。每个边界用checked算术。
- Host/Key/Version/Upgrade/early-data承载字段须单值；Connection允许多个值合并token检查；拒CL（包括0）、TE、obs-fold、非ASCII或控制字符request-target、非法百分号、fragment、用户信息或绝对URL。Host必填合法ASCII authority，不能缺省拿SNI代替；Upgrade限定websocket，版本13，Key规范标准base64解码16。未知普通header可忽略，不记录值。
- path配置为1..1024字节ASCII绝对路径，不含query/fragment/控制/空格；百分号须完整，解码后仍合法ASCII。normal/header模式将请求path与配置path各percent-decode一次后区分大小写精确比较，不做`+`转空格、不折叠`..`/重复斜线、不忽略尾斜线；query不参与匹配也不解释其`ed`数字，仍受request-target上限。路径中query的客户端阈值提示不是实际early-data。
- path early-data模式另要求配置path无百分号，请求raw path为同一原始base path加无转义RawURL后缀，不接受query；不能将query里的secret或数字解码为前缀。这比上游部分宽松输入严格，文档公开，而非声称逐字节行为全等价。
- 可选host以成熟authority类型解析，DNS忽略ASCII大小写、不trim尾点，IPv6用括号/IP解析；端口若配置则必须相同，未配置只比较host部分但仍验证请求端口合法。不通配、不解析DNS、不作业务路由依据。Origin不作为非浏览器代理认证；不强制同源，不授予网页/API权限。
- 不协商压缩；客户端合法扩展提议可忽略且响应不回扩展，后续RSV仍拒。不实现真正应用子协议；early-data关闭时任何非空Sec-WebSocket-Protocol拒绝，避免误吞认证前缀。
- 错误只发固定小响应（400/404/431等）或关闭，不含请求值/目标，不重定向或代理HTTP。101写完前不进入协议认证；101不是代理成功，仍需保留握手许可。

### D3. 同时覆盖header与path early-data，禁隐式探测

本批纳入三家实际发送的无padding RawURL：header默认名兼容Xray；path后缀兼容sing-box/Mihomo。支持显式自定义header，但只允许合法单个HTTP token≤64，禁止Host/Connection/Upgrade、Key/Version/Accept/Extensions、CL/TE/Authorization/Cookie/转发头及代理认证相关保留名；比较忽略大小写。不得同时接受header与path两个来源。

- max_bytes为解码载荷上限；解析前限制编码长度`ceil(4*max_bytes/3)`，max8192时≤10923。严格RawURL、拒padding/标准`+/`/非法尾位/逗号列表/重复值；Xray服务端对旧标准base64的宽容是已见事实，但固定三家客户端发送RawURL，本项目公开不接受其宽容别名，不悄悄宣称完全等价。
- header缺省/空值表示无前缀，不强迫每次必须early-data；path无后缀同理。其他来源的非空Sec-WebSocket-Protocol不能被自定义header/path模式顺带接受。
- 仅当载体为Sec-WebSocket-Protocol且成功解码为非空时，101回填请求同一合法token；其他header及path不回填。此回填是已知代理early-data方言，不是额外子协议协商/服务器身份验证。
- 101成功后解码字节排在所有WS帧明文之前；HTTP parser已经读到的帧字节交给帧引擎，不把它们当明文；两个prefix各有唯一游标。prefix直到完整协议认证成功前同样受绝对deadline/握手槽。错误认证不得访问业务DNS/目标。

替代方案：只做不带early-data的标准WS会漏掉现用客户端配置；自动猜任意头/path会产生歧义与泄密。选择两个显式模式和严格边界。

### D4. 成熟WS库候选与最小结构护栏

规划首选候选`tokio-tungstenite =0.30.0`、`tungstenite =0.30.0`（default=false，仅handshake）及`http =1.5.0`、`httparse =1.10.1`，具体直接/传递边按真实API最小化；WS不用库内TLS/connect/url，复用既有tokio-rustls局部ring。0.29缓存不是锁定选择：其handshake需另引sha1^0.10，0.30源码显示采用已有sha1^0.11，但不能因此声称完整闭包无需新增包。精确发布归档经[静态门禁](../../../docs/websocket-dependency-gate.md)核对：tokio-tungstenite0.30.0为edition2018、MIT，tungstenite0.30.0为edition2021、MIT OR Apache-2.0，两者均声明MSRV1.85；http1.5.0声明1.57，httparse1.10.1未声明精确MSRV。归档校验和公告审查不等于实际Rust1.91构建通过。

已只读核对候选接口/缺口：

- `tungstenite0.30.0/handshake/server.rs`公开`create_response(&http::Request<()>)`；自己先用httparse有限解析/保存多值，再构造http Request，使用该成熟函数生成101。默认库握手没有覆盖本设计全部重复头/Host/CL/TE门禁，不直接依赖无限自动握手。
- `tokio-tungstenite0.30.0/src/lib.rs:303–324,345–385`：Stream读取与Sink写分开poll；start_send的Io WouldBlock已表示消息已接受/排队并返回Ok，不能重投同一消息。`from_partially_read`能接收HTTP后已读字节，但会直接进入库内部缓冲，不能绕过本批帧头护栏。本实现选择公开`from_raw_socket`，将HTTP尾部放在护栏下方的PrefixIo，使预读与后续socket字节都先经过同一结构校验，不执行二次Upgrade。
- `tungstenite0.30.0/protocol/mod.rs:457–474`：自动Pong/Close flush遇WouldBlock记录待刷状态后仍调用read_message_frame；单一适配器可在写背压时继续poll读，不用互斥锁把两方向串住。
- `protocol/frame/mod.rs:254–287`：WriteBufferFull发生在入缓冲前并返回未接收帧；IO WouldBlock后未写完缓冲保留。`read_frame:173–191`先检声明长度上界再按该长度reserve。
- **已见缺口**：`protocol/frame/frame.rs:163–179`未拒非最短126/127长度，也未独立检64位高位。因此不能声称仅配库参数就满足规格；本批增加仅解析≤14字节帧头的结构护栏，验证最短编码、64位高位、声明长度/控制头约束，再原样交成熟引擎。跟踪剩余payload只是定位下一个头，mask/反mask、消息聚合、continuation/Close/UTF8等仍由成熟库负责；不复制完整WS状态机、不改vendor、不手写密码学。护栏含HTTP预读路径与普通读路径，不能绕开prefix。

依赖门禁先读精确官方index/归档、普通文件/sha256/yanked、完整许可及传递normal/build闭包、生产features/MSRV/公告，验证上述接口及最小原型的背压/控制/关闭/原始尾部。新增核心依赖及锁变更前须真实用户确认；若精确候选不满足范围或需超上述窄护栏的补丁，报告暂停并调整规划，不能默换版本、忽略规格、更新整图或提高MSRV。

### D5. 有限适配器与内存/调度边界

新增窄`transport::websocket`字节流，不泛化全部协议。外层仍满足AsyncRead+AsyncWrite+Unpin+Send，内部单一拥有`WebSocketStream<帧头护栏<前缀原始IO>>`及至多一个已完成Binary读取游标、一个early-data游标、关闭状态和deadline；不产生永久worker、不spawn每帧任务、不使用持锁跨await。

固定边界（本批不暴露任意增大的配置旋钮）：

| 项 | 上限/策略 |
|---|---|
| HTTP | 头16384字节/64项；target12288（可容纳1024字节base path与8192字节载荷的10923字节RawURL后缀）；HTTP后预读16384；合计预读32768 |
| early-data | 配置1..8192解码字节，关闭时0；编码先验上界及规范尾位检查 |
| WS输入帧/累计消息 | 各1048576字节；包含任意合法binary/continuation聚合；超限头先拒 |
| 引擎read buffer | 显式16384，不用库默认128KiB |
| 引擎write buffer | write_buffer_size=0、max_write_buffer_size=131072（含待发WS framing）；不得默认usize::MAX |
| 单次业务写分段 | 最多16384字节形成一个Binary；大写可短返回，调用方继续 |
| 每poll非业务事件/底层读取 | 最多32事件/帧头起点、最多65536原始字节，达到后保存状态、唤醒再Pending；空消息、Ping/Pong也消耗预算 |
| 控制待发 | 依赖库单待发自动Pong/Close和固定写缓冲，不能额外建无限控制队列 |
| 关闭等待 | 固定5000ms，仍受更早的Server强停/剩余握手期限取消 |

库可能在一次read内部持续读取空continuation而不返回Message，因此仅限制外层32事件还不够；原始帧头护栏同时执行每轮32个新帧头/65536原始字节的读预算，预算跨库内部重入保持，返回Pending并登记/唤醒，到下一外层poll才重置；已缓冲事件也计外层预算，防止空分片内循环独占执行器。输入库可能同时持帧缓冲、分片累积及完成消息，不能把1MiB消息上限误说成连接总内存只有1MiB；记录保守上界与实测最大分配。全局连接数乘以每连接上限仍可能很大，文档公开，不用UDP排队预算兜底全部WS内存。

poll_read循环只提取Binary，不把空消息/Ping/Pong当EOF；text在库完成其受限UTF8/消息处理后拒绝，不宣称完全零分配拒text。完成消息先按游标排空再取下条。poll_write先查关闭闩锁，再有限poll_ready/start_send；Ok表示本批n字节已接受，Io WouldBlock已由tokio封装为Ok不得重发。WriteBufferFull未接受，先推动flush/背压再重试，不能把原Message::Frame误认可直接重复的业务。poll_flush只推动已接受的记录，不增加业务计量。错误永久结束，不重同步继续。必须用交替Pending/1/7/17字节短写和真实下行背压测试证实，而非从Stream/Sink trait存在推导保证。

### D6. Close是会话关闭，不能伪造半关闭

首次poll_shutdown立即闩锁，后续poll_write即BrokenPipe且不计量，即便关闭还Pending。先刷已接受输出，再发送正常Close；允许读向处理对端响应，不用未到来的TCP EOF永久阻塞；完成后底层shutdown/归还IO。peer Close只将1000/无状态映射正常结束，异常码错误关闭；等待不超过5秒或更早的Server force。库poll_close本身不证明已经等到peer或底层真正结束，需要适配器独立状态与期限。

底层raw EOF未Close、半帧或TLS缺close_notify保留错误。Close到达时半分片未完成不得伪造有效字节；已完整返回的消息保留。当一向业务TCP结束且需要WS shutdown时，Close会终止承载，不能继续承诺另一向长期传输。接收VMess自身EOF块可以在WS仍Active时结束该正文读向，维持已有解析语义；但当前`body::Writer::poll_shutdown`在发终止块后还会调用底层shutdown，因此这不自动提供WS上的双向独立半关闭保证，不在本批静默改旧Writer。VLESS/Trojan没有同样的协议结束wire，不能自造。server-first及非EOF依赖双向交换必测，依赖客户端单向FIN后服务器才回包的场景列为公开不支持通用透明保证，不偷写“半关闭测试通过”。

### D7. 复用业务及统一绝对deadline

每accepted连接只创建一次`absolute=now+handshake_timeout`，依次可选TLS、Upgrade、early-data/协议认证都使用timeout_at同值；握手许可在完整协议认证后释放，连接许可到承载/子任务实际结束才释放。HTTP错误不进入路由/DNS；协议合法后仍由现有Context检查Reject先于业务DNS/拨号及成功应答。

Trojan/VLESS从现有分支窄提取泛型业务helper，VMess将“准备承载并认证”与“accepted业务分派”分开；继续复用body/udp::vless/udp::trojan/udp::xudp_body/udp::vmess，不复制codec或重放。WS的认证失败直接结束承载，不调用会等待对端Close的旧handshake错误shutdown；旧TLS接口仍保留原行为。WS是否TLS由真正完成tls.accept的分支传入，不把前置反代当可信安全事实。

为满足本批“首非法XUDP/Reject不得先产生成功响应”，仅VLESS WS使用`xudp_deferred`：完成首个合法UDP New的帧解析、逐目标路由及关联槽准入后才发送唯一VLESS `[0,0]`，首Keep/End/KeepAlive、TCP或被拒目标不会先应答。旧TLS/Vision/REALITY及VMess已有响应时序不变。共享Trojan/VLESS原生UDP与XUDP读取现区分帧边界干净EOF和半帧：第一字节前EOF正常结束，已读任何长度/元数据/payload后截断仍错误；WS底层无Close或TLS截断仍先由承载报错。该共享错误分类变更须在本批重跑旧路径回归，不能套用历史证据。

不增加全局transport管理器/后台HTTP server。所有IO/缓冲由会话持有，UDP用已有TaskTracker；drop/force后等待原join/children屏障。联合准备先验证全部新材料再运行监听，后置失败归还此前bind。只在最内层业务接口Counted，HTTP、early-data认证部分、WS/TLS封装全部排除。

### D8. 开发与集中验收分开

第1–6组是开发门禁：先精确依赖/接口确认，后配置/HTTP/帧/early-data/协议组合/生命周期，必要测试+fmt/check/严格Clippy+真实示例+同一输入证据完成才标“已实现待集中验收”。该状态允许继续gRPC/XHTTP等独立模块。

第7–9组单列官方客户端静态/运行、新能力簇三平台/精确1.91/release、最终报告。实际官方运行须本批另获许可，不沿用旧33项授权；当前不能把固定上游源码当真实互通。三协议×WS/WSS×业务类型×两种early-data按三家实际可用配置矩阵逐项记录，不支持/未运行分别保留，不能为了数字整齐预设全支持。内存/回环端使用原始HTTP/帧夹具和独立客户端；协议wire金样不复用生产parser/encoder。

## Risks / Trade-offs

- [WS与TCP关闭不等价] → 显式会话Close语义、原生协议EOF保留、特定EOF依赖应用公开限制，不以关闭报错伪称透明半关闭。
- [库默认写缓冲无限、消息过大] → 所有相关参数显式固定，声明超限头前置拒绝，累计分片上界及真实背压/分配验证。
- [成熟库缺最短长度检查] → 窄原始头结构护栏，库继续负责完整WS状态/加解mask；若需扩大为完整自研帧引擎则暂停。
- [early-data在URI/头中包含身份秘密] → 不记录完整URI/头，不自动探测、规范RawURL/固定上界，回显仅明示子协议方言；外层TLS或明确不安全选项。
- [HTTP101被当认证成功或逐层刷新期限] → 共享绝对deadline/握手槽，业务准入仍在原协议之后，负向自持DNS/目标观察。
- [WSS混淆引入新的TLS provider] → 禁库TLS/connect features，沿用局部ring，不动冻结vendor或全局provider。
- [上游容忍text/标准base64/更多HTTP变体] → 本批更严格输入策略公开；固定客户端合法Binary/RawURL仍需真实矩阵验收，不声称宽松非法输入全等价。
- [为快推进误算旧证据] → 每批输入摘要/退出码单列，失败和ignored不算通过；本规划不动REALITY/VMess/Vision旧快照。

## Migration Plan

纯加性新入口，旧JSON无需迁移；部署仍未授权。实施后只给含无效占位的回环模板，用临时测试凭据替换后验证check/启动/业务。回退配置可移除新增入口并保留旧类型，不执行实际生产切换。依赖版本/锁差异须按获准范围审查；旧release不含新能力，不自动重建/发布或归档。
