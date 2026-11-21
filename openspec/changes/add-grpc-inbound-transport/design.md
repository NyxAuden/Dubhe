## Context

动机见[proposal](proposal.md)，行为合同见[spec](specs/grpc-inbound-transport/spec.md)。这是规划，不是已实现或依赖批准；当前不改Cargo、锁、生产及测试代码。上一WS开发证据不覆盖gRPC。

### 已核实的本地接点

- `src/runtime.rs:313–403`：accept取得全局物理连接和每入口握手许可；当前连接任务外层force会直接取消整个处理future。gRPC必须单独处理连接driver及RPC排空，不能直接复制这一取消边界。
- `src/runtime.rs:611–769`：已有泛型VMess/VLESS业务helper；Trojan认证可用`read_request`，VLESS无flow可用`read_plain_request`。认证和业务可以分开，没必要复制DNS、路由及UDP内核。
- `src/forward.rs:102–120`：TCP relay用`copy_bidirectional`；单向EOF后关闭对应写端，另一向继续。`src/protocol/vmess/body.rs:536–557`的writer在正文终止块后仍shutdown底层，gRPC适配器必须只结束响应方向。
- `src/udp.rs:328–420`及`src/udp/{vmess,xudp}.rs`：UDP辅助任务由JoinSet及全局`Context.children`追踪。新RPC还需要局部结束屏障，不能在UDP子任务仍退出时归还RPC额度。现UDP函数返回Ok也不保证调用过底层shutdown，RPC拥有者必须显式完成gRPC结尾。
- `src/config.rs:483–527`和`src/telemetry.rs`：尚无RPC限制或RPC活动计数；`connections`是物理连接，不能改成逻辑流数量。

### 固定上游事实与证据等级

下表来自固定提交公开源码只读核查，不是官方客户端运行。多数新gRPC文件通过WebFetch读取，尚无本地原文归档及SHA256，实施首任务补齐可复查来源，不将旧WS来源manifest冒充新证据。

| 基线 | 已核事实及范围 |
|---|---|
| Xray v26.10.31 / `a4a3dff5b20c2faae567b742c172c7b95e75c083` | `main/distro/all/all.go`仍导入grpc，`dial.go`/`hub.go`真实注册客户端及监听，不是报错stub。现有配置有非移除弃用警告，不能写成已移除。`stream.proto`定义`Hunk { bytes data=1 }`及`MultiHunk { repeated bytes data=1 }`，Tun/TunMulti都是双向RPC。普通serviceName经PathEscape后组成服务/方法路径；另有以`/`开头、末段以`|`区分方法的自定义语法。 |
| sing-box v1.14.4 / `c005f35300ce76427dc285481ec5695f5b179cd2` | 分派真实存在；with_grpc走full实现，不带该tag走Lite实现，并非不支持。full只注册GunService.Tun/Hunk，已读选项及注册不含TunMulti。Lite同样使用Tun、无TLS时可走prior-knowledge H2；其宽松的长度/tag解析不作为本项目规则。 |
| Mihomo v1.19.33 / `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` | VLESS/VMess/Trojan出站均实际调用gun客户端。普通serviceName组成`/<name>/Tun`，未配置时路径`/GunService/Tun`，以`/`开头时作为完整路径。已核调用不含MultiHunk分支；不据此断言整个仓库不存在其他角色。 |

固定来源：[Xray注册](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/main/distro/all/all.go)、[Xray服务](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/grpc/hub.go)、[Xray命名](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/grpc/config.go)、[Xray schema](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/grpc/encoding/stream.proto)、[sing-box分派](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/transport/v2ray/grpc_lite.go)、[sing-box full](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/transport/v2raygrpc/server.go)、[sing-box Lite](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/transport/v2raygrpclite/server.go)、[Mihomo gun](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/gun/gun.go)。不复制Go模块，不从协议字段或API存在推导运行通过。

规范依据：[gRPC HTTP2协议固定版本](https://github.com/grpc/grpc/blob/cf61c7d62a1a7f43b9d2ea6488186bc14fc41a8c/doc/PROTOCOL-HTTP2.md)、[RFC9113](https://www.rfc-editor.org/rfc/rfc9113.html)、[protobuf encoding](https://protobuf.dev/programming-guides/encoding/)。gRPC五字节消息前缀不是protobuf自带的长度前缀；HTTP2多个RPC也不是Xray multiMode或代理TCP mux。

## Goals / Non-Goals

**Goals:** 将成熟H2连接和有限gRPC字节流分层；同一连接上多RPC独立认证；保留方向性结束；以明确的应用及库边界控制内存、工作量、期限和资源归属。先开发必要回环与旧路径回归，再集中验收。

**Non-Goals:** 不实现完整通用gRPC框架、HTTP网站或任意transport堆叠；不自研HPACK/Huffman、H2流状态机或protobuf解码器。其他排除项见proposal。上游配置语法不要求原样导入，本项目用明确RPC完整路径表达兼容组合。

## Decisions

### D1. 三个独立入口、显式完整RPC路径

增加`vless-grpc`、`vmess-grpc`、`trojan-grpc`，复用所属users、业务开关及成对可选`certificate/private_key`，用户数1..1024。VLESS仅flow=None、xudp默认false；VMess沿用四个默认false开关及同Server重放池；VLESS/Trojan明文即使回环也要`allow_insecure_transport:true`。不放松旧类型，不接受Vision/REALITY/early-data等混入字段。

新`grpc`为必填严格对象：

- `path`：必填单Hunk RPC完整路径，例如`/GunService/Tun`。
- `multi_path`：可选MultiHunk RPC完整路径，例如`/GunService/TunMulti`；缺省关闭，出现null、空值或与path相同均拒。
- 路径各1..1024字节ASCII，以`/`开头且含非空服务及方法部分；禁止空段、控制、空格、反斜线、query、fragment和不完整百分号编码。合法`%HH`保留原字节，精确区分大小写，不做percent-decode、斜线/点折叠、重定向或尾斜线兼容。
- 不同时提供隐式serviceName默认值、mode探测和任意metadata配置。单/多消息模式由命中的两个不同路径确定；未知模式/字段拒绝。文档给出三家普通命名映射；Xray自定义命名应先按固定客户端规则得到最终路径，再配置这里，不能声称所有上游原始字符串直接等价。

TLS只提供`h2` ALPN且必须实际协商到h2；None/http1.1/其他协议拒绝。明文只接受HTTP2 prior-knowledge，不支持HTTP1 Upgrade。VMess只信本次真实TLS事实，不信`:scheme`、Forwarded或入口在回环。

理由：完整路径消除三家serviceName转义/默认差异，仍可表达已核单/多方法，不必引入一套猜测兼容的服务名语言。给旧入口添加通用transport及把TLS变可选会改变既有契约，故不采用。

### D2. 直接h2与prost，不引入默认tonic/hyper框架

规划首选`h2 =0.4.20`（关闭默认features）和`prost =0.14.4`（default=false，仅`derive,std`），复用已锁`http =1.5.0`和`bytes =1.12.1`；bytes可由prost公开重导出，是否需要根直接边以实际最小API为准。tokio-util所需codec/io特性须作为真实增量审查，不能假称都已开启。仅需两种bytes消息，不引入prost-types、protoc、prost-build、tonic默认router/channel/TLS、hyper或第二锁。标准TLS仍本项目局部ring，不动两个冻结vendor。

**候选未批准。** 本地h2缓存index只到0.4.13、prost只到0.14.3，不足以证明当前候选存在、可离线构建或安全；公开docs.rs已核h2 0.4.20及prost 0.14.4接口。实施先查精确官方index/归档、普通文件和SHA256/yanked、完整许可、所有新增normal/build闭包、features、MSRV和完整公告范围，保存旧锁快照及最小预期diff。门禁完成后新增核心依赖/锁增量另取真实确认；不得整图升级或提高1.91。

已核接口与缺口：

- [h2 server](https://docs.rs/h2/0.4.20/src/h2/server.rs.html)：Builder有窗口、帧、头表/列表、并发、每流发送阈值、reset保留/错误限额、data_frame_budget。handshake先flush本端SETTINGS、读完24字节客户端preface后Ready，**未等首客户端SETTINGS或ACK**。`poll_accept`驱动连接后交付完整请求，`poll_closed`可继续驱动所有流。
- [h2 share](https://docs.rs/h2/0.4.20/src/h2/share.rs.html)：reserve/poll_capacity、send_data/send_trailers/reset，RecvStream的数据/trailers及显式release_capacity。max_send_buffer_size只是capacity阈值，不阻止不守约的任意send_data，应用必须先取得额度。
- [h2 stream](https://docs.rs/h2/0.4.20/src/h2/proto/streams/stream.rs.html)及[counts](https://docs.rs/h2/0.4.20/src/h2/proto/streams/counts.rs.html)：并发数释放要求协议已闭且pending_send及buffered_send_data均空；仅把END_STREAM入队不会马上释放名额。这不是物理socket flush证明。
- [h2 framing](https://docs.rs/h2/0.4.20/src/h2/codec/framed_read.rs.html)：没有公开partial HEADERS观察、逐头块deadline或精确压缩块硬上限；内部CONTINUATION限制由头列表/帧限额推导，最低仍可有5个非最终CONTINUATION，不是独立旋钮。data_frame_budget不覆盖所有控制帧协作调度。D3增加窄护栏，不能假称库自带。
- [prost encoding](https://docs.rs/prost/0.14.4/src/prost/encoding.rs.html)：公开但doc-hidden的decode_key/skip_field/DecodeContext可用于有限顶层字段预扫描，随后仍用派生Message解码。默认递归预算100，不启用no-recursion-limit；singular bytes后值覆盖，repeated bytes追加。pin精确版本并为这些接口做可执行原型，不能把内部公开API当稳定跨版本承诺。

替代方案：tonic默认栈闭包较大并隐藏部分资源接点；直接把DATA当字节流会漏掉gRPC及protobuf合同；自写protobuf/HPACK违反成熟实现边界。若精确归档或原型无法满足D3–D8，暂停并说明差异，不静默换库、删规格或复制上游模块。

### D3. 有限H2配置与9字节I/O护栏

使用`h2::server`完成H2帧/HPACK/流状态/流控。新护栏放在h2下、真实TLS明文IO上，只识别preface及9字节帧头、计数payload剩余字节、头块和期限；不解码HPACK、重写帧、实现窗口或替代成熟状态机。无额外永久传输worker。

| 边界 | 本批取值及归属 |
|---|---|
| 收帧最大payload | 16384，Builder与护栏一致；超限声明在payload分配前拒 |
| 解压头列表/HPACK动态表 | 8192 / 4096；列表按name/value+32计费 |
| 完整请求应用头项 | 最多64，完成解码后再查，不冒称第65项解码前零分配 |
| 压缩头块 | HEADERS及后继CONTINUATION的总payload最多16384字节，最多8帧含首/末；含padding/priority也计入 |
| stream接收窗/连接接收窗 | 各65535；不自动扩成多MiB |
| H2并发stream | `limits.max_grpc_streams_per_connection`，默认16，合法1..128，含半关闭和尚在库内排队的结束流 |
| 每流发送阈值 | 65536；应用取得capacity后才有限send_data，不能依赖该参数替任意send_data硬拒绝 |
| reset状态 | max_concurrent_reset_streams=32、max_pending_accept_reset_streams=16、max_local_error_reset_streams=Some(64)、保留1秒 |
| 小DATA预算 | 显式data_frame_budget=32768；不称控制帧总预算 |
| 每次driver poll | IO护栏累计最多32个新帧头及65536原始字节；读写均有限，跨h2内部重入保留预算 |
| 控制频率 | 每连接固定1秒桶、最多256个非DATA/非HEADERS/非CONTINUATION控制帧，超出有限终止；这是额外安全策略，不声称无限控制流都兼容 |
| 头/初始阶段期限 | 见D7，均为绝对期限，不按字节刷新 |

护栏先完整保存并检查9字节窄头，再原样交库；payload流式转交，不另按声明缓存。preface仍由h2校验，护栏只跟踪其24字节位置。初始peer帧须是非ACK SETTINGS，结构交h2核；头块必须在同一stream连续，非法交错/超界可以提前终止连接。不存在已完成headers绕护栏的partially-read捷径。

每个driver外层poll只重置一次共享IO预算；库内部反复poll_read不得重置。达到预算保存游标、登记并自唤醒后Pending，避免PING/SETTINGS/空帧连续就绪独占执行器。库已缓冲数据另受固定读取交付和外层最多32个accept/完成事件约束。不得用每个IO方法调用重置预算冒充协作。

护栏观察每个不完整帧头的首字节时刻；判断为HEADERS后，将该时刻延续到完整END_HEADERS，CONTINUATION不能刷新。driver持有并独立poll最近绝对计时器，即使输出阻塞也不能停止计时。完整首HEADERS的开始时间通过有界stream-id记录移交RPC认证；记录上限为配置stream上限加reset保留上限，不能按任意ID建无界map，溢出有限失败。非头DATA payload本身不套逐头块期限，避免把正常流控等待误称慢头。

库的8192头列表上限不是全解压瞬态硬ceil：已读源码会标oversize、停止保留后继续同步HPACK，到超过4倍才中止；单字段先解码也有瞬态分配。因此用16384压缩块/8帧/4096表/库超限策略联合建立保守内存模型，而非另造HPACK字段计数器。应用64项是额外语义门禁。

### D4. 严格RPC与gRPC/protobuf字节流

仅POST、HTTP2、命中配置完整路径、合法`:scheme`/可选authority、单值`content-type: application/grpc`或`application/grpc+proto`进入RPC；不接受query、JSON或通用自定义编解码。`:scheme`允许http或https，但不据此判断传输是否加密，也不要求明文必须标http：固定sing-box Lite及Mihomo gun构造的URL即使底层明文仍为https。`te`若出现须单值trailers；缺省也接受，这是固定代理客户端兼容例外，不是通用gRPC规范规则——固定Mihomo gun只显式写Content-Type/User-Agent，尚未证明其HTTP fork自动补TE，不能先强制TE再宣称该客户端组合可用。固定sing-box Lite显式写TE: trailers。成熟h2检查伪头顺序、重复和禁用的连接字段；应用再拒Content-Length、歧义关键头及非预期扩展。相关请求构造来源：[Mihomo gun](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/gun/gun.go)、[sing-box Lite client](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/transport/v2raygrpclite/client.go)。

无消息压缩：grpc-encoding缺省或identity可接受，其他编码以固定UNIMPLEMENTED状态失败；每条消息压缩flag必须0。grpc-accept-encoding可作为对端能力忽略，响应不压缩。普通有限metadata不转发、不授权、不记录值；未知grpc保留语义不悄悄解释。请求trailers本批不支持，非空trailers有限失败，不把它们当业务或认证。所有这些都是公开输入策略，不声称上游宽松输入全部等价。

grpc-timeout接受最多8位数字加规范单位H/M/S/m/u/n，以checked算术转为绝对RPC期限；0表示立即到期。它从首请求HEADERS开始生效，不能延长服务端认证期限，合法短期限可提前取消整个RPC；省略不附加业务总期限。错误格式拒绝。长连接既有业务不受新RPC认证期限牵连。

适配器实现AsyncRead/AsyncWrite，有两条独立方向、唯一读/写游标：

1. 读取5字节gRPC前缀，flag=0、BE32长度≤1048576，先检查声明后才有限分配。DATA边界与消息无关，保留一份当前DATA游标、一个有限消息累积和一个解码消息游标。
2. 对完整消息用prost的key/skip做有限顶层扫描：最多1024次字段出现、MultiHunk中字段1最多256项；group等未知wire按成熟skip和递归限额处理，不自写varint。随后Message::decode，single的重复bytes按末值规则，multi按出现顺序拼接所有data，空项跳过。空消息不表示EOF。
3. 至多持一条完整解码消息；不提前拉取下一条。protobuf field和代理认证/UDP包都可跨DATA或gRPC消息；传给协议的是原始顺序字节，不让H2消息边界改UDP边界。
4. 单次业务write最多16384字节，编码成所属Hunk或仅一个data项的MultiHunk，附标准五字节前缀。写游标先排已接受块，再接受下一块；reserve_capacity目标不是累加。仅在取得足够capacity后把一段移交send_data，不任意累积。
5. 接收容量只在字节进入有限消息累积/被实际消费或明确丢弃时归还；已取得但未消费的DATA不提前release。累积满了不再读，不能边无限归还边增长队列。每poll最多32条空/完成消息及有限IO推进；一次有限1MiB解码仍有自己的有界CPU成本，不谎称所有解码都仅65536步。

固定响应：合法RPC可先返回HTTP200及application/grpc头，这只是承载就绪。未知路径/方法、类型、资源及认证失败仅固定小状态/无敏感说明；合法gRPC错误用非零grpc-status（如UNAUTHENTICATED、RESOURCE_EXHAUSTED、INVALID_ARGUMENT），不发代理成功字节。帧损坏、RST或连接错误可直接reset/关闭，不强求在坏连接写成功trailers。错误计数每次规定拒绝只计一次，Context路由Reject不能重复加。

理由：multi消息仍是一个有序代理字节流，不为每个data项另认证或另建TCP；完整有限Message解码保留成熟protobuf兼容语义，避免照抄某些客户端忽略外层长度/tag的宽松代码。最大消息/字段策略是本项目容量限制，不是protobuf通用规范上限。

### D5. 连接driver、RPC许可及真实结束屏障

每物理TCP仍占现全局max_connections及Connection gauge，新增`limits.max_grpc_streams`默认256（全Server、所有gRPC入口共享，非零且≤Semaphore/u32允许范围）。每连接应用RPC也受max_grpc_streams_per_connection；这个字段同时设置H2 MAX_CONCURRENT_STREAMS，不能只限制spawn而让库无界排队。新增`grpc_streams` gauge表示已准入、尚未真正回收的RPC，不改变connections/tcp_flows/udp_associations意义。

每入口连接准备握手池仍为现max_handshakes，另建同容量的RPC认证池，二者独立，防止大量待认证RPC阻断物理连接初始化。RPC可共享物理身份安全事实，不能共享代理认证结论。完整headers交付后以try_acquire取得全局RPC、本连接RPC和每入口RPC握手额度，失败不spawn等待任务，有限拒绝。头未完成时由H2/护栏的连接资源及期限负责，不声称尚无完整headers的对象已取得RPC许可。

一条连接只有一个拥有h2::Connection的driver；有限RPC任务各持RecvStream/SendStream及代理状态。driver持续poll_accept/poll_closed，公平回收JoinSet和处理stop/force/计时，不在等待一个慢RPC结束时停止驱动连接。无每帧spawn、无持锁跨await、无单锁串住上下行。认证结果不能覆盖同连接另一RPC；VMess仍使用同Server预备身份及重放池，跨直承载/TLS/WS/gRPC共享原策略。

为gRPC引入窄任务scope：RPC拥有局部TaskTracker、取消信号及持有RPC许可/gauge的共享lease；UDP reader/mapping同时纳入局部scope与现全局children。旧公开UDP入口继续用原默认scope，新入口通过窄内部scoped接点复用相同实现，不能复制UDP内核或克隆独立DNS/预算。scope/lease覆盖所有派生子任务，避免父future取消后许可先于子任务归还。UDP关联许可同样须保持到其映射/reader实际退出。

RPC工作future返回或被取消后，先取消所属子任务、close/wait局部scope并确认JoinSet结束，再归还RPC/关联资源。正常完成还要执行D6的响应结尾。gRPC连接分支不沿用外层force直接drop整个driver的方式：force交driver取消工作并join有限RPC包装任务；保留清理包装层，不以abort整个包装层代替局部屏障。异常退出时共享lease仍随真实子任务持有，Server最终全局children.close/wait兜底实际结束，而不是计时后宣布全部归还。

### D6. 方向性结束、flush与最终状态

- **请求方向**：只有完整gRPC消息边界的请求END_STREAM、且没有非法trailers时，AsyncRead返回EOF。半前缀/半消息/半protobuf、RST、连接丢失、TLS缺close_notify返回错误。VLESS/Trojan据此让relay向目标发真实TCP FIN，仍可接收目标迟后响应。
- **响应方向**：首次poll_shutdown即闩锁拒绝后续write；先把已接受块交h2发送队列，再send_trailers(grpc-status:0)，仅结束本响应方向。poll_shutdown成功不代表对端收讫或socket物理flush，更不修改请求EOF状态。重复shutdown幂等，Pending后late写失败且零额外计量。
- **flush**：仅表示适配器已接受的块已按capacity移交成熟h2队列；库没有公开每stream物理flush通知，文档明确语义，不伪造flush ack。连接driver继续驱动实际输出；受控短写/真实背压验证已接受字节恰一次。
- **句柄生命周期**：h2在发送trailers后可以继续读取请求；但最后所有handle在请求仍活动时drop会隐式RST（服务端已关发送时可为NO_ERROR，否则CANCEL）。所以poll_shutdown不能直接drop整个RPC，工作仍有读方向时必须保留并继续poll。
- **VMess**：正文authenticated EOF可先结束代理读向；writer最终底层shutdown只结束gRPC响应。若业务已结束而请求END_STREAM尚未来到，RPC结尾拥有者保留接收句柄，有限排空后续封装/允许的空消息，不将额外正文当新会话；非预期额外正文错误。该尾部等待固定最多5000ms或更早业务期限/force，届时显式取消，不能先宣称完整双向干净结束。
- **UDP与XUDP**：复用各自帧边界/End/idle规则；工作函数Ok返回后仍由RPC拥有者完成正常响应trailers，错误则非零状态或reset。请求EOF不会凭空承诺无限等待所有UDP目标回包；保持原关联结束契约，并公开该区别。
- **非零状态**：认证、资源、解码或业务错误发生前若未正常结束响应，不得发送grpc-status:0。已成功结束一个方向后另方向才出错，不能倒改已发状态；RPC整体仍归为异常/取消，不将单方向状态冒充全会话成功。

必须用三个独立协议对端实证目标等待FIN后才回包、目标先FIN后请求继续、VMess终止块、同时半关闭、RST及真实TLS截断；不能只根据上面源码状态机勾通过。对端本身若CloseSend/Close直接cancel等有局限，在官方矩阵逐组合记录，不缩减服务端合同。

### D7. 绝对期限、GOAWAY与停机

物理准备从accept时刻t0起只给一个`handshake_timeout_ms`：TLS、服务端初始SETTINGS输出、客户端preface及首合法非ACK SETTINGS的接收/解析共享绝对期限。h2 handshake Ready仅preface边界；driver继续驱动，直到首peer SETTINGS已完整交库、本端对应SETTINGS ACK完整交给下层IO且同轮库驱动无错误，才释放物理握手许可。护栏对出站也只跟踪9字节帧头/剩余长度，识别该ACK完成，不生成ACK或解释SETTINGS值。它不是等客户端ACK本端设置，更不能刷新t0期限。若客户端在此前pipeline合法RPC，由同driver继续驱动但先有界持有/暂不进入协议业务；相关请求仍占库流限额且保留原tH期限。已核[settings源码](https://docs.rs/h2/0.4.20/src/h2/proto/settings.rs.html)会对peer设置生成ACK，部分应用可能在ACK入队后报错，故不能仅看入队或一个首帧计数就宣称准备成功。精确归档原型须验证错误传播及该观察顺序，不把仅构造Future算完成。

每个新请求的首HEADERS起点tH到完整认证共享一个`tH+handshake_timeout_ms`；不从accept交付请求、取得许可、gRPC首消息或内层协议每层重新计时。若在物理准备阶段开始，尚未完成的连接准备也仍受t0期限。后续任意HEADERS/CONTINUATION块都有自己的绝对组装期限，活动连接不能靠首RPC已认证绕过慢头保护。不完整9字节帧头同样有限；库控制及已有业务仍由driver处理。命中grpc-timeout时采用更早期限，DNS/拨号继续原有限策略并受RPC取消传播。

stop后立即停监听、禁止新应用RPC准入并调用graceful_shutdown，持续poll库的GOAWAY(MAX)+PING+最终last-id流程；h2允许约一RTT内在途请求被看到，不将其再spawn为新业务。已有RPC在原Server shutdown_timeout_ms内排空。期限到force取消剩余工作、关闭IO、join RPC局部scope及driver，最后全局children屏障；对端不回PING不能无限拖停机。GOAWAY不是RST所有已有流，last-id含义交成熟库处理，不自造“最后完成流”算法。

### D8. 内存、计量与必要验证

输入每RPC至多一个≤1MiB wire消息、prost解码所有权及当前DATA/游标；bytes字段尽量使用Bytes避免无谓深拷贝，但必须记录实际decode分配而不是假定零拷贝。每连接接收窗65535约束未归还DATA，不约束已复制并归还进有限消息的内存；全局RPC额度控制这些应用缓冲。输出每RPC一个≤16384业务块及有限编码，h2按capacity保持每流≤65536待发数据。

不能只用活动RPC gauge估算全部H2内存：工作返回后尚排队的结束流仍占库并发数；每连接配置流上限、reset保留数、固定本地响应头/trailers及有限codec写入共同约束尾部状态。库没有公开连接级总发送硬ceil或每流物理flush通知，模型必须纳入codec、HPACK及reset状态，不把max_send_buffer_size叫进程硬内存限额。默认max_connections乘这些上限可能很大，文档公开容量乘积与调整建议，不拿UDP字节预算或某次RSS观测兜底。

为精确h2/prost做小型可执行原型：capacity/分块、release_capacity、send_trailers后继续收、drop/reset、结束流待发仍计并发、preface/首SETTINGS边界、真实写阻塞、GOAWAY和9字节护栏调度。另做隔离单测试分配观测，输入夹具覆盖1MiB单/多消息、256空项、未知字段、HPACK超限、控制帧及关闭流待发。公开区分申请字节/live峰值与OS/TLS/RSS；固定测试阈值不是任意allocator上的严格证明。

业务计量仍放在协议正文/目标接口：只实际Ok(n)或完整成功业务数据报，不含H2/gRPC/protobuf/TLS、认证及响应。入队接受不是远端收讫，也不是财务计费。原三协议XUDP延迟成功响应、逐包Reject、身份重放、security/options、首载荷/server-first、来源及包边界不能被承载层成功掩盖。

测试分两层：必要新配置/护栏/codec/库原型、独立protobuf金样及H2对端、三协议明文/真实TLS和资源/关闭/CLI，以及受影响旧路径、本地fmt/locked check/严格Clippy；昂贵官方新矩阵、平台全量、精确1.91、release及最终报告后置另授权。每次保存真实命令、退出码、失败历史、输入摘要；failed/skipped/ignored不作passed。

## Risks / Trade-offs

- [gRPC处于Xray非移除弃用状态] → 明确固定提交仍真实可用，后续跟进实际移除，不把历史multiMode永久承诺成不淘汰功能。
- [h2慢头/控制预算缺口] → 用9字节窄护栏和独立deadline补足；保持HPACK及状态机由成熟库负责，恶意头块终止整个连接是有限防护，不等同单RPC认证错误应隔离。
- [HPACK解压瞬态与h2内部队列不等于配置单值] → 固定压缩块、表、库并发/reset和本地小响应，核源码及分配/背压原型；不能验证界限时停在门禁，不凭trait乐观勾选。
- [protobuf内部公开扫描API可能变化] → 精确pin与原型、复审升级；不默换自研解析器。
- [RPC结束丢handle诱发RST、许可先归还] → 方向状态分离、显式结尾、局部scope/共享lease、真实join屏障与端口/额度复用测试。
- [多RPC共享连接发生连接级错误] → 认证/业务拒绝和RST局限于流；非法H2/HPACK、头块超限及连接断开允许影响整连接，不能把二者混为零隔离缺陷或完全隔离承诺。
- [自有对端可能共享同类误解] → 手工protobuf金样与成熟H2对端分层，保留负向；官方三家组合只有另获准实际运行后才记兼容通过。

## Migration Plan

纯加性新类型/限制/统计，不自动改旧配置、协议默认值、监听或已验收契约；旧Limits缺省对象仍接受，新增统计字段单独说明。依赖门禁和实际变更确认后才实施，开发完成状态仅“已实现待集中验收”。回退时使用旧入口配置而非在新入口静默降级；没有本批生产部署动作，不操作Git、归档、容器、系统网络或发布。
