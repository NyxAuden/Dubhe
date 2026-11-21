## Context

动机见proposal.md，外部契约见specs/vless-vision-inbound/spec.md。本批是连续实现路线中的一个模块：必要开发检查先做，昂贵验收留到能力簇收尾，未验收任务不勾选、不阻断下一模块规划。

已检查本地代码：

- `src/config.rs`的`VlessUser`只有name/uuid，未知字段拒绝，现有测试会拒绝flow；UUID采用固定长度全用户比较与脱敏包装。
- `src/protocol/vless.rs`认证后要求addons长度0；`Accepted`只包含Single或Xudp，运行层不知道用户flow。XUDP命令3没有基础目标字段。
- `src/runtime.rs:378`用普通TlsAcceptor建立VLESS TLS，随后普通AsyncRead解析，再按TCP/UDP分派。`tls::load`显式ring、允许TLS1.2/1.3。
- `forward::relay`以Counted包住业务流，copy_bidirectional保留半关闭；`udp::xudp::serve`自己先写一次VLESS响应，再split为带有界通道的reader/writer。
- `tokio-rustls 0.26.6`的普通poll_read会反复poll_fill_buf，common::poll_fill_buf也会在wants_read允许时继续输入；其TLS shutdown发送close_notify。简单get_mut/into_inner无法撤回已被rustls处理的原始Direct字节。
- rustls 0.23.46提供ServerConnection::read_tls/process_new_packets/write_tls/reader/writer、IoState及set_buffer_limit。其记录上限为16384+2048字节载荷，握手重组有65535字节上限；这些可用于手动有界驱动，不用私有字段或密码后端变更。
- 参考测试已有固定版本/官方归档摘要、普通文件和运行前SHA-256门禁、最小环境、回环、0600配置、RAII进程回收。33个旧入口保留，不把它们的历史通过当新Vision结果。

基础研究与固定引用见`docs/reality-vision-feasibility.md`。Xray基线为v26.10.31 / `a4a3dff5b20c2faae567b742c172c7b95e75c083`，Mihomo为v1.19.33 / `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`，sing-box为v1.14.4 / `c005f35300ce76427dc285481ec5695f5b179cd2`。其实际Vision依赖分别还包括Mihomo使用的metacubex/sing-vmess v0.2.5 / `9b7fdbf462a5cf6366628631ef426c1a91f5df82`和sing-box使用的sing-vmess / `a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017`，不能用不相关协议依赖的提交代替。本轮追加只读关键源码核对，不是新互通结果或完整上游安全审计。参考实现只用于理解协议，不复制MPL/GPL实现代码，所需密码学和随机数仍来自现有成熟依赖。

关键固定源码证据：

- [Xray Vision writer、完整记录判定及padding，L326–620](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/proxy.go#L326-L620)与[内层TLS识别，L623–674](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/proxy.go#L623-L674)。
- [Xray flow/命令准入，L538–615](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/inbound/inbound.go#L538-L615)与[客户端UDP/443策略，L240–307](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/outbound/outbound.go#L240-L307)。
- [Mihomo Vision reader/writer，L63–242](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/vless/vision/conn.go#L63-L242)。
- [sing-vmess Vision reader/writer，L106–251](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/vless/vision.go#L106-L251)与[原生UDP不编码flow，L226–272](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/vless/protocol.go#L226-L272)。

三家初始UUID探测和异常头行为并不一致。本项目选择的一次性透明分支、严格增量头与EOF规则是明确的防御契约，不声称逐字复刻三家。Xray后续半头可能提前切换属于源码路径推导，未运行复现，不作为已确认上游缺陷。

## Goals / Non-Goals

**Goals:** 在不改动旧无flow行为的前提下增加可验证的Vision服务端；把TLS记录所有权、应用封装和资源生命周期分离，但不引入任意传输插件框架。数据边界与认证必须先被独立测试证明，再扩展其他协议。

**Non-Goals:** 本批不接入REALITY握手、TLS fork、uTLS、VLESS Encryption、平台splice、通用TCP mux或新传输包装。首版用户态复制不是不实现Direct；不复制实验性客户端的GPL模块或按上游私有内存布局取缓冲。当前规划不运行官方客户端或恢复容器。

## Decisions

### 1. 用户flow和已认证请求模式分离

为`VlessUser`增加有穷flow类型：缺省/空字符串表示None，另有`xtls-rprx-vision`；null和其他值拒绝，Debug仍脱敏UUID。入口级flow保持未知字段，避免与用户模式双重定义。混合用户保留同一证书和TLS1.2/1.3监听；是否允许Vision由握手后的实际TLS版本决定，而不是看到配置里有Vision用户就全局禁TLS1.2。

扩展握手内部返回值，携带用户标识、已验证UUID字节、命令及请求body模式：Plain或Vision。公开基础入口保留空flow行为的包装，不让普通调用者因新增选项默认开启Vision。先完成UUID比较，再读取最多255字节addons；小型专用protobuf子集解析器只接受已支持flow字段，检查有限varint、边界、重复和未知字段，不为一个字符串引入完整protobuf runtime。请求flow不进入普通日志。

固定基线的准入矩阵：

| 已认证用户 | 请求flow | 命令 | 外层TLS | body路径 |
|---|---|---|---|---|
| 无flow | 空 | 1/2/显式3 | 1.2或1.3 | 旧普通TLS；3限UDP-only |
| 无flow | Vision | 任意 | 任意 | 拒绝 |
| Vision | Vision | 1 | 必须1.3 | Vision TCP |
| Vision | Vision | 显式3 | 必须1.3 | Vision解包后的UDP-only XUDP |
| Vision | Vision | 2 | 任意 | 拒绝 |
| Vision | 空 | 1 | 任意 | 拒绝 |
| Vision | 空 | 2/显式3 | 1.2或1.3 | 普通TLS UDP/XUDP例外，不挂Vision |

不得把用户flow与请求flow做无条件相等比较。Xray请求空flow命令3会利用首body字节判断XUDP；本内核已有严格UDP-only逐帧解析，继续只在明确启用xudp后接受，不预读猜测后放开TCP mux。错误请求不得先连接目标或返回成功。

### 2. 选择手动ServerConnection单记录驱动

为包含Vision用户的VLESS监听从TCP accept起使用专用受控TLS承载，连接认证后无flow请求仍可走其普通模式；纯无flow监听继续沿用当前TlsAcceptor路径，Trojan不受影响。共享证书加载/配置准备，只把接受连接及IO驱动拆开，不复制证书校验或全局安装provider。

承载唯一拥有原始IO、ServerConnection、输入记录进度、待写TLS密文、方向状态及错误闩锁。用标准AsyncRead/AsyncWrite对外提供已解包业务字节，但内部不先split socket、不另起无限worker。poll方法不能在锁内await，若外部tokio::io::split，仍由一个承载对象序列化底层访问。

读方向流程：

1. 先交付已解密但未消费的明文或Vision解包结果，未判定前不输入下一条record。
2. 读取恰好5字节TLS头，验证长度，随后只读该record剩余；既不使用无界read_to_end，也不允许read跨越当前记录。边界后数据留在内核socket或明确拥有的有界尾部，不交给rustls。
3. 通过只包含这条record的同步切片调用read_tls/process_new_packets，逐步排出必要TLS控制输出，取得解密结果后立即推进Vision状态机。
4. 只有明确仍需要外层TLS时才输入下一条record。收到完整Direct块之后先排完当前明文尾部，再切原始IO。

写方向以rustls writer接受应用字节、有限write_tls输出及非阻塞底层写入组成；保持Pending/部分写的游标。set_buffer_limit(Some(65536))约束应用写入所生成的TLS缓存，不把它误称全部RSS上限；只有上一待写块可排空/保持有界时才能接受下一业务块。握手消息仍受rustls自身限制、固定记录缓冲及握手期限限制。每次poll工作量有限，只有确有待处理进度才自唤醒。

备选“record包装＋tokio-rustls AsyncBufRead”看似改动较小，但其内部循环、控制消息、关闭和写方向读副作用仍需额外门禁，长期所有权更隐晦；本批不采用。Unbuffered API虽暴露更多输入所有权，但借用及输出状态更复杂；目前公共buffered ServerConnection加单record调度已可表达需要，不预先换TLS依赖。先写可证伪的边界实验，若公共API路径失败，保留失败用例并报告，不增加私有字段unsafe或吞字节补救。

### 3. Vision读写方向独立且增量解析

协议codec不依赖网络read边界：初始最多缓存16字节以比较用户UUID；完整不匹配时把已读字节原样交回，并进入无padding外层TLS路径。完整匹配后等待5字节块头，随后流式交付content、定额跳过padding，只有二者均耗尽才提交命令。上游单buffer首次识别及partial头实现细节不复制；本内核在任意分片下保持同一语义。

```text
ProbePrefix --> Header --> Content --> Padding --0--> Header
     |                                     |--1--> PlainTls
     v                                     |--2--> Raw
  PlainTls
```

初始零输入、完整Continue块后的块边界及End/Direct后无进行中字段时EOF可正常结束该读方向；只收到匹配UUID前缀的一部分且EOF、完整UUID后缺头、头/内容/padding不全都报截断，不能误当完整业务。遇第一个不匹配字节即可明确透明分支，不必等满16字节；保留所有已读字节，之后不重新扫描UUID。5字节头未完整前禁止根据单个command字节提前End/Direct；u16内容/填充长度用剩余计数流式处理，不按peer长度一次分配两个65535缓冲。未知command使状态永久失败；End/Direct后不再把后续业务字节解释为Vision控制头。

下行有独立UUID首块、content/padding游标及命令提交；有必要的有限共享内层TLS识别状态，但不因读方向已Raw便自动把写方向也改Raw。VLESS响应头在Vision封装前经外层TLS写一次，首Vision块从响应body开始。

### 4. Direct提交是有顺序的事务

读方向完整Direct后：交付该块内容→消费全部padding→排出本次解密结果尚余的明文→交付承载自持的原始尾部→读原始socket；不从rustls私有密文缓冲寻找遗失数据，因为驱动从未将下一record喂进去。

写方向：生成最终Direct块→完成该块的外层TLS加密输出和必要flush→确保ServerConnection及自持密文输出已排空→提交Raw→仅从原始IO发送后续业务。Pending/部分写不重复提交；失败闩锁，不能把下一业务块写到错误的层。

Direct前处理并排空ticket/KeyUpdate/alert等控制输出；一方向Raw不影响另一方向读取合法外层TLS记录，但如果之后处理的TLS控制消息要求在已Raw写方向生成外层记录，不能混入原始业务。该非法时序有限时终止并释放资源，明确测试，而不是默默丢掉业务或切回TLS。初始配置不额外启用0-RTT/自发KeyUpdate；对端合法控制在Direct前仍应正常处理，不通过禁掉所有控制掩盖驱动缺口。

关闭按写方向状态：PlainTls/Padding阶段按普通TLS结束及底层半关闭；Raw阶段仅关闭原始写半端，不发送外层close_notify。EOF保持另一方向排空，force取消经统一运行器回收。读方向Raw后不再调用任何可能隐含TLS读的默认TlsStream方法。

### 5. 下行封装与有限内层TLS识别

独立解析内层TLS记录头与握手元数据，只决定是否能Direct，不解密内层业务。跨read/write分片重组必要的记录/握手头；缓存/检查预算按记录及字节量约束，不能按一次系统read等同一个包。默认固定最多检查8条TLS记录及65536字节，预算耗尽选择End继续外层TLS；该选择只影响优化，不影响业务正确性。

只在解析ServerHello的supported_versions确认内层TLS1.3、所选套件为0x1301/0x1302/0x1303/0x1304且ApplicationData记录完整边界时选择发送Direct；0x1305及未知套件不启用。TLS1.2/非TLS/不允许或预算内未能识别选End。首批数据仍可Continue以等待有限识别，不能因为本批不做splice而一律End从而避开真正Direct路径。完整记录判定不能绑定一次poll_write：有界跟踪跨写入记录进度，在完成的ApplicationData记录边界提交最终块。上述条件仅用于本端发送策略；收到合法Direct必须按wire语义切换，不以本端识别状态、套件或Direct块内容是否恰由完整TLS记录组成增加拒绝条件。Mihomo/sing-vmess与固定Xray的发送策略在此并不完全一致。

首版写端采用总块不超过8192字节的保守策略：每块正文最多8171字节，统一预留16字节UUID和5字节头，大内容有界拆分。已识别内层TLS且正文小于900字节时，padding取安全均匀随机数U[0,499]+900-content_len，否则取U[0,255]，再限于8192-21-content_len；因此padding最多1399字节，不能误写为900。首次空正文Continue也允许长padding。该分布和8192是固定Xray的发送策略参考，不是wire接收上限，不承诺统计外观完全相同。解析端接受完整u16范围并流式交付/跳过，不分配与peer长度成倍增长的缓冲。End/Direct只提交在最终相关块，使用固定长度队列；不要求复制Xray寻找最后17 03 03位置的buffer拆分启发式。随机数通过现有ring provider安全接口及无偏有界取样取得，不自行实现PRNG或密码算法。

### 6. 共享转发及UDP接入不重复响应

TCP在握手、flow/TLS版本和目标检查后继续使用Context::connect，随后写一次VLESS响应、启用Vision body适配，再进入forward::relay。Counted只看解包业务，不计UUID、padding或TLS头；“成功”沿用现有明文写接口返回Ok(n)语义，不声称远端已确认，也不对已成功接受的字节在后续网络故障时倒扣。新的缓冲适配不能在Pending重试时对同一载荷重复返回Ok或计数。

XUDP复用现有serve和Association，不另起会话池。将其“发送VLESS响应”与“已应答body循环”拆成私有适配：原入口保持serve写响应，Vision运行层先写外层VLESS响应，再把Vision body交给只处理XUDP body的入口，防止响应头重复或错误放入padding内。所有命令3仍逐帧只接受UDP网络；已有GlobalID不续接、会话代次、来源、预算和回收语义不变。原生UDP空flow例外不经过Vision包装。

客户端端口443策略与服务端路由分开：Xray默认Vision UDP/443可能本地拒绝，测试要辨认包是否到达内核。服务端不增加全局443禁令；需要显式客户端策略的场景只在能力簇验收时受控测试。

### 7. 开发检查先行，完整验收集中

实施任务分两段，前段是推进下一模块所需门禁，后段保留集中验收任务：

- 开发段：fmt/check、局部严格Clippy、专用wire/parser与record驱动实验、真实回环独立测试端、flow/UUID/TLS版本拒绝、半帧/背压/强停、受影响旧VLESS/XUDP回归。先让record门禁通过再绑定运行入口，避免把无法切换的TLS流接入生产路径。
- 集中段：固定三家Vision TCP的非TLS/内层TLS1.2/内层TLS1.3与Direct证据，客户端分别可用的原生UDP/XUDP、UUID/flow/TLS版本/信任负向，同一新构建旧33项官方矩阵，macOS/Linux双架构全量、精确MSRV、release/示例及构建/许可报告。

普通ignored不计通过；新模块可在本批集中段尚未运行时继续实施，但状态只到“已实现待验收”。每份证据关联自己的源码/测试/客户端/工具链摘要，不把较早209/33项结果继承到新代码。

官方矩阵保留原固定三家版本，实际启动另行取得新范围批准。容器当前不可用只阻塞Linux最终段：先只读核查实例/端点/卷，恢复需要的启动操作按实际环境另行处理，不删现有资源、不切全局context。若旧QEMU仍需GCC局部VA环境，保留完整命令与编译器探测警告，不把其当项目代码要求或静默写入全局环境。

## Risks / Trade-offs

- [手动TLS驱动的Pending/控制消息/半关闭容易出错] → 单记录输入和有限输出的独立门禁先行；不用私有字段/unsafe绕开，失败保持未实现。
- [UUID或Vision头跨片被误判] → 增量状态机、所有截断前缀和任意分片测试；不复制上游依赖单buffer的行为。
- [Direct写出顺序或双向状态混淆导致字节损坏] → 独立方向及提交屏障，测试“最终外层record＋原始数据”同到、短写、仅单向Direct及取消。
- [客户端flow/UDP策略差异被错误归一化] → 准入矩阵与原生UDP/两类XUDP分别验收，443本地拒绝和服务端流量证据分开。
- [混合用户改变旧TLS/VLESS行为] → 仅含Vision监听使用受控承载，纯无flow路径保留；TLS1.2和空flow例外明确回归。
- [较宽严格解析或客户端能力不足] → 固定源码与独立报文先验证；实测缺口保持未通过，不为矩阵把Direct变End或丢弃flow。
- [集中验收延后发现集成问题] → 必要编译/认证/数据/资源检查仍先行，未验收状态和输入快照明确，集中段不得删除。
- [随机padding与上游分布不同] → 只声明线协议与状态兼容，不声称流量外观或规避检测效果，不做相关部署调优。

## Migration Plan

旧version1 JSON无需迁移，缺省用户flow为空；新的Vision配置在旧二进制明确未知字段失败。新增示例单独命名，不覆盖已有示例与历史验收。实施后先标已实现待验收，能力簇集中验证完成才更新有限兼容结论。用户现有部署不自动重启，回退可使用已保存摘要的旧release但不能解析新flow字段。本变更不自动归档、Git操作、发布、生产部署或系统网络修改。
