## Context

动机与算法/身份范围见 proposal.md，行为契约见 specs/shadowsocks-inbound/spec.md。现有代码已检查：

- `runtime::Server` 仅拥有 TCP `Listener`；bind 中全部监听成功后才 run，统一 stop/force token 和 JoinSet；每入口拥有握手许可，TCP连接共享全局连接许可。
- `udp::Association` 按目标创建 connected UDP socket，可复用路由、DNS、目标限额和 TaskTracker，但并不满足2022“一会话一个稳定出站socket”的要求。`Packet` 已含全局字节许可与可选会话代次，XUDP 已验证过旧代次过滤。
- `forward::Context` 管路由/DNS/预算，`relay` 用明文计量包装和 `copy_bidirectional` 保留半关闭。Shadowsocks不应另起一套目标拨号、日志或计量系统。
- `config` 拒绝未知字段并脱敏解析错误。现有 `User` 的 password Debug 已脱敏，但新入口顶层 password 也必须有等效保护，不能让枚举派生 Debug 回显密钥。
- 参考测试已有固定版本/官方摘要核验、回环目标、私有产物、RAII kill/wait和正常/负向结果分离；当前九项全部实际通过。新方法不能把这些历史通过当作自身结果。

固定规范：shadowsocks/shadowsocks-org commit `eb7862d19b5d1ade04b89e2d49f8c68d34c8b031` 的 [AEAD](https://github.com/shadowsocks/shadowsocks-org/blob/eb7862d19b5d1ade04b89e2d49f8c68d34c8b031/docs/doc/aead.md)、[SIP022](https://github.com/shadowsocks/shadowsocks-org/blob/eb7862d19b5d1ade04b89e2d49f8c68d34c8b031/docs/doc/sip022.md)、[SIP023](https://github.com/shadowsocks/shadowsocks-org/blob/eb7862d19b5d1ade04b89e2d49f8c68d34c8b031/docs/doc/sip023.md)。提交API确认其为完整commit，规范仓库LICENSE为MIT。只读参考，不复制上游实现。

固定实现证据：

- Xray `a4a3dff5b20c2faae567b742c172c7b95e75c083` 的 `infra/conf/shadowsocks.go`、`proxy/shadowsocks_2022/{shadowsocks_2022,cipher,kdf,outbound,replay}.go`：三个2022方法、ChaCha禁止PSK链、AES多用户分支、客户端PSK链与简化settings字段。
- sing-box `c005f35300ce76427dc285481ec5695f5b179cd2` 的 `protocol/shadowsocks/inbound.go`，其 go.mod 固定 sing-shadowsocks `65740e0f0e3ea0d78beb9f3972ba42a75a6cd160`。后者的 `shadowaead/protocol.go` 和 `shadowaead_2022/{protocol,service}.go` 已核查算法及密钥/会话调用。
- Mihomo `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` 的 `adapter/outbound/shadowsocks.go` 使用方法库封装，`udp-over-tcp` 与插件是独立分支；本批明确不用它们。其方法依赖版本在go.mod中固定，不从单个适配文件推断算法全集。

## Goals / Non-Goals

**Goals:** 用小型协议适配层接入现有内核；同进程所有权、认证先于副作用、有限重放与会话状态、可追溯分算法验收。先保持现有入口行为，再扩展必须不同的原生UDP路径。

**Non-Goals:** 不启动上游relay服务来代替原生集成；不实现历史流密码、无加密、额外AES192/XChaCha/ChaCha12/8方法、2017多密码试解、ChaCha2022 EIH、多级EIH中继、SIP003插件、UoT、Shadowsocks代理出站或配置导入。上述边界只限定本批，长期扩展另有变更。

## Decisions

### 1. 协议库与内核职责分离

选用 `shadowsocks = "=1.25.0"` 的协议层，关闭默认features，仅启用 `aead-cipher`、`aead-cipher-2022` 及下述本地缓存禁用feature；不启用 `hickory-dns`、`security-replay-attack-detect`、stream/extra算法，不引入 `shadowsocks-service`。通过 `shadowsocks::crypto` 使用其密码库，不另写AEAD/KDF/AES块/随机数，不移植Go实现。内核自己accept、持有UDP监听和会话socket，只调用协议流与内存编解码，不使用完整上游relay、插件、resolver或其会话管理器。

**依赖基线（只读研究，未构建）：**

| 包 | 发布版本 | 发布包所记录的不可变commit | 声明许可 | 声明MSRV |
|---|---|---|---|---|
| shadowsocks | 1.25.0 | `ab388c7466d21f979430e33cc9ef10e22fb05955` | MIT | 1.91 |
| shadowsocks-crypto | 0.8.0 | `2ac3f4f6194476ff7b7be2a43c3a83e33510663b` | MIT | 1.85 |

来源：[协议库清单](https://github.com/shadowsocks/shadowsocks-rust/blob/ab388c7466d21f979430e33cc9ef10e22fb05955/crates/shadowsocks/Cargo.toml)、[密码库清单](https://github.com/shadowsocks/shadowsocks-crypto/blob/2ac3f4f6194476ff7b7be2a43c3a83e33510663b/Cargo.toml)。研究时已核对crates.io发布包checksum和 `.cargo_vcs_info.json`；实施时仍要在独立空目录重新获取、核验并保存实际摘要，不能从本规划推断本地已存在vendor文件或锁定结果。

协议库两个AEAD features会强制启用AWS-LC，不能通过关闭默认features或额外开启ring替代。因此下一实施批次将项目声明MSRV从未实际验证的1.85提升至1.91，并分别用1.91和当前1.95验证；若传递依赖无法在1.91构建则保留门禁，不虚报MSRV。现有TLS继续使用ring，新协议新增AWS-LC；需记录实际解析的 `aws-lc-rs`/`aws-lc-sys` 版本、原生构建工具和完整传递许可，不把样本锁文件当成最终依赖图。

**已确定的最小依赖补丁：** 当前1.25.0的2022 UDP编解码器有每OS线程102400项、TTL30秒的密码缓存，认证前可填充，按方法、key指针和SID定位，公开API不能禁用或改成满拒绝。直接依赖原版不能满足本批资源契约。实施时在项目 `vendor/shadowsocks` 保留MIT许可、完整来源和可复现diff，以Cargo路径补丁替换该协议crate，新增仅用于禁用2022 UDP派生密码缓存的feature，本内核始终启用。禁用路径每次用原有成熟密码库构造短生命周期cipher，不能在认证前遗留SID索引状态；不改算法、报文、KDF或认证顺序，也不vendor完整应用或复制其他参考内核实现。密钥仍由稳定拥有的配置/用户对象提供，禁止每包临时密钥及依赖指针身份表达业务归属。必须对有/无缓存的合法报文结果做一致性测试，并在内核选用的禁用路径验证大量不同SID无缓存增长。此补丁是已选实现任务，不是声称当前稳定版已具备该接口，也不要求本轮向上游发布内容。

替代方案：直接使用未补丁的库会留下资源违约；独立重写整个2022 UDP/EIH状态编解码会重复成熟协议实现；仅等待上游提供接口无法形成可执行交付。选择可审计的MIT依赖补丁控制缓存及下述协议严格性，代价为维护小型上游差异和每包密码构造成本。以后只有固定新版提供等效行为且通过本内核回归时才移除补丁。

**2026-11-04经用户直接确认的适配补充：** 实际22项依赖探针中，两项characterization测试复现三个2022方法会接受901字节padding和跨认证chunk变量头；padding读取还会把提前EOF当作结束。高层API不暴露chunk边界，不能由透明socket适配可靠补齐。将同一MIT协议crate补丁扩展为：入站padding<=900且完整读取；变量头（包括padding）必须首认证chunk，不能仅warn；密码协议流每方向计数实际AEAD调用，固定生产上限2^63次，远低于96bit nonce空间，在达到上限前终止且错误后不得继续用该cipher。计数在真正密码调用前扣减，poll重试不得重复扣减；长度块、载荷块及2022首固定头全部计入。测试只在crate内部注入接近终止边界/小预算，不对外暴露增大上限或任意nonce修改接口。不修改shadowsocks-crypto算法、nonce格式或密码原语。合法报文仍不变，非法报文按原规格拒绝。此扩展由新增任务1.5单独验收，原缓存补丁通过不代表TCP门禁通过。

### 2. 配置与敏感材料

新增 `Inbound::Shadowsocks` 和有穷方法枚举；JSON字段见规格。密码使用独立脱敏包装或为新增入口提供安全Debug，序列化仍保留配置所需原值。2022用标准Base64严格解码后检查精确长度，不能继承某上游“原始字节回退/过长自动哈希”的宽松行为。2017允许非空密码经库的标准旧KDF派生。

单层EIH的入口身份PSK与用户PSK分开存储，用户索引/哈希表在准备阶段构造；查表只是选择候选密钥，只有完整AEAD和头语义验证后才产生用户会话。身份哈希不记录日志。拒绝同密钥、重复用户密钥及哈希表冲突，避免歧义。所有生产凭据只在内存和用户配置中，不把示例共享测试值当成安全默认。

### 3. 监听准备与运行器

保持现有TCP监听封装，增加协议准备后的共享状态及可选原生UDP listener所有权；无需为了四种入口设计通用插件ABI。Shadowsocks绑定TCP后取得实际地址，再绑定同地址UDP；2022入口还在准备阶段通过临时socket验证所需双栈出站配置，2017不额外要求此能力。任一步失败由局部所有权释放全部已创建监听。准备阶段不创建业务任务、不DNS或拨号。

run为每个已准备的原生UDP入口启动一个有界接收/分派主任务，与既有accept任务一起参加错误传播和停机屏障。停止接新TCP和新UDP会话后，已存在UDP会话可在排空期限内继续处理；force后取消所有reader/worker/回程任务，TaskTracker等待实际socket析构。`local_addr`继续返回每入口唯一地址，不给TCP/UDP两个互不相同的临时端口。

### 4. TCP适配与失败行为

采用公开的 `ProxyServerStream::from_stream_with_user_manager(context, stream, method, key, users)` 包装内核accept的流，`handshake()`返回目标，EIH成功后用 `user_key()`映射已配置身份；认证与全局salt准入通过后才交给现有 `Context::connect` 与 `forward::relay`。2017地址可能跨多个认证chunk，适配不能把首个chunk剩余数据丢掉。2022先完成固定/变量头、EIH、方向/时间和padding/首载荷检查；两种方法的响应加密仍在协议流内，计量包装只看到明文业务数据。具体API见 [ProxyServerStream](https://github.com/shadowsocks/shadowsocks-rust/blob/ab388c7466d21f979430e33cc9ef10e22fb05955/crates/shadowsocks/src/relay/tcprelay/proxy_stream/server.rs)。

该高层流没有salt getter，不能把低层 `CryptoStream::received_nonce()` 当成握手后可用接口，2017内部还会消费接收salt。采用透明底层流适配器：只观察原本 `poll_read` 返回的前 `method.salt_len()` 字节，不额外预读、不拆分返回、不引入BufReader；握手成功后通过 `get_ref()`取得最多32字节的捕获结果，再执行共享精确查重，尚未准入不得拨号、转发或响应。2017下行在透明写适配器中捕获首salt，任何对应密文字节发出前同步执行原子登记；待写、部分写和重试不得重复登记或漏发前缀。库没有响应salt替换接口，TCP碰撞或池满即关闭，不承诺重新生成已建立流的salt。

2022初始salt、可选EIH与固定头沿用协议库的一次底层read语义，不先行 `read_exact` 抽走salt，也不在外层改成短读自动补齐；有效首读后后续chunk仍可任意拆包。短读及握手认证失败采用统一零linger RST关闭策略，由原始socket的受控所有权设置，避免暴露消费边界且不引入无限排空任务；普通已建立业务的正常半关闭不得设置此失败策略。响应首salt和头保持库的合并写行为，独立报文及固定客户端测试核实，不能仅由API存在推定合规。

每TCP连接创建独立的库Context，设ReplayAttackPolicy::Ignore且不开Bloom feature。2022会强制Reject并保留内部60秒精确池，无法公开关闭；独立Context使其只含本连接有限salt，存活连接数由现有许可约束，不能共享该无容量参数的池作为全局查重。内核自己的共享集合承担跨连接/身份的真正准入，其容量与每连接固定内部状态分别核算。

所有读写仍受握手/业务取消管理；nonce计数器耗尽关闭，半关闭只关闭对应方向，不丢弃反方向缓冲或在业务计量里加入salt/标签。以上透明适配与独立Context方案来自源码推导，尚未编译或集成验证；最小适配测试是后续实施门禁。

### 5. 精确重放集合和容量

新增全局 `limits.max_replay_entries`（默认65536，校验范围1..=1048576），约束本进程所有Shadowsocks共享精确salt记录与必要的在途预留；采用按过期时间排序的有界队列配哈希集合，不使用有误报的Bloom过滤器，不靠容量驱逐仍有效记录。使用单调时钟；60秒和120秒记录混用时也必须按到期先后清理，队列不能保留已从集合删除的无限陈旧项。已认证/通过语义后原子“查重并插入”，并发重复只有一个通过。容量满拒绝新记录，包括此时无法登记的2017回程salt；不削弱已有会话的保护，不自动关闭查重。

2022 TCP保存入站salt60秒，按入口/用户作用域，不把发送salt加入2022入站池。2017使用120秒明确有限窗口，按入口/密钥域共享TCP/UDP接收与发送salt保护，防止在保护窗口内反射或跨路径重放；2017 UDP解密前保存salt前缀，完整认证和地址校验后才查重。TCP响应salt通过写适配器登记，碰撞或容量满关闭；UDP响应先编码到有界缓冲，再登记其salt，碰撞时最多重新编码8次，容量满立即丢弃，任何未经登记的报文不得发出。不同用户的重放空间不合并。不能从随机salt生成推出有限内存永久唯一。

2022 UDP窗口采用本内核的小型8192位滑动位图，不仅为窗口算法引入整个 `shadowsocks-service`；这是非密码学的业务序号状态机，独立测试完整窗口边界、最高值和不回绕。完整认证和语义验证后才更新，不同用户相同session_id独立。库的低层UDP编解码函数本身不执行packet_id窗口查重，不能认为调用成功已完成防重放。

### 6. 两条原生UDP关联路径

直接使用公开的 `relay::udprelay::crypto_io::{decrypt_client_payload, encrypt_server_payload}`，不使用会隐含创建会话的完整relay。解密在原地缓冲返回净荷长度、Address和可选 `UdpSocketControlData`；2022 control暴露已认证的client SID、packet_id及可选EIH用户，且返回前已校验AEAD、type、时间和地址。入站control的server SID为0，回程必须从Default构造并填入内核自己的server SID/counter，不能原样反射。低层回程函数不会根据control.user切换密钥，EIH回程必须显式传已认证用户uPSK，而非入口iPSK。所有2022 UDP调用必须走决策1的无派生缓存feature。

2017按 `(入口, 客户端源端点)` 建立关联，可复用现有Association的connected目标映射。仅完整认证、地址合法、重放通过后才建状态；每包经过共享路由与DNS，不因为目标变更复用旧路由决定。低层2017 UDP解密不查重，保存原始salt并在内核登记是必要步骤，不能用库Context策略代替。

2022按 `(入口, 用户索引或单密钥身份, client_session_id)` 管理会话。每会话持有一个设置 `IPV6_V6ONLY=false` 的双栈unconnected出站socket，IPv4目标转换为mapped地址、IPv6目标原样发送；同会话两个地址族保持同一端口。无此能力的平台准备失败，不能偷偷创建两套socket改变NAT语义。内核维护有界的实际已发送目标集合/活动时间；recv_from后规范化mapped来源，仅允许有效目标回包。路由Reject不DNS、不发送，也不增加目标授权。

单入口分派器拥有窗口、最新认证来源、服务端随机sid和发送packet_id；子任务回程只携带内部编号+代次和实际来源，不能自选客户端身份。新客户端端点的认证包通过窗口与头校验后原子更新最新来源，迟到重放无权迁移。下行在实际加密/发送时读取当前来源，避免队列里缓存旧地址。有效会话idle为 `max(udp_idle_timeout_ms, 60000)`；单元测试用可控时钟验证，不用生产短TTL绕过保留要求。计数器耗尽或局部socket错误可提前释放转发资源，但必须保留仍有效的拒绝重建记录及其关联名额直到保护期结束，不能删除窗口后让旧SID重新以全新会话准入；服务整体停止后的状态释放不属于在线容量淘汰。

### 7. 有界报文、并发和计量

每原生UDP入口固定一个接收任务与一个顺序认证/分派主任务，不建立按包或按未认证SID的任务。入口密文通道容量沿用 `udp_queue_packets`，密文排队也先取得全局 `udp_bytes` 许可；接收任务只有一个固定接收缓冲，分派任务至多处理一包，解密后许可随实际缓冲所有权移交或释放。回程队列使用同一字节预算，每关联占用 `udp_slots`。每个2022会话只增加一个受追踪的socket回程reader；2017保留每目标reader但受关联数与目标数乘积约束。禁用派生缓存后密码对象仅存活于当前编解码调用，不随输入SID增长。排队条数、目标记录、重放记录与socket数分别有限，内存报告不把payload字节预算当成总RSS上限。

TCP握手许可也用于约束新入口未认证连接。拒绝/无效包不能先创建永久会话。新关联只有在认证/语义、路由和容量检查后创建，重放/窗口更新仍必须早于任何目标发送。逐包解析、DNS、发送都有限时且可取消，顺序分派接受受限队首阻塞的吞吐取舍，不能为优化并发引入无界worker。会话创建、映射发送及收到合法回程更新活动，但未经认证/无效/重放包不能延长会话。所有回程reader受children追踪，close和强停都join。处理完整帧后再产生目标副作用。

加密后总长必须满足UDP上限，本批统一采用不超过65507字节的保守密文上限；不能简单复用明文 `max_udp_payload`。固定接收缓冲覆盖普通UDP完整长度，并用可获知实际长度/截断标志的接收方式拒绝截断或超出支持范围的数据报，不把截断前缀送入解密。2017与2022的头、EIH、padding和tag开销分别计算；IPv4/IPv6及回程最大长度测试独立。只统计成功写到目标或客户端的业务明文字节，空UDP数据报合法时仍转发且计量为0。现有Association reader对空UDP回包已保留，但其他协议的空包策略不因此改变。

### 8. 验收与证据

参考客户端配置使用原生TCP/UDP、禁用插件/UoT/TCP mux，不加入TLS证书测试（Shadowsocks原生不使用TLS）。Mihomo为 `type:ss`、`cipher`、`password`、`udp:true`、`udp-over-tcp:false`；sing-box为shadowsocks outbound的method/password；Xray使用固定源码明确接受的简化address/port/method/password settings，保留关闭mux。EIH客户端password为 `identityPSK:userPSK`，每个PSK仍标准Base64。

目标矩阵为三家客户端各六方法单密钥和两方法AES多用户，共24组客户端/方法/身份模式组合；每组分别记录TCP/UDP正常及错误密钥负向，不能把一组的TCP通过等同于UDP通过。多用户测试至少验证两个不同用户，错误身份PSK与未知用户PSK独立拒绝。不把任一客户端内不支持/不能执行的情况标通过。保留原九项参考测试独立回归。

内部测试使用固定规范向量、独立测试端的成熟crypto原语和手工协议封装，不通过生产codec生成输入；测试篡改、全部截断边界、地址跨chunk、2017高位长度、2022padding/时间/salt绑定、重放竞争/容量/过期、2022 UDP乱序/迁移/同ID不同用户/稳定双栈端口、队列慢消费和停机。macOS及两个Linux容器完整普通回归；Linux不运行macOS官方二进制。每批保存源码/锁文件/二进制摘要及日志，不覆盖VLESS历史验收。

## Risks / Trade-offs

- [成熟库的默认重放或缓存与本契约不同] → 每连接Context、透明salt门禁和2022 UDP无派生缓存补丁先做最小适配测试；精确集合/窗口由内核控制，不能为了省代码撤销规范要求。
- [依赖补丁增加维护成本及无缓存路径的每包计算开销] → 只维护MIT协议crate的最小可复现差异，不改密码算法；固定单入口分派任务和有界队列，记录构造成本及差异回归。未证实补丁的资源行为及原有报文一致性前不进入互通通过状态。
- [一次首读遇到实际网络分段会拒绝连接] → 这是SIP022明确行为，文档公开并验证固定客户端按规范合并首写；不以修改握手语义伪造规范通过。
- [2022 UDP与既有connected映射拓扑不同] → 独立有限会话策略而非修改旧入口的来源过滤语义；混合启用时回归旧入口。
- [同源双栈socket平台差异] → macOS/Linux两架构真实验证mapped地址、V6ONLY和稳定源端口；准备时不可用明确失败。
- [精确重放容量耗尽导致新请求拒绝] → 有界容量与fail-closed公开，过期归还；不提前驱逐保护记录。
- [新增依赖的MSRV/许可/默认features膨胀] → 固定版本/feature和锁文件、更新许可表，声明MSRV与实际验证分开；不自动升级项目许可证或混入GPL实现。
- [外部运行授权或客户端能力缺口] → 只记录实际结果，任务保持未完成，不换工具或代理绕过。

## Migration Plan

新增入口不改变version1旧配置，新增资源限制采用默认值保持旧配置可解析。先内部验证，再固定官方客户端受控验收，最后更新兼容矩阵。用户现有部署不会自动更新或重启；不做公网部署、Git操作或归档。回退可使用已记录摘要的VLESS验收快照，新Shadowsocks配置在旧版本明确失败，不静默忽略入口。
