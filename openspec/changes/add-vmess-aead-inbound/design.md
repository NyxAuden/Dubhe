## Context

动机见 `proposal.md`，行为契约见 `specs/vmess-aead-inbound/spec.md`。本项目是单 package 的原生 Rust 服务端：`runtime` 联合准备监听、分配连接/握手许可；`forward::Context` 提供路由、DNS、UDP 预算和子任务屏障；TCP 在业务接口外使用 Counted，UDP 在实际业务发送/接受处计量。

当前没有 VMess 实现。VLESS/Trojan 的 TLS 配置是必填平面字段，不能直接复用为“VMess 总有 TLS”；`udp::vless` 的 u16 数据报封装也不是 VMess cmd2。现有 `udp::xudp_body` 已把 VLESS 响应与 body 分离，可以复用 UDP-only XUDP 生命周期，但必须先通过 VMess 正文承载，不得发送 `00 00`。SS 的 ReplayPool 只理解 salt、入口/身份索引和 60/120 秒窗口，不应直接塞入 VMess 标识。

Vision 开发门禁已经完成，完整验收仍为独立未完成任务。本变更不以先执行 Vision 官方/三平台验收为前置；本轮只生成规划，不修改 Rust、Cargo 或测试实现。

### 固定研究基线

以下仅是只读源码事实，不是执行或互通证据。版本标签与不可变提交分别为 Xray v26.10.31 `a4a3dff5b20c2faae567b742c172c7b95e75c083`、sing-box v1.14.4 `c005f35300ce76427dc285481ec5695f5b179cd2`、SagerNet/sing-vmess `a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017`、Mihomo v1.19.33 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`。Mihomo 实际使用 MetaCubeX/sing-vmess v0.2.5 `9b7fdbf462a5cf6366628631ef426c1a91f5df82`，不能拿 SagerNet 的实现替代该依赖事实。

- [Xray 默认 security/options 及 UDP→XUDP](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/outbound/outbound.go#L97-L166)、[padding 默认](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/outbound/outbound.go#L222-L225)、[当前 JSON security 映射](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/infra/conf/vmess.go#L24-L43)。当前 Xray 的 none/zero 名称不证明线上发送 security 5。
- [sing-box 默认 packet/security/TLS](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/vmess/outbound.go#L80-L106)、[sing-vmess none/zero](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/client.go#L36-L62)、[正文默认 flags](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/client.go#L130-L166)。sing-box TLS+auto 选择 zero，默认 UDP 为 cmd2；非 TLS 的 auto 使用 3/4。
- [Mihomo 依赖](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/go.mod#L37-L43)、[选项传入](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vmess.go#L475-L498)、[实际分叉默认 flags](https://github.com/MetaCubeX/sing-vmess/blob/9b7fdbf462a5cf6366628631ef426c1a91f5df82/client.go#L135-L160)。测试显式填写 cipher，不能假定其解析器自动补空值。
- [cmdKey](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/protocol/id.go#L41-L48)、[嵌套 KDF](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/kdf.go#L9-L30)、[AuthID](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/aead/authid.go#L26-L47)、[时间及早期重放](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/aead/authid.go#L99-L118)。
- [请求 AEAD 完整封装](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/aead/encrypt.go#L14-L60)、[内层编码](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/encoding/client.go#L63-L99)、[服务端检查](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/encoding/server.go#L179-L244)、[响应 AEAD](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/encoding/server.go#L312-L354)。
- [SHAKE 序列](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/encoding/auth.go#L30-L70)、[帧及 padding](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/crypto/auth.go#L249-L275)、[正文 nonce](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/encoding/client.go#L302-L310)、[ChaCha key](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/protocol.go#L144-L151)。
- [认证长度减正文 tag](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/crypto/chunk.go#L43-L64)、[下行长度使用 request 材料](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/encoding/server.go#L379-L410)、[sing-vmess 下行材料](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/service.go#L400-L432)、[认证长度状态](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/chunk_length_aead.go#L19-L43)。
- [Xray 提前判断 EOF](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/crypto/auth.go#L153-L170)、[显式空帧](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/crypto/auth.go#L337-L350)、[会话 key/IV 缓存](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/encoding/server.go#L26-L67)。本项目不继承其计数回绕或未验证空帧 tag 的行为。
- [cmd3 不带外层目标](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vmess/encoding/client.go#L79-L94)、[XUDP 内帧](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/xudp.go#L142-L175)、[packetaddr 标记及地址类型](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/packetaddr/packetaddr.go#L8-L15)、[packetaddr 封装及空 payload](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/packetaddr/conn.go#L62-L95)。

## Goals / Non-Goals

**Goals:**

- 把 AEAD 头认证、正文编解码与业务调度分开；密码计算委托库，自己实现有限线协议及生命周期。
- 覆盖三家当前默认正文组合，并实现有明确开关的 UDP 扩展和实验性认证长度，不靠静默忽略选项获得“互通”。
- 显式记录本项目的加固差异：精确重放窗口、有限 nonce、完整验证终止块、直承载明文正文策略。
- 开发门禁与完整兼容验收分离，后者不阻断下一独立模块。

**Non-Goals:**

- 不更换现有 TLS 后端或受控 Vision 承载；VMess 普通 TLS 使用现有 TlsAcceptor。
- 不增加动态插件/通用 transport 框架，不把长期协议路线塞入本变更。
- 不提供无限连接时长承诺、跨进程重放持久化、TCP mux、GlobalID 跨承载续接或 VMess 出站。
- 不声称 authenticated-length 安全解决流量分析，亦不改其 wire 来掩盖已知跨方向 nonce 问题。

## Decisions

### 1. 独立配置类型，可选 TLS 和安全默认值

新增 `VmessUser { name, uuid }`，不复用 VlessUser，避免接受 flow。入口使用平面字段：`type/tag/listen/users`，可选成对 `certificate/private_key`；`xudp`、`packetaddr`、`allow_insecure_body`、`allow_authenticated_length` 均为缺省 false 的布尔值。两个 UDP 扩展开关独立，开启不改变普通 cmd2。证书字段缺省省略，显式 null、半组、空路径拒绝；旧 VLESS/Trojan 必填 TLS 不变。

UUID 只接受标准 16 字节表示的规范字符串形式，大小写按解析后身份去重，用户名入口内唯一且非空；与现有 UUID 校验保持一致，限制每入口 1..=1024 个用户，使 AuthID 候选扫描有固定配置上限。所有错误只给字段位置/种类，用户和 prepared 的 Debug 不展示 UUID/key/IV。`alter_id/alterId/security/flow` 等非本地 schema 字段为未知字段，不提供配置导入别名。

security 5 在实际完成 TLS 握手的承载上可用；直承载只有 `allow_insecure_body:true` 才接受。选择该策略而非一律禁用 5，是为兼容 sing-box TLS+auto；不默认允许无 TLS 的明文正文。认证长度发现固定 wire 方向间重用材料，故 `allow_authenticated_length` 默认 false；只有显式开启才进入兼容分支，不能假装忽略该位。

### 2. 成熟密码原语与可组合的协议 KDF

拟采用如下生产依赖；这是规划选择，不是已下载、已锁定或已编译证明：

| 用途 | 拟用版本/特性 | 已查许可与 MSRV |
|---|---|---|
| AuthID 单块 AES | 现有 aes 0.9.4 升为直接生产依赖 | MIT OR Apache-2.0，Rust 1.89 |
| 头/正文 AEAD | aes-gcm 0.11.1、chacha20poly1305 0.11.0 | MIT/Apache-2.0，Rust 1.85 |
| MD5 协议派生 | md-5 0.11.0 | MIT OR Apache-2.0，Rust 1.85 |
| SHAKE128 | shake =0.1.0，关闭默认特性 | RustCrypto 从 sha3 0.12 拆分的公开 XOF 库；MIT OR Apache-2.0，Rust 1.85 |
| CRC32-IEEE | crc32fast 1.5.4 | crates.io 元数据：MIT OR Apache-2.0，Rust 1.63 |
| 可接受预初始化 hash 的 HMAC/SHA256 | cryptoxide =0.5.1，关闭默认，仅 hmac/sha2 所需特性 | MIT/Apache-2.0，Rust 1.78 |

实施时发现原规划 `sha3 0.12.0` 已移除 Shake128；2026-11-05 向用户明确报告并暂停，用户随后要求继续。现修正为官方拆分的 `shake 0.1.0`，SHAKE128 算法及 wire 不变，保留失败历史，不声称原依赖 API 已通过。实施阶段的真实依赖/features/许可/MSRV/公告记录见 `docs/vmess-dependency-gate.md`。

保留既有 sha2 0.10 和 SS 依赖，不为此升级整个项目的摘要接口。cryptoxide 最新 0.6.7 的元数据要求 Rust1.95，超出项目 MSRV1.91；选择 0.5.1 需在依赖报告记录理由。运行前须核对实际发布包、传递依赖、features、许可、撤回/安全公告及 MSRV，遇不满足条件即暂停该任务，不静默替换方案。

KDF 是“使用嵌套 keyed hash 构造器的 HMAC-SHA256”，不是 HKDF，也不是依次 HMAC 上一步结果。已核对 RustCrypto hmac0.13 的公开构造只接受密钥并从摘要初始状态构建，不直接接收运行时 keyed hash 构造器；不硬写 ipad/opad 绕过成熟库。选用 [cryptoxide0.5.1 Hmac::new(digest,key)](https://docs.rs/cryptoxide/0.5.1/cryptoxide/hmac/struct.Hmac.html) 及 [Digest 接口](https://docs.rs/cryptoxide/0.5.1/cryptoxide/digest/trait.Digest.html)，以薄适配器把已初始化 HMAC 暴露为 Digest，转发 input/result/reset，报告 SHA256 的 32 字节输出、64 字节 block_size。每层 HMAC 仍由库计算，适配器不实现压缩函数、padding、HMAC 算法或伪随机源。

KDF 根的 key 为 ASCII `VMess AEAD KDF`，后续每个 path 是下一层的 key，最终输入 cmdKey；深度仅来自固定协议 labels 与固定长度 AuthID/nonce，不受 peer 任意递归控制。对各层、重置、重复 result 和完整派生分别设独立向量，所有输出缓冲精确32字节。协议校验 FNV1a32 是非密码校验，不宣称提供认证；真正认证由 AEAD 完成。随机填充沿用 ring secure_random，不自研 PRNG。

### 3. 头部状态机与成功交付点

准备时每用户预计算 `cmdKey=MD5(UUID16 || "c48619fe-8f02-49e0-b9e9-edf763e17e21")` 及 AuthID AES key。握手依次处理：

`AuthID[16] | encryptedLength[18] | connectionNonce[8] | encryptedHeader[len+16]`

AuthID 解密为 `timestampBE64 | random[4] | CRC32BE[4]`。遍历全部候选，检查 CRC 和时间且必须唯一匹配；不能只以 CRC 成功声称完整请求认证。头长度与正文分别使用标准 KDF label 派生 AES128-GCM key/nonce，AAD 都是原始密文 AuthID。无目标 IO 发生在此阶段。

内层固定前缀38字节，含版本1、正文 IV/key、响应认证字节、options、padding/security、reserved、cmd。cmd1/2 后有 portBE16 与 VMess 地址（IPv4=1、domain=2、IPv6=3）；cmd3 省略整个目标，直接 padding 与 FNV1a32BE。域名最多255字节、padding最多15字节，据此内层绝对上限316字节（38+259+15+4），密文最多332字节；长度 AEAD 验证后先查范围再读取。禁止按任意 peer u16 分配大头部缓冲。

验证完整长度、版本/reserved、FNV、地址/命令/选项/策略后才返回不可变的会话材料与 TCP、NativeUdp、Xudp 或 PacketAddr 模式。cmd1 路由和目标连接成功后发送一次响应；UDP 先获得必要关联/模式准入，真实逐包目标仍在发送前走路由。响应头不包进正文，写入受期限约束并 flush，server-first 目标无需等待客户端先发正文。

响应正文 key/IV 是请求 key/IV 分别 SHA256 后前16字节。响应头为 `GCM(lenBE16)[18] | GCM(responseAuth,0,0,0)[20]`，AAD为空，使用标准 `AEAD Resp Header Len Key/IV` 与 `AEAD Resp Header Key/IV` labels，从响应 key/IV 分别派生。无额外 CFB 层、动态命令或连接复用。

### 4. 专用精确重放池与时间防回退

新增 VMess 专用池和 `limits.max_vmess_replay_entries`（缺省65536，范围1..=1048576），每进程所有 VMess 入口共用；不改变 `max_replay_entries` 的 SS 语义。容量统计 AuthID 与会话 key/IV 两类记录的总数，正常会话占两条，不能误称可容纳等量完整会话。key 含原始 UUID 身份、记录种类和固定字节标识，同凭据跨入口也不能通过入口索引绕过。禁止 Debug 秘密。

- AuthID 通过候选 CRC/非负时间窗检查后，立即原子提交；长度/正文认证失败或取消不撤销，与上游提交顺序一致。完整认证前没有有效 AuthID 的任意输入不插池。
- 完整请求头 AEAD 与结构校验通过后，业务准入前提交 `UUID + requestKey + requestIV`；以新 AuthID 复用仍受保护的材料也拒绝。两次提交不跨 await 持锁。第二次容量失败保留第一条，不为“回滚”重新开放 AuthID。
- 接受与有效当前时间整数秒差 <=120 的非负 timestamp。首次见起使用至少241秒的单调 TTL，覆盖未来120秒 ID 仍可能被接受至首次见后240秒及秒边界；不能照搬“120秒窗口所以TTL120”。会话材料使用同样保护期，明确是有限窗口防复用，不是永久全历史唯一。
- HashSet/Map 加按 deadline 排序的 heap；每有效key一个到期项，重复/容量失败不追加，满额拒绝不驱逐仍有效记录。无独立无限清理 worker，准入时有界清理。
- 时间抽象在每次采样取 `max(系统时间, 上次有效时间+单调经过时间)` 并保存新的锚点，以完整亚秒精度的Unix Duration保存有效时间，只在最终比较timestamp时取整数秒；不得每次重锚丢弃小数而使高频请求冻结逻辑时间。使用checked arithmetic，系统时间非法/溢出则拒绝。时间回退不让已过期的旧 ID 再次进入窗口，向前跳变后不自动回退开放旧窗口；代价是主机时间严重跳变可暂时拒绝正常客户端。用注入时钟覆盖高频亚秒采样，不改系统时间。

SS 已有有界集合/到期堆模式可参考，但不提前提炼通用框架或混合不同 TTL 规则。进程重启丢失保护记录是明确边界，不能宣传跨重启抗重放。

### 5. 正文安全矩阵与 codec 边界

选项位为 C=0x01（chunk）、M=0x04（mask）、P=0x08（padding）、A=0x10（authenticated length）。0x02 连接复用及未知位拒绝；P 必须同时有 M。选择显式矩阵而非照抄某个上游宽松分支：

| security | cmd1 TCP / cmd3 XUDP | cmd2 原生/packetaddr |
|---|---|---|
| 3/4 | 总为 AEAD 分块；C 可0/1，支持 M、M+P，A 须开关准许 | 同左，但每个已验证块是一包，不能拆并 |
| 5 | options0为裸流；options1为普通u16长度分块 | 仅options1，每块一包 |
| 其他 | 拒绝 | 拒绝 |

security3/4 不设置 C 仍保持上游实际分块行为；普通允许 options0/1/4/5/12/13，开启 A 后允许16/17/20/21/28/29。security5 不接受 M/P/A；当前客户端 none/zero 的有效 0/1 路径已覆盖，不把任何 security5 请求默默强加密。Xray默认0x0d、sing默认0x05、sing TLS+auto 的5/0或5/1均有独立测试。

普通3/4块：`sizeBE16[2] | AEAD(payload)[payload+16] | randomPadding`，size 包含 tag/padding。每方向以完整16字节 IV 初始化一条 SHAKE128 流；P 先消费2字节取BE16%64作为padding长度，再由 M 消费2字节作size XOR。若仅 M，只消费mask；不能分开初始化两个 SHAKE。tag不认证后置padding，因此不承诺padding篡改一定被拒绝；业务 payload 只在tag验证后交付。

AES正文key直接为16字节；ChaCha正文key为 `MD5(key)||MD5(MD5(key))`。正文nonce为 `counterBE16 || IV[2..12]`，从0开始，上下行用各自正文key/IV。使用更宽计数器保存状态，在单方向第65537次操作前失败，绝不截断回绕；若发送显式终止块，必须仍有一次额度，保守预留最后一次供终止。此限制会导致大流量长连接需要重连，必须公开，不能偷偷继承上游回绕。

A 开启后用18字节认证长度替代2字节size，解密长度是 `payload+padding`（不含正文tag16），不再消费mask随机数；P仍消费各方向SHAKE的padding随机数。长度key=`KDF16(requestKey,"auth_len")`，算法随3/4，nonce两向均从0、使用requestIV。**固定上游双向长度材料相同，确实跨方向复用key/nonce**；只能保证各方向内部不回绕，不能宣称整个连接 nonce 唯一。保留兼容但默认关闭、单独警告；不自行加方向域或偏移伪装互通。

普通块接收长度上限65535，A模式正文密文上限65535+16=65551；不能把普通size上限错误套到A的解密长度。固定有界接收和发送缓冲各至多一个完整块，发送TCP可选16KiB正文以降低延迟；接收不把该发送选值当wire上限。输出块只编码一次，以游标排空，Pending不重新消耗nonce/SHAKE/随机数，失败永久闩锁。poll_read不得因无关下行Pending阻塞已经就绪的上行。

TCP适配为 AsyncRead/AsyncWrite，cmd3也走同一字节流适配；cmd2使用显式数据报读写接口，不通过AsyncRead丢失chunk边界。UDP payload还受 `max_udp_payload` 约束；加入packetaddr头、AEAD tag和本次padding后不能装入一帧时明确拒绝/丢弃并计drop，不能拆成多包或称65507在所有模式下一律可用。普通临时解密块有固定上限，进入持久队列前仍申请共享字节许可，队列满不得积累额外无界完整块。

### 6. EOF、半关闭与取消

3/4 的完整空 payload AEAD 块（含tag、padding）为终止信号，必须先读完并验证tag，不能看到size=tag+padding就提前返回EOF。完整块边界的传输EOF允许结束，以兼容只关闭连接的实现；半长度/半密文、坏tag报错。底层TLS缺close_notify等真实错误不改成成功EOF。合法结束后不再消费同方向尾部新业务。

security5裸流按传输EOF结束；普通长度分块的零长度块为终止，不解释为零字节原生UDP。原生cmd2无法无歧义传空payload，记录为边界；现有XUDP空payload政策保持。packetaddr有非空7/19字节地址头，故允许地址头完整、业务payload为空的数据报。不能把tag16或短地址头当UDP数据。

poll_shutdown一开始锁定写关闭，即使Pending也不得再接受新业务；排出已有输出，再按模式写一次合法终止（有额度才写）并关闭底层写端。读向继续排空，不因单向结束取消反向。取消/force依现有任务所有权回收，无分离永久加解密worker，不在select中丢弃已消费半帧；UDP reader沿用独立tracked任务。

### 7. UDP 模式及共享 body 接口

- **NativeUdp**：cmd2且非控制标记，固定请求目标；每个正文chunk恰一数据报，无额外VLESS u16包头。不跨chunk补齐包内容。共享 Association 路由、DNS、目标限额、实际来源过滤及空闲回收。
- **Xudp**：`xudp:true`才接受cmd3，外层没有目标字段；body经VMess流codec后直接进入现有 `udp::xudp_body`。保留现有逐帧只准UDP、会话id/代次、来源、GlobalID不跨承载复用及回收行为；不得发送VLESS response。混合入口回归确保原VLESS/Vision响应一次性未改变。
- **PacketAddr**：`packetaddr:true`且cmd2目标域名精确为 `sp.packet-addr.v2fly.arpa` 才内部识别，不解析控制域名，外层端口不作为业务目标。每个解密chunk为 `01|IPv4[4]|portBE16|payload` 或 `02|IPv6[16]|portBE16|payload`；无域名类型，无额外长度，地址在端口前，不能复用VMess请求地址的IPv6=3布局。回程按真实来源编码；短头/未知类型/端口0有限拒绝，不跨下一chunk补头。关闭扩展仍拦截该保留域名并拒绝，不能落到普通DNS。

`udp::framed` 当前只适配Trojan/VLESS字节流，选择增加VMess专用小适配器而非泛化所有framing；复用 Association/Packet/cleanup，不复制目标路由和任务管理。必要时把内部可见性调整为crate级，注释从“仅VLESS”改为真实复用边界；不改变旧wire契约。

### 8. 开发门禁及集中验收

开发时先过依赖/KDF/头部，再过正文与边界，再接运行器。独立金样不能全部由生产codec生成：保存来源、公开测试凭据和预期hex，使用另一组直接成熟密码API的测试端覆盖首payload、错误头/正文、SHAKE消费顺序、两向材料、UDP边界及EOF；不运行参考内核替代本机开发测试。

完成新增及受影响配置、VMess、UDP/XUDP、TLS/VLESS/Vision和共享资源定向回归，加fmt、locked all-targets check、严格Clippy，保存命令/退出码/失败历史及当前输入摘要，文档标“已实现待集中验收”。此时可继续其他模块，最终任务保持未勾。

能力簇收尾再独立获准运行三家固定官方矩阵：3/4各自TCP+原生UDP、直承载+TLS；sing-box TLS+auto的5默认；Mihomo/sing-box显式XUDP与packetaddr各自可用组合；Xray默认可触发的UDP路径和显式XUDP分开观测；M/P/A选项独立，A开关拒绝和显式启用均记录。TLS证书信任、错误UUID/时间/标签/选项等负向必须证明未触及受控目标。Xray当前不发送5不能列作其security5通过，客户端不支持的组合不能偷删或算通过。

同一最终构建重跑既有33项参考回归及已获准的新Vision矩阵，三平台普通/vendor、MSRV1.91、features/许可、release/示例分别记录。既有官方执行授权不扩展到VMess或Vision；不得自行启动容器恢复环境。全量通过前不all_done、不自动归档或Git。

## Risks / Trade-offs

- [认证长度跨方向复用key/nonce属于固定wire局限] → 默认禁用、显式开关和醒目文档；测试精确材料而不声称安全性质优于上游；普通默认0x05/0x0d不依赖该扩展。
- [16位正文计数耗尽使大流量连接较早结束] → 公开额度及终止保留策略，实际边界回归；不以长期连接需求为由回绕nonce或改wire。
- [AuthID CRC不是完整认证且多用户扫描消耗CPU] → 最多1024用户、预计算、固定大小读取、握手并发/期限及精确池上限；成功业务仍要求完整AEAD/结构/路由准入。
- [有有效身份的恶意请求可占满保护池] → 满则拒绝、不提前驱逐；记录容量包含两类项与恢复时间，不降低抗重放换吞吐。
- [时间前跳后锚点不回退可能拒绝正常客户端] → 注入时钟覆盖，明确时钟运维要求；不修改系统时钟，不清池来假修复。
- [无正文加密只保护AEAD头，裸TCP业务不保密也不认证] → 实际TLS或显式allow_insecure_body，文档/示例默认安全，不把none当legacy。
- [嵌套KDF容易误用普通HMAC/HKDF，密码API版本不一致] → 成熟库的实例可组合API、固定薄包装、分层独立向量；先过依赖门禁再接runtime。
- [UDP最大wire长度与本地payload上限不同] → 每模式按实际开销检查，不拆包；保存超限与空包边界证据。
- [源码默认不证明外部互通，cone/配置转换可能改变Xray/Mihomo路径] → 最终保留实际生成配置与wire观测，默认与强制组合分开记录；不把尚未执行的具体路径当既成事实。

## Migration Plan

新增入口和独立配置/示例，不迁移旧用户或隐式开启扩展。开发实现后使用当前源码构建检查模板，旧release不当新二进制；回退时移除新增入口即可保留既有协议配置。生产部署、发布、Git和归档均不是本变更自动步骤；所有证据由实际运行后更新，不把本设计当上线批准。
