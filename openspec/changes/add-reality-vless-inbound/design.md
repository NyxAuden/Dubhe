## Context

动机见 [proposal.md](proposal.md)。本设计为尚未实施的下一独立变更，日期 2026-11-05；VMess 的 21/30 与 Vision 的 18/27 是各自开发/验收进度，均不是 REALITY 证据。

### 已观察的接点

- `src/config.rs` 的 `Inbound::Vless` 仍要求 `certificate/private_key`；`VlessUser` 已支持无 flow/Vision，UUID 脱敏，未知字段拒绝。本批不将旧证书字段改成可选。
- `Server::check` 当前只校验配置/本地证书，不监听或拨号；`Server::bind` 联合准备失败通过析构归还端口；`Listener` 持有每入口握手许可，accepted TCP 受全局连接许可限制。
- `src/runtime.rs` 的 VLESS Vision 分支已用 `Controlled::accept` 驱动 rustls，再复用 `handshake_with_flow`；`Vision<S>` 具体持有 `Controlled<S>`，不是任意 `AsyncRead/AsyncWrite`。
- `Controlled<S>` 具体持有 rustls `ServerConnection`，只读一条 record，保留独立读/写 Direct、flush 屏障、真实 TLS EOF/KeyUpdate/关闭语义。其输入适配必须保留预读原文，不靠拿到裸 socket 绕过。
- 当前锁定 rustls `0.23.46`、aws-lc-rs `1.19.0`、ring `0.17.14`、rcgen `0.13.2`；根普通 TLS 显式使用局部 ring provider。aws-lc 已在生产依赖图中，但本批增加直接用途和 hybrid provider 仍要重新审查 features/原生构建。
- `openspec/specs/` 仅有 `.gitkeep`，旧变更未归档；本批只添加新能力 delta，不假造旧主规格或修改旧验收输入快照。

### 固定协议/API来源

1. Xray `v26.10.31` / `a4a3dff5b20c2faae567b742c172c7b95e75c083`，[客户端认证与证书验证](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/reality/reality.go#L101-L208)、[short ID/版本配置](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/infra/conf/transport_security.go#L103-L160)。
2. REALITY `v0.0.0-20261014101318-83f621788ca8` / `83f621788ca88b83179810b12baa7ae518aacb83`，[CH/认证/目标分流](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/tls.go#L163-L301)、[目标 SH 与完成边界](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/tls.go#L352-L467)、[密钥与证书](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/handshake_server_tls13.go#L101-L185)、[ClientFinished](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/handshake_server_tls13.go#L1230-L1254)。这些是源码证据，未运行该内核。
3. 本地发布源码 rustls `0.23.46`：`server/server_conn.rs` 的 `ClientHello/ServerConfig`、`server/hs.rs` 证书选择、`server/tls13.rs:378..437,526..603` 的 SH/证书生成顺序、`crypto/signer.rs` 的 `CertifiedKey`；[公开源码](https://docs.rs/crate/rustls/0.23.46/source/src/server/tls13.rs)。
4. 本地 aws-lc-rs `1.19.0`：`agreement::PrivateKey::from_private_key/agree` 支持静态 X25519；`signature::PqdsaKeyPair::from_seed/sign` 支持 ML-DSA-65。rcgen `0.13.2` 的 `RemoteKeyPair/from_remote` 可向成熟 DER 构造器提供自选证书 signatureValue；实际首扩展次序、证书匹配与对端验证仍需门禁实验。
5. 既有 [可行性研究](../../../docs/reality-vision-feasibility.md)保留历史假设；Vision 后续已经开发，不能把旧“尚未实现”描述覆盖当前源码。本次未再泛搜或选用第三方 fork。

## Goals / Non-Goals

**Goals:**

- 按新能力规格交付认证、特殊证书、目标 SH/有限记录策略、固定目标回落和 VLESS/Vision 接入；选项必须可用，不留“能配置但忽略”的 ML-DSA。
- 每个字节、socket、许可、transcript 和关闭状态有唯一所有者；密码/TLS 运算委托成熟库，原生 Rust 负责协议编排和有限生命周期。
- 开发门禁允许用独立测试端/离线金样/自持 TLS peer，不把完整官方矩阵前置到每个模块；开发完成只标待集中验收。

**Non-Goals:**

- 不复刻上游所有 TLS 外观、探测缓存或定时特征；不提供公网目标选择、外观调参或检测规避部署。下述受控模板/记录能力是本批承诺，未覆盖行为单列，不声称上游实现等价。
- 不接入外部内核进程，不复制 MPL/GPL 模块；不重写 TLS、X25519、ML-KEM、ML-DSA、HKDF、HMAC、AES 或 DER 编解码算法。
- 不引入通用插件 ABI、通用 fallback 框架或任意承载泛型层；保持现有 Controlled/Vision 主体，不顺便重构全部协议。

## Decisions

### D1. 新增明确的配置类型，不改旧 VLESS TLS 语义

新增 `Inbound::VlessReality`，serde 显式名字 `vless-reality`；保留 `tag/listen/users/xudp`，`reality` 为严格嵌套配置，未知字段拒绝。复用现有 VlessUser 校验和 flow，新增入口用户数限制 1..=1024；不影响旧入口已记录边界。

| reality 字段 | 本批选择 |
|---|---|
| `target` | 必填 `{"host":"…","port":…}`；host 为合法非空域名或 IP，port 1..=65535，不从 SNI 推导，不接受 URL/路径；示例只用自持回环 |
| `private_key` | 必填无 padding 的 base64url，解码恰 32 字节静态 X25519 私钥；拒绝无效导入/全零原始值，派生公钥后用于重放命名空间；ECDH 零共享秘密由成熟库拒绝 |
| `server_names` | 1..=64 个非空 ASCII DNS 名，每项不超过 253 字节，精确区分大小写匹配、不通配；重复拒绝；不是证书 CA 信任配置 |
| `short_ids` | 1..=256 个 hex 偶数长度 0..16 字符，大小写解码后右补零至 8 字节，再查重；空串只有显式给出才接受 |
| `max_time_diff_ms` | 默认 120000，允许 1..=600000；拒绝 0/null，明确不同于上游“0关闭”的选项，不提供不受限时间模式 |
| `min_client_version/max_client_version` | 可选恰三个 0..255 整数；不设置则无该方向门槛，双设要求 min<=max，比较含端点；不捏造上游默认 min |
| `mldsa65_seed` | 可选无 padding base64url，解码恰 32 字节；显式 null/空值拒绝；未设置与设置必须分别实测，错误配置不能降级 |
| `fallback_idle_timeout_ms` | 默认 10000，允许 1..=60000，仅成功读写实际推进重置 |
| `fallback_max_duration_ms` | 默认 60000，允许 1..=300000，且不小于 idle；总期限不能被持续流量延长 |

`limits.max_reality_replay_entries` 独立默认 65536，范围 1..=1048576，SS/VMess 不变。所有秘密字段使用已有 Secret 语义和自定义脱敏 Debug/错误；序列化配置仍含配置秘密，不承诺它天然脱敏，不写入公开日志。

`check` 只解析、校验与准备本地密钥/证书/补丁能力，不 DNS、不 bind、不拨目标、不启动探测；`bind` 准备全部配置再开始 run，不因 REALITY 接入破坏联合准备。target 为域名时使用受预算控制的现有 DNS；拨号前拒绝匹配本Server已绑定的具体IP+端口、回环别名同端口及未指定地址的目标。监听为wildcard时保守拒绝相同端口的辅助目标（即便可能是远端，边界公开），不凭可疑NAT关系声称已识别所有网络自环；端口0使用bind后的实际端口。此保护不是允许绕过路由的通用SSRF过滤。

选择独立类型而非把 certificate/private_key 改可选：避免破坏旧配置、公开 API 和“TLS缺失时悄然裸传”的风险；未来统一配置另批设计，不在本次引入全传输枚举。

### D2. 先有界预读与认证，后固定目标连接

拟新增 `src/tls/reality/{hello,auth,replay,certificate,target}.rs` 与模块入口；仅按职责拆分，不引入运行时插件。用记录状态机保存 `wire_prefix` 和原始握手 `raw_ch`：

- TLS record 载荷上限 18432；完整 CH（含 4 字节握手头）至多 65536；预读 wire 总量至多 131072；完成 CH 前至多 32 条记录。均为本项目资源上限，超限关闭；不能宣称无限片数兼容。
- 只读取完成当前 record 所需字节，不对下条 record 预读；CH 完成所在 record 的尾部包含于 prefix，不再复制进 TLS 第二次。
- 解析握手字段/扩展时用 checked 长度和切片；记录 SID 的经过验证的范围，不用盲 `raw[39..71]`；raw_ch 不含 record header，原始 wire 不重组后作为 fallback 替身。
- 重复 SNI/key_share/supported_versions 等关键扩展、重复关键 share、非法向量长度关闭；合法普通 TLS 缺少 REALITY 所需 share 是认证失败，可回落；畸形 share 不是回落豁免。实际 pre_shared_key/early_data 拒绝；仅有 `psk_key_exchange_modes` 不等于提出 PSK，不因此误拒当前客户端。
- 共用 `handshake_timeout_ms` 的绝对截止时间，覆盖预读、认证、target DNS/SH 和本地 TLS/VLESS 认证，不在每个阶段重置整段期限。辅助 DNS/连接额外受 dial/DNS 子期限，取最早截止时间。

与上游先拨 target 再读 CH/MirrorConn 不同，本项目先验结构/资源，合法认证先提交重放占位，再拨配置目标；失败但可回落的合法 TLS CH 也只能拨该 target。这一顺序差异明确记录，不以“上游必须先拨”绕过有限资源。

### D3. 认证材料和 hybrid 选择严格分离

固定认证流程：

1. CH 中 hybrid(0x11ec/X25519MLKEM768) share 1216 字节在前，可选 X25519 share32 在后；为防歧义完整扫描并拒绝重复，较上游遇普通share即break更严格。
2. 有普通share就用其公钥，否则取 hybrid 最后32字节；两者公钥不必相同。静态 X25519 运算拒绝低阶/全零结果。
3. `AuthKey = HKDF-SHA256(ECDH32, salt=random[..20], info="REALITY", L=32)`；AES-256-GCM nonce 为 random[20..32]。
4. AAD 为完整 raw_ch，只有已验证的 SID32 内容置零，其长度字节仍32；解密结果恰16：version3、reserved0、BE32秒、shortID8。临时AAD缓冲不覆盖原文，原密文 SID用于后续 TLS/MLDSA/fallback。
5. 验证 SNI、shortID、版本上下界、保留位零、以毫秒比较的非负 Unix 时间。shortID不是用户身份，后续必须验证 VLESS UUID。

认证与 TLS KX 是不同过程。TLS 由目标 SH 组选择 aws-lc provider 的独立临时 X25519/ML-KEM，普通 share32/shared32，hybrid server share1120/shared64，组合顺序 ML-KEM 在前。不能拿 AuthKey 当 TLS traffic secret，不将 hybrid CH等同最终hybrid协商。

### D4. 额外精确重放池，不冒充上游事实

固定上游未发现精确 CH replay check；仅完成新 TLS ClientFinished 后才能应用交付，不意味着重放 CH 不会消耗资源。本项目添加本地防护：

- `Server::bind` 为所有 REALITY 入口创建一个独立 Arc池；key为 `(派生静态公钥32, SHA256(raw_ch含密文SID))`，不因换入口或原始私钥等价表示绕过命名空间。不同公钥隔离；不同Server实例/重启不共享。
- Auth/时间/版本/SNI/shortID 均通过后，在 target DNS、拨号、MLDSA签名前原子 check-and-insert；后续失败/取消不撤销。未认证垃圾不插池；重放/满额直接关闭，不进入fallback。
- 每条占位持有到 `2*max_time_diff_ms+1000ms`；u32秒客户端时间转换为毫秒 checked，额外一秒保守覆盖粒度。跨入口时间窗不同则同key命名空间取该静态公钥各入口最大窗来计算TTL；不能让短窗入口占位先过期而长窗重新接受。
- 精确 HashSet+每有效key一条最小到期堆项；不无界保留墓碑，不为重复续期，不提前驱逐。锁内无await。
- 有效时间用墙钟锚点和单调经过时间取max，保存亚秒，不改系统时间；极端时间错误fail-closed，不把时钟后跳当容量清理理由。测试注入时钟，不改VMess旧输入/算法。

使用新的有限池而非“继承VMess TTL241”是因为时间窗可配置且身份/key不同。可复用抽象仅限确有公共、无旧行为变更的薄辅助，不为DRY重写旧池。

### D5. 成熟密码与 DER，不手工改固定偏移

- aws-lc-rs `=1.19.0`，关闭无关默认 features，只启用审查确认的非FIPS生产构建需求；用于静态X25519、HKDF/HMAC-SHA256/SHA512、Ed25519、ML-DSA。不因已有传递依赖而免审。
- AES-256-GCM沿用成熟 `aes-gcm =0.11.1`；不改VMess已有AES128封装为REALITY冒用，不实现AES/GHASH。
- rustls `=0.23.46` 的 aws-lc provider仅新REALITY配置局部使用，明确允许TLS1.3/受控套件和组；旧入口继续显式ring，不 `install_default()`。
- rcgen `=0.13.2` 由dev提升为本模块生产候选，关闭不必要pem/x509-parser，复用 `RemoteKeyPair` 和 `PKCS_ED25519`：DER构造时证书签名器返回 `HMAC-SHA512(AuthKey,pub32)`，其SPKI为真实Ed25519公钥；TLS `SigningKey` 是真实对应Ed25519私钥，不拿HMAC实现CertificateVerify。随机Ed25519材料在准备时生成，不写到磁盘。
- 可选MLDSA由 `PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed)`导入。消息是同一HMAC输入串 `pub32||原CH||最终SH`，不是先HMAC pub再以其结果拼接CH/SH。签名context为空、标准ML-DSA-65，长度3309，公钥1952，首个扩展OID0.0；签名自身可以是有效标准随机签名，不要求与Go deterministic字节一致，必须以独立验证证明模式/context相同。
- 如果rcgen首扩展顺序或自选signatureValue无法满足要求，先报告门禁失败；不能自写ASN.1或复制固定证书DER后盲patch。使用成熟DER替代库属于新增依赖范围，需重新审查并更新规划，不默换。

准备阶段核对9项：发布来源、crate checksum/lock、普通文件、yanked、许可、精确API/features、MSRV元数据、已知公告、最小编译/向量。后续全锁公告/精确1.91是集中门禁，不能用元数据等价实际构建。aws-lc-rs声明`ISC AND (Apache-2.0 OR ISC)`，rustls `Apache-2.0 OR ISC OR MIT`，rcgen `MIT OR Apache-2.0`；完整原生/传递许可证另核，不凭此清单宣布全库无问题。

### D6. 基于精确 rustls 的最小加性钩子

基础“外部认证+标准TLS+HMAC证书”只做可证伪的内存/回环实验，不作为生产默认或完成捷径。完整要求选择当前rustls源码上的最小有界补丁，不采用已发现的旧版/协议不一致fork，也不升级到0.24开发版。

预计保留 `vendor/rustls/` 官方精确0.23.46源码、全部许可/原始摘要、来源清单、复现补丁与说明，Cargo patch统一解析到这一版本，避免tokio-rustls与Controlled持有两种不兼容rustls类型。**这会让所有入口编译到同一受补丁crate，但普通配置不启钩子，必须实际回归；不是“旧入口完全不受影响”。** 新features/字段默认关闭，没有钩子保持原控制流。

限定接口及调用位置：

1. **已校验模板选择**：外部target解析得出的套件/组只能是原CH真实offer、本地provider允许项，不改TLS版本/签名校验/Finished策略。配置把候选限制到模板所选项，拒绝HRR、PSK、非TLS1.3和未知模板扩展；不允许调用者塞任意不一致协商值。
2. **最终SH构造**：`server/tls13.rs::emit_server_hello` 完成本地KX后，以目标原SH模板替换同组等长share，保留已验证的random/扩展顺序等字段。解析后再核对suite/group/session-id/version/compression/长度。构造一份不可变的最终raw SH，**输出与transcript都消费这一份确切编码**；不允许一份重新序列化用于hash、另一份用于socket，也不暴露任意transcript重写API。
3. **SH后/Certificate前逐连接回调**：在该不可变SH确定后、构造证书flight前调用，本地持有AuthKey/raw CH/配置MLDSA；返回受长度约束的证书DER与原SigningKey。复核SPKI匹配和签名方案，不能更换协商结果、跳过CertificateVerify或读取traffic secrets。无MLDSA仍可共用同一安全接点。
4. **有限握手记录输出策略**：只处理受控初始flight及明确的握手后辅助记录，有限fragment/padding策略，仍由成熟rustls记录层完成认证加密、nonce和密钥更新；不在项目中重写record AEAD，不提供任意socket密文注入。当前`MessageEncrypter::encrypt`没有padding参数，aws-lc TLS1.3 provider内部拼接inner type后直接Seal，因此仅改fragmenter不足。最小补丁允许给记录加密器增加默认不支持的有限padding操作与精确密文长度计算，仅aws-lc TLS1.3实现零padding格式后调用原AWS-LC Seal；记录序号/AEAD限额仍由原record layer唯一推进。普通provider/配置不走新操作，预检长度/支持能力后再编码，错误必须传播为握手失败，不能触发`encrypt_outgoing`内部unwrap panic。详细布局按D7门禁，超出可安全表达的范围报告阻塞，不能把`max_fragment_size`当作已完整实现。

本地初始flight必须先在有界内存中完成证书、布局、KX与transcript一致性检查，再允许首次socket输出；仅“SH已经排入rustls队列”不等于允许输出。若本地构造失败，丢弃整个未提交session，回落持有的原始target流。前置预检不能替代Finished验证；之后TLS继续由原状态机验证。

补丁不允许修改密码算法、证书/Finished验证、不受限扩展透传、借私有字段布局、导出traffic secrets或绕过record AEAD限额。若实际需要超出上述四点、更新核心版本/依赖/许可证范围，停止相关任务并说明，不能在apply中暗吸收。维护成本、差异审查和上游安全更新是该选择真实代价。

### D7. 固定目标辅助连接、记录布局与回落所有权

状态和不可逆边界：

```text
accepted --> bounded CH --> classify/auth --> replay commit (valid only)
                 |                |                    |
                 x close          v                    v
                              fixed target         fixed target
                                  |                    |
                               raw fallback      target SH + layout
                                                       |
                                            validated local TLS flight
                                                       |
                                              local output committed
                                                       |
                                              verify ClientFinished
                                                       |
                                               VLESS authentication
                                                       |
                                                TCP / UDP / Vision
```

- 每accepted TCP至多一条同时存活target连接，共用连接生命周期；target仅从配置取，SNI是认证条件而非可拨地址。target域名经现有DNS并发/截止预算，拨号前拒绝解析到任一当前监听的明确自环地址；不创建每CH字段/每record后台任务。
- target接收原始预读wire prefix，后续输入由单一受控pump拥有；target下行在本地提交前至多保存131072字节/32条record，单record同18432上限，初始模板读取受握手绝对期限。只接受已知TLS1.3 SH格式、echo SID、允许suite和两种share，HRR/非零compression/未知协商扩展不能进本地TLS。
- 有效路径保存目标SH原文与有限布局描述，真实替换本地share；target密文不能拿来伪造本地encrypted flight，不重用目标TLS秘密。target socket在全部本地flight预检结束前保持存活，保存已读下行；预检失败可转移原socket与保存字节进入fallback，不再另拨一条“重放目标”。只有决定本地提交时才关闭辅助target并join；不能先关闭target再声称可向同一连接回落。合法认证路径此时只需向target发送已保存CH prefix，后续客户端字节保留给本地TLS，不让两个任务竞争读取客户端。
- 本批记录策略固定为上游已核的两种有界初始布局：七槽依次为 SH、CCS、EncryptedExtensions、Certificate、CertificateVerify、Finished、可选 ticket。每槽长度为含5字节头的record总长；第一个加密槽>512字节时，将本地EE至Finished聚合为一个record，否则按独立消息槽输出；此门槛是固定源码行为，不是基础认证的已证必要条件。服务端没有target会话密钥，**只能观察opaque record长度/顺序，不能解密验证target密文内具体消息类型**；槽名是采用的布局解释，不是完成了target证书/Finished验证。聚合型收一条、分离型收四条初始加密record，不同分片模式不自动支持；可选ticket槽仅取同次已读且完整的下一record，不延长等待，无则省略。布局收集受总量/绝对期限，短布局超时回落，额外未知record不转发到本地TLS。启用计划时零padding为`目标总record长度-(5+真实消息长度+1个inner content type+AEAD tag长度)`；负值、TLS1.3 record/inner plaintext规范上限或布局不完整在提交前拒绝模板并回落，禁止截断消息，不能把预读18432的通用上限等同TLS1.3可发密文上限。所有真实握手消息仍按实际编码进入transcript，padding不进transcript。开发测试覆盖两种布局、MLDSA大证书可容纳/不可容纳与边界计算；即便target把应用密文放在所解释槽位，也只能影响长度计划，不可成为本地业务明文。
- 可选第七槽只生成当前application密钥下的空application_data记录，不生成可恢复票据，也不把单字节NewSessionTicket当应用数据交付。本批不启动上游启动探测或复刻`GlobalPostHandshakeRecordsLens`全局表，因而不发送其额外post表记录；这是公开的外观行为差异，不是遗漏待决定。所有辅助空记录由rustls记录层持有并递增发送序号，解密应用明文为零、业务计量为零，下一真实VLESS响应必须正常解密；不得外部自行Seal后忘记推进rustls序号。接收端连续空record另受每poll工作量、握手绝对期限约束，不无限热循环。
- 以上依据固定[目标槽位和聚合](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/tls.go#L330-L380)、[padding/伪ticket转换](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/conn.go#L546-L587)、[transcript与聚合](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/conn.go#L1200-L1245)、[post表及完成门槛](https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/tls.go#L403-L444)；仅源码核查，没有互通结果。不能把目标加密字节直接原样发到本地新密钥连接。
- fallback保持原CH及已读target下行恰一次交付。结构合法但认证/SNI/时间/版本失败进入固定target原始双向复制；malformed/超限/early_data/PSK/replay/full pool直接关闭。合规错误UUID/flow在REALITY完成后关闭，不能重新回落。
- **提交闩锁**在首次poll本地TLS输出前锁定（保守于首次成功字节），Pending/短写也不能选择fallback。target路径与本地flight不能拼接。提交前的模板错误可转原target流；提交后任何TLS错误只关闭双方。
- fallback用独立未Counted的有限双向转发，保留半关闭、idle/total deadline和force取消；持有全局连接许可直到结束，握手许可在分类与原始回落建立完成后释放，不让60秒回落占满握手槽。不得调用业务`forward::relay`而产生业务计量。

模板/记录策略不是对第三方网络外观的承诺；若固定客户端互通还需要额外记录语义，按可复现受控失败证据更新范围，不以“已经HMAC通过”跳过。

### D8. 复用 Controlled 与现有 VLESS/Vision，不旁路边界

`PrefixIo<TcpStream>`先按游标回放原始prefix，再读socket，不能克隆prefix给两条路径同时读；fallback与local TLS只在提交前二选一。使新承载仍为 `Controlled<PrefixIo<TcpStream>>`，新增一个接收已准备ServerConnection/配置的窄构造接点，不抽象所有协议session trait。

REALITY新入口统一走Controlled（无flow也可），TLS1.3 ClientFinished真实通过再调用 `vless::handshake_with_flow`。复用现有TCP route/connect→reply→relay，原生UDP/XUDP与Vision分派；必要时只提取已有accepted分派的窄helper，不复制整个VLESS handler。完整握手期限后释放握手许可，connection许可保留到业务/回落实际结束。

| flow/命令 | 本批行为 |
|---|---|
| 无flow，TCP | 允许；route/DNS/connect成功后一次VLESS应答 |
| 无flow，原生UDP | 允许；仍现有VLESS数据报，复用Association预算/来源过滤 |
| 无flow，cmd3 | 仅xudp:true，现有UDP-only XUDP |
| Vision，TCP | 允许；一次VLESS应答后Vision原始流状态机 |
| Vision，cmd3 | 仅xudp:true；Vision后接xudp_body，不重复VLESS响应 |
| Vision，原生cmd2、TCP mux、未知flow | 按既有规则拒绝，不静默退无flow |

重新验证“最后TLS record+Direct同次到达”、prefix尾部、单向Direct、另向TLS/KeyUpdate、写背压不阻塞读、shutdown首次poll锁写、FIN/EOF。不能因同叫ServerConnection或使用aws-lc就继承旧Vision通过。

### D9. 资源、统计和测试分层

- 固定target连接/DNS及本地密码操作纳入accepted连接/握手配额；最多accepted数个辅助socket，握手阶段由`max_handshakes`限制。MLDSA每握手最多一次、配置密钥在准备时导入；若使用blocking任务，必须有限并发、被追踪且force后等待实际完成，不留取消后后台签名。
- TLS输入/输出和布局总量按D2/D7有限；fallback每向固定小缓冲（建议16KiB），没有无界mpsc；UDP复用旧全局byte/slot/queue/target/DNS限制，不按包派无限任务。
- stats业务计量只包在VLESS后的payload接口；target辅助/回落、TLS/VLESS/Vision/HMAC/MLDSA不计业务字节。日志只入口tag、阶段、错误种类和可核查结果，不写原始CH/SID/AuthKey/UUID/shortID/种子。拒绝只分类一次。
- stop停监听，drain保留已有连接到既有deadline，force取消accepted/pump/UDP并join，最后children.close/wait；准备失败、TLS失败、target失败与回落取消均需端口重绑/许可归还证明。

开发门禁按依赖连续推进：成熟库/补丁最小实验→配置/CH/auth/replay→证书/目标模板→Controlled/VLESS/Vision→资源/定向回归→文档。各步必要测试随开发，完整官方矩阵/三平台/精确MSRV/release后置。独立测试端不能调用生产auth/parser/certificate，固定向量需记录来源/生成工具摘要；安全库相同不是使用同生产编排。

集中矩阵先静态核对固定三家实际REALITY依赖/MLDSA选项/默认share与flow；当前仅Xray固定源码已核，不能预写Mihomo/sing-box各扩展都支持。执行前取得新官方范围许可（旧33项不覆盖），分别记录普通组/hybrid、无MLDSA/有MLDSA、无flow/Vision/TCP/UDP/XUDP、负向与IPv6。官方不支持和未到达本内核的客户端配置错误不是内核通过。

## Risks / Trade-offs

- [TLS握手补丁扩大安全维护面] → 仅四类加性接口、default off、全部普通入口回归、精确来源/差异/升级记录；旧安全审计不自动覆盖补丁。
- [目标模板长度装不下本地证书，尤其MLDSA] → 提交前验证布局和flight总量，使用受控可容纳/不可容纳peer；不能截断签名或以回落等价成功。
- [目标每连接额外socket/DNS成本及固定回落被滥用] → 先有界分类、认证成功先重放提交、固定单目标、连接/握手预算、idle/total期限、回落不升级为通用代理。
- [更严格时间/reserved/重复share/PSK策略偏离上游] → 独立schema、不声称同配置等价；固定客户端真实负向/默认矩阵，失败不私自关闭保护。
- [base64密钥或解析报错泄漏] → Secret及脱敏错误、测试捕获stdout/stderr/Debug；私有工件不整体公开。
- [先通过基础公共API实验后低估剩余工作] → 基础实验不勾完整握手/MLDSA/模板任务；任务以端到端行为而非代码存在计完成。
- [局部provider与Cargo feature合并影响旧入口] → 显式provider、cargo tree记录normal/build合并，真实旧TLS/Vision/VMess/SS回归；不误称仅新入口编译受影响。
- [被动时间回退或容量饱和拒绝合法用户] → 有界fail-closed且公开限制；不宣称永久防重放或无损可用性保证。

## Migration Plan

1. 本轮只交付规划；实施须后续实际请求进入apply。现有可执行文件与Cargo输入不在规划阶段改动。
2. 实施先通过依赖/补丁接口门禁，再加入新入口；旧配置无迁移要求。新增示例独立命名 `examples/vless-reality.json`，只给回环目标/占位密钥，替换后check/启动由自持peer验证。
3. 开发完成写本批命令、失败历史、生产/测试/vendor/lock摘要与“已实现待集中验收”；不使用磁盘旧release、不重命名旧报告为新结果。
4. 获准后的最终能力簇再运行官方矩阵、macOS/Linux ARM64/x86_64全量与vendor、精确Rust1.91、release，按同一最终输入记录通过/失败/ignored/缺口。容器恢复、外部二进制、部署发布均不由本规划自动授权。
5. 回退通过停用新入口/恢复本批补丁前依赖构建进行，不动系统代理/DNS/防火墙；这些是设计说明，不在本轮自动执行。无Git、自动归档或生产部署。
