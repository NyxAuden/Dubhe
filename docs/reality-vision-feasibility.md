# REALITY / Vision 入站互通可行性研究

研究日期：2026-11-04。范围：本项目未来的 REALITY 服务端与 `xtls-rprx-vision` 入站；不重复 VLESS v0 基础帧、无 flow TCP 或原生 UDP 的实现研究。本轮只读本地及上游源码，仅新增本文，未修改 Rust 实现或依赖，未下载、构建或运行外部可执行程序，未操作外部协议测试目标。

## 结论与证据强度

1. **不能据此宣称 rustls 无法实现 Vision。** `tokio-rustls 0.26.6` 公开底层 IO 与 `ServerConnection`，`rustls 0.23.46` 公开明文读取、手动 TLS IO 和 unbuffered 状态机。Vision 的关键是按方向切换外层 TLS、保全缓冲及保持写入顺序。已有 Rust 客户端采用“限制每次输入的 TLS record＋`AsyncBufRead`＋原始流访问”，构成可行的源码参考，但本项目尚未验证服务端互通。
2. **不能把 `TlsStream::get_mut()` 或 `into_inner()` 等同于安全完成切换。** 默认 TLS 读取可能越过 Direct 边界，提前处理属于内层 TLS 的后续字节；仅拿回 socket 无法找回已交给 rustls 私有密文缓冲的全部内容。必须从连接建立开始控制记录输入，并在每个解密结果后让 Vision 判断是否继续。
3. **REALITY 与 Vision 应分开验证。** REALITY 涉及 ClientHello 认证、特殊证书以及握手消息控制；Vision 涉及握手后的流状态机。普通 TLS 1.3 上先验证 Vision，不需要先实现 REALITY；REALITY 有效认证路径也可先在无 flow 下验证。
4. **REALITY 的一部分需求可由公共 API 外围组合表达，完整固定版本行为尚未证明。** 有界读取原始 ClientHello、外部认证、逐连接证书构造、随后将原始数据交给 rustls，是值得验证的服务端路径。公开 `ClientHello` 视图没有 raw/random/session-id/key-share 字节；原样采用上游 ServerHello 模板、按其记录布局输出，以及可选 ML-DSA-65 对 ClientHello/ServerHello 的绑定，没有找到直接等价的稳定配置钩子。这是当前接口缺口，不能扩大为任意公共 API 组合都不可能实现。
5. **本轮未确认可直接采用的成熟 Rust REALITY＋Vision 入站库。** 找到的项目包括实验性客户端、较旧的 rustls fork，以及 AnyTLS 上的 REALITY fork；范围、版本或认证实现均需单独核对。源码存在、README 宣称兼容、上游 TLS 库的审计记录，都不等于这些修改已经通过本项目固定 Xray 版本的互通与安全验证。

以上“已观察”指阅读固定源码所得；“候选路径”是设计判断；全文没有实测互通或性能结论。主会话的无 flow VLESS 基线可以独立推进，不能因本研究而提前接受 Vision flow 或宣称 REALITY 兼容。

## 1. 固定上游与依赖

Xray 基线是本项目研究选定的 `v26.10.31`、commit `a4a3dff5b20c2faae567b742c172c7b95e75c083`；本轮 [tag ref API](https://api.github.com/repos/XTLS/Xray-core/git/ref/tags/v26.10.31) 返回的 commit 与之相符。本轮直接获取该 commit 的 [go.mod][xray-mod]、[go.sum][xray-sum] 及下列实现文件；不把浮动 main 或旧版教程作为固定版本证据。

| 项目 | 已核查版本或事实 |
|---|---|
| Xray Go 版本声明 | `go 1.27` |
| Xray 选择的 REALITY | `github.com/xtls/reality v0.0.0-20261014101318-83f621788ca8` |
| REALITY 完整 commit | `83f621788ca88b83179810b12baa7ae518aacb83`，由 [GitHub commit API][reality-commit] 展开短 hash |
| Xray 选择的 uTLS | `github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af` |
| REALITY 自身的模块声明 | [go.mod][reality-mod] 声明 Go 1.27、uTLS `v1.8.2`；不能将这个较低声明误作 Xray 根模块选择的 uTLS 版本 |
| REALITY 的 go.sum 条目 | 模块 `h1:RjLnVvlzK4q6zWaSBPNRGsrgx2fbJDeUWffjw574uzs=`；go.mod `h1:ptlSkJ8k/7IDauNH0SA96JPOo+nYGLTv2Y3UMpwvAsY=`。本轮核对清单文本，未下载模块 zip 复算 |
| 本项目 TLS | `Cargo.lock` 锁定 rustls `0.23.46`、tokio-rustls `0.26.6`；`Cargo.toml` 和 `src/tls.rs` 显式采用 ring provider |
| 参考许可 | [Xray LICENSE][xray-license]：MPL-2.0；[REALITY LICENSE][reality-license]：MPL-2.0，另有 [LICENSE-Go][reality-go-license] 保留 Go 来源的 BSD 条款 |

REALITY 服务端由 Xray 的 `transport/internet/reality.Server` 调用 `github.com/xtls/reality.Server`；同文件的 `UClient` 使用 uTLS，是客户端路径。不能因为客户端需要 uTLS 内部状态，就推断 Rust 服务端必须实现相同的客户端钩子。

## 2. Vision 入站路径和底层流要求

### 2.1 入站选择与约束

已观察调用关系：

- [TCP listener `keepAccepting`][xray-tcp] 先建立 TLS 或 REALITY 包装，再交给入站；[REALITY transport `Server`][xray-reality] 委托固定 REALITY 依赖。
- [VLESS `Handler.Process`][xray-inbound] 的 flow 分支检查用户配置与请求是否匹配。对普通 TLS 要求外层 TLS 1.3；另有 REALITY 及 VLESS Encryption 分支。普通 TLS 1.2 的成功握手不足以满足该 Vision 分支。
- Vision flow 的原生 UDP 命令在此直接拒绝；Mux/XUDP 另有分支与限制。主会话拟实现的“无 flow 原生 UDP”不能顺带宣称“Vision UDP 已支持”。
- 该版本对普通 TLS、REALITY 使用 `vless.AccessTLSBuffers`，之后将 `VisionReader`/`VisionWriter` 接到 body reader/writer 与 dispatcher。VLESS Encryption 是另一承载分支，不纳入本文的首个 Rust 互通目标。
- 非 RAW 承载或特定额外包装会影响能否穿透到底层连接以及 `CanSpliceCopy` 状态。不能对任意 `AsyncRead + AsyncWrite` 对象默认承诺 Vision Direct 或 splice。

主要定位：`inbound.go` 的 flow 检查约在 548–607 行；[vless.go `AccessTLSBuffers`][xray-vless] 读取 `input` 和 `rawInput` 字段，并兼容旧式 `bytes.Buffer` 与新式 `*bytes.Buffer`。这是 Go 实现的私有字段访问方式，Rust 不需要照搬其内存布局。

### 2.2 Direct 切换是协议语义

[proxy.go][xray-proxy] 的 `VisionReader.ReadMultiBuffer`、`VisionWriter.WriteMultiBuffer`、`XtlsFilterTls` 与 `SuppressOuterCloseNotify` 给出以下事实：

- padding 命令有 Continue `0x00`、End `0x01`、Direct `0x02`。End 结束 padding；Direct 还会切换该方向的传输方式。不能把两者当成同一标志。
- 读取端在一个 Direct block 的内容及 padding 完整消费后，先保留当前解包输出，再合并 TLS `input` 中的已解密剩余数据、`rawInput` 中的预读原始字节，最后改读底层连接。
- 写入端先通过外层 TLS 发出包含 Direct 的最后一个 block，后续写入才进入原始连接。该版本还在原始写入完成后才将下行 splice 状态置为 ready，源码明确说明要避免并发直写竞争。
- 上下行有独立的切换标志。一边已 Direct、另一边仍使用外层 TLS，是必须能表达的状态，不能把整个双向连接一次性丢弃或替换。
- 切换后 Xray 抑制外层 TLS `close_notify`，直接关闭底层连接，避免把外层告警混入已经承载内层 TLS 的原始流。Rust 实现必须同样明确半关闭、取消和 flush 的所有权。
- Direct 的内层数据仍可能是端到端 TLS 密文；它不是“将用户内容明文发送”。`XtlsFilterTls` 检查内层握手和套件，`IsCompleteRecord` 等条件参与决定是否启用 Direct。非 TLS 或不满足条件的流仍需要正确结束 padding 并继续外层 TLS。

关键实现定位：reader 203–288 行，writer 326–407 行，内层识别 625–674 行，关闭及解包 677–730 行。本文不规定 padding 随机分布或部署策略，只记录互通所需状态和数据边界。

### 2.3 splice 只是另一层优化

`CopyRawConnIfExist` 在非 Linux/Android、连接类型不满足、任一相关状态禁止 splice 时调用普通 `readV`；条件满足时才调用 TCP 的 `ReadFrom` 路径。该提交还保留“启用上行 splice”的 TODO。

因此应分别验收：

1. Vision padding 和 Direct 状态机的字节正确性，包括原始流切换；
2. 用户态原始流复制的资源与生命周期正确性；
3. Linux splice 等平台优化的吞吐、CPU、取消、计数及回退行为。

“不实现 splice”可以是首版性能限制；“收到 Direct 后仍将所有数据交给外层 TLS”是协议错误，不能用同一个限制声明掩盖。macOS 上也能验证前两项，不能用 macOS 结果推断 Linux splice 性能。

## 3. REALITY 的实际握手需求

### 3.1 固定版本的认证与证书

已读固定依赖 [tls.go `Server`][reality-server] 和 [handshake_server_tls13.go `handshake`][reality-hs]，并以 Xray [`UClient` / `VerifyPeerCertificate`][xray-reality] 交叉核对：

- 服务端需要原始 ClientHello、random、session ID、key-share 字节和 SNI。认证涉及静态 X25519 私钥与客户端 key share 的共享秘密、HKDF-SHA256、AES-GCM，以及版本、时间、short ID 检查；这里的认证密钥不是直接从 TLS exporter 取得。
- **这个固定版本要求 key-share 列表先出现有效 X25519MLKEM768，再允许可选 X25519。** `tls.go` 215–239 行在缺少所需 hybrid share 时退出认证分支；可用普通 X25519 share 作为认证首选，否则使用 hybrid share 中的 X25519 部分。不能以早期“只支持普通 X25519”的实现证明本版本兼容，也不能把“要求提供 hybrid share”误写为“最后一定协商 hybrid 组”。
- 服务端生成使用 Ed25519 公钥的证书，将证书签名字段设置为基于 AuthKey 的 HMAC-SHA512；TLS CertificateVerify 仍由相应 Ed25519 私钥完成。Xray 客户端读取证书公钥与签名并进行该认证校验。只给 rustls 一个普通自签名证书不能替代此流程。
- 可选 ML-DSA-65 额外验证会绑定 ClientHello 和 ServerHello 原始消息。服务端在生成该证书扩展时使用这些消息；客户端配置了额外验证密钥时才执行对应验证。这个能力必须独立声明和测试，不能从基础 HMAC 证书路径推断已支持。

### 3.2 上游还做了更多 TLS 内部控制

固定 REALITY `Server` 建立另一条连接、保留收到的 ServerHello 和记录长度等信息，并在自己的握手中使用其 ServerHello 结构、替换 key share、生成自己的 TLS 密钥与证书。`tls.go` 约 315–383 行与 `handshake_server_tls13.go` 88–177 行显示，该路径已超出“标准 TLS 配置＋一个证书回调”。

这些是上游实现事实，不表示它们每一项都已被证明是有效认证客户端互通的最低必要条件。本文仅研究与受控客户端互通相关的 API 边界，不给出外部目标选择、流量外观调优或检测规避部署步骤。后续若验证依赖另一 TLS peer，应使用受控本地服务或离线夹具。

## 4. rustls 0.23.46 / tokio-rustls 0.26.6 API 对照

本节实际阅读本机 registry 对应版本源码，线上链接固定到同版本，避免引用 `latest`。

| 所需能力 | 已观察公共 API | 可表达范围与限制 |
|---|---|---|
| 获取承载流和 TLS 会话 | tokio-rustls 服务端 [`TlsStream::get_ref/get_mut/into_inner`][tokio-server] | 可以获得 IO 与 `ServerConnection`，不需要假设原始 socket 被永久隐藏；`into_inner` 本身不执行缓冲排空或协议切换 |
| 读取尚未交给业务层的明文 | rustls [`ConnectionCommon::reader`][rustls-conn] | 可以排空已解密数据；不能据此取出私有 `deframer_buffer` 中的全部原始密文字节 |
| 控制喂入 TLS 的字节 | [`read_tls/process_new_packets/write_tls`][rustls-conn] | 调用方可以提供只含一个 record 的输入并在处理后检查明文；需要自己实现有界异步驱动与输出排空 |
| 外部拥有输入缓冲 | [`UnbufferedServerConnection`][rustls-server]、[`process_tls_records` / `UnbufferedStatus::discard`][rustls-unbuffered] | 输入切片由调用方持有，处理后按 discard 移除已消费前缀；可在 ReadTraffic 后决定不再处理后续原始数据。不是自动完成 Vision，也不等于内核零拷贝 |
| 按记录交还明文 | tokio-rustls [`AsyncBufRead`][tokio-server] | 可用 `poll_fill_buf/consume` 避开普通 `poll_read` 的批量补读；还须在更底层限制每次喂给 rustls 的记录数量 |
| ClientHello 配置选择 | [`Acceptor` / `Accepted::client_hello/into_connection`][rustls-server]；tokio-rustls `LazyConfigAcceptor` | 可延迟选择逐连接配置；公开 ClientHello 只有 SNI、ALPN、套件、签名算法、named groups 等摘要，未公开 random/session ID/raw/key-share 载荷。外部预读解析并保留原文是另一路径 |
| 动态证书与签名 | [`ResolvesServerCert`][rustls-server]、[`CertifiedKey::new` / `SigningKey`][rustls-signer] | 可以传入自选 DER 证书与签名密钥；密钥一致性检查比较 SPKI，并非要求证书签名必须由公共 CA 签发。因此基础 REALITY 证书有可验证的注入路径；实际 Xray 接受结果未测 |
| 密码算法/组扩展 | [`CryptoProvider` / `SupportedKxGroup` / `ActiveKeyExchange`][rustls-crypto] | 可定制密码提供者；本项目 ring 的组列表只有 X25519/P-256/P-384。[aws-lc provider][rustls-aws] 提供 X25519MLKEM768。ring 限制不是整个 rustls API 的限制，切换 provider 也不会自动实现 REALITY |
| 任意 ServerHello 模板与握手记录布局 | 已核查 `ServerConfig`、server handshake 源码与上述扩展接口 | 未发现接受任意序列化 ServerHello 模板、替换 transcript 或在已有 ServerHello 后回调重建证书的直接公共接口。`max_fragment_size` 不是完整的记录布局控制接口；需要进一步最小实验或有界补丁设计 |
| 密钥导出 / kTLS | [`dangerous_extract_secrets` / `dangerous_into_kernel_connection`][rustls-server] | 后者存在于 unbuffered server API，并有使用前提；它们面向密钥接管，不自动处理 Vision Direct。Direct 复制内层密文通常不需要导出外层 TLS 密钥 |
| Direct 后关闭 | tokio-rustls `poll_shutdown` 调用 `send_close_notify`，见 [server.rs][tokio-server] | Direct 后不能无条件调用普通 TLS shutdown；需要在对应方向处理原始 IO 的关闭及尚未完成的另一方向 TLS 状态 |

### 4.1 默认 `TlsStream` 的具体预读问题

rustls `ConnectionCommon` 的 `deframer_buffer` 是私有字段。tokio-rustls [common `read_io`][tokio-common] 在 `read_tls` 后调用 `process_new_packets`；该处理可能消费输入中的多个完整 TLS record。如果最后一个外层 TLS record 与首批 Direct 数据一起到达，将它们全部交进去可能导致后者被误当作外层 TLS 解密。

此外，`tokio-rustls 0.26.6` 服务端 `AsyncRead::poll_read` 在还有调用方缓冲空间时，会继续调用 `poll_fill_buf` 补读。因此“底层每次只返回一个 record”仍不是充分条件：若调用方使用普通 `read`，它可能在 Vision 有机会看见 Direct 之前开始读下一个 record。

可执行候选有两种，均尚未在本项目实现：

- **保留 tokio-rustls：**从 TLS 握手前装入持有预读尾部的 record 限制包装，Vision 使用 `poll_fill_buf/consume` 消费明文并逐次判断；切换时排空会话明文，随后先读包装内保存的尾部，再读 socket。写端独立 flush，保留尚未切换方向的 TLS 状态。
- **自己驱动 rustls：**使用 `ServerConnection` 手动逐 record 输入，或使用 `UnbufferedServerConnection` 和自有输入/输出缓冲。每次处理获得明文后先推进 Vision 状态，再决定是否继续交给 TLS。unbuffered 中的 discard、借用释放、待发送 TLS 记录及错误状态都需要完整处理。

第一条改动范围可能较小，第二条更明确地控制数据所有权；优劣需由边界测试和维护成本决定。任意上层缓冲、统计包装或通用 `copy_bidirectional` 都必须经过该连接状态机，不能旁路读写。

### 4.2 REALITY 的最小验证路径

服务端可以先有界读取并保存 ClientHello，在 TLS 状态机外完成认证与必要字段解析，构造逐连接证书/配置，然后将**原始、未改写的握手字节**回放给 rustls。这样无需从 rustls 读取客户端临时私钥，也无需把客户端 uTLS 钩子机械移植到服务端。

“未启用 ML-DSA-65、使用普通 rustls TLS 1.3 ServerHello、但具有正确 REALITY 认证与证书”的有效客户端路径，是应优先证伪或证实的实验假设。尚未确认固定 Xray 客户端会完全接受该组合；也没有证明它与完整 REALITY 服务端行为等价。可选 ML-DSA、hybrid-only ClientHello、HRR、记录布局和握手后记录应分别测试。若需要 fork，只为实验证实的接口缺口设计最小补丁，不先假设所有需求都必须 fork。

## 5. 已找到的 Rust 实现与限制

以下均固定到本轮 GitHub API 返回的提交，只读选定文件，未运行其测试或检查发布二进制。这里的“许可”是项目元数据及已读许可文件的声明，不是对代码来源和组合分发的法律确认。尤其不能将 rustls 原项目的许可或审计结论自动覆盖所有 fork 新增代码。

| 项目与固定提交 | 已观察范围 | 许可及采用限制 |
|---|---|---|
| [undead-undead/rustls-reality][candidate-undead]，`cdae8d922a94ef8896df21da1eb13e6461315783` | rustls `0.22.0` fork，增加 `RealityConfig` 和服务端握手修改。[reality.rs][candidate-undead-code] 的认证是 Session ID 前 8 字节 HMAC-SHA256 比较，并向 ServerHello random 注入 HMAC；[tls13.rs][candidate-undead-tls] 实际调用这些函数。这与本轮固定 Xray 的 AES-GCM Session ID 认证和 HMAC-SHA512 证书认证不等价 | [Cargo][candidate-undead-cargo] 与 [LICENSE][candidate-undead-license] 声明 Apache-2.0 OR ISC OR MIT。README 明示 modified fork、不要用于通用 TLS。不能把名称或“支持 REALITY”描述作为固定版本互通依据，也不能直接替换当前 0.23.46 |
| [undead-undead/xray-lite][candidate-lite]，`0a531b025aeca9d7e0e19ecc39de57c8dba75f97` | README 宣称 VLESS＋REALITY＋XHTTP，同时明确“不带流控”；[Cargo][candidate-lite-cargo] 使用 rustls 0.22 / tokio-rustls 0.25，并 patch 到仓内 fork。读到的范围不能证明 Vision 入站 | [LICENSE][candidate-lite-license] 和 Cargo 为 MIT；仓内 fork 的具体来源与修改仍需独立追踪，不能将同作者独立 fork 的上述差异直接归到此仓所有路径 |
| [ssrlive/reality-rs][candidate-any]，`e71b6c20b0860d9fa9589862e81fa8869ed4fa7a` | REALITY 上的 AnyTLS 客户端和服务端；[server/reality.rs][candidate-any-code] 公开原始 ClientHello、认证所需字段和 ServerHello template 相关类型。库 [Cargo][candidate-any-cargo] 版本是 `0.24.0-dev.2`，不是当前 0.23 系列；未证明 VLESS/Vision 服务端 | 根 [LICENSE][candidate-any-license] 与 rustls 子包声明 Apache-2.0 OR ISC OR MIT。[anyreality/Cargo.toml][candidate-any-app] 未声明独立 license 字段，应用新增部分的许可适用范围应在复用前澄清。README 后半保留上游 rustls 的生产使用说明，不能当作 fork 已成熟的证据 |
| [ERGFT/vpn-core][candidate-vpn]，`991ec20d9da729f4eeeea02ef1ce3aa5d8898680` | README 自称实验性客户端；[vision.rs][candidate-vpn-vision] 实现 Direct、外层 TLS flush、`poll_fill_buf`、明文排空；[raw.rs][candidate-vpn-raw] 控制 record 输入并保存预读尾部。vendor 的 rustls 版本恰为 0.23.46，提供重要的架构参考，但它是客户端，不是本项目可直接复用的入站库 | [workspace Cargo][candidate-vpn-cargo] 为 GPL-3.0-or-later；[vendor Cargo][candidate-vpn-rustls] 声明 Apache-2.0 OR ISC OR MIT。当前项目许可证未定，不能直接复制 GPL 模块。[Go REALITY 互通测试源码][candidate-vpn-tests] 使用独立 Go 测试程序且 `#[ignore]`，本轮未执行，不能据测试文件存在断言本项目或固定 Xray 完整互通 |

其中 vpn-core 对 `poll_fill_buf` 的使用与本地 tokio-rustls 批量 `poll_read` 源码相互印证，说明“公共流接口＋受控 record 输入”有具体参考代码。它依赖的 rustls fork 也承担 REALITY 客户端钩子；不能反过来得出 Vision 本身一定需要该 fork。

本轮搜索覆盖这些相关来源，不是全网穷尽调查；“未确认成熟实现”不等于“Rust 社区没有实现”。未确定的范围继续标为未确认。

## 6. 可执行的后续工作与验收门槛

| 顺序 | 工作 | 完成标准 |
|---|---|---|
| 1 | 保持基础 VLESS 与 flow 扩展边界明确；新增专门的可切换传输设计，不把能力隐含在通用流 trait 中 | 未实现的 flow/承载组合被明确拒绝；无 flow TCP/原生 UDP 的能力声明独立；设计写清上下行 TLS 状态、原始 IO、输入尾部、输出队列、关闭及统计的唯一所有者 |
| 2 | 使用现有 rustls 0.23.46，在本地内存流/回环流做 Vision record 边界实验，对比“record 包装＋AsyncBufRead”和手动/unbuffered 驱动 | 构造“最后一个外层 record＋Direct 原始数据”同一次到达、任意分片及合并；逐字节验证不丢失、不重复、不越界解密；覆盖 Continue/End/Direct、仅一个方向 Direct、短写和背压 |
| 3 | 在普通 TLS 1.3 上实现并验证独立 Vision 状态机 | 受控非 TLS、内层 TLS 1.2、内层 TLS 1.3 数据分别走正确路径；响应与 Direct 写入顺序、另一方向继续 TLS、取消/FIN/EOF/关闭不注入错误外层告警；先使用用户态复制 |
| 4 | 用固定源码生成或整理本地 REALITY 认证与证书测试向量，再验证公共 API 的最小服务端候选 | 正/负认证向量覆盖 short ID、时间/版本、认证标签和畸形 ClientHello；含 hybrid share 与可选 X25519 组合；证书认证与 CertificateVerify 分别验证；结果明确区分“基本认证通过”和“完整固定版本兼容” |
| 5 | 只针对步骤 4 暴露的缺口评估 provider 或最小 fork；单独处理 ML-DSA-65 和 ServerHello/transcript 需求 | 写出所需钩子、调用时机、秘密数据边界、可复现失败用例和升级成本；核对许可与补丁来源；不把更换 ring、提取 TLS secrets 或换 fork 当作自动完成协议支持 |
| 6 | 完成功能后再做固定版本端到端与性能验收 | 后续授权测试阶段使用受控本地 TLS peer 和固定 Xray 客户端；本轮不运行外部程序。分别记录无 flow REALITY、TLS＋Vision、REALITY＋Vision 的客户端构建/配置/结果。最后单独测 Linux splice，与用户态复制对照，不以吞吐替代正确性 |

必要边界测试还包括：padding 头/正文/尾部跨 record、零有效载荷、TLS post-handshake 消息、待发 ticket/KeyUpdate 与 Direct 的顺序、握手后取消、非 RAW 包装被拒绝或正确保留语义。对 malformed 输入应设置长度/时间预算，不将无界缓存作为预读问题的修复。

## 7. 仍未验证的问题

- 上述公共 API 组合的服务端实现能否通过固定 Xray `a4a3dff…` 客户端的完整认证、证书验证与后续读写；本轮只有源码证据，没有互通结果。
- 基础 REALITY 有效连接是否只需认证＋特殊证书＋标准 TLS 1.3，即能与固定客户端互通；上游其他握手行为的最低必要范围尚未实测。
- 可选 ML-DSA-65 证书绑定能否由稳定公共接口组合表达；目前没有确认方案，也没有证明必须改 rustls 核心。
- hybrid-only、hybrid＋普通 X25519、HRR、分片 ClientHello 等组合是否被候选路径完整处理；本项目 ring provider 不具备 hybrid 算法，但其他 provider 可用性和升级代价未在本项目验证。
- 单向 Direct 期间并发读写、TLS 控制消息、半关闭与取消的完整状态机；`into_inner()` 不能代替这些证明。
- 所列 Rust fork 的全部补丁、真实发布质量、CI 执行结果、长期维护、安全修复追踪以及源码许可证来源链；本轮不作成熟度或安全认证。
- splice 的实际收益、平台支持、统计和退出语义；尚未做性能测试，不能以“零拷贝”作为本阶段能力声明。

本轮主要固定源码均联网读取成功。一次尝试访问 vpn-core 的 `vendor/rustls-reality-patch/REALITY-PATCH.md` 返回 404，未将这个未取得文件作为补丁范围或许可证证据；其余未验证项均如上保留，不以推测补齐。

本文引用链接均固定到提交或 crate 版本。rustls/tokio-rustls 的两个代表性 docs.rs 源码链接已确认返回 HTTP 200，具体 API 结论以本地锁定版本源码阅读为依据。

[xray-mod]: https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/go.mod
[xray-sum]: https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/go.sum
[xray-license]: https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/LICENSE
[xray-tcp]: https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/tcp/hub.go#L90-L119
[xray-inbound]: https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/inbound/inbound.go#L548-L627
[xray-vless]: https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/vless.go#L21-L32
[xray-proxy]: https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/proxy.go
[xray-reality]: https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/reality/reality.go
[reality-commit]: https://api.github.com/repos/XTLS/REALITY/commits/83f621788ca8
[reality-mod]: https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/go.mod
[reality-license]: https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/LICENSE
[reality-go-license]: https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/LICENSE-Go
[reality-server]: https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/tls.go
[reality-hs]: https://github.com/XTLS/REALITY/blob/83f621788ca88b83179810b12baa7ae518aacb83/handshake_server_tls13.go
[rustls-server]: https://docs.rs/crate/rustls/0.23.46/source/src/server/server_conn.rs
[rustls-conn]: https://docs.rs/crate/rustls/0.23.46/source/src/conn.rs
[rustls-unbuffered]: https://docs.rs/crate/rustls/0.23.46/source/src/conn/unbuffered.rs
[rustls-signer]: https://docs.rs/crate/rustls/0.23.46/source/src/crypto/signer.rs
[rustls-crypto]: https://docs.rs/crate/rustls/0.23.46/source/src/crypto/mod.rs
[rustls-aws]: https://docs.rs/crate/rustls/0.23.46/source/src/crypto/aws_lc_rs/mod.rs
[tokio-server]: https://docs.rs/crate/tokio-rustls/0.26.6/source/src/server.rs
[tokio-common]: https://docs.rs/crate/tokio-rustls/0.26.6/source/src/common/mod.rs
[candidate-undead]: https://github.com/undead-undead/rustls-reality/blob/cdae8d922a94ef8896df21da1eb13e6461315783/README.md
[candidate-undead-code]: https://github.com/undead-undead/rustls-reality/blob/cdae8d922a94ef8896df21da1eb13e6461315783/rustls/src/reality.rs
[candidate-undead-tls]: https://github.com/undead-undead/rustls-reality/blob/cdae8d922a94ef8896df21da1eb13e6461315783/rustls/src/server/tls13.rs
[candidate-undead-cargo]: https://github.com/undead-undead/rustls-reality/blob/cdae8d922a94ef8896df21da1eb13e6461315783/rustls/Cargo.toml
[candidate-undead-license]: https://github.com/undead-undead/rustls-reality/blob/cdae8d922a94ef8896df21da1eb13e6461315783/LICENSE
[candidate-lite]: https://github.com/undead-undead/xray-lite/blob/0a531b025aeca9d7e0e19ecc39de57c8dba75f97/README.md
[candidate-lite-cargo]: https://github.com/undead-undead/xray-lite/blob/0a531b025aeca9d7e0e19ecc39de57c8dba75f97/Cargo.toml
[candidate-lite-license]: https://github.com/undead-undead/xray-lite/blob/0a531b025aeca9d7e0e19ecc39de57c8dba75f97/LICENSE
[candidate-any]: https://github.com/ssrlive/reality-rs/blob/e71b6c20b0860d9fa9589862e81fa8869ed4fa7a/README.md
[candidate-any-code]: https://github.com/ssrlive/reality-rs/blob/e71b6c20b0860d9fa9589862e81fa8869ed4fa7a/rustls/src/server/reality.rs
[candidate-any-cargo]: https://github.com/ssrlive/reality-rs/blob/e71b6c20b0860d9fa9589862e81fa8869ed4fa7a/rustls/Cargo.toml
[candidate-any-license]: https://github.com/ssrlive/reality-rs/blob/e71b6c20b0860d9fa9589862e81fa8869ed4fa7a/LICENSE
[candidate-any-app]: https://github.com/ssrlive/reality-rs/blob/e71b6c20b0860d9fa9589862e81fa8869ed4fa7a/anyreality/Cargo.toml
[candidate-vpn]: https://github.com/ERGFT/vpn-core/blob/991ec20d9da729f4eeeea02ef1ce3aa5d8898680/README.md
[candidate-vpn-vision]: https://github.com/ERGFT/vpn-core/blob/991ec20d9da729f4eeeea02ef1ce3aa5d8898680/core/src/vless/vision.rs
[candidate-vpn-raw]: https://github.com/ERGFT/vpn-core/blob/991ec20d9da729f4eeeea02ef1ce3aa5d8898680/core/src/transport/raw.rs
[candidate-vpn-cargo]: https://github.com/ERGFT/vpn-core/blob/991ec20d9da729f4eeeea02ef1ce3aa5d8898680/Cargo.toml
[candidate-vpn-rustls]: https://github.com/ERGFT/vpn-core/blob/991ec20d9da729f4eeeea02ef1ce3aa5d8898680/vendor/rustls-reality-patch/Cargo.toml
[candidate-vpn-tests]: https://github.com/ERGFT/vpn-core/blob/991ec20d9da729f4eeeea02ef1ce3aa5d8898680/core/tests/interop_go_reality.rs
