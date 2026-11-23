# REALITY 开发阶段记录（已实现待集中验收）

日期：2026-11-05；变更 `add-reality-vless-inbound`。第1–6组 **21项开发任务已完成，整体21/29**；第7–9组8项官方客户端、平台、精确MSRV、release和最终报告集中验收仍未执行。因此状态为“已实现待集中验收”，不是整个变更 all_done。以下暂停/失败段保留当时历史，最新结论由本批31条真实命令和同一输入快照支持，不能用规划、元数据解析或旧构建替代。

## 初始开发断点（历史）

- 根 Cargo 加入精确 aws-lc-rs `1.19.0`、生产 rcgen `0.13.2`、精确 rustls `0.23.46` 及局部 aws-lc provider；随后为本地最小补丁加入 `vendor/rustls` patch 与 `reality` feature。普通 TLS 的局部 ring 选择尚未改动，但新补丁仍未通过验证。
- 配置、有限 ClientHello 与 vendor 握手接口正在编写，尚未接入运行器；没有真实 REALITY 业务通过证据。独立测试端仅完成部分公开 API 研究，不能称为已实现客户端。
- 本机可用空间检查约 56 GiB；未清理缓存或删除任何文件。

## 实际构建失败

执行：

```sh
cargo check --offline -p dubhe --lib
```

退出码 **101**。新增 aws-lc-rs/rustls/rcgen 等依赖已编译，根 package 在并行编辑窗口报错：

- `E0583`：当时 `src/config/reality.rs` 尚未写入。
- `E0004`：`src/runtime.rs` 尚未覆盖新增 `Inbound::VlessReality`。

此命令发生在根 manifest 加入本地 rustls patch 之前，不能作为受补丁 rustls 编译通过的证据。上述是历史输出，不表示后来写入的文件仍不存在；没有用空模块、`todo!` 或删除新枚举绕过错误，也没有把中间编译失败写成通过。

## 安全依赖门禁暂停

静态审查发现已有生产锁中的 `time 0.3.45` 受 `RUSTSEC-2026-0009 / CVE-2026-25727` 影响，涉及不可信 RFC2822 输入的递归栈耗尽，公告修复范围为 `>=0.3.47`。它在本批前已经是生产依赖，不是 REALITY 首次引入；尚未发现项目对受影响 RFC2822 解析的调用证据，但不能因此宣称无受影响依赖或门禁通过。

并行实施均已保存断点并暂停扩写/构建。进一步静态核查：生产 `time` features 为 alloc/formatting/parsing/std，受影响解析实现确实编入，不能称“未编译”。当前 tracing-appender 使用固定年月日格式，rcgen/yasna 使用日期/ASN.1 时间，根源码及 SS vendor 未发现 RFC2822 调用；此为未见可达，不是漏洞豁免。

最小修复候选为 time `0.3.47`、time-core `0.1.8`、可选 time-macros `0.2.27`，以及 num-conv `0.2.0`。前三者声明 Rust `1.88`、num-conv 声明 `1.57`，均不高于项目 `1.91`；官方索引/归档摘要已比对、未撤回，许可 MIT OR Apache-2.0。尚未实际构建这些修复版本；未更新 `time`，未豁免公告，未自行扩大核心依赖更新范围。候选原始证据位于私有 `.test-artifacts/reality-dependency-static-k9szRE/baseline/time-update-candidate.json`，完整静态门禁由独立报告记录。

暂停时相对上批 VMess 输入快照发生变化的原文件为 `Cargo.toml`、`Cargo.lock` 和 `src/config.rs`；新配置、hello/auth 与 vendor 钩子只是未验证初稿，replay、TLS 状态机接通、独立客户端及运行器尚未完成。当前工作树不能当作已可构建交付；上批摘要仍只证明其原输入，不能覆盖这些新变更。

## 获准修复并恢复开发

用户实际选择“允许修复并继续（推荐）”后，只更新获准四包：`time 0.3.47`、`time-core 0.1.8`、`time-macros 0.2.27`、`num-conv 0.2.0`。Cargo 首次自动选择 num-conv 0.2.2，随后精确纠正为获准的 0.2.0；保留这一历史。逐包锁差异除四包版本外，仅含此前批准的 rustls 同版本 registry→path 来源切换。`cargo fetch --locked`、离线 metadata 和 locked/offline tree 均成功，最终锁摘要 `a6f70121acafa096472034013e9572754f8ad2d5adbd8a638a1f0507a3a4b2cd`。这些不是代码编译或互通证据。

恢复后，受补丁 `cargo check --locked --offline -p rustls --lib` 通过。配置定向测试的真实首次编译仍退出 101，阻塞为运行器尚未穷尽处理新入口；尚未执行测试，不以依赖编译成功代替根项目通过。配置/hello/auth/replay、有限 TLS 钩子和独立测试端继续实施，生产证书、固定目标与运行器正在接入。先前暂停段保留当时事实，不代表现在仍等待授权。

## 已实现的开发能力

- 严格配置6项、hello8项、auth4项、replay7项及target10项已在根locked/offline单元测试实际执行；配置全回归44项通过。精确重放跨入口等价公钥、最大窗、取消保留及满池零辅助拨号另有集成验证。
- vendor rustls13项真实TLS/独立record解密/transcript/KeyUpdate/普通ring TLS1.2/1.3测试通过；feature完全关闭构建及128文件来源补丁复现通过，完整证据见 `vendor/rustls/REALITY-SOURCE.txt`。上游发布crate缺testdata、非workspace成员，不能称上游全库单测通过。
- 独立测试端6项通过，默认1项Python跨库门禁ignored；该跨库测试另显式执行1项通过，cryptography50.0.2与AWS-LC同seed公钥、pure/空context签名双向验证。默认ignored仍不计通过。
- `tests/reality_inbound.rs`新增8项业务/示例全部通过，连同共用peer自测为14 passed/0 failed/1 ignored；覆盖普通/混合组、两认证share/MLDSA组合、TCP首载荷/server-first/半关闭/计量、IPv4/IPv6原生UDP、XUDP、Vision双向Direct及真实内层TLS1.2/1.3。该文件引用共用自测，不能把重复执行数量说成不同场景。
- `tests/reality_fallback.rs`新增5项/15子场景通过：长度不足及8类不兼容SH使用原target、半record超时连续回放、损坏ClientFinished/EOF及错误UUID/flow不重新回落；唯一原连接/原文恰一次和零业务均有观察。
- 资源测试已验证自持阻塞DNS下三种UDP预算/有限children、坏UUID/Reject先于业务DNS、同时5承载4关联强停join及真实映射端口重绑；新入口路由拒绝只分类一次，旧入口既有统计语义保持。
- 新承载Vision KeyUpdate/下行背压仍能上行/真实截断、逐字节密文与close_notify集成4项通过。精确Pending/短写/shutdown承载单元3项、不可逆提交单元3项通过；首写Pending/短写后关闭回落选项，首次shutdown Pending后拒绝late写且不增加计量。高级UDP6项验证来源过滤、超限即时拒绝、跨目标/代次/GlobalID隔离、逐帧TCP拒绝及额度释放，IPv6实际执行，无skip。

后续真实失败仍保留：独立端aes-gcm0.11五处nonce切片类型已修为固定12字节引用；业务测试Vec的extend引用类型推断改extend_from_slice；测试MutexGuard跨await改块作用域，Copy组不再clone。hello取消测试原误假设单poll会耗尽输入，已按Tokio协作预算修测试；DNS单测原用.invalid被本地规则提前拒，改自持.test。提交短写测试原对第二次续写也断言TLS头，修为只断言首poll；这些不改变生产安全边界。并行新增模块尚未落盘期间有E0583失败，未伪造空文件绕过。

## 最终开发门禁与证据映射

全部31条命令在同一根目录/同一生产和测试输入执行，退出码均为0。私有目录 `.test-artifacts/reality-dev-a96lm8_o/` 保存 `final-commands.json`（逐命令参数、退出码、时长、日志SHA256）、`final-01.log` 至 `final-31.log`、`inputs.json` 和运行/快照脚本。末轮后再次逐文件核对快照及全部日志摘要，输入无漂移。不要整体公开该目录。

| 命令范围/日志 | passed | failed | ignored |
|---|---:|---:|---:|
| config:: / final-04 | 44 | 0 | 0 |
| tls::（含REALITY35、旧TLS10） / final-05 | 45 | 0 | 0 |
| protocol::vless:: / final-06 | 18 | 0 | 0 |
| protocol::vision:: / final-07 | 23 | 0 | 0 |
| protocol::vmess:: / final-08 | 49 | 0 | 0 |
| runtime::（含新资源2和peer6） / final-09 | 22 | 0 | 1 |
| udp:: / final-10 | 23 | 0 | 0 |
| reality独立peer / final-11 | 6 | 0 | 1 |
| reality_inbound / final-12 | 14 | 0 | 1 |
| reality_lifecycle / final-13 | 19 | 0 | 1 |
| reality_fallback / final-14 | 11 | 0 | 1 |
| reality_boundaries / final-15 | 10 | 0 | 1 |
| reality_udp / final-16 | 12 | 0 | 1 |
| 旧Vision/VLESS/XUDP/VMess集成 / final-17..20 | 9+7+7+16 | 0 | 0 |
| resources/CLI/examples / final-21..23 | 7+14+1 | 0 | 0 |
| SS配置/依赖/UDP及旧SOCKS/Trojan / final-24..27 | 5+22+3+9 | 0 | 0 |
| 指定根package目标执行合计 | **396** | **0** | **7** |
| 显式MLDSA Python↔AWS跨库 / final-28 | 1 | 0 | 0 |
| rustls独立record/TLS/默认路径 / final-29 | 13 | 0 | 0 |

合计为 **410次测试执行通过、0失败**，不是410个不同测试场景：common REALITY peer的6项自测在runtime和6个集成目标内重复注册。7个默认ignored均是同一显式Python跨库门禁的重复注册，不计为通过；另在final-28中实际显式执行该门禁1项通过。没有运行33项官方ignored矩阵，不能把它们算入本轮，也不能将396称为全量 `cargo test --all-targets`。

其余命令：final-01根package fmt、final-02 locked/offline all-targets check、final-03严格Clippy均通过；final-29 runner另实际验证reality feature完全关闭的ring/std/tls12构建；final-30在独立新空目录复现官方归档+补丁，128个结果文件摘要匹配；final-31 OpenSpec strict通过。vendor/rustls内冻结evidence没有覆盖，末轮日志写入主线工件目录，避免破坏PATCHED.json复现。

复现命令形态（每个filter/target分别一条，不把cargo多个filter并写）：

```sh
cargo fmt -p dubhe --check
cargo check --locked --offline -p dubhe --all-targets
cargo clippy --locked --offline -p dubhe --all-targets -- -D warnings
cargo test --locked --offline -p dubhe --lib tls:: -- --nocapture
cargo test --locked --offline -p dubhe --test reality_inbound -- --nocapture
cargo test --locked --offline -p dubhe --test reality mldsa65_python_cryptography_cross_verifies_aws_lc_both_directions -- --ignored --nocapture
python3 -I vendor/rustls/run-tests.py --root $PROJECT_ROOT
# verify-source的--empty-dir必须每次选择新的空目录，不能复用上次结果。
openspec validate add-reality-vless-inbound --strict --no-interactive
```

| 开发任务 | 实际证据 |
|---|---|
| 1.1 | [依赖静态门禁](reality-dependency-gate.md)、四包获准修复、final-02实际locked编译；不冒称精确1.91/完整最终审计 |
| 1.2 | auth独立SID金样、peer独立DER/HMAC/CV、final-28同seed公钥/跨库双向签名；无外部内核 |
| 1.3、3.2、3.4 | vendor精确来源/默认关闭、final-29真实KX/三suite/两布局/独立transcript/零padding/空app/AEAD边界/KeyUpdate/普通TLS，final-30补丁复现 |
| 2.1 | config6新测及44全配置、旧入口证书语义/秘密脱敏、CLI check |
| 2.2–2.4 | hello8/auth4/replay7、lifecycle跨入口等价key最大窗/取消/满额零target；畸形/PSK/early_data硬关闭 |
| 3.1、3.3 | 生产rcgen远程HMAC签名值与真实SigningKey分离；独立peer首扩展与CH/最终SH/密钥/签名篡改，inbound普通/混合及MLDSA真实Finished/业务 |
| 4.1 | target10单测、自持普通/混合target及opaque分离布局；DNS/自环/取消保存/超限，非公网 |
| 4.2–4.3 | 提交3单测、fallback5/15子场景、lifecycle认证失败/唯一target/原文恰一次/idle+total/强停；提交后Finished/UUID错误不回落 |
| 5.1 | inbound无flowTCP/首载荷/server-first/半关闭、runtime坏UUID及Reject先于业务DNS/目标/应答；辅助IO不计业务 |
| 5.2 | inbound及udp6新增：原生/UDP-only XUDP/Vision、IPv4/IPv6、多会话目标/来源过滤/代次/GlobalID隔离/逐帧拒TCP/空包及载荷计量。**2026-11-06：命令 3 已改为完整 Mux，TCP New 合法、GlobalID 进程级接管；本行为历史开发记录，见 [Mux 说明](mux.md)。** |
| 5.3 | inbound真实内层TLS1.2/1.3/双向Direct，boundaries4及controlled3：单record尾部/首raw、KeyUpdate、短写Pending、背压读进展、shutdown拒写、半关闭和真实TLS截断 |
| 5.4 | lifecycle13、runtime2：混旧入口共享连接/握手/UDP/排队预算，阻塞DNS/target、五承载force/join/children屏障、映射/监听重绑与秘密零输出；密码运算同步有界，无遗留blocking任务 |
| 6.1 | 同输入final-01..31全部退出0，旧路径定向回归重新执行，不沿用旧106/209/262/33 |
| 6.2 | [说明](reality.md)、独立回环占位模板，替换后真实CLI check/启动/Vision数据见inbound示例测试；本地文档链接检查无缺失 |
| 6.3 | 本映射、输入逐文件快照/工具链/上游来源、任务核对及strict；开发完成仅21/29 |

## 最终开发输入

`inputs.json`按路径排序，对每项 `sha256 + 两空格 + 相对路径 + 换行` 的UTF-8串再SHA256；这是文件集合标识，不是Git提交或release。生产源码内嵌测试按整文件哈希，独立tests.rs/*_tests.rs及tests目录另列。vendor列全部普通文件，包括原许可、补丁、测试、脚本和冻结evidence。

| 集合 | 文件数 | SHA256 |
|---|---:|---|
| 自有生产输入（含Cargo） | 44 | `5af922c10829434e146965ae2975b5ada2364c252a3350b3a6403df1604528e9` |
| 独立测试输入 | 37 | `2a0ce73bc24e32bd946b0e161f4937e1061a623b1a06d182a4a75c7d159c343d` |
| 示例JSON | 10 | `993acd4185069bb5d6acc0f0715982aa56343154419c1ece88ae732ca04d2ac4` |
| Shadowsocks vendor全部文件 | 70 | `492837defd4f266f99673ca2521a744e92ab943f903b9712a65d4d101e4f44f1` |
| rustls vendor全部文件 | 131 | `0abf965a58a0e663e3c0df2a13c5e42e63d0fa7c00da494f18e041d0321a03f5` |
| Cargo.lock | 1 | `a6f70121acafa096472034013e9572754f8ad2d5adbd8a638a1f0507a3a4b2cd` |

环境：macOS ARM64，rustc1.95.0/cargo1.95.0，OpenSpec1.12.0。磁盘末轮约50GiB可用，未清理/删除文件。Xray与REALITY固定版本见[协议说明](reality.md)，rustls原归档SHA256 `48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`。

## 与官方客户端互通时的 target 约束（2026-11-22 实测）

服务端 `reality.target` 必须是**完整 TLS 1.3 服务端**，且满足三条硬约束，
否则官方客户端会在 target 侧断开（表现为 `UnexpectedEof`）：

1. **证书签名算法必须是 ECDSA 或 RSA，不能是 Ed25519。**
   官方 Xray 客户端用 uTLS 的 Chrome fingerprint，其 `signature_algorithms`
   扩展只声明 ECDSA/RSA 系列。用 Ed25519 证书做 target 时 rustls 找不到共同
   签名算法，握手直接断开。
   `tests/common/reality.rs` 的 `TargetOptions::cert_alg` 提供
   `TargetCertAlg::EcdsaP256` 供此类用例显式选择；默认仍为 Ed25519，
   不影响本机回环测试。
2. **ServerHello 必须回显客户端提供的 32 字节 session_id**（Xray 依赖）。
3. **flight 形状必须落在 `RecordPlan` 可表达范围内**
   （`vendor/rustls/src/server/reality.rs`）。因此 OpenSSL `s_server`
   不能直接当 target——实测报「REALITY 目标模板截断」。

   具体规则（`RecordPlan::new`）：**首条加密记录 `> 512` 字节时必须是
   1 条聚合记录；否则必须正好 4 条**（EE / Certificate / CertificateVerify
   / Finished）。这条边界极易踩中：rustls 的紧凑 flight 在某些证书尺寸下
   会发出**恰好 512 字节**的首记录，落进「必须 4 条」分支却只发了 1 条，
   于是 `collect_template` 一直等第 2 条直到握手超时——表现为约 50% 的
   连接失败，且成功与否取决于证书与 ServerHello 的实际长度（同一配置
   重复执行结果不稳定）。

   测试侧的做法是给 target 证书加足量非关键扩展（
   `tests/reference_clients.rs` 的 `REALITY_TARGET_CERT_PADDING`），
   把首条记录稳定推到 512 以上。**不要改 `RecordPlan` 的校验来绕过**：
   该规则来自上游 flight 形态，真实 CDN 满足它。

target 不需要公网可达：用本内核自己的 `trojan` 入站（ECDSA 证书、独立端口）
即可。注意 `src/config/reality.rs` 的自环检查会拒绝 target 与任一监听器
地址+端口相同（含回环别名同端口），且 target 必须监听具体 IP 而非泛洪地址。

## 未执行与公开边界

第7–9组8项仍未完成：本批三家官方客户端/组合能力静态矩阵与实际互通、能力簇macOS全量、Linux ARM64/x86_64、精确Rust1.91、release及最终验收结论。官方执行前须另取本批许可；不沿用旧33项授权。Vision保持18/27、VMess21/30，各9项集中验收同样未完成。

没有运行外部内核/官方客户端、恢复容器、Git 操作、归档、发布、部署或系统网络/权限修改。既有 VMess/Vision/SS报告保持原始输入范围，不冒充本批通过；本批旧路径定向回归使用本批新输入，仍不扩大为旧官方矩阵已重跑。独立客户端、可容纳的自持target和内部密码金样不等于三家官方客户端完整兼容或安全审计/生产容量保证。

## 增量：REALITY 出站（2026-11-10）

服务端批次21/29不变。新增 `vless`/`vmess`/`trojan` 的 REALITY 出站：vendor rustls 增加默认关闭的客户端 SID 钩子与 `reality_auth_key` 加性方法；根项目新增 `src/tls/reality_client.rs`，使用自定义 X25519/X25519MLKEM768 KX、AES-256-GCM SID 编码、HMAC-SHA512 临时证书校验与 TLS1.3 Ed25519 CertificateVerify 校验；直接依赖新增 `x509-parser =0.18.1`（`default-features=false`）。配置校验允许 `reality` 与 `vless`/`vmess`/`trojan` 组合，与 `tls` 互斥；VLESS Vision flow 可与 REALITY 组合，拒绝 QUIC/mKCP 等底层承载；`trojan` 的强制安全层放宽为 TLS 或 REALITY。

实际命令与结果：

```sh
cargo check --locked --offline --all-targets                 # 退出0
cargo test --locked --offline --lib config::                 # 94 passed
cargo test --locked --offline --test reality \
  --test reality_boundaries --test reality_composition \
  --test reality_fallback --test reality_inbound \
  --test reality_lifecycle --test reality_udp \
  --test reality_outbound --test outbound_transport_config   # 全部通过
cargo test --locked --offline --test outbound_protocols \
  --test outbound_udp                                        # 17 + 13 passed
python3 -I vendor/rustls/verify-source.py --archive <rustls-0.23.46.crate> --empty-dir <新空目录>  # 129文件补丁复现通过
```

`tests/reality_outbound.rs` 实际为 12 passed、1 ignored：VLESS 纯 TCP 分别对 X25519 与 X25519MLKEM768 target、VLESS Vision+REALITY、VLESS 原生 UDP、VLESS/VMess/Trojan REALITY-over-gRPC，以及配置负例（含 WS/HTTPUpgrade 拒绝）；ignored 是既有显式离线 ML-DSA Python 门禁。格式化后全量普通套件实际为 **1061 passed、0 failed、42 ignored**（`cargo test --locked --offline`，`CARGO_INCREMENTAL=0`），随后删除 `target/debug/incremental` 约5 GiB；测试二进制与依赖构建保留供复验。vendor 补丁 `patch_sha256` 现为 `15193093491f58b3f7fa3b04f6371a580fbded8ac8d2ccf223d016681b2e1b4d`，`PATCHED.json` 共129个文件；旧服务端批次输入哈希表不覆盖本增量，不能作为本增量最终输入快照。该哈希是本批输入的历史记录；该 9deec061 哈希是 ShadowTLS v3 出站批次的历史快照；官方 Xray REALITY 互通批次又修改了 Ed25519 CertificateVerify 与目标 record 尺寸策略，当前 `vendor/rustls/PATCHED.json` 的 `patch_sha256` 为 `6d99dfe20b82aa8da8c8b0ed697d75e8539577e5d109afc444d18eadd8ee951b`。复验时以当前文件和独立空目录复现结果为准，不能把历史哈希混作同一快照。

**2026-11-10 校正**：Xray 官方 REALITY 只支持 RAW、XHTTP、gRPC。此前本仓库把 REALITY 组合到 WebSocket/HTTPUpgrade 并以其回环作为证据，属于非上游扩展；现已从入站与出站配置中移除，`tests/reality_composition.rs` 改为校验 gRPC/XHTTP 接受、WS/HTTPUpgrade/H3 拒绝，原 `vless-ws + REALITY` 数据面测试不再作为兼容证据。VMess/Trojan + REALITY 本身仍在上游支持矩阵内（RAW/XHTTP/gRPC），不是本项目自创。

未执行：与 Xray 等官方服务端/客户端互通、三平台、精确 Rust1.91、release、完整 RustSec 全闭包复审和许可汇总。`x509-parser` 门禁见[依赖报告](reality-dependency-gate.md)，能力边界见[REALITY说明](reality.md)与[出站说明](outbound.md)。

## 增量：官方 Xray REALITY 互通（2026-11-12）

固定 Xray v26.10.31（macOS ARM64）完成 VLESS（无 flow 与 `xtls-rprx-vision`）、
VMess、Trojan 三类 REALITY 的双向 TCP 本机互通：官方 Xray 客户端 → 本内核
`vless-reality`/`vmess-reality`/`trojan-reality`，以及本内核对应出站 → 官方
Xray REALITY 服务端；全部通过真实 HTTP GET。另完成 VLESS/VMess/Trojan 的 REALITY-over-gRPC 与 REALITY-over-XHTTP
（auto）双向；固定目标为本机 TLS 1.3 服务。

期间修复两处实际缺陷：

1. **服务端 Ed25519 CertificateVerify**：Xray Chrome/uTLS ClientHello 的
   `signature_algorithms` 不包含 Ed25519，原 `resolve` 仍要求
   `choose_scheme(schemes)` 成功，导致认证成功后被错误回退。现与 Xray 一致，
   REALITY 激活时强制 Ed25519 CertificateVerify；普通 TLS 仍按客户端列表协商。
2. **固定目标 record 尺寸**：原实现要求本地 flight 与目标逐 record 等长，目标
   EncryptedExtensions 不含 SNI ack 时槽位不足而回退。现目标槽位足够时模仿
   总长，不足时使用自然长度，保持聚合/分槽形态。
3. **出站 ClientHello signature_algorithms**：原只声明 Ed25519，固定目标的
   RSA/ECDSA 证书无法完成目标侧 TLS 握手；现声明 Ed25519、ECDSA 与 RSA-PSS/
   PKCS#1 的常规集合，REALITY 临时证书仍只接受 Ed25519。

定向回归：`cargo test --locked --test reality_inbound --test reality_outbound
--test reality_composition` 为 15+15 通过、2 ignored；vendor REALITY 测试
13 通过、0 失败；`verify-source.py` 复现 129 文件通过。最终全量
`cargo test --locked --all-targets` 为 1383 通过、0 失败、42 忽略（78 个结果块）。当前
`vendor/rustls/PATCHED.json` 的 `patch_sha256` 为
`6d99dfe20b82aa8da8c8b0ed697d75e8539577e5d109afc444d18eadd8ee951b`。
VMess/Trojan REALITY、REALITY-over-gRPC/XHTTP、三平台、精确 MSRV 与 release
仍未验收。
