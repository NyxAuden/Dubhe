# WebSocket 依赖静态门禁

审查日期：2026-11-05；范围：`add-websocket-inbound-transport` task 1.1 / design D4。**精确候选存在，未见本范围内的未修复 RustSec 版本阻塞；可将下列四个新增包及最小直接边提交真实用户确认。这不是依赖变更授权、候选 Cargo 解析或编译通过证明。** 本轮不勾任务，不改 Cargo、锁、生产代码或冻结 vendor；未构建、执行下载代码/build.rs、启动官方客户端/容器或另起代理。

## 输入与证据边界

私有工件根：`$PROJECT_ROOT/.test-artifacts/ws-dependency-static-NR8t2s`，目录权限0700，脚本及数据按 `umask 077` 创建。原始下载逐项进入独立新空目录；自写脚本位于独立 `scripts/`，均从项目根以 `python3 -I` 启动。`.crate` 以数据逐成员读取，检查普通文件/目录、重复路径、绝对路径和 `..`，不用 `extractall`，不执行归档内容。官方 index/归档/RustSec 原文而非公开网页摘要作为依据。

- 旧 `Cargo.lock`：SHA256 `a6f70121acafa096472034013e9572754f8ad2d5adbd8a638a1f0507a3a4b2cd`，75857字节；原样副本 `baseline/Cargo.lock.snapshot`。这是审计快照，**不是第二份用于 Cargo 解析的锁**。
- 旧 `Cargo.toml`：SHA256 `5ff66db14dffba3eadc601ce07ec6e78b3af002bd53f333e3b19716a0da96dfb`，2031字节；副本 `baseline/Cargo.toml.snapshot`。根声明 Rust **1.91**。
- design：`ee30afcdd409ca6286ab25c1ca697b5dcde5ac1d3dbba796a2a733f5106c4796`；tasks：`c868eefd1327a6107873335e888606bcff457edd0f7b801755c345cd67eebcfa`。
- 旧锁313项含 dev/所有平台，不等于生产包数。只读 `cargo metadata --offline --locked` 与根 `cargo tree --offline --locked --edges normal,build` 均退出0；生产基线 **205个包版本**，未重新审计整个旧图。
- 原始响应、请求URL/时间/退出码、成员清单、源码/完整许可字节与SHA256见 `downloads/`、`packages/`、`archive-read/`；完整目录摘要见 `manifest.json`。MCP dahepix连接失败，本门禁不依赖它。

## 精确候选、来源与完整许可

下列六项均从官方 `https://index.crates.io/<crate sparse path>` 读取**精确 name+vers**行，`yanked=false`；新下载 `https://static.crates.io/crates/<name>/<name>-<version>.crate`，lstat为普通文件，SHA256逐项等于 index `cksum`。已有两包另与旧lock checksum相等；新增四包旧lock无此项。归档全部成员仅普通文件/目录，无符号或硬链接。

| 包 | 相对旧锁 | 发布 edition / rust-version | 实际许可 | `.crate` / index SHA256 |
|---|---|---|---|---|
| tokio-tungstenite 0.30.0 | 新增 | **2018 / 1.85** | **MIT** | `17a073bfed563fa236697a068031408a93cd9522e08abf9933ead3e73411bd71` |
| tungstenite 0.30.0 | 新增 | 2021 / 1.85 | MIT OR Apache-2.0 | `e48ac77174b19c110a50ab2128b24215ac9cb40e0e12e093fb602d175c569d22` |
| http 1.5.0 | 新增 | 2021 / 1.57.0 | MIT OR Apache-2.0 | `918d3568bebf352712bc2ef3d46a8bcf1a75b373be6539de198e9105cbbf9ce0` |
| httparse 1.10.1 | 新增 | 2018 / **未声明** | MIT OR Apache-2.0 | `6dbf3de79e51f3d586ab4cb9d5c3e2c14aa28ed23d180cf89b4df0454a69cc87` |
| futures-util 0.3.34 | 复用；建议增加直接边 | 2018 / 1.71 | MIT OR Apache-2.0 | `0d50a92467f8ba5dd6e3ee5d4bd04d73ab2e4e1c44474a0674821dfce14b79bc` |
| bytes 1.12.1 | 复用；不需直接边 | 2021 / 1.57 | MIT | `fc652a48c352aef3ea3aed32080501cf3ef6ed5da78602a020c991775b0aff04` |

**D4元数据校正**：不能将两WS crate统一写成edition2021和双许可；上表粗体是校验后的发布归档事实，设计文件未由本代理修改。两WS包 MSRV同为1.85。httparse的 manifest/index/README 未给精确MSRV，不能从edition或build脚本的1.59 SIMD条件推导其最低Rust；实际1.91仍待获准后编译。

完整 `LICENSE` / `LICENSE-MIT` / `LICENSE-APACHE` 全文已保留并读取，不只依赖SPDX：MIT要求随副本/重要部分保留版权和许可；选Apache时保留全文、适用归属、修改声明及存在时的NOTICE义务。六包无独立NOTICE成员，未发现必须新引MPL/GPL模块。许可证各成员SHA256在 `packages/<name>-<version>.json`，例如tokio-tungstenite/LICENSE `fdd55e2b2da854b0fbdc1e607df7c2ba1e1ebf91ecb77c515511ebeef972bc8f`、tungstenite/LICENSE-APACHE与httparse/LICENSE-APACHE同为 `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`。这是静态许可核对，不是法律意见或最终发行许可汇编。

## 最小直接边与正常/构建闭包

为将D4四个**精确版本**全部落为根约束，建议获准后仅加入以下五条直接依赖；本轮没有应用：

```toml
tokio-tungstenite = { version = "=0.30.0", default-features = false, features = ["handshake"] }
tungstenite = { version = "=0.30.0", default-features = false, features = ["handshake"] }
http = { version = "=1.5.0", default-features = false, features = ["std"] }
httparse = { version = "=1.10.1", default-features = false, features = ["std"] }
futures-util = { version = "=0.3.34", default-features = false, features = ["sink", "std"] }
```

- `futures-util` 提供适配器的 `Stream` / `Sink` traits；不需要为这条根边开启默认 async-await/macro/io/channel。tokio-tungstenite自身也请求 `sink,std`。**旧生产这些features已存在**，根default=false不反向关闭既有合并features。
- `bytes` 直接边**非必要**：`tokio_tungstenite::tungstenite::Bytes` 已公开重导出，Message::Binary使用它。若后续实现确实直接 `use bytes::...`，才另列 `bytes={version="=1.12.1",default-features=false,features=["std"]}`；仍不新增包或feature。
- API层还能缩到根仅直接依赖tokio-tungstenite/httparse/futures-util：前者 `pub use tungstenite`，后者WS库又 `pub use http`，可通过重导出使用。**但这样根不再精确约束tungstenite/http版本**，必须以授权后的lock强制并复核；故本门禁更推荐上述五边精确pin，不为少两行牺牲D4精确候选约束。
- http/httparse自己的default均只有std；tungstenite传递边会照常启其default/std，不可宣称全图没有default feature。**两个WS包**的default均关闭；tokio-tungstenite只有handshake；tungstenite为handshake及其四个依赖feature `data-encoding,http,httparse,sha1`。不启WS `connect,stream,url,native-tls*,rustls-tls*,__rustls-tls`，复用现有tokio-rustls局部ring，不改provider/vendor。handshake仍编入部分客户端握手/同步connect API，并非从包中删除所有客户端源码；不调用它们，不启异步connect feature。

精确发布清单中启用的**全部新增 normal 边**如下；四包没有目标条件依赖或build-dependencies，dev/examples/benches不计生产：

| 父包 | 启用边及手工沿用的精确解析版本 |
|---|---|
| tokio-tungstenite 0.30.0 | tungstenite 0.30.0；futures-util 0.3.34（default=false,sink/std）；tokio 1.54.1（default=false,io-util）；log 0.4.35 |
| tungstenite 0.30.0 | bytes 1.12.1、data-encoding 2.11.1、http 1.5.0、httparse 1.10.1、log 0.4.35、rand 0.10.3、sha1 0.11.0、thiserror 2.0.21 |
| http 1.5.0 | bytes 1.12.1、itoa 1.0.18 |
| httparse 1.10.1 | 无normal/build子包 |

所有共享版本逐边满足真实清单的caret范围，旧生产已含所需feature。**新增包集合恰四项，无既有版本升级、共享feature增量或新增build依赖包；加性生产图预计205→209。** 尤其 `rand^0.10.2→既有0.10.3`、`sha1^0.11.0→既有0.11.0`，不额外引入rand0.9或sha1 0.10。下游futures-sink/core/task、slab、pin-project-lite、digest、getrandom、proc-macro等均旧锁已有且无新features，不重复当新增包。

`httparse` **有新的build.rs**，虽无build依赖包，仍不能说“没有新构建逻辑”：已全文只读检查，它运行 `RUSTC --version`、读取目标/feature环境并输出SIMD cfg，无下载/C编译/链接动作；本轮从未执行。其余三新增包 `build=false`。

手工闭包与全部normal/build边在 `closure.json`。为了确认不漏隐藏新增包，沿上述九个共享边界包的旧metadata保留全部平台normal/build后代55个包版本及边，均已存在；未重审它们的全部许可/公告或重审205包。该既有闭包最高**已声明**MSRV1.87（ctutils），另有redox_syscall/scopeguard/smallvec/wasi未声明；这些不是本批引入。六项精确归档中已声明值均≤1.85。手工结论**不等于候选Cargo解析成功**：以后若实际diff出现第五个新包、既有升级或新feature，须先回到门禁，不可把此报告用于批准任意更新。

## RustSec：完整树、全部命中与实际版本

本轮 HEAD **`7f6085443f236889cc5df7e54078b0a0193bd95a`**，提交时间 `2026-11-05T08:35:23Z`，完成读取时间 `2026-11-05T08:39:12Z`；实际tree对象 `8a1c7a5b76488d9bd598e139f3104907a1af7659`。Git trees recursive API **2431项、truncated=false**；不是沿用REALITY的旧2425项树。按四新增包、两个可能新增直接边及七个新增边直接复用包共**13个精确包名**枚举，找到**14份公告**，全部读取正文和完整 `versions/affected/withdrawn/informational`；逐文件Git blob SHA1与树一致，另保存SHA256。

公告固定前缀：`https://github.com/RustSec/advisory-db/blob/7f6085443f236889cc5df7e54078b0a0193bd95a/crates/<包名>/<ID>.md`。以下仅展示**实际版本所在分支**修复下界；其他分支和受影响函数/OS全文未截掉，见 `rustsec/advisories.json`、`rustsec/version-verdicts.json` 与对应原文。

| 实际包/版本 | 全部命中ID | 实际范围判断 |
|---|---|---|
| tungstenite 0.30.0 | RUSTSEC-2023-0065 | 客户端超长HTTP头CPU DoS；patched≥0.20.1，当前已修复；仍需D2有限前置HTTP门禁 |
| http 1.5.0 | RUSTSEC-2019-0033、0034 | HeaderMap::reserve溢出/DoS、Drain内存安全；均patched≥0.1.20，当前已修复 |
| bytes 1.12.1 | RUSTSEC-2026-0007 | BytesMut::reserve release整数溢出；patched≥1.11.1，unaffected<1.2.1，当前已修复；不靠debug溢出panic豁免 |
| futures-util 0.3.34 | RUSTSEC-2020-0059、0062 | MappedMutexGuard Send/Sync、FuturesUnordered Sync；分别patched≥0.3.7、≥0.3.2，当前已修复 |
| rand 0.10.3 | RUSTSEC-2026-0097 | informational=unsound；需log/thread_rng与logger重入/reseed等联合条件，实际0.10分支patched≥0.10.1；当前已修复，旧生产亦未启rand/log |
| tokio 1.54.1 | RUSTSEC-2021-0072、0124 | LocalSet abort、oneshot close并发；新分支patched分别≥1.8.1、≥1.13.1，当前已修复 |
| tokio 1.54.1 | RUSTSEC-2023-0001 | 仅Windows named-pipe配置；新分支patched≥1.23.1，当前已修复，不仅依赖宿主macOS排除 |
| tokio 1.54.1 | RUSTSEC-2023-0005、RUSTSEC-2025-0023 | unsound informational：ReadHalf unsplit/Pin（需io-util）、broadcast clone/Sync；新分支patched分别≥1.24.2、≥1.44.2，当前已修复 |
| tokio 1.54.1 | RUSTSEC-2026-0384 | 只影响1.54.0的Interval多线程竞争，Sleep/Timeout不受影响；patched≥1.54.1，当前恰达修复线，不能降至已yanked 1.54.0 |
| tokio 1.54.1 | RUSTSEC-2026-0386 | unsound informational：Unix AsyncFd构造器I/O安全；新分支patched≥1.53.3（另有1.51维护分支），当前已修复 |

14份均无withdrawn，不把informational自动忽略。完整树中 `tokio-tungstenite,httparse,data-encoding,itoa,log,sha1,thiserror` 七个包名无公告文件。**本快照、本13包名范围无未修复的版本命中**，不是无未知漏洞、所有公开渠道皆安全、全锁审计或cargo-audit通过。未重审旧图深层55包的历史公告；它们没有新增版本/features，本次范围不据此扩大。

## 归档API事实与未验证缺口

以下只以匹配index的精确归档为真，不继承网页源码摘要当归档结论：

- tokio-tungstenite发布VCS `4994a078037a18a9347b8cf49291a5031d63d9e0`；tungstenite `7f4aeaf0944992c5664c8fb8e0d54577c7e18020`。
- tungstenite `src/handshake/server.rs:37–103` 有公开 `create_response(&Request)->Result<Response>`，通过成熟SHA1生成Accept，校验24字节base64解码16字节的Key；不替代重复头/Host/精确HTTP1.1/CL/TE等项目门禁。
- tokio `src/lib.rs:218–242,303–408` 有 `from_raw_socket`、`from_partially_read`、分开Stream/Sink；`start_send` 的Io WouldBlock确为已入缓冲后返回Ok。不能重复投递；WriteBufferFull在帧入缓冲前失败，返回Message::Frame，不能盲重投原业务。
- tungstenite `src/protocol/frame/frame.rs:163–179` **仍缺最短126/127编码和64位高位独立检查**；D4≤14字节结构护栏仍必要，含HTTP预读路径。`frame/mod.rs:177–191`先检查u64声明帧长度再reserve；`protocol/mod.rs:457–474`自动Pong/Close flush遇WouldBlock仍继续读。
- 静态交接时，帧/消息/缓冲、poll预算、背压、Close及WSS/旧TLS回归均未执行。后续主线已获准执行开发门禁，成熟库API原型、有限分配、真实背压及协议回环的实际结果见[开发记录](websocket-development.md)和[内存记录](websocket-memory.md)；不能把本段静态结论或候选MSRV元数据当作精确1.91、三平台或官方互通。

## 执行记录与下一门槛

仅执行上述只读Cargo metadata/tree、自写数据审查脚本和官方HTTPS GET。确切命令/输入校验见 `baseline/final-input-integrity.json`。关键独立证据摘要：

| 工件（相对私有根） | SHA256 |
|---|---|
| `closure.json` | `32eb60c8af89e7e5571d22b617d33f7a0ebcbca2ac19a02b57d3305b1e65b2dc` |
| `rustsec/advisories.json` | `b7a24f2562d056aba8e83e090daac60bc800b98e3d4fee2f024e6222140cef0b` |
| `rustsec/version-verdicts.json` | `c11d6e64df6aeb6a078bb226d745804d0c961838402fa59d3043570b8e193225` |
| 完整tree原文 `downloads/rustsec-tree-vil_qw00/response` | `c1c79cb8de3ef2c1feda1f7ce26968889eb907b1a8d9ca53f1723864ca9e7373` |
| `baseline/cargo-metadata.json` | `cc4264a95fe0f288dc107d42c5473627f41039b59b5d6e3dd50998f9f9d52909` |
| `baseline/production-tree.txt` | `7fca5284128fd346cc21511e20f8350313974337033eb78722e1c19bfbe0c7b4` |

关键复现入口（均从项目根）：

```sh
python3 -I .test-artifacts/ws-dependency-static-NR8t2s/scripts/gate.py candidates "$PWD" "$PWD/.test-artifacts/ws-dependency-static-NR8t2s"
python3 -I .test-artifacts/ws-dependency-static-NR8t2s/scripts/rustsec.py "$PWD" "$PWD/.test-artifacts/ws-dependency-static-NR8t2s"
python3 -I .test-artifacts/ws-dependency-static-NR8t2s/scripts/closure.py "$PWD" "$PWD/.test-artifacts/ws-dependency-static-NR8t2s"
```

首条只适用于**新的空证据根**，当前根已存在快照/成员，不能原地重跑覆盖；重做应为每轮新建私有空根并按同样流程保存新原文。

失败不隐藏：首次RustSec tree以commit为API参数返回sha与HEAD中tree.sha不同，身份断言失败，未算通过；随后改用HEAD明确tree对象重取，验证非截断树和全部公告Git blob成功。原失败响应保留。多次只读Bash汇总/证据收束调用遇工具安全判定服务暂时超时，未执行对应调用，后续正常重试成功；不改权限、不委托绕过，不将失败当通过。最终Cargo、锁、design、tasks摘要均与初始快照相同。

**后续真实授权与初次验证**：用户已在主会话明确选择“确认并继续（推荐）”，仅批准上述四个精确新包、futures-util直接边和必要本地构建/受控回环开发验证。主线随后按五边精确pin方案修改根manifest；`cargo update -p dubhe`实际仅新增四包，无移除或已有版本升级，只有根包依赖列表变化。新lock SHA256为`56b19d93fc724a1cf6b2cf0dd52264029112e41194bb5f0299ae8000d613b723`，真实锁差异在私有`.test-artifacts/ws-dev-l28eb9oi/lock-diff.json`；首次locked all-targets check退出0。此记录不代表后续定向测试或集中验收全部完成。

**原静态交接时的下一步边界**：先取得真实用户对四新包、上列直接边及必要锁增量的确认，才可由主会话修改Cargo/锁和构建。本轮不替主会话申请/推定授权。授权后实际diff应限定四新包，保留旧版本；审真实production features/锁checksum、最小locked编译与定向测试，不允许全图update、不建立第二Cargo锁、不抬MSRV。若解析/实际API测试偏离本窄闭包或需要超D4护栏补丁，暂停反馈。最终许可汇编、精确1.91和完整能力簇验收仍待后续，不声称编译已通过。
