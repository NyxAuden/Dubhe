# Shadowsocks 批次验收记录

测试日期：2026-11-04；交付核对：2026-11-05。变更：`add-shadowsocks-aead-inbound`。**本批40/40任务已完成：三平台普通回归、三家固定官方客户端24项Shadowsocks及同一新构建旧九项全部通过，变更未归档。** 原生TCP/UDP、六种算法和两个AES单层EIH模式已接入；自有测试、依赖双方互测和历史VLESS结果不代替本批官方兼容证明。

## 验收范围

- AEAD 2017：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，每入口单共享密码。
- AEAD 2022：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`，严格Base64单PSK。
- 两个AES 2022方法另支持单层EIH双用户；ChaCha 2022不支持EIH，不进行多密码试解。
- TCP复用共享路由、DNS、连接/握手许可、双向半关闭及明文计量；UDP为原生数据报，复用全局关联/排队字节预算和统一stop/force/children屏障。
- 不包括插件、UoT、TCP mux、多级EIH、Shadowsocks出站或其他算法。具体保护窗口、密文上限和日志边界见 [使用说明](shadowsocks.md)及[依赖门禁](shadowsocks-dependency-gate.md)。

## 当前构建验证

| 环境/检查 | 实际结果 |
|---|---|
| macOS ARM64 / Rust 1.95.0 普通测试 | **209 passed、0 failed、33 ignored** |
| Linux ARM64 / Rust 1.95.0 断网固定容器 | **209 passed、0 failed、33 ignored** |
| Linux x86_64 / QEMU / Rust 1.95.0 断网固定容器 | **209 passed、0 failed、33 ignored**，AWS-LC完整构建及vendor25项通过；编译器局部QEMU设置及警告见下文 |
| Rust 1.91 MSRV | Linux ARM64精确Rust **1.91.0**及1.91.1各自全目标编译检查通过（含AWS-LC）；未运行该工具链全部测试 |
| macOS fmt / all-targets check / Clippy `-D warnings` | 通过，无编译警告 |
| vendor生产features全库 / macOS ARM64、Linux ARM64、Linux x86_64 | 三平台各 **25 passed、0 failed** |
| macOS release / version / SOCKS示例check | 通过，未发布版本为 `0.1.0` |
| 三个Shadowsocks示例替换独立随机凭据后release check | **3项全部通过**，输出不含测试凭据 |
| 本批三家官方客户端24组Shadowsocks | **24 passed、0 failed，60个场景** |
| 同一新构建旧九项Trojan/VLESS/XUDP官方客户端回归 | **9 passed、0 failed，27个场景** |
| 完整显式官方矩阵 | **33 passed、0 failed、0 ignored、9 filtered out，313.55秒** |

209项普通测试组成：113 lib、9 CLI、5 DNS、1 examples、9 integration、9 reference配置/注册表生成、7 resources、5 Shadowsocks配置、22 Shadowsocks依赖接口、3 Shadowsocks联合监听、2 Shadowsocks混合资源、3 Shadowsocks UDP功能、5独立UDP wire、2 standard-client、7 VLESS、7 XUDP。普通回归中的33项ignored为24个新Shadowsocks入口及9个旧官方客户端入口，不计通过；上表官方结果来自另一次完整显式执行。三平台最终普通回归使用同一最终测试输入，以`--nocapture`核对均无IPv6 SKIP；macOS/Linux ARM64无编译警告，x86_64有下述构建探测警告及QEMU分配器提示，不能称三平台均无警告。

## 固定官方客户端分方法矩阵

平台均为官方 **macOS ARM64** 构建。每格表示独立测试通过TCP首个二进制载荷回显、同一SOCKS UDP关联访问两目标三报文，以及该身份模式全部负向断言。

| 方法及身份模式 | Mihomo v1.19.33 | sing-box v1.14.4 | Xray v26.10.31 |
|---|---|---|---|
| aes-128-gcm / 单密码 | TCP/UDP/错误密码通过 | TCP/UDP/错误密码通过 | TCP/UDP/错误密码通过 |
| aes-256-gcm / 单密码 | TCP/UDP/错误密码通过 | TCP/UDP/错误密码通过 | TCP/UDP/错误密码通过 |
| chacha20-ietf-poly1305 / 单密码 | TCP/UDP/错误密码通过 | TCP/UDP/错误密码通过 | TCP/UDP/错误密码通过 |
| 2022-blake3-aes-128-gcm / 单PSK | TCP/UDP/错误PSK通过 | TCP/UDP/错误PSK通过 | TCP/UDP/错误PSK通过 |
| 2022-blake3-aes-256-gcm / 单PSK | TCP/UDP/错误PSK通过 | TCP/UDP/错误PSK通过 | TCP/UDP/错误PSK通过 |
| 2022-blake3-chacha20-poly1305 / 单PSK | TCP/UDP/错误PSK通过 | TCP/UDP/错误PSK通过 | TCP/UDP/错误PSK通过 |
| 2022-blake3-aes-128-gcm / 单层EIH | 双用户TCP/UDP及两负向通过 | 双用户TCP/UDP及两负向通过 | 双用户TCP/UDP及两负向通过 |
| 2022-blake3-aes-256-gcm / 单层EIH | 双用户TCP/UDP及两负向通过 | 双用户TCP/UDP及两负向通过 | 双用户TCP/UDP及两负向通过 |

单密钥每组2场景：有效凭据、错误密码或合法长度的错误PSK。EIH每组4场景：第一用户、第二用户、错误身份PSK、未知用户PSK。共18×2＋6×4＝**60个Shadowsocks场景**。负向均要求内核TCP rejected及UDP dropped增长，目标无连接/数据、客户端无业务回包、上下行业务字节为零；不是仅凭客户端超时判断。正向逐项检查TCP载荷不变、UDP来源/目标/载荷及双向业务计量。

旧九项分别是三家客户端的Trojan/TLS、基础VLESS/TLS和VLESS XUDP，每项3场景，共27场景。保留原有限边界：固定Mihomo的基础VLESS不具备本测试所需原生UDP，使用XUDP组合验证UDP；错误证书信任场景仅验证TCP，不能扩称UDP证书负向。本批Shadowsocks没有TLS信任场景。

最终完整运行的33份结果及87个场景已逐项复核，`(client,mode)`全部唯一，每份顶层结果均为passed。最终索引：`.test-artifacts/ss-final-dji1rlkd/official-final-results.json`；每条包含独立结果路径及SHA-256。

本批复核的解压后二进制SHA-256（归档官方摘要、来源及固定提交见 [参考客户端](reference-clients.md)）：

| 客户端 | 二进制SHA-256 |
|---|---|
| Mihomo | `f3e8ae41397c08cbf900ce1f7c8a168285d29954e9bca5d84d69a2b2561adfe9` |
| sing-box | `6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2` |
| Xray | `9ddc3b0d912a8539285918e4fead4b60bbc449acdb639450ba068bc7efb983b7` |

官方归档API digest匹配不是数字签名验证，未声称从源码可复现客户端二进制。每个场景启动前仍重算本地二进制摘要、拒绝symlink，并核对固定版本/平台/ready状态。

## 输入、构建与私有证据

最终汇总：`.test-artifacts/ss-final-dji1rlkd/manifest.json`。较早本地快照保留在`.test-artifacts/ss-acceptance-a8kwa4s9/manifest.json`，不覆盖VLESS/XUDP历史。

| 对象 | SHA-256 |
|---|---|
| 生产输入集合（99文件） | `fc19b7113470c4e731bff2dec1a870f7b07f7ebc8808c6281b83cd3fc2dd5633` |
| Cargo.lock | `be8a6fdf432be2d2957a297acab00db62fe9e6c2e8d4710e64c62307589b495f` |
| vendor可复现补丁（1174行） | `9f4c7fd398c017df13d75084ade4237837619c11c389249b2b219a493fb92098` |
| 最终测试输入集合 | `bbcf010d0894e8678312f1d58d95b797bbe1907e81b12f7dc7c91189ef576168` |
| macOS release二进制 | `f8d32b4b24fd0d24eb56f04798f43eeafee44af1427dc94020579363898049b0` |

生产集合覆盖Cargo.toml、Cargo.lock、全部`src/**/*.rs`及vendor全部实际文件（含协议源码、补丁、来源和许可），不是只摘要补丁。测试集合独立覆盖全部`tests/**/*.rs`，src内单元测试已包含于生产集合。算法：相对POSIX路径排序，每项`SHA256 + 两空格 + 路径 + 换行`拼接UTF-8后求总SHA-256。工具、示例及交付文档另列逐文件摘要。

官方互通服务端为test profile内的本项目库，不是启动release子进程；它与release关联同一生产输入，但不声称两个profile的二进制相同。初次矩阵使用的旧测试集合`86111058df4418b16e3a73ef8290c75696a80774893746079b164e6fb074ee02`只用于失败历史，不作为最终通过输入。

最终三个随机示例release check结果：`.test-artifacts/ss-final-dji1rlkd/release-examples-1fsio39v/result.json`。更早一次记录脚本缩进错误，只完成首例便写出结果，后遇FileExistsError；已保留该失败记录，不作为三例通过证据。修正后在新独立目录实际完成3例并断言数量，配置为私有文件，不公开测试凭据。

## 本地测试分层

| 行为 | 实际证据及边界 |
|---|---|
| 严格配置、身份唯一性、Base64、脱敏、check无监听 | `tests/shadowsocks_config.rs`、CLI和联合监听测试 |
| 依赖公开TCP/UDP API、一次首读、padding、salt观察 | `tests/shadowsocks_dependency.rs`的22项；同源适配，不称官方互通 |
| 六方法TCP framing、最大块、IPv4/IPv6/域名、半关闭、计量 | `src/protocol/shadowsocks/tcp_tests.rs`的15项手写wire，只复用成熟密码原语 |
| 错误key/tag、截断、type/time/padding、非法地址、并发重放、EIH | 上述独立TCP测试；未经认证/准入不得连接目标 |
| 六方法UDP与双用户、稳定双栈socket、迁移/来源过滤 | `tests/shadowsocks_udp.rs`的3项，使用成熟库codec |
| 独立UDP布局/响应认证、65507字节密文、跨TCP/UDP重放 | `tests/shadowsocks_udp_wire.rs`的5项，独立AES/ChaCha/EIH布局 |
| 8192位窗口、u64极值、60秒保护、满容量、salt期限及原子准入 | 私有状态单元测试，不声称遍历全部nonce空间 |
| reader关闭/计数耗尽后保护状态、迁移、旧代次、队列/字节/目标限额 | UDP生命周期13项；salt回程碰撞最多8次、池满零输出 |
| 全局跨协议许可、握手门限、超限恢复及精确计量 | `tests/shadowsocks_resources.rs`的2项 |
| 双栈失败、监听错误、DNS队首阻塞、慢读TCP与活跃UDP强停 | `src/runtime_tests.rs`的4项，验证预算、任务及端口归还 |
| vendor预算、Pending/部分I/O/错误终止、禁用认证前缓存 | 25项：20预算、2缓存、3原有测试 |

本地UDP wire曾连续五轮各5项通过，不是长期压力或生产稳定性证明；短时资源测试、QEMU用例及回环边界不作吞吐基准。

## 失败历史与修正

1. Linux ARM64首次离线解析缺少`arc-swap`缓存；随后只读挂载已下载registry，继续`--network none --offline`，AWS-LC和vendor25项完成编译并通过。
2. Linux ARM64首次lib为112通过、1失败：测试假定2MiB写入必在40ms内背压。改固定64KiB堆缓冲、最多64MiB/500ms有界填充且客户端不读；完整208项随后通过，不改生产转发语义。
3. macOS默认UDP发送缓冲9216字节使合法大报文`Message too long`。只为内核自持SS socket准备至少65507字节收发缓冲，不缩小原有更大缓冲、不改系统参数；六方法及两EIH最大密文测试随后通过。
4. UDP wire测试发生临时端口冲突和future栈溢出，现隔离用例端口分配并将大缓冲移到堆。另一次EIH超时未唯一确定根因；保留日志，后续五轮及全量通过不等于定位了该次根因。
5. Linux ARM64最终框架复跑暴露联合监听测试端口竞态：随机UDP端口对应TCP不保证空闲，过早释放首端口还可能选到相同端口。测试现用Mutex隔离并联合预留TCP/UDP，保留首对直到第二端口选定且断言不同；未改生产监听失败处理。随后两平台最终209项通过。
6. Linux x86_64的旧QEMU下AWS-LC多次出现cc/cc1 SIGSEGV，单任务、关闭C调试信息及增大进程局部栈仍失败，曾在jitterentropy C编译失败。后续发现进程级128GiB虚拟地址预留可完成393对象的完整AWS-LC构建（32MiB输出，不是分配128GiB物理内存）；全局对Cargo设置该环境会停滞，已停止并保留日志。改为仅GCC命令注入该环境后vendor25项及完整普通209项均实际通过、exit0；env包装的探测警告完整保留，详见下节，不能称该构建无警告或已用崩溃栈确诊根因。未禁汇编、未换密码算法或改项目源码。
7. 精确Rust1.91.0首次在容器tmpfs安装后遇noexec的OS Permission denied，未进入编译，不是工具审批拒绝。未改挂载/系统权限，在普通临时容器目录重新官方安装后全目标检查通过，含原生构建。最终测试输入又完成1.91.0全目标检查，不声称MSRV完整运行测试。
8. 官方矩阵首轮25通过、8失败，全为sing-box SS正向TCP首载荷超时。阶段诊断确认SOCKS CONNECT成功、内核tcp_flows=1且uplink/downlink=0。原测试合并应用数据与SOCKS请求，混入本地SOCKS流水线预读的额外行为；固定sing-box所用sing提交5dc452e537bf以reader解析请求后将NewLazyConn(conn,version)交给handler，没有显式传该reader。探针改为标准CONNECT完成后再发送相同二进制首载荷；不改服务端认证/一次首读、密码库或负向判据。定向测试后，**最终同一次完整矩阵33项全部通过**，不是拼接局部结果。保留首轮日志和独立结果索引。
9. 宿主曾仅剩约2.3GiB；用户明确要求清理。首次删除缓存被审批器拦截，未绕过；仅在取得对具体`target/debug/incremental`的直接确认后删除。保留源码、证据、依赖缓存、release及全部既有容器资源，后续采用`CARGO_INCREMENTAL=0`控制增长。未删除其他目录或Docker卷/镜像。

## 执行命令与权限边界

本地完整构建/测试已有用户直接确认，含vendor、依赖构建脚本及AWS-LC。首次官方运行被审批器拦截后没有执行；随后用户明确选择“允许上述33项”，对三个官方仓库、固定版本及本机回环范围直接确认，原命令获准才执行，没有换工具、委托或修改权限绕过。

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p shadowsocks --lib --no-default-features --features aead-cipher,aead-cipher-2022,aead-2022-no-udp-cipher-cache
CARGO_INCREMENTAL=0 cargo test --locked -p dubhe -- --nocapture
CARGO_INCREMENTAL=0 cargo test --locked -p dubhe --test reference_clients -- --ignored --nocapture --test-threads=1
cargo fmt -p dubhe --check
CARGO_INCREMENTAL=0 cargo check --locked -p dubhe --all-targets
CARGO_INCREMENTAL=0 cargo clippy --locked -p dubhe --all-targets -- -D warnings
```

客户端使用独立空工作目录、最小清理环境、0600配置/日志、回环高端口、RAII kill/wait及停止后端口重绑检查。官方测试每项独立60秒外层期限，串行执行；并非全矩阵60秒。

## Linux x86_64 的实际构建环境与警告

成功环境为QEMU user x86_64 7.0.0、GCC12.2.0（Debian 12.2.0-14+deb12u1）、glibc2.36-9+deb12u14、guest kernel6.8.0-64-generic，Rust/Cargo1.95.0、LLVM22.1.2。实际amd64子镜像摘要：`sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb`。源码`/work`及registry只读，根文件系统只读，网络关闭，复用已有amd64 cargo/target卷，`/tmp`为256MiB tmpfs，保留默认noexec，core limit为0。

仅在该次容器进程内使用下列环境，不写入项目配置或宿主环境；**不对Cargo/Rustc全局设置QEMU_RESERVED_VA**：

```sh
AWS_LC_SYS_CC='/usr/bin/env QEMU_RESERVED_VA=0x2000000000 /usr/bin/gcc'
CARGO_INCREMENTAL=0
CARGO_TARGET_DIR=/target
CARGO_NET_OFFLINE=true
```

容器内实际执行：

```sh
cargo test --locked --offline -p shadowsocks --lib --no-default-features --features aead-cipher,aead-cipher-2022,aead-2022-no-udp-cipher-cache -- --nocapture
cargo test --locked --offline -p dubhe -- --nocapture
```

vendor25项构建2m02s、测试3.60s；普通回归构建4m19s，113 lib加96 integration共209通过，33个官方入口保持ignored，18个结果块包括空main/doc。最终日志明确`VALIDATION_STATUS=0`，无SKIP，IPv6条件测试实际通过。此平台没有启动macOS官方客户端。

必须保留的构建边界：

- env包装使cc-rs家族探测只调用`/usr/bin/env -E ...`而不带后续GCC参数，独立完整AWS构建出现24条家族探测警告并回退GNU。
- c11、stdalign、builtin_swap、linux_random四项能力编译检查全部成功；memcmp编译器缺陷探针未能构建，依赖自行警告后跳过。实际GCC12.2不在该探针针对的GCC9.0–9.3/10.0–10.1范围，但没有将跳过写成通过，也未修改或屏蔽检查代码。
- 完整AWS构建`BUILD_STATUS=0`，393对象、约32MiB，保留mldsa_intt、edwards25519_scalarmulbase、bignum_montmul_p384及jitterentropy-timer等对象。Cargo指纹保持AEAD2017/2022、AWS-LC及禁UDP派生缓存特性；关键清单/构建脚本及105个Rust文件前后摘要不变。
- 日志中的jemalloc `MADV_DONTNEED does not work`是QEMU环境提示，回退memset；不把它抹去或称为原生环境测试。
- GCC原生`-wrapper`方案只完成空文件预处理小探针，没有项目回归结果；不是本次通过所用方案。独立AWS构建的外层zsh记录器曾因只读变量`status`返回1，容器原始日志明确BUILD_STATUS=0；后续vendor/root改用rc记录，均实际exit0。

完整命令、版本、警告、失败历史、特性及不变性原始证据保存在本批私有汇总目录的`linux-amd64/`，入口为`evidence-index.json`及`evidence.sha256`；原始调查目录`$HOME/WorkSpace/aws-lc-amd64-QcwSSV`亦保留。主会话重新核对原始日志计数、真实退出标记及全部校验清单。最初核验脚本误找EXIT_STATUS而非实际VALIDATION_STATUS导致断言失败；修正记录字段后核验通过，该脚本错误不是项目测试失败。QEMU修正不代表默认环境故障已消失，也不作原生性能或全面安全证明。

## 任务到证据的对应

以下按OpenSpec任务号对应实际执行证据，不以规划文档本身证明完成。三平台最终普通日志分别为汇总目录内`macos-final-ordinary.log`、`linux-arm64-final.log`、`linux-amd64/root-local.log`；vendor分别见`vendor-static.log`、`linux-arm64-final.log`及`linux-amd64/vendor25-local.log`。逐项机器可读索引为`task-evidence.json`，每项关联源码/测试、日志和结果；最终文档、工具、示例摘要保存在同目录manifest。

| 任务号 | 实现/测试及实际验收证据 |
|---|---|
| 1.1 | `vendor/shadowsocks/UPSTREAM.json`、原许可及`.test-artifacts/ss-source-kmkobk2f/manifest.json`的两包来源/归档摘要；`source-license-check.log`再次核验来源并生成可复现diff |
| 1.2 | vendor无UDP缓存feature及两项缓存一致性/状态测试；三平台生产features库25项日志 |
| 1.3 | Cargo.toml/lock、根package特性树、302包许可清单；`source-license-check.log`及精确MSRV日志，TLS仍选ring |
| 1.5 | vendor TCP严格padding/首chunk、每方向AEAD预算补丁；20项预算及22项公开适配，三平台均实际通过 |
| 1.4 | `tests/shadowsocks_dependency.rs`的22项六方法/双AES EIH公开TCP/UDP适配；三平台普通回归 |
| 2.1 | `src/config/shadowsocks.rs`、配置5项及CLI9项，严格方法/身份模式/脱敏/旧配置回归 |
| 2.2 | 配置身份唯一性/Base64/重放容量边界及CLI check无监听测试；三平台普通日志 |
| 2.3 | `tests/shadowsocks_listener.rs`3项联合监听、端口0及失败释放；CLI无ready回归 |
| 2.4 | `src/runtime_tests.rs`双栈能力失败与单监听失败注入；三平台普通日志 |
| 3.1 | `replay.rs`精确集合、过期/容量/并发域隔离测试，TCP并发重放和UDP跨路径重放；三平台普通日志 |
| 3.2 | `salt_io.rs`透明读写、Pending/分段/部分写、碰撞/池满测试；独立TCP/UDP无副作用断言 |
| 3.3 | `packet_window.rs`及UDP生命周期窗口/计数极值、无效语义、tombstone与slot保护测试 |
| 4.1 | 独立TCP六方法首载荷、2017跨chunk地址、IPv4/IPv6/域名、双向半关闭；三平台普通日志 |
| 4.2 | 独立TCP三2022方法时间±30、方向/padding、65535块及请求salt绑定；三平台普通日志 |
| 4.3 | 独立TCP双AES EIH双用户/错误身份/未知用户/认证标签负向；最终官方EIH六项另有双用户结果 |
| 4.4 | 一次首读短读、握手超时/取消的socket关闭及许可释放测试；正常半关闭另验 |
| 4.5 | 独立TCP15项中的截断/长度/type/time/padding/tag/非法地址和并发重放，目标未触及 |
| 5.1 | receiver/队列/预算/MSG_TRUNC生命周期测试、独立UDP最大密文边界及runtime DNS队首阻塞 |
| 5.2 | 独立2017 UDP来源/多目标、反射/跨路径重放、回程salt最多8次及池满零输出 |
| 5.3 | UDP独立wire5项六方法布局/响应认证和EIH双用户；生命周期发送失败计量/packet ID测试 |
| 5.4 | 双栈稳定源端口及实际来源过滤、目标上限/Reject先于DNS测试；三平台无IPv6跳过 |
| 5.5 | endpoint迁移/排队回最新端点、同SID双用户、旧代次、60秒保护及reader结束/耗尽测试 |
| 6.1 | 混合资源2项及runtime队首阻塞，跨入口连接/握手/UDP/字节预算和超限后恢复 |
| 6.2 | 独立TCP、UDP wire/功能及混合资源精确明文计量，含空载荷、padding、EIH及发送失败 |
| 6.3 | runtime活跃TCP慢读/UDP强停、半帧/监听失败、生命周期stop/force/children和端口重绑 |
| 6.4 | macOS最终普通209/0/33、fmt、check、严格Clippy；`macos-final-ordinary.log`及check日志 |
| 6.5 | Linux两架构最终普通各209/0/33、vendor各25，精确Rust1.91.0/1.91.1及Rust1.95实际记录；x86警告/环境与失败历史另列 |
| 7.1 | 参考配置/注册表普通9项，24个唯一SS入口；逐场景普通文件/摘要/最小环境/私有配置及进程RAII |
| 7.2 | 官方三家`aes-128-gcm-single`各自TCP/原生UDP及错误密码独立结果 |
| 7.3 | 官方三家`aes-256-gcm-single`各自TCP/原生UDP及错误密码独立结果 |
| 7.4 | 官方三家`chacha20-ietf-poly1305-single`各自TCP/原生UDP及错误密码独立结果 |
| 7.5 | 官方三家`2022-blake3-aes-128-gcm-single`各自TCP/原生UDP及错误PSK独立结果 |
| 7.6 | 官方三家`2022-blake3-aes-256-gcm-single`各自TCP/原生UDP及错误PSK独立结果 |
| 7.7 | 官方三家`2022-blake3-chacha20-poly1305-single`各自TCP/原生UDP及错误PSK独立结果 |
| 7.8 | 官方三家`2022-blake3-aes-128-gcm-eih`双用户TCP/UDP、错误身份及未知用户独立结果 |
| 7.9 | 官方三家`2022-blake3-aes-256-gcm-eih`双用户TCP/UDP、错误身份及未知用户独立结果 |
| 7.10 | 同一次完整官方矩阵旧九项独立结果，保留基础VLESS和证书负向原边界，不复用历史构建充数 |
| 8.1 | 三个占位示例、使用说明、普通示例回归及`release-examples-1fsio39v/result.json`随机凭据3例实际check |
| 8.2 | 302包许可清单、兼容矩阵及本报告；三平台/24SS/旧9分开关联，生产99文件/测试17文件/锁文件/补丁摘要与私有原始日志 |
| 8.3 | `release-spec.log`的release/version/SOCKS check、最终随机三例check、三个相关OpenSpec严格校验及最终交付摘要；没有归档/Git/发布/部署 |

其中7.2–7.10的逐项路径及结果摘要全部来自`official-final-results.json`，不以表格中的文字替代真实产物。

## 容器与交付边界

Rust1.95固定镜像：`rust@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1`。显式使用现有Colima Unix socket及专用cargo/target卷，源码和宿主registry只读，普通测试断网，不切全局Docker context。x86_64使用QEMU，不是原生性能证明。

Rust1.91 ARM64固定镜像：`rust@sha256:20262682d0201e219012287e8c1e6a7a14b6ebd46bb2b280714f23c06678c285`，内含1.91.1，已断网全目标check；随后以官方rustup在一次性容器普通目录安装精确1.91.0，同样check通过。单任务、dev debug关闭和incremental关闭以控制空间。工具链下载用官方网络，Cargo保持`--locked --offline`，不能称精确工具链安装容器全过程断网；未改宿主工具链。

依赖许可清单含302个workspace/可选/跨平台/开发包，不表示全部链接到生产。vendor补丁来源和许可完整保留；TLS仍为rustls/ring，AEAD新增AWS-LC原生构建成本。项目自身许可证仍未定稿，`publish=false`。当前验收不构成全面安全审计、长期稳定性或生产容量证明。

release已验证版本、SOCKS示例及三个随机凭据Shadowsocks示例；本变更、VLESS及foundation三个相关OpenSpec均通过严格校验，任务完成状态以实际日志、摘要和逐项证据对应表核对。没有修改系统代理、防火墙、DNS或Docker全局设置，没有Git操作、OpenSpec归档、发布或生产部署。`.test-artifacts/`含测试凭据、证书和临时私钥，**禁止整体公开**。
