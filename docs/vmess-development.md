# VMess 开发阶段记录（不代替最终兼容验收）

日期：2026-11-05；环境macOS ARM64/Darwin27.2，rustc1.95.0/cargo1.95.0。变更`add-vmess-aead-inbound`第1–5组为21项开发任务，第6–8组9项集中验收仍未执行。Vision保持18/27，其剩余9项同样是集中验收，不是阻断本批的开发前置。

## 实现及证据映射

| 任务 | 实际实现/证据 |
|---|---|
| 1.1 | [依赖门禁](vmess-dependency-gate.md)：精确锁定版本、生产features合并、发布包三方checksum、许可/MSRV元数据、固定RustSec完整快照；当前根all-targets check通过，不声称精确MSRV实际构建通过 |
| 1.2 | crypto.rs薄Digest适配与成熟HMAC/AES/AEAD/MD5/SHA256；Python标准hmac独立KDF/二进制path/KDF16、FIPS197/NIST、重复result/reset，3项通过 |
| 1.3–1.4 | config::38项含新增VMess配置16项，TLS成对/null/未知flow/alterId/UUID/限额/脱敏；CLI新增4项、runtime准备新增3项，真实check不监听及失败端口归还 |
| 2.1–2.3 | replay.rs六项含并发重复/饱和、双条目容量/堆、精确241秒、未来窗口、亚秒锚点/回退/前跳/溢出；header18项含独立AuthID、取消提交、跨入口/身份/会话材料保护 |
| 2.2、2.4 | header独立完整请求/38字节响应hex、全部截断/逐字节篡改/有界长度、地址/安全矩阵、Pending短IO、响应一次/取消/失败闩锁；真实server-first见tests/vmess.rs |
| 3.1–3.5 | body22项：双向AES/ChaCha固定hex、C/M/P/A/5矩阵、单SHAKE/0..63padding、65535/65551边界、完整终止tag、TLS真实错误保留、Pending取消/一次游标、失败闩锁、shutdown后拒写/半关闭；实际走完65536次AEAD后拒绝65537，不只跳末计数 |
| 4.1 | runtime/独立测试端：直TCP/实际TLS、三安全值/首载荷/服务器先发/半关闭；自持DNS注入证明cmd1/cmd2认证/时间/security/A/Reject先于DNS/真实目标及成功响应 |
| 4.2 | native cmd2每chunk一包；多大小连续数据、source过滤、配置超限、坏tag/半帧/空终止、空闲/关联限额；近上限包实测，公共socket缓冲修复；不插VLESS长度 |
| 4.3 | packetaddr独立7/19字节、IPv4/IPv6实际执行、交错两目标/空业务、短头不补、开关关闭零控制域DNS、逐包Reject；回程IPv6头导致超限时drop后下一nonce仍正确 |
| 4.4 | cmd3无外层目标，经body接UDP-only XUDP；多session/目标/代次/End/reuse，跨承载同GlobalID隔离及TCP frame拒绝，security5实际TLS裸流和分块、旧VLESS/Vision回归。**2026-11-06：命令 3 已改为完整 Mux（TCP + xudp 门控 UDP，GlobalID 进程级接管），本行为历史开发记录，见 [Mux 说明](mux.md)。** |
| 4.5 | 混合SOCKS/VMess连接与UDP额度、半头/半body/三UDP强停；runtime新增自持DNS真实阻塞使1包队列+512载荷预算饱和、固定children数、force真实join/许可归还；慢读64MiB/500ms有界形成背压，上行仍交付，目标/监听端口可重绑 |
| 5.1–5.2 | 下列最终22条命令均退出0；两独立模板替换占位后真实CLI check及服务启动/业务通过；使用/矩阵/路线/README明确“已实现待集中验收” |
| 5.3 | 最终命令、输入文件逐项摘要与本报告；未沿用旧106/209/33为本批通过 |

独立测试端`tests/common/vmess.rs`不调用生产VMess codec/KDF；密码操作仍委托成熟库。另有头/正文测试内嵌由Python标准hashlib/hmac与既有cryptography产生的固定hex，避免仅以同构双方互测作为依据。没有安装Python包或运行参考内核。

## 最终集中开发命令

所有命令在项目根执行。原始日志/退出码/时间/结果保存在私有目录：

`.test-artifacts/vmess-dev-52ls33tw/`

最终清单为`final-commands.json`，逐命令日志`final-01.log`至`final-22.log`；`commands.json`与01..20.log是大包追加前较早一轮，不能替代最终修复输入。

```sh
cargo fmt -p dubhe --check
cargo check --locked --offline -p dubhe --all-targets
cargo clippy --locked --offline -p dubhe --all-targets -- -D warnings
# 以下各filter分别执行一条，不合并为不存在的cargo多filter命令：
cargo test --locked --offline -p dubhe --lib config::
cargo test --locked --offline -p dubhe --lib protocol::vmess::
cargo test --locked --offline -p dubhe --lib protocol::vless::
cargo test --locked --offline -p dubhe --lib protocol::vision::
cargo test --locked --offline -p dubhe --lib tls::
cargo test --locked --offline -p dubhe --lib runtime::tests::
cargo test --locked --offline -p dubhe --lib udp::vmess::
cargo test --locked --offline -p dubhe --lib udp::tests::
# 下列target也分别执行：
cargo test --locked --offline -p dubhe --test vmess
cargo test --locked --offline -p dubhe --test vless
cargo test --locked --offline -p dubhe --test xudp
cargo test --locked --offline -p dubhe --test vision
cargo test --locked --offline -p dubhe --test resources
cargo test --locked --offline -p dubhe --test cli
cargo test --locked --offline -p dubhe --test examples
cargo test --locked --offline -p dubhe --test shadowsocks_config
cargo test --locked --offline -p dubhe --test shadowsocks_dependency
cargo test --locked --offline -p dubhe --test integration
cargo test --locked --offline -p dubhe --test shadowsocks_udp
```

| 定向目标 | passed | failed | ignored |
|---|---:|---:|---:|
| config | 38 | 0 | 0 |
| VMess crypto/header/body/replay（3+18+22+6） | 49 | 0 | 0 |
| VLESS wire | 18 | 0 | 0 |
| Vision codec | 23 | 0 | 0 |
| TLS | 10 | 0 | 0 |
| runtime（含新增VMess9） | 14 | 0 | 0 |
| VMess packetaddr及公共UDP | 1+9 | 0 | 0 |
| VMess独立业务/示例 | 16 | 0 | 0 |
| VLESS/XUDP/Vision/资源集成 | 7+7+9+7 | 0 | 0 |
| CLI/旧示例 | 14+1 | 0 | 0 |
| SS配置/依赖/UDP及旧SOCKS/Trojan集成 | 5+22+3+9 | 0 | 0 |
| **合计** | **262** | **0** | **0** |

这是指定filters/targets的合计，不是`cargo test --all-targets`全量；被filter排除的测试没有算通过，也没有执行33项ignored官方矩阵。所有新网络测试仅自持回环，包括IPv6 `::1`，本轮没有以“可用时跳过”代替IPv6实际执行。fmt/check/Clippy均退出0；OpenSpec strict另行执行。

## 失败和修复历史（不得描述成首次全过）

1. 规划`sha3 0.12`提供SHAKE的判断错误，真实包已移除该API；先报告暂停，用户继续后改官方`shake0.1.0`，算法/wire不变，规划/依赖同步。
2. 配置先接入而runtime尚未穷尽枚举时根测试编译失败；早期独立配置38通过不当作根通过。后续真实根config38通过。header/body初稿引用的tests文件尚未写时all-targets失败；未写空文件/删模块绕过。
3. header测试首编译nonce数组类型与局部变量遮蔽错误已修；body Clippy返回类型复杂与测试unwrap警告已修；crypto大枚举用Box包装AES对象。body向量19→21→22为实际递增历史，最终22均实跑。
4. crypto独立KDF金样通过，但重复result测试揭示cryptoxide SHA256 result会消耗状态并panic；Nested根改既有RustCrypto sha2 clone+finalize薄转发，HMAC仍全委托cryptoxide，没有自写ipad/opad。修复后crypto3、后续49全通过。
5. 独立集成端初编译有digest0.10/0.11 trait歧义、usize/u64统计类型、误引用不存在forced字段、unused import；修复夹具后运行。混合UDP限额测试错误调用“必须成功”的SOCKS helper，实际应收到REP1；改成独立验证失败应答，未降低生产限制。
6. 示例追加先用临时Vec跨await借用导致E0716，改局部绑定；无生产影响。
7. 近上限UDP测试最初实际EOF：macOS自持socket `SO_SNDBUF=9216`，65507发送报EMSGSIZE；本机独立Python socket复现，提升该socket至65507后发送成功。公共Association创建目标socket时复用已有SS逐socket缓冲准备；同时测试自持echo调整自身缓冲。没有改sysctl/系统DNS/防火墙，没有缩小65507测试逃避。带P边界夹具另修正为考虑上下行独立padding，选择数学保证可装下的值；无P原生与A+packetaddr仍实际65507，普通/A最大wire另由独立codec完整覆盖。
8. 无package范围的`cargo fmt --check`包含workspace vendor并失败，差异在上游保留格式；该次失败后连着的check/clippy未执行。未格式化vendor或改变其可复现补丁，改用任务指定根package `cargo fmt -p dubhe --check`后通过，其他构建门禁也实际重跑。
9. 大包修复后完整重跑上述22条定向命令，不能沿用大包追加前较早一轮247项结果。依赖API403等静态查询失败详见独立依赖门禁。

## 最终输入集合

`inputs.json`逐文件列路径与SHA256。集合摘要算法：按路径排序，将每项编码为`sha256 + 两空格 + 相对路径 + 换行`，对UTF-8串再SHA256。此为文件输入快照，不是Git提交、release或跨平台构建ID。

- 生产自有输入41文件：Cargo.toml/Cargo.lock及src下非独立测试文件；有内嵌`#[cfg(test)]`的源文件按文件整体哈希。
- 测试输入23文件：tests下Rust及src内`*_tests.rs`/tests目录独立测试文件；不把测试端当产品客户端。
- examples集合包括全部当前JSON模板；vendor另列Rust文件集合。两者不是未经审查重新生成的上游补丁。

| 集合 | SHA256 |
|---|---|
| 自有生产输入 | `41c93dbadc6b593920315d717f85bb8ecfde67f61b9933329c6f74cdc1a8ca87` |
| 独立测试输入 | `e51bb3aa56fab4ea322520242563ab965f6c5dff36ebf71785094bc3b0f51b24` |
| 全部JSON示例 | `c0fe55877ff01fb2f8cb7cfb05998b4480a19f35b072c05f3809577dadf89992` |
| vendor Rust源集合（未改） | `5dbbe8a55f94ffd7044a72ceebe0cb3e0a3dadac495e2e26ebef66c0e2821a15` |
| Cargo.lock | `d107638fa5c7560596f15a1482346f17b335ec9ed78463e927641f0f164f3a58` |
| final-commands.json | `36de212d3210a73a60e6c74719233e19900821ded657753dc024384e8d81dc76` |
| inputs.json | `2916b7864b4555ee15c70911462a8aca7e8b8e8859849f76f433ba81e4add03a` |

密码/头/正文固定hex位于版本输入内；私有工件可能含路径、测试凭据和临时私钥，不公开整个`.test-artifacts/`。

## 未执行与后续

- 没有启动VMess/Vision官方客户端新矩阵；旧33项权限不扩展到本批。
- 没有启动/恢复容器，没有Linux新输入全量、精确Rust1.91新输入构建、vendor全库测试、新release、长稳/生产部署或发布。
- 旧验收报告保持其原输入范围。最终第6–8组9项保持未勾；不得将本报告命名为完整VMess兼容验收或all_done。
- 必要开发门禁通过可继续下一独立模块，不要求先重复完整官方/三平台。没有Git初始化、分支、提交、push、自动归档或系统网络/权限修改。
