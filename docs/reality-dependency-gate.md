# REALITY 依赖门禁（静态审查与后续开发验证）

审查日期及开发验证补记日期：2026-11-05；本轮 RustSec HEAD/完整树确认时间 `2026-11-05T06:10:23Z`。适用变更：`add-reality-vless-inbound`。**首次静态审查因旧生产锁 `time 0.3.45` 命中 RUSTSEC-2026-0009 而暂停；用户随后实际选择“允许修复并继续（推荐）”，主会话完成必要最小四包更新。现锁 time 0.3.47 满足该公告修复范围，后续 locked/offline all-targets 编译、独立密码金样和定向开发回归已实际通过，任务1.1–1.3已完成。** 原静态审查由只读代理完成，未改锁或构建；其交接时限制及失败历史保留，下文使用“交接时/当时”区分，不表示当前仍未编译或等待授权。

本文件的主体是静态审查，不单独构成任务1.1完成证明；后续实际命令、金样、vendor来源/补丁复现、普通TLS回归和同一输入摘要见[开发记录](reality-development.md)。开发段21/29已完成，不等于精确 Rust1.91、官方客户端、三平台、release或最终全锁安全审计通过；第7–9组8项集中验收仍待执行。

## 范围与安全边界

- 已读取该变更的 proposal、design、tasks、spec，以及现有依赖/能力边界。
- 原静态审查代理只新建本文件与私有静态证据，未改 Cargo.toml、Cargo.lock、源码、vendor、规划任务或系统权限；本节限定该次静态工作，不涵盖后续主会话开发。
- 该次静态审查仅执行源码/许可读取、普通文件和 SHA256 检查、`cargo metadata/tree --offline --locked` 纯元数据命令及官方公开只读网络请求，未构建、运行测试、执行下载代码/构建脚本/官方客户端、启动容器或安装全局工具。后续主会话按获准范围实际编译/本地测试，见开发记录。
- 新下载分别放入新建空目录；Python 一律 `python3 -I`，不从下载目录启动解释器。归档仅作为数据读取，不使用不受控解包，不执行其中内容；未复制 MPL/GPL 协议模块。
- 私有证据根目录：`$PROJECT_ROOT/.test-artifacts/reality-dependency-static-k9szRE`。其创建权限受 `umask 077` 限制；本文不要求公开整个 `.test-artifacts`。
- MCP dahepix 本会话连接失败，未依赖该服务；没有将连接失败描述为未配置或无访问权。

## 必须先处理的旧生产锁公告

### RUSTSEC-2026-0009 / CVE-2026-25727

固定正文：[RustSec `965bf9ad083b58e6340d65829d85217b18be9290` 的 RUSTSEC-2026-0009](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/time/RUSTSEC-2026-0009.md)。公告日期 2026-02-05，别名 `GHSA-r6v5-fh4h-64xc`。

- 受影响范围：`time >=0.3.6, <0.3.47`；修复 `>=0.3.47`，`<0.3.6` 不受影响。
- 条件：使用 `time::format_description::well_known::Rfc2822` 解析不可信日期输入，深层嵌套注释可能递归耗尽栈造成拒绝服务。公告不是对所有日期格式、格式化输出或 ASN.1 日期构造的笼统指控。
- 首次审查锁定的 **0.3.45 确实落在版本影响区间**。这是已存在于旧生产依赖图、在本批扩大审查时新发现的问题，不是 REALITY 首次引入 time，也不能借“旧问题”省略门禁。后续用户授权修复后的锁定版本为0.3.47，详见下节；这里保留的是修复前事实。
- 修复前生产 tree 中 time features 为 `alloc,formatting,parsing,std`，`parsing` 来自既有 `tracing-appender 0.2.5`。`time/src/lib.rs:113-114` 在该 feature 下编译 parsing；`src/parsing/parsable.rs:27,166` 包含 Rfc2822 实现，`src/parsing/combinator/rfc/rfc2822.rs:33-50` 存在递归。因此不能说受影响实现没有编入 feature 图。是否最终被链接器消除未检查。

### 当前调用可达性检查

静态检查了当前根 `src/`、`tests/`、vendor Shadowsocks，以及 metadata 中实际启用的 time 消费边：

| 消费边/调用点 | 实际用法 | 与本公告的关系 |
|---|---|---|
| 根 `src/main.rs:29-45` | tracing-appender 非阻塞 stderr writer；tracing-subscriber 普通 JSON fmt；未使用 rolling appender 或 time 定制 timer | 未见把网络/配置数据送给 Rfc2822 的调用 |
| tracing-appender `src/rolling.rs:562-566,631-636,684,829-830` | 固定年月日/时分 FormatItem 描述、日期格式化，以及按同一固定描述解析文件名 | 不是 Rfc2822；根当前也未启 rolling 构造 |
| rcgen `src/certificate.rs`、`src/lib.rs` | Date/Time 构造、证书有效期输出、可选 x509 解析器的时间转换 | 当前生产关闭 x509-parser；未见 Rfc2822 |
| yasna `src/models/time.rs:117-118,334-335` | ASN.1 UTCTime/GeneralizedTime 自有格式解析后调用 time 的日期构造器 | 不调用 time 的 Rfc2822 parser |
| metadata 其他声明 time 的包 | hickory-net/proto 0.26 的可选边未启用；jiff、rustls 的相应边为其 dev 依赖；tracing-subscriber 的可选 time feature 未启用 | 不将仅有 manifest 声明误当当前生产调用边 |

全上述范围搜索 `Rfc2822/rfc2822` 无调用命中；检查相关 parse 调用实际参数也未见转换成该格式。**这只是本快照的静态“未见可达路径”，不是形式化不可达证明、漏洞豁免或未来安全保证，不能把版本命中写成无受影响依赖。**

### 必要最小修复（最初候选，后经用户授权由主会话应用）

官方 sparse index 与新下载 `.crate` SHA256 已逐项一致，均 `yanked=false`，四包都实际携带 MIT/Apache 完整双许可证。

| 包/变化 | 声明 MSRV | `.crate`/index SHA256 |
|---|---|---|
| time `0.3.45 → 0.3.47` | `1.83.0 → 1.88.0` | `743bd48c283afc0388f9b8827b976905fb217ad9e647fae3a379a9283c4def2c` |
| time-core `0.1.7 → 0.1.8` | `1.83.0 → 1.88.0` | `7694e1cfe791f8d31026952abf09c69ca6f6fa4e1a1229e18988f06a04a12dca` |
| time-macros `0.2.25 → 0.2.27`（可选） | `1.83.0 → 1.88.0` | `2e70e4c5a0e0a8a4823ad65dfe1a6930e4f4d756dcd9dd7939022b5e8c501215` |
| num-conv `0.1.0 → 0.2.0`（`^0.2.0` 最低候选） | 仍 `1.57.0` | `cf97ec579c3c42f953ef76dbf8d55ac91fb219dde70e49aa4a6b7d74e9919050` |

`time 0.3.47` 精确要求 `time-core =0.1.8`、可选 `time-macros =0.2.27`，将 num-conv 改为 `^0.2.0`；宏也要求 core `=0.1.8` 与 num-conv `^0.2.0`。其余当前生产启用子依赖 deranged/itoa/powerfmt 的范围不需因此更换。已有普通生产 time feature 图未启 macros，但 lock/all-targets 仍须处理宏的配套项，不可把“可选”误写成锁文件无此包。

四包均声明不高于项目 **Rust 1.91**；这是元数据可行，不是实际 1.91 构建通过。0.3.46 不含公告修复，不能作为安全候选。未选择更高最新版本，不因本发现扩大到任意整图更新。

发布包中已只读确认 0.3.47 的 RFC2822 注释解析增加 depth/DEPTH_LIMIT 检查；证据保留精确成员路径 `src/parsing/combinator/rfc/rfc2822.rs`，不是仅从 CHANGELOG 推断。

**处理历史与当前状态：先报告并暂停，再取得用户真实选择“允许修复并继续（推荐）”；主会话随后完成上述四包更新与 fetch，不是静默豁免。** 本代理本次仅根据所交付工件补记文档，没有执行更新、网络调查、构建或测试。

- 主会话保存的 `baseline/before-authorized-update.json` 记录修复前lock SHA256 `7dc99f2a489cea4d02ebd036345c5d7058951e378d63d1b701669e40051c159c`。
- `baseline/authorized-update-diff.json` 实际列出的版本变化恰为：time `0.3.45→0.3.47`、time-core `0.1.7→0.1.8`、time-macros `0.2.25→0.2.27`、num-conv `0.1.0→0.2.0`；四包更新后lock checksum与本代理此前已核官方index/归档摘要逐项相同。除此之外只有**先前rustls 0.23.46由registry切到同版本path**的来源变化，没有其他包版本升级；路径包lock不再带registry checksum，原始发布摘要仍用于来源溯源，不能替代vendor内容/补丁审查。
- 主会话报告Cargo首次自动选择 num-conv 0.2.2，随后精确纠正为授权最小候选0.2.0；最终diff保留的是0.2.0，不能把该中间超出候选的解析结果写成最终版本。
- 主会话报告最终lock SHA256为 `a6f70121acafa096472034013e9572754f8ad2d5adbd8a638a1f0507a3a4b2cd`，并交付 `baseline/after-authorized-metadata.json`、`baseline/after-authorized-tree.txt`。这是授权修复后的元数据/tree证据，**不是编译结果**；本补记不重新执行metadata/tree或构建。
- dev增加 `yasna 0.5.2` 仅为既有包的直接边，不构成第五个新增/升级包；其生产传递边及许可审查仍为上文所述。
- 现锁time0.3.47满足公告patched区间，已解决该旧版本阻塞。静态交接时仍不能仅凭版本修复勾task1.1；随后主会话补齐最小locked编译及接口/来源门禁，才据真实证据勾选。精确Rust1.91及最终全锁审查仍待task8.3，不用MSRV元数据代替。

## 精确依赖与生产 features

### 最初建议与当前直接边

以下是静态交接时建议的根 manifest 直接边，原静态代理未编辑；后续task1.3另加入默认关闭的`reality` feature及同版本vendor patch，不能把此历史片段当作最终完整manifest。

```toml
aws-lc-rs = { version = "=1.19.0", default-features = false, features = ["alloc", "non-fips"] }
rcgen = { version = "=0.13.2", default-features = false }
rustls = { version = "=0.23.46", default-features = false, features = ["ring", "aws_lc_rs", "std", "tls12"] }
# aes-gcm 沿用既有 =0.11.1，default=false，aes/alloc
```

task1.3随后实际加入rustls `reality`加性feature及`[patch.crates-io] rustls = { path = "vendor/rustls" }`，该feature在vendor默认关闭。最终根边显式启用`ring,aws_lc_rs,std,tls12,reality`；ServerConfig默认无钩子，REALITY局部使用aws-lc，普通TLS继续局部ring，不安装全局provider。新增13项record/真实TLS回归、feature完全关闭构建及128文件来源补丁复现均实际通过，见[开发记录](reality-development.md)与[vendor来源](../vendor/rustls/REALITY-SOURCE.txt)，而非仅由原发布摘要推断。

| 包 | 发布元数据 MSRV | 许可声明 | 静态 feature/API 结论 |
|---|---|---|---|
| aws-lc-rs 1.19.0 | 1.71.0 | `ISC AND (Apache-2.0 OR ISC)` | `non-fips` 启用 aws-lc-sys；alloc 是公开 feature，但所需 agreement/HKDF/HMAC/Ed25519/PQDSA API 本身未受此 feature 门控 |
| aws-lc-sys 0.47.0 | 1.71.0 | 下节完整表达式 | 原生 C/汇编构建，非纯 Rust；不启 fips/ssl/bindgen/unstable/all-bindings |
| rustls 0.23.46 | 1.71 | `Apache-2.0 OR ISC OR MIT` | 新增 aws_lc_rs provider，不取消旧 ring/std/tls12 |
| rcgen 0.13.2 | manifest/index 未声明 | `MIT OR Apache-2.0` | 生产 default=false，不需 crypto/pem/ring/aws_lc_rs/x509-parser；RemoteKeyPair 可用 |
| yasna 0.5.2 | manifest/index 未声明；README 称核心 1.36，启用 time 时服从 time 更高门槛 | `MIT OR Apache-2.0` | rcgen 必需，启 std/time/default空集合；无 big-int/bit-vec 新边 |
| time 0.3.47（授权修复后；旧锁0.3.45） | 1.88.0（旧1.83.0） | `MIT OR Apache-2.0` | 已有生产包；旧公告命中保留，现版本满足patched区间；交接时未编译，后续实际locked编译通过 |
| aes-gcm 0.11.1 | 1.85 | `Apache-2.0 OR MIT` | 既有 aes/alloc；真实全图另合并 default/getrandom |

rcgen README 的 MSRV 是“尽量支持七个月前 Rust”的政策，没有可替代 rust-version 的精确数值；不能捏造声明 1.60/1.71。包括未声明项在内，最终精确 1.91 构建仍需 task 8.3。

### 实际合并不能只看根边

- 原有 `shadowsocks → shadowsocks-crypto 0.8.0` 已启 aws-lc-rs default，包含 alloc、aws-lc-sys、ring-io、ring-sig-verify。根 `default-features=false` 不会抵消它，不能称全生产图无默认 features。
- rustls 的 `aws_lc_rs` 会启 `webpki/aws-lc-rs`、`aws-lc-rs/aws-lc-sys`、`aws-lc-rs/prebuilt-nasm`。**prebuilt-nasm 是该固定版 feature 的真实传递需求**，不是此处单独选择 Windows 二进制。主会话应记录实际原生构建参数和分发内容；本代理未执行构建。
- aws-lc-sys 的 default `all-bindings` 没有因本建议开启；生产观察到其 features 为 `prebuilt-nasm`。未启 bindgen 不等于所有未知平台均不需生成绑定，跨平台仍须实测。
- rustls 默认 feature 还包括 logging、prefer-post-quantum；这里不启默认。hybrid 组已在 aws-lc provider 中公开，`prefer-post-quantum` 只改变相应默认排序，不是使用 `X25519MLKEM768` 的先决条件。新配置应显式限制组/套件，不能依赖全局默认选择。
- rcgen 根生产边 features 为空。已有 dev `rcgen ="0.13"` 在 test/metadata 的合并图表现为 default/crypto/pem/ring；这不等于正常生产也启它们。不能将无 crypto 的生产能力仅靠 dev 合并后测试证明。
- aws-lc-rs `alloc` 文档说明其对 `io::writer` 有意义，crate 无条件 `extern crate alloc`；agreement/HKDF/HMAC/PQDSA 中使用堆分配并未普遍受 alloc feature 门控。保留显式 alloc 说明本项目允许分配，不宣称这是 no_std 或固定无堆实现。

### 2026-11-10 REALITY 出站新增 `x509-parser`

REALITY 出站的临时证书需要读取 DER 中的 SPKI 与签名字段。为避免自写 ASN.1/DER 解析器，经用户明确选择新增直接依赖：

```toml
x509-parser = { version = "=0.18.1", default-features = false }
```

| 项目 | 实际值 |
|---|---|
| 版本与来源 | `0.18.1`，crates.io `.crate` SHA256 `d43b0f71ce057da06bc0851b23ee24f3f86190b07203dd8f567d0b706a185202`；`Cargo.lock` checksum 相同 |
| 声明 MSRV / edition | `rust-version = "1.67.1"`，edition 2018（低于项目声明 MSRV 1.91） |
| 许可 | `MIT OR Apache-2.0`；发布包实际包含 `LICENSE-MIT`、`LICENSE-APACHE` |
| features | 根边 `default-features = false`；发布 manifest 的 `default = []`，不启 `verify`/`aws-lc-rs`/`ring` |
| 生产闭包 | 新增 `asn1-rs 0.7.2`、`asn1-rs-derive 0.6.0`、`asn1-rs-impl 0.2.0`、`der-parser 10.0.0`（`bigint`）、`oid-registry 0.8.1`、`rusticata-macros 4.1.0`、`nom 7.1.3`、`minimal-lexical 0.2.1`、`num-bigint 0.4.8`、`num-integer 0.1.47`；`data-encoding`、`lazy_static`、`thiserror 2`、`time 0.3.47` 等已在既有生产图中 |
| 新增包许可 | 上述新增包均为 `MIT OR Apache-2.0`，`nom` 为 `MIT`（其依赖 `minimal-lexical` 为 `MIT OR Apache-2.0`）；发布包保留对应 LICENSE 文件 |
| 新增包 MSRV | `asn1-rs` 1.68、`der-parser`/`oid-registry` 1.63、`num-bigint` 1.60、`num-integer` 1.31、`nom` 1.48；`asn1-rs-derive`/`asn1-rs-impl`/`rusticata-macros` 发布 manifest 未声明 `rust-version` |
| API 使用 | 仅 `x509_parser::parse_x509_certificate` 读取 `tbs_certificate.subject_pki.subject_public_key.data` 与 `signature_value.data`；不启用其证书链/名称约束验证，不把解析成功当认证成功 |
| 安全验证 | REALITY 的 HMAC-SHA512 与 Ed25519 CertificateVerify 仍由 AWS-LC 执行；解析结果只作为被验证输入。`tests/reality_outbound.rs` 覆盖证书签名与 Ed25519 签名的正/负路径 |

**未完成项**：本轮没有对新增闭包重新枚举 RustSec 公告，也没有执行 `cargo-deny`/`cargo-audit`、精确 Rust 1.91 locked 全目标构建或发布许可汇总；这些仍归集中验收。`x509-parser` 的 `verify` feature 未启用，`aws-lc-rs`/`ring` 可选边未进入本闭包。普通 TLS 仍不使用该依赖。

## 真实新增生产边和原生构建链

最初根 manifest 中 rcgen 仅 dev，rustls 只有 ring/std/tls12；AWS-LC 与 time 已由既有 SS/日志链进入生产。随后主会话增加上述直接边。本代理保存的一次成功 `cargo tree --edges normal,build` 快照共有 **205 个包版本（含根）**；相对既有 VMess 203 个生产包，新增生产包为 **rcgen 0.13.2、yasna 0.5.2**，不是把整条 time 或 AWS-LC 链算作新包。

- 新边：root→rcgen；rcgen→rustls-pki-types、time、yasna；yasna→time。time 包早已存在，但用途和生产边增加，仍须审。
- 新用途/feature 边：root→aws-lc-rs，rustls/webpki→aws-lc-rs；不将 AWS-LC 原来只供 SS 的审查自动当作新静态 X25519/ML-DSA/TLS provider 已验证。
- rcgen 无生产 pem/ring/aws-lc-rs/x509-parser/zeroize 边；pem 3.0.6 为当前 dev 合并闭包，MIT，不计本批新增生产。
- `aws-lc-sys → cc 1.11.0(parallel)、cmake 0.1.58、dunce 1.0.5、fs_extra 1.3.0、Unix pkg-config 0.3.34`；cc 再用 jobserver 0.1.35、find-msvc-tools 0.1.15、shlex 2.0.1、libc。以上已在生产构建链，不是 REALITY 新增包，但新 feature 原生参数需重核。
- 这些构建包许可：cc/cmake/pkg-config/jobserver/find-msvc-tools/shlex/libc 为 MIT OR Apache；fs_extra 为 MIT；dunce 为 `CC0-1.0 OR MIT-0 OR Apache-2.0`。闭包另有 subtle BSD-3-Clause、rustls-webpki/untrusted ISC、ring Apache-2.0 AND ISC。跨平台 r-efi 的 LGPL 是 OR 选择项，可选择实际提供的 MIT/Apache，不表示项目必须采用 LGPL。
- 未计根的重点依赖及其解析 normal/build 闭包（含全部平台边与 metadata 的 dev feature 合并）为72个包版本、70个包名，最高已声明 MSRV 1.89（aes）；成功生产 tree 中未见声明高于1.91。此72项集合刻意包含 pem/time-macros 等非当前宿主生产项，不能冒称严格生产包数，也不是完整 Cargo.lock 审计。

## 关键 API 静态核对

源码来自下面校验过的精确发布包；只是接口可行性，不代替任务 1.2 语义金样或最小编译。

| 用途 | 精确 API/边界 |
|---|---|
| 静态 X25519 | `agreement::PrivateKey::from_private_key(&X25519, raw32)`，不是不支持X25519的 `from_private_key_der`；`compute_public_key()`；`agreement::agree(&PrivateKey, peer, error, closure)` 可复用静态私钥；原始秘密经 closure 交 HKDF。低阶点/全零结果应测实际成熟库错误，不自行曲线运算 |
| HKDF-SHA256 | `hkdf::Salt::new(HKDF_SHA256, salt20).extract(ecdh32).expand(&[b"REALITY"], KeyType32)?.fill(out32)`；KeyType只表达长度，不自写HKDF |
| HMAC-SHA512 | `hmac::Key::new(HMAC_SHA512,key)`、`Context::with_key/update/sign` 或成熟 `sign`；绑定串为 pub32 或 pub32∥rawCH∥rawSH，不能把前次HMAC结果再拼接作为新消息 |
| AES-256-GCM | 既有 `aes_gcm::Aes256Gcm` 为 AES256/U12 nonce，默认tag16；`KeyInit`/`AeadInOut` 等成熟API。无需新增算法包或复用VMess的AES128编排 |
| Ed25519/CV | `signature::Ed25519KeyPair::generate_pkcs8`/`from_pkcs8`/`from_seed_unchecked`、真实 public_key，优先可传播错误的 `try_sign`；普通 `sign` 内部expect。种子先做本项目恰32字节校验，不拿from_seed_unchecked名称当允许任意长度 |
| ML-DSA-65 | `signature::PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed32)`；`sign(msg,&mut sig)` 返回长度；标准公钥1952、签名3309。公开契约pure/空context，不支持HashML-DSA/external-mu；不要求与Go deterministic签名字节相同，仍需同seed公钥及跨库验证 |
| DER/特殊signatureValue | `rcgen::KeyPair::from_remote(Box<dyn RemoteKeyPair+Send+Sync>)`、`PKCS_ED25519`；RemoteKeyPair返回真实公钥与64字节HMAC。内部sign_der把其返回值直接写为signatureValue BIT STRING；无需手写DER或盲patch固定偏移 |
| MLDSA首扩展 | `CustomExtension::from_oid_content(&[0,0],sig)`；自定义扩展排在内置AKI/SAN/usage/CA等之后。要成为Extensions[0]，需确保这些内置扩展为空/关闭；默认NoCa、空SAN/usage、AKI=false可以满足，必须独立解析实际DER验证 |
| rcgen无crypto限制 | **显式设置serial_number**；不设时`certificate.rs:658-660`返回MissingSerialNumber，不能靠dev crypto合并掩盖。RemoteKeyPair的serialize_der/serialized_der会panic，不能用它导出真实TLS私钥；CV真实私钥独立持有 |

固定发布提交：

- AWS-LC Rust：`5d496f88b40f327e28315deecc1a5a1fd1e81e95`，例如 [agreement](https://github.com/aws/aws-lc-rs/blob/5d496f88b40f327e28315deecc1a5a1fd1e81e95/aws-lc-rs/src/agreement.rs#L307-L328)、[MLDSA seed](https://github.com/aws/aws-lc-rs/blob/5d496f88b40f327e28315deecc1a5a1fd1e81e95/aws-lc-rs/src/pqdsa/key_pair.rs#L141-L199)、[sign](https://github.com/aws/aws-lc-rs/blob/5d496f88b40f327e28315deecc1a5a1fd1e81e95/aws-lc-rs/src/pqdsa/key_pair.rs#L231-L247)、[pure模式](https://github.com/aws/aws-lc-rs/blob/5d496f88b40f327e28315deecc1a5a1fd1e81e95/aws-lc-rs/src/signature.rs#L108-L114)。
- rcgen：`447322c693d6ef6420ce61fdcdb6de516c04660a`，路径 `rcgen/src/key_pair.rs:181-188,402-449,657-670`、`rcgen/src/certificate.rs:634-835`。
- rustls：`f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`，路径 `rustls/src/crypto/aws_lc_rs/mod.rs:245-278`。后续vendor补丁不在此发布摘要保障范围内。

## 发布来源、普通文件与三方摘要

缓存根：`$HOME/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f`；源码根为对应 `registry/src/index.crates.io-1949cf8c6b5b557f`。九个缓存 `.crate` 均用lstat确认普通文件，归档无符号/硬链接成员；下列为**首次审查/修复前历史表**，SHA256均曾等于对应官方 sparse index cksum与锁文件registry checksum，均 `yanked=false`。time配套四包授权更新后的checksum见前节，已与主会话diff对照；rustls随后同版本改为path，不能将历史registry checksum说成当前path包仍有lock checksum。

| 包 | `.crate` SHA256 |
|---|---|
| aws-lc-rs 1.19.0 | `048006790404103c488e6c5616b3e7e702a71292aadda08e8f7698a9e0d2eb53` |
| aws-lc-sys 0.47.0 | `8bfbe32ac36b3c428696ce315464181bc4029d689fd58e3f2a4e58c252242f52` |
| rustls 0.23.46 | `48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf` |
| rcgen 0.13.2 | `75e669e5202259b5314d1ea5397316ad400819437857b90861765f24c4cf80a2` |
| yasna 0.5.2 | `e17bb3549cc1321ae1296b9cdc2698e2b6cb1992adfa19a8c72e5b7a738f44cd` |
| time 0.3.45 | `f9e442fc33d7fdb45aa9bfeb312c095964abdf596f7567261062b2a7107aaabd` |
| time-core 0.1.7 | `8b36ee98fd31ec7426d599183e8fe26932a8dc1fb76ddb6214d05493377d34ca` |
| time-macros 0.2.25 | `71e552d1249bf61ac2a52db88179fd0673def1e1ad8243a00d9ec9ed71fee3dd` |
| aes-gcm 0.11.1 | `7f2b8006a0c83f52b62ba44a97b58bf76fe2f70a329e588f67f89691d93d498f` |

逐项检查了本地manifest、vcs信息、全部许可证文件及本次读取的关键API源码与归档成员字节相同；结果在 `baseline/archive-verification.json`。这不是对每个源码文件做全量逐字节审计，也不是第三方密码实现独立安全审计。

vcs信息还给出：yasna `b7e65f9a4c317494cce2d18ea02b3d6eaaea7985`；time 0.3.45 `d41b5e129b52dc3486a89a4367e1979496f661d7`；AES-GCM `2eff6ccb137850202ad581afb6e947f302ccbbcf`。aws-lc-sys包记录实际原生AWS-LC提交 `cd481c207e38f06aeb5766f4a1cdfce10a4c0af8`，不能用Rust包装层提交替代原生来源。

### 并发修改下的输入快照

- 最初只读lock SHA256为 `d107638fa5c7560596f15a1482346f17b335ec9ed78463e927641f0f164f3a58`（既有VMess快照）。
- 主会话随后增加直接边和rustls provider；本代理成功保存的 metadata/tree 已含这些新边，不能把它们误称尚未修改的旧manifest基线。生产tree 205项，metadata中rcgen仍有dev feature合并。
- 后续观察到 Cargo.lock SHA256 `7dc99f2a489cea4d02ebd036345c5d7058951e378d63d1b701669e40051c159c`；上述九包版本/checksum仍相同，time仍0.3.45。该次根manifest SHA256 `c1686e3433296856803df03f66dd550318a9d06bd50b524cfdaa845c1902ef45`。
- 此后一次 `cargo tree --offline --locked` 因主会话继续调整尚未同步lock的输入返回101，明确提示不能更新锁。本代理保留失败，不去掉locked重跑，不改锁；该次失败不能当解析成功。
- 后续用户授权最小修复后，主会话补存before/diff/after metadata/tree，并报告新lock SHA256 `a6f70121acafa096472034013e9572754f8ad2d5adbd8a638a1f0507a3a4b2cd`，见前节。**这补充了修复后解析证据，不消除前次失败历史，也不证明最终vendor补丁和编译通过**；后续输入变化仍需重新保存摘要。

## AWS-LC完整原生许可与分发义务

不能只保留 aws-lc-rs 顶层较短的 SPDX 声明。aws-lc-sys 0.47.0 完整声明为：

```text
ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause
AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)
```

已读归档内完整 `LICENSE`（20337字节）、`aws-lc/LICENSE`（20338字节）及 Fiat独立许可，确认：

- AWS新文件 Apache-2.0 OR ISC；BoringSSL旧部分ISC、新部分Apache-2.0；OpenSSL来源部分按此版本原文Apache-2.0，不套用其他历史版本许可推断。
- mlkem-native/mldsa-native：Apache-2.0 OR ISC OR MIT；Fiat：MIT；s2n-bignum：Apache-2.0 OR ISC OR MIT-0（其ML-KEM/SHA3部分另保留有署名MIT选择）；Jitterentropy：BSD-3-Clause。Jitterentropy上游还有GPL替代条款，但本发布包LICENSE明确选择BSD、非GPL；本代理未复制GPL-only代码。
- 原生LICENSE另列公共领域/CC0参考实现，不能因为Cargo表达式不显示CC0就删除实际版权来源说明。
- Google Test、Go测试runner、Wycheproof列在“不编入libcrypto/libssl的测试/构建用途”段，不能据其名字声称生产链接了它们；发布源码包含什么与二进制链接什么需区别。
- 当前原生归档只带顶层两份LICENSE和Fiat独立LICENSE，未单独打包部分被其文字引用的s2n/Jitterentropy LICENSE路径；根完整许可已包含选用许可证全文，实际源码也保留对应SPDX/版权头。分发应保留**完整根许可及适用版权头、Fiat许可**，不把“引用路径未打包”说成许可不存在，也不删来源说明。
- aws-lc-rs LICENSE包含ISC和Apache全文；rustls三个LICENSE文件；rcgen LICENSE包含MIT/Apache。time系列、AES-GCM完整双LICENSE均实际核对。
- yasna发布归档**未打包独立LICENSE文件**，但manifest/README和源码头明确MIT/Apache双选。已按同一发布vcs提交从官方仓库补存 `LICENSE-MIT`、`LICENSE-APACHE`，无改动、未执行；后续分发不能只带一句Cargo元数据而漏全文。

关键完整许可证摘要：

| 原文 | SHA256 |
|---|---|
| aws-lc-rs/LICENSE | `b50b376e7d24a0598488b730c3034ffcd0b58dd36c0913a24b9903a3cfd04bf7` |
| aws-lc-sys/LICENSE | `728536b4160e051f86d7c9c388f704866b3d512cd7df97ac3516c65279523c4e` |
| aws-lc-sys/aws-lc/LICENSE | `977c541bd25ffe36975dde25c028c0cd15ddf3d08243983b58e8a6a3d9447523` |
| aws-lc-sys/aws-lc/third_party/fiat/LICENSE | `43e358d7b6eb109d0f51f7b3a090fd82607965767c25fadee39e922475de2061` |
| rcgen/LICENSE | `2ff0e21d54b189664c884c142f7a608aae1515524b72e6b1ca251577760d44cf` |
| yasna官方提交/LICENSE-APACHE | `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2` |
| yasna官方提交/LICENSE-MIT | `2a7df90e60fd5512b8bca35d3ce90e068f21c52d962855053fd1d9e2e7ca0f16` |

以上不构成法律意见；最终发行须汇总实际版本/选用许可证、版权及NOTICE要求。没有从参考REALITY/Xray移植MPL/GPL协议代码。

## RustSec完整树枚举与全部命中

本轮重新请求公开HEAD，仍为既有VMess报告采用的 `965bf9ad083b58e6340d65829d85217b18be9290`，提交时间 `2026-11-03T20:34:28Z`。完整 Git trees recursive API **2425项，truncated=false**。据上述70个精确包名枚举 `crates/<包名>/*.md` 得32条，全部成功读取正文和versions/withdrawn/informational，保存到私有证据；没有把404、搜索空结果或截断当无公告。

下表的每个ID均可在固定前缀 `https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/<包名>/<ID>.md` 查阅。为紧凑列出与当前分支相关的patched下界；多分支完整区间保存在原文/JSON中，判断不通过字符串简单大小比较。

| 包/锁定版本 | 公告 | 修复/状态与判断 |
|---|---|---|
| aes-gcm 0.11.1 | RUSTSEC-2023-0096 | patched>=0.10.3；当前已修复 |
| aws-lc-sys 0.47.0 | RUSTSEC-2026-0044 | X.509名称约束；patched>=0.39.0；当前已修复 |
| aws-lc-sys 0.47.0 | RUSTSEC-2026-0045 | AES-CCM标签时序；patched>=0.38.0；当前已修复 |
| aws-lc-sys 0.47.0 | RUSTSEC-2026-0046 | PKCS7证书链；patched>=0.38.0；当前已修复 |
| aws-lc-sys 0.47.0 | RUSTSEC-2026-0047 | PKCS7签名；patched>=0.38.0；当前已修复 |
| aws-lc-sys 0.47.0 | RUSTSEC-2026-0048 | CRL分发点；patched>=0.39.0；当前已修复 |
| base64 0.22.1 | RUSTSEC-2017-0004 | patched>=0.5.2；当前已修复 |
| cmov 0.5.4 | RUSTSEC-2026-0003 | patched>=0.4.4；当前已修复 |
| ctutils 0.4.8 | RUSTSEC-2026-0385 | patched>=0.4.4；当前已修复，含近期2026-10公告 |
| once_cell 1.21.4 | RUSTSEC-2019-0017 | patched>=1.0.1；当前已修复 |
| rand_core 0.10.1 | RUSTSEC-2019-0035 | patched ^0.3.1或>=0.4.2；当前已修复 |
| rand_core 0.10.1 | RUSTSEC-2021-0023 | patched>=0.6.2；当前已修复 |
| ring 0.17.14 | RUSTSEC-2025-0007 | unmaintained公告已于2025-02-22撤回，不当作未修漏洞 |
| ring 0.17.14 | RUSTSEC-2025-0009 | AES溢出检查panic；patched>=0.17.12；当前已修复 |
| ring 0.17.14 | RUSTSEC-2025-0010 | <0.17不维护；unaffected>=0.17；当前不命中 |
| rustls-webpki 0.103.16 | RUSTSEC-2023-0053 | patched>=0.101.4（另有旧分支）；当前已修复 |
| rustls-webpki 0.103.16 | RUSTSEC-2026-0049 | CRL匹配；patched>=0.103.10；当前已修复 |
| rustls-webpki 0.103.16 | RUSTSEC-2026-0098 | URI约束；当前稳定分支patched>=0.103.12；已修复 |
| rustls-webpki 0.103.16 | RUSTSEC-2026-0099 | 通配符约束；当前稳定分支patched>=0.103.12；已修复 |
| rustls-webpki 0.103.16 | RUSTSEC-2026-0104 | CRL解析panic；当前稳定分支patched>=0.103.13；已修复 |
| rustls-webpki 0.103.16 | RUSTSEC-2026-0382 | 不信任中间证书；当前稳定分支patched>=0.103.16；已修复，不可降锁 |
| rustls 0.23.46 | RUSTSEC-2024-0336 | complete_io无限循环；当前分支patched>=0.23.5；已修复 |
| rustls 0.23.46 | RUSTSEC-2024-0399 | Acceptor panic；patched>=0.23.18；当前已修复 |
| rustls 0.23.46 | RUSTSEC-2026-0285 | 跨加密级握手消息；patched>=0.23.45；当前已修复 |
| rustls 0.23.46 | RUSTSEC-2026-0346 | session Debug泄密；patched>=0.23.46；当前已修复 |
| rustls 0.23.46 | RUSTSEC-2026-0347 | ECH拒绝后缓冲数据；patched>=0.23.46；当前已修复 |
| rustls 0.23.46 | RUSTSEC-2026-0348 | Brotli证书解压内存；patched>=0.23.46；当前已修复，且本图不启brotli |
| rustls 0.23.46 | RUSTSEC-2026-0349 | SH影响后续KX降级；patched>=0.23.46；当前已修复 |
| shlex 2.0.1 | RUSTSEC-2024-0006 | patched>=1.3.0；当前已修复 |
| time旧0.3.45／现0.3.47 | RUSTSEC-2020-0071 | patched>=0.2.23；两版本均已修复该历史问题 |
| **time旧0.3.45 → 授权后0.3.47** | **RUSTSEC-2026-0009** | **patched>=0.3.47；首次审查命中并暂停，用户授权后修复版本；后续另补实际locked编译及接口门禁才完成task1.1，见首节** |
| untrusted 0.7.1/0.9.0 | RUSTSEC-2018-0001 | patched>=0.6.2；两版本均已修复 |

同一完整树中 aws-lc-rs、rcgen、yasna、time-core、time-macros、num-conv 等其余集合包名未收录公告文件；这只限定数据库快照，不能扩称无未知漏洞或所有公开渠道无报告。本轮没有执行cargo-audit或安装审计器；task 8.3仍须最终全锁/生产feature/原生/补丁复审。

## 可复现命令、证据与失败历史

主要命令如下，均应使用绝对项目路径，Python只处理数据：

```sh
openspec status --change add-reality-vless-inbound --json
openspec instructions apply --change add-reality-vless-inbound --json
cargo metadata --offline --locked --manifest-path $PROJECT_ROOT/Cargo.toml --format-version 1
cargo tree --offline --locked --manifest-path $PROJECT_ROOT/Cargo.toml -p dubhe --edges normal,build --prefix none --format '{p} features=[{f}]'
cargo tree --offline --locked --manifest-path $PROJECT_ROOT/Cargo.toml --edges normal,build,features -i aws-lc-rs@1.19.0
cargo tree --offline --locked --manifest-path $PROJECT_ROOT/Cargo.toml --edges normal,build,features -i time@0.3.45
curl -fsSL https://api.github.com/repos/RustSec/advisory-db/commits/HEAD
curl -fsSL 'https://api.github.com/repos/RustSec/advisory-db/git/trees/965bf9ad083b58e6340d65829d85217b18be9290?recursive=1'
# 索引精确行；不能把无行/失败当验证成功
curl -fsSL https://index.crates.io/aw/s-/aws-lc-rs
curl -fsSL https://index.crates.io/aw/s-/aws-lc-sys
curl -fsSL https://index.crates.io/ru/st/rustls
curl -fsSL https://index.crates.io/rc/ge/rcgen
curl -fsSL https://index.crates.io/ya/sn/yasna
curl -fsSL https://index.crates.io/ti/me/time
curl -fsSL https://index.crates.io/ti/me/time-core
curl -fsSL https://index.crates.io/ti/me/time-macros
curl -fsSL https://index.crates.io/nu/m-/num-conv
# 修复候选仅作为数据下载到每包新建空目录
# https://static.crates.io/crates/<name>/<name>-<version>.crate
```

私有证据包含成功metadata/tree、九包摘要对照、32条公告正文与parsed TOML、完整非截断树、官方索引原文、最小修复四归档与manifest/许可证、yasna固定提交许可。关键证据文件SHA256：

| 相对证据根路径 | SHA256 |
|---|---|
| baseline/cargo-metadata.json | `9ba5af13352d11138e09a2add3452b4b23cee6e3d05e1f3670cb4a900d8cc1a9` |
| baseline/production-tree.txt | `0d9f7a0d6d33ec5d82d8c1e1737fe50e1bb300b0e9ff7acf5955a90cb6b07cac` |
| baseline/archive-verification.json | `feeda17adcfe9973bfbd543c0d871a1244161918218727178090b1d15a6fcf6c` |
| baseline/time-update-candidate.json | `ff027e17783698f2d660992388ef56c14a19c03517b0785a7eefd37b8e5c425c` |
| rustsec-tree/tree.json | `b1ab28993d87af5647f3e8bf120cbe60c5263438fdb165e63150cb391464e097` |
| rustsec-tree/advisories.json | `6b2597f393c7ad52715f41d3e3a623f1e1faa7e2786bf73eec0e98ab18e0f402` |

失败与纠正不隐藏：

1. 本地搜索猜 `aws-lc-rs/src/pqdsa/mod.rs`、根 `src/logging.rs` 不存在；实际模块入口为`src/pqdsa.rs`、日志调用在`src/main.rs`。均为只读定位错误，不是构建失败。
2. 首次索引文件glob按`index-time-*`也可匹配time-core/time-macros，导致精确版本取不到或摘要断言失败；已改为同时按JSON内**精确name+vers**匹配，九包对照全部重跑成功。没有将失败当摘要通过。
3. time修复归档初次将多个同名`rfc2822.rs`平铺保存，后项测试成员覆盖了前项解析器证据；原归档未动，已直接按精确成员路径另存`src-parsing-combinator-rfc-rfc2822.rs`，SHA256 `31e2b343501a322d3a1b28e3eff1ddab364d090ef4328dbcb28097febf0ea020`。递归修复判断只依据该精确成员，不依据被覆盖同名文件。
4. 并发输入变化后locked tree返回101，未移除locked、未写锁、未据此宣称最终解析成功。主会话的编译/锁定结果需另附实际命令和退出码。

## 后续门禁

- time命中已报告并曾暂停；用户随后真实选择允许必要最小修复，主会话已完成四包更新/fetch并交付差异与解析工件。本代理已将其lock checksums与此前官方index/归档核查结果对照，保留首次发现、暂停及num-conv中间纠正历史，不将授权误写成风险豁免。
- 当前time0.3.47已满足该公告patched区间。静态报告交接时尚缺编译，因此当时未勾任务1.1；随后主会话已实际完成 `cargo check --locked --offline -p dubhe --all-targets`（退出0），以及配置44项、REALITY模块、业务/回落/资源定向测试，任务1.1已据真实静态与编译证据勾选。最终统一命令/输入见[开发记录](reality-development.md)。这不抹掉上述失败，也不代表精确Rust1.91或最终全锁审计完成。
- 主会话完成最小locked生产编译与无crypto rcgen API证明；task1.2验证AuthKey/SID、基础HMAC/CV、首扩展及同seed MLDSA跨库语义。不把静态接口存在当作测试通过。
- task1.3单独核查官方rustls可复现vendor及默认关闭四类补丁，确保同一版本类型和旧TLS回归；原始发布摘要不为补丁后代码背书。
- task8.3使用精确Rust1.91 locked all-targets真实编译，记录平台/原生编译参数和完整许可/安全公告；旧SS的MSRV记录不继承为本批证明。
- 所有最终验收在同一最终生产/测试/vendor/lock输入上另作记录；本文件不批准官方内核运行、容器、发布、部署或系统网络/权限变更。
