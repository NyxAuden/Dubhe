# VMess 依赖门禁（任务 1.1 的静态依赖部分）

查询日期：2026-11-05；RustSec 查询起点 `2026-11-05T05:03:13Z`。本报告仅核查包元数据、锁文件、生产特性、发布摘要、许可和公开公告；**不是 VMess 最终验收、完整漏洞审计或 MSRV 实际构建通过报告**。

本次仅新建本文件，没有修改 Cargo.toml、Cargo.lock、源码、规划或权限；没有安装工具、执行上游/下载代码、参考客户端、构建脚本、代理或容器。Cargo 命令仅为 `metadata`、`tree`，均 `--offline --locked`。未下载或解包新归档；发布归档摘要来自已经存在的 Cargo 缓存。网络只读查询官方 crates.io 稀疏索引及 GitHub RustSec 数据。密码向量与根项目编译由主会话负责，本文不代替其执行证据。

## 结论与范围

- 下述七个直接依赖、两个新传递依赖均在官方稀疏索引确认存在、`yanked=false`；本地 `.crate` SHA256、Cargo.lock checksum、稀疏索引 cksum 三方一致。
- 当前宿主生产 normal/build 图中 203 个包的已声明 MSRV 最高为 1.91（含根包），未发现声明大于项目 1.91 的条目。**声明不是用精确 Rust 1.91 编译的结果**；未声明 MSRV 的既有包也不能据此证明兼容。
- 固定 RustSec 完整树和相关公告逐项比对后，所审 VMess 直接/生产传递链未发现当前锁定版本落入公告影响范围。此结论只覆盖下面列出的包名与数据库快照，不代表“整个项目无漏洞”。
- 生产 features 存在既有 Shadowsocks 链的合并，不能声称全图都关闭默认特性。未为 VMess 改变该既有链或扩大 SS 算法范围。
- 任务 1.1 的编译/密码语义测试由主会话另行确认；任务 7.3 的精确 MSRV、最终生产图、全量锁文件许可/公告复审仍待执行。

## 锁文件、直接版本和实际生产 features

核对时 Cargo.lock SHA256：

```text
d107638fa5c7560596f15a1482346f17b335ec9ed78463e927641f0f164f3a58
```

当前工具链：`rustc 1.95.0 (59807616e 2026-04-14)`、`cargo 1.95.0 (f2d3ce0bd 2026-03-21)`；声明 `rust-version = "1.91"`。本地包根目录为 `$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f`，缓存归档根目录为 `$HOME/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f`。

| 包 | 根 manifest 约束 | 当前生产合并 features | 包声明 MSRV | 包声明许可 |
|---|---|---|---|---|
| aes | `=0.9.4`, default=false | 无 | 1.89 | MIT OR Apache-2.0 |
| aes-gcm | `=0.11.1`, default=false, aes/alloc | aes, alloc, default, getrandom | 1.85 | Apache-2.0 OR MIT |
| chacha20poly1305 | `=0.11.0`, default=false, alloc | alloc, default, getrandom | 1.85 | Apache-2.0 OR MIT |
| md-5 | `=0.11.0`, default=false | alloc, default, oid | 1.85 | MIT OR Apache-2.0 |
| shake | `=0.1.0`, default=false | 无 | 1.85 | MIT OR Apache-2.0 |
| crc32fast | `=1.5.4` | default, std | 1.63 | MIT OR Apache-2.0 |
| cryptoxide | `=0.5.1`, default=false, hmac/sha2 | digest, hmac, mac, sha2 | 1.78 | MIT/Apache-2.0 |

`aes-gcm` / `chacha20poly1305` 的 default/getrandom、`md-5` 的 default/alloc/oid 来自既有 `shadowsocks -> shadowsocks-crypto 0.8.0` 生产边。根边的 `default-features=false` 只关闭该边请求，不会抵消其他边。未启用 cryptoxide 的默认 argon2/blake2/sha1/sha3/curve25519 等特性；未启用 AEAD 的 reduced-round、额外 buffer 功能；没有新增密码原生库后端。crc32fast 默认 std 是显式保留的普通生产功能。

直接版本精确固定，用于本批 API/向量/锁定结果复现，不意味着永远拒绝安全更新。AES、AEAD、MD5 已在既有 SS 链存在相同版本，直接提升用途而不升级整条链。旧 `sha2 0.10.9` / digest 0.10 链仍保留，不将全项目摘要 API 强行迁移到 digest 0.11。

`cryptoxide 0.5.1` 的 `Hmac::new(digest,key)` 接受具体、已初始化的 Digest，适合 VMess 的嵌套 keyed-hash 构造；不是用普通 HKDF 替代。查询官方索引确认 `cryptoxide 0.6.7` 声明 Rust **1.95.0**，超过项目 MSRV 1.91；故保持已规划的 `=0.5.1`，不静默提高工具链要求。此理由不等于对 0.5.1 做了完整密码学审计。

## SHAKE 修正及 HMAC 状态语义历史

1. 原规划 `sha3 0.12.0` 已移除 `Shake` / `Shake128` / `Shake256`。本地发布包 CHANGELOG 明确记录 2026-05-15 移至独立 `shake`；`shake 0.1.0` CHANGELOG 同样说明初版从 sha3 迁入。公开变更源为 [RustCrypto/hashes#869](https://github.com/RustCrypto/hashes/pull/869)。
2. 据本批规划保留的历史，2026-11-05 已报告原 API 不成立并暂停，用户随后要求继续；现用官方拆分包 `shake =0.1.0`。这是依赖/API纠正，SHAKE128 算法及 wire 不变。当前 Cargo.lock 已无 sha3；不得把原依赖方案描述为编译通过。
3. 主会话报告：crypto 派生金样已通过，但首次重复 `result/reset` 测试发生 panic。本次只读核实 cryptoxide 0.5.1 的 `Digest::result` 文档允许多次调用，而 `sha2::Sha256::result` 自身检查 `!computed` 并消耗状态；`Hmac::raw_result` 后续读取又调用底层 result，因而不能把该单次 SHA256 实现直接作为可重复读取的 Nested 根。
4. 当前源码 `src/protocol/vmess/crypto.rs` 的 Nested 底层已由主会话改为既有 RustCrypto `sha2::Sha256`，通过 `clone + finalize`、update/reset 薄转发满足接口语义；每层 HMAC 仍由 cryptoxide 库完成，没有自行写 ipad/opad、压缩函数或密码原语。单独 `derive_response` 仍使用 cryptoxide SHA256 的单次 result。此处记录实现与失败历史；修正后的回归结果由主会话填写其他验收证据，本报告未运行测试。

只读源码锚点：本地 cryptoxide `src/digest.rs:45-58`、`src/sha2.rs:82-95`、`src/hmac.rs:105-116`；项目 `src/protocol/vmess/crypto.rs:18-49,78-83`。

## 发布包完整性、来源与许可

以下表的 SHA256 同时匹配本地缓存、lock 与官方稀疏索引；各项均未撤回。发布提交来自本地发布包 `.cargo_vcs_info.json`，不是另行下载执行所得。

| 包 | `.crate` SHA256 | 发布提交 |
|---|---|---|
| aes 0.9.4 | `fc0fc36d7440d015b45468ba08a21e80e056ebbd014c611c6298bb7503e04bd1` | `9a84f2f8b581f62bcd00e16b5e11a2f6251916ee` |
| aes-gcm 0.11.1 | `7f2b8006a0c83f52b62ba44a97b58bf76fe2f70a329e588f67f89691d93d498f` | `2eff6ccb137850202ad581afb6e947f302ccbbcf` |
| chacha20poly1305 0.11.0 | `9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb` | `e37a978ccf0992d9053fbc039470d6527108e393` |
| md-5 0.11.0 | `69b6441f590336821bb897fb28fc622898ccceb1d6cea3fde5ea86b090c4de98` | `b5051e5a5e7dc86a6c27c1ec7a390744ebcfb97a` |
| shake 0.1.0 | `09057cb2149ad4cbd2da1e26b351f9a4c354219421229c69c3063e6f61947c4a` | `8f3e56dc4e197b8adbc3d5a9ed109e326d6b159c` |
| crc32fast 1.5.4 | `5f97d3416d5337d15c4b0d78c8c91df922ca143f57ec20e2d1c188333047ef04` | `118796a864d40beed113e887522531d5474b8abc` |
| cryptoxide 0.5.1 | `facfae029ec4373769eb4bd936bcf537de1052abaee9f246e667c9443be6aa95` | `3d757dd8ee5b3c279b7717aecfba947440f1e41b` |
| keccak 0.2.2 | `d8f198d1db720e4940b5a493201d199d9f24f568f8f746bd13706243a2f71598` | `ae480398120a0e753048dcf03dfeb2f6882c15aa` |
| sponge-cursor 0.1.0 | `3a0219bd7d979d58245a4f41f695e1ac9f8befdffadd7f61f1bae9e39abc6620` | `9c8674f4fdf00fb524cd06d89da29d125db07582` |

九包均实际携带 LICENSE-MIT、LICENSE-APACHE，并核对 MIT 授权语句和 Apache 2.0 标题。cryptoxide 元数据保留旧式 `MIT/Apache-2.0` 原文，不能误写成两者同时强制的 AND；发布时按实际选择保留版权和许可。该检查不是完整法律审计，也未把上游协议实现代码移植到项目。

直接包除 crc32fast 声明 `build = "build.rs"` 外均 `build=false`；本次没有执行该脚本。新增 keccak/sponge-cursor 也 `build=false`。既有 AWS-LC、ring 等构建链没有在本轮重新编译或重新审计。

## 生产传递链与基线差异

相对既有 `docs/dependency-baseline.md` 的包名/版本表（不是历史 lock 的严格 diff），本批当前生产新增五包：直接 `crc32fast 1.5.4`、`cryptoxide 0.5.1`、`shake 0.1.0`，传递 `keccak 0.2.2`、`sponge-cursor 0.1.0`。后两者均 MSRV1.85、MIT/Apache 双选，features为空；keccak 用既有 cfg-if/cpufeatures，sponge-cursor 无当前启用的生产子依赖。cryptoxide 无传递依赖；crc32fast 只用既有 cfg-if。

VMess可达生产链中其余关键包：aead 0.6.1、cipher 0.5.2、crypto-common 0.2.2、ctr 0.10.1、ghash 0.6.0、polyval 0.7.3（hazmat）、universal-hash 0.6.1、chacha20 0.10.2（cipher/rng/xchacha）、poly1305 0.9.1、digest 0.11.3（alloc/block-api/default/mac/oid）、block-buffer 0.12.1、hybrid-array 0.4.15、inout 0.2.5、ctutils 0.4.8、cmov 0.5.4、cpubits 0.1.1、cpufeatures 0.3.1、typenum 1.20.1、const-oid 0.10.2、getrandom 0.4.3、rand_core 0.10.1、libc 0.2.191、cfg-if 1.0.5。这些已经存在于基线，不应全计为VMess新引入；ctutils声明MSRV1.87，其余这批新RustCrypto接口主要为1.85，均不超过1.91。

全锁文件相对该表还多出 `aes-gcm-siv0.12.1`、`bloomfilter3.0.2`、`camellia0.2.1`、`ccm0.6.1`、`siphasher1.0.4`、`sm40.6.0` 六项，但本次 `cargo metadata` 无对应解析包，根生产tree亦无这些包；属于lock中保留的可选项，不是VMess生产启用或本轮通过完整公告审查的证明。由于未获历史lock逐字节快照，本文不对其首次引入时间作结论。不能删除它们以缩小最终7.3的全锁文件审计范围。

## RustSec 公开公告查询

固定快照：[RustSec/advisory-db `965bf9ad083b58e6340d65829d85217b18be9290`](https://github.com/RustSec/advisory-db/commit/965bf9ad083b58e6340d65829d85217b18be9290)，GitHub提交时间 `2026-11-03T20:34:28Z`。Git trees recursive API返回 **2425项、truncated=false**；不是用单包目录404或截断搜索冒称无公告。

核查包名集合：上述七直接及其生产闭包 aead、cipher、digest、crypto-common、cpubits、cpufeatures、universal-hash、ghash、polyval、poly1305、chacha20、block-buffer、inout、hybrid-array、typenum、cmov、ctutils、ctr、rand_core、keccak、sponge-cursor、const-oid、cfg-if、getrandom、libc，另纳入保留的sha2。该快照按 `crates/<精确包名>/*.md` 完整枚举得到以下8条，均成功读取正文与patched条件，没有靠404推断：

| 公告 | 对象/已公开问题 | patched | 本锁版本及判断 |
|---|---|---|---|
| [RUSTSEC-2023-0096](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/aes-gcm/RUSTSEC-2023-0096.md) | aes-gcm，坏tag后暴露解密缓冲 | >=0.10.3；<0.10.0不受影响 | 0.11.1，已在修复范围 |
| [RUSTSEC-2019-0029](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/chacha20/RUSTSEC-2019-0029.md) | ChaCha计数溢出重复密钥流 | >=0.2.3 | 0.10.2，已修复；公告亦说明chacha20poly1305不受该历史问题影响 |
| [RUSTSEC-2026-0003](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/cmov/RUSTSEC-2026-0003.md) | ARM32非恒时生成 | >=0.4.4 | 0.5.4，已修复 |
| [RUSTSEC-2026-0385](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/ctutils/RUSTSEC-2026-0385.md) | mask/u128比较非恒时；2026-10-23公告 | >=0.4.4 | 0.4.8，已修复；没有遗漏近期公告 |
| [RUSTSEC-2026-0012](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/keccak/RUSTSEC-2026-0012.md) | 旧opt-in ARMv8 asm约束unsound | >=0.1.6 | 0.2.2，已在修复范围 |
| [RUSTSEC-2019-0035](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/rand_core/RUSTSEC-2019-0035.md) | 旧版未对齐访问 | ^0.3.1 或 >=0.4.2 | 可达0.10.1，旧链0.6.4亦已修复 |
| [RUSTSEC-2021-0023](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/rand_core/RUSTSEC-2021-0023.md) | RNG种子长度检查错误 | >=0.6.2；<0.6.0不受影响 | 0.10.1及0.6.4均已修复 |
| [RUSTSEC-2021-0100](https://github.com/RustSec/advisory-db/blob/965bf9ad083b58e6340d65829d85217b18be9290/crates/sha2/RUSTSEC-2021-0100.md) | 0.9.7 AVX2长消息错误 | >=0.9.8；<0.9.7不受影响 | 保留0.10.9，已修复 |

集合内其余包名在这次完整树中无公告文件；这只代表**该快照中未收录**，不保证无未知漏洞，也不覆盖GitHub未纳入RustSec的所有报告。没有运行 `cargo audit` 或安装审计工具；没有借此宣称全锁文件、跨平台、整个SS/TLS链完成最终审计。

## 可复现命令与失败历史

下列命令均在项目根运行；Python均 `-I`、仅读标准库及受控本地数据，没有执行下载脚本。

```sh
rustc --version
cargo --version
cargo metadata --offline --locked --format-version 1
cargo tree --offline --locked -p dubhe --edges normal,build --format '{p} features=[{f}]' --depth 2
for p in aes@0.9.4 aes-gcm@0.11.1 chacha20poly1305@0.11.0 md-5@0.11.0 shake@0.1.0 crc32fast@1.5.4 cryptoxide@0.5.1; do
  cargo tree --offline --locked --edges normal,build -p "$p" --format '{p} features=[{f}]'
done
cargo tree --offline --locked -p dubhe --edges normal,build,features -i aes-gcm@0.11.1
cargo tree --offline --locked -p dubhe --edges normal,build,features -i md-5@0.11.0
shasum -a 256 Cargo.lock
for p in aes-0.9.4 aes-gcm-0.11.1 chacha20poly1305-0.11.0 md-5-0.11.0 shake-0.1.0 crc32fast-1.5.4 cryptoxide-0.5.1 keccak-0.2.2 sponge-cursor-0.1.0; do
  shasum -a 256 "$HOME/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/$p.crate"
  jq -c . "$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/$p/.cargo_vcs_info.json"
done
```

生产包数/MSRV聚合：从 `cargo tree --prefix none --format '{p}' --edges normal,build -p dubhe` 提取包名/版本，与metadata对照，得到203、最高声明1.91、大于1.91的集合为空。基线差异是标准库 `tomllib` 读lock、正则读既有Markdown表后集合比较，没有运行项目的文档生成脚本。

官方索引成功查询命令如下（每行取精确版本，不能把空结果当已验证）：

```sh
for spec in '3/a/aes:0.9.4' 'ae/s-/aes-gcm:0.11.1' 'ch/ac/chacha20poly1305:0.11.0' 'md/-5/md-5:0.11.0' 'sh/ak/shake:0.1.0' 'cr/c3/crc32fast:1.5.4' 'cr/yp/cryptoxide:0.5.1' 'cr/yp/cryptoxide:0.6.7' 'ke/cc/keccak:0.2.2' 'sp/on/sponge-cursor:0.1.0'; do
  index_path="${spec%:*}"; version="${spec##*:}"
  curl -fsSL "https://index.crates.io/$index_path" |
    jq -c --arg v "$version" 'select(.vers==$v) | {name,vers,cksum,yanked,rust_version,features,features2}'
done
```

RustSec 查询固定步骤：

```sh
date -u '+%Y-%m-%dT%H:%M:%SZ'
curl -fsSL https://api.github.com/repos/RustSec/advisory-db/commits/HEAD |
  jq '{sha,commit:{committer:.commit.committer},html_url}'
curl -fsSL 'https://api.github.com/repos/RustSec/advisory-db/git/trees/965bf9ad083b58e6340d65829d85217b18be9290?recursive=1' |
  jq '{sha,truncated,count:(.tree|length),selected:[.tree[].path|select(test("^crates/(aes|aes-gcm|chacha20poly1305|md-5|shake|crc32fast|cryptoxide|aead|cipher|digest|crypto-common|cpubits|cpufeatures|universal-hash|ghash|polyval|poly1305|chacha20|block-buffer|inout|hybrid-array|typenum|cmov|ctutils|ctr|rand_core|keccak|sponge-cursor|const-oid|cfg-if|getrandom|libc|sha2)/.*\\.md$"))]}'
for p in crates/aes-gcm/RUSTSEC-2023-0096.md crates/chacha20/RUSTSEC-2019-0029.md crates/cmov/RUSTSEC-2026-0003.md crates/ctutils/RUSTSEC-2026-0385.md crates/keccak/RUSTSEC-2026-0012.md crates/rand_core/RUSTSEC-2019-0035.md crates/rand_core/RUSTSEC-2021-0023.md crates/sha2/RUSTSEC-2021-0100.md; do
  curl -fsSL "https://raw.githubusercontent.com/RustSec/advisory-db/965bf9ad083b58e6340d65829d85217b18be9290/$p"
done
```

保留失败记录：crates.io版本API对七直接包和cryptoxide0.6.7均HTTP403，不能当未撤回/无公告；后续官方sparse index成功提供精确记录。第一次sparse循环在zsh误用变量名 `path`，覆盖该命令进程的PATH导致curl/jq找不到；命令未取得数据，已改为局部 `index_path` 后重跑成功，没有修改系统或权限。早期搜索误指尚不存在的 `src/vmess`、根级vmess通配符得到无文件，随后仅定位正确 `src/protocol/vmess/crypto.rs`。这些均不覆盖实际失败、不构成测试通过。

## 后续仍须执行

- 主会话完成当前根check、密码向量以及重复result/reset修正后的回归；本文不预告通过结果。
- 精确Rust1.91.0执行最终locked all-targets构建，分别记录真实平台、构建脚本/原生参数；既有SS历史MSRV证据不能自动继承为本批VMess证据。
- 任务7.3对最终生产features和完整lock（包括开发/跨平台/可选残留条目）重新出具全量许可/安全公告记录，并更新旧基线的“直接/传递”分类；本次未改写旧基线。
- lock或依赖版本变化后重算摘要、复查新版本许可/MSRV/yank/公告。当前未发现实质依赖阻塞，不等于批准发布、部署或扩大参考客户端执行权限。
