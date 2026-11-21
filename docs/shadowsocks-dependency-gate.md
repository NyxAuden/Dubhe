# Shadowsocks 依赖与适配门禁

测试日期：2026-11-04；交付核对：2026-11-05。**原生 Shadowsocks TCP/UDP 已接入内核运行器；三家固定官方客户端24项Shadowsocks及同一新构建旧九项回归全部通过，共87个场景。** 当前平台验证、输入摘要与失败历史见 [验收报告](shadowsocks-acceptance.md)。既有 VLESS 验收二进制是历史快照，本批九项是重新实际执行，不继承历史摘要或外部互通结果。

## 来源与补丁

1. 已从官方 Cargo 索引核对未撤回版本的 checksum，重新计算下载包 SHA256，核对 `.cargo_vcs_info.json` 的完整提交并阅读 MIT 许可；未执行解包目录中的脚本。
2. `vendor/shadowsocks` 保留发布来源、MIT 许可及 `UPSTREAM.json` 原始逐文件摘要。`shadowsocks-crypto` 不修改，使用锁定的 registry 包。
3. MIT 协议 crate 的本地补丁包括：禁用 2022 UDP 认证前派生密码缓存；2022 TCP padding≤900、完整读取及变量头含 padding 必须位于首认证 chunk；每个 TCP 方向固定最多 `2^63` 次实际 AEAD 操作，错误或耗尽后永久终止。没有修改密码学原语。维护边界见 `vendor/shadowsocks/PATCH.md`。
4. 当前可复现 `vendor/shadowsocks/upstream.patch` 为 **1174 行**，SHA256：`9f4c7fd398c017df13d75084ade4237837619c11c389249b2b219a493fb92098`。生成器已核对两归档和原始逐文件摘要；新增用途说明没有改写上游摘要。

| 包 | 版本 | SHA256 | 发布提交 |
|---|---|---|---|
| shadowsocks | 1.25.0 | `e2065b026dbe4f47048eca384adf07f693bf901050d80abd3adb7b2422709b2d` | `ab388c7466d21f979430e33cc9ef10e22fb05955` |
| shadowsocks-crypto | 0.8.0 | `b404a62ebea5003f44b9a2748dee7555c5f9ae39896508e466a2a91ee6fa5df5` | `2ac3f4f6194476ff7b7be2a43c3a83e33510663b` |

crates.io 元数据 API 曾返回 HTTP403，随后正常通过 Cargo 官方索引核对 checksum，没有绕过认证或权限。原始私有来源证据为 `.test-artifacts/ss-source-kmkobk2f/manifest.json`；其中静态暂停快照不代表当前源码构建，不公开整个目录。

## 已执行的依赖门禁

- 生产 features 的 vendor 全库：**25 passed、0 failed**，包括 20 项预算、2 项缓存和3项原有测试。预算模块改为 `tcprelay/mod.rs` 唯一私有模块后消除了重复基础测试，原先26项并非另一个保护能力。
- 两项缓存测试覆盖三个2022方法的缓存/无缓存报文一致性及各2048个不同SID的合法/损坏标签输入。生产禁用路径不声明线程局部缓存；这些是同源密码测试，不是官方互通。
- 预算测试在内部注入0/1/2/3/4/8及最后一次预算，覆盖六方法、请求/响应头、Pending、部分写、tag错误、部分输出后I/O失败、耗尽后零后续I/O；没有真实遍历 `2^63` 或 `2^96` 次操作。仅允许已经认证/加密的最后缓冲排空，下一次AEAD永久拒绝。
- 公开适配接口 `tests/shadowsocks_dependency.rs`：**22 passed**。覆盖六方法、两AES EIH模式及双用户、TCP/UDP接口、首载荷、半关闭、透明salt观察、一次首读、padding900合法及901/截断/跨首chunk拒绝。
- 每连接库 Context 的有限状态结论来自调用路径与独立/共享 Context 行为测试，不是池项数或RSS实测。全局精确重放由内核另行负责。

## 原生接入与本地验证

以下均有实际执行证据；最终三平台普通回归与显式官方矩阵已另行统一运行，输入摘要、数量及历史失败分别保存在[验收报告](shadowsocks-acceptance.md)：

- 配置测试 **5 passed**、CLI **9 passed**、联合监听 **3 passed**。严格标准Base64及密钥长度、EIH静态索引、null/未知字段、身份唯一性、脱敏、check无绑定、联合准备失败无ready和端口释放均有回归。
- 原生 TCP 已接入共享路由、DNS、连接/握手许可和双向relay；原生 UDP 已接入共享关联/字节预算、队列、目标上限与同一 stop/force/children 屏障。runtime 不再临时拒绝 Shadowsocks。
- 内核精确salt池、透明salt I/O、8192位滑窗及发送计数器已有单元测试；2017收发/TCP/UDP共用120秒保护域，2022 TCP60秒，2022 UDP会话至少60秒；容量满时拒绝，不提前淘汰保护状态。
- 独立 TCP 手写wire测试 **15 passed**，六方法首载荷、2017地址跨chunk、IPv4/IPv6/localhost域名、双向半关闭、并发同salt只有一个目标、EIH双用户与错误身份、wrong key/tag、全请求截断前缀、非法地址/type/time/padding、一次首读短读及握手超时/取消均有覆盖。只复用成熟密码原语，不用客户端流或生产framing构造请求。
- 原生 UDP 功能集成 **3 passed**，覆盖六方法、双AES EIH用户、空载荷、IPv4/IPv6稳定源端口、迁移、旧回包发最新端点、重放不夺回地址、坏tag不推进窗口和陌生来源过滤；此文件使用库codec，不称为独立wire。
- 独立 UDP wire已由主会话执行 **5 passed**；手写2017/AES2022/ChaCha2022及单层EIH布局，响应独立解密、双用户同SID、错误key/type/time/address/padding/tag及选定截断、反射、跨TCP/UDP重放、多来源/多目标、65507字节完整密文和超限回程计量均有覆盖。扩大测试后遇到临时端口冲突、一次EIH超时及测试future栈溢出；已隔离wire用例的临时端口分配并将大缓冲移到堆上，随后连续5轮各5项全部通过、资源2项及严格Clippy通过。没有确定一次EIH超时的独立根因，保留此历史；最终三平台统一回归均通过。
- UDP生命周期单元 **13 passed**，覆盖计数耗尽及reader关闭后tombstone/slot保留60秒、停接新会话且已有会话可排空、旧代次、MSG_TRUNC、IPv6密文超限、队列/字节预算归还、同SID双用户独立socket、已排队回程迁移、目标上限及Reject先于本地DNS探针、回程salt碰撞8次上限和池满零输出。
- 运行器故障与停机注入 **4 passed**：双栈能力失败时全部监听归还、2017不依赖探针，单监听任务错误使混合入口半帧连接结束，本地不响应DNS服务使分派器队首阻塞但队列/字节/任务数有界，以及活跃TCP慢消费者与原生UDP共同经过有限排空/force/children屏障归还socket。混合SOCKS5/SS资源集成 **2 passed**：共享连接/UDP名额、每入口握手门限、密文字节超预算与恢复、精确明文计量。
- 最大报文测试暴露macOS默认UDP发送缓冲9216字节会拒绝合法大报文，已为SS自持监听/出站socket准备至少65507字节收发缓冲，未修改系统设置；修复后六方法及两AES EIH最大完整密文测试通过。
- 最新完整普通回归：macOS ARM64、Linux ARM64及Linux x86_64/QEMU（Rust1.95.0）各 **209 passed、0 failed、33 ignored**，包含9项参考配置/注册表测试；macOS fmt、all-targets check及严格Clippy均通过，无警告。三平台以`--nocapture`核对IPv6实际运行，无SKIP；x86_64有下述QEMU构建探测警告，不称全部平台无警告。33项忽略为24项新Shadowsocks与9项旧官方客户端测试，不算通过；随后完整显式官方矩阵实际33 passed、0 failed，87场景逐项复核通过，不能把ignored当该证据。
- Linux ARM64首次完整运行曾为112项lib通过、1项失败：测试假定2MiB目标写入必在40ms内背压，Linux缓冲实际允许完成。现改为固定64KiB堆缓冲、最多64MiB/500ms有界填充，客户端保持不读；修改后的完整208项回归通过。AWS-LC原生编译及vendor25项也已在该平台通过。保留首次离线缺缓存和上述失败日志，不以最终通过抹去历史。

CLI屏蔽 `shadowsocks` 库原生日志，保留内核脱敏、限速分类事件，真实未知EIH用户测试验证身份材料不进入CLI输出。该过滤属于本项目CLI subscriber；嵌入lib的调用者必须自行保持日志脱敏，不能宣称vendor所有日志已被修改。

## 依赖与工具链边界

- 生产只启用 `aead-cipher`、`aead-cipher-2022`、`aead-2022-no-udp-cipher-cache`；禁用上游默认features、库DNS、Bloom及stream/extra算法，不依赖 `shadowsocks-service`。
- TLS保持rustls/ring，DNS使用Hickory 0.26.2（2026-11-14 为关闭 RUSTSEC 公告升级，见[生产门禁](production-readiness.md)）。AEAD依赖引入 `aws-lc-rs 1.19.0`、`aws-lc-sys 0.47.0`，没有替换TLS密码后端。`socket2`用于双栈/截断标志/zero-linger；dev `aes`、`blake3`用于独立EIH测试，未自研密码算法。
- AWS-LC声明许可分别为 `ISC AND (Apache-2.0 OR ISC)` 和 `ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)`；分发仍须保留实际选用声明，元数据清单不是法律审计。
- 已实际使用Rust/Cargo1.95.0、Apple clang17.0.0、CMake4.4.5（macOS ARM64）及Linux ARM64容器的Debian原生工具链；Linux ARM64的AWS-LC与全部普通测试已通过。声明MSRV1.91，固定`1.91-bookworm`实际含Rust/Cargo1.91.1，已完成断网`cargo check --all-targets`（含AWS-LC原生编译）；随后通过官方rustup在独立临时容器安装精确Rust1.91.0，`cargo check --locked --offline --all-targets`也通过（含AWS-LC原生编译），未运行该工具链全部测试。Linux x86_64随后以GCC局部QEMU虚拟地址预留完成AWS-LC构建、vendor25项及普通209项；env包装有编译器家族识别和memcmp检查跳过警告，见验收报告，不声称该平台无警告或默认QEMU环境已修复。
- vendor是workspace member以运行补丁测试，default-member仍只有内核。全量metadata/lock中的optional/dev/跨平台条目不等于生产启用；实际功能以根package特性树为准。不得删除这些记录来缩小许可表。

## 权限历史与可复现命令

早期执行曾被权限检查阻止，暂停期间没有换工具、委托代跑或修改权限。随后用户直接选择“允许完整本地验证”，明确授权本项目后续vendor全库、配置/API/CLI/普通回归、fmt/check/严格Clippy，以及相关构建脚本和AWS-LC原生编译；网络仅限受控本机回环。本地构建随后恢复并实际执行成功。用户本轮要求完成所有项后，首次官方客户端命令仍被审批器拦截，未执行；随后用户通过问题工具明确选择“允许上述33项”，授权官方来源、已校验的Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31的24组Shadowsocks及旧九项回环互通，原命令获准后才启动。没有换工具或委托绕过。授权始终不包括系统设置、发布或生产部署；最终完整33项已实际通过，87场景结果已独立核验。

```sh
cargo test --locked -p shadowsocks --lib --no-default-features --features aead-cipher,aead-cipher-2022,aead-2022-no-udp-cipher-cache
cargo test --locked -p dubhe
cargo fmt -p dubhe --check
cargo check --locked -p dubhe
cargo clippy --locked -p dubhe --all-targets -- -D warnings
cargo tree --locked -p dubhe -e features
python3 -I "tools/vendor_shadowsocks.py" ".test-artifacts/ss-source-kmkobk2f/manifest.json" --diff
python3 -I tools/dependency_report.py --output docs/dependency-baseline.md
```

vendor原有格式与当前rustfmt默认不同，整crate格式检查曾失败；未批量重排上游文件以扩大补丁。根内核fmt通过不表示vendor整crate已通过格式检查。原始构建日志按私有任务ID保存，当前生产/测试/release摘要及私有日志索引见[验收报告](shadowsocks-acceptance.md)，最终汇总为`.test-artifacts/ss-final-dji1rlkd/manifest.json`；早先本地快照与官方首轮25通过/8失败均保留，不覆盖为最终结果。

## 门禁结论与持续维护边界

- 长度、时间、双栈能力失败注入、混合协议资源、会话及停机边界已补齐；最终macOS ARM64、Linux ARM64、Linux x86_64（QEMU）各209普通测试通过、0失败、33忽略，vendor各25通过，无IPv6跳过。QEMU构建警告与失败历史完整保留，不把单探针成功当全量结果。
- Linux ARM64精确Rust1.91.0/1.91.1全目标编译检查通过；不是所有架构MSRV全部运行测试。24组官方Shadowsocks及同一新构建旧九项均已在完整33项矩阵实际通过；普通ignored和同源测试不代替外部证据。
- Linux x86_64完整AWS构建使用`AWS_LC_SYS_CC='/usr/bin/env QEMU_RESERVED_VA=0x2000000000 /usr/bin/gcc'`，不全局影响Cargo/Rustc，不禁用汇编或缩减算法。env家族探测回退GNU及memcmp探针跳过均披露；该环境设置只用于本次隔离验证，不修改宿主或项目配置。详见[验收报告](shadowsocks-acceptance.md)。
- 发现依赖与规格冲突时报告，不用库默认行为替换本批契约。未来依赖升级需重新核验补丁、特性、许可、工具链及各兼容单元；本批完成不扩大到未列能力，不归档、不Git、不发布、不部署。
