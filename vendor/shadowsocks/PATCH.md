# 本地协议库依赖补丁

这不是未经修改的上游发布包。上游MIT许可保留在 LICENSE，原始逐文件摘要、发布包摘要及不可变提交见 UPSTREAM.json。

- 来源：shadowsocks 1.25.0；commit `ab388c7466d21f979430e33cc9ef10e22fb05955`。
- 原始发布包SHA256：`e2065b026dbe4f47048eca384adf07f693bf901050d80abd3adb7b2422709b2d`。
- 密码库：shadowsocks-crypto 0.8.0（MIT）；commit `2ac3f4f6194476ff7b7be2a43c3a83e33510663b`；发布包SHA256 `b404a62ebea5003f44b9a2748dee7555c5f9ae39896508e466a2a91ee6fa5df5`。密码库不vendor、不修改。
- 官方索引及下载地址均保留在UPSTREAM.json；下载工具同时核对官方Cargo索引checksum与包内 `.cargo_vcs_info.json`。

## 差异

### 2022 UDP无派生密码缓存

新增feature `aead-2022-no-udp-cipher-cache`，只让2022 UDP的 `get_cipher` 每次构造短生命周期对象，不留下由未认证SID或key指针索引的线程局部缓存。正常不启用此feature时保留原有缓存路径；内核依赖必须开启它。密码算法、KDF、nonce及合法报文格式不变。

两个库内单元测试对比原缓存与禁用缓存的密码结果，并对三个2022方法分别输入2048个不同SID的合法与损坏标签数据报，断言禁用路径不填充测试用缓存。生产禁用feature构建完全不声明该缓存；测试构建额外声明原缓存用于对照。

### 严格2022 TCP变量头

`proxy_stream/protocol/v2.rs` 拒绝大于900字节的入站padding，并使用完整读取，截断padding不再按正常EOF接受。`proxy_stream/server.rs` 拒绝变量头（包括padding）跨越首个认证数据块，不再仅记录警告。保留原有零padding时首块必须带业务载荷的约束。

依赖适配测试 `tests/shadowsocks_dependency.rs` 将原缺口复现改为拒绝回归，覆盖三个2022方法、padding边界/截断及变量头各切分位置。

### TCP每方向固定AEAD操作预算

`tcprelay/mod.rs` 声明唯一的私有 `aead_budget.rs`，`aead.rs` 与 `aead_2022.rs` 共同使用该实现，不重复加载源码；每个reader/writer拥有独立的固定生产上限 `2^63`，不能通过生产接口调大。长度块、载荷块和2022首固定头都在实际AEAD调用前扣减；Pending及密文部分写重试不重复扣减。EIH的AES块不是AEAD，不占用该nonce预算。

读写错误或尝试越限后永久锁定该方向，清空内部缓冲；reader释放cipher，writer不再调用cipher或底层写入。EIH的writer换用户密钥只允许在该方向首次AEAD操作前进行，不能用reset复活已使用或失败的方向。此补丁不修改密码算法、密码库nonce递增实现或报文布局。

最后一次允许的操作已经认证的缓冲明文仍可交付，已加密的在途密文仍可发完；下一次需要AEAD时拒绝，随后不再产生输出或密码操作。测试通过仅 `cfg(test)` 可用的私有小预算注入验证边界，不声称真实执行了 `2^63` 次。共享测试文件 `aead_budget_tests.rs` 覆盖Pending、部分写、认证失败、耗尽、I/O失败及终止后重试；各模块额外覆盖三方法、2022请求/响应和reset约束。

## 可复现差异与验证

`upstream.patch` 包含清单、实现和新增测试，不包含此说明与来源元数据本身。用本项目工具在工程根目录生成（不要在下载/解包目录运行解释器或Cargo）：

```sh
python3 -I tools/fetch_shadowsocks_source.py
python3 -I tools/vendor_shadowsocks.py <新生成的manifest路径> --diff
```

首次vendor命令不带 `--diff`，拒绝覆盖既有目的目录。原始包与提取目录各自隔离，核验工具只提取普通文件，不运行其中的代码。原始本地证据见 `.test-artifacts/ss-source-kmkobk2f/manifest.json`（不公开该私有目录）。

以下是需要相应本地构建/测试授权的验证命令，不应在权限拒绝后换工具代跑：

```sh
cargo test --locked -p shadowsocks --lib --no-default-features --features aead-cipher,aead-cipher-2022,aead-2022-no-udp-cipher-cache cache_tests
cargo test --locked -p shadowsocks --lib --no-default-features --features aead-cipher,aead-cipher-2022,aead-2022-no-udp-cipher-cache aead_budget
cargo test --locked -p rust-proxy-kernel --test shadowsocks_dependency
```

`-p shadowsocks` 的默认features不包含2022，不能省略上述生产features后仍宣称测试覆盖2022。缓存测试、预算测试与接口探针不构成独立wire或官方客户端互通证据。最新执行范围及权限状态见 `docs/shadowsocks-dependency-gate.md`。

## 维护边界

只引入协议crate，不使用上游service/完整relay/插件；业务监听、路由、DNS、全局重放、UDP窗口/会话计数、队列和停机由本内核持有。TCP预算不替代UDP计数器策略。当前仍需通过完整入口、资源及独立报文测试，不因vendor或可编译便宣称支持。

升级前重新核验许可、摘要、MSRV、features和资源行为；只有固定新版提供等价缓存控制、严格协议验证和计数终止保护，并通过本内核回归后，才能移除相应补丁。
