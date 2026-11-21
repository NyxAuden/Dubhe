# Snell TCP 顺序连接复用对齐记录（2026-11-11）

变更：`align-snell-outbound-reuse`。在既有 v4/v5/v6 记录出站与适用 obfs 上增加默认关闭的 `snell.reuse`，不是并发多路复用，不改 wire。UDP 与 QUIC 不因本批复用；前者按固定上游独立建连，后者尚未实现。

## 固定上游

`github.com/sagernet/sing-snell@v0.0.0-20260904135315-bc5a12ac736f` 与 sing-box v1.14.4。只读核对 `snellv4/client.go`、`snellv6/client.go`、两版 `reuse.go`、`internal/reuse/reuse.go` 及 sing-box Snell outbound 的复用/UDP分派，不编译或运行上游。

| 文件 | SHA256 |
| --- | --- |
| `snellv4/reuse.go` | `5f6ca8cd0902d65290e5f2d9504339688ae97c7cd4e990e2713c1fcd2337ee04` |
| `snellv6/reuse.go` | `dcd883d3bf647ee89b25251d9a6e8dab9d551850a14be522b2688dce84cc6c57` |
| `internal/reuse/reuse.go` | `877f20a0dd343cbfc6c5439b5ee139b7ca7ad9241a0ed803c20d42cf0d9c610d` |

上游复用的是同一记录流状态，每个目标重新发送 CONNECT_V2、读取 ReplyTunnel/ReplyError；CloseWrite 发零块，Close 后必要排空到对端逻辑零块。固定上游池最多 10 项、180 秒最大空闲年龄、20 秒清理周期，丢弃达到 `0x80001` 字节关闭。本实现另设排空总期限 30 秒，不接受无界等待。上游 v4/v5 共享记录、v6三模式与正式 obfs 组合保持既有配置边界。

## 实施

- 配置：`SnellClientOptions.reuse: bool` 默认 false，严格拒绝非布尔值，序列化保留；每个编译出站独立 Arc<Pool>，Debug 凭据仍脱敏；新模板 `examples/snell-reuse-outbound.json`。
- 逻辑流：沿用 `ClientStream` 所有的 Reader/Writer/future，仅重新建立逻辑应答/缓存/FIN 状态，保留 salt/nonce/profile 与 obfs 首消息状态；不把延迟应答强改为建连前认证确认，不自动重放失败业务。
- 回池：只允许已验证首应答且无失败的租借；已接受写完成、发送一次零块并收到对端正式零块后 ready。尚有下行则由原状态机排空，累计丢弃达到 `0x80001` 或总耗时 30 秒关闭；错误应答/AEAD、传输截断、失败写、未读首应答、取消中的重新请求均不回池。
- 池：10 permit 同时覆盖 waiting+ready，FIFO、取用时检查180秒过期，单个弱所有权清理器每20秒清理。活流只持 Weak<Pool>；后台不自持 Context/Pool，所有任务在现有 TaskTracker 下。
- 路径：Context 根出站与链式 Snell 中间跳先取池，仅池空才调用原承载工厂，不先拨号再丢弃。UDP不取池。无运行时所有权的低层 public `outbound::connect` 显式拒绝 reuse，要求 Context 工厂，不静默忽略。
- 生命周期：热替换时显式停用旧路由池（不能依赖初始 Context 被释放），关闭旧 ready/waiting，已交付活流不因池失效关闭且不再回旧池。最终实例出站取消信号跨热重载共享，children.close/wait 前取消，停机不等180秒空闲期限。

## 开发验证与真实失败

环境：macOS ARM64，Rust/Cargo1.95.0，`CARGO_INCREMENTAL=0`，锁定离线，默认线程栈；无新依赖或 vendor 变更。

- 首轮全目标 check 退出0；新增模块 **2 passed、7 failed、0 ignored**，集成因前一步失败未执行。原因是新增独立 raw 对端误用请求版本1作为记录版本，实际固定记录层是4（原有独立 Snell wire 测试也为4）。仅改测试向量，不改变生产报文；日志 `/tmp/rpk-snell-reuse-targeted.9YKjRf`。
- 修正后定向：9项池模块、6项新集成、20项既有入站、9项基础出站、6项obfs集成全部通过，退出0；模块另外652项被过滤，不称全量。日志 `/tmp/rpk-snell-reuse-targeted-fixed.y9vSGI`。
- 收尾额外补坏AEAD/无逻辑零块的传输EOF、显式旧池停用（运行时仍保留旧Context）、旧空闲承载在热替换时关闭、新示例roundtrip；全目标check、11项池模块、6项池集成与2项既有热重载用例全部通过，退出0。日志 `/tmp/rpk-snell-reuse-final-targeted.6P9hYE`；这仍不是完整回归。
- 本批最终 `cargo fmt --all -- --check`、`cargo check --locked --offline --all-targets`、`cargo test --locked --offline` 全部退出0；**1289 passed、0 failed、43 ignored**，76个结果块。日志 `/tmp/rpk-snell-reuse-validation.sx9g8X`；显式去除 `RUST_MIN_STACK`，使用默认线程栈。相较obfs收尾输入新增17项（11模块、6集成）；结果只覆盖本批收尾代码，不覆盖后续能力改动。

模块/集成覆盖：独立 raw 对端延迟应答、跨目标旧数据隔离及FIN一次；全部记录模式/适用obfs连续salt/nonce状态；读写Pending/取消、半请求销毁、池上限/排空字节、虚拟时间超时和过期、弱所有权与热替换活流、并发/默认关闭、UDP独立、认证/路由拒绝、运行时/链式真实物理拨号计数、最终停机和端口重用。

本批完整回归完成后仅清理本项目 `target/debug/deps/*.rcgu.o`：1159个文件、逻辑6.06GiB；库、测试二进制、日志与私有资产全部保留。清理后本机可用约38GiB。

现有警告仍存在，退出0不等于零警告。无全局 `RUST_MIN_STACK`、无降容量或删负向用例掩盖失败。

## 验收边界

官方Snell/Surge/sing-box客户端、三平台、精确MSRV、release、长期稳定性/容量与正式安全审计未执行；本机双方回环、独立raw对端与记录向量不等同官方互通。不Git/归档/发布，不修改系统代理/DNS/路由/防火墙，不操作Colima/容器/系统缓存。日志与私有测试资产保留在本机。
