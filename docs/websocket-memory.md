# WebSocket 成熟库 API 与用户态缓冲内存

本批范围是 `tokio-tungstenite =0.30.0`、`tungstenite =0.30.0` 及锁中的 `bytes =1.12.1`。这份说明区分源码分析、可执行原型和实际测量；没有将静态可读当成运行通过，也没有将 1 MiB 消息上限写成整连接内存上限。

## 固定输入与源码接点

读取的是本机 registry 中上述精确版本的普通源码文件，不执行其中脚本、不改依赖或 vendor。以下路径相对对应 crate 的根目录；SHA-256 是本次实际读取文件的摘要，供父流程核对输入，不代替依赖归档/许可/公告门禁。

| crate / 文件 | SHA-256 | 关键接点 |
|---|---|---|
| tokio-tungstenite / `src/lib.rs` | `26ead2ccaceae8c45e225d46391ee3ac598791753c8cc1668f07cddc114f75d7` | 345–385：ready/start_send/flush |
| tokio-tungstenite / `src/compat.rs` | `58e610b11d36e969ecb311d6e8f048db2f19049c8b3787752c53a511f86e39d9` | 149–202：Async IO 到同步 WouldBlock 的转换 |
| tungstenite / `src/protocol/mod.rs` | `63a89ddb980ecef57afced4a2090551aa26764ffe482a3894f91c06fbaa0c755` | 449–477：控制回包受阻仍继续读；491–590：写入与自动控制；683–709：分片聚合 |
| tungstenite / `src/protocol/frame/mod.rs` | `29affc076bc3b11196a75a315fbd2af8bc58f1e72f21b9a865dba1d63e65f095` | 123–131、170–240：接收分配；250–287：写缓冲 |
| tungstenite / `src/protocol/frame/frame.rs` | `36897ee772b3bf527614751c43d19ee94e95b32fb644cf4e1409587c021ee15a` | 362–372：载荷复制进输出 Vec |
| tungstenite / `src/protocol/message.rs` | `0d6b0b03d61e3c9add69d83874eb9fb7e4222bd880cf34b02391f74e6c3bd45b` | 114–144：分片累计、容量增长与完成 |
| bytes / `src/bytes_mut.rs` | `48bf55ffb1e3062082cae343c223e063104e3eee0a18f291a72942026062adbd` | 254–271、407–426、610–805：freeze/split/reserve |
| bytes / `src/bytes.rs` | `eee15c02105022837d6ed01c6863fee58802ce7bd7c300e158521c9ae61257fc` | 947–980：Vec 到 Bytes 的所有权转换 |

根 `Cargo.toml`、`src/lib.rs`、`src/main.rs` 及 `src/`、`tests/` 的只读检查没有发现禁止本测试使用 unsafe 的 crate lint。新增测试自身启用 `deny(unsafe_op_in_unsafe_fn)`。所有 unsafe 限于测试中的 `GlobalAlloc` 实现及四个显式 `System` 委托，不进入生产代码。本次只读报告的默认工具链是 Rust 1.95.0；这不是精确 MSRV 1.91 的编译证据，本地默认工具链没有安装可供核查的标准库 `alloc/src/raw_vec` 源码。

## 两种写入返回值不能混用

`tests/websocket_library.rs` 是独立可执行的库 API 原型，不调用生产 WS 适配器或 Guard。

1. **tokio `start_send` 的 Io WouldBlock 表示已接受。** `AllowStd` 将底层 `Pending` 转为 `io::ErrorKind::WouldBlock`，库 `start_send` 将这个错误转为 `Ok(())` 并令 ready=false。测试分别注入底层 `Pending` 和显式 `Io(WouldBlock)`，使用 1/7/17 字节短写，先输出 3 字节再阻塞；反复 ready/flush 保持 Pending，解除阻塞后只推动 flush，不能重新提交同一消息。输出与独立构造的未 masked 服务端线格式逐字节比较，再 flush 及发送后续消息确认恰一次。
2. **同步 `WriteBufferFull` 表示本帧未入队。** `FrameCodec::buffer_frame` 在 reserve、format、底层 write 之前比较 `frame.len() + out_buffer.len()` 与上限。固定 128 KiB 输出队列可收下七个 16384+4 字节帧，第八个返回 `WriteBufferFull(Box<Message::Frame(...)>)`，不是原来的 Binary 变体。测试保留这个返回帧，确认拒绝没有增加底层 write 次数；解阻 flush 前七帧后，仅重投返回的帧一次，再次 flush 不得重复。底层已发生 Io WouldBlock 的前七帧不得重投。

主线已于2026-11-05在macOS ARM64、Rust1.95.0上实际执行该独立binary，`1 passed / 0 failed / 0 ignored`，上述两种返回值及恰一次线格式断言均通过。首次日志为私有`.test-artifacts/ws-dev-l28eb9oi/first-library.log`；最终同输入门禁记录见[开发记录](websocket-development.md)。该结果不等于整生产连接或官方客户端互通。

## 逻辑长度不等于分配容量

本批显式参数如下。以下 KiB/MiB 均按 1024 换算。

| 存储/操作 | 参数 | 不应作出的推断 |
|---|---|---|
| 输入帧、累计消息 | 各 1048576 字节 | 两者不是共享的一块 1 MiB 内存 |
| 引擎 read_buffer_size | 16384 字节 | 不是接收缓冲永远不超过 16 KiB |
| write_buffer_size / max_write_buffer_size | 0 / 131072 字节 | 128 KiB 限制的是逻辑排队长度，不是 Vec capacity 或 RSS |
| 单次业务写 | 最多 16384 字节 | 编码期间仍有业务副本与输出 Vec 同时存在 |
| early-data | 最多 8192 解码字节 | 不包含 HTTP 中编码值的原始存储 |
| HTTP 头及尾部预读 | 合计最多 32768 字节 | 不包含 parser/Request 的结构与有界字段副本 |
| 护栏 | 最多 14 字节头 | 原始尾部拥有自己的有界 Vec |

实际所有权和复制点：

- `FrameCodec::new` 先分配 read_buffer_size 的 `BytesMut`。完整长度头解析后，先按 `max_frame_size` 拒绝超限，再执行 `in_buffer.reserve(len)`；因此只收到合法大帧头、载荷尚未到齐时也可能已经申请约 1 MiB。
- `reserve(len)` 的语义是“再容纳 len 字节”，并非“把容量设为 len”。如果已经预读了部分载荷，还要计算当前长度、底层 Vec offset 与保留容量；`BytesMut` 的独占/共享分支有原空间回收、Vec reserve、显式倍增、换新分配并复制等路径。`read_in` 只把一次读取限制到 16 KiB，不限制已经申请的总容量。
- `split_to(len)`、`freeze()`、Frame 到未分片 Binary 一般共享或移动缓冲所有权，不复制整帧。一个短的 `Bytes` 视图仍可能钉住整块较大的 backing allocation；不能只累加 `Message::len()`。
- 分片 Binary 的 `IncompleteMessage` 以独立 `Vec<u8>` 累积。每个 frame 的 `Bytes` 要复制进这个 Vec，期间帧缓冲和累积缓冲并存。累计长度在 extend 前检查，但 Vec 按增长策略保留多余容量；text 分片的 StringCollector 有相同的容量问题。生产适配器拒 text 不等于库在拒绝之前零分配。
- 完成的分片 `Vec` 转 `Bytes` 会保留原 Vec 分配，必要时另分配小的共享元数据，并非强制 shrink 到消息长度。库交给外层的完成消息游标也占内存，必须排空后再取下一条，不能积攒多个完成消息。
- 本批业务写先将最多 16 KiB 调用者切片复制为拥有所有权的 Vec/Bytes，再由 `format_into_buf` 复制进 `out_buffer`。写短返回时 `drain` 删除逻辑前缀，不代表释放 Vec capacity。自动 Pong 与 Ping 的 Bytes 可共享；待发槽只有一个，但仍可能保留其 backing。

## 保守用户态缓冲容量模型

**本批以每条承载 32 MiB 作为保守的 transport 缓冲容量核算额度，而不是 1 MiB。** 这是针对固定库、固定参数、有限完成消息/控制槽以及通常几何增长 Vec 的源码容量模型和回归预算；不是 Rust 公共 API 保证的、跨任意分配器/编译器的严格 RSS 上限。局部 `reserve` 的 capacity 可以大于逻辑上限，标准库 `Vec` 公共契约也没有“至多两倍”的上界。没有标准库容量策略或实际分配证据时，不得把下面估算升级为无条件硬上限。

为避免把共享 Bytes 当成零内存，或把 realloc 的旧块漏掉，按比正常生产组合更松的同时存活模型核算：

- 令 `M=1048576`、`R=16384`、`H=32768`、`E=8192`、`W=131072`、`S=16384`。
- 对接收 backing 使用宽松额度 `C=4*(M+R+14)=4259896`。它给长度 reserve、已有部分读取、offset、倍增与头空间留余量，并不宣称库真的每次都申请 C。
- 最多四份 C 同时计入：当前接收 backing、被完成消息/控制视图钉住的旧 backing，以及读缓冲换新时保守计入的旧/新块。共享时仍重复记账，从而不依赖零拷贝节省。
- 再额外计入 `4*M`：分片累积 Vec 的容量和增长迁移旧块。完成消息若已计入 backing 仍重复记账。
- 输出以 `4*W` 计入容量和迁移旧块，另加一个 `S` 的单次拥有载荷；HTTP 原始存储与 early-data 按 `2*H + 2*E` 留容量余量，再留 64 KiB 给有界控制/字段/共享元数据。
- 合计约 21 MiB，向上取整到 **32 MiB/承载的缓冲预算**。正常生产适配器排空完成游标后才继续读，往往不会同时持有上述所有项；这里不以这种较低常见占用替代保守核算。

这份预算不包括应用调用者的读写缓冲、协议认证/正文、UDP队列、会话任务栈、执行器、通用错误/日志、分配器 arena/碎片/内部 realloc 双块瞬态、TLS 缓冲及证书、内核 socket 缓冲、其他连接和进程共享状态。HTTP parser 字段对象的精确峰值及整个生产适配器仍需单独测量。32 MiB 不是新的连接准入机制，也不是整体内存已受此数强制限制的声明；全局连接数乘以每连接预算仍可能很大。若需要可强制执行的整连接内存硬上限，还需能约束底层分配及整条协议链的独立设计，不能依靠本页估算冒称已经具备。

## 实际分配测量的实现和限制

`tests/websocket_library.rs` 独占一个 integration-test binary，且只有 `websocket_library_api_and_allocations` 一个 `#[test]`。它不启动 Tokio runtime、不 spawn、不联网。自定义 `GlobalAlloc` 原样委托 `System`，记录成功 alloc/alloc_zeroed/realloc 的实际 Layout 请求大小；计数器全部为静态原子，不在分配器内执行日志、加锁或动态分配。

每个窗口在引擎创建前开始，固定输入线格式夹具在窗口外分配，IO 只借用输入且不收集输出，窗口内创建的业务输出临时副本仍计入。打印发生在窗口关闭之后。覆盖三种固定夹具：

1. 1 MiB 单个 Binary，同时存在受背压的有界输出队列。
2. 累计恰为 1 MiB、故意跨 Vec 增长边界的 Binary 分片；保留完成消息，继续累积下一消息约 512 KiB、插入 Ping，再只给下一个合法 1 MiB 帧的头及 64 字节载荷，从而测量提前 reserve 与未完成聚合并存。
3. 相同的前一条完成消息改为合法 ASCII text 分片，覆盖 StringCollector；这仅是库分配测量，不表示生产承载接受 text。

第 2/3 项刻意比生产游标策略更激进；下一条消息若最终收全会因累计长度超限而拒绝，测量的是拒绝前允许存在的有界半帧状态。测试只读到 WouldBlock，不将其假装为成功 EOF。

输出每行以 `WS_LIBRARY_ALLOC` 开头，字段定义如下：

- `peak_delta`：窗口内观测到的全进程 live requested bytes 峰值，减开始时基线。它是 **System 调用边界可见的请求量**，不是 malloc 实际 usable size 或 RSS。
- `retained_delta`：固定压力状态尚保留完成消息/半帧/写队列时的 live 增量。
- `end_delta`：显式 drop 本窗口引擎和保留消息后的 live 增量，便于观察测试/库是否仍保留请求内存；不凭它单独作进程泄漏诊断。
- `calls`、`reallocations`：成功分配/重分配次数及其中 realloc 次数。
- `largest_request`：实际传给 System 的最大单次分配请求；`requested_total` 是累计请求量，不是峰值。

重分配成功后按新大小替换旧大小；System 内部搬迁时旧块与新块实际是否同时存在，对 GlobalAlloc 包装器不可见，**不在 peak_delta 内伪造该内部峰值**。窗口是全进程时间差而非逐对象归因；唯一测试且无异步运行时减少干扰，但 libtest/系统分配器的其他活动仍可能贡献噪声。测试断言消息/线格式/有界写队列及三个固定夹具不超过 32 MiB 分配回归阈值；该阈值的通过不构成任意输入或整连接峰值证明。

### 实际运行结果

2026-11-05主线执行，退出码0；macOS ARM64、rustc1.95.0。精确命令：

```sh
cargo test --locked --offline --test websocket_library -- --nocapture --test-threads=1
```

下表单位为字节（次数列除外）；原始`WS_LIBRARY_ALLOC`行及输入摘要由开发工件保存，不借用Guard的结果。

| 夹具 | peak_delta | retained_delta | end_delta | calls / reallocations | largest_request | requested_total |
|---|---:|---:|---:|---:|---:|---:|
| single_binary_1mib | 1196104 | 1196104 | 0 | 16 / 4 | 1064960 | 1458332 |
| fragmented_binary_and_reserved_next_frame | 4276362 | 4276362 | 0 | 30 / 14 | 1048640 | 6848693 |
| fragmented_text_and_reserved_next_frame | 4276362 | 4276362 | 0 | 30 / 14 | 1048640 | 6848693 |

最大观测请求峰值为4276362字节（约4.08MiB），不是32MiB阈值，也不是整条WS/WSS连接或OS/TLS/生产RSS峰值。零end_delta只说明这些测量窗口显式drop后请求增量归零。锁为`56b19d93fc724a1cf6b2cf0dd52264029112e41194bb5f0299ae8000d613b723`；后续平台或库输入须重新实际测量，不能将本表扩为所有输入的硬上界。
