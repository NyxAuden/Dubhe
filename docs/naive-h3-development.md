# Naive H3 入站与 padding 对齐记录（2026-11-11）

变更：`align-naive-h3-inbound`。本批是服务端入站，不将原生代理出站或浏览器网络栈等价性混入完成声明。

## 固定依据与纠正

- NaiveProxy 发布基线：`v154.0.8037.49-5`。
- `klzgrad/forwardproxy` 提交：`e747854e78743dba85c039b38ed185fb11d93667`。
- 该提交的 `forwardproxy.go` SHA256：`07b4e3e7cff3ea3d45e08e9016168b39400222d014d420f6ed26507461aafa6b`。
- H1 `serveHijack` 调用 `dualStream(..., false)`，不启用 payload padding。此前把“H1 padding”列为缺项不准确；本批纠正文档，不添加客户端不期待的私有帧。
- H2/H3 在非空 `Padding` 请求头协商后启用双向首8块 PaddedData，第9块起为裸字节。
- 响应头长度30..61，前16字节选自 ``!#$()+<>?@[]^`{}``，剩余为 `~`；修正此前遗漏 `<>` 和随机后缀的问题。

## 实施

- `h3:true` 显式开启 UDP QUIC/TLS1.3 H3，TCP TLS H1/H2 保持可用。先绑定TCP实际地址，再绑定同地址UDP，`:0` 也使用同一个实际端口；默认false。
- H3使用普通CONNECT authority，不带扩展 `:protocol`，也不要求 `:scheme`/`:path`。Basic认证与路由在拨目标前完成；重复认证头拒绝，不回落direct。
- H2/H3共用runtime全局连接预算、同入口握手预算与全局复用流预算；每连接另限并发流/未完成头任务。H3未完成请求头独立限时读取，不阻塞控制流及其他请求。
- H3解码头上限8192字节、3条单向控制/QPACK流、64KiB流接收窗口与各1MiB连接收发窗口。有界写队列8块、每块最多16KiB，flush/FIN等待发送任务处理确认，不宣称远端已收到。
- padding写入将完整有界帧接受到pending后返回业务长度，后续write/flush/shutdown保存短写游标排空。取消Pending写不接受新数据，也不会将旧帧错算为下一次不同缓冲。
- 独立writer由取消guard和TaskTracker管理，连接/流任务由JoinSet及全局children屏障跟踪；有限超时终止、join并释放socket。H2停止期间继续驱动连接以排空已有流。
- 无新增依赖；Cargo清单/锁文件、vendor源码和密码原语未修改。

## 失败与修复

1. 首次真实集成：既有H1/H2三项通过，H3三项请求意外400。锁定 `h3 0.0.8` 客户端 `Pseudo::request` 会为普通CONNECT补 `:scheme=https` 与 `:path=/`，不是合规普通CONNECT。服务端拒绝保持不变。测试专用backend通过公开QUIC接口替换首HEADERS为RFC9114 §4.4/RFC9204无动态表字面编码，其余控制流/响应/DATA由既有h3实现驱动；不改vendor，也不据此声称官方客户端互通。
2. 测试backend最初有泛型方法类型推导错误；改为显式 `OpenStreams::<Bytes>::close` 后编译。
3. 全局流预算耗尽时直接drop resolver只产生EOF，h3客户端报 `H3_FRAME_UNEXPECTED` 并关整条连接。改为有界读取请求头后用 `H3_REQUEST_REJECTED` 复位；测试证明H2释放预算后同一H3连接能再次成功CONNECT。
4. 首次集中命令受zsh `noclobber` 拒绝覆盖mktemp新建空日志，未执行检查或测试；改用仅覆盖本命令新建空日志的 `>|`，保留失败事实。

## 验证状态

本机macOS ARM64，Rust/Cargo 1.95.0。开发回环仅在受控回环地址，不修改系统网络。

- padding模块5项已通过：响应头、短写/取消/flush、首8块/第9块、拆包、截断与零容量读。
- `CARGO_INCREMENTAL=0 cargo test --locked --offline --test naive_h3 --test naive`：**12 passed、0 failed**（H1/H2三项、H3九项），退出0。日志为本会话任务 `becrs4xsf.output`。
- H3九项包含同端口三承载、普通流与计量、padding边界、错误身份/reject零目标业务、FIN后反向响应、非法伪头/重复认证头、慢头隔离/流上限恢复、H2/H3共享预算、阻塞写停机端口释放。
- H3 writer另有2项模块测试覆盖队列背压、取消flush/FIN不重复、写错误与确认丢失，集中全量真实执行通过。
- `cargo fmt --all -- --check`：退出0。
- `CARGO_INCREMENTAL=0 cargo check --locked --offline --all-targets`：退出0；保留既有unused/dead-code等警告，不声称零警告。
- `CARGO_INCREMENTAL=0 cargo test --locked --offline`：**1208 passed、0 failed、43 ignored**，71个结果块，退出0；未设置全局 `RUST_MIN_STACK`，不以增加栈掩盖失败。完整日志：本机 `/tmp/rpk-naive-h3-validation.I8L6kM`。相较前批1192新增16项（5 padding、2 writer、9 H3集成）。

官方NaiveProxy、其他官方客户端、三平台、精确MSRV、release与正式容量/安全验收均未执行；本机互测不能推导这些结论。不Git、归档或发布。历史批次的范围和数字保持原样。

## 存储

构建统一 `CARGO_INCREMENTAL=0`。最终仅清理本项目已完成构建遗留的 `target/debug/deps/*.rcgu.o`：1080个、逻辑5.53GiB，可用空间约32GiB恢复为38GiB。保留源码、vendor、库/测试二进制、日志及测试私钥；未清系统缓存、容器或镜像。
