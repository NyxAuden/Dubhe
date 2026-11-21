# Naive 原生 H1 出站对齐记录（2026-11-12）

变更：`align-naive-h1-outbound`。新增显式H1普通CONNECT、固定forwardproxy裸payload与固定sing-box填充payload的显式选择；不增加wire字段、不自动猜测/回退/重放，不新增依赖、vendor补丁或密码原语。当前本内核H1入站仍为裸流，不从出站能力反推服务端能力。

## 固定源码与角色差异

以下文件仅在各自新空目录只读下载与核SHA256，没有构建/执行上游；脚本不置于下载目录。

| 来源 | 文件 | SHA256 |
| --- | --- | --- |
| klzgrad/forwardproxy `e747854e78743dba85c039b38ed185fb11d93667` | forwardproxy.go | `07b4e3e7cff3ea3d45e08e9016168b39400222d014d420f6ed26507461aafa6b` |
| SagerNet/sing-box `v1.14.4` | protocol/naive/inbound.go | `caa718fc2f676b8cee8d8b373abb34b4081b7dbdf901ecaa31e862375cd85b01` |
| 同上 | protocol/naive/inbound_conn.go | `f61dd34c47421d06dc04c407016cc9984714bb511cf4f7afe8fa30c8c164d3a2` |

- forwardproxy.go:296–359普通CONNECT，先200/Flush后拨号；638–658的H1 serveHijack最终调用dualStream(..., false)，裸payload。不能把200当成目标已经成功建立。
- sing-box inbound.go:147–205要求非空Padding/Basic，200后H1 Hijacker创建naiveConn，209–237交给构造时初始化的UoT Router（61行）。inbound_conn.go:175–193的naiveConn明确通过readWithPadding/writeChunked，首8块PaddedData。不是和forwardproxy相同的裸H1。
- 两者都有非空Padding响应头，因此不能根据头自动判断H1 payload。先前“H1不padding”的描述只对固定forwardproxy成立，当前使用文档已纠正为按上游角色区分；历史H2/H3批次的结果和当时输入保持不变。
- 本地`h1_padding`是显式选择已有上游行为的配置，不是新wire扩展；没有伪造官方客户端互通结论。

## 实施边界

- `naive.http_version:"1.1"`，默认仍为`"2"`；新增`h1_padding:false`。true仅H1可用；H1启用`udp_over_tcp`另需h1_padding=true及实际支持UoT的sing-box等对端。裸H1/UoT组合配置拒绝，不宣称普通forwardproxy具备UDP。
- Basic/CA/目标authority/受保护extra_headers共用原校验。H1通告http/1.1并接受无ALPN，拒绝不匹配协议；H2仍强制h2，H3仍专属QUIC。根与链中间跳共用实际TCP版本分派，保留类型擦除边界，不增大全局线程栈。
- 请求实际字节≤8192、CONNECT authority与Host一致，写完实际flush再读。响应严格CRLF/HTTP1.1，最多64项头，≤4个100/102/103临时响应且累计头≤8192；最终仅200成功，101/非200/重复Padding/截断/超限失败。不预读业务，不自动重试，成功CONNECT的Content-Length/Transfer-Encoding依RFC9110忽略。
- 默认H1返回原裸流，即使Padding非空也不加/剥帧；显式填充要求非空Padding响应，复用正式PaddedStream，双向首8块与第9块边界不变。握手没有派生任务，取消/超时直接销毁拥有承载；半关闭/反向排空交由原TLS/流或成熟padding codec。
- H1显式UoT复用每目标独立会话和Association队列/字节/目标预算，正式isConnect=true+SOCKS目标/u16载荷，空包仍占至少1字节。UDP via保持拒绝。
- 示例：`examples/naive-h1-outbound.json`（裸），`examples/naive-h1-padding-outbound.json`（sing-box填充/UoT）；原H2示例保留。

## 开发验证进度

1. 首次验证脚本使用mktemp创建日志后，被zsh防覆盖设置拒绝普通重定向（file exists），退出1，Cargo未执行；改为只覆盖本次新建日志的重定向，不改变源码或全局shell设置。此项是脚本失败，不是编译或测试失败。
2. 全部代码/测试/文档落盘后，`cargo fmt --all`、`cargo check --locked --offline --all-targets`退出0；Naive相关模块 **29 passed、0 failed、0 ignored、673 filtered**，新增H1集成5、原Naive出站7、原Naive入站3、Naive H3入站9、HTTP代理7、TCP出站19、UDP出站13、XHTTP出站6均通过，退出0。日志`/tmp/rpk-naive-h1-targeted.BrENLz`。现有编译警告保留，不把退出0说成零警告。

已执行范围包括两种H1 payload、首8/第9、早数据/严格头/临时头上限、短写/半请求与慢响应取消、TLS/CA/身份/ALPN/路由负向、多目标/空包/双栈/超限后旧会话、4字节预算/Drop、停机背压与端口回收。H1新增9项模块与5项集成，另将既有TCP/认证/默认UDP/链式/强停用例覆盖到H1；3. 最终`cargo fmt --all -- --check`、`cargo check --locked --offline --all-targets`与`cargo test --locked --offline`均退出0；**1349 passed、0 failed、43 ignored**，79个结果块，日志`/tmp/rpk-naive-h1-validation.C82JYy`。默认线程栈，显式去除全局`RUST_MIN_STACK`；较前批新增14项（9模块+5集成），定向用例也包含在全量内。结果仅覆盖本批收尾输入，不覆盖后续变更。
4. 回归结束、确认无Cargo/rustc运行后，仅清理本项目`target/debug/deps/*.rcgu.o`：1206项、逻辑6.42GiB（6889508808字节），保留库、测试二进制、日志与私有资产；可用空间由约31GiB恢复至38GiB。没有清理系统缓存/容器。

前批AnyTLS `1335 passed / 0 failed / 43 ignored`仅覆盖其收尾输入，不覆盖本批新增H1代码。集中验证使用macOS ARM64、Rust/Cargo1.95.0、CARGO_INCREMENTAL=0、锁定离线、默认线程栈，Cargo串行。

## 验收与操作边界

本批官方NaiveProxy/sing-box客户端与服务端、三平台、精确MSRV/release、长期容量及正式安全审计未执行。独立参考对端也不是官方互通。无Git/归档/发布，不改系统代理/DNS/路由/防火墙，不操作Colima/容器/系统缓存；本机测试凭据/私钥/日志不发布。集中完成后仅清本项目可重建rcgu对象，保留库/测试二进制/证据。
