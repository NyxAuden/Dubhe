# Naive 显式 H1 填充入站对齐记录（2026-11-12）

变更：`align-naive-h1-inbound-padding`。本批新增默认关闭的H1入站选项，对齐固定sing-box实际首八块PaddedData与UoT Router；默认裸H1仍对齐固定forwardproxy。不自动猜测/新增wire字段，不新增依赖、Cargo锁文件、vendor补丁或密码原语。

## 固定依据

沿用[H1出站批记录](naive-h1-outbound-development.md)已实际只读下载并核hash的文件，不重复构建运行上游：

- sing-box `v1.14.4` protocol/naive/inbound.go：SHA256 `caa718fc2f676b8cee8d8b373abb34b4081b7dbdf901ecaa31e862375cd85b01`，61行构造UoT Router，147–205检查CONNECT/Padding/Basic并将Hijacker流交naiveConn，209–237路由。
- 同版本inbound_conn.go：SHA256 `f61dd34c47421d06dc04c407016cc9984714bb511cf4f7afe8fa30c8c164d3a2`，175–193明确H1经过readWithPadding/writeChunked，使用首8块PaddedData。
- forwardproxy `e747854e78743dba85c039b38ed185fb11d93667` forwardproxy.go：SHA256 `07b4e3e7cff3ea3d45e08e9016168b39400222d014d420f6ed26507461aafa6b`，H1 serveHijack最终dualStream(...,false)，裸流。双方都有Padding头，不能据此自动区分。

正式wire已存在；`h1_padding`仅本地显式模式配置，不承诺与上游配置格式或浏览器网络栈等价。

## 实施与安全边界

- `type:naive`入站新增布尔`h1_padding`，默认false；true只改变http/1.1或无ALPN的H1路径。H2/H3保留按非空Padding协商。模板`examples/naive-h1-padding.json`，旧`examples/naive.json`默认不变。修改该选项视为监听配置变化，要求完整重启，不热切换已建立流的codec。
- 共享HTTP请求解析抽窄入口，仅填充Naive要求CONNECT和单一非空Padding，继续共用Basic常量时间比较、重复认证拒绝、HTTP1.1/64项头/8192字节预算；普通HTTP/Mixed和默认裸Naive的合法行为不放宽。读取块限制到剩余头预算，精确8192头仍可成功，超出不得借同批CRLFCRLF绕过。
- 只有该窄入口接受精确小写`sp.v2.udp-over-tcp.arpa:0`；不放宽其他魔数/普通0端口。正式v2魔数字符串与既有UDP模块共享，避免传输层复制。普通TCP仍经Context目标路由/拨号后200、失败502；不将固定上游先200时序等同本地已实现时序。
- 200及正式30..61字节Padding响应先写并实际flush，再包装PrefixReader(early,wire)与PaddedStream。头后完整/半帧原始早数据只交codec一次，不复制身份或padding算法，首8块/第9块双向边界不变。无Padding/非CONNECT/认证失败不能拨目标。
- UoT先认证200，不DNS/拨魔数，随后在正式padding流内读取标准v2初始请求。支持connect/逐包目标模式，初始SOCKS地址与逐包UoT地址类型码按既有规范区分；逐包目标经共享Association路由/目标/队列/字节/关联预算，空包至少占1字节。默认裸H1/HTTP/Mixed仍拒绝魔数0端口，不静默直连。
- TLS与填充H1头共用绝对握手deadline，认证后即归还握手许可；H1一连接一流，复用max_connections/max_handshakes，不额外消耗H2/H3流槽。没有新detached任务，外层runtime force销毁拥有future；UoT reader/映射仍由Association/children跟踪。

## 开发验证进度

1. 全部生产代码、测试、示例与文档落盘后首轮集中运行：全目标check及两组库测试因新增`naive/h1/tests.rs`遗漏`tokio::time::timeout`导入而编译失败（12处E0425）；后续集成实际通过：新增H1入站12、原H1出站5、Naive出站7、Naive入站3、Naive H3含不变性10、HTTP代理7、热替换2、TCP出站19、UDP出站13。日志`/tmp/rpk-naive-h1-inbound-targeted.PwIvHQ`。脚本未如预期在中间失败停止，外层退出0仅为末条成功，不作为整组通过；后续用显式`&&`串联，任一步失败停止。
2. 仅补测试timeout导入并移除本批未使用的io导入，不放宽生产语义或删除负向场景。修后全目标check退出0；HTTP解析模块 **4 passed、0 failed、0 ignored、705 filtered**，Naive相关模块 **33 passed、0 failed、0 ignored、676 filtered**（两组有1个重叠测试，不能相加算独立项）；新增H1入站12、H3入站含模式不变性10、原H1出站5、Naive出站7、原Naive入站3、HTTP代理7、热替换2、TCP出站19、UDP出站13均通过，整组退出0。日志`/tmp/rpk-naive-h1-inbound-fixed.5EaIGR`。4字节预算、1关联上限及取消后的真实UDP端口回收均包含，现有编译警告保留，不称零警告。
3. 最终`cargo fmt --all -- --check`、`cargo check --locked --offline --all-targets`、`cargo test --locked --offline`均退出0；**1369 passed、0 failed、43 ignored**，80个结果块，日志`/tmp/rpk-naive-h1-inbound-validation.eCVYZz`。日志无error行，不仅依据外层状态；默认线程栈，显式去除全局`RUST_MIN_STACK`，每个Cargo显式`&&`串联。较前批新增20项（4 HTTP解析模块、3 H1资源模块、12 H1集成、1 H3不变性集成），包含首轮编译失败的原用例。结果只覆盖本批收尾输入，不覆盖后续改动。
4. 确认无Cargo/rustc运行后，仅清本项目`target/debug/deps/*.rcgu.o`：1222项、逻辑6.56GiB（7045950880字节），保留库、测试二进制、日志与私有测试资产；可用空间由约31GiB恢复38GiB，不清系统缓存或容器。

验证覆盖：默认/非法/示例、普通HTTP/Mixed/裸H1不放宽、半帧early、首8第9/大双向TCP/FIN反向、错误身份/缺少重复头/方法/截断零业务，UoT connect/逐包两目标/空包/双栈/限额/reject、生产原生H1出站TCP/UDP、慢头/握手释放、H1/H2共享准入与H3不变、4字节/1关联预算与取消真实UDP端口回收、路由热替换保旧流/选项修改拒绝热切换、强停背压。

前批H1出站完整1349/0/43只覆盖其收尾输入，不是本批新入站结果。本批仍采用macOS ARM64、Rust/Cargo1.95.0、CARGO_INCREMENTAL=0、锁定离线、默认线程栈，所有Cargo串行，完整落盘后集中运行。

## 验收与操作边界

官方NaiveProxy/sing-box客户端、三平台、精确MSRV/release、长期容量/稳定性与正式审计未执行。双方回环和独立wire对端不替代官方互通。不Git/归档/发布，不修改系统代理/DNS/路由/防火墙，不操作Colima/容器/系统缓存。凭据/私钥/日志保留本机。最终完成后仅清本项目可重建rcgu对象，保留库与测试二进制/证据。
