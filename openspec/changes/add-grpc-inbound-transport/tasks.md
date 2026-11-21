## 1. 固定来源、依赖门禁与API原型

- [x] 1.1 将已核三家固定提交的实际注册/客户端、RPC命名、Hunk/MultiHunk、请求头及关闭接点保存为可追溯只读来源记录；以commit/path/原文SHA256和来源表验证Xray仍真实single+multi、sing-box full/Lite与Mihomo已核single范围，不把非移除弃用警告写成已移除，不运行官方客户端或执行下载源码。
- [x] 1.2 对D2精确h2/prost候选及全部新增normal/build闭包执行官方index/归档普通文件、SHA256/yanked、完整许可、features、MSRV与完整公告范围门禁，保存旧锁和最小预期增量报告；以逐包/逐边来源和结果核对验证，不把本地旧index或docs.rs页面当归档证明，新增核心依赖/锁修改前另取真实确认，不抬1.91或升级整图。
- [x] 1.3 获准后仅加入核查通过的精确依赖/必要特性边并保持两个vendor冻结；以真实锁差异、normal/build/features树、locked最小编译及旧普通TLS回归验证，若多出未审新包、既有升级或特性扩大先回门禁，不建立第二Cargo锁。
- [x] 1.4 对精确候选做可执行API原型，覆盖reserve/poll_capacity及有限send_data、release_capacity、send_trailers后仍收请求、drop/RST、结束流待发仍占库并发、preface/首SETTINGS及ACK观察、真实背压和GOAWAY；用独立protobuf金样核prost key/skip扫描、singular覆盖/repeated追加及递归保护，保存实际失败/修复，不凭源码或trait存在宣称运行通过。

## 2. 严格配置与资源模型

- [x] 2.1 新增三独立gRPC入口、D1必填grpc.path/可选multi_path、成对可选TLS及所属身份/安全开关；以合法/边界/错误类型/未知字段/null/重复身份/路径原字节/非法flow/明文策略及旧入口回归验证，联合check不监听、不作业务DNS/拨号，Debug/错误不泄露凭据、路径元数据或私钥。
- [x] 2.2 增加D5全局max_grpc_streams默认256、每连接max_grpc_streams_per_connection默认16及范围校验、独立RPC认证池和grpc_streams计量；以旧Limits缺省/JSON往返、新界限/饱和及同TCP多RPC计数验证，connections仍按物理TCP、旧握手/TCP/UDP/DNS契约不被改写。

## 3. HTTP2引擎、结构护栏与RPC头准入

- [x] 3.1 按D3配置成熟h2帧/窗口/HPACK/头列表/并发/发送阈值/reset/data预算，增加仅preface位置、9字节帧头和payload剩余计数的护栏；以逐字节、全部关键截断、16384声明上限、压缩头块16384/8帧、CONTINUATION关联/交错及超限头验证，HPACK/Huffman/窗口/状态机仍由库处理，不改vendor。
- [x] 3.2 实现每driver poll跨库重入共享32帧头/65536原始字节预算、有限控制频率及逐头块绝对期限/有界stream起点记录；以连续控制/空帧、部分9字节头、后续慢HEADERS/CONTINUATION、输出阻塞时计时和另一任务进展验证，不按IO调用重置预算、不只用初次连接timeout覆盖活动连接慢头。
- [x] 3.3 实现D4 POST/H2/完整路径、解压后64项、Content-Type、TE可缺省但出现须单值trailers、scheme及authority/metadata/压缩/timeout规则，真实TLS必须ALPN h2；以错误路径/方法/重复关键头/伪头/Content-Length/编码/非法timeout、明文https scheme及伪Forwarded验证，固定小错误无秘密反射且零业务访问，HTTP200不是代理成功。

## 4. gRPC消息和有限字节流适配

- [x] 4.1 实现五字节前缀、flag0、1MiB先验消息上限和prost Hunk/MultiHunk有限顶层预扫描/派生解码；以原始金样、任意DATA拆并、零消息/空项、重复singular、多项/未知字段/group递归、1024字段/256项边界、varint/长度/截断及只头巨额声明验证，不自写protobuf解码、不把空消息当EOF。
- [x] 4.2 实现一份当前DATA/有限消息累积/解码游标及精确接收capacity归还；以1MiB跨65535窗消息、部分消费、不提前拉下一消息、明确丢弃、另一RPC进展及取消验证，不借提前无限release堆积消息，UDP边界只由所属协议恢复。
- [x] 4.3 实现单次业务write最多16384、一个有限编码块、capacity后send_data及恰一次游标/flush语义；以1/7/17短写、交替Pending、部分前缀、真实socket背压、恢复后无重复及只计成功载荷验证，不把库每流发送阈值当任意send_data硬拒绝或物理flush确认。
- [x] 4.4 实现D6请求边界EOF、响应独立shutdown/trailers、首次shutdown拒写闩锁、错误/取消状态及有限尾部等待；以目标等待FIN才回包、目标先FIN后继续上行、同时结束、shutdown Pending后late写零计量、半消息/RST/缺状态/真实TLS截断及drop不误reset验证，不造私有EOF或直接丢handle冒充半关闭。

## 5. 连接driver、认证与真实任务回收

- [x] 5.1 将新入口接入单h2 Connection driver及有限RPC JoinSet，分开物理准备和RPC准入/认证许可并持续公平poll连接；以同连接多身份/目标、坏认证/RST不伤其他RPC、跨入口全局RPC/握手饱和与容量恢复验证，超额不spawn等待任务、RPC不重复计TCP，VMess预备池不得逐RPC重建。
- [ ] 5.2 为RPC及复用UDP reader/mapping增加D5局部scope/共享lease和scoped内部接点，同时保留全局children及旧公开包装；以工作取消、阻塞DNS、活跃映射/队列、异常结束时实际join及许可/gauge最后归还验证，不复制DNS/路由/UDP内核，不在子任务仍活时提前释放RPC/关联额度。
- [ ] 5.3 落实t0的TLS/preface/首合法SETTINGS及本端ACK观察绝对期限，首HEADERS tH到完整认证共享期限及更早grpc-timeout；以每阶段耗时、pipeline请求、错误SETTINGS、超时/半消息和占满握手池验证，无逐层刷新，库报错不能被仅ACK入队或handshake Ready掩盖。
- [ ] 5.4 新连接分支实现stop禁止RPC准入、持续驱动GOAWAY、有限drain/force、RPC局部与全局结束屏障，避免外层force直接drop整个driver；以活动TCP/UDP/阻塞DNS、对端不回PING、并行RPC取消、监听后置失败及监听/映射端口重绑验证，任务/许可实际归还后才报告停止。

## 6. 三协议复用与独立业务对端

- [ ] 6.1 将vless-grpc接入无flow认证/TCP/原生UDP/显式UDP-only XUDP，复用既有helper及首New后延迟响应策略；以single/multi、明文/真实TLS独立端的首载荷/server-first、一次响应、IPv4/IPv6、多目标/来源/代次/GlobalID及请求FIN后目标回包验证，坏UUID/flow/命令/关闭扩展/逐帧TCP和Reject先于相应业务及成功响应。
- [ ] 6.2 将vmess-grpc接入同Server AEAD认证/重放池及TCP/原生UDP/XUDP/packetaddr；以single/multi、明文/真实TLS的security3/4/策略5、M/P/A开关、正文认证EOF及两方向结束、首载荷/server-first、逐包目标/来源验证，并做直承载/TLS/WS/gRPC跨承载重放、坏时间/标签/security/options与伪Forwarded零业务负向。
- [ ] 6.3 将trojan-grpc接入多用户摘要/TCP/逐包UDP，保持旧Trojan必填TLS；以single/multi、明文/真实TLS的认证任意拆并、首载荷/server-first、FIN依赖应用、IPv4/IPv6、多目标/来源、空/大包及精确计量验证，错误摘要/CRLF/命令/截断/逐包Reject零不应有业务访问。

## 7. 开发综合门禁、示例和证据

- [ ] 7.1 补同连接慢下行仍上行/另一RPC前进、stream与connection窗口耗尽/恢复、认证及全局资源跨新旧入口竞争、UDP队列/XUDP控制、取消后真实任务/端口复用综合回归；以受控回环和可观察屏障保存载荷/预算/计量结果，不把超时退出、API存在或UDP预算当全部内存/调度证明。
- [ ] 7.2 按D8对精确库和适配器建立容量/所有权模型及隔离分配观测，覆盖最大single/multi、空项/未知字段、头解压超限、控制和结束流待发；以源码摘要、真实peak/retained/end/最大申请记录验证，明确库/应用/codec/reset尾部预算，不把RSS或某个固定回归阈值写成跨allocator硬上界。
- [ ] 7.3 新增三协议明文/TLS六份独立回环占位模板及gRPC路径/模式/安全/limits/半关闭/flush说明，更新README/路线/矩阵；以原模板无有效秘密不能误用、替换后真实CLI check/启动/业务及本地链接核对验证，公开TE缺省兼容例外、明文scheme非安全事实和无Vision/REALITY/HTTP1 Upgrade组合。
- [ ] 7.4 对本批同一代码/测试/示例/锁输入执行新配置/护栏/消息/适配器/资源/三协议/CLI及受影响旧TLS/VLESS/Vision/REALITY/VMess/Trojan/WS和共享UDP必要回归、根fmt、locked all-targets check与严格Clippy；逐命令保存真实退出码、失败修复及passed/failed/ignored，不先跑昂贵官方/三平台全量作为开发前置。
- [ ] 7.5 将第1–7组全部行为映射真实证据并记录生产/测试/示例/工具链/锁/两个冻结vendor输入，核OpenSpec strict及任务进度；仅必要开发全部通过才标已实现待集中验收并推进后续模块，第8–10组保持待验收，旧WS 577或其他旧结果不拼为本批通过。

## 8. 后置官方客户端兼容矩阵

- [ ] 8.1 静态核定三家固定客户端实际协议/承载/单或多模式、服务路径、TLS与UDP扩展配置，生成明确支持/不支持/未核矩阵及自持回环配置；以版本/来源/归档/普通文件/运行前SHA256/私有日志门禁验证，实际运行前另取本批许可，不沿用旧SS24加九项或WS依赖授权。
- [ ] 8.2 获准后执行各客户端实际支持的三协议gRPC明文/标准TLS、single及Xray multi组合；以首载荷/server-first/大载荷、信任/坏认证/路径/ALPN、真实结束/trailers及客户端自身半关闭限制验证，逐组合记录结果，不把HTTP200、源码或自有H2互测当官方通过。
- [ ] 8.3 执行实际支持的原生UDP/XUDP/packetaddr、多目标/会话/IPv4/IPv6、逐包Reject和错误认证/标签/时间/flow/扩展开关负向；以零不应有业务访问、精确payload及资源回收验证，在另获准最终能力簇范围重跑相关旧官方组合，未运行或不支持不勾为成功。

## 9. 后置平台、release及完整依赖验收

- [ ] 9.1 对最终能力簇同一输入执行macOS ARM64普通全量、相关两个vendor回归、fmt/check/严格Clippy、release及全部示例检查；以真实命令/退出码/测试计数、IPv6、二进制和源码摘要验证，不沿用旧release或把ignored计通过。
- [ ] 9.2 只读核查可用隔离Linux环境，在另获准范围运行Linux ARM64/x86_64普通/vendor全量及IPv6；以同输入/真实退出码记录平台结果及QEMU/原生构建警告，不自行恢复容器、修改全局context、删除实例/镜像/卷/缓存，未执行保持待完成。
- [ ] 9.3 用精确声明Rust1.91执行locked all-targets真实编译，复审全生产features/完整传递许可/公告/原生构建和两vendor来源/补丁摘要；以锁/工具链/构建及许可清单验证，不把候选MSRV元数据或旧Shadowsocks编译结果当本批通过。

## 10. 后置最终报告与完整场景映射

- [ ] 10.1 根据真实官方/平台/MSRV/release证据写gRPC验收报告并更新矩阵/使用/路线，逐协议/模式/安全/业务/关闭限制给结论；以最终输入/版本/摘要/命令一致性验证，不公开含凭据/私钥/元数据的整个私有工件目录，不声称全面替代或生产容量/安全审计完成。
- [ ] 10.2 将全部规格场景及任务关联最终真实证据并核OpenSpec strict/实际进度；仅规定开发与集中验收全部完成才标all_done，保留失败和未运行历史，不自动归档、Git、发布部署或修改系统网络/权限。
