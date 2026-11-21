## 1. 固定依赖与接口门禁（开发阶段）

- [x] 1.1 对D4精确WS/HTTP候选执行官方index/归档普通文件、SHA256、yanked、完整许可、normal/build新增闭包、features、MSRV元数据和完整公告范围审查，保存依赖报告及旧lock快照；新增核心依赖/锁修改前另取真实确认，条件不符暂停，不默用缓存0.29、更新整图或抬高1.91。
- [x] 1.2 获准后仅加入核查通过的最小精确依赖与必要边，关闭WS库TLS/connect/url并复用局部ring；以locked最小编译、真实feature树/锁差异和普通TLS回归验证，不改两个冻结vendor或建立第二锁，记录首次失败及修复。
- [x] 1.3 建立候选公共API小原型和独立原始HTTP/帧夹具，验证成熟Accept、HTTP尾部经护栏而非直接进库、Io WouldBlock已接受/WriteBufferFull未接受、自动Pong受背压仍读和有限Close；以可执行定向测试及固定源码摘要验证，不因trait存在就宣称接口满足，不运行官方内核。

## 2. 严格新入口与有限 Upgrade（开发阶段）

- [x] 2.1 新增独立vless-ws/vmess-ws/trojan-ws及D1严格websocket/early_data对象、成对可选TLS、身份上界与VLESS/Trojan显式不安全开关；以合法/边界/错误类型/null/未知字段/占位/重复身份/flow/旧入口配置回归验证，check不监听联网且秘密脱敏。
- [x] 2.2 实现D2的16384字节/64头/12288 request-target/32768合计预读边界和成熟HTTP解析、正确101；以逐字节、全部关键截断、头+首帧合并、重复关键头、CL/TE/obs-fold/方法/版本/键/超限立即失败及慢客户端验证，错误无敏感反射且零业务DNS/拨号。
- [x] 2.3 实现normal/header路径单次percent-decode精确匹配、path模式原始base+后缀、可选Host规则与HTTP/1.1 WSS ALPN边界；以大小写/尾斜线/百分号/query/ed提示/IPv6 Host/端口/非法authority/Origin和压缩提议回归验证，不将Host或Forwarded当身份、TLS或拨号地址。

## 3. Early-data 与帧结构护栏（开发阶段）

- [x] 3.1 实现显式header/path early-data及D3的规范无padding RawURL、先验编码/解码上限、自定义header保留名和仅子协议载体回填；以空/缺省、非法尾位/标准base64/padding/重复/列表、最大8192、错误位置、前缀+帧分割和秘密零输出验证，不自动探测或混拼来源。
- [x] 3.2 实现≤14字节原始帧头护栏，验证非最短126/127、高位、声明长度/控制头上界并原样交成熟引擎，HTTP预读和socket路径都覆盖；以逐字节/所有头截断/边界长度/只头超限/连续帧验证，保持mask/framing由库完成，不扩大为自研WS或修改vendor。
- [x] 3.3 将成熟帧/消息引擎配置为D5固定帧/累计消息/读写缓冲限额，完成Binary/continuation到有序字节流映射；以跨消息代理头、多包同消息、空消息、控制插入、text/RSV/mask/opcode/非法continuation及累计分片超限验证，空消息不算EOF、UDP不借WS边界拆并。

## 4. 背压、调度与关闭（开发阶段）

- [x] 4.1 实现有限AsyncRead/AsyncWrite适配器及精确写入/flush游标，单次业务写≤16384、固定写缓冲、待发控制有限；以1/7/17字节短写、交替Pending、错误及取消验证已接受字节恰一次，WriteBufferFull和Io WouldBlock不混淆，不留后台writer。
- [x] 4.2 实现外层32事件及护栏每轮32头/65536原始字节预算、原读写waker与读向可前进；以自持真实下行背压仍上行/处理Ping、恢复后无重复、空continuation/控制连续输入的有界poll和有限分配验证，不仅靠超时或UDP预算宣称无界循环已解决。
- [x] 4.3 实现首次shutdown即拒写的闩锁、已接受数据flush、正常/异常Close分类、5秒关闭期限和底层结束；以首poll Pending后late写零计量、同时Close/无状态/异常码、半帧/无Close EOF/TLS缺close_notify、真实VMess EOF及EOF依赖TCP应用限制验证，不自造单向FIN或把截断当正常结束。

## 5. 三种协议与公共生命周期（开发阶段）

- [x] 5.1 将vless-ws接入既有无flow认证、TCP/原生UDP/显式UDP-only XUDP，必要时窄提取业务helper；以WS/WSS独立端首载荷/server-first、一次响应、IPv4/IPv6、多目标/来源/代次/GlobalID隔离和大小/空包策略验证；坏UUID/flow、扩展关闭/逐帧TCP及Reject在业务DNS/拨号/成功响应之前拒绝，不套用旧Vision结果。
- [x] 5.2 将vmess-ws接入同Server身份重放池及原AEAD/body/UDP/XUDP/packetaddr，窄拆承载认证与accepted分派；以WS/WSS security3/4及真实TLS或显式策略的5、M/P/A原开关、任意消息拆并、跨旧直承载重放、首载荷/server-first和IPv4/IPv6逐包目标验证，伪造Forwarded不能授TLS且不发送VLESS响应。
- [x] 5.3 将trojan-ws接入既有多用户摘要、TCP/UDP及公共转发；以WS/WSS头/载荷任意拆并、逐帧目标/来源、IPv4/IPv6、CRLF/错误摘要/命令/超限及截断验证，错误认证/Reject零业务DNS和网络，明文显式弱化不改旧Trojan必填TLS。
- [x] 5.4 将TLS/Upgrade/early-data/协议认证置于同一绝对握手deadline与原握手许可，全部新承载/UDP纳入共享连接/DNS/关联/排队预算及stop→drain→force→join/children屏障；以新旧入口饱和、逐层耗时不刷新、慢头/半帧/阻塞DNS/活跃UDP强停、后置准备失败/监听及映射重绑、任务/内存上界和只计成功业务载荷验证。

## 6. 开发完成门禁与连续推进

- [x] 6.1 在本批同一输入执行新配置、HTTP/early-data/护栏/适配器/Close、三协议WS/WSS数据和资源/CLI定向回归，另旧TLS/VLESS/Vision/REALITY/VMess/Trojan及共享UDP必要回归、根fmt、locked all-targets check和严格Clippy；保存实际命令/退出码/失败历史，必要项真实通过才勾，不重跑完整官方/三平台充当开发前置。
- [x] 6.2 新增三协议独立WS/WSS回环占位示例和使用/early-data/限额/关闭语义说明，更新README/路线/矩阵为已实现待集中验收；以替换占位后真实CLI check/启动/业务及文档链接检查验证，明确无通用半关闭保证、无Vision/REALITY/HTTPupgrade和旧release不含新能力，不提供公网调优。
- [x] 6.3 将第1–6组全部行为逐条映射真实开发证据，记录生产/测试/示例/两个vendor/lock/工具链输入与固定上游来源，核对任务和OpenSpec strict；仅全部开发门禁完成才继续下一模块，第7–9组保持待验收，旧410/262/209/33不拼接为新通过。

## 7. 固定官方组合矩阵（能力簇收尾）

- [ ] 7.1 静态核对三家固定官方客户端实际WS/WSS、三协议业务路径、header/path early-data配置及上游依赖，生成显式矩阵和本机受控配置；以来源/版本/归档/运行前SHA256/普通文件/RAII/私有日志门禁验证，不预设全部组合支持，运行前另取本批许可，不沿用旧33项授权。
- [ ] 7.2 获准后执行各家实际支持的VLESS/VMess/Trojan WS/WSS TCP及无early/header/path早期数据组合；以真实首载荷/服务器先发/大载荷/协议EOF或公开Close限制、标准TLS信任和坏身份/路径/Host/关闭模式负向验证，逐组合记录已验证/不支持/未执行，不把源码可读当通过。
- [ ] 7.3 执行各客户端实际可用的原生UDP/XUDP/packetaddr、多个目标/会话、IPv4/IPv6及错误认证/标签/时间/flow/扩展关闭负向，观察零不应有业务DNS/目标与只计payload；同最终能力簇输入按另获准范围重跑旧33及Vision/VMess/REALITY矩阵，缺失组合不勾为成功。

## 8. 平台、精确工具链与构建（能力簇收尾）

- [ ] 8.1 对最终能力簇同一输入执行macOS ARM64普通全量、SS/rustls vendor相关回归、fmt/check/严格Clippy、release及全部示例检查，保存实际passed/failed/ignored、IPv6与二进制/源码摘要，不沿用旧构建或把ignored计通过。
- [ ] 8.2 只读核查可用隔离Linux环境，在另获准范围内恢复并运行Linux ARM64/x86_64普通/vendor全量及IPv6，核对同输入/退出码并保留QEMU/原生编译警告；不改全局context、不删实例/卷/镜像/缓存，未运行保持未完成。
- [ ] 8.3 用精确声明Rust1.91执行locked all-targets真实编译，复审全生产features、新增传递许可/原生构建/完整公告和两vendor可复现来源；以构建/锁/工具链/补丁摘要及许可清单验证，不以候选MSRV元数据或旧SS记录替代。

## 9. 最终结论与规格证据（能力簇收尾）

- [ ] 9.1 按真实官方/平台/MSRV/release证据写WS验收报告并更新矩阵/使用/路线，逐协议/承载/early-data/业务及关闭限制记录结果；以最终输入/命令/版本/摘要一致性验证，不公开含凭据/私钥/early-data的整个工件目录，不声称生产容量或全面安全审计。
- [ ] 9.2 将全部规格场景与任务关联真实证据并执行OpenSpec strict/真实进度核对；仅规定开发与集中验收全部完成才标all_done，保留失败/未运行历史，不自动归档、Git、发布、部署或修改系统网络/权限。
