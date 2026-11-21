## 1. 配置与密码依赖门禁（开发阶段）

- [x] 1.1 按design审查并加入aes/aes-gcm/chacha20poly1305/md-5/shake/crc32fast及限定cryptoxide依赖，关闭无关features、保留既有sha2与SS语义；以锁文件、cargo tree生产features、发布包/许可/MSRV/安全公告记录和新增模块最小编译验证，依赖条件不符时暂停，不静默更换算法或提高MSRV。
- [x] 1.2 使用成熟库及薄Digest适配实现协议嵌套HMAC KDF、cmdKey、AuthID key、ChaCha key和响应材料派生；以独立金样覆盖根/各path、二进制path、KDF16、reset/重复result及精确32字节输出，禁止以HKDF、一次拼接HMAC或自写ipad/opad替代。
- [x] 1.3 增加独立VmessUser与vmess入口schema，落实1..=1024用户、UUID/用户名唯一与脱敏，xudp/packetaddr/allow_insecure_body/allow_authenticated_length缺省false；以旧配置回归、JSON往返、占位/畸形/重复UUID、null/类型错误、历史/未知字段及秘密不泄漏测试验证。
- [x] 1.4 增加成对可选TLS字段和独立max_vmess_replay_entries限制，保持旧入口必填TLS及SS重放预算不变；以合法直承载/TLS、半组/空路径/非法证书、预算1及上限边界、CLI check不监听和后续入口失败归还端口验证。

## 2. AEAD头部与重放防护（开发阶段）

- [x] 2.1 实现AuthID候选扫描、CRC/非负±120秒检查、原子早期占位、241秒单调保护及防时间回退锚点；以独立AuthID、并发重复、跨入口同UUID、不同身份、未来边界/回退/前跳/溢出和注入时钟测试验证，不修改系统时钟。
- [x] 2.2 实现请求长度/nonce/正文AEAD与最多316字节内层解析，检查AAD、version/reserved、FNV、地址/命令、security/options与实际TLS准入；以逐字节/合并首载荷、全部关键截断、长度/tag/绑定信息篡改、cmd3省略目标及未知组合测试验证，错误请求零目标IO。
- [x] 2.3 完成UUID+正文key/IV的第二层保护及两类条目共享容量/到期堆，失败取消不撤销已提交AuthID且满额不驱逐；以换AuthID复用材料、容量1/2、并发饱和、认证前垃圾不插池、失败后重试、每key恰一到期项及到期恢复测试验证。
- [x] 2.4 实现一次性AEAD响应头与响应正文材料交付，响应无CFB/动态命令且不包入body；以独立响应金样、长度/认证字节检查、短写Pending/flush及server-first回环验证，认证/路由失败不发送成功响应。

## 3. 有界正文codec与流适配（开发阶段）

- [x] 3.1 实现security3/4普通AEAD chunk、普通u16长度和各向正文材料/nonce，接收完整wire范围；以独立AES/ChaCha金样、0/1/最大载荷、C位0/1、合并分片、标签篡改及未认证正文不交付测试验证，不把发送块选值当接收上限。
- [x] 3.2 实现按方向完整IV播种的单条SHAKE流、mask与padding顺序及有界随机padding；以固定序列覆盖0x04/0x05/0x0c/0x0d、0..63 padding、mask和padding不重复消费、P无M拒绝、背压不重新编码及padding不具AEAD认证的实际边界验证。
- [x] 3.3 实现默认关闭的authenticated-length分支，18字节长度、减正文tag语义及A下不消费mask随机数；以独立3/4向量覆盖A/M/P组合、上下行沿用request材料、各方向计数和65551字节密文边界，默认拒绝/显式启用均验证，文档不宣称跨方向nonce唯一。
- [x] 3.4 实现security5的TCP/XUDP裸流或普通长度分块、cmd2长度数据报，落实实际TLS或allow_insecure_body策略；以TLS+auto对应wire5/0和5/1、直承载拒绝/显式允许、M/P/A拒绝及原始二进制/边界EOF验证，不能将none当legacy认证。
- [x] 3.5 实现有限AsyncRead/AsyncWrite、数据报接口、一次性输出游标、失败闩锁、nonce耗尽及EOF/shutdown；以短读写/交替Pending、完整空AEAD块验tag、边界EOF/半帧错误、最后额度/第65537操作拒绝、读不被无关写背压阻塞、shutdown开始后拒写且计量不增长和双向半关闭测试验证。

## 4. 运行器、UDP与共享资源（开发阶段）

- [x] 4.1 接入直承载/普通TLS VMess监听，TLS与协议共用握手期限，TCP复用route/DNS/connect/relay；以独立测试端验证三种安全值、首载荷与server-first、错误UUID/时间/flow字段/选项、Reject先于自持DNS与目标连接、混合监听及准备失败回收。
- [x] 4.2 增加原生cmd2数据报适配并复用Association，不插入VLESS包头、不跨chunk拆并；以不同大小连续包、双向数据、固定目标/实际来源过滤、超限拒绝/丢弃及空终止不作业务包测试验证，记录各模式最大可用载荷而非统一宣称65507。
- [x] 4.3 实现明确开启的packetaddr魔术目标准入、IPv4/IPv6地址前置编码及真实来源回包；以7/19字节独立金样、两目标交错、完整地址头+空业务、短头/未知类型/端口0、逐包Reject及开关关闭零控制域名DNS验证，不从下一chunk补头。
- [x] 4.4 将cmd3经VMess字节流codec接现有UDP-only XUDP body，禁止发送VLESS响应及TCP mux；以xudp开关、多会话/目标/代次、实际来源、逐帧TCP拒绝、GlobalID不跨承载及原VLESS/Vision响应一次性回归验证。
- [x] 4.5 纳入共享TCP/握手/UDP/排队字节预算及stop→drain→force→join/children，业务计量不含封装；以VMess与旧入口混合限额、重放池满、慢读背压、半头/半body、活跃三种UDP及强停测试验证，任务/端口/许可/统计最终恢复，无按包无限任务。

## 5. 开发阶段完成门禁与连续推进

- [x] 5.1 执行新增及受影响配置、VMess wire/运行器、UDP/XUDP、TLS/VLESS/Vision、资源及CLI定向测试，加根package fmt、locked all-targets check和严格Clippy；保存实际命令/退出码/失败修复历史，独立向量与真实业务均通过才勾选，不在此重复全部官方/三平台。
- [x] 5.2 增加独立直承载和TLS示例及VMess说明，更新使用/路线/兼容状态为已实现待集中验收；以替换占位后CLI check/启动和文档一致性检查验证，明确security5策略、认证长度局限、nonce额度、UDP空包/最大载荷与旧release不含新能力，不覆盖旧示例。
- [x] 5.3 核对第1–5组行为与实际证据，记录开发阶段命令清单、失败历史、生产/测试输入集合与依赖摘要；只在必要门禁通过后允许推进下一独立模块，第6–8组保持待验收，不继承旧106/209/33结果为VMess通过。

## 6. 固定官方客户端矩阵（能力簇收尾）

- [ ] 6.1 为固定Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31准备独立显式启用的VMess矩阵与可审查配置，核对实际VMess依赖/默认选项；以离线配置/注册表检查验证官方来源/归档摘要/普通文件/运行前SHA-256、回环、RAII回收及私有日志门禁，实际启动前单独取得新范围许可，不沿用旧33项授权。
- [ ] 6.2 获准后执行三家实际可用的security3/4 TCP直承载与TLS、默认auto、M/P及显式开启A路径，另外执行sing-box TLS+auto的security5和其他实际提供5的客户端；逐组合验证数据/计量/半关闭/服务器先发、默认关闭A的拒绝，记录实际wire材料，不把Xray配置名none当5已通过。
- [ ] 6.3 实际执行各家原生UDP、显式XUDP与packetaddr可用组合，区分Xray默认选择/强制路径和客户端不支持；覆盖多目标/会话、IPv4/IPv6执行情况、UDP53/443、空包/超限及扩展开关，保存配置和实际模式，不以原生UDP替代扩展或将未到内核的客户端拒绝算内核通过。
- [ ] 6.4 实际执行错误UUID/时间/标签/选项与TLS信任负向，核对零受控目标访问；同一最终构建重跑旧33项参考回归及另获准的Vision矩阵，分别保存输入/版本/摘要/结果/缺口，未授权或未执行的组合保持未完成，不拼接旧证据冒充新全量通过。

## 7. 平台、工具链与构建（能力簇收尾）

- [ ] 7.1 在最终能力簇输入上执行macOS ARM64普通全量、vendor测试、fmt/check/严格Clippy、release及全部示例检查；记录实际passed/failed/ignored、IPv6执行情况和源码/测试/release摘要，不预写通过数、不使用旧release代表新能力。
- [ ] 7.2 先只读核查隔离Linux环境，再按实际获准范围恢复并执行Linux ARM64与x86_64完整普通/vendor回归；核对同一最终输入、退出码和IPv6，保留QEMU/编译器告警，不删实例/镜像/卷/缓存、不改全局context，未恢复则任务未完成。
- [ ] 7.3 对精确声明MSRV1.91执行locked all-targets编译并核对最终生产features、全部新增/传递依赖、许可和安全公告，保存工具链/原生构建参数与cryptoxide版本约束理由；不把包元数据或单平台check称作跨平台MSRV运行通过。

## 8. 最终兼容结论与证据（能力簇收尾）

- [ ] 8.1 根据实际官方/平台/工具链证据更新VMess验收报告、兼容矩阵、使用与路线，逐项区分已验证/未覆盖/不支持/环境阻塞，保留固定源码来源、默认差异、认证长度安全边界与nonce限制；不公开包含凭据/私钥的整个.test-artifacts目录。
- [ ] 8.2 将全部任务关联到实际输入和证据，运行OpenSpec严格校验并核对真实apply进度；只有所有规定行为和集中验收均通过才标all_done，保留失败历史及未归档状态，不自动Git、归档、发布、部署或修改系统网络/权限。
