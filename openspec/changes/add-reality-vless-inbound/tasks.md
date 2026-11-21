## 1. 成熟依赖与接口门禁（开发阶段）

- [x] 1.1 审查当前精确 aws-lc-rs1.19.0、rustls0.23.46、rcgen0.13.2 及新增生产/传递边，确认静态X25519/HKDF/HMAC/AES256GCM/Ed25519/pure MLDSA API、features、来源checksum、yanked、许可、MSRV元数据及公告；保存门禁文档和最小locked编译结果，条件不符报告暂停，不默换库、算法或提高MSRV。
- [x] 1.2 用成熟原语建立独立AuthKey/SID及证书金样，验证零化SID的完整CH AAD、基础HMAC与正常CertificateVerify分离、同seed MLDSA公钥及跨库有效签名验证；记录工具/夹具摘要，以基础公共API回环实验证伪或证实候选，仅作为接口门禁，不据此勾完整REALITY兼容，不运行官方内核。
- [x] 1.3 从官方精确rustls0.23.46准备可复现vendor及默认关闭的加性钩子骨架，保留原始摘要/许可/补丁/来源，统一Cargo解析并保持普通入口局部ring；以无钩子普通TLS最小回归、features/类型一致性和差异审查验证，不复制MPL/GPL代码，超D6四类范围则暂停。

## 2. 严格配置与有界认证（开发阶段）

- [x] 2.1 新增独立vless-reality与严格reality对象、既有VLESS用户/flow、秘密脱敏及max_reality_replay_entries；以D1合法/边界/错误类型/null/未知字段、base64url、shortID补零查重/空串、版本/时间/回落期限和旧入口JSON回归验证，不使旧证书字段可选。
- [x] 2.2 实现有界逐record原始ClientHello预读、checked结构/扩展解析及PrefixIo所有权，落实18432单record、65536握手、131072预读/32record上限和绝对期限；以逐字节/跨record/同record尾部、全部关键截断/溢出/重复/超限、Pending取消和原文恰一次回放验证。
- [x] 2.3 实现hybrid在前/可选普通share的完整扫描、认证优先选择、成熟静态X25519/HKDF/AES256GCM与SNI/shortID/version/reserved/time策略；以独立SID向量、两X25519公钥不同、hybrid-only、标签/AAD/低阶点/长度/顺序/时间毫秒端点和普通TLS可回落分类验证，不混淆TLS临时秘密。
- [x] 2.4 实现同Server跨入口、按派生静态公钥+rawCH摘要的独立原子重放池及单调保护，以该公钥最大入口时间窗计算TTL；以并发重复/等价私钥表示、跨入口不同窗口、不同身份、取消保留、容量1/饱和、不增墓碑、到期/回退/溢出及认证前垃圾不占位验证，重放/满额零target拨号且不回落。

## 3. 特殊证书与最小 TLS 钩子（开发阶段）

- [x] 3.1 用rcgen成熟DER和RemoteKeyPair构造Ed25519/HMAC证书，真实SigningKey负责CertificateVerify；以独立DER解析、SPKI/64字节signatureValue、正常CV/Finished、错误HMAC/密钥及普通CA证书不能替代认证验证，不盲patch固定DER偏移。
- [x] 3.2 实现D6已校验目标模板的组/套件限制及最终rawSH钩子，本地独立KX后替换等长share，socket输出和transcript消费同一编码；以普通X25519/hybrid实际握手、独立transcript/Finished核对及错误SID/组/套件/HRR/未知扩展拒绝验证，不暴露任意transcript或traffic-secret改写接口。
- [x] 3.3 实现最终SH确定后、Certificate前的逐连接受限证书回调与可选MLDSA65 seed签名，保证首扩展OID0.0、pure/空context、HMAC(pub||原CH||最终SH)绑定；以独立公钥/签名验证、无MLDSA及CH/SH/扩展顺序/签名/verify-key篡改测试验证，不要求随机有效签名与Go逐字节相同、不静默降级。
- [x] 3.4 实现D7有限初始flight两种record计划、成熟aws-lc记录加密器零padding和可选空application辅助record，保留原TLS序号/AEAD限额/错误传播；以分离/聚合、精确长度、MLDSA可容纳/不足、TLS1.3规范上限、错误不panic、辅助解密零明文及下一真实业务record正确解密验证，不实现全局post探测表或外部自行Seal。

## 4. 固定目标与原始回落（开发阶段）

- [x] 4.1 实现配置固定target的受预算DNS/拨号、自环防护与有界SH/opaque长度计划采集，target仅收原始CH prefix；以本机普通组/hybrid peer、精确echo SID、套件/组/record异常、域名预算/超时、自环及零公网访问验证，明确opaque密文槽位不代表验证了target证书/Finished。
- [x] 4.2 实现全部本地flight预检后才允许输出的不可逆提交闩锁，并在预检前保留原target及下行字节；以模板不兼容/布局不足转原target、首poll写Pending/短写后拒绝回落、本地Finished失败关闭、target至多一条存活连接和原文恰一次验证，不先关target再另拨伪回落。
- [x] 4.3 实现结构合法认证失败仅向固定target的未计业务原始双向转发，落实idle/total期限、半关闭及连接许可所有权；以错误Auth/SNI/time/version/shortID、客户端SNI无法改拨地址、已读下行回放、持续流量总期限、慢读/取消/端口回收验证，malformed/PSK/early_data/replay/full pool不回落。

## 5. VLESS、Vision 与共享生命周期（开发阶段）

- [x] 5.1 将准备完成的REALITY会话/prefix接入Controlled并在ClientFinished后复用VLESS认证/分派，保持联合准备/check不监听或联网；以无flow TCP首载荷/server-first/半关闭、合法REALITY错误UUID/flow、Reject先于业务DNS/目标/成功响应、后置准备失败归还端口验证，target辅助IO与业务IO分开统计。
- [x] 5.2 接入无flow原生UDP/显式XUDP及Vision TCP/UDP-only XUDP，不重复VLESS响应，不支持Vision cmd2/TCP mux；以独立测试端、真实IPv4/IPv6数据、多目标/会话/代次/实际来源、开关关闭/逐帧TCP拒绝/GlobalID隔离、空包和业务payload计量验证，不插入其他协议封装。
- [x] 5.3 在新承载重跑Vision的单record/明文排空与双方向切换边界；以最后外层record+首Direct合并、prefix尾部、单向Direct/另向TLS、KeyUpdate、短写Pending、写背压读向前进、shutdown后拒写及半关闭/真实TLS截断验证，不继承旧Vision结果。
- [x] 5.4 将target/pump/密码操作/回落及UDP全部纳入共享许可和stop→drain→force→join/children屏障；以旧入口混合连接/握手/UDP/排队饱和、半头/阻塞DNS/target/签名、活跃回落/Vision/UDP强停、有限任务数/内存、许可和监听/映射端口重绑及秘密零日志验证，不留取消后blocking任务。

## 6. 开发完成门禁与连续推进

- [x] 6.1 在当前本批输入执行配置、REALITY/auth/replay/cert/TLS/target/fallback、运行器/VLESS/Vision/UDP及资源/CLI定向回归，另根package fmt、locked all-targets check和严格Clippy，并对受补丁rustls新增单元及普通TLS默认路径回归；保存实际命令/退出码/失败历史，必要证据均通过才勾选，不重复完整官方/三平台。
- [x] 6.2 新增独立回环目标/占位凭据示例和REALITY说明，更新使用/路线/矩阵为“已实现待集中验收”；以替换占位后的真实check/启动/业务与文档链接检查验证，明确两层身份、非零时间/精确重放/PSK差异、有限模板、无post探测表、回落仅固定目标及旧release不含新能力。
- [x] 6.3 将第1–6组行为逐条映射实际开发证据，记录生产/测试/两个vendor/lock/工具chain输入摘要与上游来源；以任务核对和OpenSpec严格校验验证，仅开发门禁完成后推进下一独立模块，第7–9组保持待验收，不以旧106/209/262/33拼接为本批通过。

## 7. 固定官方客户端矩阵（能力簇收尾）

- [ ] 7.1 静态核查Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31的实际REALITY依赖/默认share/flow/MLDSA选项，准备独立显式启用矩阵和自持target配置；以官方来源/归档及运行前SHA256/普通文件/回环/RAII/私有日志门禁验证，实际运行前另取本批许可，不沿用旧33项授权。
- [ ] 7.2 获准后执行各客户端实际支持的无flow TCP与Vision TCP、普通/混合TLS组、无MLDSA/有MLDSA组合；以真实数据、server-first/半关闭、独立内层TLS1.2/1.3/Direct、计量和原始share/SH记录验证，不支持/未执行/客户端拒绝分别记录，不预写全支持。
- [ ] 7.3 执行实际支持的无flow原生UDP/XUDP和Vision UDP-only XUDP及认证/时间/shortID/UUID/flow/MLDSA负向，分开固定target与业务目标访问；以多目标/会话、IPv4/IPv6、来源过滤/大小/空包/扩展开关及负向零业务验证，并在同最终输入另获准后重跑旧33项及Vision/VMess矩阵，不把独立端互测当官方结果。

## 8. 平台、精确工具链与构建（能力簇收尾）

- [ ] 8.1 对最终能力簇输入执行macOS ARM64普通全量、SS及受补丁rustls vendor相关测试、fmt/check/严格Clippy、release和所有示例检查；保存实际passed/failed/ignored、IPv6执行与源码/测试/vendor/release摘要，不用旧二进制或预写数量。
- [ ] 8.2 只读核查隔离Linux环境，按另获准范围恢复并执行Linux ARM64/x86_64普通/vendor全量，核对同一最终输入、退出码与IPv6；保留QEMU/原生编译告警，不改全局context、不删实例/镜像/卷/缓存，未运行保持未完成。
- [ ] 8.3 执行精确声明Rust1.91的locked all-targets编译，核对全部生产features、原生AWS-LC参数、新增/传递许可与完整安全公告及rustls可复现补丁；以实际构建日志/工具链/锁文件/来源差异报告验证，不以元数据或旧SS MSRV结果替代。

## 9. 最终兼容结论与证据（能力簇收尾）

- [ ] 9.1 根据真实官方/平台/MSRV/release证据写REALITY验收报告并更新矩阵/使用/路线，逐组合区分已验证/不支持/未覆盖/环境阻塞；以最终输入/版本/命令/摘要/实际结果及本地额外策略、模板/post表边界一致性验证，不公开含凭据/私钥的整个工件目录。
- [ ] 9.2 将全部规格场景和任务关联实际证据并执行OpenSpec strict/真实进度核对；仅全部规定开发与集中验收完成才标all_done，保留失败历史和未归档状态，不自动Git、归档、发布、部署或修改系统网络/权限。
