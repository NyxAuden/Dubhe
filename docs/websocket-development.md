# WebSocket 开发阶段记录（已实现待集中验收）

日期：2026-11-05；变更 `add-websocket-inbound-transport`。第1–6组19项开发任务的行为和本地门禁已完成，整体为 **19/27，已实现待集中验收**；第7–9组8项官方客户端矩阵、最终平台/精确MSRV/release及报告仍未完成，不是 all_done，不自动归档。

## 实施范围

- 三个独立入口 `vless-ws`、`vmess-ws`、`trojan-ws`；证书/私钥成对可选，真实TLS为WSS，旧VLESS/Trojan必填TLS契约不变。明文VLESS/Trojan须显式准许，VMess security5依真正TLS或原显式正文策略。
- 有限HTTP/1.1 Upgrade、成熟Accept、严格path/可选Host、显式默认header/custom header/path early-data；规范RawURL、解码最多8192字节。HTTP尾部在Guard下回放，不能作为明文或绕开帧结构校验。
- 成熟WS引擎负责mask、continuation、消息/Close；窄≤14字节护栏补最短长度、高位、声明上界和每poll原始读预算。帧/累计消息各1MiB，读缓冲16KiB、逻辑写队列128KiB、业务写分段16KiB，外层32事件、底层32头/65536字节预算。
- 复用原三协议认证、VMess同Server重放、TCP/原生UDP及所属显式扩展，不复制业务DNS/路由/UDP状态机。**2026-11-06 更新：**命令 3/`v1.mux.cool` 现进入完整 Mux，VLESS WS 在认证成功后立即发送唯一 `[0,0]`，不再等待首个 UDP New；`xudp` 只门控 Mux 内 UDP。下文“首合法 UDP New 后应答”和“拒绝 TCP mux”均属历史记录，见 [Mux 说明](mux.md)。
- 同一绝对握手deadline覆盖TLS/HTTP/early-data/认证，认证完成才释放握手槽。共享连接/DNS/UDP/排队预算与stop→drain→force→join/children真实屏障。
- Close为会话关闭，不是透明TCP单向FIN。真实VMess正文EOF保留读向语义，但旧body writer最终仍shutdown承载；不增加私有EOF协议。使用与限制见[WebSocket说明](websocket.md)。

不含Vision/REALITY叠WS、HTTPupgrade、gRPC/XHTTP、H2/H3、WS outbound、跨承载 GlobalID 1 分钟续接；命令 3 的完整 Mux 已接入但属“已实现待集中验收、未测试”。不缩减长期目标。

## 依赖授权与来源

[静态门禁](websocket-dependency-gate.md)核对官方index/归档普通文件、SHA256、yanked、完整许可、normal/build闭包、features/MSRV元数据及指定包完整公告。用户在主会话真实选择“确认并继续（推荐）”后，才修改Cargo/锁及构建。仅新增：

- tokio-tungstenite `=0.30.0`、tungstenite `=0.30.0`，均关闭defaults，仅handshake。
- http `=1.5.0`、httparse `=1.10.1`，关闭defaults，仅std。
- 直接复用已锁futures-util `=0.3.34` 的sink/std；未增加bytes直接边。

真实锁差异仅四新包，未移除或升级已有包；生产包205→209。WS TLS/connect/url/stream未启用，WSS复用现有tokio-rustls局部ring，不install全局provider。httparse新增build.rs确实在授权构建中执行，不能称无新构建逻辑。两个冻结vendor和单锁结构不变。

固定上游Xray v26.10.31 / `a4a3dff5b20c2faae567b742c172c7b95e75c083`、sing-box v1.14.4 / `c005f35300ce76427dc285481ec5695f5b179cd2`、Mihomo v1.19.33 / `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`。精确文件/摘要及公开来源见[设计D4及上游事实](../openspec/changes/add-websocket-inbound-transport/design.md)、依赖报告和[库内存说明](websocket-memory.md)，源码可读不是官方运行证据。

## 保留的真实失败与修复

初始开发日志保留在私有 `.test-artifacts/ws-dev-l28eb9oi/`，不公开整个目录。

1. 首次Trojan负向12通过/1失败，VLESS运行器负向也曾不能及时回收：原handshake认证失败会调用底层shutdown，WS因此等待无人继续读的Close。保留旧TLS接口行为，WS调用窄提取的只读认证函数，失败直接结束整个承载；没有加长超时掩盖问题。
2. VMess逐包Reject曾13通过/1失败，rejected多1；运行器负向曾6通过/1失败：共享XUDP及Trojan/VLESS UDP将合法Close后的帧边界EOF当UnexpectedEof，再计一次拒绝。增加首字节边界探测；只在任何新帧字节前干净EOF正常结束，半长度/地址/元数据/payload仍错误。底层WS无Close/TLS截断仍是错误。
3. 首轮旧路径回归 `affected-regressions.log` 为367通过/1失败/1忽略：`exhausted_byte_budget_keeps_end_and_returns_all_resources`仍要求完整End后帧边界shutdown报错。按上述正常边界语义改为正常结束，保留预算/End/children与归还断言；半帧独立负向不放宽。
4. 初次Clippy报重复加载VMess测试模块，随后可见性调整曾E0603；改复用既有测试模块并仅`pub(super)`开放，不复制模块或allow屏蔽。
5. 首次30条同输入门禁所有测试均通过，但第3条严格Clippy退出101：XUDP测试冗余全切片、UDP测试enum大小差异。改直接切片值和Box大变体后重跑全部30条，旧失败不覆盖。
6. Close状态修复：peer先Close后库flush已终止，避免再次flush/poll_close触发AlreadyClosed；成功shutdown后计时器不再复活报TimedOut。真实TLS截断、完整/未完成消息、late write零计量与6秒后稳定均由定向测试支持。

安全判定服务多次暂时超时的调用未执行，不计为命令成功；没有改权限、换代理绕过。最后所有数据以实际日志/逐命令退出码为准，不据shell命令组最后一个0推断前面的结果。

## 最终同输入开发门禁

最终私有证据根 `.test-artifacts/ws-final-107due_z/`：`final-commands.json`保存每条argv、退出码、时长、日志SHA256及测试摘要，`final-01.log`至`final-30.log`保存原文，`inputs.json`保存逐文件输入，`input-verification.json`确认**输入漂移=[]、非零命令=[]、日志摘要不符=[]**。运行脚本位于前述初始开发目录`final-run.py`；最终证据使用新的私有空目录，不覆盖失败历史。

**全部30条命令退出0，577次测试执行通过、0失败、7忽略。**不是577个不同场景；REALITY common peer自测在lib及多个集成目标重复注册，7个ignored是同一Python跨库门禁的重复注册，本批没有显式重跑该跨库门禁，也不计通过。没有运行33项官方ignored矩阵，更不是当前能力簇三平台全量验收。

| 命令/日志 | passed | failed | ignored |
|---|---:|---:|---:|
| 根lib（含配置61、WS传输66、WS运行器9、旧TLS/协议/UDP等） / 04 | 370 | 0 | 1 |
| WS ALPN / 05 | 1 | 0 | 0 |
| 三协议early-data真业务 / 06 | 8 | 0 | 0 |
| 协议EOF/会话Close限制 / 07 | 2 | 0 | 0 |
| 六模板CLI检查/启动/业务 / 08 | 9 | 0 | 0 |
| 库API/分配原型 / 09 | 1 | 0 | 0 |
| Trojan、VLESS、VMess WS/WSS / 10–12 | 13+10+14 | 0 | 0 |
| 旧SOCKS/Trojan、VLESS、XUDP、Vision、VMess / 13–17 | 9+7+7+9+16 | 0 | 0 |
| REALITY peer/inbound/UDP/lifecycle/fallback/boundaries / 18–23 | 6+14+12+19+11+10 | 0 | 6 |
| 旧resources、DNS、CLI、标准curl、examples / 24–28 | 7+5+14+2+1 | 0 | 0 |

其余：01根package fmt check、02 locked/offline all-targets check、03严格Clippy、29真实normal/build/features树、30OpenSpec strict均退出0。测试仅自持回环/内存，不访问公网业务目标。IPv6定向未出现SKIP；这不推导其他环境可用。

关键复现形态（各target/filter分别调用）：

```sh
cargo fmt -p dubhe --check
cargo check --locked --offline -p dubhe --all-targets
cargo clippy --locked --offline -p dubhe --all-targets -- -D warnings
cargo test --locked --offline -p dubhe --lib -- --nocapture
cargo test --locked --offline -p dubhe --test websocket_early -- --nocapture
cargo test --locked --offline -p dubhe --test websocket_library -- --nocapture --test-threads=1
openspec validate add-websocket-inbound-transport --strict --no-interactive
```

### 任务与实际证据映射

| 开发任务 | 代码/真实门禁 |
|---|---|
| 1.1 | 静态依赖报告、真实用户授权、旧锁及四包差异、完整指定公告与归档摘要 |
| 1.2 | 精确五边/四新增，final02/29真实编译和features、lib普通TLS回归；两个vendor摘要保持 |
| 1.3 | final09两种背压返回值独立线格式原型；lib Upgrade RFC Accept/rawtail经Guard、背压Pong及有限Close |
| 2.1 | config61含17新WS配置测、CLI/examples，严格对象/null/flow/身份/旧契约与脱敏 |
| 2.2 | Upgrade26项：头/target/预读边界、逐字节/截断/合并、重复/CL/TE/obsfold/Key、有限错误及父绝对timeout；runtime自持DNS零查询和允许请求正对照 |
| 2.3 | path/Host单元及final05真实三入口ALPN None/http1.1/优先http1.1与仅h2失败；Forwarded不授TLS |
| 3.1 | Upgrade规范RawURL/8192/编码上界/保留名/回填与秘密零反射；final06三协议WS/WSS×三carrier，全认证+首载荷、关键边界、8192和坏认证零业务 |
| 3.2 | Guard27项：头全部截断、prefix/socket、最短/高位/只头超限/合法1MiB、取消/游标/永久错误，无自研mask引擎 |
| 3.3 | 承载13项：Binary/continuation/空/控制、累计1MiB及text/RSV/opcode/mask负向；三协议UDP跨消息拆并 |
| 4.1 | 1/7/17短写与交替Pending、Guard取消、永久错误、成熟库WriteBufferFull/IoWouldBlock原型，无后台writer |
| 4.2 | 真实TCP下行背压仍读上行/Ping且恢复恰一次；空continuation/32头/65536字节预算，fixed-library分配实测及保守模型 |
| 4.3 | shutdown首poll Pending后late写BrokenPipe且零计量、5秒期限、双方Close/无状态/异常、半帧/rawEOF/真实TLS截断；final07真实VMess EOF与EOF依赖应用限制 |
| 5.1 | final11 VLESS10项，首载荷/server-first、原生UDP/XUDP、多目标/来源/IPv6/代次/GlobalID/大小/空包；首非法/Reject零成功，runtime自持DNS |
| 5.2 | final12 VMess14项，security3/4/策略5、M/P/A、四承载方向重放、原生UDP/packetaddr/XUDP及坏AEAD/Forwarded/逐包Reject；final06early真实首块 |
| 5.3 | final10 Trojan13项，多用户、TCP/UDP/IPv6/来源、全部认证/UDP截断、大小/空包/逐包Reject；原必填TLS及runtime零DNS |
| 5.4 | runtime9项，新旧连接/每入口握手、单绝对期限、阻塞DNS/有限UDP队列、全部UDP路径与packetaddr竞争、force children/许可归还/监听和真实映射重绑、精确payload计量；无每帧任务 |
| 6.1 | final01–30全部0，受影响旧路径按当前输入重跑；失败历史不隐藏 |
| 6.2 | 六占位示例final08真实原模板失败/替换后check不bind/启动/业务；README/usage/路线/矩阵及传输/内存说明、文档链接核查 |
| 6.3 | 本逐项映射、输入摘要、精确上游/库来源、strict与真实任务核对；仅开发完成，8项集中验收待做 |

这里是有限开发证据，不是任意资源调度/生产容量证明。packetaddr数据报wire只有IP，不能伪造域名阻塞DNS；测试以同Server原生VMess UDP的真实阻塞DNS与活动packetaddr映射竞争共享预算。

### 内存实测口径

库原型三个固定夹具在macOS ARM64测得请求峰值1196104 / 4276362 / 4276362字节，窗口drop后增量均0。约4.08MiB最大观测不是整连接RSS，也不是所有输入硬上限；32MiB为松容量核算与回归阈值，不是新增准入机制。源码增长/共享Bytes/同时存活与OS/TLS/分配器内部瞬态排除项见[内存说明](websocket-memory.md)。全局连接数仍须结合完整链路和内核缓冲预算。

## 最终开发输入

逐文件SHA256按相对路径排序，对`摘要 + 两空格 + 路径 + 换行`再次SHA256；非Git提交或release。生产文件内嵌单测按整文件，独立`tests.rs`/`*_tests.rs`及tests目录归测试；vendor全部普通文件含许可/补丁/冻结evidence。

| 集合 | 文件数 | SHA256 |
|---|---:|---|
| 自有生产/Cargo | 49 | `b11497c313cec211f1d0102b6dc6b073ad153893ab3c4b25108c71bbfa9f703a` |
| 独立测试 | 51 | `aa42bf50f824bf8d4ab06c908abe5ef418caf423e2f54e48b6775c3ba392c5a0` |
| 示例JSON | 16 | `dd74abeaaa04f2b5a43bd35d32f15361a66bd1811a60ceb5ba23e31686124c34` |
| rustls vendor | 131 | `0abf965a58a0e663e3c0df2a13c5e42e63d0fa7c00da494f18e041d0321a03f5` |
| Shadowsocks vendor | 70 | `492837defd4f266f99673ca2521a744e92ab943f903b9712a65d4d101e4f44f1` |
| Cargo.lock | 1 | `56b19d93fc724a1cf6b2cf0dd52264029112e41194bb5f0299ae8000d613b723` |

环境：`rustc 1.95.0 (59807616e 2026-04-14)`、cargo1.95.0、aarch64-apple-darwin、OpenSpec1.12.0。两个vendor集合与REALITY开发快照一致，旧WS前锁被本批获准四包增量替换，旧报告只支持各自输入。

## 未执行与后续

本批没有运行任何新官方代理客户端、恢复/启动容器、Linux验证、精确Rust1.91、release、发布或生产部署，也没有Git/归档/系统代理/DNS/防火墙/权限修改或删除操作。官方运行前另取本批许可，不能沿用旧SS24+9授权。7个ignored不计通过；旧410/262/209/33不拼接为本批结果。

Vision18/27、VMess21/30、REALITY21/29的集中验收继续待完成。开发完成允许推进下个独立能力，gRPC/XHTTP、QUIC协议、NW3/Anywhere及其他路线尚未实现，不把WS完成当成整个内核完成。
