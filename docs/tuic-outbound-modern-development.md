# TUIC 出站现代能力对齐记录（2026-11-11）

变更：`align-tuic-outbound-modern`。补出站角色的真实拥塞控制选择与可选QUIC早期握手，不把入站已支持推导成出站完成。

## 固定依据

- `sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4/tuic/client.go` SHA256：`f52624d1af0ac20da5b3c1760e6b01565ea30c1b39ad9263e2b77cab0725a151`。
- `sing-box v1.14.4/option/tuic.go` SHA256：`b3d11be4673107951c7a4ceb5be37a112ccc42d57d03239daf63a9d2ba774974`。
- 只读核查上游DialEarly、Authenticate exporter、CC选项，以及锁定Quinn 0.11.11 `into_0rtt`/`ZeroRttAccepted`/早期流拒绝接口，不执行上游客户端。

## 实施与边界

- 出站`tuic`对象增加`congestion_control`（cubic默认、new_reno/new-reno、bbr）与`zero_rtt_handshake`（默认false），保留`udp_relay_mode`。未知算法/字段、错误布尔类型配置拒绝。
- 三算法复用现有modern模块的Quinn真实工厂，作用于TCP与UDP连接；不只是保存配置字符串，也不承诺与另一QUIC库各代BBR性能完全相同。
- 每出站按地址族最多缓存两个endpoint，复用同一TLS票据存储。活TCP流/UDP关联持有endpoint所有权，热替换丢弃旧出站不会误关旧流；最后所有者Drop关闭endpoint，无新应用后台任务。
- 显式开启时真实尝试`into_0rtt`：无票据回到完整握手；TCP只提前发送标准Connect元数据，UDP连接只提前发送无目标/无副作用的标准Heartbeat。
- 业务载荷不提前发送：等待完整握手后通过真实TLS exporter派生UUID/password token，写正式Authenticate帧，再交付流或UDP发送器。TUIC没有认证成功应答，不能把写Authenticate称为已获远端确认。
- 明确0-RTT拒绝且连接仍成功时，仅重建TCP元数据流一次；若证书/连接/未知写错误则失败关闭，不重放业务，不回落direct。UDP不把首业务DATAGRAM放进早期队列，避免拒绝后待发队列语义导致重复/丢失歧义。
- PendingConnection取消guard关闭未交付连接；建立/认证受统一dial_timeout约束，无伪造early exporter、自持Arc认证任务或私有wire扩展。

**0-RTT不是天然防重放。** 默认关闭；提前Connect元数据可能在经过合法认证后触发连接副作用，部署方仍需接受TLS1.3早期数据的重放风险。这里不提供0-RTT业务延迟收益承诺。

## 验证状态

本机macOS ARM64，Rust/Cargo 1.95.0，受控回环。测试含成熟rustls票据存储的计数包装，只记录插入事件，不打印票据或密钥。

- 首次全目标check因取消测试错误地把`second.await`结果传给timeout而编译失败；改为对Incoming future本身施加timeout。未将失败命令标为通过。
- 第一轮定向：`cargo test --test tuic_outbound_modern` 3项通过，`cargo test --lib transport::tuic_client` 4项通过，退出0。真实覆盖无票据首连、有票据early尝试及接受/拒绝、唯一Connect、默认关闭、取消回收与活流保活；补两种UDP载波恢复后，定向结果为集成3项、模块5项全部通过（日志任务`b1edvo9e3.output`）；native/quic均真实尝试并接受early，然后在标准认证后只发送/回显唯一业务包。
- 首次全量：全目标check退出0；运行至45个测试结果块时，已通过1014项、失败1项、忽略42项，因既有`shadowsocks_udp_wire`随机端口联合绑定失败而中断。TCP的`:0`分配不检查UDP端口占用，后续UDP绑定报AddrInUse。修复为TCP/UDP联合准备，只有`:0`且UDP AddrInUse时有限重选（最多32次）；固定端口/其他错误仍立即报错。新增注入回归验证重试、固定冲突失败及句柄释放，不缩小测试或改系统网络。
- 修复后完整重跑：`cargo fmt --all -- --check`、`CARGO_INCREMENTAL=0 cargo check --locked --offline --all-targets`均退出0；`CARGO_INCREMENTAL=0 cargo test --locked --offline`为 **1233 passed、0 failed、43 ignored**，73个结果块，退出0。未设置全局`RUST_MIN_STACK`。完整日志：本机`/tmp/rpk-tuic-modern-validation-fixed.uQav1O`。相较前批1224新增9项（5客户端模块、3完整接线、1端口联合准备）。仍有既有unused/dead-code等警告，不声称零警告。
- 存储：首次全量结束后、重跑前清理1112个已完成`target/debug/deps/*.rcgu.o`（逻辑5.71GiB）；最终回归后再清理1112个（逻辑5.71GiB），最后可用约38GiB。保留库/测试二进制、源码/vendor、日志及私钥；不清系统缓存或容器。

未做官方TUIC/sing-box/Mihomo客户端互通、三平台、精确MSRV、release或生产验收。没有修改Cargo清单/锁文件、vendor、密码原语或系统网络；未Git/归档/发布。测试通过不扩大这些边界。
