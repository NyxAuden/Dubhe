# 上游源码研究记录

研究日期：2026-11-04。目的：确定服务端内核的公共边界与协议特例，不做全面审计，也不把上游功能当作本项目已实现能力。

## 证据边界

- 本轮阅读 Xray/sing-box 各 10 个关键源码文件或关键函数节选；另外直接核查 Xray Trojan UDP 编解码。
- Nowhere 阅读 11 个关键文件或节选，含 Cargo 清单、入口、流/数据报、Portal、Egress 和 QUIC 生命周期。
- 源码研究阶段未运行或构建上游，也未验证性能、安全性或客户端互操作；未审查全部依赖实现。后续第一阶段单独运行了官方客户端，结果见 [互通报告](interop-report.md)，不将后续互通扩大为源码审计结论。
- 上游源码仅作只读研究，未复制到本项目源码。阅读源码后的独立实现不应被宣称为经过法律确认的 clean-room 实现。
- 下载内容在项目外各自独立临时目录中，不在其目录执行解释器、构建工具或上游脚本；持久证据使用上游链接，不依赖临时文件。

## 固定基线与许可

| 上游 | 研究基线 | 许可信息 |
|---|---|---|
| XTLS/Xray-core | [v26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31) | [MPL-2.0](https://github.com/XTLS/Xray-core/blob/v26.10.31/LICENSE) |
| SagerNet/sing-box | [v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) | [GPL-3.0-or-later](https://github.com/SagerNet/sing-box/blob/v1.14.4/LICENSE)，另有名称/关联声明限制，复用前需核查 |
| NodePassProject/Nowhere | [v3.3.0](https://github.com/NodePassProject/Nowhere/releases/tag/v3.3.0)，commit `000007b2482b8acf3a609888921fd847cad56c33` | [Cargo](https://github.com/NodePassProject/Nowhere/blob/000007b2482b8acf3a609888921fd847cad56c33/Cargo.toml) 和源码 SPDX 明确 GPL-3.0-only |
| Nowhere-Protocol | 研究时无公开 release/tag；main 上的 NW3 文档 | [规范](https://github.com/NodePassProject/Nowhere-Protocol/blob/main/PROTOCOL.md)采用 CC BY 4.0；[README](https://github.com/NodePassProject/Nowhere-Protocol)允许独立实现自行选择许可 |

第一阶段已补齐 Xray commit `a4a3dff5b20c2faae567b742c172c7b95e75c083` 与 sing-box commit `c005f35300ce76427dc285481ec5695f5b179cd2`；查询来源及官方资产校验见 [reference-clients.md](reference-clients.md)。Nowhere-Protocol main 的不可变 commit 尚未固定，必须在后续 NW3 实现前补齐；当前没有 NW3 兼容声明。具体项目许可证尚未选定，不据表格推断任意代码复制组合都合法。

## Xray：已读机制

以下链接固定在 v26.10.31。

| 文件与符号 | 已观察机制 | 对新内核的启示（设计判断） |
|---|---|---|
| [main/distro/all/all.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/main/distro/all/all.go)、[common/type.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/common/type.go) `RegisterConfig/CreateObject` | 匿名导入触发初始化，反射类型登记构造器 | 使用 Rust 显式构造器与编译特性，不复制全局 init/反射机制 |
| [infra/conf/xray.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/xray.go) `InboundDetourConfig.Build` | 分离 ReceiverSettings/ProxySettings；配置 loader 与最终编译构成是不同证据 | 配置解析、组合校验、运行实例构建分开 |
| [core/xray.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/core/xray.go) `RequireFeatures/Start` | 延迟解析依赖，未满足依赖报错；Start 注释提示失败后状态未知 | 明确定义启动屏障与失败清理，不直接继承未知状态语义 |
| [proxy/proxy.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/proxy.go)、[transport/link.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/transport/link.go)、[common/buf/buffer.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/common/buf/buffer.go) | Inbound/Outbound 分工；Link 是 Reader/Writer，Buffer.UDP 携带地址 | 数据报语义不能只看表面 Link 抽象判断；Rust 中显式区分流和包 |
| [common/session/session.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/common/session/session.go) | 原始、实际、路由目标及协议/优化相关状态 | 核心保留少量公共元数据，协议特例不堆成万能会话对象 |
| [app/router/router.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/app/router/router.go) `pickRouteInternal` | DNS 参与路由，并存在 SkipDNSResolve 循环保护 | 明确解析阶段、路由规则语义与解析递归边界 |
| [proxy/vless/inbound/inbound.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/vless/inbound/inbound.go) `Handler.Process` | Vision 检查 TLS/REALITY/VLESS Encryption 类型、访问底层缓冲并根据包装限制 splice | 不能许诺任意 AsyncRead/Write 包装都支持 Vision；协议正确性与零拷贝分别验证 |
| [proxy/trojan/protocol.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/trojan/protocol.go) `PacketWriter.writePacket/PacketReader.ReadMultiBuffer` | UDP 帧逐帧地址、载荷长度为大端 u16、CRLF 后为载荷 | 补足官方说明未展开的长度语义；不是复制其解析容错策略 |

Trojan [官方协议说明](https://trojan-gfw.github.io/trojan/protocol)已读；官方描述含认证/请求无效时的 fallback。本项目首批不实现 fallback，只声明有效认证转发的有限兼容，必须公开差异。

## sing-box：已读机制

以下链接固定在 v1.14.4。

| 文件与符号 | 已观察机制 | 对新内核的启示（设计判断） |
|---|---|---|
| [include/registry.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/include/registry.go)、[adapter/inbound/registry.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/adapter/inbound/registry.go) `Register[Options]` | 按角色注册配置和构造器，部分类型委托条件注册组 | 显式类型化模块注册，未编译模块给清晰错误 |
| [box.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/box.go) `Context/New/start/preStart` | registry 注入与校验，多阶段生命周期，启动失败调用 Close | 使用显式所有权和启动事务；Scope 内部未读，不能宣称其完整回滚已证实 |
| [adapter/router.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/adapter/router.go) `ConnectionRouterEx`、[adapter/outbound.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/adapter/outbound.go) | TCP net.Conn 与 UDP PacketConn 分离，带关闭通知，出站描述网络能力与依赖 | 依赖小接口、TCP/UDP 分开；外部 PacketConn 实现不在本次审查范围 |
| [adapter/inbound.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/adapter/inbound.go) `InboundContext`、[adapter/session.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/adapter/session.go) | 集中目标、用户、嗅探、DNS、终端信息及缓存；session 文件只提供 KeepSession 标记 | 服务端不要直接搬入终端进程/MAC 等不需要的字段 |
| [adapter/dns.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/adapter/dns.go)、[route/route.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/route/route.go) | DNSRouter/DNSClient/DNSTransport 分工，路由可触发解析并选择出站 | 分离解析与业务路由，但显式规定两者如何协作 |
| [protocol/vless/inbound.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/vless/inbound.go) `NewInbound/NewConnection/KTLSCompatible` | 组装 UoT、mux、TLS、V2Ray transport，实际协议 service 委托 sing-vmess/vless | 不能将适配层已读当作 Vision 实现已读；组合和优化约束独立校验 |

## Nowhere：已读机制

以下源码均固定到 commit `000007b2482b8acf3a609888921fd847cad56c33`，链接使用对应 tag v3.3.0。

- [Cargo.toml](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/Cargo.toml)、[src/lib.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/lib.rs)、[src/main.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/main.rs)：Rust + Tokio、rustls、Quinn；库暴露 Portal/Vector/Egress，CLI 按 URL scheme 分派。这证明其实现选型，不证明这些库覆盖其他内核全部握手。
- [src/common/lifecycle.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/common/lifecycle.rs)：平台信号入口；[src/egress/runtime.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/egress/runtime.rs)：维护任务、取消与有界排空。新内核应把信号留在 CLI，库提供停止接口。
- [src/protocol/flow.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/protocol/flow.rs)：区分 Carrier 与 FlowKind，UDP FlowId 与 QUIC stream 方向关联。
- [src/protocol/datagram.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/protocol/datagram.rs)（前 220 行节选）：DATA/FRAGMENT/CLOSE 与分片元数据；读了编码与主解码入口，未审查后续所有校验和重组算法。
- [src/portal/conn.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/portal/conn.rs)：TLS/QUIC 认证、ALPN、exporter 绑定、角色分派、Egress 注册；Egress 不允许主动打开业务流。TLS 与 QUIC 并非简单替换承载。
- [src/portal/forward/mod.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/portal/forward/mod.rs)：Forwarder 共享转发，Outlet 区分 Network/Egress，流预算和取消统一管理。
- [src/portal/egress/registry.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/portal/egress/registry.rs)：TLS 单次领取与 QUIC 可复用入口不同，RAII 注销和陈旧条目清理；不能把 Egress 当普通拨号器。
- [src/transport/quic_runtime.rs](https://github.com/NodePassProject/Nowhere/blob/v3.3.0/src/transport/quic_runtime.rs)：连接持有 UDP 路由和字节预算，有限队列及重组状态，取消后清理；具体重组实现未读。

观察到 Portal 引用 Vector 中的辅助类型/函数；这属于当前项目的模块组织，不应在新服务端项目中直接照搬角色依赖。NW3 Core 与 Prelude/Egress 扩展需要分别验证，不能用 Core 编码测试宣称 Anywhere 已互通。

## 尚未证明的事实

- 上游全量功能清单、所有 build feature、第三方库内部算法和客户端最终构建行为。
- REALITY/Vision 在候选 Rust TLS 后端上的可行性、非标准 QUIC 拥塞控制与参数对齐。
- 各客户端当前稳定构建对每种组合的真实支持；Anywhere 可用测试构建的版本与获取方式。
- 所有性能、可靠性、安全保证；这些均需要后续可执行测试。
