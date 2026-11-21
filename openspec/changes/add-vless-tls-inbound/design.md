## Context

现有单包提供 SOCKS5/Trojan，运行器拥有 TLS、连接/握手许可，udp::Association 处理路由、DNS、来源过滤、预算和受追踪子任务。Trojan UDP 的独立帧读取任务避免 select 取消导致丢失半帧。本次延用这些已验证机制。

线协议依据固定 Xray commit `a4a3dff5b20c2faae567b742c172c7b95e75c083` 的 `proxy/vless/encoding/{encoding,addons}.go`、`common/protocol/{headers,address}.go`。VLESS 使用端口优先的地址格式，UDP 使用大端 u16 长度；Xray writer 丢弃零长度数据。只研究，不复制上游实现代码。

## Goals / Non-Goals

**Goals:** 在现有库内增加基础 VLESS TLS 组合；复用连接管理和 UDP 转发，按协议保留差异；独立测试防止双方共享错误 codec。

**Non-Goals:** 本变更不实现 Vision/REALITY、TCP Mux/Rvs、XUDP 跨承载续接、无 TLS 公网入口、非 UUID 字符串映射。后续变更继续补齐，不把它们当永久排除目标。

## Decisions

- `Inbound::Vless` 与 `VlessUser` 显式配置。UUID 用小型严格解析器返回 16 字节，无新通用依赖；序列化保持 UUID 字符串，Debug 脱敏，校验以解析后字节检测重复。TLS 路径通过 Inbound 小方法共享，避免复制证书加载逻辑。
- `protocol::vless` 独立解析，不借用 SOCKS 地址类型。认证遍历全部用户使用 subtle 常量时间比较与选择；无效 UUID 不回显。addons 首批必须零长度，避免以空 flow 猜测未知扩展。
- TCP 成功拨号后写两字节响应，随后使用已有 relay；握手和响应有期限。
- UDP 复用 Association 和独立读取任务，使用有限枚举区分 Trojan 逐帧地址与 VLESS 固定目标。不用万能插件 trait，也不复制整套关联管理。VLESS 响应在获取关联预算和路由检查后发送，零帧丢弃计数。
- 外部测试沿用已有校验 manifest/受控回环/正常证书验证，用协议和模式参数生成配置。基础 VLESS 禁用 packet encoding，XUDP 使用显式独立模式；分别记录错误 UUID 与错误信任。执行仍受工具权限约束，受阻不绕过。
- REALITY/Vision 研究单独写文档，明确公共 TLS API 缺口、替代实现与许可证；不将普通 TLS 能协商当作可行性完成证明。

## Risks / Trade-offs

- [基础 UDP 与 XUDP 不同] → 客户端显式禁用 packet encoding；原生固定目标分别验收。
- [共享 UDP 循环引入 Trojan 回归] → 保留全部既有测试并三平台运行。
- [UUID 是认证凭据] → 配置错误、Debug 和日志脱敏；不使用真实凭据示例。
- [外部客户端执行不可用] → 内部实现和待互通状态分别报告，外部任务不勾通过。

## 实施发现

固定 Mihomo v1.19.33 没有原生固定目标 UDP 的可用配置：非 PacketAddr 分支强制 XUDP。sing-box 需要显式空 `packet_encoding`，Xray 除禁用 mux 还需要子进程 `XRAY_CONE_DISABLED=true`。来源记录在 `docs/vless-baseline.md`。基础阶段已实际通过三家 TCP 和 sing-box/Xray 原生 UDP，Mihomo UDP 不支持此基础组合。随后已实现独立 XUDP 兼容单元并新增三家测试配置。此前执行曾被自动审批器拒绝，没有绕过；用户再次直接确认固定客户端受控运行后，原命令获准执行，九项官方测试实际全部通过，变更14/14完成。具体证据见 `docs/vless-acceptance.md`。

## XUDP 扩展

显式 `xudp: false` 保持默认基础行为；开启后 VLESS 使用专用请求枚举表示基础请求或 XUDP 承载，不为无目标的命令3伪造业务地址。独立 codec 限制元数据512字节、完整解析再分配有界载荷，复用 VLESS 地址格式。

每承载持有会话表；每个会话复用 Association、持有全局 UDP 许可、初始目标和单调递增代次。回程共用有界队列，携带编号和代次，End/空闲后旧代次回包丢弃。完整帧由受追踪 reader 读取，有界通道背压保持控制帧顺序；载荷受全局字节预算约束，预算不足时保留控制语义并丢弃数据。每会话空闲独立于承载保活；保活不刷新会话。UDP 映射的 connected socket 保持来源过滤。GlobalID 只消费，不作为跨承载键。

New 重复、未知 Keep、TCP 网络和非法帧终止承载；End 幂等。资源或路由拒绝返回会话 End+Error，使其他会话可继续。回程使用 Keep+Data+UDP目标。基础与 XUDP 三家外部组合分别验收；基础阶段已通过的结果保留为历史快照。

## Migration Plan

新增类型不改变 version 1 配置及旧入口。测试使用回环临时端口；示例含明确 UUID/证书占位值。无生产部署，无自动归档或 Git 操作。
