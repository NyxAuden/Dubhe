## Why

现有服务端内核的协议覆盖不同，使用者常常为了现有客户端需要的不同协议部署多个内核。本项目要提供独立 Rust 服务端内核，长期覆盖 Xray-core、sing-box 与 Nowhere 当前服务端协议及能力，并以真实客户端互操作结果证明兼容。

## What Changes

- 建立单一程序的配置、模块注册、生命周期、资源预算与运行日志基础；不包装现有内核进程。
- 本变更先交付实际可用的基础闭环：SOCKS5 TCP/UDP 诊断入口、Trojan over TLS TCP/UDP 服务端、Direct/Reject 出站、系统 DNS 与最小确定性路由。
- 区分承载连接、TCP 业务流和 UDP 关联，不把 QUIC 多流、数据报或反向出口强行压成同一种字节流接口。
- 建立固定版本的外部客户端互操作测试与支持状态记录，不以解析配置或自测成功代替兼容证据。
- 记录长期协议/传输/特殊角色矩阵和后续批次；VLESS/REALITY/Vision、Shadowsocks、VMess、Hysteria2、TUIC、NW3 等不会因本阶段较小而被移出目标。
- 暂以 Linux x86_64/ARM64 为服务端验证目标、JSON 为原生配置形式，均为可调整的工程建议。

### Non-goals

- 本变更不声称完成全部协议，不实现复杂 QUIC 协议、REALITY、Vision、NW3 或反向出口。
- 不开发客户端 UI、终端设备的 TUN/系统代理接管、账号计费平台或订阅销售系统。
- 不承诺原样兼容所有上游配置、管理 API 和分享链接，也不实现动态第三方插件 ABI。
- 不在首个闭环中实现配置热更新、分布式管理或通用插件框架。

## Capabilities

### New Capabilities

- `server-runtime`: 单进程模块化服务端、严格配置校验、启动失败清理、有界停机与资源管理。
- `proxy-forwarding`: TCP/UDP 分离的业务流、Direct/Reject、最小路由与系统 DNS。
- `baseline-inbounds`: SOCKS5 和 Trojan/TLS 的明确支持组合、认证、数据转发及失败行为。
- `interoperability-evidence`: 固定上游与客户端基线、外部互操作测试和诚实的能力声明。

### Modified Capabilities

无；当前是新项目，没有既有规范或实现。

## Impact

计划增加一个库与 CLI 共用的 Rust 包、集成测试和 Linux 验收配置。拟使用 Tokio、Serde、成熟 TLS/密码学库；具体依赖版本与许可证在实施时核查并锁定，不复制上游依赖版本作为本项目承诺。

研究材料见 `docs/source-research.md`；长期范围见 `docs/compatibility-matrix.md`，阶段建议见 `docs/roadmap.md`。提案创建时所有协议均未实现；本提案本身不是功能交付证明。2026-11-04 第一阶段实施结果另见 `docs/acceptance.md`。开源方向已明确，具体许可证尚待确定，未授予对上游代码的无条件复制许可。
