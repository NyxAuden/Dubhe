## Why

固定 sing-box v1.14.4 的 Naive H1 使用正式首八块填充与 UoT Router，而现有 H1 入站只提供固定 forwardproxy 的裸隧道。两类上游不能由同样的 Padding 请求头区分，应增加显式服务端模式而不是改变现有默认行为。

## What Changes

- Naive 入站新增默认 false 的 `h1_padding`，true 时对 H1 启用固定 sing-box 首八块 PaddedData；H2/H3 继续现有能力协商，不受该字段影响。
- 填充 H1 仅接受有非空单一 Padding 头、合法 Basic 认证的普通 CONNECT；200 返回正式 Padding，保存同批早数据且不提前解码或丢失。
- 显式填充 H1 识别精确 `sp.v2.udp-over-tcp.arpa:0`，进入已有 UoT v2、UDP 路由和预算；不 DNS/拨号魔数。普通 0 端口和默认裸 H1 仍拒绝。
- 覆盖独立 TLS wire、生产原生出站、TCP/UoT、认证/方法/截断负向、共享预算/停机与热替换资源边界。
- 所有代码/测试/文档落盘后集中离线回归，记录真实结果并清项目可重建对象。

## Capabilities

### New Capabilities

- `naive-h1-inbound-padding`: 显式 Naive H1 填充入站与受认证 UoT v2 的正式 wire、路由和生命周期行为。

### Modified Capabilities

无。既有未归档批次保留各自历史输入与结果，不把出站结果当作新入站证据。

## Impact

涉及 Naive 入站配置/分派、共享 HTTP 请求解析的窄策略入口、正式 padding 与 UoT 复用、模块/集成测试和当前说明。无新依赖、Cargo/vendor/密码原语修改，无系统网络、Git、归档、发布或容器操作。官方客户端、三平台、精确 MSRV/release 与长期验收仍后置。
