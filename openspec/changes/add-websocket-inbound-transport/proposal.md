## Why

目前内核已覆盖多个代理协议，但仍不能接受现有客户端的 WebSocket/WSS 组合；仅有同名协议不能替代相应传输部署。本批增加复用现有认证、转发和资源管理的原生 WebSocket 服务端承载，继续扩大单进程兼容范围，不等待上一能力簇的昂贵集中验收。

## What Changes

- 增加独立 `vless-ws`、`vmess-ws`、`trojan-ws` 入站；三者支持 HTTP/1.1 WebSocket 和标准 TLS 上的 WSS，不改变旧 `vless`/`trojan` 必填 TLS、旧 `vmess` 可选 TLS 或 `vless-reality` 的配置语义。VLESS/Trojan 无 TLS 必须显式准许，不因回环监听自动弱化认证保密性。
- WebSocket 只承载字节流：复用 VLESS 无 flow 的 TCP/原生 UDP/可选 UDP-only XUDP、VMess 当前 AEAD TCP/原生 UDP/显式 XUDP/packetaddr，以及 Trojan TCP/UDP；协议认证、路由与 DNS 准入、UDP 来源/会话隔离、业务计量仍属于原有协议层。
- 以固定上游源码核对路径和 early-data 方言，提供显式、有界的 HTTP Upgrade、early-data 前缀及二进制帧适配；握手后已读字节和 partial-write 游标恰一次交付。不以 WebSocket 消息边界代替代理或 UDP 边界。
- 使用审查过的成熟 WebSocket/HTTP 实现，限制 HTTP 头、帧/消息、输出缓冲、控制帧和任务数量；复用连接/握手/UDP/DNS预算、绝对握手期限及 stop→drain→force→join 屏障。
- 明确 WebSocket Close 不提供通用 TCP 独立半关闭；为有自身结束标记的协议保留相应语义，缺少单向结束 wire 的组合公开限制，不自创私有 EOF 帧冒充官方兼容。
- 新增独立测试端、WS/WSS 示例、开发证据；先完成必要认证/报文/背压/停机回归，再把新官方矩阵、最终三平台/MSRV/release及报告保留到能力簇集中验收。

### Non-goals

不含 Vision/Direct、REALITY 上叠加 WS、VLESS Encryption、gRPC、XHTTP、HTTP/2 extended CONNECT、HTTP/3、WebSocket 出站、TCP mux、跨承载 XUDP 续接、反向代理/网页服务、通用 fallback、任意自定义响应头、CDN/公网目标配置或流量外观调优。此边界只限定本变更，不缩减长期完整内核目标。

## Capabilities

### New Capabilities

- `websocket-inbound-transport`: 三类独立 WS/WSS 入站的严格配置、有限 Upgrade/early-data、二进制字节流适配、协议组合、共享生命周期及分阶段证据。

### Modified Capabilities

无。`openspec/specs/` 当前没有已同步主规格；旧未归档变更的基础入口契约保留，本批通过新类型增加兼容单元，不把旧批次“首版不含包装”的历史限制改写成当时已支持。

## Impact

预计涉及 `src/config.rs`、新增传输模块、`src/runtime.rs`、少量协议业务分派接点、独立测试/示例与使用/路线/矩阵文档；复用原有 TLS 局部 ring，不改已冻结 rustls 或 Shadowsocks vendor。精确 WebSocket/HTTP 候选、normal/build 闭包、features、许可、MSRV及公告须先过依赖门禁；规划不更新 Cargo 或授权核心依赖变更，实施前取得相应真实确认。不启动其他内核提供生产服务，不引入动态 transport ABI，不执行 Git、归档、官方客户端新矩阵、容器恢复、发布或系统网络/权限修改。
