## Why

XHTTP 已成为 Xray 近期主流客户端默认使用的 HTTP 伪装承载之一，现有 WebSocket 与 gRPC 入口无法覆盖其 single/packet/stream 三种复用模式、路径会话与 downlink GET 语义。为继续向单一服务端内核覆盖上游能力，需要在不新增运行时依赖的前提下提供 VLESS/VMess/Trojan 的 XHTTP 入站。

## What Changes

- 新增三个独立入口 `vless-xhttp`、`vmess-xhttp`、`trojan-xhttp`；旧入口行为不变。
- 支持 HTTP/1.1 与 HTTP/2（TLS 下协商 h2，明文下 h1/h2c prior-knowledge）；TLS/明文策略与既有 gRPC 入口一致（明文必须显式 `allow_insecure_transport`）。
- 支持 `stream-one`、`stream-up`、`packet-up` 与 `auto` 模式；默认路径 `<path>/<session>/<seq>`，兼容 query/header 的 session/seq 与 x_padding。
- 实现上行有序队列（seq 缓冲上限默认 30）、30 秒未建立 downlink 的会话回收、GET downlink 流式响应（`text/event-stream` 可关闭）、`X-Accel-Buffering`/`Cache-Control` 头。
- 复用既有 VLESS/VMess/Trojan 认证与 TCP/原生 UDP/XUDP/packetaddr/Trojan 逐包 UDP 业务层。
- **明确不支持** XHTTP over HTTP/3（需要 QUIC 依赖）、XMUX 客户端复用策略与 fallback；这些单独变更。
- **BREAKING**: 无。新入口为增量；未知 `xhttp` 字段继续按严格配置拒绝，不静默降级。

## Capabilities

### New Capabilities

- `xhttp-inbound-transport`: XHTTP 入站的配置、HTTP/1.1 与 h2 请求处理、会话/序号/填充、上行队列、downlink 流、三协议复用与资源边界。

### Modified Capabilities

无。

## Impact

- `src/config.rs` 与 `src/config/`：新增 `Xhttp` 配置类型及三入口解析/校验。
- `src/transport/`：新增 `http1` 请求解析（可复用/抽取 WebSocket 现有升级解析）与 `xhttp` 服务端；h2 分支复用现有 `h2` 依赖。
- `src/runtime.rs`：新入口监听分发与 TLS/明文构造。
- `src/forward.rs`/`src/udp.rs`：沿用既有共享 lease 与任务回收，不复制 DNS/路由/UDP 内核。
- 测试、示例与文档：新增回环集成测试、六份占位模板与边界说明。
- 依赖：不新增 normal/build 依赖；不修改两个冻结 vendor 与现有 Cargo.lock 依赖版本。
