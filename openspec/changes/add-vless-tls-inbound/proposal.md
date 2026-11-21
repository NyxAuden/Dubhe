## Why

基础内核已有 SOCKS5/Trojan，下一批需要增加主流 VLESS 客户端接入，并尽早明确 REALITY/Vision 所需的底层能力。以独立的 VLESS v0 + 标准 TLS 兼容单元推进，避免把协议头、flow 和 TLS 扩展混作一个支持声明。

## What Changes

- 增加 VLESS v0 over TCP+TLS 入口、规范 UUID 多用户认证、TCP 和原生固定目标 UDP。
- 使用现有路由、DNS、连接/握手/UDP 预算及有期限停机；保持原有配置与行为兼容。
- 为固定 Mihomo 的 UDP 接入增加显式开启的 XUDP：命令3内的 UDP 多会话、逐帧目标、End/KeepAlive、有界缓冲和身份隔离。
- 明确拒绝非空 addons、TCP Mux、Rvs、Vision/REALITY、VLESS Encryption 与包装。不提供跨承载 GlobalID 续接；同一 ID 不得跨认证身份复用资源。
- 增加独立 wire 测试和固定三家客户端的显式互通用例；无法实际运行的客户端场景保持待互通。
- 单独记录 REALITY/Vision 可行性证据及后续工作；该研究不表示功能实现。其他剩余协议继续按路线拆分变更。

## Capabilities

### New Capabilities

- `vless-inbound`: VLESS v0 标准 TLS 入口的配置、认证、TCP/UDP、资源清理及证据约束。

### Modified Capabilities

无；基础变更仍保留在 changes 中未归档，不修改其原始行为契约。

## Impact

影响 config/runtime/protocol/udp 及测试和示例。复用 rustls 与常量时间比较，不新增 TLS 后端或自研密码学。UUID 使用严格标准字符串解析，不接受上游非 UUID 字符串派生身份扩展。生产运行不依赖上游子进程，不提交、发布或部署。
