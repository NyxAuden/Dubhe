# 内核嵌入加性 API 记录

基线：Nowhere 3.3.0，GPL-3.0-only；协议编解码、TLS/QUIC、Morph、认证和 Flow
状态机继续复用本目录上游实现，不通过启动独立内核实现。

既有适配包含固定 quinn 版本、Portal/Egress 的停止令牌及 VectorClient TCP API。
2026-11-11 本批新增：

- `VectorClient::connect_udp(host, port)`：只构造上游 Target 并调用原 `udp_flow::open_udp`。
- `VectorDatagram::send/recv/close`：薄封装原 UdpTunnel 操作；区分空数据报和 Flow EOF。
- lib.rs 公开 `VectorDatagram` 类型。

未改变任何线上报文字节、密钥派生、载波选择、重放/认证或队列算法。
根项目 `tests/nw3.rs` 用真实 Portal 覆盖显式 TLS/QUIC 载波、双目标、空包和错误密钥。
不把本记录解释为官方 Anywhere/Nowhere 客户端兼容已验收。
