## Why

TUIC v5出站已有TCP与native/quic UDP，但缺少上游正式的拥塞控制选择及显式0-RTT握手路径；入站具备这些选项不能推导出站完成。继续固定上游对齐，不把仅设置early_data或使用默认控制器冒充能力。

## What Changes

- TUIC出站参数增加congestion_control（cubic/new_reno/bbr）及zero_rtt_handshake（默认false），保留现有udp_relay_mode。
- 启用时复用TLS票据和端点以真实尝试QUIC 0-RTT；TCP可提早发送Connect元数据，UDP连接仅提前发送标准Heartbeat，业务载荷仍在握手和exporter认证写入后发送，避免native数据报拒绝后的重复/丢失歧义。
- 标准TLS exporter只能在完整握手后派生，认证与连接建立受超时约束且由调用方future拥有；不伪造early exporter，不新增脱离所有者任务。
- 无票据正常完整握手；对端明确拒绝0-RTT时只重建被拒绝的TCP元数据流，不自动重放业务，也不把未知错误当可安全重试。
- 明确0-RTT重放风险与浏览器/其他QUIC实现控制算法不等价边界；失败关闭、不回落direct。

## Capabilities

### New Capabilities

- `tuic-outbound-modern`: TUIC出站真实拥塞控制选择、可选0-RTT握手、认证与拒绝恢复生命周期。

### Modified Capabilities

- 无；主规格尚无该出站能力。

## Impact

涉及config/route、tuic_client、测试和文档。固定sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4与sing-box v1.14.4；只使用现有quinn 0.11.11、rustls 0.23.46及futures-util公开API，不增依赖/feature、不改vendor。不Git/归档/发布，不运行官方客户端/三平台/MSRV/release，不改系统网络；实施后集中锁定离线回归并清理对象文件。
