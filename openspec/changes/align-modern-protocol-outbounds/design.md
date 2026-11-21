## Context

参见 proposal.md。当前 WireGuard/MASQUE 已有 smoltcp TCP 出站，依赖 socket-udp 已启用但尚未使用；根 Association 拒绝三个出站 UDP。NW3 固定 Nowhere 3.3.0 已有内部 open_udp，VectorClient 只公开 TCP。

## Goals / Non-Goals

**Goals:** 复用成熟库/正式线格式，补三类出站 UDP、边界/隔离与生命周期；修正对齐声明。

**Non-Goals:** 不自研密码学，不修改冻结 rustls/shadowsocks；不擅自引入新核心依赖或 QUIC 补丁；不做旧协议、官方客户端/三平台/MSRV/release、发布、系统网络或 Git 操作。

## Decisions

- WireGuard/MASQUE 复用现有共享栈的 SocketSet，新建按目标绑定的 smoltcp UDP handle，独立所有者析构回收。通过共享 UDP session trait 对根 Association 暴露 send/recv；不复制已有协议认证。
- 根 Association 新增按目标的有界 session 表和有界发送队列，读任务有 JoinSet/TaskTracker 所有者。同步持有 session 完成回包后投递 Packet，复用原预算/资源槽与计量。所有新增表受 max_udp_targets 限制。
- NW3 仅增加 VectorClient::connect_udp/VectorDatagram::send/recv/close 的薄 API，内部调用原 open_udp；不改 wire、Flow 控制或密码算法。
- 修正现有 driver 持有自身强引用导致弱引用计数永不归零的退出条件；丢弃最后业务/出站所有者后关闭驱动。
- Brutal 使用本机固定 Xray 上游源码和锁定 quinn-proto 0.11.19 核对，准确 pacing/逐包反馈属依赖/API 门禁；该任务保持未完成，先完成独立不受阻 UDP 项。

## Risks / Trade-offs

- [固定目标 UDP 多会话] → 每目标独立 socket、回包源校验、有界目标表与超时。
- [用户态栈排队/MTU] → 单包长度检查，明确错误/丢包，不声称完整 L3 VPN；与现有 MTU 语义一致。
- [driver 生命周期] → 修复唯一 driver 强引用判定，退出唤醒等待者；取消时资源用 Drop 回收。
- [磁盘不足] → 完成实施后只集中编译回归，禁增量增长，保留日志并清理可重建产物。
- [旧文档/术语过时] → 以当前源码和真实测试为准更新本批文档，不改历史验收证据。
