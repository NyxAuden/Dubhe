---
status: accepted
---

# 以 GPL-3.0-only 复用 Nowhere，而不是重写 NW3

NW3 是 Rust 实现，与 Go 的 Xray-core、sing-box 不同，可以直接作为库链接。重写它意味着重新实现 TLS 1.3/QUIC 承载、Morph 前导、认证帧、Flow 分帧、0-RTT 与重放防护等大量已成熟且经过上游验证的逻辑，并承担与官方客户端的互通风险。用户明确选择「接受 GPL-3.0-only，直接复用」，并要求「一切优先复用」。

因此项目整体采用 **GPL-3.0-only**，`vendor/nowhere` 整包复用 Nowhere 3.3.0，只做两处最小本地修改：固定 `quinn`/`quinn-proto` 版本，以及新增 `Portal::run_with_stop` 以接入本内核的停止令牌。根目录新增 `LICENSE`，第三方来源与修改记录在 `THIRD-PARTY.md`。

代价与边界：

- 项目许可证不再是待定项，需按 GPL-3.0-only 分发（含对应源码）。
- Git 中的 vendored 源码由本项目维护，上游更新需要人工同步并重跑验收。
- Portal 目前是嵌入的独立子系统：自行绑定端口、直连出站，不经过本内核的 route/outbounds/统计/限额；日志格式与 telemetry IPC 也沿用 Nowhere。若要把 NW3 纳入统一策略，需要拆出协议层，这属于后续独立决策，不能由本 ADR 推导。

此决策不改变「只做服务端内核」的产品边界（见 [0001](0001-independent-server-kernel.md)），也不代表 Egress、Vector 或任意 NW3 扩展已支持。
