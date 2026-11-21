# 现代出站 UDP 与上游对齐记录（2026-11-11）

变更：`align-modern-protocol-outbounds`。用户已要求按上游正式行为逐项补齐，不实现自造线格式。

## 实施与结果

- WireGuard 出站：共享 boringtun + smoltcp 栈增加固定目标 UDP socket、双栈、空包与MTU检查；先完成真实握手，不在错误密钥路径计入成功业务。
- NW3 Vector：新增原上游 `open_udp` 的薄公共API；根关联按目标隔离Flow；显式 `/tcp:PORT`/`/udp:PORT` URL按上游解析。未修改认证、Morph或报文。
- 根Association增加逐目标有界队列，worker载荷独立占字节预算，完成/取消/超时回收；目标数受max_udp_targets限制，错误密钥/凭据/证书、路由reject均不回落直连。
- 修正两个隧道driver自持强引用导致永不退出的问题，测试证明最后所有者丢弃后外层UDP端口释放。
- 新增目标建立future单独堆分配，默认线程栈通过原REALITY队列/DNS/强停回归，不以增大RUST_MIN_STACK掩盖失败。

## 真实验证

工具链：Rust/Cargo 1.95.0，本机 macOS ARM64。

- `CARGO_INCREMENTAL=0 cargo test --locked --offline`：**1192 passed、0 failed、43 ignored**，70个测试结果块，退出0。
- 全量日志：本机临时路径 `/tmp/rpk-modern-udp-suite-fixed.GOfwLy`。
- `CARGO_INCREMENTAL=0 cargo check --locked --offline --all-targets`：退出0；仍有既有unused/dead-code等警告，不声称零警告。
- `cargo fmt --all -- --check`：退出0。
- `tests/tunnel_outbound_udp.rs`：7项，双目标、空包、IPv6内层/IPv4外层、错误密钥/认证/证书、路由拒绝、目标上限与超MTU后旧会话仍可用。
- `tests/nw3.rs`：8项，含原Portal/Egress回环及新增TLS/QUIC UDP、空包、错误密钥与拒绝路由。
- 模块新增UDP handle取消/析构、WireGuard/H3 driver最后所有者退出、ADDRESS_ASSIGN前缀验证。

首次集成用例发现显式载波端口推导失败并修复；首次全量发现REALITY默认栈溢出并修复；H3端口回收先失败后补endpoint排空，最终全量覆盖。

## 未完成与边界

完整Brutal逐包ACK/loss及独立pacing仍未完成，准确依赖/API门禁见[hysteria2-brutal-alignment.md](hysteria2-brutal-alignment.md)，未将近似实现打勾。新依赖与冻结rustls/shadowsocks未改。

WireGuard出站UDP不分片，载荷上限为隧道MTU减去IP/UDP头。三类出站通过根共享关联使用，其他独立协议驱动能否代理UDP仍按各自现有边界，不扩称全入口可用。

本机互测不是官方兼容。未运行官方客户端、三平台、精确MSRV/release或发布；未Git/归档/系统网络操作。

## 存储

构建使用 `CARGO_INCREMENTAL=0`。最终只清理已完成构建遗留的 `target/debug/deps/*.rcgu.o`（65234个，逻辑32.32GiB），保留依赖库、测试二进制与日志。清理后本机可用空间约40GiB。不清理源码、vendor、验收资产或证书。
