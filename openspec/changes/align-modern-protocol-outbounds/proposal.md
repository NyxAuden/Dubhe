## Why

现代协议主体已有入站实现，但 WireGuard/MASQUE/NW3 出站 UDP 仍失败关闭，Hysteria2 Brutal 的采样/半窗近似也不能声明为上游等价。用户于2026-11-11明确要求继续对齐并逐项补齐，按协议角色实施，不添加私有线格式。

## What Changes

- 核查固定上游与当前 QUIC 接口，修正 Brutal 完成口径；完整逐包/pacing 对齐保持独立任务，不因近似测试通过而完成。
- WireGuard/MASQUE 出站在既有用户态 smoltcp 栈补充有界 UDP 会话，复用内核 Association 路由、预算和停机。
- NW3 Vector 通过既有上游 UDP Flow 增加最小公开 API，根项目按目标复用关联，不修改报文。
- 集中离线回归，验证空包、目标隔离、错误密钥/认证、路由拒绝、取消/停机与资源回收。

## Capabilities

### New Capabilities
- `modern-outbound-datagrams`: WireGuard/MASQUE/NW3 的标准 UDP 出站与可核实的对齐状态。

### Modified Capabilities
- 无；仓库尚无上述出站角色的既有规格。

## Impact

影响 src/transport/{wireguard,masque}、新增共享 UDP socket 适配、src/udp.rs、forward.rs、vendor/nowhere 的加性 API 与测试/文档。复用锁定依赖，不改冻结 rustls/shadowsocks；新增核心依赖/扩大的 QUIC 补丁需单独门禁。旧协议、官方客户端、三平台/MSRV/release验收与系统网络操作不在本批自动执行范围。