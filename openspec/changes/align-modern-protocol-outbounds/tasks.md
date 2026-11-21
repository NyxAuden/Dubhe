## 1. 上游对齐

- [x] 1.1 核实固定上游 Brutal 与锁定 QUIC API 差异，交付精确阻塞/门禁记录并修正完成声明。
- [ ] 1.2 完整补齐 Brutal 的独立 pacing 与逐包 ACK/loss 语义，用固定上游向量及控制器测试证明，不以近似代替；涉及核心依赖/API 门禁时保持待完成。

## 2. 标准 UDP 出站

- [x] 2.1 共享栈补 WireGuard UDP socket/session 与 driver 生命周期；回环覆盖双目标、空包、取消和密钥负例。
- [x] 2.2 共享栈补 MASQUE CONNECT-IP UDP，保持标准 H3/地址分配与证书校验；回环覆盖 UDP 与资源释放。
- [x] 2.3 NW3 增加原上游 UDP Flow 薄公开 API 并接内核路由；真实 Portal/Vector 回环覆盖 TLS/QUIC、双目标及空包。
- [x] 2.4 根 Association/forward 接通三种 UDP 出站并复用预算/目标上限/路由拒绝；集成用例证明不回落直连。

## 3. 集中验证与记录

- [x] 3.1 完成后集中 fmt、锁定离线 all-targets check 与回归，失败修复，忽略不计通过；保存真实结果。
- [x] 3.2 更新当前文档/矩阵，区分入站出站与未完成项，清理本批可重建产物并报告磁盘。
