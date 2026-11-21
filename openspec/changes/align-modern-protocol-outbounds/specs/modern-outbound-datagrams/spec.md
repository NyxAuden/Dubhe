## Purpose

补齐现代代理内核的隧道与 Vector 出站 UDP 角色，在不发明线格式、不绕过路由且保持认证与资源隔离的前提下，让既有入站可按配置选择 WireGuard、MASQUE 或 NW3 发送原始 UDP 数据报。

## ADDED Requirements

### Requirement: 标准出站 UDP
内核 SHALL 通过 WireGuard、MASQUE CONNECT-IP 和 NW3 Vector 的正式上游报文承载 UDP，不把 UDP 当无边界 TCP，不静默改走 direct。

#### Scenario: 两目标与空包
- **WHEN** 同一关联向两个回环目标交替发送非空和空数据报
- **THEN** 接收端保留边界和目标地址，不串包，原样返回有效载荷。

### Requirement: 安全与有界资源
系统 MUST 保留原有身份/证书/密钥校验和路由拒绝，限制会话数、目标数和排队内存，取消/超时/停机后回收读任务及底层 socket。

#### Scenario: 认证与路由拒绝
- **WHEN** 使用错误密钥/凭据或目标命中 reject
- **THEN** 不产生目标业务流量，不退回未认证或直连路径。

#### Scenario: 取消与停机
- **WHEN** 建立过程取消或 UDP 关联结束
- **THEN** 对应用户态 UDP socket、目标关联与读任务释放，不泄漏隧道驱动。

### Requirement: 对齐证据真实
系统 MUST 把本地互测与官方兼容分开；Hysteria2 Brutal 的现存近似不得被描述为完整上游等价，未获准的依赖/API 改动不得越权实施。

#### Scenario: QUIC 能力不足
- **WHEN** 当前接口缺少逐包丢失反馈或独立 pacing
- **THEN** 记录精确阻塞与后续门禁，完整对齐任务保持未完成，不以半窗/采样替代结果打勾。
