## Purpose

移植固定上游 ShadowTLS v3 出站连接器，使现有下游代理出站可通过 `via`/detour 使用真实 TLS 外观的 ShadowTLS 外层，同时保持无目标、无 UDP、无自研密码原语的协议边界。

## ADDED Requirements

### Requirement: Targetless v3 detour

`shadowtls` 出站 SHALL 只连接配置的 ShadowTLS 服务器并完成真实 TLS + v3 记录层，返回内层原始 TCP 流；它 MUST NOT 接受业务目标、MUST NOT 作为终端路由目标、MUST NOT 提供 UDP。只有下游代理的 `via` 指向它且下游 endpoint 与 ShadowTLS endpoint 一致时才允许。

#### Scenario: Valid and invalid composition

- **WHEN** 下游 Shadowsocks/Trojan/VLESS 等出站通过 via 引用 endpoint 一致的 ShadowTLS，或 ShadowTLS 被直接选为终端/用于 UDP/endpoint 不一致
- **THEN** 前者返回可写内层流；后者在配置或拨号阶段失败关闭

### Requirement: Upstream v3 wire

客户端 MUST 使用固定上游格式：32 字节 legacy SID（28 随机 + HMAC-SHA1(password, ClientHello 去除 SID 后 4 字节并补零) 前 4 字节）、SHA256(password||server_random) KDF、握手期服务器 application_data 的 XOR/HMAC、内层 `[0x17,0x03,0x03,len][4字节 HMAC][payload]` 双向链；MUST NOT 替换密码原语或自造记录格式。

#### Scenario: Wire verification

- **WHEN** 客户端与固定 ShadowTLS 服务端/独立参考端握手
- **THEN** SID、HMAC 链、握手期记录和首内层记录均按上游格式验证，错误 HMAC/类型失败关闭

### Requirement: Real TLS and HRR

外层 MUST 使用真实标准 TLS 1.3（显式 CA/SNI），MUST NOT 复用 REALITY 临时证书/KX 验证路径；TLS1.2 回落 MUST NOT 视为已认证。客户端 SHALL 支持首个 ServerHello/HRR 一次性 seed 和 HRR 对等（CH2 保留 SID）；ECH、TLS1.3 early data、TLS1.2 会话恢复 MUST NOT 启用或宣称支持。

#### Scenario: HRR handshake

- **WHEN** 伪装 TLS 服务器发送 HRR 后完成握手
- **THEN** 客户端使用同一 SID/seed 完成 v3 认证与内层记录，不因 CH2 SID 重建失配

### Requirement: Failure and resource boundaries

记录校验失败、远端 reset/EOF、TLS/ALPN 失败、取消或实例停机 MUST 关闭内层流和所有子任务，不自动重连、不重放、不返回部分认证流。配置/chain/timeout 错误 MUST 失败关闭，不静默直连或降级到普通 TLS。

#### Scenario: Failure closed

- **WHEN** 认证/记录失败、chain endpoint 不一致或 stop 发生
- **THEN** 无可用于业务的流，连接/任务/证书资源回收

### Requirement: Evidence boundaries

实现和验证 MUST 区分本批本机回环与官方 sing-box/ShadowTLS 客户端、三平台、MSRV/release 验收；MUST NOT 宣称 ECH/early data/UDP 或完整替代上游所有配置形状。

#### Scenario: Evidence boundary

- **WHEN** 本机 SS-over-ShadowTLS 回环通过
- **THEN** 只记录该本机组合，不推导官方兼容或其它角色
