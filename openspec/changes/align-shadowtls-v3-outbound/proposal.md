## Why

项目已有 ShadowTLS v3 服务端，但固定上游 `sing-box v1.14.4`/`sing-shadowtls` 的完整客户端角色尚未移植；服务端无法作为下游代理（Shadowsocks/Trojan/VLESS 等）的 ShadowTLS 外层 detour。按“有上游参考才移植”的原则补齐该出站连接器。

## What Changes

- 新增无业务目标的 `type: "shadowtls"` 出站连接器：只拨 ShadowTLS 服务器并完成真实 TLS + v3 记录层，返回内层原始 TCP 流；由下游代理出站通过 `via`/detour 引用，不能作为终端路由目标。
- 按固定上游 `sing-shadowtls` v3 移植：32 字节 legacy SID（28 随机 + HMAC-SHA1(password, ClientHello) 前 4 字节）、SHA256(password||server_random) KDF、握手期 application_data XOR/HMAC、内层 `[23,3,3,len][4字节HMAC][payload]` 双向链、首 ServerHello/HRR 一次性 seed。
- 外层使用真实标准 TLS 1.3（显式 CA/SNI），不使用 REALITY 临时证书路径；HRR 通过已批准的 rustls SID hook 最小扩展支持；ECH、TLS1.3 early data、TLS1.2 会话恢复不支持，保持上游固定协议边界。客户端固定 strict TLS1.3，TLS1.2 回落不能作为已认证路径。
- 集成沿用现有 `via` 链：下游代理 endpoint 必须等于 ShadowTLS endpoint；ShadowTLS 作为终端、UDP 或其非法链组合在配置/运行期拒绝。
- 补配置/负向、真实 TLS 握手、SID/HMAC/记录层、无 HRR 与 HRR、SS-over-ShadowTLS 回环、取消/停机测试；不新增依赖/密码原语，不修改其它协议 wire。

## Capabilities

### New Capabilities

- `shadowtls-v3-outbound`: ShadowTLS v3 无目标 TCP detour 连接器、真实 TLS 外观、HRR 支持与失效关闭。

### Modified Capabilities

无。既有 ShadowTLS v3 服务端、`via` 链及其它出站保持不变。

## Impact

涉及新增 `shadowtls` 出站类型/配置校验、`via` 链特例、TLS SID hook 的最小 rustls 扩展、客户端记录层、测试和文档。复用现有 aws-lc HMAC/SHA、rustls/tokio-rustls、ShadowTLS 服务端常量/记录工具；无新 crate；不 Git/归档/发布、系统网络/权限/容器或官方客户端/平台/MSRV/release 验收。
