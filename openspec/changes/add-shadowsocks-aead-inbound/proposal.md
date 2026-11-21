## Why

VLESS/Trojan 有限组合已验收，仍缺少现有 Clash、sing-box、V2Ray 系客户端广泛支持的 Shadowsocks 接入。下一批需要把 AEAD 2017 与 Shadowsocks 2022 作为独立兼容单元实现，避免仅完成加解密就误称具备认证、重放防护和 UDP 会话兼容。

## What Changes

- 增加原生 Shadowsocks TCP/UDP 入站，不启动上游内核或外部插件进程。
- 首批算法明确为 AEAD 2017 的 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，以及 2022 的 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`；按算法、流量与客户端版本分别验收。
- 2017 单入口使用一个共享密码；2022 支持单 PSK，并在两个 AES 方法上支持服务端身份密钥加用户密钥的单层 EIH 多用户模式。严格拒绝无加密/旧流密码、ChaCha 多用户、未知方法和未实现插件/UoT/中继配置，不默默降级。
- 嵌入 MIT 的 `shadowsocks 1.25.0` 协议层及 `shadowsocks-crypto 0.8.0`，不使用完整 relay；固定来源和最小许可合规依赖补丁，禁用其认证前可填充且公开接口无法配置的2022 UDP密码缓存；经用户确认补齐2022 TCP padding/首chunk严格检查及协议层有界AEAD调用计数，不接受库的宽松行为代替规格。密码学原语、KDF和随机数仍使用成熟库，不重写密码。该组合声明工具链门槛提升至Rust 1.91，并新增AWS-LC构建/许可成本；依赖准备与缓存测试已执行，TCP严格适配及入口/完整互通仍须独立验收。
- 增加启动时 TCP/UDP 联合准备、UDP 原生监听、2017/2022 分离的会话与重放状态，以及端口0一致性、首段数据、半关闭、逐包路由、计量和停机资源回收。
- 增加独立协议向量/报文测试、损坏/重放/错误密钥负向测试、三平台普通回归及固定三家官方客户端受控互通；未执行项保持未验证。

## Capabilities

### New Capabilities

- `shadowsocks-inbound`: AEAD 2017/2022 的严格配置、密钥与用户模型、TCP/UDP 服务端行为、重放/会话/资源边界及兼容证据。

### Modified Capabilities

无；基础运行器规格目前保留于未归档的 foundation change，本变更沿用其同进程、多入口、就绪屏障及有期限停机契约，不改变已有 SOCKS5/Trojan/VLESS 行为。

## Impact

将影响 config/runtime/protocol/udp、示例、参考客户端验收和依赖锁定。现有运行器仅有 TCP 监听，需要增加原生 UDP 所有权和生命周期；现有 connected UDP 映射不能直接充当 2022 按会话归属且支持客户端地址变化的转发路径。新增依赖须更新锁文件、许可清单与实际工具链要求。只做服务端入站，不包含外部配置原样导入、终端客户端、链式 Shadowsocks 出站、SIP003 插件、中继部署或生产发布。本批规划不修改已验收生产代码，不自动归档、Git提交或部署。
