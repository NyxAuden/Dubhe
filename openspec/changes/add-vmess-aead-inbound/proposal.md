## Why

现有内核已实现 SOCKS5、Trojan、基础 VLESS、Shadowsocks 及待集中验收的 VLESS Vision，但尚不能原生接受 VMess 客户端。增加当前 VMess AEAD 服务端能力，可继续减少 Clash/Mihomo、sing-box 与 V2Ray/Xray 用户因协议差异部署多个内核的需求，同时不引入已废弃的旧认证路径。

## What Changes

- 新增原生 VMess AEAD 入站，支持标准 UUID 多用户、TCP 直承载及可选标准 TLS，复用现有配置检查、联合准备与监听生命周期，不启动外部内核。
- 实现 AuthID、分层 KDF、请求/响应 AEAD 头、时间窗与有界重放防护；明确认证提交点，失败不得触发目标 DNS 或拨号。
- 支持当前客户端所需的 AES-128-GCM、ChaCha20-Poly1305 与无正文加密路径，以及分块、长度掩码、全局 padding；`auto`、`none`、`zero` 的配置名与线上含义分别记录，覆盖 sing-box TLS+auto 实际使用的 security 5，不把历史正文算法混入本批。直承载的无正文加密需显式准许。
- 实现显式开启的实验性认证长度兼容；固定上游该扩展的上下行长度字段沿用相同 key/nonce 序列，默认不接受，文档必须披露该 wire 局限，不能声称所有方向 nonce 唯一或擅自改线协议。
- 实现 TCP、固定目标原生 UDP，以及各自显式开启的 UDP-only 命令3/XUDP、packetaddr。覆盖三家实际默认路径及扩展选择，避免以单一 UDP 回环宣称所有编码兼容。
- 共享全局 TCP/握手/UDP/排队字节预算、路由/DNS、业务字节计量及有期限停机；所有长度、缓存、计数器、失败和取消路径均有明确边界。
- 开发阶段完成独立向量、认证/报文/资源回归、格式、编译与严格 Clippy 后，可继续下一独立模块。新官方矩阵、三平台全量、MSRV、release 与最终兼容报告集中在能力簇收尾，不继承旧结果。
- 不包含旧 VMess legacy/非零 alterId 认证、AES-CFB 等历史正文算法、VMess 出站、配置格式导入、TCP 多路复用、VMess 新传输或其他协议；无正文加密不等于请求头未认证，也不等于提供 TLS 保密性。

## Capabilities

### New Capabilities

- `vmess-aead-inbound`：当前 VMess AEAD 服务端的显式配置、认证与防重放、有限正文编解码、TCP/UDP 接入、共享生命周期和分阶段兼容证据。

### Modified Capabilities

无。既有协议的外部行为与验收范围保持；如复用内部 UDP body 入口，不改变 VLESS 响应或其 XUDP 准入语义。

## Impact

- 实施时涉及 `src/config.rs`、`src/runtime.rs`、新增 `src/protocol/vmess/` 与 UDP 适配，以及必要的共享内部入口；不重写现有转发、路由或 TLS 内核。
- 增加独立 wire/密码派生向量、运行器、资源与 CLI 测试，准备显式启用的固定参考客户端矩阵及独立示例、能力状态说明。
- 密码原语交给成熟库；实施前记录实际版本、生产 features、许可和 MSRV，明确协议 KDF 组合与密码原语的边界。不复制参考内核实现，不直接引入未经审查的整套 VMess 内核。
- 当前仅创建规划，不修改生产源码、依赖或测试。后续实现不自动 Git、归档、发布、部署、恢复容器、修改系统网络或运行未另获许可的新官方客户端矩阵。
