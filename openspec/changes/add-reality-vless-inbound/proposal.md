## Why

现有 VLESS 已具备标准 TLS、可选 Vision 与 UDP-only XUDP，但还不能接受 REALITY 客户端；继续补齐这一安全承载，可减少用户为不同协议部署多个内核的需求。本批承接已完成开发门禁的 Vision/VMess，必要的认证、报文、编译与资源测试随开发进行，昂贵的官方客户端及三平台验收仍集中收尾。

## What Changes

- 新增原生 Rust `vless-reality` 入站，复用现有 VLESS 用户/flow、路由、TCP/UDP/XUDP、计量及停机；旧 `vless` 必填证书配置和其他入口语义不变，不包装外部内核。
- 以 Xray `v26.10.31/a4a3dff5b20c2faae567b742c172c7b95e75c083` 及 REALITY `83f621788ca88b83179810b12baa7ae518aacb83` 为固定线协议基线，实现有界原始 ClientHello、静态 X25519/HKDF/AES-256-GCM Session ID 认证，以及 hybrid-only、hybrid+普通 X25519 两种认证选择。
- 实现特殊 Ed25519/HMAC-SHA512 证书与正常 TLS CertificateVerify；可选 ML-DSA-65 种子配置必须实际产生绑定原始 ClientHello/最终 ServerHello 的有效扩展签名，不允许配置后静默忽略。
- 完成配置目标的 TLS1.3 ServerHello 模板接入、支持组/套件验证、受限记录布局，以及认证失败时仅向该固定目标的原始转发；具体布局、不可移植部分和显式偏离写入 design，不将普通 TLS＋特殊证书候选当作完整实现。
- 增加独立、有界的 REALITY 精确 ClientHello 重放池；默认时间窗和缓存是本项目额外防护，不伪称上游已有重放保护。握手前拒绝 malformed/超限/重放，不让这些请求触发目标拨号；合法但认证失败的 ClientHello 按明确策略进入固定目标回落。
- 基于当前 rustls `0.23.46` 和 aws-lc-rs `1.19.0` 审查成熟算法与最小加性握手钩子；保留可复现 vendor 来源/许可/差异，普通 TLS 路径不安装全局 provider、不启用 REALITY 钩子。不改密码原语、不复制 MPL/GPL 参考模块；接口或许可门禁不满足则停止相关实施，不删减规格。
- 本机受控 TLS peer、离线独立向量与边界回归完成后，只能标“已实现待集中验收”；官方三家实际组合、全量平台、精确 MSRV 和 release 独立记录，未执行不得算通过。

## Capabilities

### New Capabilities

- `reality-vless-inbound`：REALITY 配置、认证、TLS1.3 握手/证书、配置目标及回落、VLESS/Vision/UDP 接入、共享资源与证据边界。

### Modified Capabilities

无。当前 `openspec/specs/` 仅有占位文件，既有能力仍在未归档变更中；本批新增能力不重写旧变更的验收结论，也不虚构已存在的主规格路径。

## Impact

- 预计影响 `src/config.rs`、新增配置与 `src/tls/reality/` 模块、`src/tls/controlled.rs` 的握手输入/会话准备接点，以及 `src/runtime.rs`；复用 `src/protocol/vless.rs`、`src/tls/vision.rs` 与公共 UDP/转发，不另写一套业务协议。
- 依赖候选为当前锁定 aws-lc-rs（静态 X25519、HKDF/HMAC、Ed25519、ML-DSA）、已有 AES-GCM，以及提升为生产用途的 rcgen `0.13.2`；rustls 仅允许基于当前精确版本的审查后最小补丁。全部新增生产边、传递依赖、features、许可、公告及 Rust `1.91` 约束须单独门禁。
- 新增回环示例、定向测试、独立矩阵入口和开发/兼容记录。测试只用自持回环或离线夹具；本规划不运行官方客户端、容器、生产探测或公网压力，不修改系统网络/权限，不 Git、归档或发布。
- 不包含 VLESS Encryption、WS/gRPC/XHTTP、REALITY 出站、通用 fallback 平台、TCP mux、跨承载 XUDP 续接、Linux splice 或流量外观调优。固定上游完整外观仿真的剩余差异必须公开，不以本批完成宣称整个上游内核等价。
