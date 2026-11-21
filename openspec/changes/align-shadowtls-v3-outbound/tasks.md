## 1. 客户端与 HRR 门禁

- [x] 1.1 在 `vendor/rustls` 为现有 SID hook 增加默认关闭的 HRR 放行开关：ECH/early data 继续拒绝，CH2 不重建 SID；更新补丁元数据/门禁记录并保持 REALITY 默认行为。
- [x] 1.2 新增 ShadowTLS v3 客户端记录层：SID/HMAC-SHA1、KDF、握手期 XOR/HMAC、首 ServerHello/HRR seed、双向 Verified 链、记录边界/alert/EOF，复用服务端常量与 HMAC 原语。
- [x] 1.3 用真实标准 TLS + SID hook 构建客户端；显式 CA/SNI，禁用 ECH/early data/resumption，握手后返回内层 raw TCP 流。

## 2. 出站集成与测试

- [x] 2.1 新增 `shadowtls` 出站配置/类型/校验：version 3、password、endpoint、tls；拒绝终端/UDP/缺字段/非法 SNI，并构建 `ProxyOutbound`/ShadowTlsClient。
- [x] 2.2 在 via 链特判 ShadowTLS：下游 endpoint 一致时完成 outer TLS/v3 并返回内层流，跳过重复 TLS；终端/多 ShadowTLS/链不匹配失败关闭。
- [x] 2.3 独立参考端/真实 SS-over-ShadowTLS 回环覆盖 SID/记录/首记录、HRR、错误 HMAC/类型、终端/UDP/链拒绝、取消/停机；不调用生产客户端 codec 生成答案。
- [x] 2.4 更新说明/矩阵/路线/记录并区分官方验收；全部落盘后集中 fmt/check/test，真实修复失败，最后仅清可重建对象并报告磁盘，不 Git/归档/发布/系统网络/外部验收。
