## Why

AnyTLS 出站目前每业务独立 TLS/流，已有正式 padding 但缺少固定上游的会话池与跨流生命周期。补齐原生客户端的持续帧读取、独立流 ID、空闲会话复用和 TCP/UoT 共用池，不把 FIN 错当 TCP 半关闭，也不自造优先把所有并发业务塞进同一活会话的调度策略。

## What Changes

- AnyTLS 原生运行时出站默认按固定上游启用会话复用，可选 `anytls.disable_reuse`、空闲检查/超时毫秒值、`min_idle_session`；省略对象使用上游30秒检查/30秒超时/最少0项。配置严格校验且不增加 wire 字段。
- 每条 TLS 仅一次密码前导和 Settings；每逻辑流递增 u32 ID，SYN + 目标 PSH，后续按ID分派PSH/SYNACK/FIN，未知/迟到帧不串目标。既有逐会话 padding 计数与每出站共享方案保留；后台持续处理更新/ServerSettings/心跳/Alert，不依赖用户读取。
- 池按上游优先取最新空闲会话，池空才沿原 TCP/TLS/via 工厂拨号。并发流不擅自抢占忙会话；协议层可同时持有多个不同ID，关闭一流不关其它流。TCP 与 UoT 共用池/方案，UDP via仍失败关闭。
- FIN 关闭整条逻辑流，peer FIN不回送；本地关闭实际排空已接受写并只发一次FIN，失败SYNACK限于该流，认证/传输/Alert/截断则关闭会话。复用后v2会话按固定上游有3秒开流看门狗，收到下一完整帧头解除；不自动重放业务。
- 空闲定时回收、最少保留数量不主动预拨；本地最多64个缓存会话、每会话64活流、每流4块读队列及有限会话写队列。热替换停用旧池但保留既有活流，最终停机等待子任务/socket真实析构。
- 完整实现后集中回环/独立对端/取消与资源验证、离线全量回归并清项目对象，官方客户端等外部验收仍后置。

## Capabilities

### New Capabilities

- `anytls-outbound-pool`: 正式会话池、ID分派、多流生命周期、控制帧与有界回收。

### Modified Capabilities

- 无，主规格尚无AnyTLS出站池。

## Impact

config/route、AnyTLS客户端共享前导/帧helper与新池模块、forward根与链中间跳、UDP的AnyTLS UoT建流、热替换池停用、测试/文档。固定 `sagernet/sing-anytls@v0.0.0-20260902142641-43bb1cbea74e`：client.go SHA256 `f363c781153cbeac9575540e6e189a5226735126c26c1ef22ed2c6e95a959636`，session.go `e52cc8976c0caa07279cad01906bf2d29b0c03bf15111f58d763e22f9ab36935`，stream.go `a3ed56ec20c2ef7bfe25e68e99e4093260552cc2ff7d8276a377171298e7068c`。sing-box v1.14.4公开配置/适配另核，实际依赖 anytls/sing-anytls v0.0.11，不能混称其使用该sagernet提交；本批线协议与池语义按已固定源码实现，未执行上游。不新增依赖/改vendor/密码原语，不Git/归档/发布/系统网络，不运行官方客户端/三平台/MSRV/release。
