## Why

内核已接入三协议WS/WSS，但尚不能接受现有客户端的gRPC/HTTP2承载；只有协议认证相同，不代表相应部署组合可用。本批继续原生服务端兼容，复用已有协议/转发内核，同时补上多HTTP2流的准入、流控、半关闭与真实结束屏障，不等待上一能力簇昂贵集中验收。

## What Changes

- 增加独立 `vless-grpc`、`vmess-grpc`、`trojan-grpc` 入站，复用所属身份、安全/UDP扩展开关及成对可选标准TLS；不放松旧入口。明文VLESS/Trojan需显式准许，VMess安全判断只信真实TLS。
- 实现经过固定上游核对的gRPC双向流RPC路径、protobuf载荷、消息封装、响应状态和结束语义；明确代理专有模式与HTTP2连接多stream不是同一概念，不能用普通HTTP2 DATA冒充gRPC。
- HTTP2连接可以承载多个彼此认证、隔离并受限的代理RPC。分别管理物理连接、RPC准入/握手、协议业务流及UDP预算，不能让一条TCP连接绕过全局容量或把每个HTTP2 stream误算为物理连接。
- 使用审查过的成熟HTTP2/HPACK和protobuf实现；限制解压头、消息、流数、流控窗、输出、控制/任务与等待期限。背压、Pending和取消不重复交付，拒绝先于业务DNS/目标。
- 区分请求/响应END_STREAM、gRPC trailers/status、RST_STREAM、GOAWAY与TLS截断；保留可验证的独立发送方向结束，不把WS Close的会话级限制生搬到HTTP2，也不因底层支持半关闭就推断所有旧协议writer天然适配。
- 新增独立金样/HTTP2对端、三协议明文/TLS示例、资源/关闭与旧路径必要回归；开发完成仅标“已实现待集中验收”，新官方客户端矩阵、平台全量、精确MSRV、release和最终报告后置。

### Non-goals

不含Vision/Direct或REALITY叠gRPC、VLESS Encryption、XHTTP、HTTPupgrade、H2 extended CONNECT/H3、gRPC出站、反向代理/网页或通用RPC服务、压缩、任意元数据转发、TCP mux、跨承载XUDP续接、CDN/公网外观调优。HTTP2层多个独立RPC不是代理TCP mux。此边界只限定本批，不缩减长期服务端内核目标；已废弃上游模式不因历史名称自动恢复。

## Capabilities

### New Capabilities

- `grpc-inbound-transport`: 三协议gRPC服务端入口、严格配置/安全、有限HTTP2及protobuf消息、流控/半关闭/多RPC隔离、统一生命周期与分阶段证据。

### Modified Capabilities

无。当前 `openspec/specs/` 尚未同步主规格；保留旧未归档变更的配置、物理连接计量及协议契约，本批以新类型和显式RPC预算增加兼容单元。

## Impact

涉及 `src/config.rs`、新gRPC传输模块、`src/runtime.rs`、共享协议业务分派窄接点、必要遥测/资源限制，以及独立测试/示例/文档；现 `accept_loop` 一条TCP对应一协议会话，需要针对新入口引入有界连接driver及RPC子任务，而不是复制DNS/路由内核。候选HTTP2/protobuf依赖和已有bytes/http等直接边必须先核精确版本、normal/build闭包、许可、features、MSRV和公告，新增核心依赖/锁变更另取真实确认；本规划不修改Cargo或生产代码。沿用标准TLS局部ring，不改两个冻结vendor，不建立第二锁，不提高声明Rust1.91。无Git、归档、官方客户端新运行、容器恢复、发布部署或系统网络/权限操作。
