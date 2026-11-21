## Why

原生 Naive 出站已有 H2/H3，尚不能选择固定上游公开的 H1 CONNECT。只读复核发现 forwardproxy 与 sing-box 的 H1 payload 不同，必须显式区分，不能根据同样存在的 Padding 响应头猜测而产生不兼容流量。

## What Changes

- 增加 `naive.http_version:"1.1"`，默认仍为 `"2"`，复用既有真实 TLS/CA、Basic、目标 authority 和受保护额外头。
- H1 默认使用固定 forwardproxy 的裸隧道；显式 `h1_padding:true` 选择固定 sing-box H1 的首八块 PaddedData。两者均发送正式非空 Padding 请求头，非空响应头不自动改变裸模式。
- 根与 TCP 链中间跳实际分派 H1；有界严格解析 200 响应，保留首批下行，拒绝截断、歧义与超限，取消直接析构所拥有承载、不重放。
- H1 标准 UoT v2 限显式 padding 模式，对齐 sing-box 公开角色；不声称普通 forwardproxy 支持 UoT，不改变现有裸 H1 入站。
- 补独立对端、生产配置/路由/链式/认证/资源验证，最后集中锁定离线回归与对象清理。

## Capabilities

### New Capabilities

- `naive-h1-outbound`: 原生 Naive H1 的两种正式 payload 配置、严格 CONNECT、TCP 链、显式 UoT 和生命周期边界。

### Modified Capabilities

无。既有未归档 H2/H3 批次保留历史输入和证据，不重写为本批结果。

## Impact

涉及 Naive 配置、客户端、`forward` 根/链/ALPN 分派、独立模块与集成测试、示例和当前能力文档。不新增依赖，不修改 Cargo 锁文件、vendor 或密码原语；不 Git、归档、发布或修改系统网络。浏览器/Cronet 指纹、共享 HTTP 池和官方客户端/三平台/MSRV/release 验收仍独立后置。
