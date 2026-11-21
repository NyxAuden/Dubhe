## Why

Naive入站已有H1/H2，缺少上游正式H3承载；现有padding头字符集/后缀和短写取消行为也需要对齐。核查固定forwardproxy发现H1 hijack明确不启用payload padding，不能把该上游行为当待补缺口。

## What Changes

- Naive可选 `h3:true`，在相同端口提供UDP QUIC/H3，保留TCP TLS H1/H2默认行为。
- H3普通CONNECT（非扩展CONNECT）复用Basic认证、路由与统计，按`padding`协商首8块PaddedData。
- padding响应头对齐上游16字符集、30..61长度与波浪号后缀；修复AsyncWrite短写/Pending/flush取消数据记账。
- H1保持无payload padding，文档纠正此前缺项。

## Capabilities

### New Capabilities
- `naive-h3-inbound`: 正规Naive H3 CONNECT与padding、认证和生命周期。

### Modified Capabilities
- 无（现有主规格尚无Naive能力）。

## Impact

涉及config、runtime、naive、naive_padding、复用xhttp H3 reader、tests和文档。仅复用锁定quinn/h3依赖，不新增核心依赖、不修改vendor。官方客户端/多平台/MSRV/release、Git/归档/系统网络不执行。