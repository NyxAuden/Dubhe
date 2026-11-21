## Why

Snell TCP记录入站/出站已有v4/v5/v6，但固定上游v4/v5的正式HTTP/TLS obfs承载仍缺。继续以sing-snell obfs.go和sing-box版本分派为依据补齐，不把TLS obfs当真实TLS，不给v6叠加上游不提供的组合。

## What Changes

- Snell v4/v5 TCP记录承载可选obfs_mode:none/http/tls；v6只允许none，不私造v6+obfs。出站可配obfs_host及HTTP obfs_uri，未启用/不适用字段明确拒绝。
- HTTP obfs首写附固定上游语义的GET/101头，首读消费至CRLFCRLF，后续裸字节；不误用真实WebSocket帧。
- TLS obfs首消息按固定上游偏移/模板携带记录字节，后续按application_data记录分块；不通过rustls假握手、不声明保密性，内层Snell认证/AEAD保持必要。
- 双向短写/Pending/取消保存有界状态，flush/FIN排空，空读不消耗；首头/记录长度和等待受预算/超时限制，畸形/截断失败关闭。
- 完整接入入站、TCP出站及UDP-over-stream，测试独立模板/字节向量、往返、认证负例与回收；QUIC与出站顺序池仍独立待补。

## Capabilities

### New Capabilities

- `snell-obfs`: 固定上游HTTP/TLS外观承载的Snell双角色与取消安全边界。

### Modified Capabilities

- 无；主规格尚无该承载。

## Impact

config、Snell prepared/runtime与出站记录初始化、新独立承载模块、测试/文档。固定sing-snell v0.0.0-20260904135315-bc5a12ac736f，obfs.go SHA256 `49f65ed845a5148b533f052b99cf42b18821b4e41808368f6f6388e649032bac`。不增依赖/修改vendor/密码原语，不Git/归档/发布/系统网络，不跑官方客户端/三平台/MSRV/release；实施后集中锁定离线回归、清理可重建对象。
