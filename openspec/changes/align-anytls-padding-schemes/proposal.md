## Why

AnyTLS服务端已按padding-md5下发默认方案，但出站客户端未声明/应用方案更新，也未按默认30字节握手填充和Waste写入；服务端自定义方案未开放。继续固定上游padding.go/session.go对齐，不把收到命令6或跳过Waste当成完整客户端支持。

## What Changes

- 建立有界的正式padding scheme解析与生成，保留原始文本和标准MD5，复用成熟随机源；实现stop、包序号范围与c标记、大小区间及Waste帧写入规则。
- AnyTLS客户端默认发送30字节握手填充，在Settings声明padding-md5，将Settings/SYN/目标PSH合并为第一批写入；每出站共享方案，命令6合法更新作用于后续写及新会话握手，非法更新保留旧方案。
- 服务端增加可选padding_scheme，验证后按原始文本和摘要下发，不自造协商字段；默认保持现有方案。
- 保留帧短写/Pending/取消状态、全流FIN语义、认证/路由与有界资源；方案不能导致无界分配或无限循环。
- 本批只完成padding角色，AnyTLS出站连接池/多流复用仍独立待补，不以本批完成推导这些能力。

## Capabilities

### New Capabilities

- `anytls-padding-schemes`: AnyTLS正式方案解析、客户端生成与更新、服务端自定义下发及资源边界。

### Modified Capabilities

- 无；主规格无对应能力。

## Impact

config/route、anytls服务端与客户端、共享padding模块、TCP/UoT出站接线及测试文档。固定sing-anytls v0.0.0-20260902142641-43bb1cbea74e；不增依赖、不修改vendor或密码原语，不Git/归档/发布/系统网络；仅实施后集中离线验证，官方客户端/三平台/MSRV/release未授权不运行。
