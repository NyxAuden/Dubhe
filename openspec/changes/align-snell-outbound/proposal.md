## Why

Snell入站已有v4/v5/v6正式记录层和服务端行为，但根出站类型尚无Snell，无法将被接受的连接转给标准Snell上游。用户要求按固定上游逐项补齐现代协议角色，不用入站完成推导出站完成。

## What Changes

- 增加Snell v4/v5/v6出站，复用既有成熟AEAD/KDF及正式记录层；支持v6 default/shaped、unshaped、显式unsafe-raw。
- TCP按固定上游发送CONNECT_V2、userkey和字符串目标地址，校验服务端ReplyTunnel/ReplyError，保留业务字节、零块FIN与反向排空。
- 增加正式UDP-over-stream逐目标会话，经共享Association管理目标/字节/队列预算，保留空包和地址边界；超单记录上限拒绝不截断。
- 认证/记录损坏、路由reject、超时与取消失败关闭，不回落direct；子任务有所有者并可回收。
- 当前独立能力单元是Snell TCP记录承载上的TCP/UDP出站；正式QUIC、HTTP/TLS obfs与顺序连接池仍单独跟踪，配置不得静默接受未实现选项。

## Capabilities

### New Capabilities

- `snell-outbound`: 固定上游Snell v4/v5/v6 TCP与UDP-over-stream出站、身份/应答及资源生命周期。

### Modified Capabilities

- 无；主规格尚未建立Snell出站能力。

## Impact

涉及config/route/outbound/udp、Snell记录层的最小复用API、专属流适配、测试与文档。固定依据为sing-snell `v0.0.0-20260904135315-bc5a12ac736f` 及sing-box v1.14.4；不新增依赖、不修改vendor/密码原语，不运行官方客户端/多平台/MSRV/release，不Git/归档/发布或修改系统网络。全部实施完成后集中锁定离线验证，并清理可重建对象文件。
