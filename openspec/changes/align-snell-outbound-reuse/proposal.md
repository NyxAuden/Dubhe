## Why

固定 sing-snell 已有基于 CONNECT_V2 和双向零块的 TCP 顺序连接复用，当前内核出站每个业务流都新建承载。继 v4/v5 obfs 完成后补这一真实上游能力，不将顺序复用误称并发多路复用、不自造新报文。

## What Changes

- Snell v4/v5/v6 出站增加显式 `reuse` 布尔值，默认 false，仅影响 TCP；UDP-over-stream 按上游仍独立建连。
- 同一出站按固定目标元数据顺序开启逻辑流，保留既有记录 codec 的 salt、nonce、shaped 状态及 obfs 首消息状态；跨目标不能串入旧业务数据。
- 业务关闭后发且只发一次零块，确认对端零块才可回池；必要时有界排空旧下行。未验证首应答、错误身份/AEAD/首应答、传输 EOF、取消中的建连及失败写不能回池。
- 池按出站实例隔离，最多 10 个空闲/等待项，180 秒过期、20 秒清理周期；等待排空有 30 秒本地期限，累计丢弃达到 0x80001 字节关闭；并发逻辑流独占不同承载。所有任务可取消、停机等待真实析构，旧出站移除不误关已交付活流。
- 根建连先取池再拨号，链式 Snell 任一跳复用原路径；不绕路直连、不自动重放失败业务。回环、独立对端与资源/取消测试后集中离线全量验证。

## Capabilities

### New Capabilities

- `snell-outbound-reuse`: 标准 TCP 顺序连接复用、排空与有界池生命周期。

### Modified Capabilities

- 无，主规格尚无该出站复用能力。

## Impact

config、route、Snell client 与池、forward 建连工厂/运行时资源停机、测试和当前使用文档。固定 sing-snell v0.0.0-20260904135315-bc5a12ac736f：`snellv4/reuse.go` SHA256 `5f6ca8cd0902d65290e5f2d9504339688ae97c7cd4e990e2713c1fcd2337ee04`，`snellv6/reuse.go` SHA256 `dcd883d3bf647ee89b25251d9a6e8dab9d551850a14be522b2688dce84cc6c57`，`internal/reuse/reuse.go` SHA256 `877f20a0dd343cbfc6c5439b5ee139b7ca7ad9241a0ed803c20d42cf0d9c610d`。不新增依赖/修改 vendor/密码原语，不 Git/归档/发布/系统网络，不执行官方客户端、三平台、精确 MSRV 或 release 验收。
