## Context

见proposal.md。固定sing-snell obfs.go提供v4客户端/v5服务端的HTTP与TLS外观；sing-box v1.14.4将v6只分派至mode，不支持叠加obfs。HTTP只丢弃首CRLFCRLF之前内容，TLS只按固定偏移提取首消息数据和后续记录，非真实TLS。

## Goals / Non-Goals

**Goals:** 正式合法wire、双角色TCP/UDP-over-stream承载、首写/短写/取消正确、资源有界并保留认证失败关闭。

**Non-Goals:** 不为v6提供obfs，不实现QUIC/顺序连接池，不提供TLS保密性或真实WebSocket。不新增依赖/改vendor，不声称浏览器指纹等价。

## Decisions

- 配置沿用入站obfs_mode，允许v4/v5 none/http/tls；v6只能none。SnellClientOptions增加obfs_mode/obfs_host/obfs_uri，host最多253可见ASCII无头注入，URI最多1024、以/开头无空白；none禁host/uri、tls禁URI。
- 独立snell_obfs::Stream<S>同时实现AsyncRead/Write，按client/server角色编码首头及增量读取；modeNone直接复用原底层类型，通过包装边界类型擦除避免扩大所有入口future。
- HTTP首写GET或101，GET body是首次输入原字节，Content-Length等于其长度，后续不发WebSocket帧；首读有界消费到CRLFCRLF后原样字节流。复用成熟base64/随机源，不另实现HTTP语义。
- TLS client首0x400字节置固定ClientHello的session ticket扩展，host在其后，剩余数据拆0x4000 application_data记录；server首payload在0x6b、长度在0x69，后续同5字节记录。随机数使用成熟源，固定字段/偏移有独立向量测试。TLS首头/尾部可能跨read，游标保存在实例，空ReadBuf立即返回。
- 写入只接受有限块并先缓存完整编码返回长度；后续write/flush/shutdown排空，短写游标保存不重复首头，取消不虚报新buffer。shutdown排空后关闭承载写端，内层Snell零块语义不变。
- Snell服务端在serve_stream最外层选择一次obfs，ShadowTLS明文detour若配置Snell则遵守该入口明确obfs选项，不隐式探测；出站begin统一包装，TCP和UDP-over-stream共用，via链仍由原工厂建立底层。

## Risks / Trade-offs

- [HTTP无限头或TLS虚报长度] → 首头8KiB/固定首段/记录u16与总缓冲有界，畸形/截断明确错误，握手由原期限约束。
- [外观与保密混淆] → 只声明Snell正式obfs，不把TLS形状等同真实TLS认证，内层AEAD/身份不能省。
- [客户端先读/服务端首写时序] → 不新增强制握手等待，首消息随真实数据产生，测试请求先行与双向首payload不丢。
