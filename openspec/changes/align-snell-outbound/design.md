## Context

参见proposal.md。已核查固定sing-snell v0.0.0-20260904135315-bc5a12ac736f的snellv4/client.go、snellv6/client.go及packet.go：TCP即使不复用也使用CONNECT_V2；每方向独立salt和记录状态；UDP命令6先校验Reply，后按单记录收发数据报。既有src/protocol/snell.rs具备这些记录codec，但未提供出站流适配；根Association已有逐目标DatagramSession及预算worker。

## Goals / Non-Goals

**Goals:** 不复制密码逻辑，复用现有记录层；Poll/Pending/取消不破坏帧；配置被接受即有真实接线；认证失败、上游拒绝和根route reject不走direct；v6单记录容量按正式u16上限处理。

**Non-Goals:** 不在本批增加QUIC、HTTP/TLS obfs、顺序连接池或浏览器指纹；这些仍在长期待办。不上新依赖、不改vendor，不把本机双方互测当官方客户端互通。

## Decisions

- 增加严格的outbounds.snell对象（psk/version/userkey/mode），type=snell才允许；psk与userkey使用现有Secret脱敏，版本4/5/6、v6模式及长度与入站相同。根普通password/uuid/tls/transport等不混用；TCP via沿用既有链式拨号，UDP via仍明确拒绝。
- 在snell内部增加client子模块访问既有私有Reader/Writer，不复制KDF/AEAD。TCP立即发送正式CONNECT_V2，首应答在第一次读取时验证并保留同记录剩余业务数据：固定上游serverConn.writeResponse会等目标首个响应才发送ReplyTunnel，故不能在connect阶段强制等回复而死锁先写业务；错误身份不能从根SOCKS成功应答推导为上游认证成功，负向以目标零业务与失败关闭验证。UDP按其上游packet.go先验证隧道应答再发送数据报。
- TCP AsyncRead/Write适配将拥有Reader/Writer的future保存在实例中，跨Pending与取消保留游标；写只接受一个有界记录，flush排空、shutdown只发一次零块，读方向继续排空。相较桥接duplex+分离任务，该设计无额外后台任务、天然由出站所有权回收；相比每次临时async read/write，不丢半帧。
- 首请求保持完整单记录，不让shaped流chunk切断较长userkey+主机名；使用既有单记录codec，同一正式记录格式，不宣称发送形态逐字节等同上游。
- UDP固定目标会话实现既有DatagramSession，交给根Association的有界worker；空数据报仍含地址头，不可解释成EOF。收包严格解析来源地址；固定IP及端口不符的回包丢弃；域名由上游解析，只保留固定目标关联并检查端口。
- v4/v5单记录0x3fff，v6单记录0xffff；既有v6 unshaped/raw和UDP服务端若沿用v4上限需一起纠正并做边界测试，不截断或私自分片。队列资源仍由根limits约束。

## Risks / Trade-offs

- [异步future类型扩大根状态机] → 在Snell流适配及已有open_datagram_target边界类型擦除，不提高全局线程栈。
- [写取消已接受数据重复/丢失] → 先复制有界业务载荷并保存future，再返回接受长度；下次操作先排空；错误记为永久失败。
- [畸形Reply/UDP来源或截断] → 严格检查帧、错误只返回固定类别，不回显不受信上游文本；认证未完成不发送业务。
- [无连接池] → 每TCP业务/UDP目标独立承载，不宣称所有上游可选性能能力；池与QUIC/obfs继续单列。
