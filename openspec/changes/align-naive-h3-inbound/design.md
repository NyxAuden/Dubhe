## Context

NaiveProxy固定发布v154.0.8037.49-5及forwardproxy提交e747854e78743dba85c039b38ed185fb11d93667。后者forwardproxy.go SHA256为07b4e3e7cff3ea3d45e08e9016168b39400222d014d420f6ed26507461aafa6b；H1 serveHijack调用dualStream(...,false)，H2/H3才依据Padding头启用帧。

## Goals / Non-Goals

**Goals:** H3普通CONNECT、上游padding头与有界资源回收；短写/Pending/取消安全。

**Non-Goals:** 不复制浏览器TLS指纹，不做Naive出站或H1私有payload帧，不改vendor/密码原语/依赖，不声称官方客户端验收。

## Decisions

- Naive增加可选h3布尔值，默认false；runtime在TCP实际端口绑定后同地址绑定UDP，确保:0得到一致端口。
- 复用已有H3Reader处理DATA，Naive专用有界写任务带flush/FIN完成应答，业务写入返回只代表排队或明确发送语义，不丢写错误。
- padding写入先把业务数据复制进有界pending并返回接受长度，下一次write/flush/shutdown排空；不在Pending期间隐式接受旧缓冲却在后续不同调用虚报长度。
- H3每连接/全局流槽与连接槽、握手槽独立；stop关闭端点、join子任务，force执行取消；H2同时加流上限。

## Risks / Trade-offs

- [QUIC响应写入背压] → 写任务有界队列、完成确认、超时与取消所有者。
- [协议外观不等价浏览器] → 仅声明Naive wire对齐，指纹不在本批。
- [文档过时] → H1无payload padding明确为上游行为，真正未完成为H3/出站等角色。
