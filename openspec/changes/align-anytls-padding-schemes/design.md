## Context

见proposal.md。已核固定sing-anytls padding.go/session.go：range上界不包含（相同上下界时常量），反序区间交换；c仅在业务数据已耗尽时停止；packetCount从1计数，达到stop时永久关闭当前会话padding；默认握手30字节。客户端UpdatePaddingScheme替换出站共享factory，非法更新保留旧方案；服务端不主动对下行做同一套padding。

## Goals / Non-Goals

**Goals:** 正式文本/MD5/命令6，默认与自定义方案真实应用，不损坏帧/业务/认证及资源，后续会话可使用新握手填充。

**Non-Goals:** 本批不改AnyTLS全流FIN为TCP半关闭，不实现连接池或多流；后者持续独立跟踪。不开新vendor/密码库或私有协商字段。

## Decisions

- 新建anytls_padding模块统一默认文本、原始摘要、语法与生成；保留原始文本计算MD5，不重排/补换行。用现有AWS-LC随机源，无偏区间抽样，不自行写密码原语。
- 原文最多65535字节；stop按固定上游整数转u32语义（负值按32位回绕），包号要求规范u32十进制，重复键按最后值；未知键/非法区间按上游忽略。为安全设单计划区间/总生成字节上限，超界本地配置拒绝、远端更新忽略并保留旧方案，公开资源边界不伪造上游全输入支持。
- Scheme应用返回一组已成形字节块，按上游writePaddedLocked进行数据切分及标准Waste(0,id0)补零；c、stop、残余不足7字节时不造畸形帧。块批次不跨取消重建，短写游标保存，接受长度只对应业务字节。
- 每个AnyTLS出站在route构造Arc<SharedScheme>，由TCP与UoT连接共用；并发更新只切换不可变Arc快照。旧兼容connect入口可保留默认独立factory，生产两路径必须使用出站共享factory。
- 客户端认证前导使用factory当前handshake size，Settings含client/padding-md5/v，合并Settings/SYN/目标PSH后作为packet1处理；cmd6接收完整帧后替换共享factory，当前会话packetCount不重置、已stop不重新开启。
- Inbound::AnyTls新增padding_scheme可选原始字符串，启动前验证；会话将选中方案原样与摘要传入Settings处理，仍在ServerSettings之前下发cmd6。服务端不对下行私加新的padding策略。

## Risks / Trade-offs

- [恶意方案导致过大内存/CPU] → 原文、区间数、握手长度、每批生成量均有界，远端非法更新保留旧方案；用负向测试验证不截断帧。
- [取消/短写/新buffer虚报] → 单个有界pending批次保存块索引/偏移，下一次write先排空；flush/shutdown遵守实际完成语义。
- [共享方案错误串用] → 每出站独立Arc，不跨身份/endpoint共享；更新只影响该出站后续快照。
- [单流未读取时不会消费cmd6] → 当前非池化单流模型按读取驱动，文档不宣称后台实时更新；池/多流后续独立处理。
