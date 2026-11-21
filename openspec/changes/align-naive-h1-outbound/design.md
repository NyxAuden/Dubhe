## Context

见 proposal.md 的动机。现有 Naive 根路径按 H2/H3 分派，中间 TCP 跳固定调用 H2；TLS 工厂已有 ALPN 核查，H1 可合法不协商 ALPN。请求 helper 已统一 Basic、Padding、额外头和 8192 头预算，成熟 httparse 已锁定可用。

固定只读证据：

- forwardproxy `e747854e78743dba85c039b38ed185fb11d93667`，forwardproxy.go SHA256 `07b4e3e7cff3ea3d45e08e9016168b39400222d014d420f6ed26507461aafa6b`。CONNECT 通常先 200，再拨号；H1 serveHijack 调用 dualStream(..., false)，响应 Padding 不是 H1 payload 开关。普通直拨没有 UoT Router。
- sing-box `v1.14.4`，protocol/naive/inbound.go SHA256 `caa718fc2f676b8cee8d8b373abb34b4081b7dbdf901ecaa31e862375cd85b01`，inbound_conn.go SHA256 `f61dd34c47421d06dc04c407016cc9984714bb511cf4f7afe8fa30c8c164d3a2`。Hijacker 分支使用 naiveConn，Read/Write 经过 paddingConn，首八块 PaddedData；连接交给初始化的 UoT Router。

这说明“H1 一概无 padding”只对固定 forwardproxy 成立，不能外推全部上游。当前本内核 H1 入站仍为裸流，该事实不在本批偷偷改变。

## Goals / Non-Goals

**Goals:**

- 显式 H1 版本与 payload 选择，真正接通根和链，保持默认 H2。
- 保留 Basic/CA/ALPN/路由、预算与停机所有权，边界可独立验证。
- H1 padding 模式复用已有 codec 和 UoT v2，不创造新 wire。

**Non-Goals:**

- 不自动探测 H1 payload（响应头不足以区分）；不启用 HTTP 自动回退、透明重试或凭证重放。
- 不修改裸 H1 入站及普通 HTTP CONNECT 的既有状态码策略。
- 不新增共享 HTTP 池、明文 Naive、浏览器外观或新依赖/vendor 补丁。
- 开发回环不代替官方互通、三平台、精确 MSRV/release 验收。

## Decisions

1. `http_version:"1.1"` 对应 H1，新增默认 false 的 `h1_padding`，true 只能用于 H1。裸流对齐 forwardproxy；true 对齐 sing-box H1。H1 `udp_over_tcp:true` 必须同时 h1_padding=true，确保不会把普通 forwardproxy 冒充 UoT 对端；上游是否支持 UoT仍需部署者明确匹配。
2. 增加 TCP 版本分派 helper 供根与链共用；H3 仍专属 QUIC且拒绝 TCP 链。H1 只通告 http/1.1，允许无 ALPN，拒绝实际不匹配协议，不降低 H2 的强制 h2 策略。
3. H1 请求复用已有 request() 校验/敏感 Basic 和头。显式写 HTTP/1.1 CONNECT authority 与 Host，写后实际 flush，再读响应。请求完整字节也受 8192 上限，不拼接未经验证的头。
4. 响应逐字节有界读取到 CRLFCRLF，用已锁 httparse 严格解析，头≤8192、头项≤64；仅 HTTP/1.1、200 成功。可接受的纯 100/102/103 临时响应有次数/累计头预算，101 或其它最终非200拒绝；重复 Padding 拒绝。成功 CONNECT 的 Content-Length/Transfer-Encoding 按 RFC 9110 §9.3.6 忽略，不用 HTTP body parser 或 chunk decoder读取后续隧道。
5. 裸模式返回原 Upstream（包括地址/管理所有权），即使响应含 Padding 也不包装。显式 padding 模式要求响应非空 Padding，才复用 PaddedStream。无猜测、无 payload 探测。逐字节头读取避免吞首批业务，无额外 Prefix buffer。
6. H1 不另建 driver/发送队列/后台任务；握手 future拥有承载，取消/超时/拒绝同步丢弃，现有 Context/root 与链超时约束覆盖。payload 写/flush/FIN委托原流或成熟 padding codec，保留 TCP/TLS 半关闭与反向排空。
7. 独立 duplex/TLS 对端验证 wire，而不是只双方互测；生产链两侧、身份/CA/ALPN/路由零业务、端口/任务/预算真实释放分别验证。全部落盘后单 Cargo、CARGO_INCREMENTAL=0、默认线程栈集中 check/test，记录失败再修复。

## Risks / Trade-offs

- [H1 两上游 payload 不一致且头相同] → 显式 h1_padding；独立对端验证 false 下绝不加/剥帧，true 下首八块与第九块边界。
- [forwardproxy 200 早于目标拨号] → 文档不将 200 解释为目标连接成功；之后传输失败真实上报，不自动重放。
- [逐字节读取有额外 poll] → 仅≤8192握手头，优先保证不丢早数据与实现简单；不引入新解析库。
- [sing-box 模式不适用于当前裸 H1 入站] → 当前使用文档明确部署匹配；独立正式 wire/UoT 参考对端验证，不偷偷改服务端造成兼容破坏。

## Migration Plan

现有配置默认 H2，行为不变。新增 H1 需显式版本，sing-box padding/UoT需显式开关。回退只需恢复 H2或移除新字段；不迁移持久状态，不归档或发布。
