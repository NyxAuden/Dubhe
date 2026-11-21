## Context

见 proposal.md。前批 H1 出站已完成5/5，完整回归1349/0/43且清理对象恢复38GiB；不以该结果证明新入站。固定上游证据与hash详见`docs/naive-h1-outbound-development.md`：sing-box v1.14.4 inbound.go的Hijacker分支使用naiveConn，inbound_conn.go明确首八块padding，构造时共用UoT Router；固定forwardproxy的H1则为裸流。该差异不能靠相同能力头自动探测。

现有Naive H1委托普通runtime HTTP，H2/H3已有单独正式codec/UoT；HTTP解析器集中认证、目标解析与early buffer，默认拒绝0端口。runtime拥有连接准入/force取消，Context共享UDP预算和TaskTracker。新增模式应复用这些边界而不复制认证和codec。

## Goals / Non-Goals

**Goals:**

- 显式选择sing-box H1行为，默认与普通HTTP/Mixed行为不变。
- 认证和头校验之前不解码业务，200头与padding层正确分离，早数据可重放至codec但绝不重发网络业务。
- 精确魔数的UoT v2沿用共享预算、路由、取消与资源所有权。

**Non-Goals:**

- 不自动探测裸/填充流，不增加wire字段、协议回退或密码原语。
- 不改变H2/H3的现有协商、流控或HTTP时序，不复制另一份认证/UDP路由实现。
- 不承诺sing-box/Caddy配置兼容、Chromium/Cronet指纹或全部HTTP行为一致。
- 不新增依赖/vendor补丁或执行官方/三平台/MSRV/release验收。

## Decisions

1. 入站新增顶层布尔`h1_padding`默认false，仅影响ALPN http/1.1或无ALPN的H1路径。配置变动属于监听配置变化，沿用现有完整重启/热替换边界；不把现有活流切换codec。
2. 为共享HTTP握手抽窄策略入口：原handshake保持原行为；Naive填充入口要求CONNECT、恰好一个非空Padding头，仍共用Basic常量时间比较/重复认证拒绝/有界头和Accepted early。只在该策略允许精确v2魔数的0端口，不放宽普通HTTP/Mixed/默认Naive或普通0端口。
3. Naive专属H1处理复用绝对TLS+HTTP握手deadline；成功解析后释放握手permit。普通TCP经Context路由/拨号成功后200，失败502；UoT不先拨魔数，200后读标准初始请求。均有实际flush的正式Padding响应。
4. PrefixReader保存头后已读原始字节，先PrefixReader再PaddedStream，200响应本身不能被padding。首8块/第9块双向行为直接复用既有成熟codec。要求Padding而非默回raw，避免同一模式出现歧义。
5. UoT仅精确`sp.v2.udp-over-tcp.arpa:0`（与现有H2/H3限定一致）；真实业务逐包路由/预算，不扩称legacy和任意0端口。按实际UDP路由reject/不支持上游失败关闭，不静默直连。
6. H1仍一连接一流，复用已有max_connections/max_handshakes；不额外消耗H2/H3流permit。没有新后台任务；force取消由连接owner销毁流，UoT派生任务仍受Association/children覆盖。慢头只占自己的握手槽，已成功连接释放握手额度。
7. 独立H1 TLS端按公开wire手写padding与UoT，验证early/首8第9/大流/半关闭/截断及零目标负向；另用生产原生H1出站验证TCP和UDP，不将双方互测代替独立wire或官方验收。预算与停机需要真实端口/permit回收，不能只等sleep/timeout。

## Risks / Trade-offs

- [上游H1模式互不兼容] → 显式配置默认false，true缺少Padding拒绝；文档列清双方配置必须一致。
- [共享解析器放宽影响HTTP/Mixed] → 仅窄策略入口允许精确魔数，专测原入口0端口仍拒绝。
- [请求头后同批已含业务] → early原始字节在padding codec之前回放一次，独立对端验证截点，不靠客户端等200回避。
- [停机/慢业务残留] → 无新detached任务，真实连接/UDP关联/字节槽/端口验证。

## Migration Plan

旧配置省略字段保持裸H1。部署sing-box H1客户端时显式true，并保持客户端模式一致。恢复false只影响新实例/新连接，不切换活流。无持久状态迁移、归档或发布。
