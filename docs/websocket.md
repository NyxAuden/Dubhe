# WebSocket 入站使用与边界

**状态：已实现待集中验收（19/27）。** 19项开发任务完成，同输入30条开发门禁命令全部退出0，577次测试执行通过、7忽略不计通过；详见[开发记录](websocket-development.md)。上述运行早于命令 3 改为完整 Mux，重写后的 Mux 相关测试本批未运行。本文描述当前配置和代码路径，不构成最终兼容性、生产容量或全面安全审计结论。Xray v26.10.31 双向 VLESS/WSS（含 Xray XUDP UDP）与 Mihomo v1.19.33 客户端 VLESS/WSS TCP/UDP 有限互通已通过；其余固定官方客户端运行矩阵、三平台同输入回归、精确 Rust 1.91 工具链验证及本能力簇 release 仍未验收；不能沿用旧协议、旧平台或旧 release 的结果。普通独立回环测试也不能代替官方客户端互通。

本功能是在既有代理协议外增加有限 HTTP/1.1 Upgrade 和二进制 WS 字节流，不提供 HTTP 网站、通用反向代理、HTTP/2 WebSocket、HTTPupgrade、gRPC、REALITY 或任意 transport 组合；不提供公网部署调优。

## 支持形态

WS 和 WSS 使用相同的入口 `type`。是否真正执行服务端 TLS 握手，取决于该入口是否配置成对的 `certificate` / `private_key`，不是类型名或 HTTP 转发头。

| 入口类型 | 身份与 TCP | 原生 UDP | 显式扩展 | 明文条件 |
|---|---|---|---|---|
| `vless-ws` | 多用户 UUID，空 flow，TCP 首载荷及服务器先发 | 单目标 VLESS UDP framing | 命令 3 与目标 `v1.mux.cool` 进入完整 Mux；`xudp` 默认开启，控制 Mux 内的 UDP New/GlobalID | 必须显式 `allow_insecure_transport:true` |
| `vmess-ws` | 多用户 AEAD 认证头；正文 security 3 / 4，TCP 首载荷及服务器先发 | VMess UDP | 命令 3 进入完整 Mux；`xudp` 默认开启并控制 Mux UDP，`packetaddr` 为独立命令 2 扩展且默认关闭；正文弱化与 authenticated-length 另受策略控制 | 正文 3 / 4 无须 VLESS/Trojan 的传输弱化开关 |
| `trojan-ws` | 多用户密码摘要，TCP 首载荷及服务器先发；**无 Trojan 成功应答** | Trojan 逐数据报目标、IPv4 / IPv6、空数据报 | 不增加 fallback 或 TCP 复用 | 必须显式 `allow_insecure_transport:true` |

三类入口均允许 1～1024 个用户；用户名和协议身份必须满足各自校验及去重要求。`users` 与 `websocket` 为必需字段。未知字段、显式 `null` 的可选 TLS 路径 / `websocket.host` / `websocket.early_data`、不成对的 TLS 路径都拒绝，不静默降级。

VLESS 配置用户不得启用非空 flow；WS 请求中的非空 addons / flow 不作为普通 VLESS 接受。**Vision 与 WS 不组合**；不要将旧 Vision 或 REALITY 的证据套用于新入口。旧 `vless` / `trojan` 类型的必填 TLS 契约没有因此放松。

### 安全策略的两个不同维度

- `allow_insecure_transport` 只属于 VLESS/Trojan WS 入口，默认 `false`；即使只监听回环，明文也必须明确设置 `true`。它不是“前置反代已有 TLS”的信任声明。
- VMess `allow_insecure_body` 默认 `false`。security 5（无正文加密）只有在**本入口真正完成 TLS 握手**，或显式设置该弱化开关时才可能接受；还须满足已有 options / 命令限制，不能任意混用 mask、padding 或 authenticated-length。
- `Forwarded`、`X-Forwarded-Proto`、`Host` 等 HTTP 字段不能赋予真实 TLS 事实。前置代理终止 TLS 后以明文连接本内核，内核仍按明文承载处理。
- VMess security 3 / 4 的 authenticated-length 仍须显式 `allow_authenticated_length:true`；`xudp` 默认 `true`；`packetaddr`、`allow_insecure_body`、`allow_authenticated_length` 默认 `false`。`xudp:false` 不会关闭命令 3 的 TCP Mux，只拒绝其中的 UDP 会话。
- VMess WS 与旧 VMess 入口复用同一个 Server 内的身份重放池，不为每条 WS 连接建立空重放池。

## 六个回环占位模板

| 模板 | 监听 | early-data 配置 |
|---|---|---|
| [VLESS WS](../examples/vless-ws.json) | `127.0.0.1:10081` | 关闭，`path:"/proxy"` |
| [VLESS WSS](../examples/vless-wss.json) | `127.0.0.1:10441` | header，默认 `Sec-WebSocket-Protocol`，上限 2048 字节 |
| [VMess WS](../examples/vmess-ws.json) | `127.0.0.1:10082` | path，base 为 `/proxy/`，上限 2048 字节 |
| [VMess WSS](../examples/vmess-wss.json) | `127.0.0.1:10442` | 关闭，`path:"/proxy"` |
| [Trojan WS](../examples/trojan-ws.json) | `127.0.0.1:10083` | header，`X-Proxy-Early-Data`，上限 2048 字节 |
| [Trojan WSS](../examples/trojan-wss.json) | `127.0.0.1:10443` | path，base 为 `/proxy/`，上限 2048 字节 |

这些模板彼此独立，均不附带有效凭据、证书或私钥，**原样 `check` 必须失败**。

1. 复制所需模板到自己的配置文件，保留回环监听用于受控验证；不要直接把占位模板用于部署。
2. VLESS/VMess 将 `users[].uuid` 替换为各自新生成的随机标准 UUID，不使用仓库测试 UUID。VLESS 不添加 Vision flow。
3. Trojan 将 `users[].password` 的空字符串替换为新生成的随机秘密，并将提示性的 `name` 改为适当用户名称。这里刻意使用空密码：任意非空 `REPLACE_...` 文本本身可能就是合法 Trojan 密码，不能靠这种文本保证未配置模板失败。
4. WSS 将证书链和私钥两个绝对路径同时替换为真实材料；客户端按正常信任链和服务端名称校验证书，不以跳过验证代替配置。
5. 客户端使用模板中真实的 path、TLS 状态及 early-data 模式。path 模式是 base path 直接追加编码前缀，header 模式不是 query `ed` 提示；三者不可混用。
6. 使用包含本能力的当前构建先执行 `check -c <你的配置文件>`，确认后才执行 `run -c <你的配置文件>`。不要将旧 release 二进制默认视为已包含 WebSocket。

`check` 验证配置及成对 TLS 材料，不绑定监听、不接收客户端，也不连接代理目标；端口可绑定性由 `run` 阶段确定。CLI 退出码沿用成功 0、配置 / 运行错误 1、用法错误 2。回环示例的独立 CLI 检查与业务夹具见 [websocket_examples.rs](../tests/websocket_examples.rs)；该链接指向测试，不代表本段文档另行执行或证明了测试结果。

## HTTP Upgrade、路径、Host 与 TLS ALPN

入口只处理一个有限的 `GET`、HTTP/1.1、origin-form Upgrade 请求。HTTP 101 仅表示承载建立，不表示代理身份认证、路由、DNS 或业务拨号成功。101 完整写出并刷新前不会进入内层代理认证。

- `websocket.path` 为 1～1024 字节合法 ASCII 绝对路径，不能包含 query、fragment、空白或控制字符；百分号转义必须完整且解码后仍合法。
- early-data 关闭或 header 模式：请求 path 与配置 path 分别 percent-decode **一次**后区分大小写精确比较。`+` 不转为空格，`..`、重复斜线和尾斜线不折叠；query 不参与路径匹配。query 中的 `ed` 数字不启用 early-data，也不提供认证前缀。
- path early-data 模式：配置 base path 不允许 `%`；请求 raw path 必须为同一原始 base path 加规范 RawURL 后缀。后缀不做百分号解码，拒绝 query，不能从 query 或其他位置猜测前缀。
- `Host` 必须存在、合法且单值，不能用 SNI 补齐。可选 `websocket.host` 只额外限制 HTTP authority，不用于身份、源地址或业务路由，也不解析 DNS。DNS 名比较忽略 ASCII 大小写但保留尾点；IPv6 必须为合法方括号地址并按地址值比较。配置含端口时端口必须相等；配置不含端口时不限制请求端口值，但请求端口仍须合法。
- WSS 提供 HTTP/1.1 ALPN；接受未协商 ALPN 或 `http/1.1`，不接受协商为其他协议后继续 Upgrade。这不是 HTTP/2 / HTTP/3 实现。
- `Host`、Key、Version、Upgrade、early-data 载体等关键字段拒绝重复；Connection 可有多值，并按合法 token 合并检查。Key 要求规范标准 base64 编码的 16 字节，Version 为 13。
- 拒绝 `Content-Length`（包括 0）、`Transfer-Encoding`、obs-fold、裸 LF、非法百分号、非 ASCII / 控制字符 request-target、fragment、绝对 URL 和用户信息。不在 keepalive 上处理第二个 HTTP 请求。
- 不协商压缩或真正应用子协议。合法扩展提议可以忽略，但响应不返回扩展，后续 RSV 仍拒绝。early-data 关闭时非空 `Sec-WebSocket-Protocol` 拒绝；它不是通用子协议支持。
- `Origin` 不替代非浏览器代理认证，不强制网页同源，也不授予网站或管理 API 权限。普通 HTTP 失败只返回固定小型 400 / 404 / 431 响应或终止，不反射 URI、头值或目标，不重定向、不代理 HTTP。

## Early-data：显式模式与规范编码

`early_data` 缺省关闭；显式对象须有 `mode` 和 `max_bytes`，不能为 `null`。下面是三个 `websocket` 对象形态，不是可直接部署的完整配置。

```json
{"path":"/proxy"}
```

```json
{"path":"/proxy","early_data":{"mode":"header","max_bytes":2048}}
```

```json
{"path":"/proxy","early_data":{"mode":"header","max_bytes":2048,"header_name":"X-Proxy-Early-Data"}}
```

```json
{"path":"/proxy/","early_data":{"mode":"path","max_bytes":2048}}
```

- 编码为规范 **base64url 无 padding（RawURL）**，仅 `A-Z a-z 0-9 - _`；拒绝 `=`、标准 base64 的 `+ /`、非法尾位、逗号列表和重复载体。不会按部分上游服务端的宽容规则接受非规范别名。
- `max_bytes` 为解码后载荷上限，范围 1～8192。解码前检查编码长度不超过 `ceil(4 × max_bytes / 3)`，最大 10923 字节；再检查实际解码长度和重编码一致性。它不是可任意扩大的内存旋钮。
- header 模式默认 `Sec-WebSocket-Protocol`；自定义名须为至多 64 字节合法 HTTP token，不能选 Host、握手核心头、CL / TE、认证 / Cookie / 转发等保留头。header 比较忽略 ASCII 大小写。
- 配置 header 模式时，载体缺省或空值表示无前缀；path 模式没有后缀也表示无前缀，不要求每次请求必须带 early-data。
- 自定义 header 或 path 模式不能顺便接受另一个非空 `Sec-WebSocket-Protocol`，不自动探测、不合并两个来源。
- 仅当使用 `Sec-WebSocket-Protocol` 载体且成功解码为非空字节时，101 回填同一个合法 token；自定义 header 和 path 不回填。这个已知代理方言的回填不是服务器身份认证或通用子协议协商。
- 101 后，已解码前缀按唯一游标排在全部 WS Binary 明文之前；HTTP 后预读的原始帧字节仍先经过同一帧头护栏和 WS 解帧，不能当作代理明文或重复回放。

early-data 可以包含用户身份秘密。不要公开完整 URI、HTTP 头、客户端配置或私有测试工件；本内核不会把完整请求 URI / 头 / 认证前缀作为日志输出。关闭 early-data 也不会使明文 VLESS/Trojan 自动获得加密保护。

## 字节流、固定限额与调度

只将合法 Binary / continuation 聚合出的消息映射为有序字节流；协议头和业务载荷可跨任意消息拆分，多个 UDP 数据报也可同处一个消息。**WS 消息边界不是 UDP 报文边界**，UDP 边界仍由 Trojan、VLESS、VMess 原生 UDP 或 Mux.Cool 内层 framing 决定。

空 Binary 不算 EOF，Ping / Pong 不作为业务数据；控制帧可以插入合法分片。客户端帧必须 mask，服务端帧不 mask；text、RSV、保留 opcode、非法 continuation / Close 等错误终止承载，不重同步继续业务。有限 text 会先经过库的受限消息与 UTF-8 处理再被拒绝，不能声称零分配拒 text。

| 项目 | 当前固定边界 |
|---|---|
| HTTP 头（含终止符） / 头数 | 16384 字节 / 64 项；未见终止符达到上限即拒绝 |
| request-target | 12288 字节 |
| HTTP 每次读取 | 最多 1024 字节 |
| HTTP 后原始预读 / 合计预读防线 | 至多 16384 / 32768 字节；实际小读可能更早停止 |
| early-data | 解码至多 8192 字节，编码至多 10923 字节 |
| 单输入帧 / 累计消息 | 各 1048576 字节（1 MiB） |
| 引擎 read buffer | 16384 字节 |
| 引擎 write buffer | `write_buffer_size=0`，`max_write_buffer_size=131072`，含 framing |
| 单次业务写入 | 最多 16384 字节形成一条 Binary；大写可能短返回 |
| 外层每次 poll 的非业务事件 | 至多 32 个，空消息 / Ping / Pong 等也消耗预算 |
| 原始护栏每次外层 poll 的读取 | 至多 32 个新帧头起点 / 65536 原始字节 |
| Close 等待 | 5 秒，仍可被 Server 强制停止提前取消 |

窄护栏最多解析 14 字节原始帧头，提前检查最短 126 / 127 长度编码、64 位高位、mask、声明长度与控制头约束；mask 处理、continuation 状态、消息聚合、Close / UTF-8 仍由成熟 WS 库完成。HTTP 预读和后续 socket 数据使用同一路径。

达到 poll 预算后保存游标、唤醒并返回 Pending，避免连续空分片或控制帧在一次库内部读取中无限占用执行器。写入与 flush 分开：已接受的业务字节不因底层 WouldBlock 重投；未接受的 WriteBufferFull 先推进背压再重试。控制回复依赖库的有限待发状态，不额外建立无限控制队列；承载本身不创建永久后台 writer。

**1 MiB 是帧 / 消息限额，不是每连接总内存上限。** 原始 / 消息分片缓冲、已完成消息、写缓冲、TLS、协议状态、UDP 子任务及内核 socket 缓冲仍各有开销；全局连接数会放大这些开销，UDP 排队预算也不覆盖全部 WS 内存。内存边界与测量口径另见 [WebSocket 内存说明](websocket-memory.md)，不由本使用文档预测实测分配数字。

## 认证、准入、响应和公共计量

TLS、Upgrade、early-data 后的完整代理认证共用同一绝对 `handshake_timeout_ms` 期限，不能每完成一层重新获得整个认证时限。握手许可在协议认证完成后释放，连接许可覆盖实际承载 / 子任务生命周期；这不意味着 Mux 帧或所有后续业务都纳入同一认证 deadline。

坏 UUID / 摘要 / AEAD 身份、错误协议头、未开启的扩展等在业务 DNS / 拨号前拒绝。合法身份仍须经过原有路由；针对某个目标的 Reject 在该目标的 DNS / TCP 拨号 / UDP 发送之前执行。HTTP Host 与 early-data 不能绕过这些门禁。对无成功应答的 Trojan，不凭空添加确认字节；对有协议响应的 VLESS / VMess，HTTP 101 与内层响应也不能被混称为目标已可达。

### VLESS WS 命令 3 / Mux 的唯一响应

`vless-ws`（以及 TLS 的 VLESS/REALITY、VMess 正文层）在 UUID 或 AEAD 认证成功后，对命令 3 或目标 `v1.mux.cool` **先发送唯一成功响应**，再进入 Mux 帧循环；不再要求首个 XUDP `New` 先完成路由/关联准入。

1. 命令 3 的准入与 `xudp` 开关无关，TCP New 始终允许。
2. Mux 内的 UDP New/GlobalID 在 `xudp:true`（默认）时逐会话检查路由与全局 UDP 关联名额；失败只向该会话发送 `End + Error`，承载保持可用。
3. `xudp:false` 仍允许命令 3 的 TCP 会话，只拒绝 UDP；这不是 `[0,0]` 的延迟，也不关闭整条承载。
4. 后续目标与每个包仍走既有准入、会话代次及来源校验。GlobalID 是进程级去重键：后到连接复用关联并迁移回程 sink，旧会话收到 `End + Error`；最后一个会话结束后保留 1 分钟供跨承载续接。

早期 XUDP 的“首个合法 UDP New 后才应答”行为已不再保留；详见 [Mux 说明](mux.md)。

Trojan UDP 初始认证头的地址不固定后续目的地；每个数据报携带并检查自己的目标。逐包 Reject 可以按既有 UDP 语义丢包而保持承载，不伪造成功回包。connected UDP 映射只接受对应已选目标来源，返回实际 IP 来源；IPv6 能力依赖运行环境。

业务仍复用公共 DNS 并发、连接、UDP 关联、目标映射和排队预算，以及 stop → drain → force → join / children 退出屏障。只计成功写出的业务 payload；HTTP、TLS、early-data 中的认证头、代理响应、WS / UDP framing、控制帧和 flush 不增加业务字节计量。丢弃或拒绝的数据不冒充已成功发送的载荷。

## Close 不是透明半关闭

RFC 6455 Close 关闭整个承载会话，不表示独立方向的 TCP FIN。首次 shutdown 即拒绝后续业务写入，先刷新已接受输出，再发送正常 Close，有限等待对端并结束底层；没有“Close 后继续长期向另一方向发送”的保证。

- 对端 Close 1000 或无状态可作为正常会话结束；异常 Close 码仍为错误。
- raw EOF 缺少 Close、半帧或 TLS 缺失 `close_notify` 保留错误；已完整交付的消息不追溯撤销。合法 Close 可以终止尚未完成的消息分片，但其部分内容绝不作为完整业务消息交付；这不同于把半帧截断当正常结束。
- TCP 目标必须等客户端单向 FIN 后才回包的应用，不在本承载的通用透明保证范围内。服务器先发、无需 EOF 的双向交换是不同能力，不能用它们声称半关闭已支持。
- VMess 自身的 EOF 正文块仍按原协议解析；但当前 body writer 的 shutdown 最终也会关闭底层 WS，因此它不自动提供 WS 上的独立双向半关闭。
- 干净 WS Close 若恰在内层 UDP 帧边界可结束会话；截断 UDP 长度、地址、元数据或载荷仍保留错误，不能把残缺报文发往目标。

测试与源码入口可从 [配置](../src/config.rs)、[Upgrade](../src/transport/websocket/upgrade.rs)、[承载适配器](../src/transport/websocket/mod.rs)、[帧头护栏](../src/transport/websocket/guard.rs)、[运行时](../src/runtime.rs)、[Mux](mux.md) 和旧 [XUDP 编解码](../src/udp/xudp.rs) 核对。验收任务与未运行范围以 [当前变更任务](../openspec/changes/add-websocket-inbound-transport/tasks.md) 为准；不要把可读源码、测试文件存在或本文描述当成官方兼容与最终验收证据。
