# XHTTP 入站/出站边界（开发实现，待集中验收）

本页描述本仓库 XHTTP 入站的**已实现行为与明确限制**。已与官方 Xray v26.10.31 完成 VLESS/XHTTP TLS（auto/stream-one/stream-up/packet-up）与 VLESS/VMess/Trojan REALITY-over-XHTTP 的双向 TCP 本机互通，以及 Xray VLESS/XHTTP TLS auto XUDP 到本内核入站的 TCP/UDP（服务端 `xudp:true`；`xudp:false` 时 UDP 按设计关闭）。这些组合不代表完整官方兼容；Linux x86_64 和 Windows 尚未验收。`extra` 新增字段仅完成本地解析与本地入站运行验证，**没有**用官方 Xray 的对应配置样本做端到端互通。

## 入口与配置

- 独立入口：`vless-xhttp`、`vmess-xhttp`、`trojan-xhttp`。旧 `vless`/`vmess`/`trojan` 入口行为不变。
- `xhttp.path` 必填，1..1024 个 ASCII 可见字符，以 `/` 开头，不含 `#`/`?`。
- `xhttp.host` 可选，1..255 个 ASCII 可见字符；不校验时接受任意 Host。
- `xhttp.mode`：`auto`（默认，接受任一合法请求形状）、`stream-one`、`stream-up`、`packet-up`。
- `xhttp.no_sse_header: true` 时下行不发送 `text/event-stream` 提示头，只保留原始字节。
- `xhttp.headers`：可选静态下行头，最多 16 项；名称≤64 字节 ASCII 且不得为 `content-length`/`transfer-encoding`/`connection`/`host`，值≤1024 字节且不含 CR/LF。
- 新增顶层字段：`x_padding_obfs_mode`、`x_padding_key`、`x_padding_header`、`x_padding_placement`、`x_padding_method`、`session_id_placement`、`session_id_key`、`seq_placement`、`seq_key`、`uplink_data_placement`、`uplink_data_key`、`server_max_header_bytes`；语义与下表 `extra` 映射一致，顶层与 `extra` 同义字段同时出现会拒绝加载。
- VLESS XHTTP 不接受 `flow`（Vision 不组合；REALITY 可以组合，见 REALITY 说明）；命令 3/`v1.mux.cool` 进入完整 Mux，TCP 会话始终允许，`xudp`（默认开启）控制 Mux 内的 UDP 会话，见 [Mux 说明](mux.md)。命令 3 在认证成功后先发送唯一成功响应，再进入 Mux。
- VMess XHTTP 必须提供真实 TLS 证书/私钥，或配置 `reality`（`xhttp.h3` 除外）；明文入口不提供（VMess 只信真实 TLS/REALITY）。
- VLESS/Trojan XHTTP 可选 TLS；无证书时必须显式 `"allow_insecure_transport": true`，只接受 HTTP/2 prior-knowledge 或明文 HTTP/1.1。
- 真实 TLS 同时通告 `h2` 与 `http/1.1`；协商到 `h2` 走 HTTP/2，否则走 HTTP/1.1。
- `xhttp.h3: true` 时改为 **QUIC/HTTP3** 承载：同一 `listen` 地址改为绑定 UDP，ALPN 固定为 `h3`，必须提供真实 TLS 证书与私钥（QUIC 强制 TLS 1.3），与 `allow_insecure_transport` 互斥。请求形状、路径/主机/padding/会话与序号语义与 TCP 承载完全一致。
- 七份占位模板：`examples/vless-xhttp.json`（明文）、`vless-xhttp-tls.json`（TLS/stream-up）、`vless-xhttp-headers.json`（自定义头/padding/stream-one）、`vmess-xhttp-tls.json`（TLS）、`trojan-xhttp.json`（明文）、`trojan-xhttp-tls.json`（TLS）、`vless-xhttp-h3.json`（QUIC/HTTP3）；占位 UUID/密码/证书路径必须先替换。

## Xray `extra` 兼容（配置子集）

入站 `xhttp` 可额外出现 Xray 风格的 `extra` 对象。仅以下字段被映射到现有服务端线格式/行为；范围类字段的值形状按 Xray v26.10.31 的 `Int32Range`（整数或 `"from-to"` 字符串）：

| `extra` 字段 | 映射到 | 语义 |
|---|---|---|
| `xPaddingBytes` | `x_padding` | `"100-1000"` 或整数；`0`/`"0-0"` 归一化为默认 `100..1000`；`from>to` 时交换（同上游 `ensureOrder`）；非零范围任一端点 `<=0` 时拒绝（对应上游 “xPaddingBytes cannot be disabled”） |
| `scMaxEachPostBytes` | `sc_max_each_post_bytes` | 整数或范围；与 Xray 服务端 `hub.go` 一致只使用范围的 `To` 作为单次 POST 上限；`0` 归一化为 `1,000,000` |
| `scMaxBufferedPosts` | `sc_max_buffered_posts` | `0` 归一化为 `30`；负数拒绝 |
| `noSSEHeader` | `no_sse_header` | 直接映射 |
| `xPaddingObfsMode` | `x_padding_obfs_mode` | 混淆 padding 开关；开启后按放置位置校验请求，并按同一放置位置在响应中回送 |
| `xPaddingKey` | `x_padding_key` | 默认 `x_padding`；用于查询参数或 Cookie 名 |
| `xPaddingHeader` | `x_padding_header` | 默认 `X-Padding`；`header`/`queryInHeader` 放置使用的头名，禁止 `content-length` 等受保护头 |
| `xPaddingPlacement` | `x_padding_placement` | `queryInHeader`（默认）、`cookie`、`header`、`query`；服务端按 Xray `ExtractXPaddingFromRequest` 的顺序读取 |
| `xPaddingMethod` | `x_padding_method` | 仅支持 `repeat-x`（默认）；`tokenish` 显式拒绝 |
| `sessionIDPlacement` | `session_id_placement` | `path`（默认）、`cookie`、`header`、`query`；服务端从对应位置提取会话 |
| `sessionIDKey` | `session_id_key` | 非 `path` 放置时的键名；缺省 `x_session`（query/cookie）或 `X-Session`（header） |
| `seqPlacement` | `seq_placement` | `path`（默认）、`cookie`、`header`、`query`；服务端从对应位置提取序号 |
| `seqKey` | `seq_key` | 非 `path` 放置时的键名；缺省 `x_seq`（query/cookie）或 `X-Seq`（header） |
| `uplinkDataPlacement` | `uplink_data_placement` | `body`（默认）、`header`、`cookie`、`auto`；packet-up 上行数据来源 |
| `uplinkDataKey` | `uplink_data_key` | 头块前缀/Cookie 前缀；缺省 `X-Data`（header/auto）或 `x_data`（cookie） |
| `serverMaxHeaderBytes` | `server_max_header_bytes` | HTTP/1.1 与 HTTP/2 请求头上限；`0`/缺省为上游默认 8192，允许 `128..=16MiB`；HTTP/3 与上游一致不受该项控制 |

加载规则：

- **冲突拒绝**：同一语义同时出现在顶层与 `extra`（顶层显式出现即算，即使值等于默认值）时，配置加载失败并说明冲突字段，不做静默覆盖。Xray 在存在 `extra` 时会丢弃顶层除 `host`/`path`/`mode` 外的字段；本内核有意更严格，未在 `extra` 中出现的顶层字段继续生效。
- **显式拒绝客户端专用/无法等价承接的字段**：`downloadSettings`（客户端独立下行目标/TLS/路径，本仓库出站 XHTTP 参数是另一套配置，未承接）、`host`/`path`/`mode`/`headers`（重复表达或客户端请求头语义）、`uplinkHTTPMethod`（客户端上行方法；服务端仍只接受 POST/GET 形状）、`sessionIDTable`/`sessionIDLength`（仅客户端生成会话 ID）、`uplinkChunkSize`（仅客户端切块，服务端解码不依赖）、`noGRPCHeader`（客户端 Content-Type 形状）、`scMinPostsIntervalMs`（客户端发送间隔）、`scStreamUpServerSecs`（需要 stream-up 服务端定时向 POST 响应体写保活填充，当前未实现）、`xmux`（客户端连接复用配额）、`h2Params`（无法与 tokio h2/h3 的 SETTINGS、流控和超时逐项等价映射）以及嵌套 `extra`。
- `xPaddingMethod: "tokenish"` 在加载时拒绝：其校验/生成依赖逐字节 HPACK Huffman 长度表，本仓库当前未引入；配置可解析不等于支持。
- 未知键仍由 `deny_unknown_fields` 拒绝；映射后的数值继续受本页资源上限约束（padding `to<=16384`、单 POST `64..16MiB`、缓冲 `1..1024`）。
- `extra` 在加载时规范化合并到顶层字段，序列化回写不保留 `extra`。上述服务端可承接字段是真实生效于入站解析/响应，不做“只解析不执行”的占位支持。

## 请求形状

| 模式 | 上行 | 下行 |
|---|---|---|
| `stream-one` | 单个 POST，整个连接是一个流 | 该 POST 的响应体直接承载下行字节 |
| `stream-up` | 一个持续 POST，不与带序号的 POST 混用 | 同一会话的 GET 响应体承载下行 |
| `packet-up` | 多个独立 POST，各自带序号 | 一个 GET 响应体承载下行 |
| `auto` | 接受以上任一形状 | 按实际形状选择 |

- 路径与 Host 精确匹配（Host 配置为缺省时通配）；不匹配返回 404。
- 会话/序号的默认放置都是 `path`：stream-one 使用 `path/`，stream-up 使用 `path/session`，packet-up 使用 `path/session/seq`。配置 `sessionIDPlacement`/`seqPlacement` 后改为从 query/header/Cookie 的对应键读取；两者都不是 `path` 时不接受额外路径段。默认 `path` 放置保留历史宽松回退：查询参数、`x-session` 头或 Cookie `x_session` 也可提供会话。
- 每个会话标识要求 1..=128 字节 ASCII 可见字符，排除 `/`、`?`、`#`、`&`、`=`、`;`、`,`。
- 与 Xray 一致，GET 下行可以先于 POST 到达，此时建立待上行会话。
- `packet-up` 的上行数据默认来自请求体；`uplinkDataPlacement: "header"` 读取 `{key}-0`、`{key}-1`… 头块，`"cookie"` 读取 `{key}_0`、`{key}_1`… Cookie 块，`"auto"` 按 header + cookie + body 顺序拼接。每块是 URL-safe base64（无填充），拼接后解码；解码失败返回 400，总长超过 `sc_max_each_post_bytes` 返回 413。即使使用 header/cookie 放置，请求体仍按同一上限有界读取/丢弃，避免连接复用被污染。
- `packet-up` 的序号必须单调且不重复；重复序号与超出 `sc_max_buffered_posts` 的乱序缓冲返回 413。
- 超出 `sc_max_each_post_bytes` 的上行请求体直接拒绝。
- padding 默认范围 100..=1000。非混淆模式（默认）先从 `Referer` 查询参数、否则从请求查询参数读取 `x_padding`；值为 URL-safe base64 时按解码后长度、否则按原文长度校验，越界视为无效请求。**空 padding 仍接受**（本内核旧客户端默认不发送），这是相对 Xray 服务端的有意放宽。
- 混淆模式（`xPaddingObfsMode: true`）按 Xray 顺序读取：Cookie `x_padding_key` → `x_padding_header`（`header` 放置直接取值，其余按 URL 查询参数解析）→ 请求查询参数 `x_padding_key`；缺失或长度不符返回 400。下行响应按同一放置位置回送 padding：`header`/`queryInHeader` 写入配置的头，`cookie` 写入 `Set-Cookie`，`query` 不回送。
- 非混淆模式的下行响应固定回送 `X-Padding: X...`，长度为 padding 范围内随机值，与 Xray `hub.go` 一致。
- HTTP/1.1 的 chunked 请求体在 `stream-one`/`stream-up` 下按 chunked 解码；`Content-Length` 与 `Transfer-Encoding` 同时出现时拒绝。

## 资源与期限

- 全局 `limits.max_xhttp_sessions` 默认 256；会话超过 `session_ttl_ms`（默认 30000，范围 1000..600000）未活动即回收。
- `sc_max_each_post_bytes` 默认 1,000,000，范围 64..16 MiB。
- `sc_max_buffered_posts` 默认 30，范围 1..1024。
- `limits.xhttp_buffer_bytes` 默认 8 MiB，是同一进程内各 TCP/H3 入口共用的排队字节预算，不是进程 RSS 或所有正文缓冲的上限。
- HTTP/1.1 的 `packet-up` 请求体须在连接原握手期限内读完。`stream-up` 的 POST 在配对 GET 的内层协议认证成功前也受原期限约束；认证后归还握手名额，上传可继续，直至上传结束或中继不再读取。HTTP 200 不代表认证成功。
- `server_max_header_bytes` 默认 8192，范围 128..16 MiB；作用于 HTTP/1.1 请求头解析和 HTTP/2 `SETTINGS_MAX_HEADER_LIST_SIZE`，HTTP/3 不受控（与 Xray `http3.Server` 不使用该字段一致）。
- 会话在关闭、超时、客户端 RST 或服务端 stop 时释放；泄漏会计入 `xhttp_sessions` 计量。
- stop 后拒绝新会话准入，已有会话在 `shutdown_timeout_ms` 内排空；期限到或 force 后取消。

## 明确不支持

- 0-RTT、连接迁移调优与 Xray `quicParams` 的拥塞控制选项：不实现，使用 quinn 默认拥塞控制与固定上限。
- 同一入口同时监听 TCP（h1/h2）与 UDP（h3）：`h3: true` 时只监听 UDP。
- 任意 CDN 语义推导（例如依据 `X-Forwarded-*` 放宽认证或 TLS 事实）。
- VLESS Vision 与 XHTTP 组合；REALITY 与 XHTTP h1/h2 是上游支持的组合，本仓库已接入（h3 除外）。
- 跨承载的会话续接、跨进程会话共享。
- `xPaddingMethod: "tokenish"`；`scStreamUpServerSecs` 的 stream-up 定时响应体保活填充；`downloadSettings` 的独立下行连接；`xmux` 客户端连接复用；`h2Params` 的 HTTP/2 参数覆盖；`sessionIDTable`/`sessionIDLength`/`uplinkChunkSize`/`noGRPCHeader`/`scMinPostsIntervalMs` 等客户端生成/节奏参数；`uplinkHTTPMethod` 尚不支持任意方法（服务端只接受 POST/GET）。
- 已执行 Xray v26.10.31 的有限官方组合；新承接的 `extra` 字段仅做本地解析与本地入站运行验证，未与官方 Xray 对应配置做端到端互通；sing-box、完整 XHTTP 设置/CDN 会话放置、三平台、MSRV 与 release 未验收，不得把本地回环或 HTTP 200 当作完整兼容。

## HTTP/3（QUIC）承载

- 依赖为固定版本 `h3 =0.0.8` 与 `h3-quinn =0.0.10`，源码随 `vendor/h3`、`vendor/h3-quinn`、`vendor/h3-datagram` 固定（MIT），经 `[patch.crates-io]` 引入；`quinn` 复用既有 `=0.11.11`。
- 服务端为每个 QUIC 连接建立独立 `h3::server::Connection`；每个 HTTP/3 请求流复用与 h1/h2 相同的会话表、模式判定与认证分派。
- `stream-one`：单个 POST 的请求体是内层字节流，响应体直接承载下行；`stream-up`/`packet-up` 的 GET 下行由独立发送任务写入，POST 上行按会话汇入同一 lane。
- 固定上限：64 条并发双向流、8 条单向流（h3 控制流）、30 秒连接空闲超时；握手超时与关闭排空复用 `limits.handshake_timeout_ms` 与 `limits.shutdown_timeout_ms`，连接数与握手上限分别复用 `limits.max_connections` 与 `limits.max_handshakes`。
- 已编译并通过 2 项本机回环测试：`h3_stream_one_relays_tcp`（stream-one 经 QUIC/HTTP3 转发 TCP）与 `h3_packet_up_posts_feed_a_get_downlink`（packet-up 上行 POST 与下行 GET）。测试使用 quinn/h3 客户端与临时自签证书，覆盖 ALPN `h3`、请求伪头与响应体读写。官方 Xray/sing-box HTTP/3 客户端互通、三平台与 MSRV 验收未执行。依赖来源、许可与固定提交见[依赖门禁](xhttp-h3-dependency-gate.md)。

## 出站承载

`vless`/`vmess`/`trojan` 出站的 `transport` 可使用 `{"type":"xhttp",...}`，复用同一套请求形状：

- `http_version`: `"1.1"`、`"2"`（默认，明文为 h2c）或 `"3"`；HTTP/3 必须配置真实 TLS，并使用专用 QUIC 连接。
- `mode`: `auto`、`stream-one`、`stream-up`、`packet-up`。HTTP/1.1 的 `stream-up`/`packet-up` 通过独立的上行与下行连接实现（连接工厂必须保留同一 via/TLS 链）；没有工厂时显式拒绝，绝不改为直连。
- `headers` 是请求附加头，不能覆盖 `Host`/`Content-Length`/`Transfer-Encoding`/`Connection`/会话与 padding 头；`x_padding` 与 `max_post_bytes` 有界。
- H1 分离模式需要重新打开同一 via 链上的连接，使用逐跳连接工厂；没有工厂时显式拒绝，绝不改为直连。
- stream-up 使用一个持续 POST；POST 正常 EOF 触发上传半关闭，GET 下行继续，不把 POST EOF 当作整个隧道结束。packet-up 的单块仍受 `max_post_bytes` 限制。客户端只把收到并验证过的响应头部视为成功；不把 chunk 提交当作传输层 flush 成功。

与服务端相同，出站不实现 0-RTT、跨承载会话续接或任意 CDN 语义推导。H3 客户端与服务端共用 vendored h3/h3-quinn；Xray/sing-box 官方客户端互通、三平台、MSRV 与 release 仍未验收。

## 证据

Xray v26.10.31 的 VLESS/XHTTP TLS `stream-up` 已在 macOS ARM64 强制使用 HTTP/1.1 验证：同一条隧道在服务端握手期限前后各完成一次回显。相关本机回归还验证了 GET/POST 归还握手名额、中继空闲结束后归还会话槽，以及上传正常 EOF 后仍可接收下行。

本地测试覆盖 packet-up、stream-one、stream-up、乱序、会话隔离与重复序号、413、会话上限、TTL 过期、h2c、真实 TLS h2、自定义头与 Cookie、三协议承载及非法路径/超限 padding。测试入口 `tests/xhttp.rs`，其中 `extra` 兼容覆盖：支持字段映射（整数与 `"from-to"` 两种 Xray 形状）、顶层/`extra` 冲突拒绝、15 个仍不支持字段的显式拒绝、未知键拒绝、非法范围/资源上限、`tokenish` 值拒绝，以及运行中实际生效项：`scMaxEachPostBytes`/`noSSEHeader`、混淆 padding（header 放置的请求校验与响应回送）、header 放置的会话/序号、header 放置的 packet-up 上行数据、`serverMaxHeaderBytes` 的 HTTP/1.1 请求头上限。`tests/xhttp_outbound_client.rs` 6 项本机回环通过（H1 split、stream-up EOF、H2/H3 跨窗口、取消与 reset）。已与官方 Xray v26.10.31 完成 TLS 下四种模式与 REALITY-over-XHTTP 的双向本机互通；新增 `extra` 字段未用官方 Xray 配置样本做端到端互通；sing-box、Linux x86_64/Windows、可发布 release 仍未验收，不能据此宣称完整外部互通。
