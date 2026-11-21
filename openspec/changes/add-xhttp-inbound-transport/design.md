## Context

现有 WS 入口已有严格 HTTP/1.1 请求解析（httparse + 自有 CRLF/头数/长度门禁）与 TLS/明文监听分支；gRPC 入口已有 h2 驱动、绝对期限、每 RPC 许可与共享 lease。XHTTP 需要在这两套成熟接点上增加 HTTP 语义，而不复制协议、DNS、路由或 UDP 内核。

## Goals / Non-Goals

**Goals**

- 增量接入三协议 XHTTP 入站，默认路径元数据与上游默认一致。
- h1 与 h2 共享同一会话/队列/下行模型；明文与 TLS 只在建流层区分。
- 所有缓冲、会话、请求尺寸与任务回收有界，并可被停止流程排空。

**Non-Goals**

- HTTP/3、QUIC、XMUX、fallback、代理出站与客户端配置生成。
- 通用 HTTP 服务器语义（静态文件、压缩、keep-alive 多路复用抽象）。

## Decisions

### D1：三个独立入口，配置严格

新增 `vless-xhttp`/`vmess-xhttp`/`trojan-xhttp`，`xhttp` 配置对象含：`path`（必填）、`host`、`mode`（auto/stream-one/stream-up/packet-up）、`headers`、`no_sse_header`、`sc_max_each_post_bytes`（默认 1MiB）、`sc_max_buffered_posts`（默认 30）、`session_ttl_ms`（默认 30000）、`x_padding`（默认 100..1000）。不复用 `websocket`/`grpc` 对象，避免未实现字段被静默接受。

### D2：会话模型与上行队列

会话键为任意非空 ASCII session id（默认从路径提取，也接受 query/header）。服务端以 `Sessions: Mutex<HashMap<String, Arc<Session>>>` 管理：

- `Session` 持有 `UploadQueue`、`done` 标志与下行广播通道。
- packet-up 的 `(seq, payload)` 进入有界 `BTreeMap`，按序交付；缓冲满或重复序号即失败关闭。
- stream-up 直接以一个长 body reader 作为上行。
- stream-one 使用同一 HTTP body 作为上行、同一响应体作为下行。
- 无下行连接时 30 秒 TTL 回收；建立下行后生命周期由该请求决定。

### D3：HTTP/1.1 与 h2 共用业务接点

h1 用 httparse 解析请求头，按 `Content-Length`/`chunked` 读取 body；h2 用既有 `h2` crate 提供 `RecvStream`/`SendStream`。两者都归一为：

```text
RequestMeta { method, path_suffix, session, seq, headers, length }
Body: AsyncRead
Responder: AsyncWrite + flush
```

业务层只看到 `AsyncRead + AsyncWrite` 的桥接流，直接调用既有 `vless`/`vmess`/`trojan` 与 `runtime` 服务函数。

### D4：下行与半关闭

GET 下行先写 200 与流式头（默认 `text/event-stream`、`X-Accel-Buffering: no`、`Cache-Control: no-store`），随后逐块写出并 flush。上行结束只表示上行字节 EOF，不强制结束下行；下行结束则关闭会话与上行 reader。h1 chunked 与 h2 DATA 都由各自的写出器处理。

### D5：期限、限额与回收

- TLS/preface/首个完整请求头共享 `handshake_timeout_ms`。
- 单请求体上限 `sc_max_each_post_bytes`；超过返回 413 且不建立会话。
- 每会话占用一个 `max_grpc_streams` 等价的 XHTTP 会话名额（新增独立 `max_xhttp_sessions` 默认 256，可复用全局 UDP/RPC 计量语义，不重复计 TCP）。
- 取消/停止时先禁止新会话，等待下行与上行任务 join；共享 `Lease` 保证任务真正结束前不归还名额。

### D6：不引入新依赖

HTTP/1.1 复用 httparse；HTTP/2 复用 h2；TLS 复用 rustls；protobuf 不涉及。XHTTP/3 留待 QUIC 批次，依赖门禁通过前不写 Cargo。

## Risks / Trade-offs

- [客户端变体多] → 以 Xray v26.10.31 服务端默认与固定客户端早前核实的请求形状为准，未核实的 placement/obfs 组合显式拒绝。
- [h1/h2 会话键不一致] → 统一由 `RequestMeta` 归一，禁止各分支自行拼接路径。
- [下行长连接拖慢停机] → 停止时先关闭 session 的 done，再限时等待；到期强制取消并回收。
- [HTTP 响应头被误当成功] → 文档与测试明确 HTTP 200 不代表代理认证或业务成功。

## Migration Plan

纯增量：无配置迁移。旧入口不变；若发布后需回退，删除新入口即可，不影响既有监听。

## Open Questions

- XHTTP 的 header/cookie placement 是否在本批全部实现，还是先实现路径默认并在文档中列出未支持项：按“先实现、后统一收敛”的总节奏，本批实现 auto/header/cookie/query 解析，但仅在回环测试覆盖路径与 query；官方客户端矩阵后置。
