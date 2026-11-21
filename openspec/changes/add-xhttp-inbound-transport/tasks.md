## 1. 来源核对与依赖边界

- [ ] 1.1 固定 Xray v26.10.31 `transport/internet/splithttp` 服务端请求形状、默认值与模式语义，记录 commit/path/关键行为；不运行官方客户端、不下载源码树。
- [ ] 1.2 复核 HTTP/1.1 解析复用现有 httparse 与 WS 严格门禁、h2 复用现有依赖，确认无新增 normal/build 依赖、无锁变更、两个冻结 vendor 不动。

## 2. 严格配置与入口

- [x] 2.1 新增 `xhttp` 配置类型（path/host/mode/headers/no_sse_header/sc_max_each_post_bytes/sc_max_buffered_posts/session_ttl_ms/x_padding）及三入口解析，未知字段、非法 mode、空路径与越界数值拒绝；`xhttp.headers` 响应头扩展已实现并在回环测试中覆盖。
- [x] 2.2 落实 TLS/明文策略：VMess 必须真实 TLS；VLESS/Trojan 明文必须显式 `allow_insecure_transport`；TLS 同时提供 h2 与 http/1.1 ALPN。
- [x] 2.3 增加 `limits.max_xhttp_sessions` 默认 256 与每会话计量；旧 Limits 缺省与 JSON 往返不破坏。

## 3. HTTP 请求层

- [x] 3.1 实现 h1 请求行/头/长度的严格解析与最小拒绝路径（方法、Host、路径前缀、重复关键头、请求头总长 8192）。
- [x] 3.2 实现 body 读取：Content-Length、chunked、无 body；超过 `sc_max_each_post_bytes` 返回 413 且零拨号。
- [x] 3.3 实现 h2 请求接点（preface/headers/body/响应流）与 h2c prior-knowledge、TLS ALPN h2 选择。
- [x] 3.4 实现路径/query/header/cookie 的 session 与 seq 提取及默认 `x_padding`（query 或 Referer）长度校验。

## 4. 会话、模式与下行

- [x] 4.1 实现会话表与 TTL：默认 30 秒无下行回收、同一 session 复用、并发上限与 gauge。
- [x] 4.2 实现 packet-up 有序队列：seq 0 起始、乱序缓冲上限 30、重复/超界失败关闭、错误不影响其他会话。
- [x] 4.3 实现 stream-up：单长 POST 上行 + GET 下行，上行 EOF 不强制结束下行。
- [x] 4.4 实现 stream-one：单 POST 双向桥接与响应 flush。
- [x] 4.5 实现下行响应头与流式写出（默认 `text/event-stream`、`X-Accel-Buffering: no`、`Cache-Control: no-store`、可关闭 SSE 头）。

## 5. 三协议复用

- [x] 5.1 将 `vless-xhttp` 接入无 flow 认证、TCP、原生 UDP、显式 XUDP，复用既有服务函数与 XUDP 延迟应答。
- [x] 5.2 将 `vmess-xhttp` 接入 AEAD 认证、security 3/4/策略 5、TCP/原生 UDP/XUDP/packetaddr，复用既有预备池。
- [x] 5.3 将 `trojan-xhttp` 接入多用户摘要、TCP 与逐包 UDP，旧 `trojan` 必填 TLS 不变。

## 6. 资源、期限与停止

- [ ] 6.1 首个完整请求、TLS 与认证共享绝对期限；慢头、半请求与无 GET 会话均在期限回收。
- [ ] 6.2 停止流程禁止新会话、关闭 done、限时排空上下行与业务任务，join 后才归还会话/全局许可。
- [ ] 6.3 每会话共享 lease 覆盖 reader/mapping，异常断开不提前释放名额与 gauge。

## 7. 测试与示例

- [x] 7.1 h1 回环：三协议 TCP、packet-up 乱序、stream-up、stream-one、多会话隔离。
- [ ] 7.2 h2/h2c 回环：与 h1 相同的核心场景及 ALPN 负向。
- [ ] 7.3 负向：错误路径/Host/方法、非法填充、重复 seq、超限 body、无 GET 过期、坏认证零拨号。
- [ ] 7.4 资源：会话上限、请求 1MiB 边界、停止排空、RST/断开回收与 gauge 归零。
- [ ] 7.5 新增六份占位模板并做替换后 check；文档写明模式、路径、limits、半关闭与 HTTP 200 非成功。

## 8. 开发综合门禁

- [ ] 8.1 同一输入执行相关全量回归、fmt、locked all-targets check 与严格 Clippy，保存真实退出码与通过/忽略计数。
- [ ] 8.2 将第 1–7 组行为映射真实证据并核 OpenSpec strict；仅开发全部通过才标“已实现待集中验收”。

## 9. 后置集中验收（需另行授权）

- [ ] 9.1 固定客户端 XHTTP 明文/TLS、h1/h2、三种模式与负向矩阵。
- [ ] 9.2 三平台、精确 MSRV、release 与最终报告。
