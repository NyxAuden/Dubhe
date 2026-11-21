## Purpose

为 VLESS、VMess 与 Trojan 提供 XHTTP 入站：在 HTTP/1.1 或 HTTP/2 请求中承载代理字节流，支持 stream-one、stream-up、packet-up 三种模式及 downlink GET 流，同时保持现有认证、路由、UDP 与资源回收语义。

## ADDED Requirements

### Requirement: 配置与入口

系统 SHALL 提供独立入口 `vless-xhttp`、`vmess-xhttp`、`trojan-xhttp`，每个入口 MUST 配置非空 `xhttp.path`；未知字段、非法模式与缺失 TLS 凭据 MUST 在 check/run 前拒绝。VMess XHTTP MUST 使用真实 TLS；VLESS/Trojan 明文入口 MUST 显式配置 `allow_insecure_transport: true`。旧 `vless`/`vmess`/`trojan`/WS/gRPC 入口行为 MUST 保持不变。

#### Scenario: 严格配置
- **WHEN** 配置含未知 `xhttp` 字段、空路径、非法 mode，或 VMess XHTTP 无证书
- **THEN** 配置检查失败，不监听端口且不泄露凭据

#### Scenario: 明文策略
- **WHEN** VLESS/Trojan XHTTP 未提供证书且未显式允许明文
- **THEN** 配置被拒绝；显式允许后只接受 HTTP/1.1 或 h2c prior-knowledge

### Requirement: 请求准入与元数据提取

服务端 SHALL 只接受配置路径前缀下的 HTTP/1.1 或 HTTP/2 请求，并 MUST 从路径、query 或 header/cookie 提取 `session` 与 `seq`。默认路径形式 MUST 为 `<path>/<session>/<seq>`（stream-up 为 `<path>/<session>`，stream-one 为 `<path>`）。Host 配置存在时 MUST 校验；方法 SHALL 允许 `GET`、`POST` 及配置的 uplink 方法。缺失、重复或长度超界的 session/seq MUST 被拒绝且不产生业务访问。

#### Scenario: 路径会话
- **WHEN** 客户端 POST `/<path>/<session>/0` 并携带合法填充
- **THEN** 服务端把该请求归入对应 session 的上行队列

#### Scenario: Host 与路径不符
- **WHEN** 请求 Host 与配置不符或路径不在配置前缀下
- **THEN** 返回 404，零业务访问

### Requirement: 填充校验

服务端 SHALL 接受默认 `x_padding`（query 或 `Referer` header）并 MUST 校验其长度落在配置范围（默认 100–1000 字节）；非法 base64url、超界长度或非预期位置 MUST 返回 400，且不得建立会话或读取业务。

#### Scenario: 合法与非法填充
- **WHEN** 客户端分别发送范围内的 x_padding 与超界值
- **THEN** 前者继续处理，后者返回 400 且不计业务字节

### Requirement: 三种上行模式

服务端 SHALL 支持 `auto`、`stream-one`、`stream-up`、`packet-up`。`stream-one` MUST 在单个 POST 上双向承载（请求体上行、响应流下行）；`stream-up` MUST 接受单个长 POST 为上行、GET 为下行；`packet-up` MUST 接受带 seq 的多个 POST 并按 seq 顺序交付上行，允许乱序到达但 MUST 在缓冲上限（默认 30）内等待缺失序号，超界或重复序号 MUST 失败关闭。服务端 SHALL 按配置 mode 拒绝不匹配的请求。

#### Scenario: packet-up 乱序
- **WHEN** seq=1 先到、seq=0 后到且缓冲未超限
- **THEN** 业务按 0、1 顺序收到字节

#### Scenario: stream-one 双向
- **WHEN** 客户端在单个 POST 上先发认证再读响应
- **THEN** 服务端在同一响应流返回业务数据

### Requirement: Downlink 流

服务端 SHALL 在 GET（或 stream-one 的 POST）响应中以流式字节返回下行，默认 `Content-Type: text/event-stream`、`X-Accel-Buffering: no`、`Cache-Control: no-store`，配置关闭 SSE 头时 MUST 使用非事件流类型但仍禁止缓冲。请求结束、客户端断开或会话关闭 SHALL 终止下行并回收会话。GET 到达前的会话 MUST 在默认 30 秒后回收。

#### Scenario: GET 建立下行
- **WHEN** 客户端先 POST 认证并保持，再发起同 session 的 GET
- **THEN** 服务端返回 200 并持续输出下行字节直到任一端结束

#### Scenario: 无 GET 会话过期
- **WHEN** 仅发送上行且 30 秒内未建立下行
- **THEN** 会话与缓冲被回收，后续旧 seq 不得命中新会话

### Requirement: 三协议业务复用

XHTTP 三层 MUST 复用既有 VLESS（无 flow、TCP/原生 UDP/显式 XUDP）、VMess（AEAD、security 3/4/策略 5、TCP/原生 UDP/XUDP/packetaddr）与 Trojan（多用户摘要、TCP/逐包 UDP）实现，不得复制认证、DNS、路由或 UDP 内核。认证失败、坏 session 与请求结束 MUST 只影响所属会话。

#### Scenario: 同承载多会话
- **WHEN** 同一连接建立两个不同 session 的 XHTTP 流
- **THEN** 两个业务互不干扰，各自独立结束

### Requirement: 资源与期限

每个 XHTTP 会话 MUST 占用一个全局 RPC/会话名额与下行计量；物理连接仍按 TCP 计一次。上行缓冲、每请求大小（默认 1MiB）与会话数 MUST 有界；取消或超时后任务 MUST 在归还名额前真实结束。TLS 握手、首个完整请求与认证 MUST 受绝对期限约束，不得逐层刷新。

#### Scenario: 超限请求
- **WHEN** 单个 POST 声明或实际载荷超过默认 1MiB
- **THEN** 返回 413，不拨号且不占用会话名额

### Requirement: 明确不支持

本能力 MUST NOT 声明支持 XHTTP over HTTP/3、XMUX 客户端复用策略、fallback 或 gRPC-Web 语义；这些组合 MUST 在文档中标为未实现，不得以 HTTP 200 或本地回环结果代替官方客户端兼容结论。

#### Scenario: 未实现组合
- **WHEN** 配置请求 HTTP/3 或 XMUX 服务端策略
- **THEN** 配置被拒绝或明确报告未实现
