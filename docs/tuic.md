# TUIC v5 入站与出站

出站状态：**TCP 与 UDP 出站已实现待集中验收**（TCP共享QUIC连接、标准exporter认证；UDP每关联独立连接，native DATAGRAM或quic逐消息单向流）。官方 sing-box v1.14.4 客户端的 native 与 quic 两种 UDP relay mode 已完成到本内核入站的 TCP/UDP 本机互通。出站`tuic.congestion_control`已接真实cubic/new_reno/bbr，`tuic.zero_rtt_handshake`默认false；显式开启后用票据真实尝试早期Connect元数据/Heartbeat，业务仍等完整握手及Authenticate写入，不自动重放。开发证据见[记录](tuic-outbound-modern-development.md)。

0-RTT 验证边界（2026-11-13）：**本内核服务端与内核出站/quinn 客户端已真实观察到 0-RTT 并被服务端 debug 事件记录；官方 sing-box v1.14.4 客户端未能进入 0-RTT 路径**。官方客户端即使配置 `zero_rtt_handshake: true`，其标准 TLS 客户端未设置 `ClientSessionCache`，Go QUIC 的会话票据存储因此为空，无法恢复会话；UDP 抓包（5 条独立 QUIC 连接、同进程内强制重连）未见任何 QUIC 0-RTT 长首部包。该结论只说明官方客户端当前版本无法用于 0-RTT 验证，不代表本内核拒绝 0-RTT。详见第 9 节。

本文描述本仓库新增的 TUIC v5 服务端实现（`src/transport/tuic.rs`、`src/transport/tuic/wire.rs`）的线格式、资源上限与兼容边界。

线格式依据本地只读上游：

- `github.com/sagernet/sing-quic@v0.7.2-0.20261020082049-7e0a5869a5f4/tuic/{protocol.go,service.go,service_packet.go,packet.go,address.go}`
- `github.com/sagernet/sing-box@v1.14.4/protocol/tuic/inbound.go`、`option/tuic.go`

实现为独立编写，仅复现协议行为，未翻译或复制 GPL-3.0 上游代码。

## 1. 传输与 ALPN

| 项目 | 值 |
| --- | --- |
| 传输 | QUIC v1（RFC 9000/9001），由 quinn 提供 |
| TLS | TLS 1.3；证书/私钥复用 `src/tls.rs::load` |
| 默认 ALPN | 空（不协商 ALPN） |
| 可配置 ALPN | 非空时写入 `rustls::ServerConfig::alpn_protocols`，必须与客户端一致 |
| QUIC 数据报 | 启用（`datagram_receive_buffer_size` 非 0） |
| 0-RTT | 可配置（`zero_rtt_handshake`，默认关闭；开启依赖 rustls 有状态票据单次消费；成功认证且观察到早期流时输出 debug 事件 `tuic_0rtt_accepted`） |
| 拥塞控制 | `congestion_control`: `cubic`（默认）/`new_reno`/`bbr`，由 quinn 真实控制器执行 |

本入口保留不协商 ALPN 的客户端兼容性。与 sing-box 1.14.4 或 mihomo v1.19.34 联调时，若客户端发送 `h3`，在 dubhe 入站显式设置 `"alpn":["h3"]`，客户端也选择 `h3`。只要有一方要求 ALPN 而找不到共同值，QUIC 握手就会失败，尚未进入 TUIC 密码认证。因此：

- 未配置 `alpn`：客户端也不得发送 ALPN；
- 配置了 `alpn`：客户端必须发送其中至少一个值。

## 2. 命令字

所有多字节整数均为大端。每条流与每个数据报的前两字节为：

```
版本 u8 (=5) | 命令 u8
```

| 命令 | 值 | 载体 | 服务端行为 |
| --- | --- | --- | --- |
| Authenticate | 0 | 客户端发起单向流 | 校验 UUID + token，成功后解除认证等待 |
| Connect | 1 | 客户端发起双向流 | 读取目标地址，拨号并双向中继 |
| Packet | 2 | 数据报或客户端发起单向流 | UDP 消息 |
| Dissociate | 3 | 客户端发起单向流 | 关闭指定 `session_id` 的 UDP 会话 |
| Heartbeat | 4 | 数据报 | 忽略（仅保活） |

服务端不会主动发送 Authenticate/Connect/Packet/Dissociate 命令；服务端主动发送的单向流只用于 UDP 回包（Packet），数据报只用于 UDP 回包与 Heartbeat。

## 3. 认证

客户端打开一条单向流，载荷恰为 50 字节：

```
版本 u8 (=5) | 命令 u8 (=0) | UUID[16] | token[32]
```

- UUID 为配置中用户 UUID 的原始 16 字节（非文本形式）。
- token 由 TLS exporter 派生：

  ```text
  token = TLS-Exporter(label = UUID[16], context = password UTF-8 字节, 长度 = 32)
  ```

  与 Go 侧 `tls.ConnectionState.ExportKeyingMaterial(string(uuid[:]), []byte(password), 32)`
  等价；本实现调用 `quinn::Connection::export_keying_material`。
- 服务端遍历全部用户做常量时间 UUID 比较，命中后用该用户密码派生 token，并以常量时间比较。
- 只允许一次认证帧；第二次认证、未知 UUID、token 不匹配、超过认证超时（默认 3 秒）
  都会立即以错误码 `0`、空原因关闭整条 QUIC 连接。
- 认证失败不返回任何区分性信息；日志不记录 UUID、password 或 token。

## 4. TCP 中继

客户端为每个 TCP 连接打开一条双向流：

```
版本 u8 (=5) | 命令 u8 (=1) | 目标地址 | 应用字节流
```

- 服务端读取 2 字节命令头与目标地址，等待认证完成后调用 `ctx.connect`
  （包含路由允许检查、端口检查、DNS 与拨号超时）。
- 目标地址按第 5 节的地址格式编码；`Empty` 地址与端口 0 被拒绝。
- 后续双向字节流由 `forward::relay` 中继，计入 `tcp_flows`、`uplink`、`downlink`。
- 单条双向流的错误只重置该流（`STOP_SENDING` / `RESET_STREAM` 错误码 0），不影响同连接的其他流；这是与上游一致的行为。
- 认证前的双向流最多等待认证超时；认证超时后连接整体关闭。

## 5. 地址格式

TUIC 使用自己的地址族字节，**不是 SOCKS5 的 1/4/3**：

| 族字节 | 含义 | 后续字节 |
| --- | --- | --- |
| `0x00` | FQDN | 长度 u8（1..=255）、域名字节、端口 u16 |
| `0x01` | IPv4 | 4 字节地址、端口 u16 |
| `0x02` | IPv6 | 16 字节地址、端口 u16 |
| `0xff` | Empty | 无（仅用于非首分片的 UDP 消息） |

- 端口紧跟地址之后，大端。
- 域名必须非空且全部为 ASCII 可打印字符；服务端统一转为小写后交给路由/DNS。
- 最大地址编码长度为 `1 + 1 + 255 + 2 = 259` 字节。

## 6. UDP 消息

### 6.1 消息体

```
session_id u16 | packet_id u16 | fragment_total u8 | fragment_id u8 |
data_len u16 | 地址 | 数据（data_len 字节）
```

- `session_id` 由客户端分配，服务端按连接隔离。
- `packet_id` 用于分片重组；同一原始消息的所有分片共享同一个值。
- `fragment_total == 1` 表示未分片；服务端实现为 fail-closed，拒绝 `fragment_total == 0`。
- 分片时首片（`fragment_id == 0`）携带真实目标地址，其余分片地址字段为 `0xff`（Empty）。
- `data_len` 是当前分片的数据长度，最大 65535。

### 6.2 数据报承载（native 模式）

一个 QUIC 数据报就是一条完整的 TUIC 帧：

```
版本(5) | Packet(2) | 消息体
```

服务端回包超过当前协商 MTU 时会自行分片：按首片头部长度计算块大小，使用同一 `packet_id` 连续发送，最多 64 片。若对端未协商 QUIC 数据报，则回包被丢弃。

### 6.3 单向流承载（quic 模式）

每条 UDP 消息使用一条新的客户端单向流，内容为：

```
版本(5) | Packet(2) | 消息体
```

服务端回包同样为每条消息打开一条新的服务端单向流。`udp_relay_mode: "quic"` 的 sing-box 客户端使用该模式。

### 6.4 会话生命周期

- 首次收到某 `session_id` 的消息时创建会话；承载模式（数据报/单向流）由首条消息决定，回包沿用该模式。
- 服务端为每个会话维护 IPv4/IPv6 两个按需创建的无连接 UDP 套接字；回包目标地址取自 `recv_from` 的源地址。
- `Dissociate` 单向流（`版本 | 3 | session_id u16`）立即关闭对应会话。
- 会话空闲超过 `udp_idle_timeout`（默认 60 秒），或连接关闭，会话及其套接字被回收。
- 每个连接最多 `max_udp_sessions` 个会话；每个会话最多 `max_udp_targets` 个已解析目标。

### 6.5 分片重组

- 每组最多 `MAX_FRAGMENTS = 64` 片。
- 每会话最多 16 个并行重组组、总计 128 KiB 分片数据。
- 重组完成后的消息最多 65535 字节，并再次受 `max_udp_payload` 限制。
- 重复分片、编号越界、总数变化、超时（10 秒）均丢弃；超界会清空对应组。

## 7. 心跳与空闲

- 认证成功后，服务端默认每 10 秒发送数据报 `[0x05, 0x04]`。
- 客户端发来的同格式数据报被忽略（仅作为保活流量）。
- 认证后收到未知命令、非法版本或长度不匹配的数据报会关闭连接。
- QUIC 传输层 `max_idle_timeout` 默认 30 秒；心跳使其在活跃连接上不会触发。
- 认证超时默认 3 秒（对应 sing-box `auth_timeout`）。

## 8. 资源上限

| 项目 | 默认值 | 说明 |
| --- | --- | --- |
| QUIC 连接数 | `limits.max_connections` | 超出直接拒绝并计入 `rejected` |
| 同时握手中数 | `limits.max_handshakes` | 认证完成/失败/超时后释放 |
| 并发双向流 | 512 | `max_concurrent_bidi_streams` |
| 并发单向流 | 512 | `max_concurrent_uni_streams` |
| 每流接收窗口 | 64 KiB | `stream_receive_window` |
| 连接接收窗口 | 4 MiB | `receive_window`，限制单连接总缓冲 |
| 数据报接收缓冲 | 1 MiB | 未认证期间数据报在此排队 |
| 数据报发送缓冲 | 1 MiB | |
| 流首部读取超时 | 10 秒 | 防止慢速流长期占用任务 |
| QUIC 写超时 | 5 秒 | 单向流打开/写入、数据报发送 |
| UDP 会话上限 | `limits.max_udp_associations` | 全局信号量 |
| 每会话目标上限 | `limits.max_udp_targets` | 解析结果缓存上限 |
| 每会话上行队列 | 32 包 | 满时丢包 |
| UDP 队列字节预算 | `limits.udp_queue_bytes` | 与仓库其他 UDP 入口共享 |
| UDP 载荷上限 | `limits.max_udp_payload` | 默认 65507 |

连接关闭时：先取消连接令牌、关闭 QUIC 连接，再中止所有流任务与 UDP 会话任务，
并以 2 秒为硬上限等待任务退出。所有任务均由连接生命周期持有，不跨连接泄漏。

## 9. 与 sing-box 的兼容边界

已确认兼容：

- `udp_relay_mode: "native"`（QUIC 数据报）；
- `udp_relay_mode: "quic"`（单向流，每条消息一条流）；
- `CommandDissociate`；
- 默认无 ALPN 的握手；
- 多用户 UUID/password 认证；
- 默认心跳与认证超时语义。

兼容边界（含明确不支持项）：

- **0-RTT 默认关闭**：`zero_rtt_handshake: true` 时服务端设置
  `max_early_data_size = u32::MAX`，并要求 rustls 有状态会话票据；认证仍在完整
  握手后以 exporter token 完成。出站在`tuic.zero_rtt_handshake:true`时真实尝试early路径，只提前Connect元数据/Heartbeat；无票据完整握手，明确拒绝仅重建元数据流一次，不自动重放业务。0-RTT天生可重放，元数据仍可能有连接副作用，部署方必须接受该风险；不承诺0-RTT业务收益。
- **服务端 0-RTT 接受路径与证据**：开启后服务端通过 quinn 的服务端
  `Connecting::into_0rtt()` 提前取得 0.5-RTT 连接句柄，使流接收循环能在完整
  握手前接受早期流，并用 `RecvStream::is_0rtt()` 标记。认证流即使走 0-RTT，
  也先读帧、等完整握手后再调用 TLS exporter 校验 token；认证超时从握手完成后
  开始，握手本身由独立超时看门狗约束。认证成功后，若本连接至少有一条流在握手
  完成前被 quinn 标记为 0-RTT，服务端输出：
  `DEBUG event="tuic_0rtt_accepted" tag=<入口tag>`。该事件不包含 UUID、
  password、token 或密钥；默认 INFO 过滤下不输出，只有显式把服务端日志级别调到
  DEBUG 才可见。事件是保守的：握手完成后才交给应用的早期流会被 quinn 标为
  非 0-RTT，因而可能漏报；反过来，被标记的流只可能来自握手期，正常不会误报。
  0-RTT DATAGRAM（例如仅提前 Heartbeat 的 UDP 关联）没有等价的 quinn 标记，
  不在该事件的证据范围内。
- **官方 sing-box v1.14.4 客户端 0-RTT 阻塞点**：已用固定官方二进制、
  `zero_rtt_handshake: true`、服务端 `zero_rtt_handshake: true` 验证 native
  模式的 TCP/UDP；quic 模式沿用既有互通配置，且与 native 共用同一 TLS 会话层。
  同进程内通过服务端 800 ms
  `idle_timeout_ms` 强制断开并重连，先后出现 5 条独立 QUIC 连接；在客户端与
  服务端之间加入只读 UDP 探针后统计到 15 个 Initial 包、0 个 QUIC 0-RTT 包，
  重连仍走完整握手。原因在客户端侧：sing-box 的 `STDClientConfig` 未设置
  `tls.Config.ClientSessionCache`，而 Go QUIC 的 `QUICConn.StoreSession` 在
  缓存为空时不保存票据，下一次 `DialEarly` 因而没有 PSK/早期数据。使用 uTLS
  的 QUIC 路径也明确禁用会话恢复。因此**不得把官方 sing-box 客户端写成 0-RTT
  通过**；本仓库没有为此修改 vendor 或依赖。
- **本内核/quinn 客户端的 0-RTT 证据**：`tests/tuic.rs` 的
  `zero_rtt_reconnect_is_observed_on_the_server_and_relays_tcp` 在同一测试进程内
  先用完整握手取得票据，再用 quinn `into_0rtt()` 建立第二条连接，在 0-RTT 中
  发送 Connect 元数据，握手完成后发送 Authenticate，经服务端转发到回环 TCP 并
  收到回显；测试捕获到服务端 `tuic_0rtt_accepted` 事件，且断言日志不含
  UUID/password/token。内核出站自身也已有真实 QUIC 0-RTT 断言
  （`tuic_client` 单元测试中的 `attempted_early`/`accepted_early`），但该客户端
  同样把业务与认证安排在完整握手之后，只提前 Connect 元数据/Heartbeat。
- **`udp_over_stream`（UoT over TCP）**：这是 sing-box 的旧式 UDP-over-TCP 封装，
  不是 TUIC 的单向流模式。服务端不实现 UoT，客户端请使用
  `udp_relay_mode: native|quic`。
- **拥塞控制**：`congestion_control` 支持 `cubic`（默认）、`new_reno` 与 `bbr`；
  出站通过`tuic.congestion_control`使用相同真实工厂；未知值在配置/启动阶段拒绝，不静默回退。不改变TUIC wire；不宣称与另一QUIC库的同名算法各代实现性能完全一致。
- **QUIC 连接迁移/路径管理**：使用 quinn 默认行为，未做 TUIC 上游
  `DisablePathManager` 的等价定制，也未专门测试客户端地址迁移。
- **服务端 0.5-RTT 数据**：为在握手完成前接受 0-RTT 流会调用服务端
  `Connecting::into_0rtt()` 取连接句柄，但不会在握手完成前发送任何 TUIC 响应；
  认证 exporter、Connect 拨号与 UDP 转发仍只在完整握手和认证成功后发生。
- **认证错误细节**：不返回 UUID 是否存在等信息。

## 10. 测试

`tests/tuic.rs` 通过 `#[path]` 直接编译纯线格式模块，并用文件内独立参考编码器
（不调用被测编码函数）构造期望字节，覆盖：

- 认证帧编解码与版本/命令/长度拒绝；
- 命令头解析；
- IPv4/IPv6/FQDN/Empty 地址编码与越界/非法输入拒绝；
- UDP 消息与数据报布局、长度精确性、分片字段与 65535 上限拒绝；
- 未知 UUID 与 token 比较拒绝。

另有 4 项端到端回环测试（`tests/tuic.rs`）启动真实服务端，用 quinn 客户端
（TLS 1.3、无 ALPN）执行：

- TLS exporter token 认证后打开双向流，经 CONNECT 转发到回环 TCP echo；
- 认证后发送 UDP DATAGRAM，经服务端转发到回环 UDP echo 并收回载荷；
- 错误密码时连接被关闭；
- 完整握手取得票据后，用 `into_0rtt()` 重连，在 0-RTT 中发送 Connect 元数据、
  握手后认证并取回 TCP 回显；测试在进程内以 DEBUG 捕获
  `tuic_0rtt_accepted`，并断言日志不含凭据。该测试连续运行 10 次均通过。

定向验证命令（未运行全量测试）：

```text
cargo test --locked --test tuic
cargo test --locked --lib tuic
cargo test --locked --test tuic_outbound_modern
```

结果分别为 23/23、19/19、3/3 通过。这些测试使用临时自签证书，只证明本机协议
路径；另已用固定 Mihomo v1.19.33 客户端（`udp-relay-mode=native`）与官方
sing-box v1.14.4 客户端完成到本内核入站的 TCP/UDP 本机互通。官方 sing-box
的 0-RTT 重连未通过，原因是第 9 节所述的客户端会话缓存缺失；官方客户端全矩阵、
三平台、MSRV 与 release 验收仍未执行。

## 11. 集成点

运行器需要：

1. 在 `Inbound` 枚举新增 `Tuic` 变体，包含 `tag`、`listen`、`users`、
   `certificate`、`private_key`，可选 `alpn`、`auth_timeout`、`heartbeat`、
   `idle_timeout`、`max_streams`。
2. 在绑定阶段为 TUIC 入口创建 UDP 套接字（而不是 TCP 监听），并调用
   `tuic::prepare(options, tls::load(...)?)`。
3. 把 UDP 套接字以 `into_std()` 交给 `tuic::serve(...)`，由 `run` 的 `JoinSet`
   管理其生命周期。

具体片段见交付报告。
