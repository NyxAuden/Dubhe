# Hysteria2

出站状态：**TCP 与 UDP 出站已实现待集中验收**（QUIC + HTTP/3 认证 + 0x401 流，
TCP 共享连接；UDP 每条关联独立 QUIC 连接并使用 DATAGRAM 会话；支持 salamander/gecko obfs（已用官方 sing-box v1.14.4 客户端完成 TCP/UDP 本机互通）；
出站 `hysteria2.up_mbps/down_mbps` 已接入 `Hysteria-CC-RX` 协商和客户端 Brutal 发送控制）。
本机 TCP/UDP 回环、官方 sing-box v1.14.4 服务端本机互通，以及固定 Mihomo
v1.19.33 客户端到本内核入站的 TCP/UDP、官方 sing-box v1.14.4 客户端到本内核
入站的 TCP/UDP 本机互通均已通过；完整 Brutal pacing 仍未对齐，见下文。
 服务端

本文描述 `src/transport/hysteria2/` 的实现边界、已确认的线协议、资源上限，以及
与官方 Hysteria2 客户端 / sing-box 的兼容性。协议行为依据以下**只读**上游源码
独立实现，不复制其代码：

- `sing-quic@v0.7.2-0.20261020082049-7e0a5869a5f4/hysteria2`
  （`service.go`、`service_packet.go`、`packet.go`、`client.go`、
  `salamander.go`、`internal/protocol/*`）
- `sing-box@v1.14.4/protocol/hysteria2/`、`option/hysteria2.go`、
  `constant/hysteria2.go`

## 1. 能力总览

| 能力 | 状态 |
| --- | --- |
| QUIC 服务端、TLS 1.3 | 支持（quinn + rustls 0.23） |
| HTTP/3 密码认证 | 支持（h3 + h3-quinn） |
| TCP 代理流（0x401） | 支持 |
| UDP over QUIC DATAGRAM | 支持（含分片/重组） |
| salamander obfs | 支持 |
| gecko obfs（salamander 上叠加分片/填充） | 支持 |
| Brutal 拥塞控制 / 带宽锁定 | **部分对齐**：逐包 ACK 计数、ACK 回调读取 RTT、速率 0 委托 quinn Cubic 已与上游一致；独立 pacer 与逐包丢包仍受 quinn API 限制，见[对齐核查](hysteria2-brutal-alignment.md) |
| BBR profile 选择 | **不支持**（非 Brutal 时使用 quinn 默认拥塞控制） |
| masquerade | 支持 `string` / `file`；未认证请求返回伪装内容，`proxy` 类型不支持 |
| realm / 端口跳跃服务端 | **不需要**（端口跳跃是客户端行为） |
| 0-RTT | 不支持 |
| 多用户 | 支持（任一密码匹配即通过） |

## 2. TLS 与 QUIC

- **ALPN 必须为 `h3`**。sing-box 在未显式配置时设置
  `http3.NextProtoH3`（即 `"h3"`）；官方客户端同样使用 `h3`。
  `serve` 会校验 `rustls::ServerConfig::alpn_protocols` 含 `h3`，否则拒绝启动。
- QUIC 只使用 TLS 1.3（quinn 强制）。证书/私钥加载复用 `src/tls.rs::load`
  的 PEM 读取逻辑；入口侧需要在独占的 `Arc` 上设置 ALPN，见第 11 节。
- QUIC 参数（本实现）：

| 参数 | 值 | 说明 |
| --- | --- | --- |
| `max_concurrent_bidi_streams` | 512 | 有界；上游为 `1<<60` |
| `max_concurrent_uni_streams` | 16 | 仅认证阶段使用 |
| `datagram_receive_buffer_size` | 1 MiB | 有界 |
| `datagram_send_buffer_size` | 1 MiB | 有界 |
| `max_idle_timeout` | 配置值 | 默认建议 30 s |
| `keep_alive_interval` | 10 s | 与上游默认一致 |
| `initial_mtu` | 1200 | salamander 再加 8 字节，仍低于 1280 |
| 路径 MTU 发现 | 无 obfs 时启用；有 obfs 时关闭 | 避免 8 字节 salt 使报文超出路径 MTU |

- 认证 / QUIC 握手共用 `limits.handshake_timeout_ms`（默认 10 s）。
- 每入口接受连接数使用 `limits.max_connections` 作为信号量上限；超限的
  `Incoming` 直接 `ignore`，不派生任务。

## 3. HTTP/3 认证

客户端发送一次标准 HTTP/3 请求：

```text
POST https://hysteria/auth
Hysteria-Auth: <password>
Hysteria-CC-RX: <uint64>        # 客户端声明的接收带宽，0=未知
Hysteria-Padding: <随机填充>     # 客户端实现细节
```

服务端判定（与 `internal/protocol/http.go` + `serverSession.ServeHTTP` 对齐）：

1. `:method == POST`；
2. `:authority == "hysteria"`；
3. `:path == "/auth"`；
4. `Hysteria-Auth` 存在、非空，且与任一已配置用户密码匹配；
5. 成功时返回 HTTP 状态码 **233**（非标准状态码）；
6. 失败时返回 **404**（等价于上游默认 masquerade 的 `http.NotFoundHandler`）。

成功响应头：

```text
Hysteria-UDP: true|false
Hysteria-CC-RX: 0               # 固定 0，见第 8 节
Hysteria-Padding: <随机填充>     # 256..2047 字节，ASCII 字母数字
```

密码校验：对候选密码和每个已配置密码取 SHA-256，再用 `subtle` 做常量时间
比较，并对所有用户累加结果，不因命中顺序提前返回。允许 1..=4096 字节密码。

**认证后连接交接**：上游 sing-box 使用 quic-go `StreamDispatcher` 在 HTTP/3
解析之前截获首帧为 0x401 的双向流。`h3` crate 没有公开的流派发钩子，因此本实现
在认证响应 `finish()` 后丢弃 h3 连接，直接使用 `quinn::Connection::accept_bi()`
接收后续代理流。官方客户端在同一 QUIC 连接上只发一次认证请求，故该交接在正常
客户端上成立；如果客户端在认证后继续发送 HTTP/3 请求，本实现不会响应。

### 3.1 masquerade

未认证请求（路径不是 `/auth`、或密码不匹配）在配置 masquerade 时不再立即关闭
连接，而是用同一 HTTP/3 连接返回伪装响应：

```json
"masquerade": {"type": "string", "content": "<h1>not found</h1>", "status_code": 200}
"masquerade": {"type": "file", "directory": "/srv/www"}
```

`file` 模式把请求路径映射到目录内文件；路径为空或目录时使用 `index.html`，
拒绝包含 `..` 段或 NUL 的路径，单文件上限 4 MiB，缺失文件返回 404。请求体不
参与伪装处理。认证成功仍按原路径交接给原始 QUIC 流。

## 4. TCP 代理流

客户端打开一个**双向流**，首部格式：

```text
0x401                    QUIC varint 帧类型（编码为 0x44 0x01，共 2 字节）
地址长度                  QUIC varint，1..=2048
地址                      UTF-8 字符串，格式见下
填充长度                  QUIC varint，0..=4096
填充                      bytes，服务端只丢弃
载荷                      剩余全部字节
```

地址格式等价于 Go `net.JoinHostPort`：

- 域名/IPv4：`example.com:443`、`192.0.2.7:443`
- IPv6：`[2001:db8::1]:443`

服务端解析后调用 `Context::connect(tag, target)`，与其它入口共享路由、DNS、
拨号超时和统计。响应格式：

```text
状态(1)                  0=成功，1=失败
消息长度                 QUIC varint，0..=2048
消息                     UTF-8
填充长度                 QUIC varint，0..=4096
填充                     bytes
载荷                     成功时可紧跟上游首包
```

- 成功：先写 `0 | 空消息 | 填充(128..1023)`，随后双向字节中继。
  统计与 `Gauge::Tcp` 由 `forward::relay` 统一维护。
- 连接失败：写 `1 | "connect failed" | 填充`，不泄露内部错误文本；随后关闭流。
- 首帧类型不是 0x401、地址/填充越界、地址不是合法 `host:port`：直接关闭流，
  不写响应（与上游 `handleStream` 失败路径一致）。
- 单流请求头读取受 `handshake_timeout_ms` 限制；中继阶段受 QUIC 空闲超时限制。

## 5. UDP 承载

UDP 不使用流，而是 QUIC DATAGRAM（RFC 9221）。每条消息：

```text
sessionID      4 字节，大端
packetID       2 字节，大端
fragmentID     1 字节
fragmentTotal  1 字节
目标长度       QUIC varint，1..=2048
目标           UTF-8 `host:port`
载荷           剩余字节，0..=4096
```

- `fragmentTotal == 1` 表示未分片；否则客户端按 `(sessionID, packetID)` 重组。
- 服务端为每个 `sessionID` 建立一个 UDP 会话，持有：
  - 一个全局 `limits.max_udp_associations` 额度（`udp_slots`）；
  - 一个有界的 `mpsc` 队列（`limits.udp_queue_packets`）；
  - 一组按目标地址建立的 connected `UdpSocket`（`limits.max_udp_targets`）。
- 发送方向：载荷上限 `min(limits.max_udp_payload, 4096)`；按 1197 字节
  （`1200 - 3`，与上游 `udpMTU` 一致）切分，目标地址复制进每个分片。
- 回程方向：每个目标套接字由独立任务读取，按上述格式编码后
  `send_datagram` 发出；发送缓冲满或载荷过大时丢弃并计入 `dropped`。
- 分片重组：
  - 键 `(sessionID, packetID)`；
  - 最多 64 个条目、每项最多 4 KiB、TTL 8 s；
  - 重复/越界分片、`fragmentTotal` 不一致、总长超过 4096：丢弃整条消息；
  - `fragmentTotal > 16`：丢弃。
- 会话空闲超时按 `limits.udp_idle_timeout_ms`（或入口 `idle_timeout` 中较小者
  由调用方决定）回收；任一方向活动都会刷新。
- 队列载荷同时占用 `limits.udp_queue_bytes` 额度，慢消费者不会无限占内存。

## 6. salamander / gecko obfs

对 QUIC 使用的每一个 UDP 报文独立处理（位于 QUIC 之下）：

```text
线上报文 = salt(8 随机字节) || ciphertext
key      = BLAKE2b-256(password || salt)      # 32 字节
ciphertext[i] = plaintext[i] XOR key[i mod 32]
```

- salt 由 CSPRNG（`aws_lc_rs::rand::fill`）生成，每个报文独立；
- 接收端：`len <= 8` 的报文直接丢弃，其余全部字节解密；
- 线上长度 = 明文长度 + 8；
- 实现位于 `obfs.rs`，由自定义 `quinn::AsyncUdpSocket`（`socket.rs`）在
  `try_send` / `poll_recv` 中应用；
- 为简化边界，关闭 GRO/GSO，每条 datagram 单独生成 salt。

**gecko** 在 salamander 之上再对 QUIC 长首部报文分片：

```text
分片帧 = 0x80 | msgID(1) | chunkIdx<<4|total(1) | padLen(2, BE) | padding | chunk
线上报文 = salamander(分片帧)
```

- 首字节带 `0x80`（QUIC 长首部）的报文拆成 2..=8 片；其他报文原样走
  salamander，因此接收端无需额外判别位；
- 每片填充使线上长度落在 `min_packet_size..=max_packet_size`（默认 512/1200）；
- 接收端按 `(来源地址, msgID)` 重组，条目 TTL 8 秒、全局最多 4096 条、
  每来源最多 8 条；重复分片、total 不一致、越界帧丢弃；
- 配置：`"obfs": {"type": "gecko", "password": "...", "min_packet_size": 512,
  "max_packet_size": 1200}`；`min/max` 只允许 gecko，范围 256–1400 且 min<=max；
- 实现位于 `gecko.rs`（纯分片/重组）与 `socket.rs`（与 salamander 组合）。

## 7. 填充

与上游一致的区间（左闭右开，ASCII 字母数字）：

| 位置 | 区间 |
| --- | --- |
| 认证请求 | 256..2048（客户端生成，服务端丢弃） |
| 认证响应 | 256..2048 |
| TCP 请求 | 64..512（客户端生成，服务端丢弃） |
| TCP 响应 | 128..1024 |

填充只影响 HTTP/3 头部或流首部，不是 QUIC 包级填充；QUIC 的包级填充由
quinn/TLS 自行处理。

## 8. 明确不支持 / 存疑项

1. **Brutal 部分对齐，独立 pacer / 逐包丢包仍缺**。服务端按上游方向使用
   `bandwidth.up`（服务端发出）与 `bandwidth.down`（服务端接收）；认证响应
   返回 `Hysteria-CC-RX`，客户端据此限制上行速率，服务端发送方向使用 Brutal
   控制器。出站新增 `hysteria2.up_mbps/down_mbps`：请求携带本端接收带宽，
   认证后按 `min(服务端接收带宽, 本端上行带宽)` 设置客户端 Brutal 发送速率；
   `auto`/0 时保持回退控制器。`ignoreClientBandwidth` 为真时返回 `auto` 并
   回退常规拥塞控制。
   已通过直接依赖同版本 `quinn-proto 0.11.19` 对齐：`on_ack` 逐包计数、
   ACK 回调直接读取平滑 RTT、速率 0 时委托 quinn 内置 Cubic；不再做 100ms
   RTT 采样或用字节推算 ACK。仍保留“半窗”以抵消 quinn 由窗口推导 pacer 的
   1.25 倍补充，长期速率等于上游，但突发/pacing 时机不等价；丢包只有批量
   字节，按 MTU 折算包数。`disableLossCompensation` 配置未接入，始终启用
   损失补偿。出站已与官方 sing-box v1.14.4 服务端本机互通，但完整官方客户端
   矩阵仍未集中验收。精确阻塞、证据与最小补丁见
   [对齐核查](hysteria2-brutal-alignment.md)。
2. **BBR / bbr_profile / brutal_debug 不实现**。非 Brutal 路径使用 quinn 默认
   拥塞控制。
3. **masquerade 只实现 `string` 与 `file`**。`string` 返回固定正文（可选
   `status_code`），`file` 以目录为站点根提供静态文件（4 MiB 上限、
   `..`/NUL 路径拒绝、未知文件 404）。`proxy` 类型（反向代理）不支持；未配置
   masquerade 时认证失败仍返回 404。
5. **realm 不支持**。realm 是客户端与服务端的 NAT 打洞协调机制，需要额外的
   HTTP 控制面和 STUN；本服务端只接受普通 UDP/QUIC。
6. **端口跳跃（server_ports / hop_interval）不涉及服务端**，服务端只监听一个
   UDP 端口即可。
7. **服务端限速**：`up_mbps` / `down_mbps` 参与 Brutal 发送窗口与
   `Hysteria-CC-RX` 协商；非 Brutal 回退时不做独立令牌桶限速。
8. **认证后不再服务 HTTP/3 请求**。见第 3 节“认证后连接交接”。
9. **0-RTT、连接迁移策略**：quinn 默认行为；未针对 Hysteria2 做额外调优。
10. **`Hysteria-CC-RX` 的 `auto` 扩展**：仅在 `ignore_client_bandwidth` 为真时
    发送 sing-box 的 `auto` 哨兵；否则发送服务端接收带宽（byte/s）。
11. **QUIC DATAGRAM 的实际上限**可能低于 1197，取决于对端 `max_datagram_size`。
    当前实现固定按 1197 切分；若对端更小，`send_datagram` 会失败并丢弃，
    需要后续按 `Connection::max_datagram_size()` 自适应。
12. **h3 crate API 风险**：本地未安装 h3/h3-quinn，代码按 h3 0.0.8 的公开 API
    编写（`Connection::new` / `accept` / `send_response` / `finish`）。若实际
    版本签名不同，需要按编译错误微调，协议语义不变。

## 9. 资源上限汇总

| 资源 | 上限 |
| --- | --- |
| 每入口 QUIC 连接 | `limits.max_connections` |
| 每连接并发 TCP 流 | 512（QUIC 与本地信号量双重限制） |
| 每连接 UDP 会话 | 64 |
| 全局 UDP 关联 | `limits.max_udp_associations` |
| 每 UDP 会话目标套接字 | `limits.max_udp_targets` |
| 每 UDP 会话排队报文 | `limits.udp_queue_packets` |
| UDP 排队字节 | `limits.udp_queue_bytes`（全局） |
| 每连接 DATAGRAM 缓冲 | 1 MiB 收 / 1 MiB 发 |
| 重组条目 | 64 条 × 4 KiB = 256 KiB / 连接 |
| TCP 地址 / 消息 / 填充 | 2048 / 2048 / 4096 |
| UDP 载荷 | 4096 |
| 认证超时与流首部超时 | `limits.handshake_timeout_ms` |
| 连接空闲 | 入口 `idle_timeout`（建议 30 s） |

所有读取路径 fail-closed；没有 `unwrap`/`expect` 导致的运行时 panic（测试断言
除外），所有任务都挂在 `JoinSet` 或 `ctx.children` 跟踪器下，停机时 abort/join。

## 10. 与官方客户端 / sing-box 的兼容边界

**可用**：

- 官方 Hysteria2 客户端（apernet/hysteria v2）：密码认证、salamander/gecko、TCP、UDP；
- sing-box `type: "hysteria2"` 出站：密码认证、salamander/gecko、TCP、UDP；
  客户端侧 Brutal 发送会因服务端返回 0 而回退。

**不可用或需要配置层适配**：

- sing-box 的嵌套 `tls` 配置对象（本仓库配置风格使用扁平
  `certificate` / `private_key`，需要配置层转换）；
- `realm`、`bbr_profile`、`brutal_debug`、masquerade 的 `proxy` 类型；
- 依赖 Brutal 固定带宽语义的客户端策略。

## 11. 整合点

> 本节只描述需要主代理修改的位置；实现文件本身不注册 `mod`，也不会自动编译。

### 11.1 `src/transport.rs`

```rust
pub(crate) mod hysteria2;
```

### 11.2 `src/config.rs`

建议新增（字段名可调整，但语义需覆盖）：

```rust
#[serde(rename = "hysteria2")]
Hysteria2 {
    tag: String,
    listen: SocketAddr,
    users: Vec<User>,
    certificate: PathBuf,
    private_key: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    obfs: Option<Hysteria2Obfs>,
    #[serde(default = "default_true")]
    udp: bool,
    #[serde(default)]
    up_mbps: Option<u64>,
    #[serde(default)]
    down_mbps: Option<u64>,
    #[serde(default)]
    ignore_client_bandwidth: bool,
    #[serde(default)]
    idle_timeout_ms: Option<u64>,
},
```

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Obfs {
    #[serde(rename = "type")]
    pub kind: Hysteria2ObfsType,   // "salamander" | "gecko"
    pub password: String,
}
```

同时在 `Inbound::tag` / `listen` / `tls_paths` 的 match 中加入该变体（`tls_paths`
返回 `Some((certificate, private_key))`），并在 `validate` 中检查：

- `users` 非空且密码非空；
- `obfs.kind == Salamander` 且密码非空；
- `udp == false` 时仍允许完整认证，但认证响应 `Hysteria-UDP: false`。

如果要求直接接受 sing-box 的 `tls`/`masquerade`/`bbr_profile` JSON，需要在配置层
映射或显式拒绝；当前建议显式拒绝未支持字段，避免“接受但忽略”。

### 11.3 `src/runtime.rs`

Hysteria2 使用 **UDP** 监听，不能走现有 `TcpListener::bind` 路径：

1. 绑定阶段，对 `Inbound::Hysteria2` 跳过 TCP 监听，改为：

```rust
let socket = tokio::net::UdpSocket::bind(inbound.listen()).await?;
let address = socket.local_addr()?;
let mut tls = crate::tls::load(certificate, private_key)?;
Arc::get_mut(&mut tls)
    .ok_or_else(|| anyhow::anyhow!("Hysteria2 TLS 配置被共享"))?
    .alpn_protocols = vec![b"h3".to_vec()];
```

把 `(socket, tls)` 存入独立的 Hysteria2 监听集合；`addresses.insert(tag, address)`
保持不变。

2. 运行阶段：

```rust
let bandwidth = crate::transport::hysteria2::Bandwidth::from_mbps(up_mbps, down_mbps)?;
let options = crate::transport::hysteria2::Options::with_bandwidth(
    tag.clone(),
    users,
    obfs,                   // Option<ObfsMode>；salamander 或 gecko 参数
    masquerade,
    udp,                    // 默认 true
    bandwidth,
    ignore_client_bandwidth,
    Duration::from_millis(idle_timeout_ms.unwrap_or(30_000)),
)?;
tokio::spawn(crate::transport::hysteria2::serve(
    socket,
    tls,
    options,
    ctx.clone(),
    stop.clone(),
    force.clone(),
));
```

3. `Server::run` 的停机路径需要同时等待/取消该任务；`serve` 在 `stop` 取消后
   关闭 QUIC 端点，在 `force` 取消后 abort 所有连接任务。
4. `Server::check` 现有逻辑会通过 `tls_paths()` 自动加载 Hysteria2 证书；
   无需额外分支，但要在 `Inbound` 的 `tls_paths` match 中加入新变体。

## 12. 依赖需求与 rustls 兼容结论

| crate | 精确版本 | features | License | MSRV | 用途 |
| --- | --- | --- | --- | --- | --- |
| `quinn` | `=0.11.11` | `default-features = false`, `["runtime-tokio", "rustls-ring", "log"]` | MIT OR Apache-2.0 | 1.85 |
| `h3` | `=0.0.8` | 默认特性（如需裁剪请先确认 manifest） | MIT | 未确认（以锁定版本为准） | HTTP/3 认证 |
| `h3-quinn` | `=0.0.10` | 默认特性 | MIT | 未确认（以锁定版本为准） | quinn 适配 |
| `blake2` | `=0.10.6` | `default-features = false`, `["std"]` | MIT OR Apache-2.0 | 未声明（edition 2018） | salamander BLAKE2b-256 |

- **rustls 无冲突**：`quinn-proto 0.11.16` 声明 `rustls = "0.23.5"`（`^` 语义），
  本仓库 `[patch.crates-io]` 固定的 `=0.23.46` 满足该要求；不会产生两份 rustls。
  `quinn` 的 `rustls-ring` 特性只启用 rustls 的 `ring` provider，而
  `src/tls.rs` 已经用 ring provider 构建 `ServerConfig`，两者一致。
- **h3 / h3-quinn 版本为按公开 API 编写的首选值**。本地 cargo 缓存中没有这两个
  crate，无法离线核对 manifest；如果解析失败，可尝试 `h3 = "=0.0.7"` +
  `h3-quinn = "=0.0.9"`（API 基本相同），并在报告中记录实际锁定版本。
- 不需要新增 `bytes`、`rand`、`getrandom`：`send_datagram` 通过 `Vec<u8>` 的
  `Into<Bytes>` 推断目标类型；随机数复用已存在的 `aws-lc-rs` 的
  `rand::fill`。
- 不启用 quinn 默认的 `platform-verifier` / `bloom`，服务端不需要客户端证书
  验证器或 Bloom token 日志。

## 13. 验收建议（用户后续执行）

1. 用 `examples/` 或测试证书启动 Hysteria2 入口，确认 UDP `listen` 可绑定；
2. 官方客户端 `hysteria client`（带/不带 salamander）执行 TCP 回显与 UDP DNS；
3. sing-box 出站执行同样两组流量；
4. 错误密码：客户端应收到 404，且服务端不产生代理流；
5. 大 UDP（>1197 字节）验证分片与重组；
6. 长时间空闲后连接按 `idle_timeout` 回收，无任务泄漏；
7. 用 `cargo test --test hysteria2` 验证纯协议用例与端到端回环测试。

## 14. 本机验证状态

`tests/hysteria2.rs` 在纯线格式用例之外新增 3 项端到端回环测试：HTTP/3
认证（状态码 233）、认证后 TCP 双向流中继、认证后 UDP DATAGRAM 中继与回包，
以及错误密码被拒绝。测试使用临时自签证书与真实 quinn/h3 客户端，不依赖外部
网络。

端到端测试暴露并修复了两个服务端缺陷：

- `ObfsUdpSocket::poll_recv` 曾把 `RecvMeta::stride` 置 0；quinn 按 `stride`
  切分 `len`，会生成空切片并在驱动的接收循环中空转，导致任何 Hysteria2 连接
  都无法被接受；
- `h3::server::Connection` 在 Drop 时关闭整个 QUIC 连接；认证后立即丢弃它会使
  “认证后转用原始双向流”的交接失效。现在该控件保留到代理会话结束。

修复后 TCP 与 UDP 路径均在本机回环下通过。另新增 `gecko` obfs 回环测试：
测试侧独立实现 salamander 与 gecko 分片客户端，完成 QUIC 握手、HTTP/3 认证与
TCP 回显，验证服务端分片/重组路径。masquerade 另有 2 项回环测试：`string`
固定正文与 `file` 目录内容/404。另已用固定 Mihomo v1.19.33 客户端
（`up/down=100 Mbps`）完成到本内核入站的 TCP/UDP 本机互通。官方 Hysteria2
客户端全矩阵、三平台、MSRV 与 release 集中验收仍未执行。
