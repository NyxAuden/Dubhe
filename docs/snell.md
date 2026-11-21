# Snell v4 / v5 / v6（default/shaped、unshaped、unsafe-raw）入站与出站

本文描述 `src/protocol/snell.rs` 实现的 wire 规格、配置建议、资源上限与兼容边界。
实现依据为只读上游 `github.com/sagernet/sing-snell@v0.0.0-20260904135315-bc5a12ac736f`
与 `sing-box v1.14.4` 的入站字段；协议行为独立实现，未复制上游代码。

## 1. 版本差异（以源码为准）

上游源码中，**v4 与 v5 共享同一套 KDF、AEAD 和记录格式**：

| 项目 | v4 | v5 |
| --- | --- | --- |
| KDF | Argon2id(psk, salt, t=3, m=8 KiB, p=1, out=32)[:16] | 相同 |
| AEAD | AES-128-GCM，96-bit nonce，16-byte tag | 相同 |
| salt | 每方向首个记录前 16 字节，明文 | 相同 |
| 记录头 | 7 字节明文 + 16 字节 tag，版本 0x04 | 相同 |
| 初始 padding | 0x100..=0x1ff | 相同 |
| UDP over stream | 支持 | 支持 |

差异集中在握手与应用语义：

* v5 服务端对**首个记录的 salt** 做跨连接重放检查（两代 Bloom，容量 500000，1e-10）。
* v5 的 `PING` 在读完 3 字节请求前缀后立即返回，不消费 client id；
  v4 的通用 `ReadRequest` 会消费 client id。
* v5 的复用隧道使用 0x65 `"Remote EOF"` / 0xff `"end of file"` 错误码。
* v4 客户端即使不启用复用，TCP 握手也发送 `CONNECT_V2 (0x05)`。

因此本实现把 v4/v5 统一到同一个记录层，仅通过 `version` 控制重放检查与 PING 解析。
题目中“v5 使用不同的密钥派生 / AEAD 记录格式”的描述与上述源码不一致；这里以源码为准。

## 1.1 v6 记录模式

v6 沿用相同的 KDF、AEAD、请求格式与复用语义，差异在记录层：

| 模式 | 记录格式 | 状态 |
| --- | --- | --- |
| `default`/shaped | BLAKE2b-256 Profile 派生、Argon2id+AES-128-GCM、salt block、变长 record prefix、padding/payload mixing 与 chunk 策略 | 支持；`mode` 缺省即 default |
| `unshaped` | 首个记录前 16 字节 salt；每条记录为 AEAD(7 字节头) + AEAD(载荷)，padding 必须为 0 | 支持 |
| `unsafe-raw` | 7 字节明文头 + 明文载荷，无加密、无 padding | 支持（仅显式配置） |

default/shaped 的 profile、记录布局、填充生成、mixing、nonce 与 chunk 切分按固定 `sing-snell/snellv6` 源码独立实现；本地参考向量与解码/编码对端测试覆盖首记录、零块与后续记录。v6 不在首个记录 salt 上做 v5 的跨连接重放检查。

## 2. 密钥派生与 AEAD

### 2.1 Argon2id

```text
key = Argon2id(
    password = psk (原始字节),
    salt     = 16-byte salt,
    time     = 3,
    memory   = 8 KiB,
    threads  = 1,
    out_len  = 32
)[0..16]
```

即 Go 的 `argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]`。得到 16 字节
AES-128 密钥。注意 `out_len` 必须是 32 后截断，不能直接请求 16 字节。

### 2.2 AES-128-GCM

* nonce 长度 12 字节，初始全零。
* 每个方向独立维护 nonce；每完成一次 AEAD 操作后按**小端 96 位整数**加一。
* AAD 为空。
* tag 16 字节，附在密文尾部。

## 3. 记录格式

每个方向在第一个记录之前先发送 16 字节随机 salt（明文）。之后每个记录为：

```text
+----------------------+-------------------+---------------------------+
| header_cipher (23 B) | padding (P B)     | payload_cipher (L+16 B)   |
+----------------------+-------------------+---------------------------+
```

* `header_cipher = AES-GCM(key, nonce, header_plain)`，随后 nonce++。
* `header_plain`（7 字节）：

  ```text
  offset  size  value
  0       1     0x04           记录版本
  1       1     0x00           保留，必须为 0
  2       1     0x00           保留，必须为 0
  3       2     padding_len    big-endian
  5       2     payload_len    big-endian
  ```

* `payload_cipher = AES-GCM(key, nonce, payload)`，随后 nonce++。
* `padding` 为随机字节；接收方丢弃。
* **奇数字节交换**：在写出 `padding` 与 `payload_cipher` 后，对
  `i = 0, 2, 4, ... < min(P, L+16)` 交换 `padding[i]` 与 `payload_cipher[i]`。
  读取时先做同样的交换再解密。
* `payload_len == 0` 表示**零块 / 逻辑流 EOF**。零块只包含 23 字节加密头，
  没有 padding、没有 payload tag，nonce 只前进一次。
* 每个方向的首个非空记录携带 `padding_len = 0x100 + rand(0..=0xff)`；
  其它记录 `padding_len = 0`。
* `payload_len` 上限 `0x3fff`；本实现额外把 `padding_len` 限制在 `0x3fff`。
* 保留字节非零、版本不是 0x04、长度越界、tag 校验失败均立即关闭连接。

## 4. 请求

请求位于首个解密记录的 payload 开头，格式：

```text
offset  size  value
0       1     0x01               RequestVersion
1       1     command
2       1     client_id_len     0..=255
3       N     client_id         N = client_id_len
```

命令字：

| 值 | 名称 | 目标地址 |
| --- | --- | --- |
| 0x00 | PING | 无 |
| 0x01 | CONNECT | 有 |
| 0x05 | CONNECT_V2（复用） | 有 |
| 0x06 | UDP | 无（首个 UDP 包内携带） |

### 4.1 CONNECT / CONNECT_V2 目标地址

```text
+--------------+----------------+------------------+
| host_len (1) | host (host_len)| port (2, BE)     |
+--------------+----------------+------------------+
```

`host` **始终是主机字符串**，即使目标是字面 IP（例如 `"1.2.3.4"`）。
长度为 1..=255，字符必须为 ASCII 可见字符。IPv6 不带方括号。
字面 IP 解析为 `Host::Ip`，其余作为域名交给内核 DNS。

请求记录在地址之后如果还有字节，视为该逻辑流的 **early data**；
服务端在连上目标后先写入目标，再继续读取后续记录。

### 4.2 PING

服务端回写首个记录，payload 为 `0x01`（ReplyPong），然后关闭。
v5 解析 PING 时不消费 client id；v4 会消费。

## 5. 应答

服务端同样独立生成 salt、nonce 和密钥。首个应答记录：

| 首字节 | 含义 |
| --- | --- |
| 0x00 | ReplyTunnel，其后为流数据（可为空） |
| 0x01 | ReplyPong |
| 0x02 | ReplyError，后接 `code (1) + msg_len (1) + msg` |

本实现在目标连接成功后立即发送一个 payload 为 `[0x00]` 的首记录，
因此客户端可以尽早进入流状态；后续记录只承载流数据。

错误应答示例：

```text
[0x02, 0x01, 0x0e, "connect failed"]   目标连接失败（本实现自定义通用码）
[0x02, 0xff, 0x0b, "end of file"]      v5 非复用、首应答前上游 EOF
[0x02, 0x65, 0x0a, "Remote EOF"]       v5 复用、首应答前上游 EOF
```

认证失败、记录损坏、长度越界时不发送任何应答，直接关闭。

## 6. TCP 与复用

### 6.1 CONNECT (0x01)

单逻辑流。服务端连接目标、发送 `[0x00]` 首应答、双向中继：

* 客户端零块 → 关闭目标写端。
* 目标 EOF → 服务端关闭连接（按 v5 语义，非复用命令不写零块）。

### 6.2 CONNECT_V2 (0x05)

同一条加密隧道上顺序承载多个逻辑流：

1. 客户端发送请求记录；服务端连接目标并发送 `[0x00]` 首应答。
2. 双方以记录为边界传输数据。
3. 客户端零块 → 关闭目标写端。
4. 目标 EOF → 服务端写零块，标记该逻辑流结束。
5. 若目标先结束，服务端继续排空客户端记录直到零块，然后读取下一条请求。
6. 读取下一条请求；请求记录中地址之后的剩余字节是该逻辑流的 early data。

约束：

* 每条隧道最多 1024 个逻辑流。
* 目标先结束后，排空上限 `0x80001` 字节、超时 30 秒。
* 等待下一条请求的空闲上限 180 秒（与上游连接池最大年龄一致）。
* 不支持同一条隧道上的并发多路复用；与上游一致，逻辑流是顺序的。

## 7. UDP over stream

命令 `0x06`。服务端先发送 payload 为 `[0x00]` 的首应答记录，然后每条记录是一个 UDP 数据报：

### 7.1 客户端 → 服务端

```text
+----------------+---------------------+----------------+
| 0x01 (1)       | 目标地址             | UDP payload     |
+----------------+---------------------+----------------+
```

目标地址两种形式：

* 字面 IP：`0x00 | family | ip | port`
  * `family = 0x04`：4 字节 IPv4；`0x06`：16 字节 IPv6。
  * `port` 为 2 字节大端。
* 域名：`host_len (1) | host | port (2, BE)`（首字节非 0）。

### 7.2 服务端 → 客户端

```text
+---------------------+----------------+
| 来源地址             | UDP payload     |
+---------------------+----------------+
```

来源地址只使用字面 IP：`family (0x04/0x06) | ip | port (2, BE)`。
sing-box 的 Snell 客户端不接受域名来源，因此服务端始终回写解析后的 IP。

整个 UDP 数据报必须落在**一个记录**内（含地址前缀，v4/v5 ≤ 0x3fff，v6 ≤ 0xffff），
不做分片/重组。超出时丢弃该数据报；上游返回 payload-too-large。

## 8. 配置字段建议（对齐 sing-box）

```json
{
  "type": "snell",
  "tag": "snell-in",
  "listen": "0.0.0.0:8388",
  "psk": "REPLACE_WITH_A_RANDOM_SECRET",
  "version": 5,
  "users": [
    { "name": "alice", "userkey": "REPLACE_WITH_A_RANDOM_USER_KEY" }
  ],
  "obfs_mode": "none"
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `type` | 是 | 固定 `"snell"` |
| `tag` | 是 | 入站标识 |
| `listen` | 是 | TCP 监听地址 |
| `psk` | 是 | 原始 UTF-8 字符串，作为 Argon2id password；1..=4096 字节 |
| `version` | 是 | `4`、`5` 或 `6` |
| `mode` | v6 可选 | `default`（缺省）、`unshaped` 或 `unsafe-raw` |
| `users` | 否 | `[{name, userkey}]`；为空时接受任意 client id |
| `obfs_mode` | 否 | v4/v5 支持 `none`（缺省）、`http`、`tls`；v6 仅允许 `none` |

`userkey` 会作为请求中的 client id 发送，长度 1..=255，且在配置中必须唯一。
服务端以常量时间比较全部用户。

**注意**：sing-box v1.14.4 的 Snell 入站只注册了 version 5/6；本实现的 v4
服务端依据上游 `snellv4` 客户端行为与共享记录层实现，目标是兼容相应 v4 客户端；
已用固定 Mihomo v1.19.33 Snell v5 客户端与 sing-box v1.14.4 Snell v4/v6 客户端
完成 TCP/UDP 本机互通；sing-box v6 的 `default`、`unshaped`、`unsafe-raw` 三种
mode，以及 v4 的 `http`/`tls` obfs 均已单独通过，但这不构成完整官方客户端验收。sing-box v1.14.4 的
Snell 客户端不提供 v5 出站，因此 v5 的官方客户端证据只来自 Mihomo。

### HTTP/TLS obfs（仅 v4/v5）

入站设置 `obfs_mode: "http"` 或 `"tls"`；出站在 `snell` 对象内设置同名字段。两侧必须显式匹配，不自动探测、不回落直连。TCP 与命令 6 的 UDP-over-stream 共用该承载，Snell 身份校验与 AEAD 不变。

- HTTP：首个上行是一次 GET 头与原始 payload，首个下行是一次 101 外观头与原始 payload；之后为裸字节。虽然有 `Upgrade: websocket`，**不使用真实 WebSocket 帧**，也不是普通 HTTP CONNECT。
- TLS：首个上行在固定 ClientHello 外观的 session ticket 中携带最多 1024 字节，随后为 SNI 外观尾部；首个下行 payload 位于 `0x6b`。后续按最多 16384 字节的 application_data 外观记录分块。**不执行真实 TLS，不校验证书、不提供额外认证或保密性**。
- 出站 `obfs_host` 缺省 HTTP 为 `bing.com`、TLS 为 `cloudfront.net`；允许 1–253 字节可见 ASCII，不允许空白、斜杠、反斜杠或头注入。`obfs_uri` 仅 HTTP 适用，缺省 `/`，最多 1024 字节、以 `/` 开头且不含空白。
- `none` 不得配置 host/URI，TLS obfs 不得配置 URI，v6 不得启用 HTTP/TLS obfs。真实证书/TLS、REALITY 与通用 `transport` 不是 Snell obfs 参数。
- 接收 HTTP 首头最多 8192 字节；TLS 首段、SNI 和记录长度在有界读取前检查。短写及首头/载荷/尾部拆包由实例保存游标，`flush`/FIN 实际排空，空读不消耗。畸形、截断与错误身份失败关闭。

成对模板：[`examples/snell-obfs.json`](../examples/snell-obfs.json) 与 [`examples/snell-obfs-outbound.json`](../examples/snell-obfs-outbound.json)，均仅监听回环；替换随机凭据后使用。HTTP 模式还需双方改为 `http`，出站可加 `obfs_uri`。固定上游与本机验证见 [obfs 开发记录](snell-obfs-development.md)；不承诺外观指纹逐字节等价，不据本机双方互测宣称官方客户端兼容。

## 9. 资源上限

| 资源 | 上限 |
| --- | --- |
| 单记录 payload | v4/v5 `0x3fff` (16383)；v6 `0xffff` (65535) |
| 单记录 padding | v4/v5 `0x3fff`；v6 unshaped/raw为0，default按Profile |
| 单记录线上长度 | v4/v5最多32805字节；v6按模式/前缀/填充有界 |
| psk | v4/v5 1..4096字节；v6 12..255字节 |
| 用户数 | 1024 |
| userkey | 255 字节 |
| v5 重放缓存 | 每代 ≤ 1,000,000 个 16 字节 salt（两代） |
| 每条隧道逻辑流 | 1024 |
| 复用空闲 | 180 秒 |
| 复用排空 | 0x80001 字节 / 30 秒 |
| TCP 中继缓冲 | 每方向 32 KiB |
| UDP 目标数 | `limits.max_udp_targets` |
| UDP 队列 | `limits.udp_queue_packets` / `limits.udp_queue_bytes` |
| UDP 单报 | `limits.max_udp_payload`，且必须单记录可容纳 |
| UDP 关联数 | `limits.max_udp_associations` |
| 握手 | `limits.handshake_timeout_ms` |

长度在有界分配前检查；等待有超时或依赖运行时取消；代码中的`expect`只表达长度/所有权等内部不变量，不用它校验不受信报文。出站说明见[Snell出站](outbound.md#snell-细节)，开发验证见[记录](snell-outbound-development.md)。

## 10. 明确不支持 / 兼容边界

* **HTTP/TLS obfs 仅 v4/v5**：入站与 TCP/UDP-over-stream 出站均可用；v6 与其组合配置失败，不能根据协议名称任意叠加承载。
* **v6 支持 `default`/shaped、`unshaped` 与 `unsafe-raw`**：`default` 为缺省模式，按上游 Profile 驱动变长头、填充与混淆；`unshaped` 记录不得携带 padding。v6 要求 PSK 长度 12–255 字节；UDP 首个数据报不得与请求同帧。固定上游 v6 不提供 HTTP/TLS obfs。
* **不支持 v5 的 QUIC 代理**。
* **不支持 UDP 响应中的域名来源**；始终回写字面 IP。
* **UDP 未知地址族 fail-closed**。上游 v5 会吞掉两字节并把剩余部分当载荷转发，
  本实现直接关闭关联，避免静默降级。
* **保留头字节必须为 0**。上游读取端未检查；本实现检查并关闭。
* **padding > 0x3fff 拒绝**。
* **PING 不参与用户认证**，与上游一致（PING 无 client id 校验）。
* **同一条复用隧道不支持并发逻辑流**，只顺序处理。
* **不发送 0x65 / 0xff 的“首应答前 EOF”错误码**：本实现在目标连接成功后立即写
  `[0x00]`，因此不存在“尚未写过任何应答载荷”的分支；随后目标 EOF 时复用模式发送
  零块，非复用模式直接关闭。客户端语义等价，但字节序列与上游该分支不同。
* **v4/v5只使用首记录padding形态**，单记录≤0x3fff；v6 default则按固定上游Profile使用padding/mixing/chunk，v6 unshaped/raw单记录≤0xffff。不将形态近似宣称为全部上游能力。
* **证书字段不属于 Snell obfs**；本模块提供 TLS 外观编码，不提供真实 TLS 终止。
* **出站可显式启用 TCP 顺序连接池**（`snell.reuse: true`，默认 false），不是并发多路复用。保留同一承载的 salt/nonce/整形及 obfs 状态，收到对端逻辑零块且本地 FIN 写完后才回池；UDP 不取池。最多 10 个空闲/等待条目，空闲 180 秒过期、20 秒清理，关闭后排空最多 30 秒且丢弃达到 `0x80001` 字节即关闭。错误/未验证首应答或取消建连不回池、不自动重放业务，见[出站说明](outbound.md#snell-细节)与[池开发记录](snell-reuse-development.md)。

### QUIC 角色核查（2026-11-12，只读）

固定上游 `sagernet/sing-snell@v0.0.0-20260904135315-bc5a12ac736f`
（commit `bc5a12ac736f235b2de2926ecd2791cc925e6b8c`，GPL-3.0-or-later）的
固定源码中**没有 QUIC、ALPN、HTTP/3 或 quic-go 实现**；`go.mod`/`go.sum` 也
没有 QUIC 依赖。README 只写“除 v5 QUIC proxy 外的完整功能”，没有给出该模式
的客户端/服务端角色、wire 或测试向量。固定 `sing-box v1.14.4` 的 Snell 入站
只监听 TCP，出站只拨 TCP，并在文档中明确不实现 v5 QUIC proxy。

因此本内核不按名称推测或自造 Snell QUIC：在取得官方协议说明、固定二进制
行为或可互通参考实现之前，Quic 字段继续在配置阶段拒绝，QUIC 不列入已实现
能力。现有 TCP、UDP-over-stream、obfs 与顺序池语义不由此改变。
