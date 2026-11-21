# VLESS Encryption（mlkem768x25519plus）研究记录

状态：**入站服务端与出站客户端均已实现**（`src/transport/vless_encryption.rs` 与
`client.rs`；入站已接入 `vless`、`vless-reality`、`vless-ws`、`vless-grpc`、
`vless-xhttp`、`vless-httpupgrade`、`vless-quic`、`vless-kcp`、`vless-http`；
出站可用于 `vless` 出站的任意已建立承载；范围与限制见第 8 节）。已用官方
Xray v26.10.31 `vlessenc` 生成的 X25519/ML-KEM-768 认证对完成 VLESS/TLS 双向本机互通；
ML-KEM-768 认证对已完成 macOS ARM64 Rust1.91/1.95 与 Linux ARM64 Rust1.95 全量
验证；Linux x86_64/Windows 与可发布 release 未验收。已用官方 Xray v26.10.31 客户端的
`0rtt` 配置完成重连验证：首个连接为 1-RTT（长度块 1232），后续连接为 0-RTT
（长度块 32）并被本内核票据缓存接受；服务端调试事件只记录握手类别/长度，不含密钥。
依赖与规格均已从固定上游源码确认。
研究基线：Xray-core `v26.10.31`，只读源码
`src/proxy/vless/encryption/{common.go,server.go,client.go,xor.go}` 与
`src/infra/conf/vless.go`、`src/main/commands/all/vlessenc.go`。该目录为 MPL-2.0，
本记录只描述行为，不复制代码。

## 1. 定位

VLESS Encryption 是 VLESS 的**传输前加密层**：在 VLESS 请求头之前插入一段
自实现的握手与记录层，使整条连接在外部观察者看来是连续的 TLS 1.3
application-data 记录，同时提供前向保密（PFS）与可选的 0-RTT 票据复用。
它不替代 TLS/REALITY；可叠加在明文 TCP、TLS 或 REALITY 之上。

## 2. 配置语法

```
mlkem768x25519plus.<mode>.<time>[.<padding>...]
```

- `<mode>`：`native`（不额外混淆）、`xorpub`（握手公钥/密文做 XOR）、
  `random`（握手与后续记录头均做 XOR，最隐蔽）。
- `<time>`：服务端为 `0`/`600s`/`30-600s`；客户端只接受 `1rtt`（关闭 0-RTT）或
  `0rtt`（启用票据复用），与 Xray `infra/conf/vless.go` 一致。
- `<padding>`：形如 `100-111-1111.75-0-111` 的若干组
  `概率-最小-最大`，偶数位是 padding 长度、奇数位是发送间隔（毫秒）。
  首组长度不得小于 35；总 padding 不得超过 65553。

服务端字段名为 `decryption`，出站字段名为 `encryption`；两者由
`xray vlessenc` 一次生成，认证密钥必须配对。

模板见 `examples/vless-encryption.json`，其中的 UUID、`decryption` 与证书路径
均为占位值，必须在部署前替换。

## 出站客户端

`vless` 出站新增可选 `encryption` 字段，语法同客户端 `encryption`，密钥必须是
32 字节 X25519 公钥或 1184 字节 ML-KEM-768 封装公钥：

```json
{
  "type": "vless",
  "tag": "up",
  "endpoint": "127.0.0.1:443",
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "tls": {"ca_file": "/etc/ssl/private/proxy-ca.pem"},
  "encryption": "mlkem768x25519plus.native.1rtt.<base64url-public-key>"
}
```

- 握手在出站 TLS/WS/gRPC 包装之后、VLESS 请求头之前完成；TCP 与原生 UDP 共用。
- 支持 `native`/`xorpub`/`random`、1-RTT 与 0-RTT；0-RTT 票据在首次握手后缓存，
  票据过期/拒绝时会清除缓存，下一次拨号回到 1-RTT。
- 首次 0-RTT 失败会使当前连接失败关闭；自动在同一条连接上重试 1-RTT 需要重新
  拨号，当前版本不隐式重拨。
- 固定使用 AES-256-GCM；服务端会优先尝试 AES 并在失败时回退 ChaCha20-Poly1305。
- 本机回环已验证 `native`/`xorpub`/`random` 的 TCP、`native` 原生 UDP，以及
  入站 `vless-ws`/`vless-grpc` + `decryption` 与出站 `encryption` 的端到端组合。
- 入站 Encryption 在传输层之后、VLESS 认证之前应用；REALITY 组合走无 flow 的
  VLESS 路径（含 Vision flow；已接入 decryption+Vision）。

## 3. 密钥材料

| 角色 | X25519 | ML-KEM-768 |
| --- | --- | --- |
| 服务端 | 32 字节私钥（raw） | 64 字节种子（Go `GenerateKey768` 的 seed） |
| 客户端 | 32 字节公钥（raw） | 1184 字节封装（公钥） |

均以 base64url（无 padding）编码。服务端按长度区分：32 字节按 X25519 处理，
其余按 ML-KEM 处理。可以配置**多个**认证密钥组成中继链（relay chain）。

## 4. 握手（1-RTT）

客户端首包：

```
16 字节随机 IV
relays 链（每个认证密钥 32 或 1088 字节）
加密块 1：18 字节 = AEAD(明文 "长度" u16) —— 明文长度 = 1232
加密块 2：1232+16 字节 = AEAD(客户端 PFS 公钥 1216 字节)
padding 记录若干（每条仍是 18+len 的加密块，可按组延迟发送）
```

- `AEAD(context, key)` 的密钥 = `BLAKE3::derive_key(context, key)`，
  算法为 AES-256-GCM 或 ChaCha20-Poly1305；服务端先按 AES 尝试，
  失败后切换 ChaCha（客户端是否用 AES 取决于硬件支持）。
- 记录 nonce 是从 0 开始的 12 字节大端计数器，每记录递增；当 nonce
  达到全 0xFF 时，用**该记录的 5 字节头 + 密文整体**作为新 context
  重新派生 AEAD（重密钥）。
- relay 链：第 j 个 relay 是当前认证密钥对应的 X25519 公钥或 ML-KEM 密文；
  其后若还有下一把密钥，则用 `CTR(BLAKE3::derive_key("VLESS", nfsKey), IV)`
  把 BLAKE3(next_public_key) 的 32 字节摘要 XOR 进去。服务端反向逐层解封，
  校验摘要，得到 `nfsKey`。
- `xorpub`/`random` 模式下，relay 公钥/密文先用
  `CTR(BLAKE3::derive_key("VLESS", 原始配置密钥), IV)` 做 XOR。

服务端应答：

```
1088 字节 ML-KEM 封装密文 + 32 字节服务端 X25519 公钥 + 16 字节 GCM tag
32 字节加密票据
padding 记录若干
```

- PFS 共享密钥 = `mlkem_shared(32) || x25519_shared(32)`，
  `UnitedKey = PFS(64) || nfsKey(32)`。
- 双向 AEAD context：上行用服务端 PFS 公钥、下行用客户端 PFS 公钥。
- 票据 16 字节：前 2 字节是有效秒数（大端），其余随机。
- 客户端随后发送加密的长度 + padding 字节；服务端校验后握手结束。

## 5. 0-RTT

服务端启用非 0 有效期时，客户端可复用缓存票据：

- 首包仍带 IV + relays，但加密块 1 的明文长度字段为 `32`，
  后接 32 字节加密票据，不再发送 PFS 公钥。
- 服务端用票据查会话缓存；`UnitedKey = 缓存的 PFS(64) || 本次 nfsKey(32)`。
- 重放防护：同一 `nfsKey` 只能绑定一次票据；票据按分钟淘汰，
  最多保留 65536 条，收到未知票据时回写随机字节迫使客户端重新握手。
- 服务端先写 16 字节随机前缀，上下行 AEAD 分别以该前缀与加密票据为 context。

## 6. 记录层

- 每条记录 = 5 字节伪装头 `0x17 0x03 0x03 len(u16)` + `len` 字节密文；
  明文最大 16384，`len` 合法范围 17..=16640。
- 写侧按 8192 字节分片；读侧按长度完整读取，失败即关闭。
- `random` 模式下，仅每条记录的 5 字节头参与 XOR（用同一 CTR 流，
  按记录长度跳过密文），其余模式不做记录级 XOR。

## 7. 依赖选型

最初评估过直接用 `aws-lc-rs 1.19.0`（已在本地核对源码）：

- `aws_lc_rs::kem` 公开提供 `ML_KEM_768`、`DecapsulationKey::new`、
  `EncapsulationKey::encapsulate`、`DecapsulationKey::decapsulate`；
  **但 `DecapsulationKey::new` 只接受 2400 字节展开密钥**。
  Xray 服务端配置是 64 字节种子，需要按 FIPS 203 做种子展开，
  这属于密码原语，不能自行实现，因此未采用该路径。
- X25519 仍使用 `aws-lc-rs` 的 `agreement`；raw 32 字节私钥由
  `from_private_key` 直接接受。
- `random`/`xorpub` 模式的 AES-CTR 需要 `ctr` crate（原依赖集只有传递依赖）。
- `BLAKE3::derive_key` 需要把 `blake3` 从 dev-dependency 提升为运行时依赖，
  且上游 API 只接受 `&str` 上下文，Xray 用随机字节作上下文，因此需要本地补丁。

实现中落实的依赖（均已按第 7 节核对）：

| 依赖 | 版本 | 许可 | 用途 |
| --- | --- | --- | --- |
| `ml-kem` | 固定 `=0.3.4`（MSRV 1.87） | Apache-2.0 OR MIT | `DecapsulationKey::from_seed`（64 字节 `d\|\|z` 种子）、`EncapsulationKey::new/encapsulate`、`decapsulate`；启用 `getrandom` |
| `ctr` | 固定 `=0.10.1`（MSRV 1.85） | MIT OR Apache-2.0 | `Ctr128BE<Aes256>`，与 Go `cipher.NewCTR` 一致 |
| `blake3` | `1.8`（本地补丁，`vendor/blake3`） | Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR CC0-1.0 | derive-key；补丁新增任意字节上下文入口（见 `vendor/blake3/PATCH.md`） |

X25519 使用 `aws-lc-rs` 的 `agreement::{PrivateKey, UnparsedPublicKey}`：
`from_private_key` 接受 raw 32 字节私钥，`compute_public_key()` 可直接取回公钥，
无需自行实现种子展开或基点点乘。ML-KEM 的种子展开、封装与解封装全部委托
`ml-kem`，记录层对称算法全部委托 `aes-gcm` / `chacha20poly1305` / `ctr`，
未自行实现任何密码原语。

## 8. 实现范围与限制

支持：

- 入站类型 `vless`（含**无 TLS 的明文 TCP**）、`vless-reality`、`vless-ws`、
  `vless-grpc`、`vless-xhttp`、`vless-httpupgrade`、`vless-kcp`、`vless-quic`、
  `vless-http`。无 `fallbacks`；Vision flow 可组合。配置校验会拒绝 `decryption`
  与 `fallbacks` 同时出现；Vision 使用不切换 TLS 原始记录层的帧化模式。
- REALITY 等外层安全层或 WS/gRPC/XHTTP/HTTPUpgrade/mKCP/QUIC 承载之后，
  先应用 VLESS Encryption，再进入 VLESS 认证；无 TLS 的明文 VLESS 也直接由
  Encryption 提供协议层加密。这是 VLESS 协议层加密，与上游“可运行在任意
  承载之上”的定位一致。
- `native` / `xorpub` / `random` 三种模式；AES-256-GCM 与
  ChaCha20-Poly1305 自动探测（先按 AES 解第一段长度块，失败即切换）。
- X25519 与 ML-KEM-768 认证密钥，以及多把密钥组成的中继链。
- 1-RTT 与 0-RTT（`decryption` 时间字段大于 0 时启用票据会话）。
- 任意 padding 分组配置；未配置时使用上游默认值
  `100-111-1111.50-0-3333` / `75-0-111`。

不支持（明确不做，遇到时按普通 TLS 失败处理，不静默降级）：

- VLESS `fallbacks`；
- 不再把 REALITY/WS/gRPC/XHTTP/HTTPUpgrade/mKCP/QUIC 列为不支持承载：
  这些路径已在配置与运行时接入，见上节。

本地硬化为失败关闭、不改变线格式：

- 单条连接记录层 AEAD 次数上限 `2^63`，超限直接断开；远低于 96 位
  nonce 空间，且上游的重密钥分支只在计数溢出后才可能触发。
- 有效票据的会话数上限 65536（与默认 `limits.max_replay_entries` 一致），
  超出时淘汰最旧票据，客户端回退到完整握手。
- 同一票据下记录的重放 `nfsKey` 数量上限等于 `limits.max_replay_entries`，
  达到上限后新 0-RTT 连接被拒绝（失败关闭）。
- 票据有效期必须在 `0..=65535` 秒内：长度字段只有 2 字节，超过会在
  客户端截断，因此配置阶段直接拒绝。

客户端侧：使用 Xray `vlessenc` 生成的 `encryption` 字段（客户端 `0rtt`
或 `1rtt`）即可连接；`decryption` 中的 padding 段与密钥必须与客户端
`encryption` 对应，否则首包认证会失败。
