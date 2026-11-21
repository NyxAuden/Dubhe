# 协议与功能的上游归属

一个协议只有**一个**线协议权威来源。实现可以有很多，但实现之间的细节差异
不能当作规范。本页回答两个问题：

1. 每项能力该以谁为准；
2. 本内核当前实际上参照了谁。

判定方法：先找公开协议规范；没有规范的，以官方实现为准；官方闭源且只有逆向
实现的，明确标注「无权威规范，参照某个实现」。

## 证据等级

| 等级 | 含义 |
|---|---|
| **规范** | 存在独立、公开、与实现分离的协议文档 |
| **官方实现** | 无独立规范，但原作者实现的源码公开 |
| **逆向实现** | 官方闭源，只能参照第三方逆向工程 |

---

## 一、协议归属

| 协议 | 权威来源 | 等级 | 备注 |
|---|---|---|---|
| SOCKS5 | [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | 规范 | BIND 是本内核扩展，RFC 只定义 CONNECT 与 UDP ASSOCIATE |
| HTTP CONNECT | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) / [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) | 规范 | 代理隧道语义本身没有独立 RFC，业界以「CONNECT + 绝对 URI」惯例实现 |
| Trojan | [trojan-gfw/protocol](https://trojan-gfw.github.io/trojan/protocol) | 规范 | 原作者已归档，规范仍公开 |
| VLESS | XTLS/Xray-core | 官方实现 | 无独立规范文档；VLESS Encryption、Vision、REALITY 均由 Xray 定义 |
| VMess | V2Ray / Xray-core | 官方实现 | 无独立规范文档；AEAD 模式以 Xray 为准 |
| Shadowsocks | [shadowsocks.org 规范](https://shadowsocks.org/doc/sip002.html)（SIP002）+ `shadowsocks-rust` | 规范 | 本内核直接用 `shadowsocks-rust` 的协议层 |
| **Hysteria 2** | `apernet/hysteria` 官方文档 `Protocol` 页 | **规范** | 有 TCP/UDP/Fragmentation/Congestion Control/obfs 完整章节，[v2.hysteria.network/docs/developers/Protocol](https://v2.hysteria.network/docs/developers/Protocol/) |
| **TUIC v5** | `tuic-protocol/tuic` 仓库 `SPEC.md` | **规范** | 明确声明「本仓库不含官方实现」，版本 `0x05`；协议概念无许可限制 |
| **AnyTLS** | `anytls/anytls-go` `docs/protocol.md` | **规范** | 客户端/服务器两节完整定义帧格式、paddingScheme、复用；v2 于 2025-04、v2 更新于 2025-09 |
| **Naive** | `klzgrad/naiveproxy` README「Padding protocol, an informal specification」 | **规范（非正式）** | 只有 padding 层被正式描述；H1/H2/H3 CONNECT 本身是标准 HTTP |
| **ShadowTLS v3** | `ihciah/shadow-tls` `docs/protocol-v3-en.md` | **规范** | v1/v2 也有独立文档；本内核只实现 v3 |
| **NW3** | `NodePassProject/Nowhere-Protocol` 仓库 | **规范** | 明确「本仓库提供规范，不是实现」；Rust 实现是 `NodePassProject/Nowhere`；规范为 CC BY 4.0，独立实现可选任意许可 |
| Snell | Surge（闭源） | **逆向实现** | 无公开规范。`sagernet/sing-snell` README 自述为「Surge snell implemented in Go」，并称「All complete features except the v5 QUIC proxy」 |
| WireGuard | [WireGuard 协议文档](https://www.wireguard.com/protocol/) | 规范 | 本内核用 `boringtun` 实现 |
| REALITY | XTLS/Xray-core | 官方实现 | 无独立规范；与 Vision 同属 Xray 定义 |
| Vision | XTLS/Xray-core | 官方实现 | 同上 |
| VLESS Encryption | XTLS/Xray-core | 官方实现 | `xray vlessenc` 是唯一权威参数生成器 |
| Mux.Cool | XTLS/Xray-core | 官方实现 | 线协议以 Xray `common/mux` 为准 |
| UoT (UDP over TCP) | `sing-box` 文档 `shared/udp-over-tcp` | 规范 | v1/v2 两版；AnyTLS 规范也引用它 |
| HTTP/2 | [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) | 规范 | |
| HTTP/3 | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | 规范 | |
| QUIC | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) 等 | 规范 | 本内核用 `quinn` |
| XHTTP | XTLS/Xray-core | 官方实现 | 无独立规范；Xray v26 正在把 WS/gRPC/HTTPUpgrade 迁移到 XHTTP |
| mKCP | V2Ray / Xray-core | 官方实现 | |
| gRPC / HTTPUpgrade / WebSocket 承载 | 各协议组合，非独立协议 | 官方实现 | WebSocket 本身是 [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) |

### 纠正一处常见误解

sing-box 是很多协议的**实现**，但不是 TUIC、AnyTLS、Hysteria 2、Naive、
Snell 的作者。下面这些协议各有独立来源，不能拿 sing-box 当权威：

- TUIC → `tuic-protocol/tuic`
- AnyTLS → `anytls/anytls-go`
- Hysteria 2 → `apernet/hysteria`
- Naive → `klzgrad/naiveproxy`
- Snell → Surge（闭源，只有逆向实现）
- NW3 → `NodePassProject/Nowhere-Protocol`（规范）与 `Nowhere`（Rust 实现）

sing-box 的地位是「高质量第三方实现 + 常用配置基线」，适合用作**互操作测试
目标**，不适合作为线协议依据。

---

## 二、功能归属（非协议）

| 功能 | 权威来源 | 等级 | 说明 |
|---|---|---|---|
| `invert` 路由 | sing-box | 官方实现 | Xray 无整条规则取反 |
| `ip_is_private` | sing-box | 官方实现 | 语义为 `!IsPublicAddr`，见 `docs/upstream-facts.md` |
| `domain_regex` | sing-box | 官方实现 | Xray 用 `regexp:` 前缀，语义不同层 |
| 规则集 `rule_set` | sing-box | 官方实现 | geosite/geoip 在 1.12.0 已移除 |
| 负载均衡策略 | Xray | 官方实现 | `random`/`roundRobin`/`leastPing`/`leastLoad` |
| 连接空闲超时 `connIdle` | Xray | 官方实现 | 默认 300 秒，见 `docs/upstream-facts.md` |
| 缓冲大小 `bufferSize` | Xray | 官方实现 | 非 ARM 默认 512 KiB；生效路径未核实 |
| `tcp_keep_alive` / `udp_timeout` | sing-box | 官方实现 | 监听字段 |
| `udp_mapping` / `udp_filtering` | sing-box 1.14 | 官方实现 | 未读源码，仅文档 |
| Mux 复用（客户端侧） | sing-box `multiplex` | 官方实现 | 与 Xray Mux.Cool 不是同一线协议 |
| FakeIP | sing-box | 官方实现 | |
| DNS DoQ | sing-box（另有 RFC 9250） | 规范 | |

---

## 三、本内核当前参照

| 能力 | 参照对象 | 与本页第一节是否一致 |
|---|---|---|
| VLESS / VMess / Trojan / REALITY / Vision / VLESS Encryption / Mux.Cool / XHTTP / mKCP | Xray v26.10.31 | ✅ 一致（Xray 即权威） |
| Shadowsocks | `shadowsocks-rust` 1.25.0 | ✅ 一致 |
| Hysteria 2 | 文档与 sing-box 实现混合 | ✅ 已比对官方 `PROTOCOL.md`：认证头、233 状态、`0x401` 帧、UDP 八字段、CC-RX 语义一致 |
| TUIC | sing-box 实现 | ✅ 已比对 SPEC：五种命令与 Packet 字段顺序一致 |
| AnyTLS | `sagernet/sing-anytls` 源码 | ✅ 已比对规范：11 个命令编号 0–10 一致，`DEFAULT_SCHEME` 与官方逐字节一致 |
| Snell | `sagernet/sing-snell` 源码 | ✅ 一致（无官方规范，逆向实现即最高可得） |
| Naive | `klzgrad/forwardproxy` + sing-box | ✅ 一致（padding 层以 naiveproxy 为准） |
| ShadowTLS v3 | `sagernet/sing-shadowtls` + 官方规范 | ✅ 一致 |
| NW3 | `vendor/nowhere` 3.3.0 整包复用 | ✅ 实现即官方 Rust 实现；规范在独立仓库 |
| WireGuard | `boringtun` 0.7.1 | ✅ 一致 |
| UoT | sing-box | ✅ 一致 |
| `invert` / `ip_is_private` / `domain_regex` | sing-box | ✅ 一致 |

「⚠️」三项的共同问题：**线协议以第三方实现为准，而该协议本身有官方规范**。
这不必然导致错误，但如果第三方实现与官方规范分叉，本内核会跟着分叉。

---

## 四、待办：按归属重新分配校验任务

以下不是「新增功能」，而是**核对现有实现是否与权威来源一致**。每项都需要
读对应规范并比对，不能靠 sing-box 行为反推。

| 优先级 | 任务 | 权威来源 | 当前依据 | 已核对 |
|---|---|---|---|---|
| 1 | Hysteria 2 帧格式、认证、UDP 分片、拥塞控制、obfs | `apernet/hysteria` `PROTOCOL.md` + 官方 `extras/obfs/*` | sing-box 实现 + 本内核自测 | **已核对**：`0x401` 请求/响应、UDP 八字段、`Hysteria-CC-RX` 0/auto、`Hysteria-UDP`、Salamander（salt 8 + BLAKE2b-256(key‖salt) + XOR）、UDP 分片全到齐才交付/缺片丢弃/未分片 total=1、空闲回收与未知 Session 新建，全部一致。**修正两处**：①Gecko `min/max_packet_size` 原先限制 256–1400，官方只要求 `min>0 && min<=max && max<=2048`，已放宽；②非法地址原先不回 TCPResponse，规范要求 MUST 回，已改为回 `invalid address` Error。**Gecko 说明**：v2.6.5 的 `PROTOCOL.md` 不含 Gecko，它在 `app/v2.9.2` 引入且官方标注 experimental，依据为官方文档站 Protocol.md 与 `extras/obfs/gecko.go` |
| 2 | TUIC v5 帧类型、认证、UDP 两种承载、0-RTT | `tuic-protocol/tuic` SPEC.md | sing-box 实现 | **已核对**：五种命令、`Packet` 字段顺序 `ASSOC_ID\|PKT_ID\|FRAG_TOTAL\|FRAG_ID\|SIZE\|ADDR` 一致；Address `0xff/0x00/0x01/0x02` 一致；认证前命令暂停后恢复一致；Connect 无响应一致；UDP full-cone 一致（`tuic.rs:1099-1113`）；回程镜像首包载体一致。**两处偏差**：①客户端无周期性 `Heartbeat` 命令，改用 QUIC PING `keep_alive_interval`（`tuic_client.rs:152`）；②`Address::None` 非首分片约束只对发送侧强制，接收侧宽松接受（`tuic.rs:1352-1461`） |
| 3 | AnyTLS 帧命令、paddingScheme、复用要求、v2 特性 | `anytls/anytls-go` protocol.md | `sing-anytls` 源码 | **已核对**：11 个命令编号一致；默认 paddingScheme 逐字节一致；认证为 `sha256(password)` + BE uint16 padding 长度 |
| 4 | Naive padding 层是否与 naiveproxy 非正式规范逐字节一致 | naiveproxy README | `forwardproxy` 源码 | 未核对 |
| 5 | NW3 ALPN、认证、Morph、UDP 载体 | `Nowhere-Protocol` PROTOCOL.md | `vendor/nowhere` 实现 | 未核对 |

---

## 五、本页未核实的内容

1. Naive padding 层是否与 naiveproxy 非正式规范逐字节一致（未逐字节比对）。
2. TUIC 的 QUIC 传输细节（Heartbeat 周期、0-RTT 复用）未与 SPEC 逐条比对，仅核对了命令与帧布局。
3. Hysteria 2 的 Gecko 分片/填充**分布**属发送端自由选择，规范明确不协商，无法也不应逐字节核对；只核对了区间与帧布局。
4. Surge 的 Snell 是否存在任何公开的部分规范。
5. `NodePassProject/Nowhere-Protocol` 的 PROTOCOL.md 内容未读。
6. Hysteria 2 的 TCPResponse `Message` 字段语义、错误分类未与规范逐条比对。

---

## 六、已核对：NW3（含一处上游自相矛盾）

核对方式：以 `NodePassProject/Nowhere-Protocol` 的 `PROTOCOL.md` 为规范，逐条比对
`vendor/nowhere` v3.3.0（官方 Rust 实现，整包复用）。

**结论：规范内的项全部一致**，包括 ALPN `nw3`、认证派生链（含
`vector-authentication`、exporter label、`transport` 0x01/0x02、tag 取前 16 字节）、
AuthFrame 恰好 16 字节、FlowStart 单字节与 bit0、Target 的 ATYP `01/03/04`
及域名校验、SetupResult 0–4、QUIC `flow_id = (stream_id >> 2) + 1`、
TLS UDP 的 2 字节长度帧、DATAGRAM base word（Type 在 bits 31..30）与
FRAGMENT 附加 8 字节头、Morph 密钥派生（`nowhere/nw3/morph` 不先 hash）。

### 上游自身的不一致（不是 dubhe 的 bug）

`vendor/nowhere/src/transport/morph/prelude.rs` 与官方 v3.3.0 发布版逐字节一致
（`THIRD-PARTY.md` 未列该文件为本地修改），但它与 `PROTOCOL.md` §12.2 冲突：

| | 规范 | 官方实现 |
|---|---|---|
| TCP prelude 内容 | 「64-byte **random** prelude」，接收方「**without interpreting**」，且「must not reject a prelude because its bytes do not match a particular distribution」 | 后 32 字节编码 28 字节 payload（identity 8 + counter 6 + HMAC tag 14）并经 7-bit 打包；接收侧**验证 HMAC**，失败即拒绝 |

后果：官方 Nowhere 客户端与 `vendor/nowhere` 互通正常（同一实现），但**严格按
PROTOCOL.md 只发纯随机 prelude 的第三方实现会握手超时**（`src/portal/conn.rs`
把 `InvalidData` 静默挂起直到超时，无明确报错）。

**处理决定：不修改 `vendor/nowhere`。** 理由是该行为是官方实现的既定行为，
单方面改会破坏与官方客户端的互通；而 dubhe 的目标是「与官方客户端互通」。
此差异记录在此，供实现第三方客户端的人参考。

### 本仓库的覆盖缺口

`tests/nw3.rs` 的 17 处 `morph` 全部为 `false`/`0`，而 `morph` 默认值为 `true`
（`src/config/inbound.rs:851`）。**默认路径无测试**。这不是协议问题，是测试缺口。
