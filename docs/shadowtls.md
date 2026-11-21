# ShadowTLS v3（已实现待集中验收）

本批原生实现 ShadowTLS **v3 服务端**，并新增无目标的 **v3 出站 detour**，
固定参考 `sagernet/sing-shadowtls` 的 `v3_server.go`、`v3_conn.go`、
`service.go` 与 `v3_client.go`。当前状态为 **已实现待集中验收**；服务端
3 项、出站 5 项本机回环与 10 项记录/配置测试通过；另已通过 sing-box v1.14.4
双向与 Mihomo v1.19.33 `ss + shadow-tls` 插件入站有限互通。三平台、MSRV 或
release 结果仍无，不能从本说明推导完整兼容结论。

## 配置

模板为 `examples/shadowtls.json`，示例中的 `detour` 指向同配置内的
Shadowsocks 入站。必须先替换随机密码；仓库不附带生产凭据。

```json
{
  "type": "shadowtls",
  "tag": "shadowtls-in",
  "listen": "0.0.0.0:8443",
  "version": 3,
  "users": [{ "name": "user", "password": "REPLACE_ME" }],
  "handshake": { "server": "www.example.com", "server_port": 443 },
  "handshake_for_server_name": {
    "cdn.example.com": { "server": "cdn-real.example.com", "server_port": 443 }
  },
  "wildcard_sni": "authed",
  "strict_mode": true,
  "detour": "ss-in"
}
```

- `version` 缺省为 3，且只接受 3；v1/v2 不实现。
- `users` 非空，名称唯一；密码 1–4096 字节，允许不同用户共享同一密码
  （与上游一致）。
- `handshake.server` 可为 IP 字面量或 ASCII 域名，`server_port` 不得为 0。
- `handshake_for_server_name` 按 ClientHello SNI 精确选择伪装握手目标；未命中时
  使用 `handshake`。域名键必须为 ASCII、长度 1–253。
- `wildcard_sni` 支持 `"authed"` 与 `"all"`：未配置映射时，前者仅在认证成功后
  使用 `SNI:443` 作为伪装目标，后者在未认证回落时也使用；缺省关闭。
  该连接只用于完成真实 TLS 握手，不承载内层业务。
- `strict_mode` 为真时，若伪装服务器的 ServerHello 未声明 TLS 1.3，则不再
  认证内层流量，而是退化为透明双向复制。
- `detour` 必须引用同配置内的明文 TCP 入站：`shadowsocks`、`snell`、
  `socks5`、`http`、`mixed`，或不带证书的 `vmess`。指向自身、TLS 入站或
  其他类型会在配置校验阶段拒绝。

## 线协议要点

1. 读取首个 TLS 记录并要求为不跨记录的 ClientHello；`frame[5] == 1` 且
   session_id 长度必须为 32。
2. session_id 末 4 字节是
   `HMAC-SHA1(password, ClientHello[5..] 去掉该 4 字节并补四个 0)` 的前 4 字节。
3. 校验失败时把缓存的 ClientHello 原样写到伪装服务器，然后双向复制；这是
   普通 TLS 客户端看到的正常回落。
4. 校验成功时向伪装服务器转发 ClientHello，读取 ServerHello 回送客户端，
   并从 ServerHello 的 random 字段提取 32 字节 `server_random`。
5. 握手期：
   - 客户端发往伪装服务器方向的 `application_data` 记录逐条尝试
     `HMAC(password, server_random || "C" || payload)`；首个匹配的记录被视为
     内层首数据，不再转发；
   - 服务器发往客户端方向的 `application_data` 记录先与
     `SHA256(password || server_random)` 循环异或，再追加
     `HMAC(password, server_random || payload...)` 的前 4 字节并更新长度。
6. 认证完成后每条记录为
   `[0x17, 0x03, 0x03, len BE16][4 字节 HMAC][payload]`，写入方向按
   `server_random || "S"` 起链，读取方向按 `server_random || "C"` 起链，
   每条记录把自身前 4 字节 HMAC 追加进链；单条写入上限 16384 字节。
7. 校验失败或收到 alert 时尽力发送随机 alert 记录并关闭。

实现使用 `aws-lc-rs` 的 HMAC-SHA1 上下文与 SHA-256，不自研密码原语；
HMAC 上下文可克隆，用于计算“当前链前缀”而不破坏后续链状态。

## 内层 detour

认证后的明文流直接交给目标入站的既有协议实现，不经过二次网络监听：

- Shadowsocks：复用 `serve_generic`，2022 认证失败仍执行零 linger 关闭；
- Snell：复用 `serve_stream`；
- SOCKS5：只接受 CONNECT；UDP ASSOCIATE 返回 SOCKS5 状态 7，因为内层流没有
  独立的 UDP 控制套接字；
- HTTP：复用既有 CONNECT/绝对 URI 处理；
- Mixed：先读 1 字节判别 SOCKS5/HTTP，再复用上述路径；
- VMess（无 TLS）：复用 AEAD 认证与 Mux/UDP 分派。

## 已知边界

- 未配置 SNI 映射与 wildcard 时，伪装服务器为全局配置；v1/v2 仍不支持。
- 不支持 v1/v2、`detour` 指向 TLS 入站、内层 UDP/QUIC。
- 握手与首个合法内层记录的等待受 `limits.handshake_timeout_ms` 约束；上游
  在该阶段没有超时，本实现按内核资源策略主动终止。
- **伪装握手目标经本内核路由与出站选择建立**，不是上游的专用 handshake
  dialer；因此路由规则可以拒绝或改写伪装握手目标，并按入口 tag 计入统计。
  需要严格隔离伪装流量时，应为该入口配置独立、确定的出站规则。
- 未认证回落连接的生命周期由双向复制决定，不再套握手超时。
- 内层协议的路由与计量沿用目标入站 tag；外层 ShadowTLS tag 只出现在连接
  日志与错误分类中。
- `Verified` 写方向不发送外层 TLS `close_notify`，与上游一致；关闭时直接
  关闭底层 TCP 写端。

## 验证状态

`cargo check --all-targets` 通过；`src/transport/shadowtls.rs` 内含不依赖网络
的 HMAC/记录层单元测试。新增 `tests/shadowtls.rs` 两项本机回环测试：

- `authenticated_client_reaches_the_detour_inbound`：构造带 v3 HMAC 的
  ClientHello，经固定伪装服务器返回 TLS 1.3 ServerHello 后，以
  `server_random` 派生双向链发送 SOCKS5 问候与 CONNECT，验证 detour 明文
  SOCKS5 实际转发到回环 echo，且每帧记录 HMAC 校验通过；
- `handshake_for_server_name_selects_the_mapped_target`：ClientHello 携带 SNI
  时使用映射的伪装服务器完成握手中转；
- `unauthenticated_client_hello_falls_back_to_handshake_server`：密码不符的
  ClientHello 原样转给伪装服务器并进入双向复制，客户端收到伪装服务器的标记。

测试中的伪装服务器只返回形状合法、带 `supported_versions` 的 ServerHello，
不执行真实 TLS 握手。Mihomo v1.19.33 插件入站有限互通已另行通过；完整官方
客户端矩阵、三平台、MSRV 与 release 验收仍未执行；`examples/shadowtls.json`
继续只作占位模板。

## 11. v3 出站门禁核查（2026-11-12，只读）

固定上游 `sagernet/sing-shadowtls@v0.2.2-0.20260928201441-a9c0127d5c99`
（commit `a9c0127d5c99401c7706b66f3c62473060721997`，GPL-3.0-or-later；
`sing-box v1.14.4` 固定同一 pseudo-version）。本机只读核查结论：

- 上游出站 `DialContext` **只拨 ShadowTLS 服务器并完成外层真实 TLS**，没有业务
  目标参数；业务目标由链在其后的下游出站自己写入。它只承载 TCP 内层字节流，
  没有 UDP。不能把现有 `via` 的 CONNECT 链语义直接当作 ShadowTLS detour。
- 协议固定使用 32 字节 legacy session ID（28 随机 + 4 字节 HMAC-SHA1）、
  `SHA256(password || server_random)` KDF、4 字节 HMAC tag 和
  `[0x17,0x03,0x03,len][tag][payload]` 内层记录；不得替换为自研原语或更长 tag。
- TLS 1.3 early data/0-RTT 不可能（内层链依赖 ServerHello random）；REALITY
  不能与 ShadowTLS 叠加（两者占用同一 legacy SID）；TLS 1.2 会话 ID 恢复同样
  冲突；参考客户端不复制 ECH，ECH 应视为不支持。
- 当前冻结 rustls 的 `BuildsSessionId` hook 可用于 SID 注入。HRR 对等已获
  用户明确授权，并以默认关闭的 `Config::new_allow_hrr` 最小放行实现：ECH 与
  early data 继续拒绝，CH2 保留 CH1 SID；服务端 REALITY 默认行为不变。补丁
  元数据已按当前 `vendor/rustls/PATCHED.json` 重新复现，另有独立门禁记录。
- 出站集成选择新增无目标的 `type:"shadowtls"` detour 连接器（接近上游），由
  下游代理经 `via` 引用；没有采用给每个现有代理出站增加 ShadowTLS 层的方式。
  该选择同时保留任意受支持的内层 TCP 代理组合。
- 依赖已具备（aws-lc HMAC-SHA1/SHA-256、rustls、tokio-rustls、subtle、sha2），
  不需要新 crate；实现前仍需决定 HRR、TLS 版本/strict、ECH、外层信任源/ALPN、
  下游内层协议范围和官方验收矩阵。

上述依据与门禁已转为本批实现；详见下节。官方客户端/三平台/MSRV/release 验收仍未执行。

## 12. ShadowTLS v3 出站 detour（已实现待集中验收）

出站为**无业务目标**的 `type: "shadowtls"` 连接器，只拨 ShadowTLS 服务器并返回
认证后的内层 TCP 流。它不能作为路由终端，也不能承载 UDP；必须由另一 TCP 代理
出站通过 `via` 引用，且该出站 `endpoint` 必须与 ShadowTLS `endpoint` 完全一致。
支持的内层协议沿用现有 `via` 链（Shadowsocks、Trojan、VLESS、VMess、SOCKS5、
HTTP、AnyTLS、Snell、Naive 等），内层协议自己的 TLS/传输层在 ShadowTLS 流之上
继续建立，不会重复套外层 ShadowTLS TLS。

```json
{
  "type": "shadowtls",
  "tag": "stls-out",
  "endpoint": "stls.example:443",
  "password": "REPLACE_WITH_RANDOM_SECRET",
  "tls": {
    "ca_file": "/etc/ssl/private/shadowtls-ca.pem",
    "server_name": "stls.example"
  }
}
```

内层代理示例（Shadowsocks 通过该 detour）：

```json
{
  "type": "shadowsocks",
  "tag": "ss-out",
  "endpoint": "stls.example:443",
  "method": "2022-blake3-aes-128-gcm",
  "password": "BASE64_KEY",
  "via": "stls-out"
}
```

- `version` 固定为 3；不接受 v1/v2、UDP、ECH、TLS1.3 early data/0-RTT 或 TLS1.2
  会话恢复。外层固定真实 TLS 1.3（显式 CA、`server_name` 必须是 DNS 名），
  不使用 REALITY 临时证书/KX 或系统根证书；TLS1.2 握手不会被视为已认证。
- 客户端移植固定上游 v3 记录层：32 字节 legacy SID、`SHA256(password ||
  server_random)` KDF、握手期 XOR/HMAC、双向 4 字节 HMAC 链，以及首个
  ServerHello/HRR 一次性 seed。HRR 使用最小 rustls `allow_hrr` SID 放行，
  CH2 保留 CH1 SID；ECH/early data 继续拒绝。
- 认证失败、TLS/记录校验失败、按 `via` 链端点不一致、终端选择或 UDP 使用均
  失败关闭；不会回落普通 TLS 或直连。主文档和测试只证明本机回环组合，不证明
  官方客户端互通。
- 本机证据：客户端记录层 9 项单测、配置校验 1 项、独立集成 5 项（真实
  TLS 内层 Shadowsocks、真实 HRR 双 ClientHello、错误密码、SOCKS5 UDP
  ASSOCIATE 不直连无回包、配置负例）；该批全量 1469/0/43（MASQUE 删除前历史）。vendor HRR
  补丁已由独立空目录复现，vendor 定向测试 13/0。
- 官方 sing-box v1.14.4 darwin/arm64 本机双向互通已通过：官方客户端 →
  本内核服务端、本内核出站 → 官方服务端，均使用 v3 + 内层 Shadowsocks
  2022 与真实本机 TLS 1.3 伪装目标。该过程发现并修复连续两张 TLS 1.3
  NewSessionTicket 时旧链只丢弃第一条的缺陷；现在与上游一致连续丢弃旧链残留。
  另已用 Mihomo v1.19.33 的 `ss + shadow-tls` 插件完成到本内核入站的 TCP
  本机互通（`skip-cert-verify` 必须放在 `plugin-opts` 内）。这仍只是有限
  版本/平台/配置形态，不代表 Xray、三平台、MSRV 或 release 验收。完整命令与
  失败修复见[开发记录](shadowtls-outbound-development.md)。
