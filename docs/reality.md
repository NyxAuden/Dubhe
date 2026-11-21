# VLESS/VMess/Trojan + REALITY 服务端（已实现待集中验收）

本批固定基线为 Xray v26.10.31（`a4a3dff5b20c2faae567b742c172c7b95e75c083`）及 REALITY `83f621788ca88b83179810b12baa7ae518aacb83`。这是独立 Rust 服务端的协议编排实现，不启动参考内核、不复制 MPL/GPL 模块。服务端开发段21/29完成，同一输入的31条开发门禁命令全部退出0；其余8项集中验收保持待完成。另已增量接入 VLESS/VMess/Trojan 的 REALITY **出站**，不计入服务端21/29，见下文“REALITY 出站”。实际命令、输入摘要及逐任务证据见[开发记录](reality-development.md)，依赖门禁见[依赖报告](reality-dependency-gate.md)。已用固定 Xray v26.10.31 完成 VLESS/VMess/Trojan REALITY 的双向 TCP 本机互通（VLESS 含 Vision flow，固定目标为本机 TLS 1.3 服务）；三平台、精确 Rust1.91 与 release 仍未验收，不把单版本有限互通写成完整兼容。

## REALITY 组合矩阵

独立的 RAW（TCP）REALITY 入口为 `vless-reality`、`vmess-reality`、`trojan-reality`；
REALITY 也可作为以下入口的安全层：

- `vless-grpc` / `vmess-grpc` / `trojan-grpc`
- `vless-xhttp` / `vmess-xhttp` / `trojan-xhttp`

这是 Xray REALITY 的上游支持范围：**仅 RAW、XHTTP、gRPC**。WebSocket 与
HTTPUpgrade **不组合 REALITY**，配置阶段直接拒绝；mKCP/QUIC/XHTTP h3 等 UDP
承载同样拒绝。仓库不提供“WS + REALITY”或“HTTPUpgrade + REALITY”的非上游扩展。

配置方式是在入口内增加 `reality` 对象，并**不再配置** `certificate`/`private_key`；
二者互斥，也不能与 `allow_insecure_transport` 同时出现。REALITY 完成后，gRPC/XHTTP
处理器直接运行在 REALITY 解出的明文流上：

- gRPC 要求 ALPN 为 `h2`；
- XHTTP 依据 ALPN 选择 h2 或 h1；`xhttp.h3: true` 使用 QUIC，不能与 REALITY 组合；
- 证书轮换、回落目标与握手超时语义与既有安全层保持一致。

配置组合校验由 `tests/reality_composition.rs` 覆盖；gRPC/XHTTP 的 REALITY 数据面
尚未逐组合做官方客户端验收。

## 两层认证与承载

新增独立 `type:"vless-reality"`、`type:"vmess-reality"` 与 `type:"trojan-reality"`，保留旧 `vless`/`trojan` 的证书/私钥语义。REALITY 的静态 X25519、SNI、shortID、版本和时间策略先验证承载；完成 TLS1.3 ClientFinished 后，VLESS UUID/flow、VMess AEAD 用户表或 Trojan 密码才决定代理身份。shortID 不是 UUID，也不是用户计量标识。VMess REALITY 复用 VMess AEAD、Mux、原生 UDP/XUDP/packetaddr 与安全策略；Trojan REALITY 复用 Trojan 的 TCP 与逐包 UDP，二者均不额外接受 `certificate`/`private_key` 或 fallback 配置。

- 无 flow：TCP、原生固定目标 UDP；命令 3/`v1.mux.cool` 进入完整 Mux，TCP 会话始终允许，UDP New/GlobalID 默认准入，`xudp:false` 时关闭，见 [Mux 说明](mux.md)。
- 用户 `flow:"xtls-rprx-vision"`：TCP 或命令 3 Mux（TCP；`xudp` 门控 UDP），复用现有 Vision 双向 Continue/End/Direct；原生 cmd2、未知 flow 拒绝，不能降级为空 flow。Vision + 命令 3 仍要求外层 TLS1.3。
- 业务路径使用既有路由、DNS、连接/UDP/排队预算。Reject 先于业务 DNS/拨号和成功响应。辅助目标的 IO 与业务目标 IO 必须分开理解：错误 UUID 可以已有辅助 TLS 目标访问，但没有代理业务访问。
- REALITY、VLESS、Vision、目标辅助和回落字节均不计业务载荷；只按业务接口实际成功的 `Ok(n)` 计量，不代表远端收讫或财务计费。

## 配置与本地示例

模板为 [`examples/vless-reality.json`](../examples/vless-reality.json)，只给回环监听和自持回环目标。它含刻意无效的占位凭据，必须替换 UUID、32字节静态私钥和 shortID，准备本机普通 TLS1.3 目标后才可检查/启动。该目标须在本实现支持的有限布局内；普通证书受信任不等于 REALITY 承载认证通过。

```sh
cargo build --locked
./target/debug/dubhe check -c "examples/vless-reality.json"
./target/debug/dubhe run -c "examples/vless-reality.json"
```

以上仅为替换占位后的命令形态，不表示原模板可直接运行，也不是公网目标选择或流量外观调优指南。`check` 只做 JSON、限额、本地密钥/证书准备；不 bind、不 DNS、不连接目标。

| `reality` 字段 | 约束 |
|---|---|
| `target` | 必填 `{host,port}`，合法 IP/ASCII 域名、端口1..65535；不是 URL，不从客户端 SNI 取拨号地址 |
| `private_key` | 无 padding 的规范 base64url，解码32字节 X25519 私钥；全零原始值拒绝 |
| `server_names` | 1..64个 ASCII DNS 名，≤253字节，精确区分大小写匹配；不通配、不重复 |
| `short_ids` | 1..256个 hex 字符串，偶数长度0..16字符，右补零至8字节后查重；空串须显式配置 |
| `max_time_diff_ms` | 默认120000，允许1..600000；不能0关闭 |
| `min_client_version` / `max_client_version` | 可选三字节数组，含端点；同时设置须 min≤max |
| `mldsa65_seed` | 可选规范无 padding base64url32；显式 null/空值拒绝，不静默降级 |
| `fallback_idle_timeout_ms` | 默认10000，1..60000 |
| `fallback_max_duration_ms` | 默认60000，1..300000，且不小于 idle |

每新入口用户数1..1024，`xudp` 默认 true。独立全 Server 精确重放池 `limits.max_reality_replay_entries` 默认65536，允许1..1048576。

序列化配置仍含配置秘密，不能当作脱敏输出公开。错误/Debug/运行日志不输出私钥、种子、shortID、原始 CH/SID、AuthKey 或 UUID。固定 target 拨号前拒绝 unspecified、与任一本 Server 监听相同的具体地址/端口、回环别名同端口；wildcard 监听保守拒绝同端口，即使某地址可能远在其他主机。不能识别所有 NAT 自环，也不是通用 SSRF 过滤。

## 密码与 TLS 边界

静态认证与本地临时 TLS KX 严格分开。成熟库完成 X25519/HKDF-SHA256/AES256GCM/HMAC-SHA512/Ed25519/ML-KEM/ML-DSA，rcgen 编码 DER。SID 的 AAD 是仅 SID 内容清零的完整原始握手 CH（含4字节握手头，无 record 头），原密文 SID 保留用于 TLS transcript。

认证要求1216字节 X25519MLKEM768 share 在可选普通 X25519 share 前；两公钥可不同。认证优先普通 share，否则取 hybrid 末32字节。TLS 最终组由目标 SH 的普通 X25519 或 hybrid 选择，使用本地新鲜临时 KX，不能复用静态认证私钥或目标 TLS 秘密。

证书 Ed25519 SPKI 是真实公钥，X.509 `signatureValue` 是64字节 `HMAC-SHA512(AuthKey,pub32)`；正常 CertificateVerify 仍由对应真实 Ed25519 私钥签 transcript，Finished 继续由 TLS 状态机验证。可选 ML-DSA-65 用32字节 seed、pure/空 context，首扩展 OID0.0，签名消息为 `HMAC-SHA512(AuthKey,pub32 || 原始CH || 最终原始SH)`。同 seed 公钥及双向签名已用本机 Python cryptography 与 AWS-LC 独立跨库验证，但这不是官方内核矩阵。

rustls 精确0.23.46保留三份许可及[来源/补丁](../vendor/rustls/REALITY-SOURCE.txt)。`reality` feature 默认关闭，普通 ServerConfig 默认 None；根项目启用 feature 并不使普通入口开启握手钩子。旧入口仍局部 ring，新入口局部 AWS-LC，不安装全局 provider。所有入口编译同一补丁 crate，因此普通 TLS 需要回归，不能声称旧路径完全不受影响。补丁只提供受限目标组/套件、等长最终 SH share、SH 后证书回调和有限 record 计划，以及出站所用的逐连接 SID 构建与 auth key 派生钩子；不导出 traffic secrets，不绕过证书/CV/Finished 或 AEAD 限额。

## 固定目标、有限模板和回落

先有界 CH 分类/认证，成功后原子提交重放键，再拨配置唯一目标。每 accepted TCP 同时最多一条辅助连接。结构合法但认证/策略不匹配可以原始固定目标回落；畸形/超限/实际 PSK/early_data/精确重放或满池直接关闭。仅 `psk_key_exchange_modes` 不等于实际 PSK，不误拒。

目标只收到原始 CH prefix。下行采集最多131072字节/32 record，单 record payload最多18432；模板要求 TLS1.3、SID echo、支持的组/套件和已知扩展，不支持 HRR。目标加密内容不可解密：只观察 opaque record 长度/顺序，槽名不代表认证了目标 Certificate 或 Finished。

本地初始 flight 仅支持：第一个加密 record 总长>512 时聚合 EE..Finished；否则四个独立消息 record。可选同次已缓冲完整第七槽只生成本地 application key 下空 application record，不生成可恢复 ticket。零 padding、序号和 AEAD 全由 rustls 原记录层管理；TLS1.3 可发上限（record总长16406）不同于18432预读上限。目标槽位放不下本地真实证书/ML-DSA 时改用自然 record 长度（与 Xray 不要求逐 record 等长一致）；只有布局不完整/不兼容或超出 TLS 上限时，才在首次本地输出提交前回原目标，不截消息。

原目标及已读下行保持到全部本地 flight 在有界内存预检成功。失败回落使用同一原连接，不再另拨；原文和半 record 恰一次回放。首次 poll 本地输出前即不可逆关闭回落选项，即使首写 Pending 或短写也不能拼接目标路径。之后 ClientFinished、UUID、flow 错误只关闭，不重落。回落独立小缓冲双向复制、保留半关闭，idle仅实际读写推进刷新，总期限不被持续流量延长；不占业务 TCP/UDP 计数，分类后释放握手许可，全局连接许可保留到实际结束。

## 公开差异与非目标

- 本项目额外要求 reserved=0、时间检查非零、关键扩展/share完整扫描查重、精确 CH 重放池，禁 PSK/early_data/票据/会话恢复；与上游部分可选宽松行为不同。临时证书固定 Ed25519，且与 Xray 一致：即使客户端未在 `signature_algorithms` 中声明 Ed25519，服务端仍以 Ed25519 完成 CertificateVerify。
- 重放键为派生静态公钥+完整密文 SID 的 CH SHA256，同 Server 跨入口共享；同公钥取最大时间窗，TTL=`2*window+1000ms`。满额不驱逐，失败/取消不撤销。单调时钟保护不等于跨 Server/进程/重启的永久重放防御。
- 不启动上游全局 post-handshake 探测，不复刻 `GlobalPostHandshakeRecordsLens` 表，不承诺全部流量外观等价或原生 splice/零拷贝性能。
- REALITY 出站已接入 `vless`/`vmess`/`trojan`；VLESS 无 flow 与 Vision flow、VMess、Trojan 均已与官方 Xray v26.10.31 完成 RAW/REALITY TCP 本机互通；VLESS/VMess/Trojan 的 REALITY-over-gRPC 与 REALITY-over-XHTTP 也已通过，三平台与精确工具链仍未集中验收。VLESS Vision flow 可与 REALITY 出站组合，WebSocket/HTTPUpgrade 与 QUIC/mKCP 等承载不支持。VLESS Encryption 与通用 fallback 仍是独立能力；与上游一致，REALITY 只与 RAW/XHTTP/gRPC 组合；命令 3 的完整 Mux（含 GlobalID 跨承载 1 分钟续接）已接入但属“已实现待集中验收、未测试”。
- 未完成完整官方客户端矩阵/跨平台/精确工具链/release集中验收，不扩称完整替代三家内核；旧 release 不含本批能力。

## 官方 Xray v26.10.31 互通证据

- 官方 Xray 客户端 → 本内核 `vless-reality`/`vmess-reality`/`trojan-reality`：VLESS 无 flow 与 `xtls-rprx-vision`、VMess、Trojan 均通过本机 TCP HTTP GET。
- 本内核 `vless`/`vmess`/`trojan` REALITY 出站 → 官方 Xray 服务端：VLESS 无 flow 与 Vision flow、VMess、Trojan 均通过本机 TCP HTTP GET。
- 固定目标为本机 TLS 1.3 服务。测试暴露并修复两处真实兼容问题：
  1. REALITY 临时证书固定 Ed25519；Xray 客户端（Chrome/uTLS）未声明 Ed25519 时，原实现错误回退。现与 Xray 一致强制 Ed25519 CertificateVerify。
  2. 目标记录槽位小于本地证书时原实现失败；现改用自然 record 长度，仍保持目标 flight 的聚合/分槽形态。
- VLESS（无 flow 与 Vision flow）、VMess、Trojan 的 RAW/REALITY 双向均已通过；VLESS/VMess/Trojan 的 REALITY-over-gRPC 与 REALITY-over-XHTTP（auto）双向也已通过。三平台、精确 MSRV 与 release 未验收。

## REALITY 出站

REALITY 出站是本批新增的增量能力，不计入上面服务端变更的 21/29 任务数。配置位于 `vless`/`vmess`/`trojan` 出站：

```json
{
  "type": "vless",
  "tag": "up",
  "endpoint": "server.example:443",
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "reality": {
    "public_key": "服务端32字节X25519公钥的base64",
    "short_id": "8172635445362718",
    "server_name": "www.example.com",
    "version": "26.10.31"
  }
}
```

- `public_key` 与服务端 `private_key` 配对；接受标准或 URL-safe 无填充 base64。`short_id` 为空或最多 16 个十六进制字符；`server_name` 必须是 DNS 名并用 SNI；`version` 可省略，缺省 `26.10.31`。
- `reality` 与 `tls` 互斥；`trojan` 因此可直接以 REALITY 作为强制安全层，`vless`/`vmess` 也无需证书。与上游一致，只可与 RAW（无 transport）、gRPC、XHTTP 组合；VLESS Vision flow 可与 REALITY 组合，Vision 不能与其它 transport 同时配置，但可与 VLESS Encryption 组合。不能与 WebSocket、HTTPUpgrade、QUIC、mKCP 等承载组合，非法组合在配置阶段拒绝。
- 客户端在 ClientHello 的 32 字节 legacy session ID 中写入版本、Unix 时间戳与 shortId；认证键由本次 X25519 临时私钥与服务端静态公钥经 HKDF-SHA256(`salt=random[0..20]`, `info="REALITY"`) 派生，再用 AES-256-GCM 加密，nonce 取 `random[20..32]`，AAD 是零 SID 的完整 ClientHello。密钥交换同时支持 X25519 与 X25519MLKEM768，混合组保留 X25519 组件用于认证。
- TLS 1.3 服务端临时证书必须满足：无中间证书/OCSP、SPKI 为 32 字节 Ed25519 公钥、证书签名字段为 auth key 的 HMAC-SHA512；CertificateVerify 必须是 Ed25519 且由同一公钥验证。拒绝 TLS 1.2、HRR、ECH、会话恢复、early data 与非 Ed25519 签名；任意一步失败即关闭连接，不回落到明文或目标直连。密码运算全部复用 rustls/AWS-LC/aes-gcm，不自行实现原语；x509-parser 仅做证书 DER 解析。
- 出站可选 `mldsa65Verify`（base64 的 1952 字节 ML-DSA-65 公钥）；配置后与 Xray 一致，在同一 HMAC-SHA512 状态上追加 raw ClientHello 与 raw ServerHello，并用证书第一个扩展的 Value 验签。未配置时只做 HMAC 认证。校验失败按临时证书失败处理，不降级为普通证书信任。出站仍没有 uTLS/浏览器指纹模拟：ClientHello 由 rustls 生成，认证与 TLS 正确性不依赖指纹，但流量外观不等同 Xray 默认客户端。
- 本机 `tests/reality_outbound.rs` 已覆盖：VLESS REALITY 纯 TCP 对 X25519 与 X25519MLKEM768 目标、VLESS 原生 UDP、以及 VLESS/VMess/Trojan REALITY-over-gRPC 的 TCP 回显；ws/httpupgrade 组合在配置阶段被拒绝。已与官方 Xray v26.10.31 完成 VLESS REALITY TCP 与 VLESS Vision+REALITY TCP 的本机双向互通；VMess/Trojan REALITY 出站、三平台、精确 MSRV 与 release 仍属集中验收缺口。
