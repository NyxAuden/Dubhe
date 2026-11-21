# HTTPUpgrade 入站边界（开发实现，待集中验收）

本页描述本仓库 HTTPUpgrade 入站的**已实现行为与明确限制**。已与官方 Xray v26.10.31 完成 VLESS/HTTPUpgrade TLS 的双向 TCP 本机互通，以及 Xray XUDP UDP 到本内核入站；完整官方矩阵、三平台、MSRV 与 release 未验收，本地 6 项入站测试不代表完整官方兼容。

## 入口与配置

- 独立入口：`vless-httpupgrade`、`vmess-httpupgrade`、`trojan-httpupgrade`。旧入口行为不变。
- `httpupgrade.path` 必填，1..1024 个 ASCII 可见字符，以 `/` 开头，不含 `#`/`?`。
- `httpupgrade.host` 可选，1..255 个 ASCII 可见字符；配置后要求 Host 完全匹配。
- VMess HTTPUpgrade 必须提供真实 TLS 证书/私钥；明文入口不提供。REALITY 不组合 HTTPUpgrade（Xray 仅支持 RAW/XHTTP/gRPC）。
- VLESS/Trojan 可选 TLS；无证书时必须显式 `"allow_insecure_transport": true`。
- 真实 TLS 只接受协商到 `http/1.1` 的 ALPN；协商到 `h2` 的连接按协议错误关闭。
- 模板见 `examples/vless-httpupgrade.json`、`vmess-httpupgrade-tls.json`、`trojan-httpupgrade.json`。

## 握手

- 必须是 `GET <path> HTTP/1.1`，路径精确匹配；不匹配返回 404。
- 必须包含 `Connection: Upgrade` 与 `Upgrade: websocket`（大小写不敏感，值按逗号分词包含目标令牌）；缺失返回 400。
- 必须且只能有一个 `Host`；重复 Host、带 `Content-Length` 或 `Transfer-Encoding` 的握手返回 400。
- 通过后返回 `101 Switching Protocols`，`Connection: Upgrade` 与 `Upgrade: websocket`。
- 握手成功后同一连接直接承载协议字节流，无帧封装、无 WebSocket masking、无 ping/pong。
- 握手中读到但未消费的残留字节经 `PrefixReader` 在协议层前回放，因此允许客户端把首个协议报文与握手头一起发送（early data）。

## 与 WebSocket 的区别

- HTTPUpgrade 是“一次性升级后返回裸字节流”，没有帧头、没有 masking、没有控制帧，也不支持 `Sec-WebSocket-*` 语义。
- 因此不存在 WebSocket 的 Close 半关闭问题；连接关闭即 TCP 关闭。这是本实现选择 HTTPUpgrade 而非 WS 的主要原因。
- 两者不可互相替代：客户端必须使用对应的传输类型。

## 明确不支持

- HTTP/2 上的 HTTPUpgrade、HTTP/3。
- 任意子协议协商、扩展头、Upgrade 到其他协议。
- VLESS Vision/REALITY 与 HTTPUpgrade 组合。
- 仅 Xray VLESS/HTTPUpgrade TLS 已有运行结果；VMess/Trojan、三平台、MSRV 与 release 未验收。

## 证据

本地测试覆盖 VLESS 明文升级与早期数据、错误路径/缺失 Upgrade/重复 Host、真实 TLS 且 ALPN `http/1.1`、Trojan 与 VMess(TLS) 承载。测试入口 `tests/httpupgrade.rs`。
