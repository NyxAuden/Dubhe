# WireGuard 依赖门禁

本批核心依赖只用于 WireGuard 隧道出站；没有新增自研密码原语。

| 依赖 | 固定版本 | 许可 | MSRV / features | 用途 |
|---|---|---|---|---|
| `boringtun` | `=0.7.1` | BSD-3-Clause | edition 2018；`default-features = false`，不启用 `device`/`ffi`/`jni` | WireGuard Noise_IK 握手、封装与解封装 |
| `smoltcp` | `=0.14.0` | 0BSD | `rust-version = 1.91`（与项目声明一致）；`std` + `medium-ip` + `proto-ipv4` + `proto-ipv6` + `socket-tcp` | 用户态 IPv4/IPv6 与 TCP 栈 |
| `h3-datagram` | 0.0.2（`vendor/h3-datagram`） | MIT | edition 2021；仅作为 vendored h3/h3-quinn 的 RFC 9297 数据报适配 | h3-quinn `datagram` feature（Hysteria2 等 QUIC 数据报路径） |
| `bytes` | 1.12.1 | MIT | 既有传递依赖，本批直接引用 | 数据报载荷 |

说明：

- `boringtun` 的传递依赖包含 `chacha20poly1305 0.10.0-pre.1`、`aead 0.5.0-pre.2`
  与 `ring 0.17`；它们与项目已用的 0.11 版本并存，不替换既有密码实现。
- `h3-datagram` 与 `h3`、`h3-quinn` 一样位于 `vendor/` 且不进入 workspace 成员；
  `h3-quinn` 只启用 `datagram` feature，没有改动 HTTP/3 状态机。
- `h3-datagram 0.0.2` 另含一处本地补丁：修正 `Datagram::encode` 把已编码的
  Quarter Stream ID 丢弃、导致所有 HTTP Datagram 都按流 0 发送的缺陷。仅一行
  结构体初始化，不改版本、许可、features、MSRV 或依赖；流 0 字节不变。记录见
  `vendor/h3-datagram/PATCH.md`。
- `h3-quinn 0.0.10` 另含一处本地补丁：`RecvStream::stop_sending` 在读取
  future 持有底层流（`self.stream == None`）时跳过 STOP_SENDING，而不是
  `unwrap()` panic；版本、许可、features、MSRV 与依赖不变，发送侧
  RESET_STREAM/连接关闭不变。记录见 `vendor/h3-quinn/PATCH.md`。
- 上述许可均为宽松许可，与项目 GPL-3.0-only 兼容。
- 本门禁只记录固定版本与编译面；官方 WireGuard 服务端互通、三平台、
  精确 MSRV 与 release 验收仍需另行执行。
