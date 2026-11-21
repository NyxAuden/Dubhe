# ShadowTLS v3 出站 detour 开发记录（2026-11-12）

状态：**已实现，本机集中验收通过；官方客户端/三平台/MSRV/release 未验收**。
本批只新增无目标的 ShadowTLS v3 出站及其最小 rustls HRR 放行，不改变既有
ShadowTLS v3 服务端、其它出站或 `via` 链的正常语义。

## 固定参考

- `sagernet/sing-shadowtls@v0.2.2-0.20260928201441-a9c0127d5c99`
  （commit `a9c0127d5c99401c7706b66f3c62473060721997`，GPL-3.0-or-later），
  与 `sing-box v1.14.4` 固定同版本。
- 上游 `v3_client.go`、`v3_conn.go`、`client.go`、`v3_constrat.go`：
  SID 生成、握手期 streamWrapper、首 ServerHello/HRR seed、认证后双向
  HMAC 链与 16 KiB 写记录。
- 上游出站没有业务目标、没有 UDP；本内核按同一角色实现，不新增协议扩展。

## 实现

- 新增 `src/transport/shadowtls/client.rs`：
  - `SidBuilder` 实现 rustls `BuildsSessionId`：28 随机字节 + HMAC-SHA1
    `zero_hello[..39] || sid[..28] || 0^4 || zero_hello[71..]` 前 4 字节。
  - `ShadowTlsStream` 位于 TLS 之下，一次处理一条原始记录；首个
    ServerHello/HRR 一次性 seed，握手期 server application_data 校验
    HMAC、XOR 还原并去 4 字节 tag；读取链只推进 payload（与上游一致）。
  - `ClientVerified`：读链 `server_random||"S"`、写链 `server_random||"C"`，
    认证后链均为 payload 再 tag；首条旧链记录由 `hmac_ignore` 丢弃；alert、
    非法类型、短记录、坏 tag 失败关闭；写端 16 KiB 分片、pending 完整排空
    后才报告段长。
  - `ShadowTlsClient::connect` 使用 `Controlled` 精确记录边界完成真实 TLS，
    成功后切换 raw 流并返回内层 TCP；固定 strict TLS1.3，TLS1.2 回落返回
    Unsupported，不重连、不回落普通 TLS、不接收目标。
- 新增 `OutboundKind::ShadowTls`、`ProxyOutbound.shadowtls` 与配置校验：
  `endpoint`、`password`（1–4096 字节）、`tls.ca_file`、显式 DNS
  `tls.server_name` 必需；禁止 reality/uuid/transport/UDP/组字段等。
- `via` 链：只允许一侧 ShadowTLS detour，下游 endpoint 必须与 ShadowTLS
  endpoint 一致；`proxy_transport_factory` 对 ShadowTLS 跳过普通 TLS；
  `tunnel_factory` 在上一跳为 ShadowTLS 时完成 v3 并返回内层流。
  ShadowTLS 自身禁止 `via`，不能作为 route/default/rule/selector/urltest
  终端；终端选择、裸端点/UDP 调用另有运行期 Unsupported 兜底。
- `src/tls/controlled.rs` 增加 `into_raw()`：只在握手结束、读写均已切 raw、
  无未消费记录时返回底层流，任何边界不完整都失败关闭。
- `src/forward.rs` 增加 `Upstream::from_parts_send`：aws-lc `HmacContext`
  只 `Send` 不 `Sync`，用短临界区锁包装 `ClientVerified`，同时保留
  local_addr 与管理连接句柄。

## vendor/rustls 最小 HRR 扩展

- `rustls::client::reality::Config::new` 保持 `allow_hrr=false`；
  新增 `new_allow_hrr` 供 ShadowTLS 使用。ECH/early data 仍无条件拒绝；
  CH2 不调用 builder、不置零 SID，完整保留 CH1 SID。REALITY 默认行为不变。
- 本批记录的 `vendor/rustls/PATCHED.json` `patch_sha256`：
  `9deec0610cf8db1ca5513509e2e13190c79ac8b5776ab3abb05add94f585dc2f`
  （历史快照；当前值以 `PATCHED.json` 和 `REALITY-SOURCE.txt` 为准）。
- `python3 -I vendor/rustls/verify-source.py --archive <rustls-0.23.46.crate>
  --empty-dir <全新空目录>` 实际通过：129 个文件、归档 SHA256
  `48e13bd8...8fdf`。临时目录已清理。
- vendor 定向测试实际 **13 passed、0 failed**；feature 关闭的 ring/std/tls12
  rustls 直接编译退出 0。`run-tests.py` 本身因当前锁同时存在 rcgen 0.13.2
  与 0.14.10，`cargo build -p rcgen` 报 ambiguous；本批按同一脚本逻辑改用
  `-p rcgen@0.13.2` 显式构建并执行上述测试，未修改脚本或补丁元数据。

## 验证

- `cargo check --locked --offline --lib`：退出 0；`--all-targets`：退出 0。
- `cargo test --locked --offline --lib shadowtls::client`：9 passed。
- `cargo test --locked --offline --lib
  shadowtls_outbound_is_via_only_and_matches_detour_endpoint`：1 passed。
- `cargo test --locked --offline --test shadowtls`：3 passed（服务端回归）。
- `cargo test --locked --offline --test shadowtls_outbound`：5 passed：
  真实 TLS + 内层 Shadowsocks 回环、真实 HRR（独立记录转发器实际计数
  2 个 ClientHello）、错误密码失败关闭、SOCKS5 UDP ASSOCIATE 经 ShadowTLS
  via 不直连且无回包、配置负例。
- 最终全量 `cargo test --locked --offline`（`CARGO_INCREMENTAL=0`）：
  **1469 passed、0 failed、43 ignored、83 个结果块（MASQUE 删除前历史）**；日志
  `/tmp/rpk-shadowtls-full-validation5.log`。官方互通修复后的首次全量复跑中，
  `tests/cli.rs` 的 `unix::sighup_rotates_certificate_without_restarting_listeners`
  曾因随机端口 `AddrInUse` 失败一次；单独重跑该目标 15/15 通过，随后全量
  1469/0 通过，未修改测试或放宽断言。
- `cargo clippy --locked --offline --lib`：退出 0；`--all-targets` 仍被既有
  `tests/snell.rs` 等测试的
  `never_loop` lint 阻断，本批未改这些测试，不能记为全目标 clippy 通过。
- 全目标 `cargo check` 仍有项目既有死代码/未用导入警告；本批新增路径无
  ShadowTLS 编译 warning。

## 官方 sing-box v1.14.4 本机互通（2026-11-12）

按用户授权，仅下载官方发布二进制到独立临时目录并在回环地址运行；不修改
系统网络/代理/DNS/权限，不连接公网目标。

- 官方资产：`sing-box-1.14.4-darwin-arm64.tar.gz`，SHA256
  `0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838`；
  二进制自报 `sing-box version 1.14.4`、revision
  `c005f35300ce76427dc285481ec5695f5b179cd2`、darwin/arm64。
- 方向 A（官方 sing-box 客户端 → 本内核 ShadowTLS 服务端）：官方
  `shadowtls` v3 outbound + `shadowsocks` 2022 outbound detour，经本内核
  ShadowTLS 入站转发到本内核 Shadowsocks detour；本机 HTTP GET 实际返回
  `official-interop-ok`，退出 0。
- 方向 B（本内核 ShadowTLS 出站 → 官方 sing-box 服务端）：官方
  `shadowtls` v3 inbound + Shadowsocks 2022 inbound detour，本内核
  `shadowtls` detour + Shadowsocks 出站；本机 HTTP GET 返回
  `official-interop-ok`，退出 0。
- 真实 TLS 伪装目标均为本机 `openssl s_server`（OpenSSL 4.1.0，自签
  CA:FALSE/`localhost` 证书）；没有接公网伪装站点。
- 方向 B 首次失败暴露真实缺口：官方服务端在握手后连续下发两张 TLS 1.3
  `NewSessionTicket`（各 78 字节 application_data），本实现原先把
  `hmacIgnore` 当“只丢弃第一条”，第二张被误交给认证后读链并以 HMAC 失败
  关闭。已改为与固定上游一致：旧链匹配时保留并继续推进，连续丢弃所有旧链
  残留，首次不匹配才切到 `server_random||"S"` 链；单测改为
  `verified_ignores_consecutive_old_chain_records` 覆盖两条残留记录。
  修复后方向 B 通过。
- 结论边界：这是 **sing-box v1.14.4 / macOS ARM64 / 回环 / 单一配置形态**
  的本地互通，不是官方全矩阵、三平台、精确 MSRV 或 release 验收；Xray-core、
  Mihomo、Mihomo/Clash 客户端和其它 ShadowTLS 配置形态仍未测试。

## 明确边界

- 不支持 UDP、v1/v2、ECH、TLS1.3 early data/0-RTT、TLS1.2 会话恢复或
  REALITY 叠加；ShadowTLS 不能作为终端出站。
- 外层使用 rustls 标准 ClientHello，未复制上游可选 uTLS/浏览器指纹；本实现
  只对齐 ShadowTLS v3 协议与真实 TLS1.3 外观，不宣称 TLS 指纹等价。
- 未与官方 sing-box/ShadowTLS 客户端、三平台、精确 MSRV 或 release 互通；
  本机 SS-over-ShadowTLS 与 HRR 只证明当前输入下的回环组合。
- 未修改系统网络/代理/DNS/防火墙/权限，未提交或发布。
