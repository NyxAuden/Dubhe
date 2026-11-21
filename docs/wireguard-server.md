# WireGuard 服务端入站（用户态，无 TUN）

状态：**已实现，待集中验收**。本页只描述当前代码行为。已在本机回环完成真实
Noise_IK 握手与隧道内 TCP/UDP echo。2026-11-13 用官方 sing-box v1.14.4 WireGuard
endpoint（macOS ARM64）补齐扩展矩阵：多 peer、可选 PSK、IPv4/IPv6 内层地址的
TCP/UDP 均通过，未知 peer、错误 PSK、错误服务端公钥和越界 `allowed_ips` 源地址
均失败关闭；keepalive、rekey 与空闲清理另有报文级观察。外层 WireGuard UDP 只走
`127.0.0.1`，内层使用 `10.77.0.0/24`（IPv6 为 `fd00:66::/64`），服务端通过 helper
`route-options` 将内层目标改写回回环 echo。sing-box gVisor 会丢弃内层 `127/8`/`::1`
报文，因此没有使用回环内层地址，也没有开启局域网监听。**未与内核 `wg`/
wireguard-tools、Mihomo 客户端、Linux/Windows、MTU/分片、漫游、长稳或高并发
做完整官方矩阵验收，不声称完整官方兼容**。

## 配置

```json
{
  "version": 1,
  "inbounds": [
    {
      "type": "wireguard",
      "tag": "wg",
      "listen": "0.0.0.0:51820",
      "private_key": "<服务端 32 字节 base64 私钥>",
      "address": ["10.66.0.1/24", "fd00:66::1/64"],
      "peers": [
        {
          "public_key": "<客户端 32 字节 base64 公钥>",
          "preshared_key": "<可选 32 字节 base64>",
          "allowed_ips": ["10.66.0.2/32", "fd00:66::2/128"],
          "keepalive": 25
        }
      ],
      "mtu": 1420,
      "max_peers": 256,
      "max_tcp_connections": 256,
      "max_udp_associations": 256,
      "max_queued_datagrams": 1024,
      "max_handshake_inits_per_sec": 50,
      "peer_idle_timeout_secs": 300
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "default": "direct" }
}
```

字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| `tag` | 是 | 入口标识，同时作为路由规则的 inbound 匹配值 |
| `listen` | 是 | UDP 监听地址；`port: 0` 仅用于嵌入/测试，实际端口通过 `Server::local_addr(tag)` 获取 |
| `private_key` | 是 | 服务端静态私钥，32 字节 base64 |
| `address` | 是 | 本机隧道内 IPv4/IPv6 CIDR，数量不超过当前 `smoltcp::config::IFACE_MAX_ADDR_COUNT`（当前构建为 2）；用于用户态接口与 NAT 锚点，超量在配置阶段拒绝 |
| `peers` | 是 | 1-256 个 peer；peer 公钥必须唯一，`allowed_ips` 不得跨 peer 重叠 |
| `peers[].public_key` | 是 | 客户端静态公钥，32 字节 base64 |
| `peers[].preshared_key` | 否 | 可选 PSK，32 字节 base64 |
| `peers[].allowed_ips` | 是 | 1-16 条 CIDR；作为该 peer 隧道内**源地址 ACL** |
| `peers[].keepalive` | 否 | persistent keepalive 秒数；`0`/省略关闭 |
| `mtu` | 否 | 576-1500，默认 1420 |
| `max_peers` | 否 | 1-65536，默认 256；不得小于 `peers.len()` |
| `max_tcp_connections` | 否 | 1-65536，默认 256 |
| `max_udp_associations` | 否 | 1-65536，默认 256 |
| `max_queued_datagrams` | 否 | 1-1000000，默认 1024；同时限制待发送队列与隧道内 RX 队列 |
| `max_handshake_inits_per_sec` | 否 | 1-100000，默认 50 |
| `peer_idle_timeout_secs` | 否 | 1-86400，默认 300 |

配置校验失败即拒绝启动，包括：私钥/公钥/PSK 长度或全零、空地址、非法 CIDR、
重复或重叠的 AllowedIPs、空 peer 列表、MTU/资源上限越界。

## 握手与会话

- 完全复用 `boringtun 0.7.1`：服务端作为 Noise_IK responder，MAC1、静态密钥、
  TAI64N 时间戳、数据计数器重放检查和会话密钥轮换都在 boringtun 内完成。
- 用 `parse_handshake_anon` 从 init 中识别 peer 静态公钥，未知 peer 直接丢弃。
- 每个 peer 分配固定 24 位 slot，数据包按 `receiver_index >> 8` 路由到对应
  peer 的 `Tunn`；boringtun 每个 peer 固定维护 8 个会话组成的环。
- 每个 peer 仍受共享握手速率限制；超过限制的 init 直接丢弃。认证失败、重放、
  未知 peer、非法报文都不会产生响应，属于失败关闭。
- 空闲超过 `peer_idle_timeout_secs` 的 peer 会清空会话与 NAT 关联，之后需重新
  握手才能继续；保留同一 boringtun Handshake 的 TAI64N 高水位与索引，旧握手
  在空闲清理后仍被拒绝，不通过重建 Tunn 清除重放保护。

## 隧道内 TCP/UDP 如何转发

本模块**不创建 TUN**，也不做 IP 层转发。对每条解密后的隧道内 IP 报文：

1. 校验源 IP 是否落在该 peer 的 `allowed_ips`；
2. 将目的地址 DNAT 到本机隧道地址 + 有界临时端口（IPv4/IPv6 均支持）；
3. TCP 由 smoltcp `tcp::Socket::listen` 终止并完成三次握手；UDP 为每个五元组
   创建有界 smoltcp socket；
4. 握手完成（TCP）或首包到达（UDP）后，用原始目的 `SocketAddr` 调用运行时
   注入的 `OutboundDialer`；
5. 回包反向改写源地址/端口并重新计算 IPv4 头、TCP/UDP 校验和，再封装回该
   peer 的 WireGuard 会话。

运行时适配器（`runtime.rs`）：

- **TCP**：`Context::connect(inbound, Target::from(dst))`，走完整路由
  （`reject`、`direct`、代理/链式出站均遵循现有规则）。
- **UDP**：复用 `RoutedUdp` / `Association` 的标准路由、预算与上游中继，支持
  direct 及既有 SOCKS5/VLESS/VMess/Trojan/Shadowsocks/AnyTLS/Hysteria2/TUIC UDP
  出站；不支持的 UDP 出站/链式组合失败关闭，不会静默改走直连。
- TCP 与 UDP 均接入业务字节统计，不把 WireGuard 握手/封装字节算作载荷。

`allowed_ips` 只约束隧道内源地址，不约束目的地址；访问控制应继续由 route
规则与 outbound 选择负责。

## 资源与边界

- 上限：peer 数（配置校验）、TCP 连接、UDP 关联、待发送队列、隧道内 RX 队列、
  握手速率、每 peer 空闲会话。
- 不支持：ICMP、IPv4/IPv6 分片（直接丢弃，不做重组）、组播/广播、TUN、
  peer-to-peer IP 层转发。
- 服务端 UDP socket 的 `recv_from`/`send_to` 错误会终止驱动任务并向 runtime
  返回错误，不会静默吞掉。
- 该入口是长期 UDP 监听并持有启动时的 `Context`，因此存在 `wireguard` 入站时
  `HotReloadHandle` 会返回 `false`，由上层执行完整重启。
- 内核路由集成、系统级 TUN 或 redirect/tproxy 未实现；官方客户端只验证了
  用户态 WireGuard 入站本身。

## 官方 sing-box v1.14.4 客户端矩阵（2026-11-13，本机回环）

环境：macOS ARM64，官方 `sing-box 1.14.4`（revision
`c005f35300ce76427dc285481ec5695f5b179cd2`）作为客户端；外层 WireGuard UDP、
helper SOCKS5、客户端 mixed 入站全部只监听 `127.0.0.1`。内层 echo 目标为
`127.0.0.1` 上的 TCP HTTP/UDP echo，由 helper 的 `route-options`
（`override_address=127.0.0.1`）改写；内层地址使用 `10.77.0.0/24` 和
`fd00:66::/64`，不使用回环内层地址。测试脚本、配置与日志位于
`/tmp/rpk-wg-matrix.yyKX7n`，未进入仓库；验证后所有进程已清理。

测试入口：

```sh
SINGBOX=/tmp/rpk-official-singbox-1.14.4/sing-box-1.14.4-darwin-arm64/sing-box
KERNEL=$PROJECT_ROOT/target/release/dubhe
python3 /tmp/rpk-wg-matrix.yyKX7n/run_matrix.py \
  --root /tmp/rpk-wg-matrix.yyKX7n --kernel "$KERNEL" --singbox "$SINGBOX"
# 单项：--only multi,psk,ipv6,neg_unknown,neg_psk,neg_serverkey,neg_acl,idle,rekey
```

TCP 用 sing-box mixed 入站 + `curl` 校验响应正文，UDP 用独立 Python SOCKS5
UDP ASSOCIATE 客户端校验 echo 载荷；服务端业务字节和 UDP 关联数通过内核
管理 API `GET /stats` 交叉核对。

| 场景 | 配置要点 | TCP | UDP | 观察 |
|---|---|---|---|---|
| 多 peer | 两个客户端密钥，AllowedIPs 分别为 `10.77.0.2/32`、`10.77.0.3/32` | 通过 | 通过 | 两个客户端同时在线；echo 命中 4 次；API `udp_associations=2`，uplink/downlink=194/232 |
| 可选 PSK | 服务端 `preshared_key`、客户端 `pre_shared_key` 相同 | 通过 | 通过 | echo 命中 2 次；uplink/downlink=89/108 |
| IPv6 内层 | 服务端 `fd00:66::1/64`，peer `fd00:66::2/128` | 通过 | 通过 | helper 日志显示 `[fd00:66::1]:20100` 被改写为 `127.0.0.1:20100`（TCP/UDP 各一条） |

负向场景均为独立端口与独立内核进程：

| 场景 | 客户端条件 | TCP | UDP | 内核/echo 观察 |
|---|---|---|---|---|
| 未知 peer | 客户端静态密钥未登记 | curl 超时（28） | 无回包 | echo 0；helper 无目标连接；API uplink/downlink=0 |
| 错误 PSK | 客户端 `pre_shared_key` 与服务端不一致 | curl 超时（28） | 无回包 | 客户端日志持续 `handshake did not complete`；echo 0；API 0/0 |
| 错误服务端公钥 | 客户端 peer `public_key` 指向另一密钥对 | curl 超时（28） | 无回包 | 同上 |
| 越界 allowed_ips 源 | 客户端内层地址 `10.77.0.99/32`，服务端仅允许 `10.77.0.2/32` | 握手完成后超时（28） | 无回包 | 客户端收到 handshake response，但业务包被丢弃；echo 0；helper 无目标连接；API 0/0 |

上述负向均未产生转发：目的地址 `10.77.0.1` 在服务端路由中只指向 helper，
echo 访问日志为零、helper 无目标连接、管理 API 业务字节为 0，说明报文在
握手或入站源 ACL 阶段即被丢弃，没有落到默认 direct 出站；错误 PSK/密钥场景
客户端侧也明确报握手未完成。

keepalive/rekey/空闲清理（在客户端与内核之间串入 UDP 转发器记录 WireGuard
报文类型：1=handshake initiation，2=response，4=transport data）：

- keepalive：客户端 `persistent_keepalive_interval=1`，切除初始握手窗口后
  约 120 秒内记录到 125 个 32 字节空传输包（首个统计包 t=5.361s）。
- rekey：无业务流量的空闲期，客户端在 t=120.445s 主动发出 handshake
  initiation，服务端 t=120.446s 返回 response；随后 TCP 请求仍成功。该时间来自
  boringtun/WireGuard 标准的 `REKEY_AFTER_TIME=120s`，sing-box 客户端没有可配置
  的 rekey 间隔。
- 空闲清理：服务端 `peer_idle_timeout_secs=2`、客户端不启用 keepalive。空闲 6 秒
  后客户端仍用旧会话发送 UDP，服务端未转发（无回包）；约 15 秒后（客户端
  `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT`）客户端重发 handshake initiation
  （t=21.603s），服务端返回 response，紧接着发送的 UDP 在 t=21.651s 得到 echo。
  说明空闲清理会拒绝旧会话，客户端需重新握手；该测试的 2 秒超时极小，若新握手
  后继续空闲超过 2 秒服务端会再次清理，这是测试超时值导致的预期行为，默认
  300 秒不受影响。

限制：以上只覆盖 macOS ARM64、单机回环、一个 sing-box 版本；未使用内核 `wg`/
`wireguard-tools`、Mihomo 或其他官方客户端。未验证外层 IPv6、MTU/分片、ICMP、
组播、漫游、长稳、高并发、握手限速饱和、PSK 轮换和单 peer 多地址。因此本页
不把该矩阵扩称为完整官方兼容。

## 测试

- `src/transport/wireguard_server.rs` 文件内 17 项测试：IPv4/IPv6 TCP echo、
  IPv4 UDP echo、未知 peer、重放（含空闲清理后）、强制 rekey、多 peer、资源上限、
  畸形报文、配置校验、NAT 前原始校验和、TCP 半关闭后响应、停机取消未完成拨号
  并等待子任务与监听端口释放。
- `tests/wireguard_server.rs` 3 项集成测试：通过完整 `Config` + `Server::bind`
  启动 `type: "wireguard"` 入站，使用回环 UDP 完成真实握手，验证 TCP/UDP echo、
  TCP 业务计量、UDP 确实经过 SOCKS5 上游及非法配置（含超接口容量）失败关闭。
- 官方 sing-box 客户端矩阵不进入 `cargo test`：脚本、配置和日志位于
  `/tmp/rpk-wg-matrix.yyKX7n`，只作为 2026-11-13 的本机互测证据；仓库内测试仍
  只覆盖 boringtun + smoltcp 自洽与内建入站行为。

运行：

```sh
cargo test --test wireguard_server
cargo test --lib wireguard_server
```

上述仓库内测试只证明本机 boringtun + smoltcp 自洽，不构成官方客户端兼容结论；
官方客户端矩阵的覆盖范围与限制以本节上方的矩阵表为准。
