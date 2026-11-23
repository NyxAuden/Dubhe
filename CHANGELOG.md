# 变更记录

本项目的所有重要变更记录在此文件。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 行为变更（geo 路由语义）

- **多地址目标**：`ip_is_private` 与 `ip_cidrs`/`geoip:`/`mmdb:` 现在要求
  **同一个解析地址**同时满足；此前两个条件可由不同地址分别满足。
  与 Xray、sing-box 均不一致（两家都是并集），dubhe 采用更严格的契约。
- **`invert` + 未解析 IP**：目标域名尚未解析时，IP 条件视为未知，
  `invert` 不再把它翻成命中。依赖「反向 IP 规则捕获所有未解析域名」的
  配置需要显式写出域名规则。

### 新增

- 地理数据集：`geosite.dat` / `geoip.dat` / MaxMind mmdb / sing-box rule-set
  source JSON，见 `docs/geo.md`。读取与展开有固定预算，超限失败而不是截断。
- 首次公开：服务端代理内核，Rust 实现，单进程多协议。
- 入站 40 个变体：VLESS / VMess / Trojan 各承载（RAW、REALITY、Vision、
  WS、gRPC、XHTTP、HTTPUpgrade、mKCP、QUIC、HTTP）、Shadowsocks
  （AEAD 2017/2022）、Hysteria2、TUIC v5、AnyTLS、Snell v4/v5/v6、
  ShadowTLS v3、Naive H1/H2/H3、WireGuard、SOCKS5、HTTP/Mixed、
  dokodemo-door、NW3 Portal。
- 出站：SOCKS5 / HTTP / VLESS / VMess / Trojan / Shadowsocks / AnyTLS /
  Snell / Naive / ShadowTLS detour / Hysteria2 / TUIC / WireGuard /
  NW3 Vector，含链式与 `selector` / `urltest` 出站组、反向 Mux Portal。
- `dubhe export`：从服务端配置生成 Xray / sing-box / Mihomo / Anywhere AJSON，
  并用真实内核校验。
- `dubhe convert --from xray`：Xray 配置转换，高级语义显式拒绝而非静默丢弃。
- 按用户流量统计（`GET /stats/users`）、Prometheus 指标、活动连接管理 API。
- 管理 API 安全加固：仅回环监听、强制 Bearer、定长比较。

### 变更

- `limits.idle_timeout_ms`：TCP 中继双向空闲超时，对齐 Xray `connIdle`
  默认 300 秒。修复此前死连接永久占用连接名额的问题。
- 路由新增 `invert`、`ip_is_private`、`domain_regex`，对齐 sing-box 语义。
  `ip_is_private` 与 sing-box `!IsPublicAddr` 逐条一致（**不含** CGNAT）。
- Hysteria2 gecko `min/max_packet_size` 校验放宽到官方约束
  （`min>0 && min<=max && max<=2048`），此前 256–1400 会拒绝合法配置。
- Naive 请求侧 `padding` 头长度修正为规范要求的 16–32 字节
  （此前误用响应侧的 30–61）。

### 修复

- `check` 现在拒绝两个入口抢占同一 `(地址, 端口, TCP/UDP)`。此前 `check`
  通过，`run` 才在绑定阶段报 `AddrInUse` 并整体退出。TCP 与 UDP 同端口
  仍然允许（例如 `socks5` + `hysteria2`）。
- README 更正「同一端口可按 ALPN / 首包分流」的不实表述：实际只有 `mixed`
  （按首字节分 SOCKS5/HTTP）与 `fallbacks`（认证失败后回放明文到本地目标），
  不支持按 ALPN/SNI 选择协议栈。并补充 `fallbacks` 的真实边界——回放的是
  TLS 解密后的明文，指向另一个 TLS 入口不会工作。
- 显式配置 `is_private_ip` 集合：补 multicast，移除错误的 CGNAT 判定。
- Hysteria2 非法目标地址不再静默关闭，按规范回 TCPResponse Error。
- 导出模块补齐此前静默丢弃的 4 个协议变体与 7 个入口。
- 导出配置用真实内核验证，修正多处 TLS 判定与协议能力错误。
- 中继包装缺少 `poll_write_vectored` 转发导致的 H2 偶发超时。

### 已知限制

- **只有 Trojan / VLESS（含 XUDP）/ Shadowsocks 有可复现的第三方客户端测试**，
  其余协议仅本机回环。当前测试基线 1467 通过 / 0 失败 / 42 忽略。
- Linux x86_64 未取得可信全量测试结果与 release 构建；Windows 未验收。
- 未做独立安全审计、长期 soak 或容量压测。
- 无内嵌 ACME、无多 SNI 证书、QUIC / REALITY 证书轮换需完整重启。
- 无动态用户管理（增删用户需重启实例）。

详见[生产可用性评估](docs/production-readiness.md)与
[服务端兼容矩阵](docs/compatibility-matrix.md)。
