# 生产可用性评估（2026-11-13）

结论：**当前版本可用于受控实验/内测和明确的协议子集服务端角色，不应直接作为生产代理或完整替代 Xray/sing-box/Nowhere。**

本文只列生产门禁，不把单机回环、编译通过或单个官方客户端结果扩称为生产兼容。

## 当前已有证据

- macOS ARM64：Rust 1.91.0 当前全量为 **1465 passed / 0 failed / 42 ignored**；
  Rust 1.95.0 历史全量为 1383 / 0 / 42。
- Linux ARM64（Colima 4 CPU / 8 GiB + `rust:1.91-bookworm`）：当前全量测试
  **1389 / 0 / 42**、release 已按当前源码构建，`version`/`check` 冒烟通过。
- Linux x86_64：`cargo check --locked --all-targets` 通过；QEMU 下全量测试受 cargo `fork/exec` 偶发死锁影响，未取得可信全量结果，未构建 release。
- macOS ARM64 release（Rust 1.91.0，包含 fuzz feature 入口与 TLS 私钥权限检查的当前源码）：
  `dubhe 0.1.0`，30,138,800 字节，SHA-256
  `b5a1db63f86b3cde2615258cb3c00f34410056d35536ff742c67b6a2fdb13e3f`。
  两个固定干净 target 目录的构建逐字节一致，命令与边界见
  [可复现构建记录](reproducibility.md)。
- Linux ARM64 release（含当前 fuzz feature 入口与 TLS 私钥权限检查的源码）：
  `dubhe 0.1.0`，33,144,056 字节，SHA-256
  `7ec912b1b93e6e8327fc814309c7bb0713f34674b0c4e8d2970b891e108f3405`；
  单次构建，尚未做 Linux ARM64 双构建可复现比对。
- 官方互通覆盖 macOS ARM64 回环上的 Xray/sing-box/Mihomo/Nowhere 有限组合，详见
  [官方互通记录](official-interop-development.md)。
- 2026-11-14 已落地 M1 部分基线：`rust-toolchain.toml` 固定 1.91.0、三平台 CI 工作流、
  `deny.toml`、`tools/ci.sh`、`tools/supply-chain.sh`、`tools/release.sh`、
  `tools/repro-check.sh`、systemd unit、`/metrics`、`api.token_file`、
  [运维基线](operations.md)、[可复现构建记录](reproducibility.md) 与
  [威胁模型](threat-model.md) 初版。这些是工程门禁，不替代原生 Linux x86_64 验收、
  外部审计或容量测试。

## P0：上生产前必须完成

### 1. 发布矩阵与可复现产物

- 已加入固定工具链、三平台 CI、`tools/ci.sh`、`tools/release.sh`、`deny.toml` 和
  `tools/supply-chain.sh`；但 **Linux x86_64 原生全量测试和 release 仍未完成**，
  Windows/macOS x86_64 没有构建产物。
- 已完成 macOS ARM64 的双干净目录可复现构建比对；已本地生成 CycloneDX SBOM
  （312 组件，见 [SBOM 记录](sbom.md)），但仍无签名产物、正式发布包、
  安装包/容器镜像，版本升级/回滚流程仍需落地。
- release 二进制未做启动冒烟、权限降级运行、配置迁移和滚动升级验证。
- 全量 Clippy 已清零：`cargo clippy --locked --all-targets -- -D warnings`
  在本项目代码上无警告（`vendor/` 内固定版本的上游源码不计入），CI 与
  `tools/ci.sh` 均以此为准入门禁。

### 2. 安全审计与失败关闭

- 没有独立第三方安全审计、模糊测试/差分测试和长期 soak 测试。
- 已建立初版[威胁模型](threat-model.md)：未认证资源消耗、握手 DoS、UDP 放大、
  TLS/QUIC 降级、日志注入、配置/密钥文件权限、管理 API token 泄漏；仍需安全评审和
  对应测试证据。`fuzz/` 已建立配置、Vision、SOCKS5 数据报、地址、XUDP、VLESS/Trojan
  数据报目标；2026-11-14 已用 nightly + cargo-fuzz 对 15 个入口（含 XHTTP 头/上行、
  gRPC payload、VMess header、Snell、TUIC wire）各运行 30 秒，共约 825 万次执行、
  0 crash/OOM。该结果只是短时冒烟，**不等于完整握手 fuzz 或安全审计**，详见
  [fuzz 记录](fuzzing.md)。
- `vendor/rustls`、`vendor/shadowsocks`、`vendor/blake3` 等本地补丁需要固定来源、
  许可、补丁 SHA、上游同步和 CVE 响应流程；当前有门禁文档，但没有自动化持续审计。
- 需要验证所有入口在畸形长度、半包、截断、重放、并发上限、取消/停机路径下失败关闭；
  当前有大量单测，映射和缺口见 [失败关闭证据矩阵](fail-closed-matrix.md)，但不等于
  审计结论。
- GPL-3.0-only 与 vendored Nowhere 的源码提供、NOTICE、二进制分发义务需要发布流程落实。

#### 2.1 依赖公告与已完成的修复

2026-11-14 使用 `cargo-deny 0.20.2` 对当前 `Cargo.lock` 执行 `cargo deny check`。
初次检查发现：

- `hickory-proto 0.24.4` / `hickory-resolver 0.24.4`：
  RUSTSEC-2026-0119、0487、0489、0490、0491、0505、0511、0512、0514、0530、0531。
- `rustls-pemfile 2.2.0`：RUSTSEC-2025-0134（上游已归档，不再维护）。

已处理：

- `hickory-resolver` 升级到 `=0.26.2`，同时解析 `hickory-proto`/`hickory-net` 0.26.3；
  Rust 1.88 MSRV、MIT OR Apache-2.0，默认 `system-config`/`tokio`，未启用
  DNSSEC/QUIC/HTTP3 可选边。DNS 测试（受控 UDP、超时、hosts、并发规则）已重跑。
- PEM 加载从 `rustls-pemfile` 迁移到 `rustls-pki-types` 的 `PemObject`，不再依赖
  已归档 crate。
- 修复后重新执行 `cargo deny check`：**advisories、bans、licenses、sources 全部通过**。
  `deny.toml` 仍保持无 ignore；新增依赖或公告会重新阻断。

这不等于完整安全审计，也不等于所有 DNS 行为已被生产验证；只是当前锁文件的已知公告
已清零。后续必须在 CI 中持续运行 `tools/supply-chain.sh`，并保留公告复核记录。

### 3. 运行与运维

- 已加入 systemd unit、非 root/权限硬化、`/metrics`、`api.token_file` 和
  [运维基线](operations.md)；仍需在目标发行版和内核上完成启动、崩溃重启、
  SIGTERM 排空和权限降级的实际验收。launchd、告警、审计日志和长期指标存储未完成。
- 管理 API 现有 `healthz/stats/metrics/connections`；没有 OpenTelemetry、
  告警、持久化指标和连接追踪导出。
- ACME/证书自动续期未内嵌；推荐外部 certbot/lego。SIGHUP 只覆盖部分 TCP/TLS
  入口，QUIC/mKCP/REALITY/ShadowTLS 证书轮换仍需完整重启；UDP 入口或监听器
  变化会短暂停机。
- 没有配置 schema 版本迁移、Xray/sing-box 配置导入器或正式发布说明/回滚手册；
  运维文档已给出最小升级/回滚流程。

### 4. 部署形态与路由

- 没有 TUN、redirect/tproxy、systemd socket activation、出站 BIND、透明代理部署。
- 配置是本项目自定义 schema，不是 Xray/sing-box/Clash 配置兼容；迁移需要人工转换。
- fallback 是稳定子集，未覆盖完整 Unix socket/`serve`/高级回退语义。
- XHTTP 的 `downloadSettings`、CDN/外部下行、部分客户端放置字段仍显式拒绝；
  Hysteria2 独立 pacer/逐包 loss 仍受 quinn API 限制。
- TUIC 官方 sing-box 客户端 0-RTT 受上游缺少 `ClientSessionCache` 阻塞，不能算本内核通过。
- WireGuard 官方矩阵目前只有有限单 peer/多 peer/PSK/IPv6 回环组合，未覆盖内核 wg、
  Mihomo、外层 IPv6、MTU/分片、ICMP、漫游、长稳和高并发。
- gRPC/XHTTP/REALITY/Snell/ShadowTLS 等仍有官方全矩阵、版本差异和异常路径未验收。

### 5. 容量与性能

- 当前默认 `max_connections=1024`、每入口 `max_handshakes=64`、
  `max_udp_associations=256` 等是安全默认值，不是生产容量结论。
- 没有多核吞吐、延迟、内存/FD/队列压力、慢客户端、连接风暴、UDP 放大和长时间
  稳定性基准；没有按 CPU/内存/带宽给出容量模型。
- 需要针对 TLS/REALITY/QUIC/gRPC/XHTTP 分别做压测，并记录丢弃/拒绝/回收行为。

## P1：按目标协议逐步补齐

- Hysteria2：精确 Brutal 独立 pacer、逐包 loss、realm/端口跳跃、BBR profile 评估。
- XHTTP：`downloadSettings`/CDN、完整 `extra` 客户端字段、官方配置样本端到端。
- gRPC：完整 headers/trailers、官方 Xray 全矩阵、不同客户端版本。
- REALITY：剩余官方客户端/平台/异常矩阵。
- Snell：QUIC 目标（上游有明确实现后再做）；ShadowTLS v1/v2 明确不支持。
- Mihomo REALITY、TUIC 0-RTT、官方 Anywhere 等需要上游真实客户端证据。
- Linux x86_64 全量与 release；Windows 构建与运行验收。

## 建议生产门禁顺序

1. 固定并签署版本；生成 SBOM、校验和、源码提供说明。
2. 完成 Linux x86_64 全量与 release；至少再完成一个非 macOS 真机/原生平台。
3. 独立安全审计 + 模糊/差分/恶意输入测试 + 依赖公告持续扫描。
4. 加入 systemd/launchd、权限降级、日志轮转、Prometheus/OTel、ACME 和完整热重载。
5. 做连接/UDP/握手/慢客户端/长稳容量压测，形成容量与故障手册。
6. 按实际目标客户端补协议矩阵，不能以回环和单版本结果替代。

在此之前，建议只把本内核用于受控内测或已明确验证的协议子集，并保留上游内核作为回退。
