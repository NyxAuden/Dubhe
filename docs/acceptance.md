# 第一阶段验收记录

日期：2026-11-04。变更：`establish-server-kernel-foundation`。这份记录只覆盖第一阶段，不代表全部长期协议目标已经实现。

## 最终结果

| 验收项 | 实际结果 |
|---|---|
| macOS ARM64 普通测试 | 73 passed、0 failed，3 项外部客户端测试默认 ignored |
| Linux ARM64 普通测试 | 73 passed、0 failed，3 项外部客户端测试默认 ignored |
| Linux x86_64 / QEMU 普通测试 | 73 passed、0 failed，3 项外部客户端测试默认 ignored |
| macOS fmt / check / Clippy | 全部退出码 0，Clippy 使用 `-D warnings` |
| macOS release 构建、version、SOCKS 示例 check | 全部退出码 0，版本 `dubhe 0.1.0` |
| 三家官方客户端单独互通 | 3 passed、0 failed，TCP/UDP 与负向场景见 `interop-report.md` |
| IPv6 | 三个平台均实际执行通过，最终日志无 SKIP |

73 项组成：45 库单元测试 + 4 CLI + 5 DNS + 1 示例 + 9 端到端 + 7 资源 + 2 标准客户端。单独运行 DNS 时的 5 项不再重复计入。普通测试的 ignored 不计通过；官方客户端结论来自此前单独完成的运行，收尾时重新执行被审批器拒绝，未绕过，已有日志与 `result.json` 已复核。

资源循环是至少 5.2 秒的短期回归：macOS 248 轮 / 5.203873 秒 / 单向 9086 字节，Linux ARM64 252 轮 / 5.212077699 秒 / 单向 9240 字节，Linux x86_64 186 轮 / 5.221207515 秒 / 单向 6820 字节。断言载荷计量和连接/关联名额回收；这些数字不是吞吐基准或长期稳定性结论。

## 构建与原始证据

项目尚无 Git 仓库/commit，采用输入摘要定位本次构建：

| 对象 | SHA-256 |
|---|---|
| `Cargo.lock` | `69f11690fd2b272b09caf184afc6c2f12e9c77754c748f633a52fc252b653460` |
| 生产输入集合 | `f943d47554ed13de54fd736288a1ac9a8c4d99b5d4e0be4ead01ac875314d64f` |
| macOS ARM64 `target/release/dubhe` | `77899ce7832dc4ac1663e19a580da491004e724c5bc879fe90b2ed19908f8da6` |

生产输入集合为 `Cargo.toml`、`Cargo.lock` 和全部 `src/**/*.rs`，按相对 POSIX 路径排序，将每项编码为 `文件SHA256 + 两个空格 + 相对路径 + 换行`，对连接后的 UTF-8 字节求 SHA-256。输入逐项摘要、当前测试文件摘要及原始输出副本保存在本机 `.test-artifacts/final-acceptance-f4zey1lm/manifest.json`；此目录不提交或公开。这不是从上游源码到二进制的可复现构建证明。

| 日志副本 | 原会话任务 | 内容 |
|---|---|---|
| `macos-arm64.log` | `br0qh8ax5.output` | 最终 DNS、check、Clippy、73 项普通测试及 release |
| `linux-arm64.log` | `bomldeug2.output` | 最终 ARM64 普通测试 |
| `linux-amd64-qemu.log` | `b1s4vlhve.output` | 最终 x86_64 普通测试，含 QEMU 下 jemalloc 的 MADV_DONTNEED 提示，退出码仍为 0 |
| `reference-clients-prior-run.log` | `buw59d8te.output` | 较早一轮测试、三家官方客户端 3/3 通过和 release 构建；不将其旧普通测试数替代最终 73 项 |

官方互通运行的是测试 profile 中的库服务端，不是 release 子进程；相同生产输入的 release 摘要在收尾复核未变。Linux 验收为 test profile 编译并实际执行，没有额外宣称 Linux release 包已经发布。

## 验证环境与命令

- macOS ARM64，Rust/Cargo 1.95.0。
- Colima 原有 default 实例，Linux ARM64，2 CPU / 4 GiB；启动时使用 `--activate=false --save-config=false --ssh-config=false`，未切换全局 Docker context。
- Linux x86_64 使用同一 Colima 下的 QEMU 仿真实际运行测试，不是仅交叉编译，也不是原生性能测量。
- 官方 Rust 多架构容器镜像固定为 `rust@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1`。
- 源码只读挂载到 `/workspace`，Cargo 与 target 使用本项目专用命名卷，没有容器端口映射到主机公网。

本机命令：

```sh
cargo check --locked --all-targets
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --test reference_clients -- --ignored --nocapture
cargo build --locked --release
./target/release/dubhe check -c "examples/socks5.json"
```

普通测试包含协议/配置/路由单元测试、UDP 预算/取消回归、CLI、受控 DNS、示例、端到端、资源循环和 curl 标准客户端。三项官方客户端测试默认 ignored，已单独显式执行；Linux 不运行 macOS 参考二进制。

两套 Linux 的运行命令相同，仅替换平台和专用卷后缀。例如 ARM64：

```sh
docker --host "unix://$HOME/.colima/default/docker.sock" run --rm \
  --platform linux/arm64 \
  --mount "type=bind,source=$PROJECT_ROOT,target=/workspace,readonly" \
  --mount "type=volume,source=dubhe-cargo-arm64,target=/usr/local/cargo" \
  --mount "type=volume,source=dubhe-target-arm64,target=/target" \
  --workdir /workspace --env CARGO_TARGET_DIR=/target --env CARGO_BUILD_JOBS=2 \
  rust@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 \
  cargo test --locked --all-targets -- --nocapture
```

x86_64 使用 `linux/amd64` 与 `dubhe-cargo-amd64`、`dubhe-target-amd64`。未切换全局 Docker context，未映射外部端口。测试容器通过 `--rm` 自动回收；现有 Colima 实例、镜像、专用缓存卷与客户端产物保留，未擅自清理。

三平台 rustc 均为 `1.95.0 (59807616e 2026-04-14)`，cargo 为 `1.95.0 (f2d3ce0bd 2026-03-21)`。标准 SOCKS 客户端是以下已有 curl 构建，通过 `--socks5-hostname` 访问回环 HTTP 目标：

| 平台 / 来源 | curl 版本 | 可执行文件 SHA-256 |
|---|---|---|
| macOS ARM64 / `/opt/homebrew/opt/curl/bin/curl` | 8.23.0 | `b78797230ba16eb11b6bdb80dfac56c068df6233159cf490427d097aa9c431e1` |
| Linux ARM64 / 固定镜像 `/usr/bin/curl` | 7.88.1，Debian 修订 `7.88.1-10+deb12u14` | `9180a740999930f997b33dc7d682e37edc62f59fd9b8ebe6b724a165caec0283` |
| Linux x86_64 / 固定镜像 `/usr/bin/curl` | 7.88.1，Debian 修订 `7.88.1-10+deb12u14` | `58824afa640f512e07e895c0f2d1e1fe2c3fd1456acab689b6e4c1c75cef2593` |

初次编译时并行模块尚未齐备及一个 Tokio API 使用错误已修正；示例测试最初保持连接却只等待 3 秒，短于默认 5 秒排空，被修正为结束业务连接后停止；Clippy 发现测试中的冗余 let 已修正。最后新增总拨号期限测试曾因临时 Target 生命周期导致 E0716，改为局部绑定后已在三平台通过。不能把这些历史失败省略成“第一次即全通过”。

## 行为规格到测试的映射

| 规格场景/要求 | 实际测试或证据 |
|---|---|
| 同进程两个入口 | `trojan_tcp_coalesced_and_fragmented_header`；`valid_dual_inbounds_defaults_and_serialization` |
| 未实现配置不降级 | config 内未知字段/未知协议/扩展表驱动测试；CLI 非零退出 |
| check 不占端口 | `check_validates_both_inbounds_without_binding_or_accepting_connections`，监听地址预先被占用仍能检查成功 |
| 部分启动失败清理 | `startup_failure_releases_prepared_listener`，原端口立即可重绑 |
| 强制停机与任务释放 | `forced_shutdown_closes_live_tcp_and_udp_for_both_protocols`，含 UDP 映射端口重绑；CLI SIGINT/SIGTERM |
| 慢握手及恢复 | `handshake_limit_timeout_and_recovery` |
| UDP 字节/队列上限 | `byte_budget_empty_packets_and_full_queue_release_permits`、`slow_consumer_queue_is_bounded_and_close_joins_tasks` |
| 活动下行映射不被误删 | `downstream_activity_preserves_mapping_and_cancel_waits_for_socket_drop` |
| 日志脱敏及错误刷新 | `invalid_checks_exit_nonzero_emit_errors_and_redact_configuration`、CLI signal 测试；config Debug/serde 错误测试 |
| TCP 半关闭 | `socks_tcp_domain_half_close_and_counting` |
| 首段数据与分段请求 | `trojan_tcp_coalesced_and_fragmented_header`，协议独立 wire 单元测试 |
| UDP 多目标/空载荷/源校验 | `socks_udp_multi_target_zero_payload_and_source_validation`、`trojan_udp_multiple_frames_and_zero_payload` |
| 路由顺序与域名/CIDR | route 模块 8 项测试；`route_reject_does_not_connect` |
| Direct DNS 与 IP 不解析 | `controlled_dns_answers_nxdomain_and_no_ip_lookup` |
| hosts | `hosts_mapping_works_without_dns_network` |
| DNS 并发/超时/取消 | `dns_limits_timeout_and_cancel_return_slots` |
| 总拨号期限包含 DNS 且取消归还预算 | `total_dial_timeout_cancels_slow_dns_and_returns_budget` |
| 多地址拨号 | `tcp_dial_retries_next_address` |
| 上下行业务计数 | 半关闭测试、`five_second_local_tcp_udp_churn_recovers_slots_and_counts_payload_only` |
| SOCKS 认证/降级/BIND/FRAG | protocol::socks5 单元测试及独立 UDP 集成测试 |
| 标准 SOCKS 客户端 | `curl_uses_standard_socks5_connect`；目标拒绝对应 `socks_refused_target_reports_rep_five` |
| UDP 控制连接关闭/超时 | resources 中 SOCKS/Trojan 的 close_and_idle 测试 |
| Trojan TLS1.2/1.3/证书匹配 | tls 模块 3 项测试，正常证书验证而非 insecure |
| Trojan 多用户/错误密码 | protocol::trojan 独立 wire 测试；`trojan_wrong_password_never_dials` |
| UDP 粘帧/拆帧/截断/长度/CRLF | protocol::trojan 单元测试及多帧集成测试 |
| 有限组合限制 | 配置拒绝 fallback/包装等未知字段；`usage.md` 公开差异 |
| 真实参考客户端 | `reference_clients.rs` 三项显式运行，详细见 `interop-report.md` |
| IPv6 | `ipv6_tcp_udp_when_available`；环境不支持时打印 SKIP，不能算通过 IPv6 |
| 资源持续回收 | 本地至少 5.2 秒 TCP/UDP 建立-转发-关闭循环；这是短期回归，不是生产长稳测试 |
| 示例可用 | `documented_examples_check_start_and_transfer`：Trojan 模板替换成临时证书/密码后验证 |

证据治理场景同样已核对：仅解析器单测不能提升为已验证；参考客户端缺失/摘要不符/启动失败会使显式互通测试失败；新上游版本不继承旧版本结果；仅交叉编译不能算平台运行通过。这些约束分别落实在 `reference_clients.rs` 的前置校验、兼容矩阵、互通报告与分阶段路线中。当前三平台的 IPv6 均未跳过；若未来环境不支持，测试会打印明确的 SKIP。

四份规格的场景映射及公开限制已核对；`openspec validate establish-server-kernel-foundation --strict --no-interactive` 通过。30 项实施任务均有实现与上述证据对应；严格校验本身仅证明规格结构，不代替运行测试。本变更未归档。

## 实施时修正的边界问题

- 持续 accept 时显式回收完成的 JoinSet 条目，不让偏置选择阻碍回收。
- SOCKS5 UDP ASSOCIATE 超限/建立失败发送标准失败回复。
- UDP 映射同时记录上行和有效下行活动，已结束接收任务的映射可清理。
- 强制取消父连接后，TaskTracker 等待 UDP 子 future 完整析构，避免停机返回时仍占 socket。
- CLI 正常返回 ExitCode，保证后台日志守卫刷出错误；信号注册在运行前完成。

## 结果的边界

- 验收不是全量安全审计、模糊测试或性能容量证明，未执行生产部署、长时间 soak 或公网压力测试。
- 没有测试全部 Clash/V2Ray 客户端变体，只验证记录的具体三个构建与组合。
- MSRV 1.85 仅依赖元数据约束，未实际编译验证。
- 不宣称 Trojan fallback、复用、WS/gRPC、其他协议或上游全部配置/API 已实现。
- 示例/互通的测试私钥仅在临时测试产物中，未作为生产证书提交；不要发布 `.test-artifacts/`。
- 未提交 Git、未归档 OpenSpec、未自动发布或部署。具体项目许可证仍是对外分发门禁。
