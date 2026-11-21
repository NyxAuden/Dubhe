# VLESS 批次验收记录

日期：2026-11-04；语义更新说明 2026-11-06。变更：`add-vless-tls-inbound`，14/14任务完成、未归档。基础 VLESS TLS 与当时的可选 UDP-only XUDP 已完成三平台内部验证及三家固定官方客户端的有限外部互通验收。九项显式官方客户端测试全部通过，不将有限组合扩大为全部 VLESS 扩展兼容。

**2026-11-06 语义更新：命令 3 现按上游语义进入完整 Mux.Cool（TCP 会话 + `xudp` 门控的 UDP），不再由 `xudp` 决定是否接受命令 3。** 本文所有运行编号、摘要与外部客户端结果均为旧 UDP-only XUDP 构建的历史证据，不能回填或推导新 Mux；新 Mux 状态为“已实现待集中验收、未测试”。旧 XUDP 场景测试已按新语义重写或改名，纯 `protocol::xudp`/`udp::xudp_*` 编解码与资源测试保留。当前边界见 [Mux 说明](mux.md)，旧协议边界见 [vless-baseline.md](vless-baseline.md)。

## 历史 XUDP 构建（2026-11-04）

当时支持默认关闭的 `xudp` 配置、命令 3 内 UDP 多会话、逐帧目标、End/KeepAlive、独立会话空闲、逐包路由和来源过滤、全局关联/排队字节预算，以及编号代次和跨认证连接隔离；GlobalID 仅消费，不提供跨承载续接。该历史构建不支持 TCP Mux、Rvs、Vision/REALITY、VLESS Encryption 或传输包装。上述“仅 UDP / 拒绝 TCP Mux / GlobalID 隔离 / 会话独立空闲”均已不是当前命令 3 语义。

| 环境/检查 | 当前结果 |
|---|---|
| macOS ARM64 / Rust 1.95.0 | 117 passed、0 failed、9 ignored |
| Linux ARM64 / 固定 Rust 容器 | 117 passed、0 failed、9 ignored |
| Linux x86_64 / QEMU 固定容器 | 117 passed、0 failed、9 ignored |
| fmt / check / Clippy `-D warnings` | 通过 |
| release / version / SOCKS 示例 check | 通过，未发布版本仍为0.1.0 |
| 三家 XUDP 及基础 VLESS/Trojan 九项外部测试 | 显式运行9 passed、0 failed、0 ignored，7.07秒；普通测试中的ignored不计入通过 |

普通测试组成：69 lib、5 CLI、5 DNS、1 examples、9 integration、5 reference配置生成、7 resources、2 standard_client、7 VLESS、7 XUDP。三平台没有 SKIP，VLESS/XUDP IPv6 用例均实际执行。x86_64 日志含 QEMU 下 jemalloc 的 MADV_DONTNEED 提示，不影响通过结果，不作为原生性能证明。

原始日志和逐文件摘要保存于 `.test-artifacts/xudp-acceptance-r_6fga68/manifest.json`：

- 生产输入 SHA-256：`59fa717439d49d61a6c7776f847c8416d9d4f169ed5fe5eb00a4167bd0819733`。
- macOS release SHA-256：`0a3b2ab6cbf4b394b8d75ed8861bbe576f7ac037897f52ccdf40f0e222387a58`。
- Cargo.lock SHA-256：`69f11690fd2b272b09caf184afc6c2f12e9c77754c748f633a52fc252b653460`；没有新增依赖。
- 输入摘要算法：Cargo.toml、Cargo.lock、全部 src/**/*.rs 按相对 POSIX 路径排序，每项 `SHA256 + 两空格 + 路径 + 换行` 拼接后再做 SHA-256。测试文件另有逐文件摘要；目录不是 Git 仓库，没有提交编号。

短期循环资源回归：macOS 234轮/5.2152745秒/单向8580字节；Linux ARM64 280轮/5.213092233秒/单向10252字节；Linux x86_64 186轮/5.206008186秒/单向6820字节。这是原有转发层短期资源回归，不是 XUDP 吞吐基准或生产稳定性证明。

本次中间失败已修复：Association 回程队列移交调用方后，旧资源测试未释放该队列便断言字节预算完全归还；测试现显式释放队列。Clippy 检出测试中的两处无效 as_ref，已修正。最终全部普通回归和严格检查通过。

## 历史 XUDP 场景映射（2026-11-04）

下表保留当时测试名与覆盖。重写后的同名/新名测试尚未运行，不能把本表结果用于新 Mux。

| 行为 | 测试 |
|---|---|
| 默认关闭、严格布尔配置、命令3认证且不吞首帧 | config / protocol::vless 新增单元测试 |
| 拆分/合并、状态/选项/网络/地址、GlobalID精确长度、截断和长度限制 | protocol::xudp 独立 wire 测试（纯编解码保留） |
| 多会话、多目标、缺省目标、域名、逐字节帧、空包和载荷计量 | `multiple_sessions_targets_fragmentation_and_accounting`（新 Mux 下保留，空回包现会成帧） |
| 同编号/GlobalID跨身份隔离、End幂等与编号重用、旧端口回收 | `end_reuse_and_global_id_are_isolated_between_identities`（已由 `global_id_takeover_moves_sink_and_old_session_gets_error` 按进程级去重语义取代） |
| 已排队旧代次回包不能进入复用编号的新会话 | `queued_old_generation_cannot_reach_reused_session` |
| 字节预算耗尽仍保留End，关闭归还所有预算 | `exhausted_byte_budget_keeps_end_and_returns_all_resources` |
| 全局会话名额、逐包路由拒绝、目标上限、释放后恢复 | `global_limit_route_changes_and_target_limit_release_sessions`（新 Mux 下保留） |
| KeepAlive不保留会话、半帧空闲关闭 | `keepalive_does_not_pin_sessions_and_partial_frame_idle_closes`（已改为 `keepalive_does_not_pin_udp_mappings_and_partial_frame_closes_connection`） |
| TCP网络/未知会话/重复New/超长元数据及载荷/默认关闭均拒绝 | `malformed_unknown_duplicate_and_disabled_xudp_never_forward`（已拆为 `per_session_errors_and_tcp_sessions_keep_mux_connection_usable`、`malformed_frames_fail_closed_without_forwarding`、`command_three_without_xudp_accepts_mux_but_gates_udp_per_session`） |
| 伪造回包来源过滤、强停后socket立即重绑 | `source_filter_and_forced_stop_reclaim_sockets`（新 Mux 下保留） |
| IPv6 XUDP | `ipv6_xudp_when_available`，三平台均实际执行 |
| 三家配置显式XUDP且关闭TCP复用 | reference_clients的5项配置生成测试，无外部进程；仅为客户端配置边界，不代表服务端拒绝 TCP Mux |

## 当前构建的官方客户端互通

此前调用曾被自动审批器拒绝，未换工具、测试名、脚本或代理绕过。随后用户通过问题工具直接选择“允许运行上述客户端”，范围明确为已校验的 Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31、回环临时端口、本机目标，不安装服务或修改系统代理。取得确认后的原命令获准执行，最终9 passed、0 failed、0 ignored、5 filtered out，耗时7.07秒。

三项 XUDP 显式用例为 `mihomo_vless_xudp_tcp_udp_authentication`、`sing_box_vless_xudp_tcp_udp_authentication`、`xray_vless_xudp_tcp_udp_authentication`。三家正常场景均通过TCP回显及单SOCKS UDP关联中的两目标三报文；错误UUID的TCP/UDP请求均被拒绝且未触及目标，不受信任证书的TCP请求被拒绝。错误信任没有验证UDP。所有客户端校验服务器证书，不使用跳过证书验证。测试结束清理进程。

| 模式 | Mihomo v1.19.33 | sing-box v1.14.4 | Xray v26.10.31 |
|---|---|---|---|
| Trojan/TLS | TCP/UDP、错误密码、错误信任通过 | 同左 | 同左 |
| 基础VLESS/TLS | TCP、错误UUID、错误信任通过；原生UDP不在客户端基线内 | TCP/原生UDP、错误UUID、错误信任通过 | 同左 |
| VLESS/TLS + XUDP | TCP/XUDP、错误UUID、错误信任通过 | 同左 | 同左 |

九份 `result.json` 均已核对 `status:passed`，每份包含三个场景；日志、结果副本及逐项摘要保存于 `.test-artifacts/xudp-interop-1bvv64ko/manifest.json`。该清单关联前述平台验收清单，重新核对生产输入与release摘要均未变化。官方二进制的版本、平台、官方校验与文件摘要由参考测试重新检查；本次外部平台仅macOS ARM64。

| XUDP客户端 | 原始结果路径 |
|---|---|
| Mihomo | `.test-artifacts/interop-mihomo-vless-xudp-K4jMcA/result.json` |
| sing-box | `.test-artifacts/interop-sing-box-vless-xudp-52nIGS/result.json` |
| Xray | `.test-artifacts/interop-xray-vless-xudp-2KrfSW/result.json` |

据实际执行证据，OpenSpec 2.8与3.2已完成，变更14/14完成；未自动归档、发布或部署。

## 基础组合历史结果

以下记录对应 XUDP 加入前的独立快照，不能作为当前构建的外部回归结果。

2026-11-04：macOS ARM64 普通测试101 passed / 0 failed / 6 ignored；Linux ARM64和x86_64（QEMU）各97项内核测试加4项配置生成测试通过，0失败。三平台 VLESS IPv6 均实际执行，无 SKIP。本机 fmt/check/严格Clippy/release 构建成功。

直接取得受控运行确认后显式执行六项官方客户端测试，6 passed / 0 failed，耗时6.98秒。范围：Mihomo VLESS TCP；sing-box/Xray VLESS TCP与原生UDP；三家Trojan TCP/UDP回归。各包含错误凭据及不受信任证书控制；错误信任仅测试TCP。

基础产物清单：`.test-artifacts/vless-acceptance-jm4d2n1c/manifest.json`。生产输入摘要 `94cecc44c6b889593c6330075f8d92d5a6d7bf67b5a3f59a16536b5335d30de9`，macOS release SHA-256 `7e166f300959df04ce816538fcd507c2ca056a11d4fbf0fb207dd03af31ae31c`。Cargo.lock 与当前相同。

| VLESS 客户端 | 已运行范围 | 结果产物 |
|---|---|---|
| Mihomo v1.19.33 | TCP、错误UUID、错误信任；UDP不在基础组合内 | `.test-artifacts/interop-mihomo-vless-7lRlQD/` |
| sing-box v1.14.4 | TCP、原生UDP两目标三报文、错误UUID、错误信任 | `.test-artifacts/interop-sing-box-vless-KekhzA/` |
| Xray v26.10.31 | TCP、原生UDP两目标三报文、错误UUID、错误信任 | `.test-artifacts/interop-xray-vless-afbMs3/` |

上述产物均已核对 `status:passed`。首次UDP集成测试缺少客户端TLS flush而触发空闲终止，已修正并回归；一次全目标编译碰到参考测试文件编辑中间态，文件完成后最终检查通过。测试凭据、证书及私钥不公开。

基础VLESS集成测试继续覆盖TCP首段载荷/半关闭/域名/计量、错误身份与扩展不拨号、原生UDP帧边界/预算/空闲/停机回收、IPv6及示例实际启动；CLI覆盖check不绑定、TLS匹配与UUID脱敏。原SOCKS5/Trojan测试全部保留并随当前构建回归。

REALITY/Vision 的固定源码与当前 TLS API 研究见 [reality-vision-feasibility.md](reality-vision-feasibility.md)。研究区分已观察事实与候选路径，不表示这些扩展已实现。

## 执行命令与环境

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets -- --nocapture
cargo build --locked --release
# 下载的官方客户端须获准执行；本次取得直接确认后9项通过：
cargo test --locked --test reference_clients -- --ignored --nocapture
```

Linux 使用已有 Colima 实例、专用缓存卷和固定官方镜像 `rust@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1`，源码只读挂载，普通测试不启动下载客户端。没有修改全局Docker context或系统代理，没有生产部署、发布、Git提交或OpenSpec归档。
