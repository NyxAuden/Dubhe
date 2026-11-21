# Hysteria2 Brutal 对齐核查（2026-11-13 更新）

## 固定输入

- 上游 apernet/hysteria 提交：`6b90c8c6bbe7c71ce849682ba9269acf44bc4abe`
  （仓库已重定向到 `HyNetworks/hysteria`，提交哈希不变）。
- `core/internal/congestion/brutal/brutal.go` SHA-256：
  `c620671ca0bfff791c512fda1b0a3cda48e44688430e30c8ab57677e4a87f83a`。
- `core/internal/congestion/common/pacer.go` SHA-256：
  `ca7cb0bd5897e573050522d7c8ec85b21964843d7cd2ac2fb0929f375442ed3c`。
- 上游 `apernet/quic-go` 提交 `2895f039137a405a34cffbcb27510ad31717d89a`
  （`OnCongestionEventEx` 的逐包 ACK/丢包列表定义）。
- 锁定 `quinn 0.11.11`、`quinn-proto 0.11.19`。

## 结论

**本次已消除三类差异，但完整 Brutal 上游等价仍未完成，不得宣称完全对齐。**
剩余差距集中在 quinn 的 pacing 与丢包反馈 API，不在本仓库的控制算法。

| 上游行为 | 当前状态 |
| --- | --- |
| 逐包 ACK 计数：`len(ackedPackets)` | **已对齐**：`Controller::on_ack` 每确认一个 ack-eliciting 包调用一次 |
| RTT 取 ACK 时的 `SmoothedRTT()` | **已对齐**：ACK 回调直接读 `RttEstimator::get()` |
| 非 Brutal 回退到常规拥塞控制 | **已对齐**：直接委托 `quinn_proto::congestion::Cubic` |
| 5 秒槽、50 样本、ACK 率下限 0.8、丢包不降窗 | **算法一致**：ACK 侧精确，丢包侧按 MTU 折算 |
| 独立 pacer：`bps / ackRate` 令牌桶 | **仍阻塞**：quinn `Pacer` 私有且由窗口推导 |
| 逐包丢包列表：`len(lostPackets)` | **仍阻塞**：quinn 只给批量 `lost_bytes` |
| `bandwidth.disableLossCompensation` | **未接入**：配置层不在允许改动范围，当前始终补偿 |

## 2026-11-13 已消除的差异

### 1. 逐包 ACK（精确）

直接依赖与 quinn 0.11.11 已解析的同版本 `quinn-proto = 0.11.19`（Cargo.lock
仅新增根包对 `quinn-proto` 的一行引用，无新包、无版本变化），从而可以在
`on_ack` 中命名 `RttEstimator`。

quinn 的 ACK 路径（`quinn-proto-0.11.19/src/connection/mod.rs`）：

- `on_ack_received` 对每个新确认包调用 `on_packet_acked`（第 1527 行）；
- `on_packet_acked` 在包为 ack-eliciting 时调用
  `congestion.on_ack(now, sent, size, app_limited, &path.rtt)`（第 1613–1623 行）；
- 一批 ACK 处理完后调用一次 `on_end_acks`（第 1531 行）。

因此控制器把每个 `on_ack` 计为一个包，等价于上游
`OnCongestionEventEx` 的 `len(ackedPackets)`；不再使用
`sent - lost - in_flight` 字节推算，也不再把纯 ACK/小包折算成包数。

极小边界：quinn 在当前路径挑战（`challenge.is_none()` 为假）期间不把 ACK
转发给控制器，路径迁移/验证窗口内可能少计少量 ACK；常规单路径代理不受影响，
上游对应路径是否需要同口径过滤未在本仓库验证。

### 2. RTT 来自 ACK 回调

`on_ack` 的 `rtt: &RttEstimator` 是连接当前的 RFC6298 平滑 RTT；
控制器在每次 ACK 时读取 `rtt.get()` 并用于下一个窗口决策，等价于上游
`b.rttStats.SmoothedRTT()`（`brutal.go:79-86`）。

`mod.rs` 与 `client.rs` 中每 100ms 轮询 `connection.rtt()` 的后台任务已删除；
RTT 现在只来自真实 ACK，空闲连接不会用轮询值驱动窗口。

### 3. Cubic 委托

速率 0（认证前、`ignoreClientBandwidth`、客户端收到 `Hysteria-CC-RX: auto`
或 0）时，`Brutal::window/on_ack/on_congestion_event/on_mtu_update/metrics/
initial_window/clone_box` 全部委托 `quinn_proto::congestion::Cubic`。
这与 quinn 默认 Cubic 是同一份实现，不再有模块内重写的近似；单元测试
`rate_zero_delegates_to_quinn_cubic_exactly` 对初始窗口、丢包响应、MTU 更新
逐字节比较。

### 4. 认证后的统计窗口

速率从 0 切到非 0 时重置 5 秒 ACK 率槽位（等价上游认证后新建
`BrutalSender`），速率 0 期间不采样。`disableLossCompensation` 未接入，
因此控制器始终执行损失补偿（上游默认值）。

## 仍阻塞的精确边界（quinn 0.11.19）

### A. 独立 pacer（无法仅靠直接依赖解决）

上游 pacer 与窗口是两套独立机制：

- `pacer.go:23-30`：pacer 的带宽函数为 `bps / ackRate`；
- `brutal.go:79-86`：窗口为 `bps * srtt * 2 / ackRate`，2 倍余量留给 pacer；
- `brutal.go:39-44`：`CanSend` 用 `bytesInFlight <= cwnd`。

quinn 中 pacer 是私有的，且发送预算完全由拥塞窗口推导：

- `src/connection/pacing.rs:15`：`pub(super) struct Pacer`，外部不可访问；
- `src/connection/pacing.rs:92`：令牌补充为 `window * 1.25 * elapsed_rtts`；
- `src/connection/pacing.rs:129`：容量由 `window` 与 `srtt` 计算；
- `src/connection/mod.rs:616`：在途上限为
  `in_flight.bytes + bytes_to_send >= congestion.window()`；
- `src/connection/mod.rs:627-632`：`pacing.delay(...)` 直接接收
  `congestion.window()`。

若把上游 2 倍窗口原样返回，quinn 会同时把 pacing 提高到约 2.5 倍目标速率；
因此当前仍返回**半窗** `bps * srtt / ackRate`（下限 2 个 MTU），使长期平均
速率等于上游的 `bps / ackRate`。这不等于独立 pacer：突发吸收只有约 1 个
BDP（上游 2 个），发送由窗口/ACK 时钟驱动而非固定速率令牌桶。

最小补丁方案（需修改 quinn/quinn-proto，不在本次授权范围）：

1. 在 `quinn-proto/src/congestion.rs` 的 `Controller` 增加
   `fn pacing_rate(&self) -> Option<u64>`（byte/s），默认 `None`；
2. `quinn-proto/src/connection/pacing.rs` 的 `delay` 在 `Some(rate)` 时用该
   速率替代 `window * 1.25 / srtt` 的令牌补充，容量仍按上限钳制；
3. `quinn-proto/src/connection/mod.rs:627` 把
   `congestion.pacing_rate()` 传入 pacer；`window()` 则可返回上游 2 倍 cwnd。
4. 普通 QUIC 路径默认 `None`，行为不变。

### B. 逐包丢包（无法仅靠直接依赖解决）

上游 `OnCongestionEventEx` 收到 `lostPackets []LostPacketInfo`，Brutal 按
`len(lostPackets)` 计数（`brutal.go:109-130`；接口定义见 quic-go
`congestion/interface.go:34-37,55-58`；构造见
`internal/ackhandler/sent_packet_handler.go:1031`）。

quinn 的钩子只有：

- `src/congestion.rs:54-64`：`on_congestion_event(..., lost_bytes: u64)`；
- `src/connection/mod.rs:1807-1812`：调用方传入
  `size_of_lost_packets`（批量字节），逐包 `lost_packets` 列表在同文件
  `1770-1790` 行内部迭代，未暴露。

当前按 `lost_bytes.div_ceil(mtu)` 折算包数。批量字节可能混入 ACK-only 包，
且小包/混合尺寸会失真；ACK 侧精确、丢包侧仍为近似。

最小补丁方案：

1. 在 `Controller::on_congestion_event` 增加 `lost_packets: u64` 参数，或在
   trait 增加带 `&[LostPacketInfo]` 的扩展回调；
2. 调用点传入 `lost_packets.len()`（Brutal 只需要计数；若要精确字节可用
   列表本身）；
3. 仅对 ack-eliciting 丢包计数以匹配上游 `IsAckEliciting()` 过滤。

### C. disableLossCompensation

上游服务端 `core/server/server.go:196` 与客户端
`core/client/client.go:162` 都把 `bandwidth.disableLossCompensation` 传给
`NewBrutalSender`；`brutal.go:132-136` 在启用时强制 `ackRate = 1`。

本仓库 `config.rs` 尚无该字段，`runtime.rs`/`route.rs` 也未传递；添加需要
修改 `src/config.rs` 与运行时映射，超出本次允许的文件范围。控制器当前行为
对应上游默认值 `false`。

## 测试

- `CARGO_INCREMENTAL=0 cargo test --locked --lib hysteria2`：25 passed。
- `CARGO_INCREMENTAL=0 cargo test --locked --test hysteria2`：26 passed，
  包含 `client_declared_rx_activates_brutal_send_path` 的真实 QUIC 回环。
- 依赖变更：`quinn-proto = { version = "=0.11.19", default-features = false }`
  作为直接依赖；`Cargo.lock` 仅根包依赖列表新增一行，无新包/版本变化。

单元测试覆盖：逐包 ACK 计数、RTT 来自 ACK 回调、49/50 样本边界、0.8 下限、
丢包不降窗、速率切换重置、认证前不采样、Cubic 委托等价。

## 2026-11-12 出站接入补充（历史）

Hysteria2 出站已增加 `hysteria2.up_mbps/down_mbps`：认证请求发送本端接收带宽
`Hysteria-CC-RX`，从认证响应读取服务端接收带宽，并按
`actualTx = min(serverRx, up_mbps)` 设置客户端发送控制器；`auto` 或 0 保持回退。
客户端与服务端复用同一 `BrutalControl`/`BrutalFactory`。BBR profile、realm、
端口跳跃仍不支持。已用官方 sing-box v1.14.4 服务端完成本机 TCP 互通，但未做
官方客户端/全矩阵验收。
