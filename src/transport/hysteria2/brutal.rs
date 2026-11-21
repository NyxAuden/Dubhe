//! Hysteria2 Brutal 控制器（服务端发送方向与客户端发送方向）。
//!
//! 对齐上游 `apernet/hysteria` 提交
//! `6b90c8c6bbe7c71ce849682ba9269acf44bc4abe`：
//!
//! - `core/internal/congestion/brutal/brutal.go`：固定目标速率，不按丢包降窗；
//!   发送窗口按 5 个一秒槽位统计 ACK 率，ACK 率低于 0.8 时把发送速率抬高到
//!   `target / 0.8`（损失补偿），样本不足 50 个包时不补偿。
//! - `core/internal/congestion/common/pacer.go`：独立令牌桶 pacer，预算按
//!   `target / ackRate` 补充。
//! - `core/server/server.go`：服务端发送方向使用
//!   `min(客户端 Hysteria-CC-RX, 服务端 bandwidth.up/MaxTx)`；忽略客户端带宽
//!   （`ignoreClientBandwidth`）时回退到配置的常规拥塞控制，并在认证响应中
//!   回 `Hysteria-CC-RX: auto`。服务端接收方向（`bandwidth.down/MaxRx`）只
//!   通过认证响应告知客户端，由客户端对上行发送做 Brutal；服务端自身不对
//!   接收方向做固定速率整形。
//!
//! # 已消除的差异
//!
//! 通过直接依赖与 quinn 0.11.11 已解析的同版本 `quinn-proto` 0.11.19：
//!
//! - [`Controller::on_ack`] 对每个新确认的 ack-eliciting 包调用一次，直接
//!   累计包数，等价于上游 `len(ackedPackets)`；不再用
//!   `sent - lost - in_flight` 字节推算。
//! - RTT 取自 ACK 回调的 [`RttEstimator::get`]（quinn 的平滑 RTT），等价于
//!   上游 `RTTStats.SmoothedRTT()`；不再每 100ms 轮询连接。
//! - 速率 0（不启用 Brutal）时把 ACK/丢包/MTU 事件委托给
//!   `quinn_proto::congestion::Cubic`，与 quinn 默认控制器完全一致；不再使用
//!   模块内重写的 Cubic 近似。
//!
//! # 仍存在的 quinn API 边界（不得据此宣称完整对齐）
//!
//! - **无独立 pacer**：quinn 的 `Pacer` 私有，发送预算由
//!   `window() * 1.25 / srtt` 推导，连接在途字节也以 `window()` 为上限
//!   （`quinn-proto-0.11.19/src/connection/mod.rs` 的发送循环）。上游窗口是
//!   `bps * srtt * 2 / ackRate`，其中 2 倍余量留给独立 pacer。这里暴露给 quinn
//!   的窗口取上游窗口的一半（`bps * srtt / ackRate`），使长期速率维持在
//!   `bps / ackRate`；突发吸收能力与平滑 pacing 仍与上游不同。
//! - **无逐包丢包列表**：`on_congestion_event` 只提供批量 `lost_bytes`，没有
//!   `lostPackets []LostPacketInfo`；只能按当前 MTU 折算包数，且该批字节可能
//!   混入 ACK-only 包。ACK 侧已是精确逐包计数，丢包侧仍是近似。
//! - **`bandwidth.disableLossCompensation` 未接入**：配置层不在本改动允许范围；
//!   控制器当前始终启用损失补偿（上游默认值）。
//!
//! 需要完全对齐时必须在 quinn 侧增加最小 API（独立 pacing 速率/预算钩子、
//! 逐包丢包计数或列表），仅靠直接依赖 `quinn-proto` 无法完成。精确证据见
//! `docs/hysteria2-brutal-alignment.md`。

use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use quinn_proto::RttEstimator;
use quinn_proto::congestion::{
    Controller, ControllerFactory, ControllerMetrics, Cubic, CubicConfig,
};

/// 上游 `pktInfoSlotCount`：ACK 率统计的秒槽数量。
const PKT_INFO_SLOTS: usize = 5;
/// 上游 `minSampleCount`。
const MIN_SAMPLE_COUNT: u64 = 50;
/// 上游 `minAckRate`。
const MIN_ACK_RATE: f64 = 0.8;
/// 上游 `GetCongestionWindow` 在 RTT 不可用时的返回值。
const INITIAL_CWND: u64 = 10 * 1024;

/// 上游 `congestionWindowMultiplier`。
const UPSTREAM_CWND_MULTIPLIER: f64 = 2.0;

/// Hysteria 服务端带宽配置，单位为 bit/s。
///
/// 方向严格按上游 `core/server/config.go` 的 `BandwidthConfig`：
///
/// - `up_bps` = `bandwidth.up` = `MaxTx`：**服务端发给客户端**的上限，
///   用于约束服务端发送方向的 Brutal 目标速率；
/// - `down_bps` = `bandwidth.down` = `MaxRx`：**客户端发给服务端**的上限，
///   只写入认证响应 `Hysteria-CC-RX`（单位 byte/s），不约束服务端发送。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Bandwidth {
    pub up_bps: u64,
    pub down_bps: u64,
}

impl Bandwidth {
    /// 上游要求非零带宽至少 65536 byte/s（524288 bit/s）。
    const MIN_NONZERO_BPS: u64 = 65_536 * 8;

    pub(crate) fn new(up_bps: u64, down_bps: u64) -> std::io::Result<Self> {
        for (name, value) in [("up", up_bps), ("down", down_bps)] {
            if value != 0 && value < Self::MIN_NONZERO_BPS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Hysteria2 bandwidth.{name} 至少为 65536 byte/s"),
                ));
            }
        }
        Ok(Self { up_bps, down_bps })
    }

    /// 从配置层的 `up_mbps` / `down_mbps` 构造。
    ///
    /// 配置字段与上游 `bandwidth.up/down` 同名同向；`None` 表示未设置。
    pub(crate) fn from_mbps(up_mbps: Option<u64>, down_mbps: Option<u64>) -> std::io::Result<Self> {
        fn convert(value: Option<u64>, name: &str) -> std::io::Result<u64> {
            value.unwrap_or(0).checked_mul(1_000_000).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Hysteria2 bandwidth.{name} 超出范围"),
                )
            })
        }
        Self::new(convert(up_mbps, "up")?, convert(down_mbps, "down")?)
    }

    /// 服务端发送方向（MaxTx）的 byte/s。
    pub(crate) fn tx_bytes_per_sec(&self) -> u64 {
        self.up_bps / 8
    }

    /// 服务端接收方向（MaxRx）的 byte/s；认证响应使用该单位。
    pub(crate) fn rx_bytes_per_sec(&self) -> u64 {
        self.down_bps / 8
    }
}

/// 计算认证后服务端发送方向的实际 Brutal 速率（byte/s，0 = 不使用 Brutal）。
///
/// 对应上游：
///
/// ```text
/// actualTx = clientRx
/// if MaxTx > 0 && actualTx > MaxTx { actualTx = MaxTx }
/// if ignoreClientBandwidth { actualTx = 0 }
/// if actualTx > 0 { UseBrutal(actualTx) } else { UseConfigured() }
/// ```
pub(crate) fn negotiate_tx_bytes(
    client_rx_bytes: u64,
    bandwidth: Bandwidth,
    ignore_client_bandwidth: bool,
) -> u64 {
    if ignore_client_bandwidth {
        return 0;
    }
    let cap = bandwidth.tx_bytes_per_sec();
    if cap > 0 {
        client_rx_bytes.min(cap)
    } else {
        client_rx_bytes
    }
}

/// 每条连接共享的 Brutal 目标速率。
///
/// 速率在认证完成后写入（服务端来自请求头，客户端来自认证响应）。控制器
/// 实例在每次 ACK/丢包事件时读取该值；`rate == 0` 表示回退常规拥塞控制。
pub(crate) struct BrutalControl {
    rate_bytes_per_sec: AtomicU64,
}

impl BrutalControl {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            rate_bytes_per_sec: AtomicU64::new(0),
        })
    }

    pub(crate) fn set_rate(&self, bytes_per_sec: u64) {
        self.rate_bytes_per_sec
            .store(bytes_per_sec, Ordering::Relaxed);
    }

    pub(crate) fn rate(&self) -> u64 {
        self.rate_bytes_per_sec.load(Ordering::Relaxed)
    }
}

/// 为每条连接构造 Brutal 控制器。
pub(crate) struct BrutalFactory {
    control: Arc<BrutalControl>,
}

impl BrutalFactory {
    pub(crate) fn new(control: Arc<BrutalControl>) -> Arc<Self> {
        Arc::new(Self { control })
    }
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.control.clone(), now, current_mtu))
    }
}

/// 上游 `pktInfo` 的 Rust 版本；`timestamp` 为控制器启动后的秒数。
#[derive(Clone, Copy, Default, Debug)]
struct PktInfo {
    timestamp: i64,
    ack_count: u64,
    loss_count: u64,
}

/// 上游 ACK 率统计：最近 5 个一秒槽位内 `acked / (acked + lost)`。
///
/// ACK 计数来自每个 `on_ack` 回调（一包一次）；丢包计数来自
/// `on_congestion_event` 的批量字节折算，见模块文档中的剩余边界。
#[derive(Clone, Debug)]
struct AckRateTracker {
    epoch: Instant,
    slots: [PktInfo; PKT_INFO_SLOTS],
    ack_rate: f64,
}

impl AckRateTracker {
    fn new(now: Instant) -> Self {
        Self {
            epoch: now,
            slots: [PktInfo::default(); PKT_INFO_SLOTS],
            ack_rate: 1.0,
        }
    }

    fn timestamp(&self, now: Instant) -> i64 {
        i64::try_from(now.saturating_duration_since(self.epoch).as_secs()).unwrap_or(i64::MAX)
    }

    /// 记录一批确认/丢包。上游按“包数”统计。
    fn record(&mut self, now: Instant, acked: u64, lost: u64) {
        let timestamp = self.timestamp(now);
        let slot = (timestamp.rem_euclid(PKT_INFO_SLOTS as i64)) as usize;
        if self.slots[slot].timestamp == timestamp {
            self.slots[slot].ack_count = self.slots[slot].ack_count.saturating_add(acked);
            self.slots[slot].loss_count = self.slots[slot].loss_count.saturating_add(lost);
        } else {
            self.slots[slot] = PktInfo {
                timestamp,
                ack_count: acked,
                loss_count: lost,
            };
        }
        self.update(timestamp);
    }

    /// 严格复刻上游 `updateAckRate`：
    /// 样本不足 50 时保持 1.0；低于 0.8 时钳到 0.8。
    fn update(&mut self, timestamp: i64) {
        let min_timestamp = timestamp - PKT_INFO_SLOTS as i64;
        let mut ack_count = 0u64;
        let mut loss_count = 0u64;
        for info in &self.slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count = ack_count.saturating_add(info.ack_count);
            loss_count = loss_count.saturating_add(info.loss_count);
        }
        let total = ack_count.saturating_add(loss_count);
        if total < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            return;
        }
        let rate = ack_count as f64 / total as f64;
        self.ack_rate = if rate < MIN_ACK_RATE {
            MIN_ACK_RATE
        } else {
            rate
        };
    }
}

/// Brutal 控制器。
///
/// 丢包不会直接缩小窗口：`on_congestion_event` 只累计 ACK 率样本，窗口
/// 变化仅来自 `rate / ack_rate` 的损失补偿。这一点与 BBR 的自适应带宽
/// 探测有本质区别。速率 0 时完全委托 quinn 内置 `Cubic`。
pub(crate) struct Brutal {
    control: Arc<BrutalControl>,
    /// 速率 0 时的回退控制器；直接委托 quinn 内置实现，保证普通 QUIC 行为不变。
    fallback: Cubic,
    tracker: AckRateTracker,
    mtu: u64,
    /// 最近一次 ACK 回调报告的平滑 RTT（上游 `SmoothedRTT()`）。
    srtt: Option<Duration>,
    /// 上一次观察到并初始化 ACK 率窗口的目标速率；用于认证后切换到 Brutal
    /// 时等价于上游新建 sender。
    observed_rate: u64,
}

impl Brutal {
    pub(crate) fn new(control: Arc<BrutalControl>, now: Instant, current_mtu: u16) -> Self {
        Self {
            control,
            fallback: Cubic::new(Arc::new(CubicConfig::default()), now, current_mtu.max(1)),
            tracker: AckRateTracker::new(now),
            mtu: u64::from(current_mtu.max(1)),
            srtt: None,
            observed_rate: 0,
        }
    }

    /// 上游 `GetCongestionWindow` 的 quinn 适配值。
    ///
    /// 上游：`rate * srtt * 2 / ack_rate`；quinn 没有独立 pacer，窗口同时
    /// 是 pacing 来源，因此去掉为独立 pacer 预留的 2 倍余量。长期发送速率
    /// 仍为 `rate / ack_rate`，但突发与 pacing 时机不等价。
    fn brutal_window(&self, rate: u64, srtt: Option<Duration>) -> u64 {
        let Some(srtt) = srtt else {
            return INITIAL_CWND;
        };
        let upstream_window =
            rate as f64 * srtt.as_secs_f64() * UPSTREAM_CWND_MULTIPLIER / self.ack_rate();
        // 上游的 2 倍余量留给独立 pacer；quinn 的 pacer 由窗口推导，
        // 因此这里折掉该倍数，使长期速率仍为 rate / ack_rate。
        let window = upstream_window / UPSTREAM_CWND_MULTIPLIER;
        // quinn 以 `in_flight + bytes >= window` 判定阻塞，窗口等于一个
        // MTU 时连一个满包都发不出去，因此下限取 2 个 MTU（上游为 1 个）。
        (window as u64).max(self.mtu.saturating_mul(2))
    }

    fn ack_rate(&self) -> f64 {
        self.tracker.ack_rate
    }

    /// 记录 ACK/丢包样本，并在目标速率变化时重置统计窗口。
    ///
    /// 速率 0 期间不采样：上游在认证后新建 Brutal sender，握手阶段的
    /// ACK 不应计入 ACK 率。
    fn record_ack_rate(&mut self, now: Instant, acked: u64, lost: u64) {
        let rate = self.control.rate();
        if rate == 0 {
            self.observed_rate = 0;
            return;
        }
        if rate != self.observed_rate {
            self.observed_rate = rate;
            self.tracker = AckRateTracker::new(now);
        }
        self.tracker.record(now, acked, lost);
    }

    /// 一次 ACK 回调 = 一个被确认的 ack-eliciting 包。
    fn observe_ack(&mut self, now: Instant, rtt: Duration) {
        if !rtt.is_zero() {
            self.srtt = Some(rtt);
        }
        self.record_ack_rate(now, 1, 0);
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // 回退控制器始终跟随 ACK 事件，速率切回 0 时可立即接管。
        self.fallback.on_ack(now, sent, bytes, app_limited, rtt);
        self.observe_ack(now, rtt.get());
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.fallback
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        // 上游 OnCongestionEventEx 按丢包个数统计；ECN 触发（lost_bytes
        // 为 0）不参与 ACK 率。quinn 只给批量字节，按 MTU 折算为包数。
        if lost_bytes > 0 {
            let packets = lost_bytes.div_ceil(self.mtu);
            self.record_ack_rate(now, 0, packets);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu.max(1));
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        let rate = self.control.rate();
        if rate == 0 {
            return self.fallback.window();
        }
        self.brutal_window(rate, self.srtt)
    }

    fn metrics(&self) -> ControllerMetrics {
        if self.control.rate() == 0 {
            return self.fallback.metrics();
        }
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        // 上游 pacer 的目标速率是 bps / ackRate；单位 bit/s。
        metrics.pacing_rate = Some((self.control.rate() as f64 * 8.0 / self.ack_rate()) as u64);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            control: self.control.clone(),
            fallback: self.fallback.clone(),
            tracker: self.tracker.clone(),
            mtu: self.mtu,
            srtt: self.srtt,
            observed_rate: self.observed_rate,
        })
    }

    fn initial_window(&self) -> u64 {
        if self.control.rate() == 0 {
            self.fallback.initial_window()
        } else {
            self.window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(rate: u64, srtt: Duration) -> Brutal {
        let control = BrutalControl::new();
        control.set_rate(rate);
        let now = Instant::now();
        let mut brutal = Brutal::new(control, now, 1200);
        brutal.observe_ack(now, srtt);
        brutal
    }

    fn quinn_default_cubic(now: Instant) -> Cubic {
        Cubic::new(Arc::new(CubicConfig::default()), now, 1200)
    }

    #[test]
    fn bandwidth_direction_matches_upstream_max_tx_max_rx() {
        let bandwidth = Bandwidth::from_mbps(Some(8), Some(4)).unwrap();
        assert_eq!(bandwidth.tx_bytes_per_sec(), 1_000_000);
        assert_eq!(bandwidth.rx_bytes_per_sec(), 500_000);

        // bandwidth.up 约束服务端发送方向；bandwidth.down 只用于通告。
        assert_eq!(negotiate_tx_bytes(2_000_000, bandwidth, false), 1_000_000);
        assert_eq!(negotiate_tx_bytes(400_000, bandwidth, false), 400_000);
        assert_eq!(negotiate_tx_bytes(2_000_000, bandwidth, true), 0);
        // 未配置 MaxTx 时不做上限裁剪。
        assert_eq!(
            negotiate_tx_bytes(2_000_000, Bandwidth::new(0, 4_000_000).unwrap(), false),
            2_000_000
        );
    }

    #[test]
    fn rejects_upstream_minimum_bandwidth_violations() {
        assert!(Bandwidth::new(65_536 * 8 - 1, 0).is_err());
        assert!(Bandwidth::new(0, 65_536 * 8 - 1).is_err());
        assert!(Bandwidth::new(65_536 * 8, 65_536 * 8).is_ok());
    }

    #[test]
    fn window_is_upstream_window_halved_for_quinn_pacing() {
        let brutal = controller(1_000_000, Duration::from_millis(100));
        let upstream_window = 1_000_000f64 * 0.1 * UPSTREAM_CWND_MULTIPLIER / 1.0;
        assert_eq!(brutal.ack_rate(), 1.0);
        // 上游公式与独立 pacer 的速率一致；quinn 窗口是它的一半。
        assert_eq!(brutal.window() as f64, upstream_window / 2.0);
        assert_eq!(brutal.window(), 100_000);
    }

    #[test]
    fn no_rtt_uses_upstream_initial_window() {
        let control = BrutalControl::new();
        control.set_rate(1_000_000);
        let brutal = Brutal::new(control, Instant::now(), 1200);
        assert_eq!(brutal.window(), INITIAL_CWND);
    }

    #[test]
    fn rtt_is_taken_from_ack_callback_not_sampled() {
        let control = BrutalControl::new();
        control.set_rate(1_000_000);
        let now = Instant::now();
        let mut brutal = Brutal::new(control, now, 1200);
        brutal.observe_ack(now, Duration::from_millis(50));
        assert_eq!(brutal.window(), 50_000);
        brutal.observe_ack(now, Duration::from_millis(200));
        assert_eq!(brutal.window(), 200_000);
    }

    #[test]
    fn insufficient_samples_do_not_compensate_loss() {
        let control = BrutalControl::new();
        control.set_rate(1_000_000);
        let now = Instant::now();
        let mut brutal = Brutal::new(control, now, 1200);
        brutal.srtt = Some(Duration::from_millis(100));
        // 49 个样本（10 ACK + 39 loss）低于上游 minSampleCount。
        brutal.record_ack_rate(now, 10, 39);
        assert_eq!(brutal.ack_rate(), 1.0, "少于 50 个样本时上游不补偿");
        assert_eq!(brutal.window(), 100_000);
    }

    #[test]
    fn loss_compensation_uses_ack_rate_floor_and_never_halves_window() {
        let mut brutal = controller(1_000_000, Duration::from_millis(100));
        let now = Instant::now();
        brutal.record_ack_rate(now, 50, 50);
        assert_eq!(brutal.ack_rate(), MIN_ACK_RATE);
        // 只有 1/0.8 = 1.25 倍补偿，没有 Cubic/BBR 式的降窗。
        assert_eq!(brutal.window(), 125_000);
        assert_eq!(brutal.metrics().pacing_rate, Some(10_000_000));
    }

    #[test]
    fn per_packet_ack_callback_counts_packets_exactly() {
        let control = BrutalControl::new();
        control.set_rate(1_000_000);
        let now = Instant::now();
        let mut brutal = Brutal::new(control.clone(), now, 1200);
        // 速率切换后的第一个 ACK 会重置统计窗口，因此从第一批开始计数。
        for _ in 0..600 {
            brutal.observe_ack(now, Duration::from_millis(100));
        }
        brutal.on_congestion_event(now, now, false, 400 * 1200);
        let acked: u64 = brutal.tracker.slots.iter().map(|slot| slot.ack_count).sum();
        let lost: u64 = brutal
            .tracker
            .slots
            .iter()
            .map(|slot| slot.loss_count)
            .sum();
        assert_eq!(acked, 600);
        assert_eq!(lost, 400);
        assert_eq!(brutal.ack_rate(), 0.6f64.max(MIN_ACK_RATE));
        assert_eq!(brutal.window(), 125_000);
    }

    #[test]
    fn congestion_event_only_records_samples_and_does_not_shrink_window() {
        let mut brutal = controller(1_000_000, Duration::from_millis(100));
        let now = Instant::now();
        let before = brutal.window();
        brutal.on_congestion_event(now, now, false, 10 * 1200);
        assert_eq!(brutal.window(), before, "Brutal 不按丢包直接降窗");
        assert_eq!(
            brutal
                .tracker
                .slots
                .iter()
                .map(|slot| slot.loss_count)
                .sum::<u64>(),
            10
        );
    }

    #[test]
    fn rate_zero_delegates_to_quinn_cubic_exactly() {
        let control = BrutalControl::new();
        let now = Instant::now();
        let mut brutal = Brutal::new(control.clone(), now, 1200);
        let mut cubic = quinn_default_cubic(now);

        assert_eq!(brutal.initial_window(), cubic.initial_window());
        assert_eq!(brutal.window(), cubic.window());

        // 丢包响应与 MTU 更新和内置 Cubic 逐字节一致。
        brutal.on_congestion_event(now, now, false, 1200);
        cubic.on_congestion_event(now, now, false, 1200);
        assert_eq!(brutal.window(), cubic.window());

        brutal.on_mtu_update(1500);
        cubic.on_mtu_update(1500);
        assert_eq!(brutal.window(), cubic.window());
        assert_eq!(brutal.metrics().congestion_window, cubic.window());

        // 认证写入速率后切换到 Brutal，归零后回退到同一个 Cubic 状态。
        control.set_rate(1_000_000);
        brutal.observe_ack(now, Duration::from_millis(100));
        assert_eq!(brutal.window(), 100_000);
        control.set_rate(0);
        assert_eq!(brutal.window(), cubic.window());
    }

    #[test]
    fn pre_auth_acks_do_not_pollute_brutal_samples() {
        let control = BrutalControl::new();
        let now = Instant::now();
        let mut brutal = Brutal::new(control.clone(), now, 1200);
        // 速率 0 期间（握手/认证）即使发生大量丢包也不采样。
        brutal.on_congestion_event(now, now, false, 1000 * 1200);
        assert_eq!(brutal.ack_rate(), 1.0);

        control.set_rate(1_000_000);
        // 速率切换后的第一个 ACK 重置窗口，之后的样本才生效。
        brutal.observe_ack(now, Duration::from_millis(100));
        brutal.on_congestion_event(now, now, false, 60 * 1200);
        assert_eq!(brutal.ack_rate(), MIN_ACK_RATE);
    }
}
