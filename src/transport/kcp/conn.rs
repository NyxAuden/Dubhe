//! 单会话 KCP 状态机与异步流。
//!
//! 结构对应 Xray `transport/internet/kcp/{sending,receiving,connection}.go`：
//! 发送窗口按序号重传，接收窗口乱序缓存并批量 ACK，定时器由 driver 任务驱动。
//! 读写两端共享同一把状态锁；driver 只在短临界区内更新状态，网络发送在锁外完成。

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::{Notify, mpsc},
    time::{MissedTickBehavior, timeout},
};
use tokio_util::sync::CancellationToken;

use super::{
    Prepared,
    mask::Mask,
    segment::{
        ACK_LIMIT, AckSegment, COMMAND_PING, COMMAND_TERMINATE, CmdSegment, DataSegment, Segment,
    },
};

/// 与 Xray 相同：3 秒无数据发送 ping，30 秒无入站关闭连接。
const PING_INTERVAL: u32 = 3_000;
const IDLE_TIMEOUT: u32 = 30_000;
/// 关闭阶段：先排空发送窗口（最多 15 秒），再重传 Terminate 3 秒。
const DRAIN_LIMIT: u32 = 15_000;
const TERMINATE_GRACE: u32 = 3_000;
/// ACK 列表与接收窗口的硬上限，避免恶意序号撑大内存。
const MAX_ACKS: usize = 4_096;
/// IPv4 的普通 UDP 有效载荷上限；统一使用较小的上限，不能靠 UDP 分片兜底。
const MAX_UDP_PAYLOAD: usize = 65_507;
/// 含多个 MTU 报文的单轮发送也必须有界，防止停机取消卡在 UDP 可写等待。
const SEND_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Sent {
    number: u32,
    payload: Vec<u8>,
    timeout: u32,
    transmit: u32,
}

#[derive(Debug)]
struct AckEntry {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

#[derive(Debug, Default)]
pub(crate) struct Shared {
    snd: VecDeque<Sent>,
    next_number: u32,
    first_unacked: u32,
    remote_next: u32,
    control_window: u32,
    rcv: HashMap<u32, Vec<u8>>,
    rcv_next: u32,
    acks: VecDeque<AckEntry>,
    srtt: u32,
    rttvar: u32,
    rto: u32,
    min_rtt: u32,
    last_incoming: u32,
    last_ping: u32,
    close_started: Option<u32>,
    terminating_started: Option<u32>,
    local_closed: bool,
    peer_terminated: bool,
    terminated: bool,
    /// 首个驱动发送/编码失败；所有后续读写必须保持失败关闭。
    error: Option<io::Error>,
    read_buf: Vec<u8>,
    read_eof: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl Shared {
    fn new(prepared: &Prepared) -> Self {
        Self {
            remote_next: 32,
            control_window: prepared.sending_in_flight,
            rto: 100,
            min_rtt: prepared.tti_ms,
            last_incoming: 0,
            last_ping: 0,
            ..Self::default()
        }
    }

    fn error(&self) -> Option<io::Error> {
        self.error
            .as_ref()
            .map(|error| io::Error::new(error.kind(), error.to_string()))
    }

    fn fail(&mut self, error: io::Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
        self.local_closed = true;
        self.terminated = true;
        self.read_eof = true;
        self.snd.clear();
        self.rcv.clear();
        self.read_buf.clear();
        self.acks.clear();
        self.refresh_first_unacked();
        self.wake_reader();
        self.wake_writer();
    }

    fn wake_reader(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    fn wake_writer(&mut self) {
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }

    fn refresh_first_unacked(&mut self) {
        self.first_unacked = self
            .snd
            .front()
            .map_or(self.next_number, |sent| sent.number);
    }

    /// 丢弃序号小于 `una` 的已发送段（对端已按序接收）。
    fn clear_below(&mut self, una: u32) {
        while let Some(front) = self.snd.front() {
            if serial_lt(front.number, una) {
                self.snd.pop_front();
            } else {
                break;
            }
        }
        self.refresh_first_unacked();
    }

    fn remove_acked(&mut self, numbers: &[u32]) -> (u32, bool) {
        if numbers.is_empty() || self.snd.is_empty() {
            return (0, false);
        }
        let acked: HashSet<u32> = numbers.iter().copied().collect();
        let before = self.snd.len();
        self.snd.retain(|sent| !acked.contains(&sent.number));
        let removed = before != self.snd.len();
        if removed {
            self.refresh_first_unacked();
        }
        let maxack = numbers
            .iter()
            .copied()
            .filter(|number| acked.contains(number))
            .fold(
                0,
                |max, number| {
                    if serial_lt(max, number) { number } else { max }
                },
            );
        (maxack, removed)
    }

    /// RFC 6298 平滑 RTT；Xray 额外把 RTO 乘 5/4，上限 10 秒。
    fn update_rtt(&mut self, rtt: u32) {
        if rtt > 0x7fff_ffff {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.rttvar = rtt / 2;
        } else {
            let delta = self.srtt.abs_diff(rtt);
            self.rttvar = (3 * self.rttvar + delta) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }
        let base = if self.min_rtt < 4 * self.rttvar {
            self.srtt + 4 * self.rttvar
        } else {
            self.srtt + self.rttvar
        };
        self.rto = base.min(10_000) * 5 / 4;
    }

    /// 快速重传：确认 `maxack` 时提前重传其之前的段。
    fn fast_ack(&mut self, maxack: u32, rto: u32) {
        let step = rto / 3;
        for sent in &mut self.snd {
            if !serial_lt(sent.number, maxack) {
                break;
            }
            if sent.transmit > 0 && sent.timeout > step {
                sent.timeout -= step;
            }
        }
    }

    fn drain_ordered(&mut self) {
        while let Some(payload) = self.rcv.remove(&self.rcv_next) {
            self.read_buf.extend_from_slice(&payload);
            self.rcv_next = self.rcv_next.wrapping_add(1);
        }
    }
}

/// 一个 KCP 会话流；读完即 EOF，写到对端确认窗口受限。
pub(crate) struct KcpStream {
    shared: Arc<Mutex<Shared>>,
    wake: Arc<Notify>,
    mss: usize,
    max_segments: usize,
}

impl KcpStream {
    pub(crate) fn error(&self) -> Option<io::Error> {
        self.shared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .error()
    }

    fn new(prepared: &Prepared) -> (Self, Arc<Mutex<Shared>>, Arc<Notify>) {
        let shared = Arc::new(Mutex::new(Shared::new(prepared)));
        let wake = Arc::new(Notify::new());
        (
            Self {
                shared: shared.clone(),
                wake: wake.clone(),
                mss: prepared.mss,
                max_segments: prepared.sending_buffer as usize,
            },
            shared,
            wake,
        )
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut shared = this
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(error) = shared.error() {
            return Poll::Ready(Err(error));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !shared.read_buf.is_empty() {
            let count = shared.read_buf.len().min(buf.remaining());
            buf.put_slice(&shared.read_buf[..count]);
            shared.read_buf.drain(..count);
            return Poll::Ready(Ok(()));
        }
        if shared.read_eof || shared.terminated {
            return Poll::Ready(Ok(()));
        }
        shared.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut shared = this
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(error) = shared.error() {
            return Poll::Ready(Err(error));
        }
        if shared.local_closed || shared.terminated {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "KCP 会话已关闭",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut written = 0;
        while written < buf.len() && shared.snd.len() < this.max_segments {
            let end = (written + this.mss).min(buf.len());
            let number = shared.next_number;
            shared.snd.push_back(Sent {
                number,
                payload: buf[written..end].to_vec(),
                timeout: 0,
                transmit: 0,
            });
            shared.next_number = shared.next_number.wrapping_add(1);
            written = end;
        }
        if written == 0 {
            // 窗口检查与注册唤醒不能跨两次加锁，否则 ACK/失败会丢失唤醒。
            shared.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        drop(shared);
        this.wake.notify_one();
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        this.wake.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut shared = this
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(error) = shared.error() {
            return Poll::Ready(Err(error));
        }
        if !shared.local_closed {
            shared.local_closed = true;
            shared.close_started = None;
            shared.read_eof = true;
            shared.wake_reader();
        }
        drop(shared);
        this.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !shared.local_closed {
            shared.local_closed = true;
            shared.close_started = None;
            shared.read_eof = true;
        }
        drop(shared);
        self.wake.notify_one();
    }
}

/// driver 任务所需的会话外状态。
pub(crate) struct Driver {
    pub socket: Arc<UdpSocket>,
    pub dest: SocketAddr,
    pub mask: Arc<Mutex<Mask>>,
    pub conv: u16,
    pub prepared: Arc<Prepared>,
    pub rx: mpsc::Receiver<Vec<Segment>>,
    pub stop: CancellationToken,
    pub on_exit: Option<Box<dyn FnOnce() + Send + Sync>>,
}

pub(crate) fn start(prepared: &Prepared) -> (KcpStream, Arc<Mutex<Shared>>, Arc<Notify>) {
    KcpStream::new(prepared)
}

impl Driver {
    pub async fn run(mut self, shared: Arc<Mutex<Shared>>, wake: Arc<Notify>) {
        let started = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(u64::from(
            self.prepared.tti_ms.max(1),
        )));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = self.stop.cancelled() => {
                    // 停机时先发送 Terminate，让对端立即看到关闭而不是等待超时。
                    let segment = {
                        let shared = shared.lock().unwrap_or_else(|error| error.into_inner());
                        (!shared.terminated).then(|| Segment::Cmd(CmdSegment {
                            conv: self.conv,
                            command: COMMAND_TERMINATE,
                            option: 1,
                            sending_next: shared.first_unacked,
                            receiving_next: shared.rcv_next,
                            peer_rto: shared.rto,
                        }))
                    };
                    if let Some(segment) = segment
                        && let Err(error) = self.send_segments(&[segment]).await
                    {
                        self.fail(&shared, error);
                    }
                    self.close(shared.clone());
                    break;
                }
                Some(segments) = self.rx.recv() => {
                    self.input(&shared, started, segments);
                }
                _ = tick.tick() => {
                    if !self.tick(&shared, started).await {
                        break;
                    }
                }
                _ = wake.notified() => {
                    if !self.tick(&shared, started).await {
                        break;
                    }
                }
                else => break,
            }
        }
        // 所有正常/失败退出都发布关闭状态；已有首错不会被正常关闭覆盖。
        self.close(shared);
        if let Some(callback) = self.on_exit.take() {
            callback();
        }
    }

    /// 配置 MTU 描述 KCP 层；外层掩码额外占用 UDP 预算，保持满 MSS 线序兼容。
    async fn send_segments(&self, segments: &[Segment]) -> io::Result<()> {
        timeout(SEND_TIMEOUT, self.send_packets(segments))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "KCP UDP 发送超时"))?
    }

    async fn send_packets(&self, segments: &[Segment]) -> io::Result<()> {
        let overhead = self
            .mask
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .overhead();
        let udp_limit = self
            .prepared
            .mtu
            .saturating_add(overhead)
            .min(MAX_UDP_PAYLOAD);
        let limit = udp_limit.checked_sub(overhead).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "KCP UDP 预算小于掩码开销")
        })?;
        for payload in segment_packets(segments, limit)? {
            let packet = self
                .mask
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .encode(&payload)
                .ok_or_else(|| io::Error::other("KCP 掩码编码失败"))?;
            if packet.len() > udp_limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "KCP 掩码报文超过 UDP 预算",
                ));
            }
            let length = self.socket.send_to(&packet, self.dest).await?;
            if length != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "KCP UDP 报文发送不完整",
                ));
            }
        }
        Ok(())
    }

    fn fail(&self, shared: &Arc<Mutex<Shared>>, error: io::Error) {
        shared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .fail(error);
    }

    fn close(&self, shared: Arc<Mutex<Shared>>) {
        let mut shared = shared.lock().unwrap_or_else(|error| error.into_inner());
        shared.local_closed = true;
        shared.terminated = true;
        shared.read_eof = true;
        shared.wake_reader();
        shared.wake_writer();
    }

    fn input(&self, shared: &Arc<Mutex<Shared>>, started: Instant, segments: Vec<Segment>) {
        let now = elapsed(started);
        let mut shared = shared.lock().unwrap_or_else(|error| error.into_inner());
        if shared.terminated {
            return;
        }
        shared.last_incoming = now;
        let mut woke_reader = false;
        let mut woke_writer = false;
        for segment in segments {
            if segment.conv() != self.conv {
                continue;
            }
            match segment {
                Segment::Data(data) => {
                    if data.option & 1 == 1 && !shared.local_closed {
                        // 对端进入关闭流程仍可继续收数据，但不再接受新写入。
                        shared.local_closed = true;
                        shared.close_started = Some(now);
                    }
                    if data.number.wrapping_sub(shared.rcv_next)
                        >= self.prepared.receiving_in_flight
                    {
                        continue;
                    }
                    shared
                        .acks
                        .retain(|entry| !serial_lt(entry.number, data.sending_next));
                    while shared.acks.len() >= MAX_ACKS {
                        shared.acks.pop_front();
                    }
                    shared.acks.push_back(AckEntry {
                        number: data.number,
                        timestamp: data.timestamp,
                        next_flush: now,
                    });
                    shared.rcv.entry(data.number).or_insert(data.payload);
                    let before = shared.rcv_next;
                    shared.drain_ordered();
                    if shared.rcv_next != before {
                        woke_reader = true;
                    }
                }
                Segment::Ack(ack) => {
                    if serial_lt(shared.remote_next, ack.receiving_window) {
                        shared.remote_next = ack.receiving_window;
                    }
                    shared.clear_below(ack.receiving_next);
                    let (maxack, removed) = shared.remove_acked(&ack.numbers);
                    if removed {
                        let rto = shared.rto;
                        shared.fast_ack(maxack, rto);
                        if serial_lt(ack.timestamp, now) && now.wrapping_sub(ack.timestamp) < 10_000
                        {
                            shared.update_rtt(now.wrapping_sub(ack.timestamp));
                        }
                        woke_writer = true;
                    }
                }
                Segment::Cmd(cmd) => {
                    shared.clear_below(cmd.sending_next);
                    shared
                        .acks
                        .retain(|entry| !serial_lt(entry.number, cmd.sending_next));
                    if serial_lt(shared.remote_next, cmd.receiving_next) {
                        shared.remote_next = cmd.receiving_next;
                    }
                    if cmd.command == COMMAND_TERMINATE {
                        shared.peer_terminated = true;
                        if !shared.local_closed {
                            shared.local_closed = true;
                            shared.close_started = Some(now);
                        }
                        shared.read_eof = true;
                        woke_reader = true;
                        woke_writer = true;
                    }
                }
            }
        }
        if woke_reader {
            shared.wake_reader();
        }
        if woke_writer {
            shared.wake_writer();
        }
    }

    /// 执行一次刷新；返回 `false` 表示会话结束。
    async fn tick(&self, shared: &Arc<Mutex<Shared>>, started: Instant) -> bool {
        let now = elapsed(started);
        let mut out = Vec::new();
        let (done, woke_reader, woke_writer) = {
            let mut shared = shared.lock().unwrap_or_else(|error| error.into_inner());
            if shared.terminated {
                return false;
            }
            let mut woke_reader = false;
            let mut woke_writer = false;

            if !shared.local_closed && now.wrapping_sub(shared.last_incoming) >= IDLE_TIMEOUT {
                shared.local_closed = true;
                shared.close_started = Some(now);
                shared.terminating_started = None;
                shared.read_eof = true;
                woke_reader = true;
                woke_writer = true;
            }
            if shared.local_closed && shared.close_started.is_none() {
                shared.close_started = Some(now);
            }

            let rto = shared.rto;
            let option = if shared.local_closed { 1 } else { 0 };

            // 1) 到期 ACK 批量发送。
            let rcv_next = shared.rcv_next;
            let receiving_window = self.prepared.receiving_in_flight;
            let mut numbers = Vec::new();
            let mut timestamp = 0;
            for entry in &mut shared.acks {
                if serial_lt(now, entry.next_flush) {
                    continue;
                }
                entry.next_flush = now + (rto / 2).max(20);
                numbers.push(entry.number);
                if timestamp < entry.timestamp {
                    timestamp = entry.timestamp;
                }
                if numbers.len() == ACK_LIMIT {
                    out.push(ack_segment(
                        self.conv,
                        option,
                        rcv_next,
                        receiving_window,
                        timestamp,
                        std::mem::take(&mut numbers),
                    ));
                }
            }
            if !numbers.is_empty() {
                out.push(ack_segment(
                    self.conv,
                    option,
                    rcv_next,
                    receiving_window,
                    timestamp,
                    numbers,
                ));
            }

            // 2) 发送窗口：Xray 的 cwnd 取对端窗口、控制窗口与容量的最小值。
            let cwnd = self
                .prepared
                .sending_in_flight
                .min(shared.remote_next.wrapping_sub(shared.first_unacked))
                .min(shared.control_window)
                * self.prepared.cwnd_multiplier;
            let mut flight = 0u32;
            let first_unacked = shared.first_unacked;
            if cwnd > 0 {
                for sent in &mut shared.snd {
                    if flight >= cwnd {
                        break;
                    }
                    if sent.transmit == 0 || !serial_lt(now, sent.timeout) {
                        sent.timeout = now + rto;
                        sent.transmit += 1;
                        flight += 1;
                        out.push(Segment::Data(DataSegment {
                            conv: self.conv,
                            option,
                            timestamp: now,
                            number: sent.number,
                            sending_next: first_unacked,
                            payload: sent.payload.clone(),
                        }));
                    }
                }
            }

            // 3) 心跳或关闭通知。
            let interval = if shared.local_closed {
                1_000
            } else {
                PING_INTERVAL
            };
            if now.wrapping_sub(shared.last_ping) >= interval {
                out.push(Segment::Cmd(CmdSegment {
                    conv: self.conv,
                    command: if shared.local_closed {
                        COMMAND_TERMINATE
                    } else {
                        COMMAND_PING
                    },
                    option,
                    sending_next: shared.first_unacked,
                    receiving_next: shared.rcv_next,
                    peer_rto: rto,
                }));
                shared.last_ping = now;
            }

            // 4) 关闭第二阶段：发送窗口清空后重传 Terminate。
            let mut done = false;
            if shared.local_closed {
                let close_started = shared.close_started.unwrap_or(now);
                if shared.snd.is_empty() {
                    let terminating = *shared.terminating_started.get_or_insert(now);
                    if now.wrapping_sub(terminating) >= TERMINATE_GRACE {
                        shared.terminated = true;
                        shared.read_eof = true;
                        woke_reader = true;
                        woke_writer = true;
                        done = true;
                    }
                } else if now.wrapping_sub(close_started) >= DRAIN_LIMIT {
                    shared.snd.clear();
                    shared.refresh_first_unacked();
                    shared.terminating_started = Some(now);
                    woke_writer = true;
                }
            }
            if shared.peer_terminated && shared.snd.is_empty() {
                // 对端已终止且本端无待发数据，无需再等待完整宽限期。
                let terminating = *shared.terminating_started.get_or_insert(now);
                if now.wrapping_sub(terminating) >= TERMINATE_GRACE / 3 {
                    shared.terminated = true;
                    shared.read_eof = true;
                    woke_reader = true;
                    woke_writer = true;
                    done = true;
                }
            }
            (done, woke_reader, woke_writer)
        };
        if woke_reader || woke_writer {
            let mut shared = shared.lock().unwrap_or_else(|error| error.into_inner());
            if woke_reader {
                shared.wake_reader();
            }
            if woke_writer {
                shared.wake_writer();
            }
        }
        if !out.is_empty()
            && let Err(error) = self.send_segments(&out).await
        {
            self.fail(shared, error);
            return false;
        }
        !done
    }
}

/// 保留现有分段线格式，只改变 UDP 聚合边界。ACK 可按原字段拆成多段，
/// 数据段不能在此重编号/拆分，超预算必须关闭（正常写入已由 MSS 限制）。
fn segment_packets(segments: &[Segment], limit: usize) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = Vec::new();
    let mut packet = Vec::new();
    let mut push = |bytes: Vec<u8>| -> io::Result<()> {
        if bytes.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KCP 单个分段超过 MTU 预算",
            ));
        }
        if packet.len() + bytes.len() > limit {
            packets.push(std::mem::take(&mut packet));
        }
        packet.extend(bytes);
        Ok(())
    };
    for segment in segments {
        match segment {
            Segment::Data(data) if data.payload.len() > u16::MAX as usize => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "KCP 数据段长度无法编码",
                ));
            }
            Segment::Ack(ack) if !ack.numbers.is_empty() => {
                let count = limit.saturating_sub(17) / 4;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "KCP MTU 无法容纳 ACK",
                    ));
                }
                for numbers in ack.numbers.chunks(count.min(ACK_LIMIT)) {
                    push(
                        Segment::Ack(AckSegment {
                            conv: ack.conv,
                            option: ack.option,
                            receiving_window: ack.receiving_window,
                            receiving_next: ack.receiving_next,
                            timestamp: ack.timestamp,
                            numbers: numbers.to_vec(),
                        })
                        .encode(),
                    )?;
                }
            }
            _ => push(segment.encode())?,
        }
    }
    if !packet.is_empty() {
        packets.push(packet);
    }
    Ok(packets)
}

fn ack_segment(
    conv: u16,
    option: u8,
    receiving_next: u32,
    window: u32,
    timestamp: u32,
    numbers: Vec<u32>,
) -> Segment {
    Segment::Ack(AckSegment {
        conv,
        option,
        receiving_window: receiving_next.wrapping_add(window),
        receiving_next,
        timestamp,
        numbers,
    })
}

fn elapsed(started: Instant) -> u32 {
    started.elapsed().as_millis() as u32
}

/// 32 位序号串行比较：`a` 在 `b` 之前。
fn serial_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::poll_fn,
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        config::{Kcp, KcpHeader, KcpSecurity},
        transport::kcp::{prepare, segment::parse},
    };

    fn data(conv: u16, number: u32, size: usize) -> Segment {
        Segment::Data(DataSegment {
            conv,
            option: 0,
            timestamp: 0,
            number,
            sending_next: 0,
            payload: vec![number as u8; size],
        })
    }

    #[test]
    fn packetizer_bounds_data_and_splits_acks_without_changing_wire_fields() {
        for limit in [21, 25, 256, 1350, 9000] {
            let mut segments: Vec<_> = (0..120)
                .map(|number| data(7, number, limit - super::super::segment::DATA_OVERHEAD))
                .collect();
            segments.push(Segment::Ack(AckSegment {
                conv: 7,
                option: 1,
                receiving_window: 800,
                receiving_next: 2,
                timestamp: 99,
                numbers: (0..257).collect(),
            }));
            segments.push(Segment::Cmd(CmdSegment {
                conv: 7,
                command: COMMAND_TERMINATE,
                option: 1,
                sending_next: 120,
                receiving_next: 2,
                peer_rto: 100,
            }));
            let packets = segment_packets(&segments, limit).unwrap();
            assert!(packets.len() >= 120);
            let mut data_numbers = Vec::new();
            let mut ack_numbers = Vec::new();
            let mut commands = Vec::new();
            for packet in packets {
                assert!(!packet.is_empty());
                assert!(packet.len() <= limit);
                let parsed = parse(&packet);
                assert_eq!(
                    parsed
                        .iter()
                        .map(|segment| segment.encode().len())
                        .sum::<usize>(),
                    packet.len()
                );
                for segment in parsed {
                    match segment {
                        Segment::Data(data) => {
                            assert_eq!(data.payload, vec![data.number as u8; limit - 18]);
                            data_numbers.push(data.number);
                        }
                        Segment::Ack(ack) => {
                            assert_eq!(
                                (
                                    ack.conv,
                                    ack.option,
                                    ack.receiving_window,
                                    ack.receiving_next,
                                    ack.timestamp
                                ),
                                (7, 1, 800, 2, 99)
                            );
                            assert!(ack.numbers.len() <= ACK_LIMIT);
                            ack_numbers.extend(ack.numbers);
                        }
                        command => commands.push(command),
                    }
                }
            }
            assert_eq!(data_numbers, (0..120).collect::<Vec<_>>());
            assert_eq!(ack_numbers, (0..257).collect::<Vec<_>>());
            assert_eq!(commands, vec![segments.last().unwrap().clone()]);
        }
        assert!(segment_packets(&[data(7, 0, 4)], 21).is_err());
        assert!(segment_packets(&[ack_segment(7, 0, 0, 8, 0, vec![0])], 20).is_err());
        assert!(segment_packets(&[], 21).unwrap().is_empty());
    }

    #[tokio::test]
    async fn mask_and_seed_are_inside_each_datagram_mtu_budget() {
        for mtu in [21, 256] {
            for (security, seed, header) in [
                (KcpSecurity::None, None, KcpHeader::None),
                (KcpSecurity::Legacy, None, KcpHeader::Srtp),
                (
                    KcpSecurity::Legacy,
                    Some("packet-seed".to_owned()),
                    KcpHeader::Dtls,
                ),
                (
                    KcpSecurity::Legacy,
                    Some("packet-seed".to_owned()),
                    KcpHeader::Dns {
                        domain: "kcp.example.com".to_owned(),
                    },
                ),
            ] {
                let config = Kcp {
                    mtu,
                    tti: 10,
                    max_sending_window: mtu * 128,
                    security,
                    seed,
                    header,
                    ..Kcp::default()
                };
                let prepared = prepare(&config).unwrap();
                let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let (_, rx) = mpsc::channel(1);
                let driver = Driver {
                    socket,
                    dest: sink.local_addr().unwrap(),
                    mask: prepared.mask.clone(),
                    conv: 7,
                    prepared: prepared.clone(),
                    rx,
                    stop: CancellationToken::new(),
                    on_exit: None,
                };
                let mut segments: Vec<_> =
                    (0..4).map(|number| data(7, number, prepared.mss)).collect();
                segments.push(ack_segment(7, 0, 0, 32, 12, (0..128).collect()));
                let overhead = prepared.mask.lock().unwrap().overhead();
                let expected_count = segment_packets(&segments, prepared.mtu).unwrap().len();
                let receiving = async {
                    let mut count = 0;
                    let mut buffer = vec![0; MAX_UDP_PAYLOAD + 1];
                    for _ in 0..expected_count {
                        let length = timeout(Duration::from_secs(1), sink.recv(&mut buffer))
                            .await
                            .unwrap()
                            .unwrap();
                        assert!(length <= prepared.mtu + overhead);
                        let payload = prepared
                            .mask
                            .lock()
                            .unwrap()
                            .decode(&buffer[..length])
                            .unwrap();
                        assert!(payload.len() <= prepared.mtu);
                        assert_eq!(payload.len() + overhead, length);
                        count += parse(&payload)
                            .iter()
                            .filter(|segment| matches!(segment, Segment::Data(_)))
                            .count();
                    }
                    assert_eq!(count, 4);
                };
                let (sending, ()) = tokio::join!(driver.send_segments(&segments), receiving);
                sending.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn socket_send_error_stops_driver_and_is_sticky_for_stream_operations() {
        let prepared = prepare(&Kcp {
            security: KcpSecurity::None,
            tti: 10,
            ..Kcp::default()
        })
        .unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // IPv4 socket 无法向 IPv6 目的发送；不依赖外网或 ICMP 行为。
        let dest = SocketAddr::new(
            std::net::Ipv6Addr::LOCALHOST.into(),
            sink.local_addr().unwrap().port(),
        );
        let (mut stream, shared, wake) = start(&prepared);
        stream.write_all(b"must not disappear").await.unwrap();
        let (_sender, rx) = mpsc::channel(1);
        let exited = Arc::new(AtomicUsize::new(0));
        let callback = exited.clone();
        let driver = Driver {
            socket,
            dest,
            mask: prepared.mask.clone(),
            conv: 7,
            prepared,
            rx,
            stop: CancellationToken::new(),
            on_exit: Some(Box::new(move || {
                callback.fetch_add(1, Ordering::SeqCst);
            })),
        };
        timeout(Duration::from_secs(2), driver.run(shared, wake))
            .await
            .unwrap();
        assert_eq!(exited.load(Ordering::SeqCst), 1);
        let first = stream.error().expect("发送失败必须记录到流").kind();
        for _ in 0..2 {
            assert_eq!(stream.read(&mut [0]).await.unwrap_err().kind(), first);
            assert_eq!(stream.write(b"new data").await.unwrap_err().kind(), first);
            assert_eq!(stream.flush().await.unwrap_err().kind(), first);
            assert_eq!(stream.shutdown().await.unwrap_err().kind(), first);
        }
    }

    #[tokio::test]
    async fn unencodable_packet_is_fatal_instead_of_silently_dropped() {
        let mut prepared = prepare(&Kcp {
            security: KcpSecurity::None,
            tti: 10,
            ..Kcp::default()
        })
        .unwrap();
        // 人为注入超过 Prepared.mss 的共享发送段，模拟内部预算失配。
        let prepared_mut = Arc::get_mut(&mut prepared).unwrap();
        prepared_mut.mss = prepared_mut.mtu;
        let (mut stream, shared, wake) = start(&prepared);
        stream.write_all(&vec![1; prepared.mtu]).await.unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_sender, rx) = mpsc::channel(1);
        let driver = Driver {
            socket,
            dest: sink.local_addr().unwrap(),
            mask: prepared.mask.clone(),
            conv: 7,
            prepared,
            rx,
            stop: CancellationToken::new(),
            on_exit: None,
        };
        timeout(Duration::from_secs(2), driver.run(shared, wake))
            .await
            .unwrap();
        assert_eq!(stream.error().unwrap().kind(), io::ErrorKind::InvalidInput);
        assert!(stream.read(&mut [0]).await.is_err());
        assert!(stream.flush().await.is_err());
    }

    struct Woken(AtomicUsize);

    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn failure_wakes_both_blocked_halves_and_discards_buffered_plaintext() {
        let prepared = prepare(&Kcp {
            max_sending_window: 1350,
            ..Kcp::default()
        })
        .unwrap();
        let (mut stream, shared, _) = start(&prepared);
        stream.write_all(&vec![1; prepared.mss]).await.unwrap();
        let reader = Arc::new(Woken(AtomicUsize::new(0)));
        let writer = Arc::new(Woken(AtomicUsize::new(0)));
        let read_waker = Waker::from(reader.clone());
        let write_waker = Waker::from(writer.clone());
        let mut buffer = [0];
        let mut read_buf = ReadBuf::new(&mut buffer);
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut Context::from_waker(&read_waker), &mut read_buf)
                .is_pending()
        );
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut Context::from_waker(&write_waker), b"full")
                .is_pending()
        );
        {
            let mut shared = shared.lock().unwrap();
            shared.read_buf.extend(b"must not leak after failure");
            shared.fail(io::Error::new(io::ErrorKind::ConnectionReset, "fatal send"));
        }
        assert!(reader.0.load(Ordering::SeqCst) > 0);
        assert!(writer.0.load(Ordering::SeqCst) > 0);
        assert!(stream.read(&mut [0]).await.is_err());
        assert!(stream.write(b"never accepted").await.is_err());
        // 空写也不能在失败之后重新显示成功。
        assert!(stream.write(&[]).await.is_err());
        let result = poll_fn(|cx| Pin::new(&mut stream).poll_flush(cx)).await;
        assert!(result.is_err());
    }

    #[test]
    fn serial_comparison_handles_wraparound() {
        assert!(serial_lt(1, 2));
        assert!(!serial_lt(2, 1));
        assert!(serial_lt(u32::MAX, 0));
        assert!(!serial_lt(0, u32::MAX));
        assert!(serial_lt(u32::MAX - 1, 1));
    }

    #[test]
    fn rto_matches_xray_rfc6298_math() {
        let mut shared = Shared {
            min_rtt: 50,
            rto: 100,
            ..Shared::default()
        };
        shared.update_rtt(100);
        assert_eq!(shared.srtt, 100);
        assert_eq!(shared.rttvar, 50);
        // min_rtt(50) < 4*var(200) → rto = 100 + 200 = 300，再乘 5/4 = 375。
        assert_eq!(shared.rto, 375);
        shared.update_rtt(u32::MAX);
        assert_eq!(shared.rto, 375, "超过 0x7fffffff 的样本必须忽略");
    }

    #[test]
    fn ack_removal_and_window_advance() {
        let mut shared = Shared::default();
        for number in 0..5 {
            shared.snd.push_back(Sent {
                number,
                payload: vec![0; 4],
                timeout: 0,
                transmit: 1,
            });
        }
        shared.next_number = 5;
        shared.refresh_first_unacked();
        let (maxack, removed) = shared.remove_acked(&[1, 2, 4]);
        assert!(removed);
        assert_eq!(maxack, 4);
        assert_eq!(
            shared
                .snd
                .iter()
                .map(|sent| sent.number)
                .collect::<Vec<_>>(),
            vec![0, 3]
        );
        shared.clear_below(3);
        assert_eq!(shared.snd.len(), 1);
        assert_eq!(shared.first_unacked, 3);
    }
}
