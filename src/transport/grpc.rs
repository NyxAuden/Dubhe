//! 原生 h2/gRPC 入站承载：只负责连接驱动、RPC 准入、消息framing与半关闭。
//! 协议认证、路由与业务封装仍由各协议层完成。

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant as StdInstant};

use h2::server::{Connection, SendResponse};
use h2::{RecvStream, SendStream};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::config::Inbound;
use crate::forward::{Context, Lease};
use crate::protocol::{trojan, vless, vmess};
use crate::session::Command;
use crate::telemetry::{Gauge, Guard as GaugeGuard};

const MAX_MESSAGE: usize = 1 << 20;
const MAX_TOP_LEVEL_FIELDS: usize = 1024;
const MAX_MULTI_ITEMS: usize = 256;
const WRITE_CHUNK: usize = 16 * 1024;
const BRIDGE_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Message)]
struct Hunk {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct MultiHunk {
    #[prost(bytes = "vec", repeated, tag = "1")]
    data: Vec<Vec<u8>>,
}

/// 每个driver外层poll重置一次的共享IO预算；库内部重入只消耗、不重置。
#[derive(Clone)]
struct IoBudget {
    frames: Arc<AtomicU64>,
    read: Arc<AtomicU64>,
    write: Arc<AtomicU64>,
}

const POLL_FRAMES: u64 = 32;
const POLL_BYTES: u64 = 65_536;

impl IoBudget {
    fn new() -> Self {
        Self {
            frames: Arc::new(AtomicU64::new(POLL_FRAMES)),
            read: Arc::new(AtomicU64::new(POLL_BYTES)),
            write: Arc::new(AtomicU64::new(POLL_BYTES)),
        }
    }

    fn reset(&self) {
        self.frames.store(POLL_FRAMES, Ordering::Relaxed);
        self.read.store(POLL_BYTES, Ordering::Relaxed);
        self.write.store(POLL_BYTES, Ordering::Relaxed);
    }

    fn frames_left(&self) -> bool {
        self.frames.load(Ordering::Relaxed) > 0
    }

    fn take_frame(&self) {
        let _ = self
            .frames
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            });
    }

    fn read_left(&self) -> usize {
        self.read.load(Ordering::Relaxed) as usize
    }

    fn take_read(&self, count: usize) {
        let _ = self
            .read
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(count as u64))
            });
    }

    fn write_left(&self) -> usize {
        self.write.load(Ordering::Relaxed) as usize
    }

    fn take_write(&self, count: usize) {
        let _ = self
            .write
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(count as u64))
            });
    }
}

/// 观察本端写出的SETTINGS ACK；D7要求确认完整输出后才释放物理握手许可。
struct AckIo<S> {
    inner: S,
    ack: watch::Sender<bool>,
    tail: Vec<u8>,
}

impl<S> AckIo<S> {
    fn new(inner: S, ack: watch::Sender<bool>) -> Self {
        Self {
            inner,
            ack,
            tail: Vec::new(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AckIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AckIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = std::task::ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        const ACK: [u8; 9] = [0, 0, 0, 4, 1, 0, 0, 0, 0];
        let mut window = Vec::with_capacity(this.tail.len() + written);
        window.extend_from_slice(&this.tail);
        window.extend_from_slice(&buf[..written]);
        if window.windows(ACK.len()).any(|part| part == ACK) {
            this.ack.send_replace(true);
        }
        this.tail = window[window.len().saturating_sub(ACK.len() - 1)..].to_vec();
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

const PREFACE: usize = 24;
const MAX_FRAME_PAYLOAD: usize = 16_384;
const MAX_HEAD_BLOCK_BYTES: usize = 16_384;
const MAX_HEAD_BLOCK_FRAMES: usize = 8;
const MAX_CONTROL_PER_SECOND: u32 = 256;
const END_HEADERS: u8 = 0x4;

struct HeadBlock {
    stream: u32,
    deadline: StdInstant,
    frames: usize,
    bytes: usize,
}

/// 客户端方向的9字节帧头护栏：拒绝超过16384的声明长度并跟踪payload剩余。
/// 真正的HPACK/窗口/状态机仍由h2完成，本层只做结构上限、期限与调度预算。
struct FrameGuard<S> {
    inner: S,
    buffer: Vec<u8>,
    offset: usize,
    preface: usize,
    header: [u8; 9],
    header_len: usize,
    payload_remaining: usize,
    budget: IoBudget,
    heads: Arc<Mutex<BTreeMap<u32, StdInstant>>>,
    head_limit: usize,
    head_block: Option<HeadBlock>,
    partial_since: Option<StdInstant>,
    control_window: StdInstant,
    control_count: u32,
    duration: Duration,
    /// 当前不完整帧头/头块的绝对期限，供driver独立计时，不依赖下一次IO。
    deadlines: Arc<Mutex<Option<StdInstant>>>,
}

impl<S> FrameGuard<S> {
    fn new(
        inner: S,
        budget: IoBudget,
        heads: Arc<Mutex<BTreeMap<u32, StdInstant>>>,
        duration: Duration,
        head_limit: usize,
        deadlines: Arc<Mutex<Option<StdInstant>>>,
    ) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            offset: 0,
            preface: PREFACE,
            header: [0; 9],
            header_len: 0,
            payload_remaining: 0,
            budget,
            heads,
            head_limit,
            head_block: None,
            partial_since: None,
            control_window: StdInstant::now(),
            control_count: 0,
            duration,
            deadlines,
        }
    }

    /// 把当前最近的结构期限交给driver；完成或清空时移除。
    /// 预算表中毒后失败关闭：不再记录期限，由调用方中止该连接。
    fn refresh_deadline(&self) -> io::Result<()> {
        let next = self
            .partial_since
            .map(|started| started + self.duration)
            .into_iter()
            .chain(self.head_block.as_ref().map(|head| head.deadline))
            .min();
        *self
            .deadlines
            .lock()
            .map_err(|_| io::Error::other("gRPC 期限预算表不可用"))? = next;
        Ok(())
    }

    fn validate(&mut self, mut data: &[u8]) -> io::Result<()> {
        let now = StdInstant::now();
        if self
            .partial_since
            .is_some_and(|since| now.duration_since(since) > self.duration)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "gRPC h2帧头组装超过绝对期限",
            ));
        }
        while !data.is_empty() {
            if self.preface > 0 {
                let take = self.preface.min(data.len());
                self.preface -= take;
                data = &data[take..];
                continue;
            }
            if self.payload_remaining == 0 && self.header_len < 9 {
                if self.header_len == 0 {
                    self.partial_since = Some(now);
                }
                let take = (9 - self.header_len).min(data.len());
                self.header[self.header_len..self.header_len + take].copy_from_slice(&data[..take]);
                self.header_len += take;
                data = &data[take..];
                if self.header_len == 9 {
                    let started = self.partial_since.take().unwrap_or(now);
                    let length = (u32::from(self.header[0]) << 16
                        | u32::from(self.header[1]) << 8
                        | u32::from(self.header[2])) as usize;
                    if length > MAX_FRAME_PAYLOAD {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "gRPC h2帧声明长度超过16384",
                        ));
                    }
                    let kind = self.header[3];
                    let flags = self.header[4];
                    let stream = u32::from_be_bytes([
                        self.header[5],
                        self.header[6],
                        self.header[7],
                        self.header[8],
                    ]) & 0x7fff_ffff;
                    self.budget.take_frame();
                    self.observe_frame(now, started, kind, flags, stream, length)?;
                    self.payload_remaining = length;
                    self.header_len = 0;
                }
                continue;
            }
            let take = self.payload_remaining.min(data.len());
            self.payload_remaining -= take;
            data = &data[take..];
        }
        self.refresh_deadline()?;
        Ok(())
    }

    fn observe_frame(
        &mut self,
        now: StdInstant,
        started: StdInstant,
        kind: u8,
        flags: u8,
        stream: u32,
        length: usize,
    ) -> io::Result<()> {
        match kind {
            0x1 => {
                if self.head_block.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gRPC h2头块被新HEADERS交错",
                    ));
                }
                let mut heads = self
                    .heads
                    .lock()
                    .map_err(|_| io::Error::other("gRPC stream 预算表不可用"))?;
                if heads.len() >= self.head_limit && !heads.contains_key(&stream) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gRPC h2 stream起点记录超限",
                    ));
                }
                heads.entry(stream).or_insert(started);
                drop(heads);
                self.head_block = Some(HeadBlock {
                    stream,
                    deadline: started + self.duration,
                    frames: 1,
                    bytes: length,
                });
                self.check_head(now)?;
                if flags & END_HEADERS != 0 {
                    self.head_block = None;
                }
            }
            0x9 => {
                let Some(head) = self.head_block.as_mut() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gRPC h2 CONTINUATION没有对应头块",
                    ));
                };
                if head.stream != stream {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gRPC h2 CONTINUATION跨stream交错",
                    ));
                }
                head.frames += 1;
                head.bytes += length;
                self.check_head(now)?;
                if flags & END_HEADERS != 0 {
                    self.head_block = None;
                }
            }
            _ => {
                if self.head_block.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gRPC h2头块期间出现其他帧",
                    ));
                }
                if !matches!(kind, 0x0 | 0x1 | 0x9) {
                    if now.duration_since(self.control_window) >= Duration::from_secs(1) {
                        self.control_window = now;
                        self.control_count = 0;
                    }
                    self.control_count += 1;
                    if self.control_count > MAX_CONTROL_PER_SECOND {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "gRPC h2控制帧频率超限",
                        ));
                    }
                }
                if kind == 0x3 {
                    self.heads
                        .lock()
                        .expect("stream起点记录锁未中毒")
                        .remove(&stream);
                }
            }
        }
        Ok(())
    }

    fn check_head(&self, now: StdInstant) -> io::Result<()> {
        let Some(head) = self.head_block.as_ref() else {
            return Ok(());
        };
        if head.bytes > MAX_HEAD_BLOCK_BYTES || head.frames > MAX_HEAD_BLOCK_FRAMES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gRPC h2头块超过16384字节或8帧",
            ));
        }
        if now > head.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "gRPC h2头块组装超过绝对期限",
            ));
        }
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FrameGuard<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset == this.buffer.len() {
            this.buffer.clear();
            this.offset = 0;
            if !this.budget.frames_left() || this.budget.read_left() == 0 {
                // 预算耗尽：先自唤醒让出driver，下一轮外层poll重置预算。
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let limit = this.budget.read_left().min(MAX_FRAME_PAYLOAD);
            let mut staging = [0u8; MAX_FRAME_PAYLOAD];
            let mut read = ReadBuf::new(&mut staging[..limit]);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let filled = read.filled().len();
            if filled == 0 {
                return Poll::Ready(Ok(()));
            }
            this.budget.take_read(filled);
            this.validate(&staging[..filled])?;
            this.buffer.extend_from_slice(&staging[..filled]);
            if !this.budget.frames_left() || this.budget.read_left() == 0 {
                cx.waker().wake_by_ref();
            }
        }
        let take = buf.remaining().min(this.buffer.len() - this.offset);
        buf.put_slice(&this.buffer[this.offset..this.offset + take]);
        this.offset += take;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FrameGuard<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let allowed = this.budget.write_left();
        if allowed == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let take = allowed.min(buf.len());
        let written = std::task::ready!(Pin::new(&mut this.inner).poll_write(cx, &buf[..take]))?;
        this.budget.take_write(written);
        if this.budget.write_left() == 0 {
            cx.waker().wake_by_ref();
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type ServerConnection = Connection<FrameGuard<Box<dyn Io>>, prost::bytes::Bytes>;

/// 每轮driver外层poll重置一次共享IO预算；h2内部重入不重置。
async fn accept_budgeted(
    connection: &mut ServerConnection,
    budget: &IoBudget,
) -> Option<Result<(Request<RecvStream>, SendResponse<prost::bytes::Bytes>), h2::Error>> {
    poll_fn(|cx| {
        budget.reset();
        connection.poll_accept(cx)
    })
    .await
}

/// 独立poll最近的结构期限；没有不完整帧头/头块时保持Pending。
/// 预算表中毒时立即返回错误，由 select 分支失败关闭。
async fn structure_deadline(deadlines: &Arc<Mutex<Option<StdInstant>>>) -> io::Result<()> {
    let next = *deadlines
        .lock()
        .map_err(|_| io::Error::other("gRPC 期限预算表不可用"))?;
    match next {
        Some(at) => {
            tokio::time::sleep_until(Instant::from_std(at)).await;
            Ok(())
        }
        None => std::future::pending().await,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    stream: TcpStream,
    inbound: Inbound,
    security: Option<crate::tls::InboundSecurity>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    handshake: OwnedSemaphorePermit,
    slots: Arc<Semaphore>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let duration = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let deadline = Instant::now() + duration;
    let per_connection = ctx.limits.max_grpc_streams_per_connection;
    stream.set_nodelay(true)?;
    let (ack_tx, mut ack_rx) = watch::channel(false);
    let budget = IoBudget::new();
    // 首HEADERS起点记录上限为每连接流上限加reset保留数，不按任意ID建无界map。
    let heads = Arc::new(Mutex::new(BTreeMap::new()));
    let head_limit = per_connection + 32;
    let deadlines = Arc::new(Mutex::new(None));
    // 真实TLS必须协商h2；明文只允许HTTP/2 prior knowledge。
    let ack_io: Box<dyn Io> = match security {
        Some(security) => match security.accept(stream, &ctx, deadline).await? {
            crate::tls::AcceptedInbound::Fallback => return Ok(()),
            crate::tls::AcceptedInbound::Stream { io, alpn } => {
                if alpn.as_deref() != Some(b"h2") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gRPC TLS/REALITY 必须协商 h2 ALPN",
                    ));
                }
                Box::new(AckIo::new(io, ack_tx))
            }
        },
        None => Box::new(AckIo::new(stream, ack_tx)),
    };
    let io = FrameGuard::new(
        ack_io,
        budget.clone(),
        heads.clone(),
        duration,
        head_limit,
        deadlines.clone(),
    );

    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(per_connection as u32)
        .initial_window_size(65_535)
        .initial_connection_window_size(65_535)
        .max_frame_size(16_384)
        .header_table_size(4_096)
        .max_header_list_size(8_192)
        .max_send_buffer_size(65_536)
        .max_concurrent_reset_streams(32)
        .max_pending_accept_reset_streams(16)
        .max_local_error_reset_streams(Some(64))
        .data_frame_budget(32_768);
    // 握手阶段同样按driver poll重置预算，避免初始写入耗尽后被永久Pending。
    let mut handshake_future = Box::pin(builder.handshake(io));
    let mut connection: ServerConnection = timeout_at(
        deadline,
        poll_fn(|cx| {
            budget.reset();
            handshake_future.as_mut().poll(cx)
        }),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC h2握手超时"))?
    .map_err(io::Error::other)?;

    let connection_slots = Arc::new(Semaphore::new(per_connection));
    let mut rpcs = JoinSet::new();
    let grpc = match &inbound {
        Inbound::VlessGrpc { grpc, .. }
        | Inbound::VmessGrpc { grpc, .. }
        | Inbound::TrojanGrpc { grpc, .. } => grpc.clone(),
        _ => return Err(io::Error::other("入口不是gRPC")),
    };
    let mut handshake = Some(handshake);
    // 物理准备完成前pipeline的合法RPC先有界持有，不进入协议业务。
    let mut pending: Vec<(Request<RecvStream>, SendResponse<prost::bytes::Bytes>)> = Vec::new();

    // handshake Ready只到preface；必须观察到本端SETTINGS ACK完整写出。
    while !*ack_rx.borrow() {
        tokio::select! {
            result = timeout_at(deadline, accept_budgeted(&mut connection, &budget)) => {
                match result {
                    Ok(Some(Ok((request, respond)))) => {
                        if pending.len() >= per_connection {
                            ctx.stats.reject();
                            rpcs.spawn(reject(respond, StatusCode::SERVICE_UNAVAILABLE));
                        } else {
                            pending.push((request, respond));
                        }
                    }
                    Ok(Some(Err(error))) => return Err(io::Error::other(error)),
                    Ok(None) => return Ok(()),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "gRPC SETTINGS ACK超时")),
                }
            }
            _ = ack_rx.changed() => {}
        }
    }
    drop(handshake.take());
    for (request, respond) in pending.drain(..) {
        let rpc_deadline = rpc_deadline(&respond, &heads, duration);
        accept_rpc(
            request,
            respond,
            rpc_deadline,
            &inbound,
            &grpc,
            &vmess,
            &ctx,
            &slots,
            &connection_slots,
            &mut rpcs,
        );
    }

    let mut stopping = false;
    let mut drain_deadline: Option<Instant> = None;
    loop {
        let timer = async {
            match drain_deadline {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        let structure = structure_deadline(&deadlines);
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = timer => break,
            result = structure => {
                // Ok(()) 表示到达绝对期限；Err 表示预算表不可用。两者都失败关闭。
                return Err(match result {
                    Ok(()) => io::Error::new(
                        io::ErrorKind::TimedOut,
                        "gRPC h2帧/头块组装超过绝对期限",
                    ),
                    Err(error) => error,
                });
            }
            _ = stop.cancelled(), if !stopping => {
                stopping = true;
                connection.graceful_shutdown();
                if rpcs.is_empty() {
                    break;
                }
                drain_deadline = Some(
                    Instant::now() + Duration::from_millis(ctx.limits.shutdown_timeout_ms),
                );
            }
            result = accept_budgeted(&mut connection, &budget) => {
                match result {
                    Some(Ok((request, respond))) => {
                        if stopping {
                            ctx.stats.reject();
                            rpcs.spawn(reject(respond, StatusCode::SERVICE_UNAVAILABLE));
                            continue;
                        }
                        let rpc_deadline = rpc_deadline(&respond, &heads, duration);
                        accept_rpc(
                            request,
                            respond,
                            rpc_deadline,
                            &inbound,
                            &grpc,
                            &vmess,
                            &ctx,
                            &slots,
                            &connection_slots,
                            &mut rpcs,
                        );
                    }
                    Some(Err(error)) => return Err(io::Error::other(error)),
                    None => break,
                }
            }
            joined = rpcs.join_next(), if !rpcs.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    return Err(io::Error::other("gRPC RPC任务异常"));
                }
                if stopping && rpcs.is_empty() {
                    break;
                }
            }
        }
    }
    // 有限drain：先把已接受RPC正常结束，期限到才强制取消；不丢整个driver。
    if !rpcs.is_empty() {
        rpcs.abort_all();
        while rpcs.join_next().await.is_some() {}
    }
    // 有限刷新GOAWAY/尾部帧后关闭，不能等待对端无限保持连接。
    // h2 在连接已关闭时可能让 accept() 立即反复 Ready；除外层 timeout 外
    // 再加期限检查、接受上限和每轮 yield，避免忙循环饿死计时器与同线程任务。
    let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let _ = timeout(Duration::from_millis(500), async {
        let mut accepted = 0usize;
        while accepted < 128 {
            if tokio::time::Instant::now() >= drain_deadline {
                break;
            }
            if connection.accept().await.is_none() {
                break;
            }
            accepted += 1;
            tokio::task::yield_now().await;
        }
    })
    .await;
    Ok(())
}

/// 首HEADERS起点tH到完整认证的共享绝对期限；记录缺失时退回本RPC的局部上限。
fn rpc_deadline(
    respond: &SendResponse<prost::bytes::Bytes>,
    heads: &Arc<Mutex<BTreeMap<u32, StdInstant>>>,
    duration: Duration,
) -> Instant {
    let stream = u32::from(respond.stream_id());
    let started = heads
        .lock()
        .expect("stream起点记录锁未中毒")
        .remove(&stream);
    let remaining = started
        .map(|started| duration.saturating_sub(started.elapsed()))
        .unwrap_or(duration);
    Instant::now() + remaining
}

/// RPC物理/应用额度与gauge；由scope及其子任务共享，最后一个持有者释放时归还。
struct RpcPermits {
    _global: OwnedSemaphorePermit,
    _connection: OwnedSemaphorePermit,
    _gauge: GaugeGuard,
}

/// 单RPC局部scope：任务、共享lease与许可同域。子任务持有lease克隆，
/// 因而RPC被外部取消时也要等reader/mapping等子任务真正结束才归还额度。
struct RpcScope {
    tasks: JoinSet<()>,
    lease: Lease,
}

impl RpcScope {
    fn new(
        stats: &Arc<crate::telemetry::Stats>,
        global: OwnedSemaphorePermit,
        connection: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            tasks: JoinSet::new(),
            lease: Lease::new(RpcPermits {
                _global: global,
                _connection: connection,
                _gauge: stats.enter(Gauge::Grpc),
            }),
        }
    }

    fn lease(&self) -> Lease {
        self.lease.clone()
    }

    fn spawn<F>(&mut self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.tasks.spawn(future);
    }

    /// 失败/取消：终止局部任务并真实join，随后随scope drop归还许可与gauge。
    async fn abort_and_join(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }

    /// 成功：有限等待局部任务自然结束。
    async fn finish(&mut self, grace: Duration) {
        let _ = timeout(grace, async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_rpc(
    request: Request<RecvStream>,
    respond: SendResponse<prost::bytes::Bytes>,
    deadline: Instant,
    inbound: &Inbound,
    grpc: &crate::config::Grpc,
    vmess: &Option<Arc<vmess::Prepared>>,
    ctx: &Arc<Context>,
    slots: &Arc<Semaphore>,
    connection_slots: &Arc<Semaphore>,
    rpcs: &mut JoinSet<()>,
) {
    let admission = admit(&request, grpc);
    let (multi, rpc_timeout) = match admission {
        Ok(admission) => admission,
        Err(status) => {
            ctx.stats.reject();
            rpcs.spawn(reject(respond, status));
            return;
        }
    };
    // grpc-timeout可把RPC期限提前，但不能延长首HEADERS起点期限。
    let deadline = match rpc_timeout {
        Some(timeout) => deadline.min(Instant::now() + timeout),
        None => deadline,
    };
    let Ok(global) = slots.clone().try_acquire_owned() else {
        ctx.stats.reject();
        rpcs.spawn(reject(respond, StatusCode::SERVICE_UNAVAILABLE));
        return;
    };
    let Ok(connection) = connection_slots.clone().try_acquire_owned() else {
        ctx.stats.reject();
        rpcs.spawn(reject(respond, StatusCode::SERVICE_UNAVAILABLE));
        return;
    };
    let scope = RpcScope::new(&ctx.stats, global, connection);
    let inbound = inbound.clone();
    let vmess = vmess.clone();
    let ctx = ctx.clone();
    rpcs.spawn(async move {
        run_rpc(
            request.into_body(),
            respond,
            inbound,
            multi,
            deadline,
            vmess,
            ctx,
            scope,
        )
        .await;
    });
}

/// 准入检查：POST、完整路径、Content-Type、TE、scheme与无压缩。
fn admit(
    request: &Request<RecvStream>,
    grpc: &crate::config::Grpc,
) -> Result<(bool, Option<Duration>), StatusCode> {
    if request.method() != http::Method::POST {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if !matches!(request.uri().scheme_str(), Some("http" | "https")) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let Some(multi) = grpc.mode(request.uri().path()) else {
        return Err(StatusCode::NOT_FOUND);
    };
    // 完整请求应用头项最多64；解压后的header list由h2的8192上限约束。
    if request.headers().len() > 64 {
        return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }
    if request.headers().get_all("content-type").iter().count() != 1 {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !(content_type.eq_ignore_ascii_case("application/grpc")
        || content_type.eq_ignore_ascii_case("application/grpc+proto"))
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if request.headers().contains_key("content-length") {
        return Err(StatusCode::BAD_REQUEST);
    }
    // grpc-encoding缺省或identity可接受；其他编码与任何content-encoding都拒绝。
    if let Some(encoding) = request.headers().get("grpc-encoding")
        && !encoding
            .to_str()
            .is_ok_and(|value| value.eq_ignore_ascii_case("identity"))
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if request.headers().contains_key("content-encoding") {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if request.headers().contains_key("te") {
        let mut values = request.headers().get_all("te").iter();
        let first = values.next();
        if values.next().is_some()
            || first.is_none_or(|value| {
                !value
                    .to_str()
                    .is_ok_and(|v| v.trim().eq_ignore_ascii_case("trailers"))
            })
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let rpc_timeout = match request.headers().get("grpc-timeout") {
        Some(timeout) => Some(parse_timeout(timeout).map_err(|_| StatusCode::BAD_REQUEST)?),
        None => None,
    };
    Ok((multi, rpc_timeout))
}

fn parse_timeout(value: &HeaderValue) -> Result<Duration, ()> {
    let value = value.to_str().map_err(|_| ())?;
    let (digits, unit) = value.split_at(value.len().saturating_sub(1));
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    if !matches!(unit, "H" | "M" | "S" | "m" | "u" | "n") {
        return Err(());
    }
    let count = digits.parse::<u64>().map_err(|_| ())?;
    let duration = match unit {
        "H" => Duration::from_secs(count.checked_mul(3_600).ok_or(())?),
        "M" => Duration::from_secs(count.checked_mul(60).ok_or(())?),
        "S" => Duration::from_secs(count),
        "m" => Duration::from_millis(count),
        "u" => Duration::from_micros(count),
        "n" => Duration::from_nanos(count),
        _ => return Err(()),
    };
    Ok(duration)
}

async fn reject(mut respond: SendResponse<prost::bytes::Bytes>, status: StatusCode) {
    let response = Response::builder()
        .status(status)
        .header("content-type", "application/grpc")
        .body(())
        .expect("固定响应头合法");
    if let Ok(send) = respond.send_response(response, true) {
        drop(send);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_rpc(
    body: RecvStream,
    mut respond: SendResponse<prost::bytes::Bytes>,
    inbound: Inbound,
    multi: bool,
    deadline: Instant,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    mut scope: RpcScope,
) {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(())
        .expect("固定响应头合法");
    let Ok(send) = respond.send_response(response, false) else {
        return;
    };
    let (app, bridge) = tokio::io::duplex(BRIDGE_BYTES);
    let (bridge_read, bridge_write) = tokio::io::split(bridge);
    let lease = scope.lease();
    let in_lease = lease.clone();
    scope.spawn(async move {
        let _lease = in_lease;
        let _ = pump_in(body, bridge_write, multi).await;
    });
    let out_lease = lease.clone();
    scope.spawn(async move {
        let _lease = out_lease;
        let _ = pump_out(bridge_read, send, multi).await;
    });
    let result = dispatch(app, &inbound, vmess, ctx.clone(), deadline, lease).await;
    if let Err(error) = &result {
        // 认证失败必须计入 rejected：此前只 abort_and_join 就返回，导致
        // gRPC 入口的 UUID/密码猜测在 dubhe_rejected_total 上完全不可见
        // （只有 RPC 准入超限才计数）。判据见下一行注释。
        //
        // 无法在此区分认证阶段与业务阶段：`dispatch` 内部 `drop(handshake)`
        // 的 permit 已被移走。因此按错误类型保守判定，只对认证类错误计数。
        if crate::forward::is_authentication_failure(error) {
            ctx.stats.reject();
        }
        // 认证或业务失败：终止并join局部任务，让对端看到显式失败而非成功trailers。
        scope.abort_and_join().await;
        return;
    }
    scope.finish(Duration::from_secs(5)).await;
}

async fn dispatch<S>(
    mut app: S,
    inbound: &Inbound,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    deadline: Instant,
    lease: Lease,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let duration = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    match inbound {
        Inbound::VlessGrpc {
            tag, users, xudp, ..
        } => {
            let mut app: Box<dyn crate::tls::Io> = match ctx.vless_encryption(tag) {
                Some(prepared) => Box::new(
                    timeout_at(deadline, prepared.accept(app))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "gRPC/VLESS Encryption 超时")
                        })??,
                ),
                None => Box::new(app),
            };
            let accepted = timeout_at(deadline, vless::read_plain_request(&mut app, users, *xudp))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC/VLESS认证超时"))??;
            crate::runtime::serve_plain_vless_scoped(
                app,
                accepted,
                tag,
                ctx,
                duration,
                *xudp,
                Some(lease),
            )
            .await
        }
        Inbound::TrojanGrpc { tag, users, .. } => {
            let request = timeout_at(deadline, trojan::read_request(&mut app, users))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC/Trojan认证超时"))??;
            match request.command {
                Command::Connect => {
                    crate::runtime::serve_trojan_connect(app, tag, ctx, &request).await
                }
                Command::UdpAssociate => {
                    crate::udp::trojan_scoped(
                        app,
                        ctx,
                        tag.clone(),
                        Some(lease),
                        request.user.as_deref(),
                    )
                    .await
                }
                Command::Bind => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "该协议不支持 BIND",
                )),
            }
        }
        Inbound::VmessGrpc { tag, .. } => {
            let prepared = vmess.ok_or_else(|| io::Error::other("VMess未准备"))?;
            let accepted = timeout_at(deadline, prepared.handshake(&mut app, true))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC/VMess认证超时"))??;
            let allow_udp = prepared.allow_udp();
            crate::runtime::serve_vmess_scoped(
                app,
                accepted,
                tag,
                ctx,
                duration,
                allow_udp,
                Some(lease),
            )
            .await
        }
        _ => Err(io::Error::other("入口不是gRPC")),
    }
}

async fn pump_in(
    mut body: RecvStream,
    mut out: tokio::io::WriteHalf<DuplexStream>,
    multi: bool,
) -> io::Result<()> {
    let mut wire = Vec::new();
    let mut processed = 0usize;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io::Error::other)?;
        let length = chunk.len();
        wire.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(length);
        loop {
            if wire.len() < 5 {
                break;
            }
            if wire[0] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gRPC消息压缩标志不受支持",
                ));
            }
            let len = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
            if len > MAX_MESSAGE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gRPC消息超过1MiB",
                ));
            }
            if wire.len() < 5 + len {
                break;
            }
            let payload = &wire[5..5 + len];
            let bytes = decode_payload(payload, multi)?;
            wire.drain(..5 + len);
            if !bytes.is_empty() {
                out.write_all(&bytes).await?;
            }
            // 每轮最多32条完成/空消息，避免连续空帧独占执行器。
            processed += 1;
            if processed == 32 {
                processed = 0;
                tokio::task::yield_now().await;
            }
        }
        if wire.len() > 5 + MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gRPC消息累积超过上限",
            ));
        }
    }
    if !wire.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "gRPC消息在完整边界前结束",
        ));
    }
    out.shutdown().await
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode_payload(payload: &[u8], multi: bool) {
    let _ = decode_payload(payload, multi);
}

/// 有限顶层扫描后解码单个Hunk/MultiHunk；空项跳过，single取末值。
fn decode_payload(payload: &[u8], multi: bool) -> io::Result<Vec<u8>> {
    scan_fields(payload)?;
    if multi {
        let message = MultiHunk::decode(payload).map_err(io::Error::other)?;
        if message.data.len() > MAX_MULTI_ITEMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MultiHunk项数超过256",
            ));
        }
        Ok(message.data.concat())
    } else {
        Ok(Hunk::decode(payload).map_err(io::Error::other)?.data)
    }
}

fn scan_fields(payload: &[u8]) -> io::Result<()> {
    use prost::bytes::Buf;
    use prost::encoding::{DecodeContext, decode_key, skip_field};

    let mut cursor = payload;
    let mut fields = 0usize;
    while cursor.has_remaining() {
        let (tag, wire_type) = decode_key(&mut cursor).map_err(io::Error::other)?;
        skip_field(wire_type, tag, &mut cursor, DecodeContext::default())
            .map_err(io::Error::other)?;
        fields += 1;
        if fields > MAX_TOP_LEVEL_FIELDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "protobuf顶层字段超过1024",
            ));
        }
    }
    Ok(())
}

async fn pump_out(
    mut input: tokio::io::ReadHalf<DuplexStream>,
    mut send: SendStream<prost::bytes::Bytes>,
    multi: bool,
) -> io::Result<()> {
    let mut buffer = vec![0u8; WRITE_CHUNK];
    loop {
        let read = input.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let payload = if multi {
            MultiHunk {
                data: vec![buffer[..read].to_vec()],
            }
            .encode_to_vec()
        } else {
            Hunk {
                data: buffer[..read].to_vec(),
            }
            .encode_to_vec()
        };
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        send_message(&mut send, prost::bytes::Bytes::from(frame)).await?;
    }
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    send.send_trailers(trailers).map_err(io::Error::other)
}

async fn send_message(
    send: &mut SendStream<prost::bytes::Bytes>,
    data: prost::bytes::Bytes,
) -> io::Result<()> {
    let length = data.len();
    send.reserve_capacity(length);
    let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "gRPC响应方向已关闭"))?
        .map_err(io::Error::other)?;
    if capacity == 0 {
        return Err(io::Error::new(io::ErrorKind::WouldBlock, "无可用发送容量"));
    }
    send.send_data(data, false).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> FrameGuard<()> {
        FrameGuard::new(
            (),
            IoBudget::new(),
            Arc::new(Mutex::new(BTreeMap::new())),
            Duration::from_secs(10),
            64,
            Arc::new(Mutex::new(None)),
        )
    }

    fn header(length: u32) -> [u8; 9] {
        [
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    }

    #[test]
    fn decode_payload_enforces_field_and_item_bounds() {
        let empty = [0x0A, 0x00];
        let mut payload = Vec::new();
        for _ in 0..MAX_TOP_LEVEL_FIELDS {
            payload.extend_from_slice(&empty);
        }
        assert_eq!(decode_payload(&payload, false).unwrap(), Vec::<u8>::new());
        payload.extend_from_slice(&empty);
        assert!(decode_payload(&payload, false).is_err());

        let mut items = Vec::new();
        for _ in 0..=MAX_MULTI_ITEMS {
            items.extend_from_slice(&empty);
        }
        assert!(decode_payload(&items, true).is_err());
        items.truncate(MAX_MULTI_ITEMS * 2);
        assert!(decode_payload(&items, true).unwrap().is_empty());
    }

    #[test]
    fn decode_payload_uses_last_singular_and_concatenates_repeated() {
        let mut payload = vec![0x0A, 3, b'a', b'b', b'c'];
        payload.extend_from_slice(&[0x0A, 2, b'd', b'e']);
        assert_eq!(decode_payload(&payload, false).unwrap(), b"de");
        assert_eq!(decode_payload(&payload, true).unwrap(), b"abcde");
    }

    #[test]
    fn frame_guard_accepts_preface_and_settings_split_across_reads() {
        let mut guard = guard();
        guard.validate(&[0u8; 20]).unwrap();
        guard.validate(&[0u8; 4]).unwrap();
        let frame = header(0);
        guard.validate(&frame[..4]).unwrap();
        guard.validate(&frame[4..]).unwrap();
        assert_eq!(guard.payload_remaining, 0);
        assert_eq!(guard.header_len, 0);
    }

    #[test]
    fn frame_guard_counts_payload_across_reads_and_headers() {
        let mut guard = guard();
        guard.validate(&[0u8; 24]).unwrap();
        let mut frame = header(5).to_vec();
        frame.extend_from_slice(b"hello");
        frame.extend_from_slice(&header(3));
        frame.extend_from_slice(b"abc");
        guard.validate(&frame[..10]).unwrap();
        guard.validate(&frame[10..]).unwrap();
        assert_eq!(guard.payload_remaining, 0);
    }

    #[test]
    fn frame_guard_rejects_declared_length_above_16384() {
        let mut guard = guard();
        guard.validate(&[0u8; 24]).unwrap();
        let error = guard.validate(&header(16_385)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    fn frame_header(length: usize, kind: u8, flags: u8, stream: u32) -> [u8; 9] {
        [
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            kind,
            flags,
            (stream >> 24) as u8,
            (stream >> 16) as u8,
            (stream >> 8) as u8,
            stream as u8,
        ]
    }

    fn push_frame(out: &mut Vec<u8>, length: usize, kind: u8, flags: u8, stream: u32) {
        out.extend_from_slice(&frame_header(length, kind, flags, stream));
        out.resize(out.len() + length, 0);
    }

    fn framed_guard(
        duration: Duration,
        head_limit: usize,
        heads: Arc<Mutex<BTreeMap<u32, StdInstant>>>,
    ) -> FrameGuard<()> {
        FrameGuard::new(
            (),
            IoBudget::new(),
            heads,
            duration,
            head_limit,
            Arc::new(Mutex::new(None)),
        )
    }

    #[test]
    fn frame_guard_rejects_ninth_head_block_frame() {
        let mut guard = guard();
        guard.validate(&[0u8; 24]).unwrap();
        let mut wire = Vec::new();
        push_frame(&mut wire, 0, 0x1, 0, 1);
        for _ in 0..7 {
            push_frame(&mut wire, 0, 0x9, 0, 1);
        }
        push_frame(&mut wire, 0, 0x9, END_HEADERS, 1);
        let error = guard.validate(&wire).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_guard_rejects_head_block_over_16384_bytes() {
        let mut guard = guard();
        guard.validate(&[0u8; 24]).unwrap();
        let mut wire = Vec::new();
        push_frame(&mut wire, 9_000, 0x1, 0, 1);
        push_frame(&mut wire, 7_385, 0x9, END_HEADERS, 1);
        let error = guard.validate(&wire).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_guard_rejects_frame_interleaved_into_head_block() {
        let mut guard = guard();
        guard.validate(&[0u8; 24]).unwrap();
        let mut wire = Vec::new();
        push_frame(&mut wire, 0, 0x1, 0, 1);
        push_frame(&mut wire, 0, 0x0, 0, 1);
        let error = guard.validate(&wire).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_guard_limits_control_frame_rate() {
        let mut guard = guard();
        guard.validate(&[0u8; 24]).unwrap();
        let mut wire = Vec::new();
        for _ in 0..=MAX_CONTROL_PER_SECOND {
            push_frame(&mut wire, 8, 0x6, 0, 0);
        }
        let error = guard.validate(&wire).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_guard_bounds_stream_start_records() {
        let heads = Arc::new(Mutex::new(BTreeMap::new()));
        let mut guard = framed_guard(Duration::from_secs(10), 64, heads.clone());
        guard.validate(&[0u8; 24]).unwrap();
        let mut wire = Vec::new();
        for index in 0..64u32 {
            push_frame(&mut wire, 0, 0x1, END_HEADERS, index * 2 + 1);
        }
        guard.validate(&wire).unwrap();
        assert_eq!(heads.lock().unwrap().len(), 64);
        let error = guard
            .validate(&frame_header(0, 0x1, END_HEADERS, 129))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_guard_records_first_head_start_and_rst_removes_it() {
        let heads = Arc::new(Mutex::new(BTreeMap::new()));
        let mut guard = framed_guard(Duration::from_secs(10), 64, heads.clone());
        guard.validate(&[0u8; 24]).unwrap();
        guard
            .validate(&frame_header(0, 0x1, END_HEADERS, 3))
            .unwrap();
        assert!(heads.lock().unwrap().contains_key(&3));
        guard.validate(&frame_header(4, 0x3, 0, 3)).unwrap();
        assert!(!heads.lock().unwrap().contains_key(&3));
    }
}
