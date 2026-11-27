//! XHTTP 入站：HTTP/1.1 与 HTTP/2 上的 POST 上行、GET 下行与三种模式。
//! 认证、路由与 UDP 业务仍复用各协议层；本模块只负责 HTTP 语义、会话与字节桥接。

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Wake, Waker};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::task::AtomicWaker;
use h2::server::SendResponse;
use h3::server::RequestStream;
use h3_quinn::{BidiStream, RecvStream as H3RecvStream, SendStream as H3SendStream};
use http::{HeaderMap, Method, Response, StatusCode};
use prost::bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::{CancellationToken, PollSender};

use crate::config::{Inbound, Limits, Xhttp};
use crate::forward::{Context, Lease};
use crate::protocol::{trojan, vless, vmess};
use crate::runtime::{AuthSlot, WeakAuthSlot};
use crate::session::Command;
use crate::telemetry::{Gauge, Guard as GaugeGuard};

const MAX_HEAD: usize = 8_192;
const STREAM_CHUNK: usize = 16 * 1024;
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 每监听入口共享的会话表；POST与GET可来自不同物理连接。
pub(crate) struct Pool {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    slots: Arc<Semaphore>,
    stats: Arc<crate::telemetry::Stats>,
    max_buffered: usize,
    ttl: Duration,
    /// 全入口共享的排队字节预算。每段排队负载持有等量 permit，
    /// 被下行读走即归还。此前只有「条数」上限，未认证流量可以按
    /// 会话数 × 条数 × 单条上限累积到 GiB 级。
    buffer_bytes: Arc<Semaphore>,
}

impl Pool {
    pub(crate) fn new(
        xhttp: &Xhttp,
        limits: &Limits,
        // 进程级共享的排队字节预算；由 `Context` 持有并注入所有入口。
        buffer_bytes: Arc<Semaphore>,
        stats: Arc<crate::telemetry::Stats>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(limits.max_xhttp_sessions)),
            stats,
            max_buffered: xhttp.sc_max_buffered_posts,
            ttl: Duration::from_millis(xhttp.session_ttl_ms),
            buffer_bytes,
        })
    }

    fn open(self: &Arc<Self>, id: String) -> io::Result<Arc<Session>> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = sessions.get(&id) {
            return Ok(existing.clone());
        }
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "XHTTP会话上限"))?;
        let gauge = self.stats.enter(Gauge::Xhttp);
        let (tx, rx) = mpsc::channel(self.max_buffered.max(1));
        let lane = Arc::new(Session {
            id: id.clone(),
            state: Mutex::new(State::default()),
            push: tokio::sync::Mutex::new(()),
            tx: Mutex::new(Some(tx)),
            rx: Mutex::new(Some(rx)),
            authenticated: CancellationToken::new(),
            reader_closed: CancellationToken::new(),
            failed: CancellationToken::new(),
            lease: Lease::new(SessionHold {
                _slot: slot,
                _gauge: gauge,
            }),
            budget: self.buffer_bytes.clone(),
        });
        sessions.insert(id, lane.clone());
        drop(sessions);
        self.spawn_reaper(&lane);
        Ok(lane)
    }

    fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions
            .lock()
            .expect("会话表锁未中毒")
            .get(id)
            .cloned()
    }

    fn remove(&self, lane: &Session) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if sessions
            .get(&lane.id)
            .is_some_and(|current| std::ptr::eq(current.as_ref(), lane))
        {
            sessions.remove(&lane.id);
        }
    }

    fn spawn_reaper(self: &Arc<Self>, session: &Arc<Session>) {
        let pool = Arc::downgrade(self);
        let ttl = self.ttl;
        let closed = session.reader_closed.clone();
        let session = Arc::downgrade(session);
        tokio::spawn(async move {
            tokio::select! {
                _ = closed.cancelled() => {},
                _ = tokio::time::sleep(ttl) => {}
            }
            let Some(session) = session.upgrade() else {
                return;
            };
            let mut state = crate::sync::locked(&session.state);
            if state.connected {
                return;
            }
            session.close(&mut state);
            drop(state);
            if let Some(pool) = pool.upgrade() {
                pool.remove(&session);
            }
        });
    }
}

struct SessionGuard<'a> {
    pool: &'a Pool,
    lane: &'a Session,
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.lane.close(&mut crate::sync::locked(&self.lane.state));
        self.pool.remove(self.lane);
    }
}

struct SessionHold {
    _slot: OwnedSemaphorePermit,
    _gauge: GaugeGuard,
}

#[derive(Default)]
struct State {
    next_seq: u64,
    pending: BTreeMap<u64, QueuedChunk>,
    pending_bytes: usize,
    connected: bool,
    upload_attached: bool,
    upload_auth: Vec<WeakAuthSlot>,
}

pub(super) struct Session {
    id: String,
    state: Mutex<State>,
    push: tokio::sync::Mutex<()>,
    tx: Mutex<Option<mpsc::Sender<QueuedChunk>>>,
    rx: Mutex<Option<mpsc::Receiver<QueuedChunk>>>,
    authenticated: CancellationToken,
    reader_closed: CancellationToken,
    failed: CancellationToken,
    lease: Lease,
    /// 本入口的共享排队字节预算（来自 `Pool`）。
    budget: Arc<Semaphore>,
}

impl Session {
    fn lease(&self) -> Lease {
        self.lease.clone()
    }

    /// 入队一段**已经在共享字节预算内**的负载。
    ///
    /// permit 随数据一起转移给 reader，读完即释放。调用方负责在
    /// 复制数据**之前**申请额度，避免先分配再拒绝。
    async fn push_queued(&self, chunk: QueuedChunk) -> io::Result<()> {
        let Some(sender) = crate::sync::locked(&self.tx).clone() else {
            return Err(closed());
        };
        tokio::select! {
            biased;
            _ = self.reader_closed.cancelled() => Err(closed()),
            result = sender.send(chunk) => result.map_err(|_| closed()),
        }
    }

    /// 申请预算后入队（先申请、再复制，避免先分配再拒绝）。
    async fn push_with_budget(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let permit = reserve(&self.budget, bytes.len())?;
        self.push_queued((bytes.to_vec(), permit)).await
    }

    /// packet-up 有序交付：允许乱序到达，缓冲有界，重复/超界失败关闭。
    async fn push_seq(
        &self,
        seq: u64,
        chunk: QueuedChunk,
        max_post: usize,
        auth: Option<&AuthSlot>,
    ) -> io::Result<()> {
        let _serial = self.push.lock().await;
        {
            let mut state = crate::sync::locked(&self.state);
            if self.reader_closed.is_cancelled() {
                return Err(closed());
            }
            if state.upload_attached {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "XHTTP上行模式冲突",
                ));
            }
            if seq < state.next_seq || seq == u64::MAX {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "无效XHTTP序号",
                ));
            }
            if seq != state.next_seq {
                if state.pending.len() >= 1024 || state.pending.contains_key(&seq) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "XHTTP序号缓冲超限",
                    ));
                }
                let buffered = state.pending_bytes + chunk.0.len();
                if buffered > max_post.saturating_mul(2).max(CHUNK_LIMIT) {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "XHTTP序号缓冲超限",
                    ));
                }
                state.pending_bytes = buffered;
                state.pending.insert(seq, chunk);
                if let Some(auth) = auth {
                    self.bind_upload_auth(&mut state, auth);
                }
                return Ok(());
            }
        }
        let Some(sender) = crate::sync::locked(&self.tx).clone() else {
            return Err(closed());
        };
        // 取消发生在已入队一部分之后时，不能留下无人推进的连续包。
        struct PartialPush<'a>(&'a Session, bool);
        impl Drop for PartialPush<'_> {
            fn drop(&mut self) {
                if self.1 {
                    self.0.fail();
                }
            }
        }
        let mut partial = PartialPush(self, false);
        let mut first = Some(chunk);
        loop {
            if first.is_none() {
                let state = crate::sync::locked(&self.state);
                if !state.pending.contains_key(&state.next_seq) {
                    partial.1 = false;
                    return Ok(());
                }
            }
            let permit = tokio::select! {
                biased;
                _ = self.reader_closed.cancelled() => return Err(closed()),
                permit = sender.reserve() => permit.map_err(|_| closed())?,
            };
            let mut state = crate::sync::locked(&self.state);
            if self.reader_closed.is_cancelled() || state.upload_attached {
                return Err(closed());
            }
            let chunk = if let Some(chunk) = first.take() {
                if let Some(auth) = auth {
                    self.bind_upload_auth(&mut state, auth);
                }
                chunk
            } else {
                let next = state.next_seq;
                let chunk = state.pending.remove(&next).expect("序号由 push 锁串行化");
                state.pending_bytes -= chunk.0.len();
                chunk
            };
            state.next_seq += 1;
            permit.send(chunk);
            partial.1 = true;
        }
    }

    fn take_reader(&self) -> Option<mpsc::Receiver<QueuedChunk>> {
        crate::sync::locked(&self.rx).take()
    }

    fn claim<'a>(&'a self, pool: &'a Pool) -> io::Result<SessionGuard<'a>> {
        let mut state = crate::sync::locked(&self.state);
        if self.reader_closed.is_cancelled() {
            return Err(closed());
        }
        state.connected = true;
        Ok(SessionGuard { pool, lane: self })
    }

    fn close(&self, state: &mut State) {
        self.end_upload();
        self.reader_closed.cancel();
        crate::sync::locked(&self.rx).take();
        state.pending.clear();
        state.pending_bytes = 0;
        state.upload_auth.clear();
    }

    fn fail(&self) {
        let mut state = crate::sync::locked(&self.state);
        // 不把不完整的上行当作可以继续下行的正常 EOF。
        self.failed.cancel();
        self.close(&mut state);
    }

    fn bind_upload_auth(&self, state: &mut State, auth: &AuthSlot) {
        if !auth.pending() {
            return;
        }
        if self.authenticated.is_cancelled() {
            auth.release();
        } else if !self.reader_closed.is_cancelled() {
            let weak = auth.downgrade();
            state
                .upload_auth
                .retain(|slot| AuthSlot::upgrade(slot).is_some_and(|slot| slot.pending()));
            if !state.upload_auth.iter().any(|slot| slot.ptr_eq(&weak)) {
                state.upload_auth.push(weak);
            }
        }
    }

    fn finish_auth(&self) {
        let mut state = crate::sync::locked(&self.state);
        for weak in state.upload_auth.drain(..) {
            if let Some(auth) = AuthSlot::upgrade(&weak) {
                auth.release();
            }
        }
        self.authenticated.cancel();
    }

    fn attach_upload(&self, auth: &AuthSlot) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if self.reader_closed.is_cancelled()
            || state.upload_attached
            || state.next_seq != 0
            || !state.pending.is_empty()
        {
            return false;
        }
        state.upload_attached = true;
        self.bind_upload_auth(&mut state, auth);
        true
    }

    fn end_upload(&self) {
        // 丢弃最后一个sender使下行reader在排空后读到EOF。
        crate::sync::locked(&self.tx).take();
    }
}

const CHUNK_LIMIT: usize = 64 * 1024;

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP会话已关闭")
}

fn auth_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "XHTTP 认证超时")
}

fn reserve(budget: &Arc<Semaphore>, size: usize) -> io::Result<OwnedSemaphorePermit> {
    let size = u32::try_from(size).map_err(|_| too_large())?;
    budget
        .clone()
        .try_acquire_many_owned(size)
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "XHTTP排队字节超预算"))
}

struct PacketBody<'a> {
    budget: &'a Arc<Semaphore>,
    chunk: QueuedChunk,
    limit: usize,
    keep_body: bool,
    body_len: usize,
}

impl<'a> PacketBody<'a> {
    fn new(budget: &'a Arc<Semaphore>, xhttp: &Xhttp, headers: &HeaderMap) -> io::Result<Self> {
        let placement = xhttp.uplink_data_placement.as_str();
        let mut body = Self {
            budget,
            chunk: (Vec::new(), reserve(budget, 1)?),
            limit: xhttp.sc_max_each_post_bytes as usize,
            keep_body: !matches!(placement, "header" | "cookie"),
            body_len: 0,
        };
        if matches!(placement, "auto" | "header") {
            body.decode(&encoded_headers(xhttp, headers)?)?;
        }
        if matches!(placement, "auto" | "cookie") {
            body.decode(&encoded_cookies(xhttp, headers)?)?;
        }
        Ok(body)
    }

    fn grow(&mut self, size: usize) -> io::Result<()> {
        let total = self
            .chunk
            .0
            .len()
            .checked_add(size)
            .filter(|n| *n <= self.limit)
            .ok_or_else(too_large)?;
        if total > self.chunk.0.capacity() {
            let held = self.chunk.1.num_permits();
            let target = total.max(self.chunk.0.capacity().saturating_mul(2).min(self.limit));
            let permit = reserve(self.budget, target.saturating_sub(held))
                .or_else(|_| reserve(self.budget, total.saturating_sub(held)))?;
            self.chunk
                .0
                .reserve_exact((held + permit.num_permits()).max(total) - self.chunk.0.len());
            self.chunk.1.merge(permit);
        }
        Ok(())
    }

    fn decode(&mut self, encoded: &str) -> io::Result<()> {
        let size = encoded.len() / 4 * 3 + (encoded.len() % 4) * 3 / 4;
        self.grow(size)?;
        let start = self.chunk.0.len();
        self.chunk.0.resize(start + size, 0);
        let written = URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut self.chunk.0[start..])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "XHTTP上行数据base64非法"))?;
        self.chunk.0.truncate(start + written);
        Ok(())
    }

    fn prepare(&mut self, size: usize) -> io::Result<()> {
        self.body_len = self
            .body_len
            .checked_add(size)
            .filter(|n| *n <= self.limit)
            .ok_or_else(too_large)?;
        if self.keep_body {
            self.grow(size)?;
        }
        Ok(())
    }

    fn append(&mut self, mut bytes: impl Buf) -> io::Result<()> {
        self.prepare(bytes.remaining())?;
        if self.keep_body {
            while bytes.has_remaining() {
                let chunk = bytes.chunk();
                self.chunk.0.extend_from_slice(chunk);
                let len = chunk.len();
                bytes.advance(len);
            }
        }
        Ok(())
    }
}

async fn drive_upload(
    lane: &Session,
    deadline: Instant,
    upload: impl Future<Output = io::Result<()>>,
) -> io::Result<()> {
    struct EndUpload<'a>(&'a Session);
    impl Drop for EndUpload<'_> {
        fn drop(&mut self) {
            self.0.end_upload();
        }
    }
    let _end = EndUpload(lane);
    tokio::pin!(upload);
    tokio::select! {
        biased;
        _ = lane.reader_closed.cancelled() => Ok(()),
        _ = lane.authenticated.cancelled() => {
            tokio::select! {
                biased;
                _ = lane.reader_closed.cancelled() => Ok(()),
                result = &mut upload => result,
            }
        }
        _ = tokio::time::sleep_until(deadline) => Err(auth_timeout()),
        result = &mut upload => result,
    }
}

/// 下发入口：TLS 只接受 h2/http1.1；明文接受 h2c prior-knowledge 或 h1。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    mut stream: TcpStream,
    config: Arc<Inbound>,
    security: Option<crate::tls::InboundSecurity>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    pool: Arc<Pool>,
    handshake: crate::runtime::HandshakePermits,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let timeout_ms = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let absolute = Instant::now() + timeout_ms;
    match security {
        Some(security) => {
            let (stream, alpn) = match security.accept(stream, &ctx, absolute).await? {
                crate::tls::AcceptedInbound::Fallback => return Ok(()),
                crate::tls::AcceptedInbound::Stream { io, alpn } => (io, alpn),
            };
            let auth = crate::runtime::AuthSlot::new(handshake);
            match alpn.as_deref() {
                Some(b"h2") => {
                    serve_h2(
                        stream, config, vmess, ctx, pool, absolute, stop, force, auth,
                    )
                    .await
                }
                Some(b"http/1.1") | None => {
                    serve_h1(
                        Conn {
                            io: stream,
                            buffer: Vec::new(),
                        },
                        config,
                        vmess,
                        ctx,
                        pool,
                        absolute,
                        stop,
                        force,
                        auth,
                    )
                    .await
                }
                Some(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XHTTP ALPN不受支持",
                )),
            }
        }
        None => {
            // 明文承载先判前24字节；分片到达时继续等到能区分h2c与h1。
            let mut prefix = [0u8; H2_PREFACE.len()];
            let mut read = 0;
            loop {
                let available = timeout_at(absolute, stream.read(&mut prefix[read..]))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP首字节超时"))??;
                if available == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "XHTTP连接提前关闭",
                    ));
                }
                read += available;
                if !H2_PREFACE.starts_with(&prefix[..read]) || read == H2_PREFACE.len() {
                    break;
                }
            }
            let auth = crate::runtime::AuthSlot::new(handshake);
            if read == H2_PREFACE.len() && prefix == H2_PREFACE {
                serve_h2(
                    PrefixReader::new(prefix.to_vec(), stream),
                    config,
                    vmess,
                    ctx,
                    pool,
                    absolute,
                    stop,
                    force,
                    auth,
                )
                .await
            } else {
                serve_h1(
                    Conn {
                        io: stream,
                        buffer: prefix[..read].to_vec(),
                    },
                    config,
                    vmess,
                    ctx,
                    pool,
                    absolute,
                    stop,
                    force,
                    auth,
                )
                .await
            }
        }
    }
}

struct Head {
    method: Method,
    target: String,
    headers: HeaderMap,
    body: BodyKind,
}

enum BodyKind {
    None,
    Length(usize),
    Chunked,
}

struct Conn<S> {
    io: S,
    buffer: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Conn<S> {
    async fn read_head(&mut self, deadline: Instant, limit: usize) -> io::Result<Option<Head>> {
        loop {
            if let Some(end) = find_head_end(&self.buffer) {
                if end > limit {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "XHTTP请求头过长",
                    ));
                }
                let head = parse_head(&self.buffer[..end])?;
                self.buffer.drain(..end);
                return Ok(Some(head));
            }
            if self.buffer.len() >= limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XHTTP请求头过长",
                ));
            }
            let mut chunk = [0u8; 1024];
            let read = timeout_at(deadline, self.io.read(&mut chunk))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP请求头超时"))??;
            if read == 0 {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XHTTP请求头截断",
                ));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    async fn read_body(&mut self, body: &BodyKind, packet: &mut PacketBody<'_>) -> io::Result<()> {
        match body {
            BodyKind::None => Ok(()),
            BodyKind::Length(length) => self.read_packet_bytes(packet, *length).await,
            BodyKind::Chunked => self.read_chunked(packet).await,
        }
    }

    async fn read_packet_bytes(
        &mut self,
        packet: &mut PacketBody<'_>,
        size: usize,
    ) -> io::Result<()> {
        packet.prepare(size)?;
        if packet.keep_body {
            let start = packet.chunk.0.len();
            packet.chunk.0.resize(start + size, 0);
            return self.read_exact_into(&mut packet.chunk.0[start..]).await;
        }
        let mut discard = [0; 1024];
        let mut left = size;
        while left != 0 {
            let n = left.min(discard.len());
            self.read_exact_into(&mut discard[..n]).await?;
            left -= n;
        }
        Ok(())
    }

    async fn stream_body(&mut self, body: &BodyKind, session: &Session) -> io::Result<()> {
        match body {
            BodyKind::None => {}
            BodyKind::Length(length) => {
                let mut remaining = *length;
                while remaining > 0 {
                    let take = remaining.min(STREAM_CHUNK);
                    let permit = reserve(&session.budget, take)?;
                    let mut piece = vec![0u8; take];
                    self.read_exact_into(&mut piece).await?;
                    session.push_queued((piece, permit)).await?;
                    remaining -= take;
                }
            }
            BodyKind::Chunked => loop {
                let line = self.read_line().await?;
                let size_text = line.split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(size_text, 16)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "非法chunk长度"))?;
                if size == 0 {
                    while !self.read_line().await?.is_empty() {}
                    break;
                }
                // 即使对端声明大chunk，也只按固定上限分块，不按声明长度分配。
                let mut remaining = size;
                while remaining > 0 {
                    let take = remaining.min(STREAM_CHUNK);
                    let permit = reserve(&session.budget, take)?;
                    let mut piece = vec![0u8; take];
                    self.read_exact_into(&mut piece).await?;
                    session.push_queued((piece, permit)).await?;
                    remaining -= take;
                }
                let mut crlf = [0u8; 2];
                self.read_exact_into(&mut crlf).await?;
                if crlf != *b"\r\n" {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk结尾非法"));
                }
            },
        }
        Ok(())
    }

    async fn read_chunked(&mut self, packet: &mut PacketBody<'_>) -> io::Result<()> {
        loop {
            let line = self.read_line().await?;
            let size_text = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "非法chunk长度"))?;
            if size == 0 {
                while !self.read_line().await?.is_empty() {}
                return Ok(());
            }
            self.read_packet_bytes(packet, size).await?;
            let mut crlf = [0u8; 2];
            self.read_exact_into(&mut crlf).await?;
            if crlf != *b"\r\n" {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk结尾非法"));
            }
        }
    }

    async fn read_line(&mut self) -> io::Result<String> {
        loop {
            if let Some(end) = find_line_end(&self.buffer) {
                let line = String::from_utf8(self.buffer[..end].to_vec())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk行非UTF8"))?;
                self.buffer.drain(..end + 2);
                return Ok(line);
            }
            if self.buffer.len() > MAX_HEAD {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk行过长"));
            }
            // 必须**直接从底层读**。这里走到说明 buffer 里没有 `\r\n`（残留
            // 半行）；此前的实现经一个「优先从 buffer 取」的辅助函数读到同一份
            // 残留、再原样放回，于是无限空转——正常网络分片即可触发。
            let mut chunk = [0u8; 1024];
            let read = self.io.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk行截断"));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    async fn read_exact_into(&mut self, out: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        if !self.buffer.is_empty() {
            let take = out.len().min(self.buffer.len());
            out[..take].copy_from_slice(&self.buffer[..take]);
            self.buffer.drain(..take);
            offset = take;
        }
        if offset < out.len() {
            self.io.read_exact(&mut out[offset..]).await?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut conn: Conn<S>,
    config: Arc<Inbound>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    pool: Arc<Pool>,
    absolute: Instant,
    stop: CancellationToken,
    force: CancellationToken,
    auth: crate::runtime::AuthSlot,
) -> io::Result<()> {
    let head_limit = xhttp_config(&config)?.server_max_header_bytes();
    loop {
        let head = tokio::select! {
            biased;
            _ = force.cancelled() => return Ok(()),
            _ = stop.cancelled() => return Ok(()),
            head = conn.read_head(absolute, head_limit) => head?,
        };
        let Some(head) = head else {
            return Ok(());
        };
        let keep = head
            .headers
            .get(http::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| !v.eq_ignore_ascii_case("close"));
        match handle_h1(conn, head, &config, &vmess, &ctx, &pool, absolute, &auth).await {
            Ok(Some(next)) if keep => conn = next,
            Ok(_) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_h1<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut conn: Conn<S>,
    head: Head,
    config: &Inbound,
    vmess: &Option<Arc<vmess::Prepared>>,
    ctx: &Arc<Context>,
    pool: &Arc<Pool>,
    absolute: Instant,
    auth: &crate::runtime::AuthSlot,
) -> io::Result<Option<Conn<S>>> {
    let xhttp = xhttp_config(config)?;
    let (path, query) = split_target(&head.target);
    let (session, seq) = match extract_meta(xhttp, &path, &query, &head.headers) {
        Ok(meta) => meta,
        Err(_) => {
            write_status(&mut conn.io, xhttp, "404 Not Found").await?;
            return Ok(None);
        }
    };
    if validate_host(xhttp, &head.headers, None).is_err() {
        write_status(&mut conn.io, xhttp, "404 Not Found").await?;
        return Ok(None);
    }
    if padding(xhttp, &query, &head.headers).is_err() {
        write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
        return Ok(None);
    }
    if !mode_allows(xhttp, &head.method, session.is_some(), seq.is_some()) {
        write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
        return Ok(None);
    }
    if head.method == Method::GET {
        let Some(session_id) = session else {
            write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
            return Ok(None);
        };
        if seq.is_some() {
            write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
            return Ok(None);
        }
        // Xray 的 GET 下行可以先于 POST 到达；无会话时创建待上行会话。
        let lane = match pool.get(&session_id) {
            Some(lane) => lane,
            None => pool.open(session_id.clone())?,
        };
        let Some(rx) = lane.take_reader() else {
            write_status(&mut conn.io, xhttp, "409 Conflict").await?;
            return Ok(None);
        };
        let _session = lane.claim(pool)?;
        timeout_at(absolute, write_stream_headers(&mut conn.io, xhttp))
            .await
            .map_err(|_| auth_timeout())??;
        let (read, write) = tokio::io::split(conn.io);
        drop(read);
        let tunnel = Tunnel::new(
            ChannelReader::new(rx, &lane),
            FinishOnDrop::new(ChunkedWriter::new(write)),
        );
        let result = dispatch(
            tunnel,
            config,
            vmess,
            ctx,
            absolute,
            Some(&lane),
            Some(auth),
        )
        .await;
        result?;
        return Ok(None);
    }
    if head.method != Method::POST {
        write_status(&mut conn.io, xhttp, "405 Method Not Allowed").await?;
        return Ok(None);
    }
    if session.is_none() {
        // stream-one：单个 POST 双向承载。
        if !matches!(
            xhttp.mode,
            crate::config::Mode::Auto | crate::config::Mode::StreamOne
        ) {
            write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
            return Ok(None);
        }
        timeout_at(absolute, write_stream_headers(&mut conn.io, xhttp))
            .await
            .map_err(|_| auth_timeout())??;
        let session_id = unique_session_id();
        let lane = pool.open(session_id.clone())?;
        let _session = lane.claim(pool)?;
        let (read, write) = tokio::io::split(conn.io);
        let input = match head.body {
            BodyKind::Chunked => BodyReader::Chunked(ChunkedReader::new(conn.buffer, read)),
            _ => BodyReader::Raw(PrefixReader::new(conn.buffer, read)),
        };
        let tunnel = Tunnel::new(input, FinishOnDrop::new(ChunkedWriter::new(write)));
        let result = dispatch(
            tunnel,
            config,
            vmess,
            ctx,
            absolute,
            Some(&lane),
            Some(auth),
        )
        .await;
        result?;
        return Ok(None);
    }
    let Some(session_id) = session else {
        write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
        return Ok(None);
    };
    if seq.is_none() {
        // stream-up：单个长 POST 持续上行。
        if !matches!(
            xhttp.mode,
            crate::config::Mode::Auto | crate::config::Mode::StreamUp
        ) {
            write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
            return Ok(None);
        }
        let lane = pool.open(session_id.clone())?;
        if !lane.attach_upload(auth) {
            write_status(&mut conn.io, xhttp, "409 Conflict").await?;
            return Ok(None);
        }
        drive_upload(&lane, absolute, async {
            write_stream_headers(&mut conn.io, xhttp).await?;
            conn.stream_body(&head.body, &lane).await
        })
        .await?;
        timeout_at(
            Instant::now() + Duration::from_millis(ctx.limits.handshake_timeout_ms),
            async {
                conn.io.write_all(b"0\r\n\r\n").await?;
                conn.io.flush().await
            },
        )
        .await
        .map_err(|_| auth_timeout())??;
        return Ok(None);
    }
    // packet-up：有界读取后按 seq 入队。
    if !matches!(
        xhttp.mode,
        crate::config::Mode::Auto | crate::config::Mode::PacketUp
    ) {
        write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
        return Ok(None);
    }
    // packet-up 的正文读取也在认证之前，必须有同一绝对期限。
    let Some(seq) = seq else {
        write_status(&mut conn.io, xhttp, "400 Bad Request").await?;
        return Ok(None);
    };
    let result = timeout_at(absolute, async {
        let mut packet = PacketBody::new(&pool.buffer_bytes, xhttp, &head.headers)?;
        conn.read_body(&head.body, &mut packet).await?;
        let lane = pool.open(session_id)?;
        lane.push_seq(seq, packet.chunk, packet.limit, None).await
    })
    .await
    .map_err(|_| auth_timeout())?;
    if let Err(error) = result {
        let status = match error.kind() {
            io::ErrorKind::InvalidData => "413 Payload Too Large",
            io::ErrorKind::InvalidInput => "400 Bad Request",
            _ => return Err(error),
        };
        write_status(&mut conn.io, xhttp, status).await?;
        return Ok(None);
    }
    write_status(&mut conn.io, xhttp, "200 OK").await?;
    Ok(Some(conn))
}

#[allow(clippy::too_many_arguments)]
async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    io: S,
    config: Arc<Inbound>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    pool: Arc<Pool>,
    absolute: Instant,
    stop: CancellationToken,
    force: CancellationToken,
    auth: crate::runtime::AuthSlot,
) -> io::Result<()> {
    let head_limit = xhttp_config(&config)?.server_max_header_bytes() as u32;
    // H2 握手本身也受 `absolute` 约束：此前只有 TLS 握手受期限保护，
    // 之后可以无限期停在 H2 握手或空转不发请求。
    let mut connection = tokio::time::timeout_at(absolute, async {
        h2::server::Builder::new()
            .max_concurrent_streams(64)
            .initial_window_size(65_535)
            .initial_connection_window_size(65_535)
            .max_frame_size(16_384)
            .max_header_list_size(head_limit)
            .handshake(io)
            .await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP h2握手超时"))?
    .map_err(io::Error::other)?;
    let mut streams = JoinSet::new();
    let duration = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    loop {
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            _ = tokio::time::sleep_until(absolute), if auth.pending() => {
                if auth.pending() { return Err(auth_timeout()); }
            }
            Some(_) = streams.join_next() => {}
            accepted = connection.accept() => {
                let Some(accepted) = accepted else { break };
                let (request, mut respond) = accepted.map_err(io::Error::other)?;
                if streams.len() >= 64 {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    metrics_reject(&ctx);
                    continue;
                }
                let deadline = if auth.pending() { absolute } else { Instant::now() + duration };
                let config = config.clone();
                let vmess = vmess.clone();
                let ctx = ctx.clone();
                let pool = pool.clone();
                let auth = auth.clone();
                let tracker = ctx.children.clone();
                streams.spawn(tracker.track_future(async move {
                    if let Err(error) = handle_h2(request, respond, &config, &vmess, &ctx, &pool, deadline, &auth).await {
                        metrics_reject(&ctx);
                        let _ = error;
                    }
                }));
            }
        }
    }
    let _ = timeout(
        Duration::from_millis(ctx.limits.shutdown_timeout_ms),
        async { while streams.join_next().await.is_some() {} },
    )
    .await;
    streams.abort_all();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_h2(
    request: http::Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    config: &Inbound,
    vmess: &Option<Arc<vmess::Prepared>>,
    ctx: &Arc<Context>,
    pool: &Arc<Pool>,
    absolute: Instant,
    auth: &crate::runtime::AuthSlot,
) -> io::Result<()> {
    let xhttp = xhttp_config(config)?;
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let (session, seq) = extract_meta(xhttp, &path, &query, request.headers())?;
    validate_host(
        xhttp,
        request.headers(),
        request
            .uri()
            .authority()
            .map(|authority| authority.as_str()),
    )?;
    padding(xhttp, &query, request.headers())?;
    if !mode_allows(xhttp, request.method(), session.is_some(), seq.is_some()) {
        reject_h2(&mut respond, xhttp, StatusCode::BAD_REQUEST).await;
        return Ok(());
    }
    if *request.method() == Method::GET {
        let (Some(session_id), None) = (session, seq) else {
            reject_h2(&mut respond, xhttp, StatusCode::BAD_REQUEST).await;
            return Ok(());
        };
        let lane = match pool.get(&session_id) {
            Some(lane) => lane,
            None => pool.open(session_id.clone())?,
        };
        let Some(rx) = lane.take_reader() else {
            reject_h2(&mut respond, xhttp, StatusCode::CONFLICT).await;
            return Ok(());
        };
        let _session = lane.claim(pool)?;
        let send = stream_h2_response(&mut respond, xhttp)?;
        dispatch_h2(
            ChannelReader::new(rx, &lane),
            send,
            config,
            vmess,
            ctx,
            absolute,
            Some(&lane),
            Some(auth),
        )
        .await
    } else if *request.method() == Method::POST {
        if session.is_none() {
            let send = stream_h2_response(&mut respond, xhttp)?;
            return dispatch_h2(
                H2Reader::new(request.into_body()),
                send,
                config,
                vmess,
                ctx,
                absolute,
                None,
                Some(auth),
            )
            .await;
        }
        let Some(session_id) = session else {
            reject_h2(&mut respond, xhttp, StatusCode::BAD_REQUEST).await;
            return Ok(());
        };
        if seq.is_none() {
            let lane = match pool.get(&session_id) {
                Some(lane) => lane,
                None => pool.open(session_id.clone())?,
            };
            if !lane.attach_upload(auth) {
                reject_h2(&mut respond, xhttp, StatusCode::CONFLICT).await;
                return Ok(());
            }
            let mut send = match respond.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .expect("响应头合法"),
                false,
            ) {
                Ok(send) => send,
                Err(error) => {
                    lane.end_upload();
                    return Err(io::Error::other(error));
                }
            };
            let mut body = request.into_body();
            drive_upload(&lane, absolute, async {
                let upload = async {
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.map_err(io::Error::other)?;
                        lane.push_with_budget(&chunk).await?;
                        body.flow_control()
                            .release_capacity(chunk.len())
                            .map_err(io::Error::other)?;
                    }
                    Ok(())
                };
                tokio::select! {
                    biased;
                    _ = std::future::poll_fn(|cx| send.poll_reset(cx)) => Err(closed()),
                    result = upload => result,
                }
            })
            .await?;
            send.send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            return Ok(());
        }
        let Some(seq) = seq else {
            reject_h2(&mut respond, xhttp, StatusCode::BAD_REQUEST).await;
            return Ok(());
        };
        let upload = async {
            let mut packet = PacketBody::new(&pool.buffer_bytes, xhttp, request.headers())?;
            let mut body = request.into_body();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(io::Error::other)?;
                let len = chunk.len();
                packet.append(chunk)?;
                body.flow_control()
                    .release_capacity(len)
                    .map_err(io::Error::other)?;
            }
            let lane = pool.open(session_id)?;
            lane.push_seq(seq, packet.chunk, packet.limit, Some(auth))
                .await
        };
        let result = tokio::select! {
            biased;
            _ = std::future::poll_fn(|cx| respond.poll_reset(cx)) => return Err(closed()),
            result = timeout_at(absolute, upload) => result.map_err(|_| auth_timeout())?,
        };
        if let Err(error) = result {
            reject_h2(&mut respond, xhttp, packet_error_status(&error)?).await;
            return Ok(());
        }
        let _ = respond.send_response(
            Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("响应头合法"),
            true,
        );
        Ok(())
    } else {
        reject_h2(&mut respond, xhttp, StatusCode::METHOD_NOT_ALLOWED).await;
        Ok(())
    }
}

fn stream_h2_response(
    respond: &mut SendResponse<Bytes>,
    xhttp: &Xhttp,
) -> io::Result<h2::SendStream<Bytes>> {
    respond
        .send_response(response_head(xhttp)?, false)
        .map_err(io::Error::other)
}

/// 下行成功响应头；HTTP/1.1、HTTP/2 与 HTTP/3 共用。
fn response_head(xhttp: &Xhttp) -> io::Result<Response<()>> {
    status_head(xhttp, StatusCode::OK)
}

fn status_head(xhttp: &Xhttp, status: StatusCode) -> io::Result<Response<()>> {
    let mut builder = Response::builder()
        .status(status)
        .header("x-accel-buffering", "no")
        .header("cache-control", "no-store");
    if status == StatusCode::OK && !xhttp.no_sse_header {
        builder = builder.header("content-type", "text/event-stream");
    }
    for (name, value) in &xhttp.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    for (name, value) in padding_response_headers(xhttp)? {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "XHTTP 响应头非法"))
}

async fn reject_h2(respond: &mut SendResponse<Bytes>, xhttp: &Xhttp, status: StatusCode) {
    let head = status_head(xhttp, status).unwrap_or_else(|_| {
        Response::builder()
            .status(status)
            .body(())
            .expect("状态响应头合法")
    });
    let _ = respond.send_response(head, true);
}

fn metrics_reject(ctx: &Arc<Context>) {
    ctx.stats.reject();
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_h2<R: AsyncRead + Unpin + Send + 'static>(
    read: R,
    send: h2::SendStream<Bytes>,
    config: &Inbound,
    vmess: &Option<Arc<vmess::Prepared>>,
    ctx: &Arc<Context>,
    deadline: Instant,
    lane: Option<&Session>,
    auth: Option<&AuthSlot>,
) -> io::Result<()> {
    let write = CancellableH2Writer {
        inner: Arc::new(Mutex::new(H2Writer::new(send))),
        wake: Arc::default(),
    };
    let tunnel = Tunnel::new(read, FinishOnDrop::new(write.clone()));
    tokio::select! {
        biased;
        _ = write.cancelled() => Err(closed()),
        result = dispatch(tunnel, config, vmess, ctx, deadline, lane, auth) => result,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch<S>(
    app: S,
    config: &Inbound,
    vmess: &Option<Arc<vmess::Prepared>>,
    ctx: &Arc<Context>,
    deadline: Instant,
    lane: Option<&Session>,
    auth: Option<&crate::runtime::AuthSlot>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let duration = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let lease = lane.map(Session::lease);
    let finish_auth = || {
        if let Some(auth) = auth {
            auth.release();
        }
        if let Some(lane) = lane {
            lane.finish_auth();
        }
    };
    let relay = async {
        match config {
            Inbound::VlessXhttp {
                tag, users, xudp, ..
            }
            | Inbound::VlessHttpUpgrade {
                tag, users, xudp, ..
            } => {
                let mut app: Box<dyn crate::tls::Io> = match ctx.vless_encryption(tag) {
                    Some(prepared) => {
                        Box::new(timeout_at(deadline, prepared.accept(app)).await.map_err(
                            |_| {
                                io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "XHTTP/VLESS Encryption 超时",
                                )
                            },
                        )??)
                    }
                    None => Box::new(app),
                };
                let accepted =
                    timeout_at(deadline, vless::read_plain_request(&mut app, users, *xudp))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "XHTTP/VLESS认证超时")
                        })??;
                finish_auth();
                crate::runtime::serve_plain_vless_scoped(
                    app,
                    accepted,
                    tag,
                    ctx.clone(),
                    duration,
                    *xudp,
                    lease,
                )
                .await
            }
            Inbound::TrojanXhttp { tag, users, .. }
            | Inbound::TrojanHttpUpgrade { tag, users, .. } => {
                let mut app = app;
                let request = timeout_at(deadline, trojan::read_request(&mut app, users))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "XHTTP/Trojan认证超时")
                    })??;
                finish_auth();
                match request.command {
                    Command::Connect => {
                        crate::runtime::serve_trojan_connect(app, tag, ctx.clone(), &request).await
                    }
                    Command::UdpAssociate => {
                        crate::udp::trojan_scoped(
                            app,
                            ctx.clone(),
                            tag.clone(),
                            lease,
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
            Inbound::VmessXhttp { tag, .. } | Inbound::VmessHttpUpgrade { tag, .. } => {
                let mut app = app;
                let prepared = vmess
                    .as_ref()
                    .ok_or_else(|| io::Error::other("VMess未准备"))?;
                let accepted = timeout_at(deadline, prepared.handshake(&mut app, true))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "XHTTP/VMess认证超时")
                    })??;
                finish_auth();
                let allow_udp = prepared.allow_udp();
                crate::runtime::serve_vmess_scoped(
                    app,
                    accepted,
                    tag,
                    ctx.clone(),
                    duration,
                    allow_udp,
                    lease,
                )
                .await
            }
            _ => Err(io::Error::other("入口不是XHTTP/HTTPUpgrade")),
        }
    };
    if let Some(lane) = lane {
        tokio::select! {
            biased;
            _ = lane.failed.cancelled() => Err(closed()),
            result = relay => result,
        }
    } else {
        relay.await
    }
}

/// 业务函数结束时异步完成HTTP流的最终帧（chunk结束或h2 END_STREAM）。
struct FinishOnDrop<W: AsyncWrite + Unpin + Send + 'static> {
    inner: Option<W>,
}

impl<W: AsyncWrite + Unpin + Send + 'static> FinishOnDrop<W> {
    fn new(inner: W) -> Self {
        Self { inner: Some(inner) }
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> AsyncWrite for FinishOnDrop<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_write(cx, buf),
            None => Poll::Ready(Err(closed())),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_flush(cx),
            None => Poll::Ready(Err(closed())),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> Drop for FinishOnDrop<W> {
    fn drop(&mut self) {
        if let (Some(mut inner), Ok(handle)) =
            (self.inner.take(), tokio::runtime::Handle::try_current())
        {
            handle.spawn(async move {
                let _ = inner.shutdown().await;
            });
        }
    }
}

/// 下行 chunked 编码；与 `ChunkedReader` 对称，流结束在 Drop 时补齐终止块。
struct ChunkedReader<R> {
    inner: R,
    buffer: Vec<u8>,
    offset: usize,
    remaining: usize,
    state: ChunkState,
    eof: bool,
}

enum ChunkState {
    Size,
    Data,
    DataCrlf,
    Trailer,
    Done,
}

impl<R> ChunkedReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            inner,
            buffer: prefix,
            offset: 0,
            remaining: 0,
            state: ChunkState::Size,
            eof: false,
        }
    }

    fn compact(&mut self) {
        if self.offset == self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        }
    }
}

impl<R: AsyncRead + Unpin> ChunkedReader<R> {
    fn read_more(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut chunk = [0u8; 4096];
        let mut read = ReadBuf::new(&mut chunk);
        std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
        let filled = read.filled();
        if filled.is_empty() {
            self.eof = true;
        } else {
            self.buffer.extend_from_slice(filled);
        }
        Poll::Ready(Ok(()))
    }

    fn take_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Some(end) = self.buffer[self.offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| self.offset + index)
        else {
            return Ok(None);
        };
        let line = self.buffer[self.offset..end].to_vec();
        self.offset = end + 2;
        self.compact();
        Ok(Some(line))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ChunkedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.state {
                ChunkState::Size => {
                    if let Some(line) = self.take_line()? {
                        let text = std::str::from_utf8(&line).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "chunk长度非ASCII")
                        })?;
                        let size =
                            usize::from_str_radix(text.split(';').next().unwrap_or("").trim(), 16)
                                .map_err(|_| {
                                    io::Error::new(io::ErrorKind::InvalidData, "非法chunk长度")
                                })?;
                        if size == 0 {
                            self.state = ChunkState::Trailer;
                        } else {
                            self.remaining = size;
                            self.state = ChunkState::Data;
                        }
                        continue;
                    }
                    if self.eof {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "chunk长度被截断",
                        )));
                    }
                    if self.buffer.len() - self.offset > MAX_HEAD {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk长度行过长",
                        )));
                    }
                    std::task::ready!(self.read_more(cx))?;
                }
                ChunkState::Data => {
                    if self.remaining == 0 {
                        self.state = ChunkState::DataCrlf;
                        continue;
                    }
                    let available = self.buffer.len() - self.offset;
                    if available > 0 {
                        let take = available.min(self.remaining).min(buf.remaining());
                        buf.put_slice(&self.buffer[self.offset..self.offset + take]);
                        self.offset += take;
                        self.remaining -= take;
                        self.compact();
                        return Poll::Ready(Ok(()));
                    }
                    if self.eof {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "chunk正文被截断",
                        )));
                    }
                    std::task::ready!(self.read_more(cx))?;
                }
                ChunkState::DataCrlf => {
                    if self.buffer.len() - self.offset < 2 {
                        if self.eof {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "chunk结尾被截断",
                            )));
                        }
                        std::task::ready!(self.read_more(cx))?;
                        continue;
                    }
                    if &self.buffer[self.offset..self.offset + 2] != b"\r\n" {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk结尾非法",
                        )));
                    }
                    self.offset += 2;
                    self.compact();
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailer => {
                    if let Some(line) = self.take_line()? {
                        if line.is_empty() {
                            self.state = ChunkState::Done;
                        }
                        continue;
                    }
                    if self.eof {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "chunk trailer被截断",
                        )));
                    }
                    std::task::ready!(self.read_more(cx))?;
                }
                ChunkState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// h1 请求体的两种原始流；h2 DATA 帧始终是原始字节。
enum BodyReader<R> {
    Raw(PrefixReader<R>),
    Chunked(ChunkedReader<R>),
}

impl<R: AsyncRead + Unpin> AsyncRead for BodyReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Raw(reader) => Pin::new(reader).poll_read(cx, buf),
            Self::Chunked(reader) => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

pub(crate) struct Tunnel<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> Tunnel<R, W> {
    pub(crate) fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for Tunnel<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for Tunnel<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

/// 排队中的一段负载，连同它占用的字节预算 permit。
///
/// permit 随数据一起入队，整段读完后与缓冲一起释放。
type QueuedChunk = (Vec<u8>, OwnedSemaphorePermit);

struct ChannelReader {
    rx: mpsc::Receiver<QueuedChunk>,
    _on_drop: tokio_util::sync::DropGuard,
    current: Vec<u8>,
    current_budget: Option<OwnedSemaphorePermit>,
    offset: usize,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<QueuedChunk>, lane: &Session) -> Self {
        Self {
            rx,
            _on_drop: lane.reader_closed.clone().drop_guard(),
            current: Vec::new(),
            current_budget: None,
            offset: 0,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.offset < self.current.len() {
                let take = buf.remaining().min(self.current.len() - self.offset);
                buf.put_slice(&self.current[self.offset..self.offset + take]);
                self.offset += take;
                if self.offset == self.current.len() {
                    self.current = Vec::new();
                    self.current_budget = None;
                    self.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.rx.poll_recv(cx)) {
                Some((next, _)) if next.is_empty() => continue,
                Some((next, permit)) => {
                    self.current = next;
                    self.current_budget = Some(permit);
                    self.offset = 0;
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

pub(crate) struct PrefixReader<R> {
    prefix: Vec<u8>,
    offset: usize,
    inner: R,
}

impl<R> PrefixReader<R> {
    pub(crate) fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for PrefixReader<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let take = buf.remaining().min(self.prefix.len() - self.offset);
            buf.put_slice(&self.prefix[self.offset..self.offset + take]);
            self.offset += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

struct ChunkedWriter<W> {
    inner: W,
    pending: Vec<u8>,
    offset: usize,
    finished: bool,
}

impl<W> ChunkedWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            offset: 0,
            finished: false,
        }
    }
}

impl<W: AsyncWrite + Unpin> ChunkedWriter<W> {
    fn flush_pending(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.offset < self.pending.len() {
            match std::task::ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.offset..])
            ) {
                Ok(0) => return Poll::Ready(Err(closed())),
                Ok(n) => self.offset += n,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        self.pending.clear();
        self.offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ChunkedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.finished {
            return Poll::Ready(Err(closed()));
        }
        if !this.pending.is_empty() {
            std::task::ready!(this.flush_pending(cx))?;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut frame = format!("{:x}\r\n", buf.len()).into_bytes();
        frame.extend_from_slice(buf);
        frame.extend_from_slice(b"\r\n");
        this.pending = frame;
        this.offset = 0;
        std::task::ready!(this.flush_pending(cx))?;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        std::task::ready!(this.flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        std::task::ready!(this.flush_pending(cx))?;
        if !this.finished {
            this.finished = true;
            this.pending = b"0\r\n\r\n".to_vec();
            this.offset = 0;
            std::task::ready!(this.flush_pending(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub(crate) struct H2Reader {
    body: h2::RecvStream,
    current: Bytes,
    offset: usize,
}

impl H2Reader {
    pub(crate) fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            current: Bytes::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.offset < self.current.len() {
                let take = buf.remaining().min(self.current.len() - self.offset);
                buf.put_slice(&self.current[self.offset..self.offset + take]);
                self.offset += take;
                self.body
                    .flow_control()
                    .release_capacity(take)
                    .map_err(io::Error::other)?;
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.body.poll_data(cx)) {
                Some(Ok(next)) => {
                    self.current = next;
                    self.offset = 0;
                }
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

pub(crate) struct H2Writer {
    send: h2::SendStream<Bytes>,
    pending: Vec<u8>,
    offset: usize,
    finished: bool,
}

impl H2Writer {
    pub(crate) fn new(send: h2::SendStream<Bytes>) -> Self {
        Self {
            send,
            pending: Vec::new(),
            offset: 0,
            finished: false,
        }
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.finished {
            return Poll::Ready(Err(closed()));
        }
        // 上一次已接受但没写完的部分先排空，否则会与本次的新缓冲混淆。
        while this.offset < this.pending.len() {
            // 只有**当前额度为零**才去等额度增加。h2 的 `poll_capacity` 表示
            // 「额度会变大」，不是「现在能写」；已有额度时调用它会一直
            // `Pending`，即使手里还有可发空间。旧实现无条件轮询，一块写满
            // `STREAM_CHUNK` 后剩余额度还在、却卡在等下一次通知，接收端又
            // 必须收齐整帧才交付——块 ≥ 16 KiB 就稳定复现这个等待。
            if this.send.capacity() == 0 {
                this.send.reserve_capacity(this.pending.len() - this.offset);
                match this.send.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(_))) => {}
                    Poll::Ready(Some(Err(error))) => {
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                    Poll::Ready(None) => return Poll::Ready(Err(closed())),
                    // 上次的尾巴还没发完：本次调用不接受新缓冲，直接等唤醒。
                    Poll::Pending => return Poll::Pending,
                }
            }
            let take = this
                .send
                .capacity()
                .min(this.pending.len() - this.offset)
                .min(STREAM_CHUNK);
            if take == 0 {
                break;
            }
            this.send
                .send_data(
                    Bytes::copy_from_slice(&this.pending[this.offset..this.offset + take]),
                    false,
                )
                .map_err(io::Error::other)?;
            this.offset += take;
        }
        if this.offset == this.pending.len() {
            this.pending.clear();
            this.offset = 0;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 本次缓冲按**实际接受的字节数**返回，绝不虚报成 `buf.len()`：
        // 剩余部分由调用方保留，下一次 `poll_write` 会重新传入。
        let mut accepted = 0usize;
        while accepted < buf.len() {
            if this.send.capacity() == 0 {
                this.send.reserve_capacity(buf.len() - accepted);
                match this.send.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(_))) => {}
                    Poll::Ready(Some(Err(error))) => {
                        return if accepted > 0 {
                            Poll::Ready(Ok(accepted))
                        } else {
                            Poll::Ready(Err(io::Error::other(error)))
                        };
                    }
                    Poll::Ready(None) => {
                        return if accepted > 0 {
                            Poll::Ready(Ok(accepted))
                        } else {
                            Poll::Ready(Err(closed()))
                        };
                    }
                    Poll::Pending => break,
                }
            }
            let take = this
                .send
                .capacity()
                .min(buf.len() - accepted)
                .min(STREAM_CHUNK);
            if take == 0 {
                break;
            }
            this.send
                .send_data(
                    Bytes::copy_from_slice(&buf[accepted..accepted + take]),
                    false,
                )
                .map_err(io::Error::other)?;
            accepted += take;
        }
        if accepted > 0 {
            Poll::Ready(Ok(accepted))
        } else {
            // 一个字节都没接受：等额度增加。不能返回 `Ok(0)`，那会被调用方
            // 当作 `WriteZero` 错误。
            Poll::Pending
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.finished {
            this.finished = true;
            let _ = this.send.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct H2SendWake {
    write: AtomicWaker,
    reset: AtomicWaker,
}

impl Wake for H2SendWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.reset.wake();
        self.write.wake();
    }
}

#[derive(Clone)]
struct CancellableH2Writer {
    inner: Arc<Mutex<H2Writer>>,
    wake: Arc<H2SendWake>,
}

impl CancellableH2Writer {
    async fn cancelled(&self) {
        let waker = Waker::from(self.wake.clone());
        let _ = std::future::poll_fn(|cx| {
            self.wake.reset.register(cx.waker());
            crate::sync::locked(&self.inner)
                .send
                .poll_reset(&mut TaskContext::from_waker(&waker))
        })
        .await;
    }
}

impl AsyncWrite for CancellableH2Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // h2 的 reset 和写额度共用一个唤醒槽；Mux 可能从另一个任务写入。
        self.wake.write.register(cx.waker());
        let waker = Waker::from(self.wake.clone());
        Pin::new(&mut *crate::sync::locked(&self.inner))
            .poll_write(&mut TaskContext::from_waker(&waker), buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *crate::sync::locked(&self.inner)).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *crate::sync::locked(&self.inner)).poll_shutdown(cx)
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn find_line_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|w| w == b"\r\n")
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_head(bytes: &[u8]) {
    let _ = parse_head(bytes);
}

fn parse_head(bytes: &[u8]) -> io::Result<Head> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XHTTP请求头非法",
            ));
        }
    }
    let method = Method::from_bytes(request.method.unwrap_or("").as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XHTTP方法非法"))?;
    let target = request.path.unwrap_or("").to_owned();
    let mut map = HeaderMap::new();
    for header in request.headers {
        let name = http::header::HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XHTTP头名非法"))?;
        let value = http::header::HeaderValue::from_bytes(header.value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XHTTP头值非法"))?;
        map.append(name, value);
    }
    let body = body_kind(&map)?;
    Ok(Head {
        method,
        target,
        headers: map,
        body,
    })
}

fn body_kind(headers: &HeaderMap) -> io::Result<BodyKind> {
    if headers.get_all(http::header::CONTENT_LENGTH).iter().count() > 1
        || headers
            .get_all(http::header::TRANSFER_ENCODING)
            .iter()
            .count()
            > 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XHTTP重复关键头",
        ));
    }
    let length = headers.get(http::header::CONTENT_LENGTH);
    let transfer = headers.get(http::header::TRANSFER_ENCODING);
    if length.is_some() && transfer.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XHTTP同时声明长度与分块",
        ));
    }
    if let Some(value) = transfer {
        let text = value
            .to_str()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XHTTP传输编码非法"))?;
        if !text.eq_ignore_ascii_case("chunked") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XHTTP不支持该传输编码",
            ));
        }
        return Ok(BodyKind::Chunked);
    }
    match length {
        Some(value) => {
            let text = value
                .to_str()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XHTTP长度非法"))?;
            let length: usize = text
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XHTTP长度非法"))?;
            Ok(BodyKind::Length(length))
        }
        None => Ok(BodyKind::None),
    }
}

fn split_target(target: &str) -> (String, String) {
    match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (target.to_owned(), String::new()),
    }
}

fn xhttp_config(config: &Inbound) -> io::Result<&Xhttp> {
    match config {
        Inbound::VlessXhttp { xhttp, .. }
        | Inbound::VmessXhttp { xhttp, .. }
        | Inbound::TrojanXhttp { xhttp, .. } => Ok(xhttp),
        _ => Err(io::Error::other("入口不是XHTTP/HTTPUpgrade")),
    }
}

fn extract_meta(
    xhttp: &Xhttp,
    path: &str,
    query: &str,
    headers: &HeaderMap,
) -> io::Result<(Option<String>, Option<u64>)> {
    let base = xhttp.path.trim_end_matches('/');
    if path != base && !path.starts_with(&format!("{base}/")) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "XHTTP路径不匹配"));
    }
    let suffix = path[base.len()..].trim_start_matches('/');
    let mut parts = suffix.split('/').filter(|part| !part.is_empty());
    let mut session = match xhttp.session_id_placement.as_str() {
        "path" => parts.next().map(str::to_owned),
        "query" => query_value(query, xhttp.session_key().unwrap_or("x_session")),
        "header" => {
            header_value(headers, xhttp.session_key().unwrap_or("X-Session")).map(str::to_owned)
        }
        "cookie" => cookie_value(headers, xhttp.session_key().unwrap_or("x_session")),
        _ => None,
    };
    let mut seq = match xhttp.seq_placement.as_str() {
        "path" => parts.next().map(str::to_owned),
        "query" => query_value(query, xhttp.seq_key().unwrap_or("x_seq")),
        "header" => header_value(headers, xhttp.seq_key().unwrap_or("X-Seq")).map(str::to_owned),
        "cookie" => cookie_value(headers, xhttp.seq_key().unwrap_or("x_seq")),
        _ => None,
    };
    if parts.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XHTTP路径段过多",
        ));
    }
    // 默认 path 放置保留历史宽松回退：查询/头/Cookie 也可提供会话，
    // 以兼容本内核既有客户端；显式非 path 放置不跨位置回退。
    if session.is_none() && xhttp.session_id_placement == "path" {
        session = query_value(
            query,
            xhttp.session_id_key.as_deref().unwrap_or("x_session"),
        )
        .or_else(|| {
            header_value(
                headers,
                xhttp.session_id_key.as_deref().unwrap_or("x-session"),
            )
            .map(str::to_owned)
        })
        .or_else(|| {
            cookie_value(
                headers,
                xhttp.session_id_key.as_deref().unwrap_or("x_session"),
            )
        });
    }
    if seq.is_none() && xhttp.seq_placement == "path" {
        seq = query_value(query, xhttp.seq_key.as_deref().unwrap_or("x_seq"))
            .or_else(|| {
                header_value(headers, xhttp.seq_key.as_deref().unwrap_or("x-seq"))
                    .map(str::to_owned)
            })
            .or_else(|| cookie_value(headers, xhttp.seq_key.as_deref().unwrap_or("x_seq")));
    }
    if let Some(id) = &session
        && !valid_session_id(id)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XHTTP会话标识非法",
        ));
    }
    let seq = match seq {
        Some(text) => Some(
            text.parse::<u64>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XHTTP序号非法"))?,
        ),
        None => None,
    };
    Ok((session, seq))
}

fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(byte, b'/' | b'?' | b'#' | b'&' | b'=' | b';' | b',' | b'"')
        })
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| percent_decode(value))
    })
}

fn cookie_value(headers: &HeaderMap, key: &str) -> Option<String> {
    let cookie = header_value(headers, "cookie")?;
    cookie.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == key && !value.is_empty()).then(|| value.to_owned())
    })
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Xray 把 packet-up 数据按 `key-N` 头块 / `key_N` Cookie 块承载，
/// 每块是 URL-safe base64 无填充片段，拼接后整体解码。
fn encoded_headers(xhttp: &Xhttp, headers: &HeaderMap) -> io::Result<String> {
    let key = xhttp.uplink_data_key().unwrap_or("X-Data");
    let max = xhttp.sc_max_each_post_bytes as usize;
    let mut encoded = String::new();
    for index in 0..=headers.len() {
        let name = format!("{key}-{index}");
        let Ok(name) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
            break;
        };
        let Some(value) = headers.get(name) else {
            break;
        };
        let value = value
            .to_str()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "XHTTP上行头块非法"))?;
        if encoded.len() + value.len() > max.saturating_mul(2) {
            return Err(too_large());
        }
        encoded.push_str(value);
    }
    Ok(encoded)
}

fn encoded_cookies(xhttp: &Xhttp, headers: &HeaderMap) -> io::Result<String> {
    let key = xhttp.uplink_data_key().unwrap_or("x_data");
    let max = xhttp.sc_max_each_post_bytes as usize;
    let Some(cookie) = header_value(headers, "cookie") else {
        return Ok(String::new());
    };
    let mut encoded = String::new();
    for index in 0..=4_096 {
        let name = format!("{key}_{index}");
        let Some(value) = cookie.split(';').find_map(|pair| {
            let (cookie_name, value) = pair.trim().split_once('=')?;
            (cookie_name == name && !value.is_empty()).then_some(value)
        }) else {
            break;
        };
        if encoded.len() + value.len() > max.saturating_mul(2) {
            return Err(too_large());
        }
        encoded.push_str(value);
    }
    Ok(encoded)
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode_uplink(encoded: &str) {
    let _ = decode_uplink_payload(encoded, 64 * 1024);
}

#[cfg(feature = "fuzzing")]
fn decode_uplink_payload(encoded: &str, max: usize) -> io::Result<Vec<u8>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "XHTTP上行数据base64非法"))?;
    if decoded.len() > max {
        return Err(too_large());
    }
    Ok(decoded)
}

fn packet_error_status(error: &io::Error) -> io::Result<StatusCode> {
    Ok(match error.kind() {
        io::ErrorKind::InvalidData => StatusCode::PAYLOAD_TOO_LARGE,
        io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
        io::ErrorKind::AlreadyExists => StatusCode::CONFLICT,
        io::ErrorKind::WouldBlock => StatusCode::SERVICE_UNAVAILABLE,
        _ => return Err(io::Error::new(error.kind(), error.to_string())),
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16)
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn validate_host(xhttp: &Xhttp, headers: &HeaderMap, authority: Option<&str>) -> io::Result<()> {
    if headers.get_all("host").iter().count() > 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "XHTTP重复Host"));
    }
    let Some(expected) = &xhttp.host else {
        return Ok(());
    };
    // HTTP/2 与 HTTP/3 的主机名在 `:authority`，HTTP/1.1 在 Host 头。
    let host = header_value(headers, "host").or(authority).unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    if host.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "XHTTP Host不符",
        ))
    }
}

fn padding(xhttp: &Xhttp, query: &str, headers: &HeaderMap) -> io::Result<()> {
    let range = xhttp.padding();
    if xhttp.x_padding_obfs_mode {
        // 与 Xray ExtractXPaddingFromRequest 的 obfs 分支一致：
        // Cookie -> Header（header 放置直接取值，其余按 URL 查询参数解析）-> 请求查询。
        let value = cookie_value(headers, &xhttp.x_padding_key)
            .or_else(|| {
                let header = header_value(headers, &xhttp.x_padding_header)?;
                if xhttp.x_padding_placement == "header" {
                    Some(header.to_owned())
                } else {
                    header
                        .split_once('?')
                        .and_then(|(_, query)| query_value(query, &xhttp.x_padding_key))
                }
            })
            .or_else(|| query_value(query, &xhttp.x_padding_key));
        let Some(value) = value else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XHTTP混淆padding缺失",
            ));
        };
        if value.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XHTTP混淆padding缺失",
            ));
        }
        return validate_padding_value(xhttp, &value);
    }
    // 非混淆模式保留上游 Referer 查询参数语义；Referer 存在时不再回退到
    // 请求查询串，避免把不同的 URL 混为一谈。
    let value = match header_value(headers, "referer") {
        Some(referer) => referer
            .split_once('?')
            .and_then(|(_, query)| query_value(query, "x_padding")),
        None => query_value(query, "x_padding"),
    };
    let Some(value) = value else {
        // 本内核允许空填充（旧客户端默认不发送）；Xray 客户端总会发送。
        return Ok(());
    };
    if value.is_empty() {
        return Ok(());
    }
    // 兼容两种上游写法：Xray 常发送按长度重复的原文（如 XXXX…），
    // 本内核旧客户端发送 URL-safe base64。任一解释落在允许范围即接受。
    let raw_ok = (range.from..=range.to).contains(&value.len());
    let decoded_ok = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .is_ok_and(|decoded| (range.from..=range.to).contains(&decoded.len()));
    if raw_ok || decoded_ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XHTTP填充长度非法",
        ))
    }
}

fn validate_padding_value(xhttp: &Xhttp, value: &str) -> io::Result<()> {
    let range = xhttp.padding();
    let valid = match xhttp.x_padding_method.as_str() {
        "repeat-x" => (range.from..=range.to).contains(&value.len()),
        // 配置校验已拒绝 tokenish；这里再次 fail closed。
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XHTTP填充长度非法",
        ))
    }
}

/// 下行响应 padding；非混淆模式按上游固定发送 `X-Padding`。
fn padding_response_headers(xhttp: &Xhttp) -> io::Result<Vec<(String, String)>> {
    let range = xhttp.padding();
    let mut selector = [0u8; 4];
    let length = if range.from >= range.to {
        range.from
    } else {
        aws_lc_rs::rand::fill(&mut selector).map_err(|_| io::Error::other("随机数生成失败"))?;
        range.from + u32::from_be_bytes(selector) as usize % (range.to - range.from + 1)
    };
    let value = "X".repeat(length);
    if !xhttp.x_padding_obfs_mode {
        return Ok(vec![("X-Padding".to_owned(), value)]);
    }
    Ok(match xhttp.x_padding_placement.as_str() {
        "header" => vec![(xhttp.x_padding_header.clone(), value)],
        "queryInHeader" => vec![(
            xhttp.x_padding_header.clone(),
            format!("?{}={value}", xhttp.x_padding_key),
        )],
        "cookie" => vec![(
            "set-cookie".to_owned(),
            format!("{}={value}; Path=/", xhttp.x_padding_key),
        )],
        _ => Vec::new(),
    })
}

fn mode_allows(xhttp: &Xhttp, method: &Method, has_session: bool, has_seq: bool) -> bool {
    use crate::config::Mode;
    if *method != Method::POST && *method != Method::GET {
        return false;
    }
    match xhttp.mode {
        Mode::Auto => true,
        Mode::StreamOne => !has_session && !has_seq,
        Mode::StreamUp => has_session && !has_seq,
        // packet-up 的下行 GET 只带会话、不带序号；带序号的是上行 POST。
        Mode::PacketUp if *method == Method::GET => has_session && !has_seq,
        Mode::PacketUp => has_session && has_seq,
    }
}

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "XHTTP请求体超限")
}

async fn write_status<W: AsyncWrite + Unpin>(
    writer: &mut W,
    xhttp: &Xhttp,
    status: &str,
) -> io::Result<()> {
    let mut response = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n");
    for (name, value) in padding_response_headers(xhttp)? {
        response.push_str(&name);
        response.push_str(": ");
        response.push_str(&value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await
}

async fn write_stream_headers<W: AsyncWrite + Unpin>(
    writer: &mut W,
    xhttp: &Xhttp,
) -> io::Result<()> {
    let content_type = if xhttp.no_sse_header {
        ""
    } else {
        "content-type: text/event-stream\r\n"
    };
    let mut response = format!(
        "HTTP/1.1 200 OK\r\n{content_type}x-accel-buffering: no\r\ncache-control: no-store\r\ntransfer-encoding: chunked\r\n"
    );
    for (name, value) in &xhttp.headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    for (name, value) in padding_response_headers(xhttp)? {
        response.push_str(&name);
        response.push_str(": ");
        response.push_str(&value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await
}

fn unique_session_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("s{now:x}{:x}", std::process::id())
}

// ---------------------------------------------------------------------------
// HTTP/3（QUIC）承载
// ---------------------------------------------------------------------------

const H3_MAX_BIDI_STREAMS: u32 = 64;
const H3_MAX_UNI_STREAMS: u32 = 8;
const H3_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// h3 错误类型只保证 `Display`，统一转成 io 错误。
fn h3_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

/// 运行 XHTTP/3 监听：一个 QUIC 端点承载多个连接，每个连接承载多个请求流。
///
/// `socket` 必须是 UDP 套接字；`tls` 来自 `tls::load`，此处只覆盖 ALPN 为 `h3`。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_quic(
    socket: tokio::net::UdpSocket,
    tls: Arc<rustls::ServerConfig>,
    config: Arc<Inbound>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    pool: Arc<Pool>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let server = quic_server_config(tls)?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| io::Error::other("XHTTP/3 需要异步运行时"))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server),
        socket.into_std()?,
        runtime,
    )
    .map_err(|_| io::Error::other("XHTTP/3 QUIC 端点创建失败"))?;
    let connections = Arc::new(Semaphore::new(ctx.limits.max_connections.max(1)));
    let handshakes = Arc::new(Semaphore::new(ctx.limits.max_handshakes.max(1)));
    let per_ip = crate::runtime::PerIpHandshakes::new(ctx.limits.per_ip_handshakes);
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let Ok(permit) = connections.clone().try_acquire_owned() else { metrics_reject(&ctx); continue };
                let Some(ip_guard) = per_ip.admit(incoming.remote_address().ip()) else { metrics_reject(&ctx); continue };
                let Ok(handshake) = handshakes.clone().try_acquire_owned() else { metrics_reject(&ctx); continue };
                let deadline = Instant::now() + Duration::from_millis(ctx.limits.handshake_timeout_ms);
                let config = config.clone();
                let vmess = vmess.clone();
                let ctx = ctx.clone();
                let pool = pool.clone();
                let stop = stop.clone();
                let force = force.clone();
                let tracker = ctx.children.clone();
                tasks.spawn(tracker.track_future(async move {
                    let _permit = permit;
                    let accepted = timeout_at(deadline, async move { incoming.await }).await;
                    let Ok(Ok(connection)) = accepted else { return };
                    // 许可由认证成功释放，不是 QUIC 握手完成。
                    let auth = crate::runtime::AuthSlot::new(
                        crate::runtime::HandshakePermits::new(handshake, Some(ip_guard)),
                    );
                    let _ = serve_h3_connection(connection, config, vmess, ctx, pool, stop, force, auth, deadline).await;
                }));
            }
            Some(_) = tasks.join_next() => {}
        }
    }
    let _ = timeout(
        Duration::from_millis(ctx.limits.shutdown_timeout_ms),
        async { while tasks.join_next().await.is_some() {} },
    )
    .await;
    tasks.abort_all();
    // 连接任务里还有流任务与 gauge；abort 只是请求取消，这里等它们 drop。
    let _ = timeout(Duration::from_secs(3), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    let _ = timeout(Duration::from_secs(3), endpoint.wait_idle()).await;
    Ok(())
}

/// 构造只协商 `h3` 的 QUIC 服务配置。
fn quic_server_config(tls: Arc<rustls::ServerConfig>) -> io::Result<quinn::ServerConfig> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // QUIC 不使用 0-RTT；rustls 要求该值为 0 或 u32::MAX。
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "XHTTP/3 TLS 配置不支持 QUIC"))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(H3_MAX_BIDI_STREAMS));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(H3_MAX_UNI_STREAMS));
    let idle = quinn::IdleTimeout::try_from(H3_IDLE_TIMEOUT)
        .map_err(|_| io::Error::other("XHTTP/3 空闲超时超出范围"))?;
    transport.max_idle_timeout(Some(idle));
    server.transport_config(Arc::new(transport));
    Ok(server)
}

/// 单个 QUIC 连接内的 HTTP/3 请求循环。
#[allow(clippy::too_many_arguments)]
async fn serve_h3_connection(
    connection: quinn::Connection,
    config: Arc<Inbound>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    pool: Arc<Pool>,
    stop: CancellationToken,
    force: CancellationToken,
    auth: crate::runtime::AuthSlot,
    absolute: Instant,
) -> io::Result<()> {
    struct CloseQuic(quinn::Connection);
    impl Drop for CloseQuic {
        fn drop(&mut self) {
            self.0.close(0u32.into(), b"");
        }
    }
    let _close = CloseQuic(connection.clone());
    let mut connection = timeout_at(
        absolute,
        h3::server::Connection::<h3_quinn::Connection, Bytes>::new(h3_quinn::Connection::new(
            connection,
        )),
    )
    .await
    .map_err(|_| auth_timeout())?
    .map_err(h3_error)?;
    let duration = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            _ = tokio::time::sleep_until(absolute), if auth.pending() => {
                if auth.pending() { return Err(auth_timeout()); }
            }
            Some(_) = streams.join_next() => {}
            accepted = connection.accept() => {
                let Some(resolver) = accepted.map_err(h3_error)? else { break };
                if streams.len() >= H3_MAX_BIDI_STREAMS as usize {
                    metrics_reject(&ctx);
                    continue;
                }
                let deadline = if auth.pending() { absolute } else { Instant::now() + duration };
                let config = config.clone();
                let vmess = vmess.clone();
                let ctx = ctx.clone();
                let pool = pool.clone();
                let auth = auth.clone();
                let tracker = ctx.children.clone();
                streams.spawn(tracker.track_future(async move {
                    let result = async {
                        let (request, stream) = timeout_at(deadline, resolver.resolve_request())
                            .await.map_err(|_| auth_timeout())?.map_err(h3_error)?;
                        handle_h3(request, stream, &config, &vmess, &ctx, &pool, deadline, &auth).await
                    }.await;
                    if let Err(error) = result {
                        metrics_reject(&ctx);
                        let _ = error;
                    }
                }));
            }
        }
    }
    let shutdown = Duration::from_millis(ctx.limits.shutdown_timeout_ms);
    let _ = timeout(shutdown, connection.shutdown(0)).await;
    let _ = timeout(shutdown, async {
        while streams.join_next().await.is_some() {}
    })
    .await;
    // 上面的宽限 drain 可能超时；abort 之后仍要等到任务真正 drop，
    // 否则它们持有的 `Gauge::Tcp` 会晚于连接任务结束。
    streams.abort_all();
    let _ = timeout(shutdown, async {
        while streams.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_h3(
    request: http::Request<()>,
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    config: &Inbound,
    vmess: &Option<Arc<vmess::Prepared>>,
    ctx: &Arc<Context>,
    pool: &Arc<Pool>,
    absolute: Instant,
    auth: &crate::runtime::AuthSlot,
) -> io::Result<()> {
    let xhttp = xhttp_config(config)?;
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let (session, seq) = extract_meta(xhttp, &path, &query, request.headers())?;
    validate_host(
        xhttp,
        request.headers(),
        request
            .uri()
            .authority()
            .map(|authority| authority.as_str()),
    )?;
    padding(xhttp, &query, request.headers())?;
    if !mode_allows(xhttp, request.method(), session.is_some(), seq.is_some()) {
        reject_h3(&mut stream, xhttp, StatusCode::BAD_REQUEST, absolute).await;
        return Ok(());
    }
    if *request.method() == Method::GET {
        let (Some(session_id), None) = (session, seq) else {
            reject_h3(&mut stream, xhttp, StatusCode::BAD_REQUEST, absolute).await;
            return Ok(());
        };
        let lane = match pool.get(&session_id) {
            Some(lane) => lane,
            None => pool.open(session_id.clone())?,
        };
        let Some(rx) = lane.take_reader() else {
            reject_h3(&mut stream, xhttp, StatusCode::CONFLICT, absolute).await;
            return Ok(());
        };
        let _session = lane.claim(pool)?;
        timeout_at(absolute, stream.send_response(response_head(xhttp)?))
            .await
            .map_err(|_| auth_timeout())?
            .map_err(h3_error)?;
        let (send, recv) = stream.split();
        let (tx, out) = mpsc::channel::<Bytes>(8);
        let cancelled = h3_cancelled(send.quic_stream().stopped());
        // recv 只用于保持请求句柄存活到下行结束，不读取客户端请求体。
        let writer = tokio_util::task::AbortOnDropHandle::new(ctx.children.spawn(async move {
            let _recv = recv;
            pump_h3(send, out).await
        }));
        let tunnel = Tunnel::new(ChannelReader::new(rx, &lane), H3Sender::new(tx));
        let relay = dispatch(
            tunnel,
            config,
            vmess,
            ctx,
            absolute,
            Some(&lane),
            Some(auth),
        );
        tokio::select! {
            biased;
            _ = cancelled => return Err(closed()),
            result = relay => result?,
        }
        timeout(
            Duration::from_millis(ctx.limits.handshake_timeout_ms),
            writer,
        )
        .await
        .map_err(|_| auth_timeout())?
        .map_err(io::Error::other)?
    } else if *request.method() == Method::POST {
        if session.is_none() {
            timeout_at(absolute, stream.send_response(response_head(xhttp)?))
                .await
                .map_err(|_| auth_timeout())?
                .map_err(h3_error)?;
            let (send, recv) = stream.split();
            let (tx, out) = mpsc::channel::<Bytes>(8);
            let cancelled = h3_cancelled(send.quic_stream().stopped());
            let writer =
                tokio_util::task::AbortOnDropHandle::new(ctx.children.spawn(pump_h3(send, out)));
            let tunnel = Tunnel::new(H3Reader::new(recv), H3Sender::new(tx));
            tokio::select! {
                biased;
                _ = cancelled => return Err(closed()),
                result = dispatch(tunnel, config, vmess, ctx, absolute, None, Some(auth)) => result?,
            }
            return timeout(
                Duration::from_millis(ctx.limits.handshake_timeout_ms),
                writer,
            )
            .await
            .map_err(|_| auth_timeout())?
            .map_err(io::Error::other)?;
        }
        let Some(session_id) = session else {
            reject_h3(&mut stream, xhttp, StatusCode::BAD_REQUEST, absolute).await;
            return Ok(());
        };
        if seq.is_none() {
            let lane = match pool.get(&session_id) {
                Some(lane) => lane,
                None => pool.open(session_id.clone())?,
            };
            if !lane.attach_upload(auth) {
                reject_h3(&mut stream, xhttp, StatusCode::CONFLICT, absolute).await;
                return Ok(());
            }
            let cancelled = h3_cancelled(stream.quic_stream().stopped());
            drive_upload(&lane, absolute, async {
                let upload = async {
                    while let Some(mut chunk) = stream.recv_data().await.map_err(h3_error)? {
                        while chunk.has_remaining() {
                            let bytes = chunk.chunk();
                            let take = bytes.len().min(STREAM_CHUNK);
                            lane.push_with_budget(&bytes[..take]).await?;
                            chunk.advance(take);
                        }
                    }
                    Ok(())
                };
                tokio::select! {
                    biased;
                    _ = cancelled => Err(closed()),
                    result = upload => result,
                }
            })
            .await?;
            let deadline = Instant::now() + Duration::from_millis(ctx.limits.handshake_timeout_ms);
            timeout_at(deadline, finish_h3(&mut stream, xhttp))
                .await
                .map_err(|_| auth_timeout())?;
            return Ok(());
        }
        let Some(seq) = seq else {
            reject_h3(&mut stream, xhttp, StatusCode::BAD_REQUEST, absolute).await;
            return Ok(());
        };
        let cancelled = h3_cancelled(stream.quic_stream().stopped());
        let upload = async {
            let result = async {
                let mut packet = PacketBody::new(&pool.buffer_bytes, xhttp, request.headers())?;
                while let Some(chunk) = stream.recv_data().await.map_err(h3_error)? {
                    packet.append(chunk)?;
                }
                let lane = pool.open(session_id)?;
                lane.push_seq(seq, packet.chunk, packet.limit, Some(auth))
                    .await
            }
            .await;
            match result {
                Ok(()) => finish_h3(&mut stream, xhttp).await,
                Err(error) => {
                    reject_h3(&mut stream, xhttp, packet_error_status(&error)?, absolute).await
                }
            }
            Ok::<(), io::Error>(())
        };
        tokio::select! {
            biased;
            _ = cancelled => return Err(closed()),
            result = timeout_at(absolute, upload) => result.map_err(|_| auth_timeout())??,
        }
        Ok(())
    } else {
        reject_h3(&mut stream, xhttp, StatusCode::METHOD_NOT_ALLOWED, absolute).await;
        Ok(())
    }
}

/// 先写成功响应头，再结束流；用于没有响应体的上行 POST。
async fn finish_h3(stream: &mut RequestStream<BidiStream<Bytes>, Bytes>, xhttp: &Xhttp) {
    let Ok(response) = status_head(xhttp, StatusCode::OK) else {
        return;
    };
    let _ = stream.send_response(response).await;
    let _ = stream.finish().await;
}

async fn reject_h3(
    stream: &mut RequestStream<BidiStream<Bytes>, Bytes>,
    xhttp: &Xhttp,
    status: StatusCode,
    deadline: Instant,
) {
    let Ok(response) = status_head(xhttp, status) else {
        return;
    };
    let _ = timeout_at(deadline, async {
        stream.send_response(response).await?;
        stream.finish().await
    })
    .await;
}

/// 把下行字节写入 HTTP/3 响应体；通道关闭即结束流。
async fn pump_h3(
    mut send: RequestStream<H3SendStream<Bytes>, Bytes>,
    mut rx: mpsc::Receiver<Bytes>,
) -> io::Result<()> {
    while let Some(chunk) = rx.recv().await {
        send.send_data(chunk).await.map_err(h3_error)?;
    }
    send.finish().await.map_err(h3_error)
}

async fn h3_cancelled(
    stopped: impl Future<Output = Result<Option<quinn::VarInt>, quinn::StoppedError>>,
) {
    if matches!(stopped.await, Ok(None)) {
        // 正常下行 FIN 不取消仍在进行的上行。
        std::future::pending::<()>().await;
    }
}

/// HTTP/3 请求体读取器；DATA 帧本身就是原始字节，无需 chunked 解码。
pub(super) struct H3Reader {
    recv: RequestStream<H3RecvStream, Bytes>,
    current: Bytes,
    offset: usize,
}

impl H3Reader {
    pub(super) fn new(recv: RequestStream<H3RecvStream, Bytes>) -> Self {
        Self {
            recv,
            current: Bytes::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for H3Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.offset < self.current.len() {
                let take = buf.remaining().min(self.current.len() - self.offset);
                buf.put_slice(&self.current[self.offset..self.offset + take]);
                self.offset += take;
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.recv.poll_recv_data(cx)) {
                Ok(Some(mut next)) => {
                    let size = next.remaining();
                    self.current = next.copy_to_bytes(size);
                    self.offset = 0;
                }
                Ok(None) => return Poll::Ready(Ok(())),
                Err(error) => return Poll::Ready(Err(h3_error(error))),
            }
        }
    }
}

/// HTTP/3 下行写入器；实际发送由 `pump_h3` 在独立任务中完成。
struct H3Sender {
    tx: Option<PollSender<Bytes>>,
}

impl H3Sender {
    fn new(tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            tx: Some(PollSender::new(tx)),
        }
    }
}

impl AsyncWrite for H3Sender {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let Some(tx) = this.tx.as_mut() else {
            return Poll::Ready(Err(closed()));
        };
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(tx.poll_reserve(cx)).map_err(|_| closed())?;
        let take = buf.len().min(STREAM_CHUNK);
        tx.send_item(Bytes::copy_from_slice(&buf[..take]))
            .map_err(|_| closed())?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.tx = None;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn paired_auth_releases_upload_permit_before_upload_is_polled_again() {
        let xhttp = serde_json::from_str(r#"{"path":"/x"}"#).unwrap();
        let pool = Pool::new(
            &xhttp,
            &Limits::default(),
            Arc::new(Semaphore::new(4)),
            Arc::default(),
        );
        let lane = pool.open("upload".into()).unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let auth = AuthSlot::new(crate::runtime::HandshakePermits::new(
            slots.clone().try_acquire_owned().unwrap(),
            None,
        ));
        let deadline = Instant::now() + Duration::from_millis(100);
        assert!(lane.attach_upload(&auth));
        let upload = drive_upload(&lane, deadline, std::future::pending());
        tokio::pin!(upload);
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx).is_pending())).await
        );
        tokio::time::advance(Duration::from_millis(99)).await;
        lane.finish_auth();
        tokio::time::advance(Duration::from_millis(2)).await;
        // 模拟连接驱动先到期检查，上传任务未再次轮询。
        assert!(Instant::now() >= deadline);
        assert!(!auth.pending());
        assert_eq!(slots.available_permits(), 1);
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx).is_pending())).await
        );
    }

    #[tokio::test]
    async fn packet_budget_is_charged_before_buffering_and_returned_on_consumption() {
        let xhttp: Xhttp = serde_json::from_str(r#"{"path":"/x"}"#).unwrap();
        let budget = Arc::new(Semaphore::new(4));
        let pool = Pool::new(&xhttp, &Limits::default(), budget.clone(), Arc::default());
        let lane = pool.open("queue".into()).unwrap();
        let mut reader = ChannelReader::new(lane.take_reader().unwrap(), &lane);
        let mut rejected = PacketBody::new(&budget, &xhttp, &HeaderMap::new()).unwrap();
        assert!(rejected.append(&b"12345"[..]).is_err());
        assert_eq!(rejected.chunk.0.capacity(), 0);
        drop(rejected);
        let mut accepted = PacketBody::new(&budget, &xhttp, &HeaderMap::new()).unwrap();
        accepted.append(&b"data"[..]).unwrap();
        assert_eq!(budget.available_permits(), 0);
        lane.push_seq(0, accepted.chunk, accepted.limit, None)
            .await
            .unwrap();
        let mut data = [0; 4];
        reader.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"data");
        assert_eq!(budget.available_permits(), 4);
    }

    #[tokio::test]
    async fn cancelling_downlink_removes_session_and_pending_bytes() {
        let xhttp: Xhttp = serde_json::from_str(r#"{"path":"/x"}"#).unwrap();
        let budget = Arc::new(Semaphore::new(4));
        let pool = Pool::new(&xhttp, &Limits::default(), budget.clone(), Arc::default());
        let lane = pool.open("cancelled".into()).unwrap();
        lane.push_seq(1, (b"data".to_vec(), reserve(&budget, 4).unwrap()), 4, None)
            .await
            .unwrap();
        let guard = lane.claim(&pool).unwrap();
        drop(guard);
        assert!(pool.get("cancelled").is_none());
        assert_eq!(budget.available_permits(), 4);
    }

    #[tokio::test]
    async fn cancelling_packet_waiting_to_enqueue_does_not_consume_sequence() {
        let xhttp: Xhttp =
            serde_json::from_str(r#"{"path":"/x","sc_max_buffered_posts":1}"#).unwrap();
        let budget = Arc::new(Semaphore::new(4));
        let pool = Pool::new(&xhttp, &Limits::default(), budget.clone(), Arc::default());
        let lane = pool.open("waiting".into()).unwrap();
        let packet = |byte| (vec![byte], reserve(&budget, 1).unwrap());
        lane.push_seq(0, packet(b'a'), 4, None).await.unwrap();
        {
            let push = lane.push_seq(1, packet(b'x'), 4, None);
            tokio::pin!(push);
            assert!(
                std::future::poll_fn(|cx| Poll::Ready(push.as_mut().poll(cx).is_pending())).await
            );
        }
        assert_eq!(budget.available_permits(), 3);
        let mut reader = ChannelReader::new(lane.take_reader().unwrap(), &lane);
        assert_eq!(reader.read_u8().await.unwrap(), b'a');
        lane.push_seq(1, packet(b'b'), 4, None).await.unwrap();
        assert_eq!(reader.read_u8().await.unwrap(), b'b');
        assert_eq!(budget.available_permits(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_partial_enqueue_reclaims_unpaired_session() {
        let xhttp: Xhttp = serde_json::from_value(serde_json::json!({
            "path": "/x", "sc_max_buffered_posts": 1, "session_ttl_ms": 30_000
        }))
        .unwrap();
        let budget = Arc::new(Semaphore::new(4));
        let limits = Limits {
            max_xhttp_sessions: 1,
            ..Limits::default()
        };
        let pool = Pool::new(&xhttp, &limits, budget.clone(), Arc::default());
        let lane = pool.open("unpaired".into()).unwrap();
        let packet = |byte| (vec![byte], reserve(&budget, 1).unwrap());
        lane.push_seq(1, packet(b'b'), 4, None).await.unwrap();
        {
            let push = lane.push_seq(0, packet(b'a'), 4, None);
            tokio::pin!(push);
            assert!(
                std::future::poll_fn(|cx| Poll::Ready(push.as_mut().poll(cx).is_pending())).await
            );
            assert_eq!(crate::sync::locked(&lane.state).next_seq, 1);
        }
        assert_eq!(budget.available_permits(), 4);
        drop(lane);
        timeout(Duration::from_millis(500), async {
            while pool.get("unpaired").is_some() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("未配对的已关闭会话不能继续占用名额");
        assert!(pool.open("replacement".into()).is_ok());
    }

    #[tokio::test]
    async fn failed_packet_enqueue_ends_paired_downlink() {
        let id = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let config = crate::config::Config::from_json(
            &include_str!("../../examples/vless-xhttp.json")
                .replace("REPLACE_WITH_A_RANDOM_VLESS_XHTTP_UUID_BEFORE_USE", id),
        )
        .unwrap();
        let inbound = &config.inbounds[0];
        let ctx = Arc::new(Context::new(&config).unwrap());
        let mut xhttp = xhttp_config(inbound).unwrap().clone();
        xhttp.sc_max_buffered_posts = 1;
        let budget = Arc::new(Semaphore::new(128));
        let limits = Limits {
            max_xhttp_sessions: 1,
            ..Limits::default()
        };
        let pool = Pool::new(&xhttp, &limits, budget.clone(), ctx.stats.clone());
        let lane = pool.open("paired".into()).unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut request = vec![0];
        request.extend_from_slice(&crate::config::parse_uuid(id).unwrap());
        request.extend_from_slice(&[0, 1]);
        request.extend_from_slice(&target.local_addr().unwrap().port().to_be_bytes());
        request.extend_from_slice(&[1, 127, 0, 0, 1]);
        request.extend_from_slice(b"ping");
        let packet = |data: Vec<u8>| {
            let permit = reserve(&budget, data.len()).unwrap();
            (data, permit)
        };
        lane.push_seq(0, packet(request), 64, None).await.unwrap();
        let (writer, mut client) = tokio::io::duplex(64);
        let reader = ChannelReader::new(lane.take_reader().unwrap(), &lane);
        let relay = async {
            let _session = lane.claim(&pool).unwrap();
            dispatch(
                Tunnel::new(reader, writer),
                inbound,
                &None,
                &ctx,
                Instant::now() + Duration::from_secs(2),
                Some(&lane),
                None,
            )
            .await
        };
        tokio::pin!(relay);
        let ready = async {
            let (mut peer, _) = target.accept().await.unwrap();
            let mut bytes = [0; 4];
            client.read_exact(&mut bytes[..2]).await.unwrap();
            assert_eq!(&bytes[..2], b"\x00\x00");
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            peer
        };
        let _peer = tokio::select! {
            result = &mut relay => panic!("中继提前结束: {result:?}"),
            peer = timeout(Duration::from_secs(2), ready) => peer.unwrap(),
        };
        lane.push_seq(2, packet(vec![2]), 64, None).await.unwrap();
        {
            let push = lane.push_seq(1, packet(vec![1]), 64, None);
            tokio::pin!(push);
            assert!(
                std::future::poll_fn(|cx| Poll::Ready(push.as_mut().poll(cx).is_pending())).await
            );
            assert_eq!(crate::sync::locked(&lane.state).next_seq, 2);
        }
        let error = timeout(Duration::from_millis(500), relay)
            .await
            .expect("目标未主动关闭时也应结束下行")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(pool.get("paired").is_none());
        assert_eq!(ctx.stats.snapshot().tcp_flows, 0);
        assert_eq!(budget.available_permits(), 128);
    }

    #[test]
    fn head_and_meta_are_strict() {
        let config: Xhttp = serde_json::from_str(r#"{"path":"/x"}"#).unwrap();
        assert_eq!(
            extract_meta(&config, "/x/abc/3", "", &HeaderMap::new()).unwrap(),
            (Some("abc".into()), Some(3))
        );
        assert!(extract_meta(&config, "/other/abc", "", &HeaderMap::new()).is_err());
        assert!(extract_meta(&config, "/x/abc/3/9", "", &HeaderMap::new()).is_err());
        assert!(extract_meta(&config, "/x/abc/notnum", "", &HeaderMap::new()).is_err());
    }

    #[test]
    fn padding_accepts_empty_and_rejects_oversize() {
        let config: Xhttp = serde_json::from_str(r#"{"path":"/x"}"#).unwrap();
        assert!(padding(&config, "", &HeaderMap::new()).is_ok());
        let small = URL_SAFE_NO_PAD.encode([0u8; 128]);
        assert!(padding(&config, &format!("x_padding={small}"), &HeaderMap::new()).is_ok());
        let large = URL_SAFE_NO_PAD.encode([0u8; 2_000]);
        assert!(padding(&config, &format!("x_padding={large}"), &HeaderMap::new()).is_err());
    }
}
