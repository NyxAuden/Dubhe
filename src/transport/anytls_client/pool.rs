//! 固定上游的空闲会话池与正式ID分派，不把忙会话选择改成新的并发调度策略。
use super::*;
use crate::sync::poisoned;
use crate::{config::AnyTlsClientOptions, forward::Upstream};
use futures_util::task::AtomicWaker;
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Mutex, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, oneshot, watch},
    time::{Duration, Instant, timeout},
};
use tokio_util::{
    sync::{CancellationToken, PollSender},
    task::TaskTracker,
};

const CACHE: usize = 64;
const STREAMS: usize = 64;
const READ_QUEUE: usize = 4;
const WRITE_QUEUE: usize = 64;
const OPEN_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct Failure {
    kind: io::ErrorKind,
    message: &'static str,
}
impl Failure {
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message)
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS会话或流已关闭")
}

pub(crate) struct Pool {
    options: AnyTlsClientOptions,
    schemes: Arc<SharedScheme>,
    state: Mutex<PoolState>,
    retired: CancellationToken,
    cleaner_started: AtomicBool,
}
#[derive(Default)]
struct PoolState {
    idle: Vec<Arc<Session>>,
    sessions: Vec<Weak<Session>>,
}
impl Pool {
    pub(crate) fn new(options: AnyTlsClientOptions, schemes: Arc<SharedScheme>) -> Self {
        Self {
            options,
            schemes,
            state: Mutex::new(PoolState::default()),
            retired: CancellationToken::new(),
            cleaner_started: AtomicBool::new(false),
        }
    }
    pub(crate) fn close(&self) {
        self.retired.cancel();
        let sessions = {
            let mut state = self.state.lock().unwrap_or_else(poisoned);
            let sessions = state
                .sessions
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            state.idle.clear();
            sessions
        };
        for session in sessions {
            session.retire();
        }
    }
    fn take(&self) -> Option<Arc<Session>> {
        let mut state = self.state.lock().unwrap_or_else(poisoned);
        while let Some(session) = state.idle.pop() {
            if !session.cancel.is_cancelled() && !session.draining.load(Ordering::Acquire) {
                return Some(session);
            }
        }
        None
    }
    fn release(&self, session: Arc<Session>) {
        if self.options.disable_reuse
            || self.retired.is_cancelled()
            || session.draining.load(Ordering::Acquire)
        {
            session.retire();
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(poisoned);
        if session.cancel.is_cancelled() {
            return;
        }
        if self.retired.is_cancelled() {
            drop(state);
            session.retire();
            return;
        }
        if state.idle.iter().any(|old| Arc::ptr_eq(old, &session)) {
            return;
        }
        state.idle.retain(|old| !old.cancel.is_cancelled());
        if state.idle.len() >= CACHE {
            drop(state);
            session.retire();
            return;
        }
        *session.idle_since.lock().unwrap_or_else(poisoned) = Instant::now();
        state.idle.push(session);
    }
    fn clean(&self) {
        let mut state = self.state.lock().unwrap_or_else(poisoned);
        state.sessions.retain(|weak| weak.strong_count() > 0);
        let mut kept = 0;
        let mut expired = Vec::new();
        // 最新空闲优先；min_idle只保留已有会话，不主动拨号。
        for session in state.idle.iter().rev() {
            if session.cancel.is_cancelled() {
                continue;
            }
            let fresh = session.idle_since.lock().unwrap_or_else(poisoned).elapsed()
                < Duration::from_millis(self.options.idle_session_timeout_ms);
            if fresh || session.has_streams() || kept < self.options.min_idle_session {
                kept += 1;
            } else {
                expired.push(session.clone());
            }
        }
        state
            .idle
            .retain(|s| !s.cancel.is_cancelled() && !expired.iter().any(|old| Arc::ptr_eq(old, s)));
        drop(state);
        for session in expired {
            session.retire();
        }
    }
    fn cleaner(self: &Arc<Self>, tracker: &TaskTracker, stop: CancellationToken) {
        if self.cleaner_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        let retired = self.retired.clone();
        let interval = Duration::from_millis(self.options.idle_session_check_interval_ms);
        tracker.spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop { tokio::select! { biased;
                _ = retired.cancelled() => break,
                _ = stop.cancelled() => { if let Some(pool)=weak.upgrade(){pool.close();} break; },
                _ = tick.tick() => { let Some(pool)=weak.upgrade() else {break}; pool.clean(); }
            }}
        });
    }
    pub(crate) fn connect<'a, F, Fut>(
        self: &'a Arc<Self>,
        password: &'a str,
        target: &'a Target,
        tracker: TaskTracker,
        stop: CancellationToken,
        wait: Duration,
        open: F,
    ) -> Pin<Box<dyn Future<Output = io::Result<Upstream>> + Send + 'a>>
    where
        F: FnOnce() -> Fut + Send + 'a,
        Fut: Future<Output = io::Result<Upstream>> + Send + 'a,
    {
        Box::pin(async move {
            let destination = address(target)?;
            if self.retired.is_cancelled() || stop.is_cancelled() {
                return Err(closed());
            }
            let operation = async {
                let session = if let Some(session) = self.take() {
                    session
                } else {
                    let wire = open().await?;
                    Session::create(wire, password, self, &tracker, stop.clone(), wait).await?
                };
                let mut guard = OpeningGuard(Some(session.clone()));
                let flow = session.open(destination).await?;
                guard.0.take();
                Ok(Upstream::new_send(flow, session.local))
            };
            let result = tokio::select! { biased;
                _=self.retired.cancelled()=>Err(closed()),
                _=stop.cancelled()=>Err(closed()),
                result=operation=>result,
            };
            if result.is_ok() {
                self.cleaner(&tracker, stop);
            }
            result
        })
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.close();
    }
}
struct OpeningGuard(Option<Arc<Session>>);
impl Drop for OpeningGuard {
    fn drop(&mut self) {
        if let Some(session) = self.0.take() {
            session.fail(io::ErrorKind::ConnectionAborted, "AnyTLS建流取消或失败");
        }
    }
}

struct Session {
    tx: mpsc::Sender<Write>,
    core: Mutex<Core>,
    failure: Mutex<Option<Failure>>,
    cancel: CancellationToken,
    draining: AtomicBool,
    peer_version: AtomicU32,
    watchdog: watch::Sender<Option<Instant>>,
    idle_since: Mutex<Instant>,
    pool: Weak<Pool>,
    local: Option<std::net::SocketAddr>,
}
#[derive(Default)]
struct Core {
    next_id: u32,
    streams: HashMap<u32, Handle>,
}
#[derive(Clone)]
struct Handle {
    data: mpsc::Sender<Vec<u8>>,
    state: Arc<FlowState>,
}
struct FlowState {
    failure: Mutex<Option<Failure>>,
    peer_fin: AtomicBool,
    local_closed: AtomicBool,
    fin_sent: AtomicBool,
    /// 已接受而未实际flush完成的业务批次；peer FIN丢弃批次不能算作发送完成。
    unflushed: AtomicUsize,
    closed: CancellationToken,
    reader: AtomicWaker,
    writer: AtomicWaker,
}
impl Default for FlowState {
    fn default() -> Self {
        Self {
            failure: Mutex::new(None),
            peer_fin: AtomicBool::new(false),
            local_closed: AtomicBool::new(false),
            fin_sent: AtomicBool::new(false),
            unflushed: AtomicUsize::new(0),
            closed: CancellationToken::new(),
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
        }
    }
}
impl FlowState {
    fn error(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap_or_else(poisoned)
            .as_ref()
            .map(Failure::error)
    }
    fn fail(&self, kind: io::ErrorKind, message: &'static str) {
        let mut error = self.failure.lock().unwrap_or_else(poisoned);
        if error.is_none() {
            *error = Some(Failure { kind, message });
        }
        drop(error);
        self.end();
    }
    fn end(&self) {
        self.closed.cancel();
        self.reader.wake();
        self.writer.wake();
    }
}
impl Session {
    fn error(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap_or_else(poisoned)
            .as_ref()
            .map(Failure::error)
    }
    fn has_streams(&self) -> bool {
        !self.core.lock().unwrap_or_else(poisoned).streams.is_empty()
    }
    fn fail(&self, kind: io::ErrorKind, message: &'static str) {
        let mut error = self.failure.lock().unwrap_or_else(poisoned);
        if error.is_none() {
            *error = Some(Failure { kind, message });
        }
        drop(error);
        self.cancel.cancel();
        let streams = std::mem::take(&mut self.core.lock().unwrap_or_else(poisoned).streams);
        for handle in streams.into_values() {
            handle.state.fail(kind, message);
        }
    }
    fn retire(&self) {
        self.draining.store(true, Ordering::Release);
        if !self.has_streams() {
            self.cancel.cancel();
        }
    }
    fn release(self: &Arc<Self>) {
        if self.draining.load(Ordering::Acquire) {
            self.retire();
            return;
        }
        if let Some(pool) = self.pool.upgrade() {
            pool.release(self.clone());
        } else {
            self.retire();
        }
    }
    fn remove(self: &Arc<Self>, id: u32) {
        let removed = self
            .core
            .lock()
            .unwrap_or_else(poisoned)
            .streams
            .remove(&id);
        // 迟到/重复Close不能把已经再次借出的会话误放回空闲池。
        if removed.is_some() {
            self.release();
        }
    }
    async fn create(
        mut wire: Upstream,
        password: &str,
        pool: &Arc<Pool>,
        tracker: &TaskTracker,
        stop: CancellationToken,
        wait: Duration,
    ) -> io::Result<Arc<Self>> {
        let local = wire.local_addr().ok();
        let scheme = pool.schemes.snapshot();
        wire.write_all(&prologue(password, &scheme)?).await?;
        let settings = settings(&scheme)?;
        let (read, write) = tokio::io::split(wire);
        let (tx, rx) = mpsc::channel(WRITE_QUEUE);
        let (watchdog, watch) = watch::channel(None);
        let session = Arc::new(Self {
            tx,
            core: Mutex::new(Core::default()),
            failure: Mutex::new(None),
            cancel: CancellationToken::new(),
            draining: AtomicBool::new(false),
            peer_version: AtomicU32::new(0),
            watchdog,
            idle_since: Mutex::new(Instant::now()),
            pool: Arc::downgrade(pool),
            local,
        });
        {
            let mut state = pool.state.lock().unwrap_or_else(poisoned);
            state.sessions.retain(|weak| weak.strong_count() > 0);
            state.sessions.push(Arc::downgrade(&session));
        }
        spawn(
            tracker,
            &session,
            stop.clone(),
            read_loop(read, session.clone(), pool.schemes.clone(), wait),
        );
        spawn(
            tracker,
            &session,
            stop.clone(),
            write_loop(
                write,
                rx,
                session.clone(),
                pool.schemes.clone(),
                settings,
                wait,
            ),
        );
        spawn(tracker, &session, stop, watchdog_loop(watch));
        Ok(session)
    }
    async fn open(self: &Arc<Self>, destination: Vec<u8>) -> io::Result<Flow> {
        let (state, rx, id) = {
            let mut core = self.core.lock().unwrap_or_else(poisoned);
            if self.cancel.is_cancelled() || self.draining.load(Ordering::Acquire) {
                return Err(closed());
            }
            if core.streams.len() >= STREAMS {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "AnyTLS会话流上限",
                ));
            }
            let Some(id) = core.next_id.checked_add(1) else {
                drop(core);
                self.retire();
                return Err(closed());
            };
            core.next_id = id;
            let (data, rx) = mpsc::channel(READ_QUEUE);
            let state = Arc::new(FlowState::default());
            core.streams.insert(
                id,
                Handle {
                    data,
                    state: state.clone(),
                },
            );
            (state, rx, id)
        };
        let mut first = frame(COMMAND_SYN, id, &[])?;
        first.extend(frame(COMMAND_PSH, id, &destination)?);
        let (tx, ack) = oneshot::channel();
        self.tx
            .send(Write::Open {
                id,
                bytes: first,
                ack: tx,
            })
            .await
            .map_err(|_| closed())?;
        ack.await
            .map_err(|_| self.error().unwrap_or_else(closed))??;
        if self.cancel.is_cancelled() {
            return Err(self.error().unwrap_or_else(closed));
        }
        Ok(Flow {
            session: self.clone(),
            state,
            id,
            rx,
            current: Vec::new(),
            offset: 0,
            tx: PollSender::new(self.tx.clone()),
            pending: None,
            closing: false,
            close_queued: false,
            shutdown_done: false,
        })
    }
}
fn spawn(
    tracker: &TaskTracker,
    session: &Arc<Session>,
    stop: CancellationToken,
    task: impl Future<Output = io::Result<()>> + Send + 'static,
) {
    let session = session.clone();
    tracker.spawn(async move{
        tokio::select!{biased;
            _=session.cancel.cancelled()=>{},
            _=stop.cancelled()=>session.fail(io::ErrorKind::ConnectionAborted,"AnyTLS实例已停止"),
            result=task=>{if let Err(error)=result{session.fail(error.kind(),"AnyTLS会话传输或帧处理失败");}},
        }
    });
}
async fn watchdog_loop(mut watch: watch::Receiver<Option<Instant>>) -> io::Result<()> {
    loop {
        let deadline = *watch.borrow_and_update();
        if let Some(deadline) = deadline {
            tokio::select! { biased;
                result=watch.changed()=>result.map_err(|_|closed())?,
                _=tokio::time::sleep_until(deadline)=>return Err(io::Error::new(io::ErrorKind::TimedOut,"AnyTLS复用开流超时")),
            }
        } else {
            watch.changed().await.map_err(|_| closed())?;
        }
    }
}
/// 读任务拥有控制帧，暂满时保持有界背压；外层spawn仍负责会话/实例取消。
async fn enqueue_control(session: &Session, command: Write, wait: Duration) -> io::Result<()> {
    timeout(wait, session.tx.send(command))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS控制队列等待超时"))?
        .map_err(|_| closed())
}

async fn read_loop(
    mut read: tokio::io::ReadHalf<Upstream>,
    session: Arc<Session>,
    schemes: Arc<SharedScheme>,
    wait: Duration,
) -> io::Result<()> {
    loop {
        let mut header = [0; FRAME_OVERHEAD];
        read.read_exact(&mut header).await?;
        session.watchdog.send_replace(None); // 固定上游在完整帧头到达时解除复用开流看门狗。
        let command = header[0];
        let id = u32::from_be_bytes(header[1..5].try_into().expect("固定头长度"));
        let mut payload = vec![0; u16::from_be_bytes([header[5], header[6]]) as usize];
        read.read_exact(&mut payload).await?;
        match command {
            COMMAND_PSH if !payload.is_empty() => {
                let handle = session
                    .core
                    .lock()
                    .unwrap_or_else(poisoned)
                    .streams
                    .get(&id)
                    .cloned();
                if let Some(handle) = handle {
                    tokio::select! {biased;_=handle.state.closed.cancelled()=>{},
                    result=handle.data.send(payload)=>{if result.is_err(){handle.state.end();}}}
                }
            }
            COMMAND_FIN => {
                let handle = session
                    .core
                    .lock()
                    .unwrap_or_else(poisoned)
                    .streams
                    .remove(&id);
                if let Some(handle) = handle {
                    handle.state.peer_fin.store(true, Ordering::Release);
                    handle.state.end();
                    session.release();
                }
            }
            COMMAND_SYNACK if !payload.is_empty() => {
                let handle = session
                    .core
                    .lock()
                    .unwrap_or_else(poisoned)
                    .streams
                    .get(&id)
                    .cloned();
                if let Some(handle) = handle {
                    handle
                        .state
                        .fail(io::ErrorKind::ConnectionRefused, "AnyTLS上游拒绝目标");
                    enqueue_control(
                        &session,
                        Write::Close {
                            id,
                            state: handle.state,
                            ack: None,
                        },
                        wait,
                    )
                    .await?;
                }
            }
            COMMAND_SERVER_SETTINGS => {
                if let Ok(text) = std::str::from_utf8(&payload)
                    && let Some(version) = text
                        .split('\n')
                        .filter_map(|line| line.split_once('='))
                        .filter(|(key, _)| *key == "v")
                        .next_back()
                        .and_then(|(_, v)| v.parse::<u32>().ok())
                        .filter(|v| *v > 0)
                {
                    session.peer_version.store(version, Ordering::Release);
                }
            }
            COMMAND_UPDATE_PADDING_SCHEME => {
                schemes.update(&payload);
            }
            COMMAND_HEART_REQUEST => {
                enqueue_control(&session, Write::Heart(id), wait).await?;
            }
            COMMAND_ALERT if !payload.is_empty() => return Err(closed()),
            _ => {}
        }
    }
}
enum Write {
    Open {
        id: u32,
        bytes: Vec<u8>,
        ack: oneshot::Sender<io::Result<()>>,
    },
    Data {
        id: u32,
        state: Arc<FlowState>,
        bytes: Vec<u8>,
    },
    Flush {
        state: Arc<FlowState>,
        ack: oneshot::Sender<io::Result<()>>,
    },
    Close {
        id: u32,
        state: Arc<FlowState>,
        ack: Option<oneshot::Sender<io::Result<()>>>,
    },
    Heart(u32),
}
async fn write_blocks<W>(
    write: &mut W,
    padding: &mut PaddingState,
    schemes: &SharedScheme,
    bytes: &[u8],
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    // 顺序有讲究：先校验长度（与 `shape` 的拒绝条件一致），再判断是否已停止
    // 塑形，最后才可能去读共享方案快照。停止之后不再加填充，`shape` 只会
    // 原样复制；此时直接写原切片，每 1 GiB 业务载荷省下约 1 GiB 复制和
    // 每个 PSH 一次分配。
    PaddingState::validate(bytes)?;
    if padding.is_stopped() {
        write.write_all(bytes).await?;
        return write.flush().await;
    }
    for block in padding.shape(bytes, &schemes.snapshot())? {
        write.write_all(&block).await?;
    }
    write.flush().await
}
async fn write_loop(
    mut write: tokio::io::WriteHalf<Upstream>,
    mut rx: mpsc::Receiver<Write>,
    session: Arc<Session>,
    schemes: Arc<SharedScheme>,
    settings: Vec<u8>,
    wait: Duration,
) -> io::Result<()> {
    let mut pending = Some(settings);
    let mut padding = PaddingState::default();
    while let Some(item) = rx.recv().await {
        timeout(wait, async {
            match item {
                Write::Open { id, bytes, ack } => {
                    if id >= 2 && session.peer_version.load(Ordering::Acquire) >= 2 {
                        session
                            .watchdog
                            .send_replace(Some(Instant::now() + OPEN_TIMEOUT));
                    }
                    let bytes = if let Some(mut first) = pending.take() {
                        first.extend(bytes);
                        first
                    } else {
                        bytes
                    };
                    write_blocks(&mut write, &mut padding, &schemes, &bytes).await?;
                    let _ = ack.send(Ok(()));
                }
                Write::Data { id, state, bytes } => {
                    if !state.peer_fin.load(Ordering::Acquire) && state.error().is_none() {
                        write_blocks(
                            &mut write,
                            &mut padding,
                            &schemes,
                            &frame(COMMAND_PSH, id, &bytes)?,
                        )
                        .await?;
                        state.unflushed.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                Write::Flush { state, ack } => {
                    if let Some(error) = state.error() {
                        let _ = ack.send(Err(error));
                    } else if state.peer_fin.load(Ordering::Acquire) {
                        // 对端整流关闭可跳过尚未发出的PSH，不能再以成功flush确认已发送。
                        let _ = ack.send(Err(closed()));
                    } else {
                        write.flush().await?;
                        let _ = ack.send(Ok(()));
                    }
                }
                Write::Close { id, state, ack } => {
                    if !state.peer_fin.load(Ordering::Acquire)
                        && !state.fin_sent.swap(true, Ordering::AcqRel)
                    {
                        write_blocks(
                            &mut write,
                            &mut padding,
                            &schemes,
                            &frame(COMMAND_FIN, id, &[])?,
                        )
                        .await?;
                    }
                    session.remove(id);
                    if let Some(ack) = ack {
                        let result = if state.unflushed.load(Ordering::Acquire) == 0 {
                            Ok(())
                        } else {
                            Err(closed())
                        };
                        let _ = ack.send(result);
                    }
                }
                Write::Heart(id) => {
                    write_blocks(
                        &mut write,
                        &mut padding,
                        &schemes,
                        &frame(COMMAND_HEART_RESPONSE, id, &[])?,
                    )
                    .await?
                }
            }
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS会话写超时"))??;
    }
    Ok(())
}

struct Flow {
    session: Arc<Session>,
    state: Arc<FlowState>,
    id: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
    tx: PollSender<Write>,
    pending: Option<oneshot::Receiver<io::Result<()>>>,
    closing: bool,
    close_queued: bool,
    shutdown_done: bool,
}
impl Flow {
    fn error(&self) -> Option<io::Error> {
        self.state.error().or_else(|| {
            // peer FIN已结束这个ID；随后整个TLS会话关闭不能抹掉已排队PSH或改写EOF。
            if self.state.peer_fin.load(Ordering::Acquire) {
                None
            } else {
                self.session.error()
            }
        })
    }
    fn barrier(&mut self, cx: &mut Context<'_>, close: bool) -> Poll<io::Result<()>> {
        self.state.writer.register(cx.waker());
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_none() {
            ready!(self.tx.poll_reserve(cx)).map_err(|_| closed())?;
            let (tx, rx) = oneshot::channel();
            let item = if close {
                self.close_queued = true;
                Write::Close {
                    id: self.id,
                    state: self.state.clone(),
                    ack: Some(tx),
                }
            } else {
                Write::Flush {
                    state: self.state.clone(),
                    ack: tx,
                }
            };
            self.tx.send_item(item).map_err(|_| closed())?;
            self.closing = close;
            self.pending = Some(rx);
        }
        let result = ready!(Pin::new(self.pending.as_mut().expect("屏障已创建")).poll(cx));
        self.pending = None;
        result.map_err(|_| self.error().unwrap_or_else(closed))??;
        if self.closing {
            self.shutdown_done = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Flow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.state.reader.register(cx.waker());
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        if self.state.local_closed.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.offset < self.current.len() {
                let count = (self.current.len() - self.offset).min(out.remaining());
                out.put_slice(&self.current[self.offset..self.offset + count]);
                self.offset += count;
                return Poll::Ready(Ok(()));
            }
            match ready!(self.rx.poll_recv(cx)) {
                Some(bytes) => {
                    self.current = bytes;
                    self.offset = 0;
                }
                None => {
                    return Poll::Ready(if self.state.peer_fin.load(Ordering::Acquire) {
                        Ok(())
                    } else {
                        Err(self.error().unwrap_or_else(closed))
                    });
                }
            }
        }
    }
}
impl AsyncWrite for Flow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.state.writer.register(cx.waker());
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        if self.state.local_closed.load(Ordering::Acquire)
            || self.state.peer_fin.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(closed()));
        }
        if self.pending.is_some() {
            ready!(self.barrier(cx, false))?;
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.tx.poll_reserve(cx)).map_err(|_| closed())?;
        let count = bytes.len().min(MAX_FRAME);
        let item = Write::Data {
            id: self.id,
            state: self.state.clone(),
            bytes: bytes[..count].to_vec(),
        };
        self.state.unflushed.fetch_add(1, Ordering::AcqRel);
        if self.tx.send_item(item).is_err() {
            self.state.unflushed.fetch_sub(1, Ordering::AcqRel);
            return Poll::Ready(Err(closed()));
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.barrier(cx, false)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        self.state.local_closed.store(true, Ordering::Release);
        self.state.end();
        if self.state.peer_fin.load(Ordering::Acquire) {
            // 对端整流结束不代表本地已接受批次/flush得到确认；不能跳过取消的屏障。
            if self.state.unflushed.load(Ordering::Acquire) != 0 || self.pending.is_some() {
                return Poll::Ready(Err(closed()));
            }
            self.shutdown_done = true;
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_some() {
            ready!(self.barrier(cx, false))?;
        }
        self.barrier(cx, true)
    }
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.state.local_closed.store(true, Ordering::Release);
        self.state.end();
        // 取消poll_reserve可能由本租借占住队列额度，先释放再尝试排入标准FIN。
        self.tx.abort_send();
        if !self.close_queued
            && !self.state.peer_fin.load(Ordering::Acquire)
            && !self.session.cancel.is_cancelled()
            && self
                .session
                .tx
                .try_send(Write::Close {
                    id: self.id,
                    state: self.state.clone(),
                    ack: None,
                })
                .is_err()
        {
            self.session.fail(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS关闭队列已满，结束会话",
            );
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod stopped_write_tests {
    use super::*;
    use std::task::{Poll, Waker};

    /// 收集写入的字节数，不做真实 I/O。
    struct Recorder {
        bytes: usize,
        writes: usize,
    }

    impl tokio::io::AsyncWrite for Recorder {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.bytes += buf.len();
            self.writes += 1;
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_to_ready(future: impl std::future::Future<Output = io::Result<()>>) -> io::Result<()> {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(result) => result,
            // 本测试用的 sink 永远不 Pending，走到这里说明实现有额外等待。
            Poll::Pending => panic!("Recorder 不应返回 Pending"),
        }
    }

    /// 停止塑形后，满帧载荷不应再被整份复制。
    ///
    /// `shape` 在停止状态下返回 `vec![data.to_vec()]`——每 GiB 业务载荷就是
    /// 一次整份复制。快路径直接写原切片，分配次数必须显著低于塑形路径。
    #[test]
    fn stopped_path_copies_far_less_than_shaping_path() {
        // 默认方案 `stop=8`：喂 8 个小包即跨过停止点。
        let shared = SharedScheme::default();
        // 上限是 MAX_FRAME + 1024；取 MAX_FRAME 本身，仍是最大的单帧。
        let payload = vec![0x5au8; crate::transport::anytls_padding::MAX_FRAME];

        let mut stopped = PaddingState::default();
        let mut sink = Recorder {
            bytes: 0,
            writes: 0,
        };
        for _ in 0..8 {
            poll_to_ready(write_blocks(&mut sink, &mut stopped, &shared, b"x")).unwrap();
        }
        assert!(stopped.is_stopped(), "喂满 stop 后应处于停止状态");

        // 停止后的满帧：快路径。写出字节必须**恰好**等于输入，不再有 Waste。
        let before = sink.bytes;
        let ((), fast_allocs, _) = crate::alloc_count::measure(|| {
            poll_to_ready(write_blocks(&mut sink, &mut stopped, &shared, &payload)).unwrap();
        });
        assert_eq!(
            sink.bytes - before,
            payload.len(),
            "快路径不得添加任何填充字节"
        );

        // 对照：全新状态下同样的 1 MiB 要走完整塑形。
        let mut shaping = PaddingState::default();
        let ((), shaping_allocs, _) = crate::alloc_count::measure(|| {
            poll_to_ready(write_blocks(&mut sink, &mut shaping, &shared, &payload)).unwrap();
        });

        assert!(
            fast_allocs < shaping_allocs,
            "快路径分配应少于塑形路径：快 {fast_allocs}，塑形 {shaping_allocs}"
        );
        assert!(
            fast_allocs <= 8,
            "快路径不应随载荷大小分配：实际 {fast_allocs} 次"
        );
        let _ = shaping_allocs;
    }
}
