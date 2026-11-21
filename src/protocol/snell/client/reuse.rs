//! Snell正式TCP顺序连接池；活流只持弱引用，不与空闲池形成所有权环。
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Duration, Instant, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::*;

const POOL_SIZE: usize = 10;
const POOL_MAX_AGE: Duration = Duration::from_secs(180);
const TIMER_INTERVAL: Duration = Duration::from_secs(20);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const DISCARD_LIMIT: usize = 0x80001;

pub(crate) struct Pool {
    ready: Mutex<VecDeque<Entry>>,
    slots: Arc<Semaphore>,
    closed: CancellationToken,
    cleaner_started: AtomicBool,
}
struct Entry {
    stream: ClientStream,
    local: Option<SocketAddr>,
    returned: Instant,
    _slot: OwnedSemaphorePermit,
}
impl Default for Pool {
    fn default() -> Self {
        Self {
            ready: Mutex::new(VecDeque::new()),
            slots: Arc::new(Semaphore::new(POOL_SIZE)),
            closed: CancellationToken::new(),
            cleaner_started: AtomicBool::new(false),
        }
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}
impl Pool {
    /// 热替换使旧池失效，但活跃租借不监听此信号，已交付业务继续完成。
    pub(crate) fn close(&self) {
        self.closed.cancel();
        self.ready
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    fn take(&self) -> Option<Entry> {
        let mut ready = self.ready.lock().unwrap_or_else(|error| error.into_inner());
        ready.retain(|entry| entry.returned.elapsed() < POOL_MAX_AGE);
        ready.pop_front()
    }
    fn put(&self, entry: Entry, stop: &CancellationToken) {
        let mut ready = self.ready.lock().unwrap_or_else(|error| error.into_inner());
        if !self.closed.is_cancelled() && !stop.is_cancelled() {
            ready.push_back(entry);
        }
    }
    fn start_cleaner(self: &Arc<Self>, tracker: &TaskTracker, stop: &CancellationToken) {
        if self.cleaner_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        let closed = self.closed.clone();
        let stop = stop.clone();
        tracker.spawn(async move {
            let mut ticks = tokio::time::interval(TIMER_INTERVAL);
            loop {
                tokio::select! {
                    biased;
                    _ = closed.cancelled() => break,
                    _ = stop.cancelled() => {
                        if let Some(pool) = weak.upgrade() {
                            pool.ready.lock().unwrap_or_else(|error| error.into_inner()).clear();
                        }
                        break;
                    }
                    _ = ticks.tick() => {
                        let Some(pool) = weak.upgrade() else { break };
                        pool.ready.lock().unwrap_or_else(|error| error.into_inner())
                            .retain(|entry| entry.returned.elapsed() < POOL_MAX_AGE);
                    }
                }
            }
        });
    }

    /// 取池在open之前，根出站和via的中间跳共用；建连取消时流还未获得回池资格。
    pub(crate) fn connect<'a, F, Fut>(
        self: &'a Arc<Self>,
        options: &'a SnellClientOptions,
        target: &'a Target,
        tracker: TaskTracker,
        stop: CancellationToken,
        open: F,
    ) -> Pin<Box<dyn Future<Output = io::Result<Upstream>> + Send + 'a>>
    where
        F: FnOnce() -> Fut + Send + 'a,
        Fut: Future<Output = io::Result<Upstream>> + Send + 'a,
    {
        Box::pin(async move {
            let operation = async {
                let (stream, local) = if let Some(entry) = self.take() {
                    let Entry {
                        mut stream, local, ..
                    } = entry;
                    stream.restart(options, target).await?;
                    (stream, local)
                } else {
                    let wire = open().await?;
                    let local = wire.local_addr().ok();
                    (super::connect(wire, options, target).await?, local)
                };
                Ok::<_, io::Error>((stream, local))
            };
            let (stream, local) = tokio::select! {
                biased;
                _ = stop.cancelled() => return Err(closed_error()),
                _ = self.closed.cancelled() => return Err(closed_error()),
                result = operation => result?,
            };
            if stop.is_cancelled() || self.closed.is_cancelled() {
                return Err(closed_error());
            }
            self.start_cleaner(&tracker, &stop);
            let lease = Lease {
                inner: Some(stream),
                pool: Arc::downgrade(self),
                local,
                tracker,
                stop,
            };
            Ok(Upstream::new_send(lease, local))
        })
    }
}
fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "Snell连接池已停止")
}

struct Lease {
    inner: Option<ClientStream>,
    pool: Weak<Pool>,
    local: Option<SocketAddr>,
    tracker: TaskTracker,
    stop: CancellationToken,
}
impl AsyncRead for Lease {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.inner.as_mut().expect("活跃租借持有流")).poll_read(cx, out)
    }
}
impl AsyncWrite for Lease {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.inner.as_mut().expect("活跃租借持有流")).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.inner.as_mut().expect("活跃租借持有流")).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.inner.as_mut().expect("活跃租借持有流")).poll_shutdown(cx)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let Some(stream) = self.inner.take() else {
            return;
        };
        if !stream.reply_read || stream.failure.is_some() || self.stop.is_cancelled() {
            return;
        }
        let Some(pool) = self.pool.upgrade() else {
            return;
        };
        if pool.closed.is_cancelled() {
            return;
        }
        let Ok(slot) = pool.slots.clone().try_acquire_owned() else {
            return;
        };
        let local = self.local;
        if stream.read_eof && stream.shutdown_done {
            pool.put(
                Entry {
                    stream,
                    local,
                    returned: Instant::now(),
                    _slot: slot,
                },
                &self.stop,
            );
            return;
        }
        let weak = self.pool.clone();
        let closed = pool.closed.clone();
        let stop = self.stop.clone();
        // 不在任务里持有Pool/Context；半记录由原ClientStream的future继续拥有。
        self.tracker.spawn(async move {
            let result = tokio::select! {
                biased;
                _ = closed.cancelled() => return,
                _ = stop.cancelled() => return,
                result = timeout(DRAIN_TIMEOUT, drain(stream)) => result,
            };
            if let Ok(Ok(stream)) = result
                && let Some(pool) = weak.upgrade()
            {
                pool.put(
                    Entry {
                        stream,
                        local,
                        returned: Instant::now(),
                        _slot: slot,
                    },
                    &stop,
                );
            }
        });
    }
}
async fn drain(mut stream: ClientStream) -> io::Result<ClientStream> {
    stream.shutdown().await?;
    let mut discarded = 0usize;
    let mut bytes = [0; 16 * 1024];
    loop {
        let count = stream.read(&mut bytes).await?;
        if count == 0 {
            if !stream.read_eof || !stream.shutdown_done || !stream.reply_read {
                return Err(invalid("Snell回池前逻辑流未结束"));
            }
            return Ok(stream);
        }
        discarded += count;
        if discarded >= DISCARD_LIMIT {
            return Err(invalid("Snell回池排空超过上限"));
        }
    }
}

#[cfg(test)]
mod tests;
