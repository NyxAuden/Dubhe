//! HTTP/2客户端发送屏障：观察Buf消耗和底层flush，不把入队或PING当作排空。
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use std::{
    future::poll_fn,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub(super) struct H2Progress {
    pub(super) submitted: AtomicU64,
    consumed: AtomicU64,
    pub(super) flushed: AtomicU64,
    pub(super) waker: AtomicWaker,
    pub(super) driver_waker: AtomicWaker,
}
pub(super) struct H2Data {
    bytes: Bytes,
    ticket: u64,
    progress: Arc<H2Progress>,
}
impl H2Data {
    pub(super) fn new(bytes: Bytes, progress: &Arc<H2Progress>) -> Self {
        let ticket = progress.submitted.fetch_add(1, Ordering::SeqCst) + 1;
        Self {
            bytes,
            ticket,
            progress: progress.clone(),
        }
    }
    fn consumed(&self) {
        self.progress
            .consumed
            .fetch_max(self.ticket, Ordering::SeqCst);
        self.progress.waker.wake();
        self.progress.driver_waker.wake();
    }
}
impl Buf for H2Data {
    fn remaining(&self) -> usize {
        self.bytes.remaining()
    }
    fn chunk(&self) -> &[u8] {
        self.bytes.chunk()
    }
    fn advance(&mut self, count: usize) {
        self.bytes.advance(count);
        if self.bytes.is_empty() {
            self.consumed();
        }
    }
}
impl Drop for H2Data {
    fn drop(&mut self) {
        // 零长度END_STREAM没有advance，直到codec释放帧后才确认其被处理。
        if self.bytes.is_empty() {
            self.consumed();
        }
    }
}
/// 从Naive抽取的实际发送屏障，专属流发送者串行调用。
pub(super) async fn flush(progress: &H2Progress) -> io::Result<()> {
    let target = progress.submitted.load(Ordering::SeqCst);
    poll_fn(|cx| {
        progress.waker.register(cx.waker());
        if progress.flushed.load(Ordering::SeqCst) >= target {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await
}

pub(super) async fn send(
    send: &mut h2::SendStream<H2Data>,
    bytes: Bytes,
    progress: &Arc<H2Progress>,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if send.capacity() == 0 {
            send.reserve_capacity(remaining);
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(0)) => continue,
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(io::Error::other(error)),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "HTTP/2发送流已关闭",
                    ));
                }
            }
        }
        let take = send.capacity().min(remaining).min(16 * 1024);
        if take == 0 {
            continue;
        }
        send.send_data(
            H2Data::new(bytes.slice(offset..offset + take), progress),
            false,
        )
        .map_err(io::Error::other)?;
        offset += take;
    }
    flush(progress).await
}

pub(super) struct FlushIo<S> {
    pub(super) inner: S,
    pub(super) progress: Arc<H2Progress>,
}
impl<S: AsyncRead + Unpin> AsyncRead for FlushIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for FlushIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 在flush之前快照，不能确认并发刚进入codec的数据。
        let consumed = self.progress.consumed.load(Ordering::SeqCst);
        std::task::ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        self.progress.flushed.fetch_max(consumed, Ordering::SeqCst);
        self.progress.waker.wake();
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
