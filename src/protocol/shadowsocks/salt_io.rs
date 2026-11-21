//! 不预读的salt观察，以及2017回程salt在任何密文输出前的原子登记。
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::replay::{Domain, ReplayPool, Window};

struct SendSalt {
    pool: Arc<ReplayPool>,
    domain: Domain,
    bytes: [u8; 32],
    length: usize,
    captured: usize,
    written: usize,
    registered: bool,
    failed: bool,
}

pub(super) struct SaltIo<S> {
    pub inner: S,
    received: [u8; 32],
    captured: usize,
    length: usize,
    send: Option<SendSalt>,
}

impl<S> SaltIo<S> {
    pub(super) fn new(inner: S, length: usize, send: Option<(Arc<ReplayPool>, Domain)>) -> Self {
        assert!(matches!(length, 16 | 32));
        Self {
            inner,
            received: [0; 32],
            captured: 0,
            length,
            send: send.map(|(pool, domain)| SendSalt {
                pool,
                domain,
                bytes: [0; 32],
                length,
                captured: 0,
                written: 0,
                registered: false,
                failed: false,
            }),
        }
    }

    pub(super) fn received_salt(&self) -> io::Result<&[u8]> {
        if self.captured != self.length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "salt未完整接收",
            ));
        }
        Ok(&self.received[..self.length])
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SaltIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = (self.length - self.captured).min(buf.filled().len() - start);
            let at = self.captured;
            self.received[at..at + n].copy_from_slice(&buf.filled()[start..start + n]);
            self.captured += n;
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> SaltIo<S> {
    fn poll_prefix(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(send) = &mut self.send else {
            return Poll::Ready(Ok(()));
        };
        if send.failed {
            return Poll::Ready(Err(io::Error::other("salt写方向已终止")));
        }
        if !send.registered {
            return Poll::Ready(Ok(()));
        }
        while send.written < send.length {
            match Pin::new(&mut self.inner).poll_write(cx, &send.bytes[send.written..send.length]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    send.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => send.written += n,
                Poll::Ready(Err(error)) => {
                    send.failed = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SaltIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(send) = &mut self.send {
            if send.failed {
                return Poll::Ready(Err(io::Error::other("salt写方向已终止")));
            }
            if !send.registered {
                let n = (send.length - send.captured).min(buf.len());
                let at = send.captured;
                send.bytes[at..at + n].copy_from_slice(&buf[..n]);
                send.captured += n;
                if send.captured == send.length {
                    if let Err(error) =
                        send.pool
                            .admit(send.domain, &send.bytes[..send.length], Window::Aead2017)
                    {
                        send.failed = true;
                        return Poll::Ready(Err(error));
                    }
                    send.registered = true;
                }
                // 接受有界salt前缀但暂不输出；下一次write/flush才排出已登记的前缀。
                return Poll::Ready(Ok(n));
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.poll_prefix(cx))?;
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Err(_)) | Poll::Ready(Ok(0)))
            && let Some(send) = &mut self.send
        {
            send.failed = true;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_prefix(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_prefix(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, task::Waker};

    struct Wire {
        reads: VecDeque<Option<Vec<u8>>>,
        writes: VecDeque<Option<usize>>,
        output: Vec<u8>,
        read_calls: usize,
        write_calls: usize,
    }
    impl Wire {
        fn new() -> Self {
            Self {
                reads: VecDeque::new(),
                writes: VecDeque::new(),
                output: Vec::new(),
                read_calls: 0,
                write_calls: 0,
            }
        }
    }
    impl AsyncRead for Wire {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.read_calls += 1;
            match self.reads.pop_front().expect("观察器不得额外读取") {
                None => Poll::Pending,
                Some(bytes) => {
                    buf.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
    impl AsyncWrite for Wire {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_calls += 1;
            match self.writes.pop_front().expect("写入次数超出测试脚本") {
                None => Poll::Pending,
                Some(max) => {
                    let n = max.min(buf.len());
                    self.output.extend_from_slice(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    const DOMAIN: Domain = Domain {
        inbound: 0,
        identity: 0,
    };

    #[test]
    fn reads_observe_only_new_bytes_without_changing_reads_or_buffers() {
        let mut wire = Wire::new();
        wire.reads = [None, Some(vec![1; 5]), Some(vec![2; 20])].into();
        let mut io = SaltIo::new(wire, 16, None);
        let mut cx = Context::from_waker(Waker::noop());
        let mut storage = [0; 64];
        let mut buf = ReadBuf::new(&mut storage);
        buf.put_slice(b"already-filled");
        assert!(Pin::new(&mut io).poll_read(&mut cx, &mut buf).is_pending());
        assert_eq!(buf.filled(), b"already-filled");
        assert!(io.received_salt().is_err());
        for _ in 0..2 {
            assert!(matches!(
                Pin::new(&mut io).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
        }
        assert_eq!(io.inner.read_calls, 3);
        assert_eq!(
            io.received_salt().unwrap(),
            [&[1; 5][..], &[2; 11][..]].concat()
        );
        assert_eq!(&buf.filled()[..14], b"already-filled");
        assert_eq!(buf.filled().len(), 39);
    }

    #[test]
    fn pending_partial_prefix_and_payload_are_emitted_once_after_registration() {
        let pool = Arc::new(ReplayPool::new(1));
        let mut wire = Wire::new();
        wire.writes = [None, Some(3), None, Some(32), Some(2), Some(32)].into();
        let mut io = SaltIo::new(wire, 16, Some((pool.clone(), DOMAIN)));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, &[7; 5]),
            Poll::Ready(Ok(5))
        ));
        assert!(io.inner.output.is_empty());
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, &[7; 20]),
            Poll::Ready(Ok(11))
        ));
        assert_eq!(
            pool.admit(DOMAIN, &[7; 16], Window::Aead2017)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(io.inner.output.is_empty());
        for _ in 0..2 {
            assert!(
                Pin::new(&mut io)
                    .poll_write(&mut cx, b"payload")
                    .is_pending()
            );
        }
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, b"payload"),
            Poll::Ready(Ok(2))
        ));
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, b"yload"),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(io.inner.output, [&[7; 16][..], b"payload"].concat());
    }

    #[test]
    fn collision_or_full_pool_is_terminal_and_emits_zero_bytes() {
        for existing in [7, 8] {
            let pool = Arc::new(ReplayPool::new(1));
            pool.admit(DOMAIN, &[existing; 16], Window::Aead2017)
                .unwrap();
            let mut io = SaltIo::new(Wire::new(), 16, Some((pool, DOMAIN)));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut io).poll_write(&mut cx, &[7; 8]),
                Poll::Ready(Ok(8))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_write(&mut cx, &[7; 8]),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_write(&mut cx, b"later"),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_flush(&mut cx),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_shutdown(&mut cx),
                Poll::Ready(Err(_))
            ));
            assert_eq!(io.inner.write_calls, 0);
            assert!(io.inner.output.is_empty());
        }
    }

    #[test]
    fn flush_and_shutdown_drain_only_complete_registered_salt() {
        for shutdown in [false, true] {
            let mut wire = Wire::new();
            wire.writes = [Some(32)].into();
            let mut io = SaltIo::new(wire, 32, Some((Arc::new(ReplayPool::new(1)), DOMAIN)));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut io).poll_write(&mut cx, &[3; 32]),
                Poll::Ready(Ok(32))
            ));
            let result = if shutdown {
                Pin::new(&mut io).poll_shutdown(&mut cx)
            } else {
                Pin::new(&mut io).poll_flush(&mut cx)
            };
            assert!(matches!(result, Poll::Ready(Ok(()))));
            assert_eq!(io.inner.output, [3; 32]);
        }
    }
}
