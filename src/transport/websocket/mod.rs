//! HTTP/1.1 WebSocket 的有限字节流；不引入每连接后台驱动任务。
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, Waker, ready},
    time::Duration,
};

use futures_util::{Sink, Stream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Sleep,
};
use tokio_tungstenite::WebSocketStream;
use tungstenite::{
    Error, Message,
    protocol::{Role, WebSocketConfig, frame::coding::CloseCode},
};

mod guard;
mod upgrade;

#[cfg(test)]
mod tests;

const MAX_MESSAGE: usize = 1_048_576;
const MAX_WRITE: usize = 65_536;
const MAX_EVENTS: usize = 32;

pub(crate) struct WebSocket<S> {
    socket: WebSocketStream<guard::Guard<S>>,
    early: Vec<u8>,
    early_offset: usize,
    incoming: Option<Message>,
    offset: usize,
    closing: bool,
    close_sent: bool,
    close_flushed: bool,
    peer_closed: bool,
    shutdown: bool,
    failure: Option<io::ErrorKind>,
    close_timer: Option<Pin<Box<Sleep>>>,
    reader: Option<Waker>,
    closer: Option<Waker>,
}

pub(crate) async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    config: &crate::config::WebSocket,
) -> io::Result<WebSocket<S>> {
    let accepted = upgrade::accept(&mut io, config).await?;
    Ok(WebSocket::new(io, accepted.raw_prefix, accepted.early_data).await)
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocket<S> {
    async fn new(io: S, raw_prefix: Vec<u8>, early: Vec<u8>) -> Self {
        let config = WebSocketConfig::default()
            .read_buffer_size(16_384)
            .write_buffer_size(0)
            .max_write_buffer_size(131_072)
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE))
            .accept_unmasked_frames(false);
        // 预读原文必须在护栏之下，不能直接填库内部的 partially_read 缓冲。
        let socket = WebSocketStream::from_raw_socket(
            guard::Guard::new(io, raw_prefix),
            Role::Server,
            Some(config),
        )
        .await;
        Self {
            socket,
            early,
            early_offset: 0,
            incoming: None,
            offset: 0,
            closing: false,
            close_sent: false,
            close_flushed: false,
            peer_closed: false,
            shutdown: false,
            failure: None,
            close_timer: None,
            reader: None,
            closer: None,
        }
    }

    fn fail(&mut self, kind: io::ErrorKind) -> io::Error {
        self.failure = Some(kind);
        self.closing = true;
        io::Error::new(kind, "WebSocket 承载已结束")
    }

    fn library_error(&mut self, error: Error) -> io::Error {
        let kind = match error {
            Error::Io(error) => error.kind(),
            Error::Capacity(_) => io::ErrorKind::InvalidData,
            Error::Protocol(_) | Error::Utf8(_) => io::ErrorKind::InvalidData,
            Error::AlreadyClosed => io::ErrorKind::BrokenPipe,
            _ => io::ErrorKind::ConnectionAborted,
        };
        self.fail(kind)
    }

    fn healthy(&self) -> io::Result<()> {
        match self.failure {
            Some(kind) => Err(io::Error::new(kind, "WebSocket 承载已结束")),
            None => Ok(()),
        }
    }

    fn begin_close(&mut self) {
        self.closing = true;
        if self.close_timer.is_none() {
            self.close_timer = Some(Box::pin(tokio::time::sleep(Duration::from_secs(5))));
        }
    }

    fn check_close_time(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.shutdown {
            return Ok(());
        }
        if let Some(timer) = self.close_timer.as_mut()
            && timer.as_mut().poll(cx).is_ready()
        {
            return Err(self.fail(io::ErrorKind::TimedOut));
        }
        Ok(())
    }

    fn receive_close(
        &mut self,
        frame: Option<tungstenite::protocol::CloseFrame>,
    ) -> io::Result<()> {
        self.begin_close();
        if frame.is_some_and(|frame| frame.code != CloseCode::Normal) {
            return Err(self.fail(io::ErrorKind::ConnectionAborted));
        }
        self.peer_closed = true;
        if let Some(waker) = self.closer.take() {
            waker.wake();
        }
        Ok(())
    }

    fn flush_socket(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.close_flushed {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.socket).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                // 服务端已收到Close后，库本次flush会完成回复并终止自身状态。
                // 之后不得再次flush库（AlreadyClosed），但底层TLS仍须单独结束。
                self.close_flushed = self.peer_closed;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.library_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn deliver(&mut self, output: &mut ReadBuf<'_>) -> bool {
        if self.early_offset < self.early.len() {
            let n = output.remaining().min(self.early.len() - self.early_offset);
            output.put_slice(&self.early[self.early_offset..self.early_offset + n]);
            self.early_offset += n;
            if self.early_offset == self.early.len() {
                self.early = Vec::new();
            }
            return true;
        }
        if let Some(Message::Binary(bytes)) = self.incoming.as_ref() {
            let n = output.remaining().min(bytes.len() - self.offset);
            output.put_slice(&bytes[self.offset..self.offset + n]);
            self.offset += n;
            if self.offset == bytes.len() {
                self.incoming = None;
                self.offset = 0;
                if let Some(waker) = self.closer.take() {
                    waker.wake();
                }
            }
            return n != 0;
        }
        false
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocket<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.healthy()?;
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.socket.get_mut().begin_poll();
        this.reader = Some(cx.waker().clone());
        this.check_close_time(cx)?;
        if this.deliver(output) {
            return Poll::Ready(Ok(()));
        }
        if this.peer_closed {
            if !this.shutdown {
                ready!(this.flush_socket(cx))?;
            }
            return Poll::Ready(Ok(()));
        }
        for _ in 0..MAX_EVENTS {
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    this.incoming = Some(Message::Binary(bytes));
                    this.deliver(output);
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(frame))) => {
                    this.receive_close(frame)?;
                    ready!(this.flush_socket(cx))?;
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(_)) => return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData))),
                Some(Err(error)) => return Poll::Ready(Err(this.library_error(error))),
                None if this.peer_closed => return Poll::Ready(Ok(())),
                None => return Poll::Ready(Err(this.fail(io::ErrorKind::UnexpectedEof))),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocket<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.healthy()?;
        if this.closing {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket 关闭后不接受业务写入",
            )));
        }
        if payload.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.socket.get_mut().begin_poll();
        match ready!(Pin::new(&mut this.socket).poll_ready(cx)) {
            Ok(()) => {}
            Err(error) => return Poll::Ready(Err(this.library_error(error))),
        }
        let n = payload.len().min(MAX_WRITE);
        match Pin::new(&mut this.socket).start_send(Message::Binary(payload[..n].to_vec().into())) {
            Ok(()) => Poll::Ready(Ok(n)),
            // 此错误表示本帧未接收；原业务切片仍由调用者持有，下一poll再尝试。
            Err(Error::WriteBufferFull(_)) => {
                ready!(this.flush_socket(cx))?;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(this.library_error(error))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.healthy()?;
        if this.shutdown {
            return Poll::Ready(Ok(()));
        }
        this.socket.get_mut().begin_poll();
        this.check_close_time(cx)?;
        this.flush_socket(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.begin_close();
        this.healthy()?;
        if this.shutdown {
            return Poll::Ready(Ok(()));
        }
        this.socket.get_mut().begin_poll();
        this.closer = Some(cx.waker().clone());
        this.check_close_time(cx)?;
        if !this.close_sent && !this.peer_closed {
            ready!(this.flush_socket(cx))?;
            match ready!(Pin::new(&mut this.socket).poll_close(cx)) {
                Ok(()) => this.close_sent = true,
                Err(error) => return Poll::Ready(Err(this.library_error(error))),
            }
        }
        if !this.peer_closed {
            // 已接受的读向消息必须先由读者排空，不为等Close另建无界丢包队列。
            if this.incoming.is_some() {
                if let Some(reader) = this.reader.as_ref() {
                    reader.wake_by_ref();
                }
                return Poll::Pending;
            }
            for _ in 0..MAX_EVENTS {
                match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                    Some(Ok(Message::Close(frame))) => {
                        this.receive_close(frame)?;
                        break;
                    }
                    Some(Ok(Message::Binary(bytes))) if !bytes.is_empty() => {
                        this.incoming = Some(Message::Binary(bytes));
                        if let Some(reader) = this.reader.as_ref() {
                            reader.wake_by_ref();
                        }
                        return Poll::Pending;
                    }
                    Some(Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(_)) => return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData))),
                    Some(Err(error)) => return Poll::Ready(Err(this.library_error(error))),
                    None => return Poll::Ready(Err(this.fail(io::ErrorKind::UnexpectedEof))),
                }
            }
            if !this.peer_closed {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        ready!(this.flush_socket(cx))?;
        match Pin::new(this.socket.get_mut().get_mut()).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdown = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.fail(error.kind()))),
            Poll::Pending => Poll::Pending,
        }
    }
}
