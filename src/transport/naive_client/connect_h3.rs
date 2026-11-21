//! h3 0.0.8普通CONNECT首HEADERS适配：不修改vendor，不改控制/响应/DATA语义。
//! RFC9114§4.4普通CONNECT不允许scheme/path/protocol，字段以RFC9204字面编码。
use bytes::{Buf, Bytes};
use h3::quic::{self, SendStreamUnframed as _};
use std::{
    io,
    task::{Context, Poll},
};

pub(super) struct Connect {
    inner: h3_quinn::Connection,
    headers: Bytes,
}
#[derive(Clone)]
pub(super) struct Opener {
    inner: h3_quinn::OpenStreams,
    headers: Bytes,
}
pub(super) struct Bidi {
    inner: h3_quinn::BidiStream<Bytes>,
    headers: Option<Bytes>,
    pending: Bytes,
}
impl Connect {
    pub(super) fn new(
        connection: quinn::Connection,
        request: &http::Request<()>,
    ) -> io::Result<Self> {
        if request.method() != http::Method::CONNECT
            || request.uri().scheme().is_some()
            || !request.uri().path().is_empty()
            || request.extensions().get::<h3::ext::Protocol>().is_some()
        {
            return Err(invalid());
        }
        let authority = request.uri().authority().ok_or_else(invalid)?;
        let mut block = vec![0, 0]; // required insert count=0, delta base=0：无动态表。
        literal(&mut block, ":method", "CONNECT");
        literal(&mut block, ":authority", authority.as_str());
        let mut section_size = 32 + 7 + 7 + 32 + 10 + authority.as_str().len();
        for (name, value) in request.headers() {
            let value = value.to_str().map_err(|_| invalid())?;
            if name.as_str().starts_with(':') {
                return Err(invalid());
            }
            section_size += name.as_str().len() + value.len() + 32;
            literal(&mut block, name.as_str(), value);
        }
        if section_size > 8192 || block.len() >= 16384 {
            return Err(invalid());
        }
        let mut headers = vec![1]; // HTTP/3 HEADERS，长度只需QUIC varint的1或2字节。
        if block.len() < 64 {
            headers.push(block.len() as u8);
        } else {
            headers.extend_from_slice(&((block.len() as u16) | 0x4000).to_be_bytes());
        }
        headers.extend_from_slice(&block);
        Ok(Self {
            inner: h3_quinn::Connection::new(connection),
            headers: headers.into(),
        })
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Naive普通CONNECT首头无效或过大",
    )
}
fn literal(block: &mut Vec<u8>, name: &str, value: &str) {
    integer(block, 3, 0x20, name.len()); // literal field line with literal name, N=H=0。
    block.extend_from_slice(name.as_bytes());
    integer(block, 7, 0, value.len());
    block.extend_from_slice(value.as_bytes());
}
fn integer(bytes: &mut Vec<u8>, bits: u8, flags: u8, mut value: usize) {
    let mask = (1usize << bits) - 1;
    bytes.push(flags | value.min(mask) as u8);
    if value < mask {
        return;
    }
    value -= mask;
    while value >= 128 {
        bytes.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    bytes.push(value as u8);
}
impl quic::Connection<Bytes> for Connect {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Opener;
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, quic::ConnectionErrorIncoming>> {
        quic::Connection::<Bytes>::poll_accept_recv(&mut self.inner, cx)
    }
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bidi, quic::ConnectionErrorIncoming>> {
        let inner = std::task::ready!(quic::Connection::<Bytes>::poll_accept_bidi(
            &mut self.inner,
            cx
        ))?;
        Poll::Ready(Ok(Bidi {
            inner,
            headers: None,
            pending: Bytes::new(),
        }))
    }
    fn opener(&self) -> Opener {
        Opener {
            inner: quic::Connection::<Bytes>::opener(&self.inner),
            headers: self.headers.clone(),
        }
    }
}
macro_rules! open {
    () => {
        type BidiStream = Bidi;
        type SendStream = h3_quinn::SendStream<Bytes>;
        fn poll_open_bidi(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Bidi, quic::StreamErrorIncoming>> {
            let inner = std::task::ready!(self.inner.poll_open_bidi(cx))?;
            Poll::Ready(Ok(Bidi {
                inner,
                headers: Some(self.headers.clone()),
                pending: Bytes::new(),
            }))
        }
        fn poll_open_send(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::SendStream, quic::StreamErrorIncoming>> {
            self.inner.poll_open_send(cx)
        }
        fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
            quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason);
        }
    };
}
impl quic::OpenStreams<Bytes> for Connect {
    open!();
}
impl quic::OpenStreams<Bytes> for Opener {
    open!();
}
impl quic::RecvStream for Bidi {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, quic::StreamErrorIncoming>> {
        quic::RecvStream::poll_data(&mut self.inner, cx)
    }
    fn stop_sending(&mut self, code: u64) {
        quic::RecvStream::stop_sending(&mut self.inner, code);
    }
    fn recv_id(&self) -> quic::StreamId {
        quic::RecvStream::recv_id(&self.inner)
    }
}
impl quic::SendStream<Bytes> for Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        while self.pending.has_remaining() {
            std::task::ready!(self.inner.poll_send(cx, &mut self.pending))?;
        }
        self.inner.poll_ready(cx)
    }
    fn send_data<T: Into<quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), quic::StreamErrorIncoming> {
        if let Some(headers) = self.headers.take() {
            let generated = data.into();
            if generated.chunk().first() != Some(&1) {
                return Err(quic::StreamErrorIncoming::Unknown(Box::new(invalid())));
            }
            self.pending = headers;
            Ok(())
        } else {
            self.inner.send_data(data)
        }
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        std::task::ready!(self.poll_ready(cx))?;
        self.inner.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.inner.reset(code);
    }
    fn send_id(&self) -> quic::StreamId {
        self.inner.send_id()
    }
}
impl quic::BidiStream<Bytes> for Bidi {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type RecvStream = h3_quinn::RecvStream;
    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        // 成熟h3::send_request先poll_ready确认首HEADERS全部写出，才允许split。
        debug_assert!(self.headers.is_none() && self.pending.is_empty());
        quic::BidiStream::<Bytes>::split(self.inner)
    }
}
