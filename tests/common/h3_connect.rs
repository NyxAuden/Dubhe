//! 测试专用普通 CONNECT 编码适配。h3 0.0.8 的客户端会无条件补 scheme/path；
//! 使用公开 QUIC backend 接口替换首个 HEADERS 为 RFC 9114 §4.4 合规报文。
//! 不修改被测服务端或 vendor；响应、DATA、控制流仍由成熟 h3 实现处理。
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h3::quic::{self, SendStreamUnframed as _};

pub struct Connect {
    inner: h3_quinn::Connection,
    headers: Bytes,
}

#[derive(Clone)]
pub struct Opener {
    inner: h3_quinn::OpenStreams,
    headers: Bytes,
}

pub struct Bidi {
    inner: h3_quinn::BidiStream<Bytes>,
    headers: Option<Bytes>,
    pending: Bytes,
}

impl Connect {
    pub fn new(connection: quinn::Connection, fields: &[(&str, &str)]) -> Self {
        // RFC 9204：无动态表引用的字段区前缀，然后以不使用 Huffman 的字面字段编码。
        let mut block = vec![0, 0];
        for (name, value) in fields {
            integer(&mut block, 3, 0x20, name.len());
            block.extend_from_slice(name.as_bytes());
            integer(&mut block, 7, 0, value.len());
            block.extend_from_slice(value.as_bytes());
        }
        let mut headers = vec![1]; // HTTP/3 HEADERS frame type
        let length = block.len();
        if length < 64 {
            headers.push(length as u8);
        } else if length < 16384 {
            headers.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
        } else {
            panic!("测试 HEADERS 超出有界报文长度");
        }
        headers.extend_from_slice(&block);
        Self {
            inner: h3_quinn::Connection::new(connection),
            headers: headers.into(),
        }
    }
}

fn integer(output: &mut Vec<u8>, bits: u8, flags: u8, mut value: usize) {
    let mask = (1usize << bits) - 1;
    output.push(flags | value.min(mask) as u8);
    if value < mask {
        return;
    }
    value -= mask;
    while value >= 128 {
        output.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    output.push(value as u8);
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
            assert_eq!(generated.chunk()[0], 1, "首个写入必须是 HEADERS");
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
        assert!(self.headers.is_none() && self.pending.is_empty());
        quic::BidiStream::<Bytes>::split(self.inner)
    }
}
