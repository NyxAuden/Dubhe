//! 独立的有限回环测试端：HTTP 与掩码帧均按公开格式编码，不调用生产承载。
#![allow(dead_code)]
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const LIMIT: usize = 1_048_576;

pub fn masked(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= LIMIT);
    let mut frame = vec![if fin { 0x80 | opcode } else { opcode }];
    match payload.len() {
        n @ 0..=125 => frame.push(0x80 | n as u8),
        n @ 126..=65535 => {
            frame.push(0xfe);
            frame.extend((n as u16).to_be_bytes());
        }
        n => {
            frame.push(0xff);
            frame.extend((n as u64).to_be_bytes());
        }
    }
    let mask = [0x13, 0x37, 0x59, 0x83];
    frame.extend(mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

pub async fn upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    path: &str,
    headers: &str,
    raw_prefix: &[u8],
) -> Peer<S> {
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{headers}\r\n"
    ).into_bytes();
    request.extend(raw_prefix);
    io.write_all(&request).await.unwrap();
    io.flush().await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), async {
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            assert!(response.len() < 16384);
            response.push(io.read_u8().await.unwrap());
        }
        String::from_utf8(response).unwrap()
    })
    .await
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 101 "));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=\r\n")
    );
    Peer {
        io,
        raw: Vec::new(),
        incoming: Vec::new(),
        read_offset: 0,
        pending: Vec::new(),
        write_offset: 0,
        fragmented: false,
        closing: false,
        eof: false,
    }
}

pub struct Peer<S> {
    io: S,
    raw: Vec<u8>,
    incoming: Vec<u8>,
    read_offset: usize,
    pending: Vec<u8>,
    write_offset: usize,
    fragmented: bool,
    closing: bool,
    eof: bool,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Peer<S> {
    pub async fn send_message(&mut self, opcode: u8, payload: &[u8]) {
        self.send_fragment(true, opcode, payload).await;
    }
    pub async fn send_fragment(&mut self, fin: bool, opcode: u8, payload: &[u8]) {
        self.flush().await.unwrap();
        self.io
            .write_all(&masked(fin, opcode, payload))
            .await
            .unwrap();
        self.io.flush().await.unwrap();
        if opcode == 8 {
            self.closing = true;
        }
    }
    pub async fn close(&mut self) {
        self.send_message(8, &1000u16.to_be_bytes()).await;
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.io).poll_write(cx, &self.pending[self.write_offset..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_offset += n;
        }
        self.pending.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
    fn parse(&mut self) -> io::Result<bool> {
        if self.raw.len() < 2 {
            return Ok(false);
        }
        let first = self.raw[0];
        let second = self.raw[1];
        if first & 0x70 != 0 || second & 0x80 != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (header, length) = match second & 0x7f {
            126 if self.raw.len() < 4 => return Ok(false),
            126 => (
                4,
                u16::from_be_bytes(self.raw[2..4].try_into().unwrap()) as usize,
            ),
            127 if self.raw.len() < 10 => return Ok(false),
            127 => {
                let n = u64::from_be_bytes(self.raw[2..10].try_into().unwrap());
                if n > LIMIT as u64 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                (10, n as usize)
            }
            n => (2, n as usize),
        };
        if length > LIMIT {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if self.raw.len() < header + length {
            return Ok(false);
        }
        let fin = first & 0x80 != 0;
        let opcode = first & 0x0f;
        let payload = &self.raw[header..header + length];
        match opcode {
            0 | 2 => {
                if (opcode == 0) != self.fragmented {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.fragmented = !fin;
                self.incoming.extend(payload);
                if self.incoming.len() > LIMIT {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            }
            8 => {
                if !fin || length > 125 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if !self.closing {
                    self.pending.extend(masked(true, 8, payload));
                    self.closing = true;
                }
                self.eof = true;
            }
            9 => {
                if !fin || length > 125 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.pending.extend(masked(true, 10, payload));
            }
            10 if fin && length <= 125 => {}
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
        self.raw.drain(..header + length);
        Ok(true)
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Peer<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if this.read_offset < this.incoming.len() && !this.fragmented {
                let n = output
                    .remaining()
                    .min(this.incoming.len() - this.read_offset);
                output.put_slice(&this.incoming[this.read_offset..this.read_offset + n]);
                this.read_offset += n;
                if this.read_offset == this.incoming.len() {
                    this.incoming.clear();
                    this.read_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            ready!(this.drain(cx))?;
            if this.eof {
                ready!(Pin::new(&mut this.io).poll_flush(cx))?;
                return Poll::Ready(Ok(()));
            }
            if this.parse()? {
                continue;
            }
            let mut bytes = [0; 16384];
            let mut buf = ReadBuf::new(&mut bytes);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.raw.extend(buf.filled());
            if this.raw.len() > LIMIT + 16394 {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Peer<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.drain(cx))?;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = bytes.len().min(16384);
        this.pending = masked(true, 2, &bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closing {
            this.pending.extend(masked(true, 8, &1000u16.to_be_bytes()));
            this.closing = true;
        }
        ready!(this.drain(cx))?;
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

/// 路由拒绝前可能已写出协议应答；只要求连接最终结束。
pub async fn closed_after_optional_response<S: AsyncRead + Unpin>(peer: &mut S) {
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), peer.read_to_end(&mut sink)).await;
}

pub async fn closed<S: AsyncRead + Unpin>(peer: &mut S) {
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(3), peer.read(&mut byte))
        .await
        .expect("连接应及时结束");
    assert!(matches!(result, Ok(0) | Err(_)), "拒绝前不应交付业务数据");
}
