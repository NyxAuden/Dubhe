//! Vision 明文适配；协议状态与 TLS/原始 IO 的所有权保持在同一个对象中。
use super::controlled::Controlled;
use crate::protocol::vision::{Command, Decoder, Direction, Encoder, Inspector, MAX_CONTENT};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 记录层角色决定业务字节的观察方向：服务端写出的是下行，客户端写出的是上行。
#[derive(Clone, Copy)]
pub(crate) enum Role {
    Server,
    Client,
}

/// Vision 的底层：普通 TLS 受控记录层，或声明了不可 splice 的明文流
/// （后者用于 VLESS Encryption 在 Vision 之下、TLS 之上的组合）。
enum VisionStream<S> {
    Controlled(Controlled<S>),
    /// 惰性消费 VLESS 应答头的受控 TLS 流；官方 Xray 可能等首帧业务后才 flush。
    LazyControlled(LazyVless<Controlled<S>>),
    Plain(S),
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionStream<S> {
    fn read_direct(&mut self) -> io::Result<()> {
        match self {
            Self::Controlled(stream) => stream.read_direct(),
            Self::LazyControlled(stream) => stream.read_direct(),
            Self::Plain(_) => Ok(()),
        }
    }

    fn write_direct(&mut self) -> io::Result<()> {
        match self {
            Self::Controlled(stream) => stream.write_direct(),
            Self::LazyControlled(stream) => stream.write_direct(),
            Self::Plain(_) => Ok(()),
        }
    }
}

/// 在首次读取时消费 VLESS `[版本, addons]` 应答；写方向立即可用。
struct LazyVless<S> {
    inner: S,
    header_done: bool,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl<S> LazyVless<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            header_done: false,
            pending: Vec::new(),
            pending_offset: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> LazyVless<Controlled<S>> {
    fn read_direct(&mut self) -> io::Result<()> {
        if !self.header_done {
            return Err(io::Error::other("VLESS 应答头未消费，不能切换原始记录"));
        }
        self.inner.read_direct()
    }

    fn write_direct(&mut self) -> io::Result<()> {
        self.inner.write_direct()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LazyVless<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pending_offset < this.pending.len() {
            let count = buf
                .remaining()
                .min(this.pending.len() - this.pending_offset);
            buf.put_slice(&this.pending[this.pending_offset..this.pending_offset + count]);
            this.pending_offset += count;
            if this.pending_offset == this.pending.len() {
                this.pending.clear();
                this.pending_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if !this.header_done {
            loop {
                let mut scratch = [0u8; 257];
                let mut read = ReadBuf::new(&mut scratch);
                std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VLESS 出站应答头截断",
                    )));
                }
                this.pending.extend_from_slice(&scratch[..count]);
                if this.pending.len() >= 2 {
                    if this.pending[0] != 0 {
                        return Poll::Ready(Err(io::Error::other("VLESS 出站应答版本不匹配")));
                    }
                    let header_len = 2 + usize::from(this.pending[1]);
                    if this.pending.len() >= header_len {
                        this.pending.drain(..header_len);
                        this.header_done = true;
                        break;
                    }
                }
            }
            if this.pending.is_empty() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let count = buf.remaining().min(this.pending.len());
            buf.put_slice(&this.pending[..count]);
            this.pending_offset = count;
            if this.pending_offset == this.pending.len() {
                this.pending.clear();
                this.pending_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LazyVless<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Controlled(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::LazyControlled(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Controlled(stream) => Pin::new(stream).poll_write(cx, data),
            Self::LazyControlled(stream) => Pin::new(stream).poll_write(cx, data),
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Controlled(stream) => Pin::new(stream).poll_flush(cx),
            Self::LazyControlled(stream) => Pin::new(stream).poll_flush(cx),
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Controlled(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::LazyControlled(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) struct Vision<S> {
    stream: VisionStream<S>,
    role: Role,
    decoder: Decoder,
    encoder: Encoder,
    inspector: Inspector,
    input: Vec<u8>,
    input_offset: usize,
    output: Vec<u8>,
    output_offset: usize,
    write_command: Command,
    framed: bool,
    read_raw: bool,
    failure: Option<io::ErrorKind>,
    shutdown_started: bool,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Vision<S> {
    /// VLESS 响应头必须已通过原始 TLS 明文接口发送一次。
    pub(crate) fn new(stream: Controlled<S>, uuid: [u8; 16]) -> Self {
        Self::with_role(VisionStream::Controlled(stream), uuid, Role::Server)
    }

    /// 出站客户端：VLESS 应答头在首次下行读取时惰性消费。
    pub(crate) fn client_lazy(stream: Controlled<S>, uuid: [u8; 16]) -> Self {
        Self::with_role(
            VisionStream::LazyControlled(LazyVless::new(stream)),
            uuid,
            Role::Client,
        )
    }

    /// VLESS Encryption 组合：Vision 仍帧化业务，但不再切换 TLS 原始记录层。
    pub(crate) fn new_plain(stream: S, uuid: [u8; 16]) -> Self {
        Self::with_role(VisionStream::Plain(stream), uuid, Role::Server)
    }

    pub(crate) fn client_plain(stream: S, uuid: [u8; 16]) -> Self {
        Self::with_role(VisionStream::Plain(stream), uuid, Role::Client)
    }

    fn with_role(stream: VisionStream<S>, uuid: [u8; 16], role: Role) -> Self {
        Self {
            stream,
            role,
            decoder: Decoder::new(uuid),
            encoder: Encoder::new(uuid),
            inspector: Inspector::new(),
            input: Vec::new(),
            input_offset: 0,
            output: Vec::new(),
            output_offset: 0,
            write_command: Command::Continue,
            framed: true,
            read_raw: false,
            failure: None,
            shutdown_started: false,
        }
    }

    fn write_direction(&self) -> Direction {
        match self.role {
            Role::Server => Direction::Downlink,
            Role::Client => Direction::Uplink,
        }
    }

    fn read_direction(&self) -> Direction {
        match self.role {
            Role::Server => Direction::Uplink,
            Role::Client => Direction::Downlink,
        }
    }
    fn check(&self) -> io::Result<()> {
        match self.failure {
            Some(kind) => Err(io::Error::new(kind, "Vision 承载已终止")),
            None => Ok(()),
        }
    }
    fn fail<T>(&mut self, error: io::Error) -> io::Result<T> {
        self.failure = Some(error.kind());
        Err(error)
    }
    fn observe(&mut self, direction: Direction, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let decision = self.inspector.observe(direction, bytes);
            if decision.consumed == 0 {
                break;
            }
            bytes = &bytes[decision.consumed..];
        }
    }
    fn poll_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        for _ in 0..32 {
            if self.output_offset == self.output.len() {
                self.output.clear();
                self.output_offset = 0;
                if self.write_command == Command::Direct {
                    self.stream.write_direct()?;
                    self.write_command = Command::End;
                    // 此处的 flush 同时提交底层 TLS 到 raw 的屏障。
                    return Pin::new(&mut self.stream).poll_flush(cx);
                }
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.stream).poll_write(cx, &self.output[self.output_offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(self.fail(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(self.fail(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => self.output_offset += n,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Vision<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check()?;
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if this.input_offset < this.input.len() {
                let n = out.remaining().min(this.input.len() - this.input_offset);
                out.put_slice(&this.input[this.input_offset..this.input_offset + n]);
                this.input_offset += n;
                return Poll::Ready(Ok(()));
            }
            this.input.clear();
            this.input_offset = 0;
            let mut bytes = [0; 16384];
            let mut buf = ReadBuf::new(&mut bytes);
            match Pin::new(&mut this.stream).poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(this.fail(error)),
                Poll::Ready(Ok(())) => {}
            }
            let data = buf.filled();
            if data.is_empty() {
                if let Err(error) = this.decoder.eof() {
                    return Poll::Ready(this.fail(error));
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_raw {
                this.input.extend_from_slice(data);
            } else {
                if let Err(error) = this.decoder.consume(data, &mut this.input) {
                    return Poll::Ready(this.fail(error));
                }
                if this.decoder.is_direct() {
                    if let Err(error) = this.stream.read_direct() {
                        return Poll::Ready(this.fail(error));
                    }
                    this.read_raw = true;
                }
            }
            // 观察的是解包业务字节，而不是 UUID、padding 或外层 TLS。
            let direction = this.read_direction();
            let body = std::mem::take(&mut this.input);
            this.observe(direction, &body);
            this.input = body;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Vision<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check()?;
        if this.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Vision 写方向已关闭",
            )));
        }
        ready!(this.poll_output(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.framed {
            return Pin::new(&mut this.stream).poll_write(cx, data);
        }
        let bytes = &data[..data.len().min(MAX_CONTENT)];
        let direction = this.write_direction();
        let decision = this.inspector.observe(direction, bytes);
        let n = decision.consumed;
        if n == 0 || n > bytes.len() {
            return Poll::Ready(this.fail(io::Error::other("Vision 识别没有进展")));
        }
        let block =
            match this
                .encoder
                .encode(decision.command, &bytes[..n], this.inspector.is_tls())
            {
                Ok(block) => block,
                Err(error) => return Poll::Ready(this.fail(error)),
            };
        this.output = block;
        this.write_command = decision.command;
        if decision.command != Command::Continue {
            this.framed = false;
        }
        // Ok(n) 表示已由有界承载接受的业务字节；后续错误不会重复接受或倒扣。
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check()?;
        ready!(this.poll_output(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check()?;
        this.shutdown_started = true;
        ready!(this.poll_output(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
