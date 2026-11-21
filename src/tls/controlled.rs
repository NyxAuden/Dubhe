//! 只向 rustls 输入一条记录，明文交还上层判定后才读取下一条记录。
//! 不依赖 TLS 私有缓冲布局；原始流读写方向分别提交切换。
use std::{
    future::poll_fn,
    io::{self, Read, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use rustls::pki_types::ServerName;
use rustls::{
    ClientConfig, ClientConnection, IoState, ProtocolVersion, ServerConfig, ServerConnection,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_RECORD: usize = 5 + 16384 + 2048;
const POLL_BUDGET: usize = 32;

/// 服务端与客户端共用的记录层会话；两侧的公共接口一致，只在握手方向不同。
enum Session {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl Session {
    fn protocol_version(&self) -> Option<ProtocolVersion> {
        match self {
            Self::Server(session) => session.protocol_version(),
            Self::Client(session) => session.protocol_version(),
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Server(session) => session.alpn_protocol(),
            Self::Client(session) => session.alpn_protocol(),
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Self::Server(session) => session.is_handshaking(),
            Self::Client(session) => session.is_handshaking(),
        }
    }

    fn wants_write(&self) -> bool {
        match self {
            Self::Server(session) => session.wants_write(),
            Self::Client(session) => session.wants_write(),
        }
    }

    fn write_tls(&mut self, sink: &mut dyn Write) -> io::Result<usize> {
        match self {
            Self::Server(session) => session.write_tls(sink),
            Self::Client(session) => session.write_tls(sink),
        }
    }

    fn read_tls(&mut self, input: &mut dyn Read) -> io::Result<usize> {
        match self {
            Self::Server(session) => session.read_tls(input),
            Self::Client(session) => session.read_tls(input),
        }
    }

    fn process_new_packets(&mut self) -> Result<IoState, rustls::Error> {
        match self {
            Self::Server(session) => session.process_new_packets(),
            Self::Client(session) => session.process_new_packets(),
        }
    }

    fn read_plaintext(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Server(session) => session.reader().read(output),
            Self::Client(session) => session.reader().read(output),
        }
    }

    fn write_plaintext(&mut self, input: &[u8]) -> io::Result<usize> {
        match self {
            Self::Server(session) => session.writer().write(input),
            Self::Client(session) => session.writer().write(input),
        }
    }

    fn send_close_notify(&mut self) {
        match self {
            Self::Server(session) => session.send_close_notify(),
            Self::Client(session) => session.send_close_notify(),
        }
    }
}

pub(crate) struct Controlled<S> {
    io: S,
    /// 两种 rustls 会话都较大；装箱避免放大包含 `Controlled` 的 future 栈帧。
    session: Box<Session>,
    record: Box<[u8; MAX_RECORD]>,
    filled: usize,
    needed: usize,
    read_raw: bool,
    write_raw: bool,
    switching_write: bool,
    read_closed: bool,
    shutdown_started: bool,
    failure: Option<io::ErrorKind>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Controlled<S> {
    pub(crate) async fn accept(io: S, config: Arc<ServerConfig>) -> io::Result<Self> {
        let mut session = ServerConnection::new(config).map_err(tls_error)?;
        session.set_buffer_limit(Some(65536));
        Self::accept_prepared(io, session).await
    }

    /// 客户端 TLS 1.3 记录层；用于 Vision 的原始记录边界切换。
    pub(crate) async fn connect(
        io: S,
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    ) -> io::Result<Self> {
        let mut session = ClientConnection::new(config, server_name).map_err(tls_error)?;
        session.set_buffer_limit(Some(65536));
        Self::establish(io, Box::new(Session::Client(session))).await
    }

    /// 接续已在有界内存完成初始 flight 预检的会话；此处才首次 poll socket 输出。
    pub(crate) async fn accept_prepared(io: S, session: ServerConnection) -> io::Result<Self> {
        Self::establish(io, Box::new(Session::Server(session))).await
    }

    async fn establish(io: S, session: Box<Session>) -> io::Result<Self> {
        let mut stream = Self {
            io,
            session,
            record: Box::new([0; MAX_RECORD]),
            filled: 0,
            needed: 5,
            read_raw: false,
            write_raw: false,
            switching_write: false,
            read_closed: false,
            shutdown_started: false,
            failure: None,
        };
        poll_fn(|cx| stream.poll_handshake(cx)).await?;
        Ok(stream)
    }

    pub(crate) fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.session.protocol_version()
    }

    /// REALITY 内层 TLS 协商出的 ALPN；用于选择 WS/HTTP/gRPC 承载。
    pub(crate) fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.session.alpn_protocol().map(<[u8]>::to_vec)
    }

    /// 先排出本条记录里尚未消费的明文，之后才直接读取原始 IO。
    pub(crate) fn read_direct(&mut self) -> io::Result<()> {
        self.check()?;
        if self.filled != 0 || self.session.is_handshaking() {
            return self.fail(io::Error::other("TLS 读切换不在记录边界"));
        }
        self.read_raw = true;
        Ok(())
    }

    /// 在两个方向都已切换到原始记录、握手结束且没有未消费记录时取回底层流。
    ///
    /// 只允许在严格边界上提取：任何未完成的状态都返回错误并由调用方失败关闭，
    /// 绝不在仍有 TLS 缓冲时丢弃字节。
    pub(crate) fn into_raw(self) -> io::Result<S> {
        self.check()?;
        let handshaking = self.session.is_handshaking();
        if handshaking || !self.read_raw || !self.write_raw || self.filled != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "TLS 会话不能提取原始流（handshaking={handshaking}, read_raw={}, write_raw={}, filled={}）",
                    self.read_raw, self.write_raw, self.filled
                ),
            ));
        }
        Ok(self.io)
    }

    /// flush 屏障完成前，后续写入不能越过最后一条 TLS 记录。
    pub(crate) fn write_direct(&mut self) -> io::Result<()> {
        self.check()?;
        if self.shutdown_started || self.session.is_handshaking() {
            return self.fail(io::Error::other("TLS 写切换状态无效"));
        }
        self.switching_write = true;
        Ok(())
    }

    fn check(&self) -> io::Result<()> {
        match self.failure {
            Some(kind) => Err(io::Error::new(kind, "TLS 承载已终止")),
            None => Ok(()),
        }
    }

    fn fail<T>(&mut self, error: io::Error) -> io::Result<T> {
        self.failure = Some(error.kind());
        Err(error)
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        for _ in 0..POLL_BUDGET {
            ready!(self.poll_output(cx))?;
            if !self.session.is_handshaking() {
                return Poll::Ready(Ok(()));
            }
            if !ready!(self.poll_record(cx))? {
                return Poll::Ready(
                    self.fail(io::Error::new(io::ErrorKind::UnexpectedEof, "TLS 握手截断")),
                );
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        if self.write_raw {
            if self.session.wants_write() {
                return Poll::Ready(self.fail(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "原始写方向不能插入 TLS 控制记录",
                )));
            }
            return Poll::Ready(Ok(()));
        }
        for _ in 0..POLL_BUDGET {
            if !self.session.wants_write() {
                if self.switching_write {
                    match Pin::new(&mut self.io).poll_flush(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(self.fail(error)),
                        Poll::Ready(Ok(())) => {
                            self.write_raw = true;
                            self.switching_write = false;
                        }
                    }
                }
                return Poll::Ready(Ok(()));
            }
            let mut sink = AsyncSink {
                io: &mut self.io,
                cx,
            };
            match self.session.write_tls(&mut sink) {
                Ok(0) => {
                    return Poll::Ready(
                        self.fail(io::Error::new(io::ErrorKind::WriteZero, "TLS 输出没有进展")),
                    );
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(error) => return Poll::Ready(self.fail(error)),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// 此函数一次最多处理一条 TLS 记录，从不预读下条记录的头。
    fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        for _ in 0..POLL_BUDGET {
            if self.filled == self.needed {
                if self.needed == 5 {
                    let payload = usize::from(u16::from_be_bytes([self.record[3], self.record[4]]));
                    if payload > MAX_RECORD - 5 {
                        return Poll::Ready(self.fail(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TLS 记录超过长度上限",
                        )));
                    }
                    self.needed = 5 + payload;
                }
                if self.filled == self.needed {
                    let mut input = &self.record[..self.needed];
                    while !input.is_empty() {
                        match self.session.read_tls(&mut input) {
                            Ok(0) => {
                                return Poll::Ready(self.fail(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "TLS 记录未被消费",
                                )));
                            }
                            Ok(_) => {}
                            Err(error) => return Poll::Ready(self.fail(error)),
                        }
                        let state = match self.session.process_new_packets() {
                            Ok(state) => state,
                            Err(_) => return Poll::Ready(self.fail(tls_error(()))),
                        };
                        self.read_closed |= state.peer_has_closed();
                        // 读写可独立推进，但不能因控制消息在写背压期间无限积累。
                        // 单条记录处理的瞬时开销另受 rustls 内部限制约束。
                        if state.tls_bytes_to_write() > 65536 + MAX_RECORD {
                            return Poll::Ready(self.fail(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "TLS 待写输出超过预算",
                            )));
                        }
                        // rustls 会把对端请求的 KeyUpdate 暂存到下一次应用写。
                        // 空写不生成应用记录，但能显化该控制输出，不能只查 wants_write。
                        if let Err(error) = self.session.write_plaintext(&[]) {
                            return Poll::Ready(self.fail(error));
                        }
                    }
                    self.filled = 0;
                    self.needed = 5;
                    if self.write_raw && self.session.wants_write() {
                        return Poll::Ready(self.fail(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "原始写方向不能插入 TLS 控制记录",
                        )));
                    }
                    return Poll::Ready(Ok(true));
                }
            }
            let mut buffer = ReadBuf::new(&mut self.record[self.filled..self.needed]);
            match Pin::new(&mut self.io).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(self.fail(error)),
                Poll::Ready(Ok(())) => {
                    let n = buffer.filled().len();
                    if n == 0 {
                        if self.filled != 0 {
                            return Poll::Ready(self.fail(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "TLS 记录截断",
                            )));
                        }
                        // 将真实 EOF 通知 rustls，使缺少 close_notify 的关闭保持错误语义。
                        self.session.read_tls(&mut io::empty())?;
                        self.read_closed = true;
                        return Poll::Ready(Ok(false));
                    }
                    self.filled += n;
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Controlled<S> {
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
        for _ in 0..POLL_BUDGET {
            match this.session.read_plaintext(out.initialize_unfilled()) {
                Ok(n) if n > 0 => {
                    out.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) if this.read_closed && !this.read_raw => return Poll::Ready(Ok(())),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(this.fail(error)),
                Ok(_) => {}
            }
            if this.read_raw {
                return match Pin::new(&mut this.io).poll_read(cx, out) {
                    Poll::Ready(Err(error)) => Poll::Ready(this.fail(error)),
                    other => other,
                };
            }
            // 输出背压不能阻止独立读方向消费已就绪的入站记录。
            // poll_output 已登记写唤醒；继续读也登记读唤醒，两者都可推进。
            if let Poll::Ready(Err(error)) = this.poll_output(cx) {
                return Poll::Ready(Err(error));
            }
            if this.read_closed {
                return Poll::Ready(Ok(()));
            }
            ready!(this.poll_record(cx))?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Controlled<S> {
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
                "TLS 写方向已关闭",
            )));
        }
        ready!(this.poll_output(cx))?;
        if this.write_raw {
            return match Pin::new(&mut this.io).poll_write(cx, data) {
                Poll::Ready(Err(error)) => Poll::Ready(this.fail(error)),
                other => other,
            };
        }
        match this.session.write_plaintext(&data[..data.len().min(16384)]) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(error) => Poll::Ready(this.fail(error)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check()?;
        ready!(this.poll_output(cx))?;
        match Pin::new(&mut this.io).poll_flush(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(this.fail(error)),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check()?;
        ready!(this.poll_output(cx))?;
        if !this.shutdown_started {
            this.shutdown_started = true;
            if !this.write_raw {
                this.session.send_close_notify();
            }
        }
        ready!(this.poll_output(cx))?;
        match Pin::new(&mut this.io).poll_shutdown(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(this.fail(error)),
            other => other,
        }
    }
}

struct AsyncSink<'a, 'b, S> {
    io: &'a mut S,
    cx: &'a mut Context<'b>,
}
impl<S: AsyncWrite + Unpin> Write for AsyncSink<'_, '_, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, bytes) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn tls_error(_: impl Sized) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "TLS 记录或握手无效")
}

#[cfg(test)]
mod tests;
