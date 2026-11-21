//! 有界的 VMess 服务端正文 codec。准入层须先执行 TLS/明文及实验性 A 位策略。
//!
//! 每个方向只有一个在途块；Pending/取消保留实际 wire 游标，不重新编码。
use std::{
    future::poll_fn,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use shake::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use super::crypto::{self, Cipher};

const CHUNK: u8 = 0x01;
const MASK: u8 = 0x04;
const PADDING: u8 = 0x08;
const AUTH_LENGTH: u8 = 0x10;
const TAG: usize = 16;
const TCP_CHUNK: usize = 16 * 1024;
const NONCE_LIMIT: u32 = 1 << 16;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "VMess 正文写端已关闭")
}

// 保留原始错误种类（尤其不能把 TLS 截断等底层错误改成成功 EOF）。
struct Failure(io::ErrorKind, String);
impl Failure {
    fn from(error: &io::Error) -> Self {
        Self(error.kind(), error.to_string())
    }
    fn error(&self) -> io::Error {
        io::Error::new(self.0, self.1.clone())
    }
}

fn nonce(counter: u32, iv: &[u8; 16]) -> io::Result<[u8; 12]> {
    let counter = u16::try_from(counter).map_err(|_| invalid("VMess 正文 nonce 额度耗尽"))?;
    let mut output = [0; 12];
    output[..2].copy_from_slice(&counter.to_be_bytes());
    output[2..].copy_from_slice(&iv[2..12]);
    Ok(output)
}

struct Codec {
    cipher: Option<Cipher>,
    length_cipher: Option<Cipher>,
    iv: [u8; 16],
    length_iv: [u8; 16],
    options: u8,
    raw: bool,
    sequence: Shake128Reader,
    counter: u32,
}

impl Codec {
    fn new(
        security: u8,
        options: u8,
        key: &[u8; 16],
        iv: &[u8; 16],
        request_key: &[u8; 16],
        request_iv: &[u8; 16],
    ) -> io::Result<Self> {
        if options & !(CHUNK | MASK | PADDING | AUTH_LENGTH) != 0
            || options & PADDING != 0 && options & MASK == 0
            || !matches!(security, 3..=5)
            || security == 5 && options & !CHUNK != 0
        {
            return Err(invalid("VMess 正文安全值或选项不受支持"));
        }
        let cipher = if security == 5 {
            None
        } else {
            Some(Cipher::new(security, key)?)
        };
        // 固定上游 wire：下行长度也用 request key/IV。此扩展跨方向重用材料，
        // 只能由上层显式开启；这里绝不能擅自改成响应材料或方向域。
        let length_cipher = if options & AUTH_LENGTH != 0 {
            Some(Cipher::new(
                security,
                &crypto::kdf16(request_key, &[b"auth_len"]),
            )?)
        } else {
            None
        };
        let mut shake = Shake128::default();
        shake.update(iv);
        Ok(Self {
            cipher,
            length_cipher,
            iv: *iv,
            length_iv: *request_iv,
            options,
            raw: security == 5 && options == 0,
            sequence: shake.finalize_xof(),
            counter: 0,
        })
    }

    fn header_len(&self) -> usize {
        if self.length_cipher.is_some() { 18 } else { 2 }
    }

    fn tag_len(&self) -> usize {
        if self.cipher.is_some() { TAG } else { 0 }
    }

    fn layout(&self, sequence: &mut Shake128Reader) -> (usize, u16) {
        let mut word = || {
            let mut bytes = [0; 2];
            sequence.read(&mut bytes);
            u16::from_be_bytes(bytes)
        };
        // P 和 M 消费同一条 SHAKE 流，严格先 P 后 M；A 模式不消费 M。
        let padding = if self.options & PADDING != 0 {
            usize::from(word() % 64)
        } else {
            0
        };
        let mask = if self.options & MASK != 0 && self.length_cipher.is_none() {
            word()
        } else {
            0
        };
        (padding, mask)
    }

    fn decode_length(&mut self, header: &[u8]) -> io::Result<(usize, usize)> {
        if self.cipher.is_some() {
            nonce(self.counter, &self.iv)?;
        }
        let mut sequence = self.sequence.clone();
        let (padding, mask) = self.layout(&mut sequence);
        let length = if let Some(cipher) = &self.length_cipher {
            let decoded = cipher.open(&nonce(self.counter, &self.length_iv)?, &[], header)?;
            let bytes: [u8; 2] = decoded
                .try_into()
                .map_err(|_| invalid("VMess 认证长度无效"))?;
            // A wire 长度不含正文 tag，65535 + 16 是合法密文上界。
            usize::from(u16::from_be_bytes(bytes)) + TAG
        } else {
            let bytes: [u8; 2] = header.try_into().map_err(|_| invalid("VMess 块长度无效"))?;
            usize::from(u16::from_be_bytes(bytes) ^ mask)
        };
        if length < self.tag_len() + padding {
            return Err(invalid("VMess 块长度不足以容纳标签或填充"));
        }
        self.sequence = sequence;
        Ok((length, padding))
    }

    fn decode_payload(&mut self, wire: &[u8], padding: usize) -> io::Result<Vec<u8>> {
        let end = wire.len() - padding;
        let output = if let Some(cipher) = &self.cipher {
            cipher.open(&nonce(self.counter, &self.iv)?, &[], &wire[..end])?
        } else {
            wire[..end].to_vec()
        };
        if self.cipher.is_some() {
            self.counter += 1;
        }
        Ok(output)
    }

    fn encode(&mut self, payload: &[u8], terminal: bool) -> io::Result<Vec<u8>> {
        if self.cipher.is_some() {
            // 非终止业务保守预留 nonce 65535，显式关闭仍能发最后一个认证空块。
            if self.counter >= NONCE_LIMIT || !terminal && self.counter >= NONCE_LIMIT - 1 {
                return Err(invalid("VMess 正文 nonce 额度耗尽"));
            }
        }
        let mut sequence = self.sequence.clone();
        let (padding, mask) = self.layout(&mut sequence);
        let overhead = padding
            + if self.length_cipher.is_some() {
                0
            } else {
                self.tag_len()
            };
        if payload.len() > usize::from(u16::MAX) - overhead {
            return Err(input("VMess 数据报不能装入单个正文块"));
        }
        let body = if let Some(cipher) = &self.cipher {
            cipher.seal(&nonce(self.counter, &self.iv)?, &[], payload)?
        } else {
            payload.to_vec()
        };
        let size = payload.len() + overhead;
        let mut output = if let Some(cipher) = &self.length_cipher {
            cipher.seal(
                &nonce(self.counter, &self.length_iv)?,
                &[],
                &(size as u16).to_be_bytes(),
            )?
        } else {
            ((size as u16) ^ mask).to_be_bytes().to_vec()
        };
        // 精确预留一个 wire 块，避免 Vec 在追加 padding 时按倍数扩容为两个块。
        output.reserve_exact(body.len() + padding);
        output.extend_from_slice(&body);
        let padding_start = output.len();
        output.resize(padding_start + padding, 0);
        if padding != 0 {
            rustls::crypto::ring::default_provider()
                .secure_random
                .fill(&mut output[padding_start..])
                .map_err(|_| io::Error::other("VMess 安全随机源失败"))?;
        }
        self.sequence = sequence;
        if self.cipher.is_some() {
            self.counter += 1;
        }
        Ok(output)
    }
}

pub(crate) struct Reader<R> {
    io: R,
    codec: Codec,
    header: [u8; 18],
    header_used: usize,
    wire: Vec<u8>,
    wire_used: usize,
    padding: usize,
    reading_body: bool,
    payload: Vec<u8>,
    payload_used: usize,
    ended: bool,
    failure: Option<Failure>,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    fn new(io: R, codec: Codec) -> Self {
        Self {
            io,
            codec,
            header: [0; 18],
            header_used: 0,
            wire: Vec::new(),
            wire_used: 0,
            padding: 0,
            reading_body: false,
            payload: Vec::new(),
            payload_used: 0,
            ended: false,
            failure: None,
        }
    }

    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if let Some(failure) = &self.failure {
            return Poll::Ready(Err(failure.error()));
        }
        if self.ended {
            return Poll::Ready(Ok(false));
        }
        let result = self.poll_frame_inner(cx);
        if let Poll::Ready(Err(error)) = &result {
            self.failure = Some(Failure::from(error));
            self.wire = Vec::new();
            self.payload = Vec::new();
        }
        result
    }

    fn poll_frame_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if !self.reading_body {
            let header_len = self.codec.header_len();
            while self.header_used < header_len {
                let mut buffer = ReadBuf::new(&mut self.header[self.header_used..header_len]);
                ready!(Pin::new(&mut self.io).poll_read(cx, &mut buffer))?;
                let count = buffer.filled().len();
                if count == 0 {
                    if self.header_used != 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VMess 块长度截断",
                        )));
                    }
                    self.ended = true;
                    return Poll::Ready(Ok(false));
                }
                self.header_used += count;
            }
            let (length, padding) = self.codec.decode_length(&self.header[..header_len])?;
            self.padding = padding;
            self.wire = vec![0; length];
            self.wire_used = 0;
            self.reading_body = true;
        }
        while self.wire_used < self.wire.len() {
            let mut buffer = ReadBuf::new(&mut self.wire[self.wire_used..]);
            ready!(Pin::new(&mut self.io).poll_read(cx, &mut buffer))?;
            let count = buffer.filled().len();
            if count == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "VMess 块正文截断",
                )));
            }
            self.wire_used += count;
        }
        // 包括空 payload：必须读取完整密文/tag/padding，验 tag 后才能宣布 EOF。
        let payload = self.codec.decode_payload(&self.wire, self.padding)?;
        self.wire = Vec::new();
        self.header_used = 0;
        self.reading_body = false;
        if payload.is_empty() {
            self.ended = true;
            return Poll::Ready(Ok(false));
        }
        self.payload = payload;
        self.payload_used = 0;
        Poll::Ready(Ok(true))
    }

    /// 仅分块模式使用；一个已验证块恰是一包，绝不跨块补齐。
    /// 如果此前通过 AsyncRead 消费了半包，则拒绝混用两种接口。
    pub async fn packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.codec.raw {
            return Err(input("VMess 裸流没有数据报边界"));
        }
        if self.payload_used != 0 && self.payload_used < self.payload.len() {
            return Err(input("VMess 不能从已部分读取的块恢复数据报边界"));
        }
        if self.payload_used == self.payload.len() {
            self.payload = Vec::new();
            self.payload_used = 0;
            if !poll_fn(|cx| self.poll_frame(cx)).await? {
                return Ok(None);
            }
        }
        Ok(Some(std::mem::take(&mut self.payload)))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Reader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(failure) = &this.failure {
            return Poll::Ready(Err(failure.error()));
        }
        if this.ended {
            return Poll::Ready(Ok(()));
        }
        if this.codec.raw {
            let before = output.filled().len();
            let result = Pin::new(&mut this.io).poll_read(cx, output);
            match &result {
                Poll::Ready(Err(error)) => this.failure = Some(Failure::from(error)),
                Poll::Ready(Ok(())) if output.filled().len() == before => this.ended = true,
                _ => {}
            }
            return result;
        }
        if this.payload_used == this.payload.len() {
            this.payload = Vec::new();
            this.payload_used = 0;
            if !ready!(this.poll_frame(cx))? {
                return Poll::Ready(Ok(()));
            }
        }
        let count = output
            .remaining()
            .min(this.payload.len() - this.payload_used);
        output.put_slice(&this.payload[this.payload_used..this.payload_used + count]);
        this.payload_used += count;
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct Writer<W> {
    io: W,
    codec: Codec,
    output: Vec<u8>,
    output_used: usize,
    closing: bool,
    terminal_encoded: bool,
    shutdown: bool,
    failure: Option<Failure>,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    fn new(io: W, codec: Codec) -> Self {
        Self {
            io,
            codec,
            output: Vec::new(),
            output_used: 0,
            closing: false,
            terminal_encoded: false,
            shutdown: false,
            failure: None,
        }
    }

    fn write_error(&self) -> io::Result<()> {
        if let Some(failure) = &self.failure {
            return Err(failure.error());
        }
        if self.closing {
            return Err(closed());
        }
        Ok(())
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        self.failure = Some(Failure::from(&error));
        self.output = Vec::new();
        error
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(failure) = &self.failure {
            return Poll::Ready(Err(failure.error()));
        }
        while self.output_used < self.output.len() {
            let count = match ready!(
                Pin::new(&mut self.io).poll_write(cx, &self.output[self.output_used..])
            ) {
                Ok(0) => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VMess 底层返回零长度写入",
                    ))));
                }
                Ok(count) => count,
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            };
            self.output_used += count;
        }
        self.output = Vec::new();
        self.output_used = 0;
        Poll::Ready(Ok(()))
    }

    fn encode(&mut self, payload: &[u8], terminal: bool) -> io::Result<()> {
        match self.codec.encode(payload, terminal) {
            Ok(output) => {
                self.output = output;
                self.output_used = 0;
                Ok(())
            }
            // 超长数据报没有消耗 SHAKE/nonce，调用方可丢包后继续。
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => Err(error),
            // 预留的最后 nonce 仍只允许 shutdown 发送，绝不再接受业务。
            Err(error)
                if self.codec.cipher.is_some()
                    && self.codec.counter == NONCE_LIMIT - 1
                    && !terminal =>
            {
                self.closing = true;
                Err(error)
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// 仅分块模式使用；空 payload 为协议终止，业务 API 明确拒绝它。
    /// 取消后已经编码的单包仍保存在 writer，可由 flush/shutdown 继续排出。
    pub async fn packet(&mut self, payload: &[u8]) -> io::Result<()> {
        self.write_error()?;
        if self.codec.raw {
            return Err(input("VMess 裸流没有数据报边界"));
        }
        if payload.is_empty() {
            return Err(input("VMess 空正文块保留为终止信号"));
        }
        poll_fn(|cx| self.poll_drain(cx)).await?;
        self.encode(payload, false)?;
        poll_fn(|cx| self.poll_drain(cx)).await
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Writer<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_error()?;
        if payload.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.codec.raw {
            let result = Pin::new(&mut this.io).poll_write(cx, payload);
            if let Poll::Ready(Err(error)) = &result {
                this.failure = Some(Failure::from(error));
            }
            if let Poll::Ready(Ok(0)) = result {
                return Poll::Ready(Err(this.fail(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "VMess 底层返回零长度写入",
                ))));
            }
            return result;
        }
        ready!(this.poll_drain(cx))?;
        let count = payload.len().min(TCP_CHUNK);
        this.encode(&payload[..count], false)?;
        // 一次成功只接受这一个有限块；其 wire 游标在后续 write/flush/shutdown 排出。
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        match Pin::new(&mut this.io).poll_flush(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.fail(error))),
            result => result,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 即使下方首次返回 Pending，也已经永久拒绝新的业务写入。
        this.closing = true;
        if this.shutdown {
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_drain(cx))?;
        if !this.terminal_encoded {
            if !this.codec.raw {
                this.encode(&[], true)?;
            }
            this.terminal_encoded = true;
        }
        ready!(this.poll_drain(cx))?;
        match Pin::new(&mut this.io).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdown = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.fail(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

type Halves<S> = (Reader<ReadHalf<S>>, Writer<WriteHalf<S>>);

pub(crate) fn split<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    security: u8,
    options: u8,
    request_key: [u8; 16],
    request_iv: [u8; 16],
) -> io::Result<Halves<S>> {
    let receive = Codec::new(
        security,
        options,
        &request_key,
        &request_iv,
        &request_key,
        &request_iv,
    )?;
    let send = Codec::new(
        security,
        options,
        &crypto::derive_response(&request_key),
        &crypto::derive_response(&request_iv),
        &request_key,
        &request_iv,
    )?;
    let (reader, writer) = tokio::io::split(io);
    Ok((Reader::new(reader, receive), Writer::new(writer, send)))
}

/// 客户端方向：写入使用请求 key/IV，读取使用派生的响应 key/IV。
///
/// 原生 UDP 使用该 split 结果的 `packet` 接口保留数据报边界。
pub(crate) fn split_client<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    security: u8,
    options: u8,
    request_key: [u8; 16],
    request_iv: [u8; 16],
) -> io::Result<Halves<S>> {
    let receive = Codec::new(
        security,
        options,
        &crypto::derive_response(&request_key),
        &crypto::derive_response(&request_iv),
        &request_key,
        &request_iv,
    )?;
    let send = Codec::new(
        security,
        options,
        &request_key,
        &request_iv,
        &request_key,
        &request_iv,
    )?;
    let (reader, writer) = tokio::io::split(io);
    Ok((Reader::new(reader, receive), Writer::new(writer, send)))
}

/// TCP 与 XUDP 共用字节流；原生 UDP 必须改用 split 后的 packet 接口。
pub(crate) struct Stream<S> {
    reader: Reader<ReadHalf<S>>,
    writer: Writer<WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    pub(crate) fn new(
        io: S,
        security: u8,
        options: u8,
        request_key: [u8; 16],
        request_iv: [u8; 16],
    ) -> io::Result<Self> {
        let (reader, writer) = split(io, security, options, request_key, request_iv)?;
        Ok(Self { reader, writer })
    }

    /// 客户端方向：写入使用请求 key/IV，读取使用派生的响应 key/IV。
    pub(crate) fn new_client(
        io: S,
        security: u8,
        options: u8,
        request_key: [u8; 16],
        request_iv: [u8; 16],
    ) -> io::Result<Self> {
        let (reader, writer) = split_client(io, security, options, request_key, request_iv)?;
        Ok(Self { reader, writer })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 与下行 write/flush 状态无关，不能因反方向 Pending 阻塞上行。
        Pin::new(&mut self.get_mut().reader).poll_read(cx, output)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, payload)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
