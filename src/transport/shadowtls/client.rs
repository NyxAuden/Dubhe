//! ShadowTLS v3 客户端记录层。
//!
//! 外层是一段真实 TLS 1.3 握手：ClientHello 的 session_id 按 ShadowTLS v3
//! 规则写入 HMAC；握手期间服务端 application_data 需要先校验 HMAC、再 XOR
//! 还原，客户端握手的原始记录则原样透传。TLS 结束后记录层切换为
//! `[23,3,3,len][4 字节 HMAC][payload]` 双向认证格式。
//!
//! 与固定上游 `sing-shadowtls` v3 一致：握手期读取链只推进 payload，
//! 认证后的读写链均为先 payload 再追加 tag。协议没有目标字段；本模块
//! 不重连、不回落普通 TLS，任何阶段失败都关闭原始流。

use std::{
    fmt,
    future::poll_fn,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll, ready},
};

use aws_lc_rs::{
    hmac::{Context as HmacContext, HMAC_SHA1_FOR_LEGACY_USE_ONLY, Key},
    rand,
};
use rustls::{
    Error as RustlsError,
    client::reality::{BuildsSessionId, Config as RealityConfig},
    crypto::ActiveKeyExchange,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    HMAC_SIZE, MAX_WRITE_RECORD, TLS_HANDSHAKE_SERVER_HELLO, TLS_HEADER_SIZE, TLS_HMAC_HEADER_SIZE,
    TLS_RANDOM_SIZE, TLS_RECORD_ALERT, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_HANDSHAKE,
    constant_time_eq, extract_server_random, kdf, send_alert, server_hello_supports_tls13, xor,
};
use crate::{
    forward::Upstream,
    tls::{ClientTls, controlled::Controlled},
    transport::DetourStream,
};

const SESSION_ID_LENGTH_INDEX: usize = 4 + 2 + TLS_RANDOM_SIZE;
const SESSION_ID_START: usize = SESSION_ID_LENGTH_INDEX + 1;
const SESSION_ID_SIZE: usize = 32;
const CLIENT_HELLO_MIN_LEN: usize = SESSION_ID_START + SESSION_ID_SIZE;

/// 按 ShadowTLS v3 规则生成 ClientHello 的 32 字节 session_id。
///
/// rustls 的 REALITY 钩子只替换 SID，不改变 TLS 语义；这里的 HMAC 与服务端
/// `verify_client_hello` 的补零计算完全一致。
struct SidBuilder {
    password: Arc<[u8]>,
}

impl SidBuilder {
    fn new(password: Arc<[u8]>) -> Self {
        Self { password }
    }

    /// `zero_hello` 是补零 SID 的完整 ClientHello 握手消息（含 4 字节握手头）。
    fn sid_for(&self, zero_hello: &[u8]) -> Result<[u8; SESSION_ID_SIZE], RustlsError> {
        if zero_hello.len() < CLIENT_HELLO_MIN_LEN {
            return Err(RustlsError::General(format!(
                "ShadowTLS ClientHello 长度不足: {}",
                zero_hello.len()
            )));
        }
        if zero_hello[SESSION_ID_LENGTH_INDEX] != SESSION_ID_SIZE as u8 {
            return Err(RustlsError::General(
                "ShadowTLS ClientHello session_id 长度无效".into(),
            ));
        }
        let mut sid = [0u8; SESSION_ID_SIZE];
        rand::fill(&mut sid[..SESSION_ID_SIZE - HMAC_SIZE])
            .map_err(|_| RustlsError::FailedToGetRandomBytes)?;
        let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, self.password.as_ref());
        let mut context = HmacContext::with_key(&key);
        context.update(&zero_hello[..SESSION_ID_START]);
        context.update(&sid[..SESSION_ID_SIZE - HMAC_SIZE]);
        context.update(&[0u8; HMAC_SIZE]);
        context.update(&zero_hello[SESSION_ID_START + SESSION_ID_SIZE..]);
        let tag = context.sign();
        sid[SESSION_ID_SIZE - HMAC_SIZE..].copy_from_slice(&tag.as_ref()[..HMAC_SIZE]);
        Ok(sid)
    }
}

impl fmt::Debug for SidBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SidBuilder([REDACTED])")
    }
}

impl BuildsSessionId for SidBuilder {
    fn build(
        &self,
        _random: [u8; TLS_RANDOM_SIZE],
        _key_share: &dyn ActiveKeyExchange,
        zero_hello: &[u8],
    ) -> Result<[u8; TLS_RANDOM_SIZE], RustlsError> {
        self.sid_for(zero_hello)
    }
}

/// TLS 之下的原始记录包装；负责握手期 SID/HMAC/XOR 与认证状态判定。
struct ShadowTlsStream<S> {
    inner: S,
    password: Arc<[u8]>,
    key: Key,
    /// 握手期 server->client 链；只推进 payload，不推进 tag。
    read_hmac: Option<HmacContext>,
    read_hmac_key: Option<[u8; 32]>,
    server_random: Option<[u8; TLS_RANDOM_SIZE]>,
    is_tls13: bool,
    authorized: bool,
    header: [u8; TLS_HEADER_SIZE],
    header_filled: usize,
    payload: Vec<u8>,
    payload_filled: usize,
    /// 单条记录的有界输出；一次 poll 只读取并处理一条记录。
    output: Vec<u8>,
    output_offset: usize,
    failed: bool,
}

/// TLS 结束后交还给内层记录层所需的握手信息。
struct HandshakeState {
    read_hmac: Option<HmacContext>,
    server_random: Option<[u8; TLS_RANDOM_SIZE]>,
    is_tls13: bool,
    authorized: bool,
}

impl<S> ShadowTlsStream<S> {
    fn new(inner: S, password: Arc<[u8]>) -> Self {
        let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, password.as_ref());
        Self {
            inner,
            password,
            key,
            read_hmac: None,
            read_hmac_key: None,
            server_random: None,
            is_tls13: false,
            authorized: false,
            header: [0; TLS_HEADER_SIZE],
            header_filled: 0,
            payload: Vec::new(),
            payload_filled: 0,
            output: Vec::new(),
            output_offset: 0,
            failed: false,
        }
    }

    /// 在严格边界上拆出底层流；记录头、负载或输出缓冲有任何残留都拒绝。
    fn finish(self) -> io::Result<(S, HandshakeState)> {
        if self.failed
            || self.header_filled != 0
            || self.payload_filled != 0
            || self.output_offset != self.output.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS 记录层不在边界，拒绝提取原始流",
            ));
        }
        Ok((
            self.inner,
            HandshakeState {
                read_hmac: self.read_hmac,
                server_random: self.server_random,
                is_tls13: self.is_tls13,
                authorized: self.authorized,
            },
        ))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS 记录层已失败",
            )));
        }
        loop {
            if this.output_offset < this.output.len() {
                let count = buf.remaining().min(this.output.len() - this.output_offset);
                if count == 0 {
                    return Poll::Ready(Ok(()));
                }
                buf.put_slice(&this.output[this.output_offset..this.output_offset + count]);
                this.output_offset += count;
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            this.output.clear();
            this.output_offset = 0;

            while this.header_filled < TLS_HEADER_SIZE {
                let mut read = ReadBuf::new(&mut this.header[this.header_filled..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(if this.header_filled == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ShadowTLS 记录头截断",
                        ))
                    });
                }
                this.header_filled += count;
            }
            let length = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
            if this.payload.len() != length {
                this.payload.resize(length, 0);
            }
            this.payload_filled = 0;
            while this.payload_filled < length {
                let mut read = ReadBuf::new(&mut this.payload[this.payload_filled..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ShadowTLS 记录截断",
                    )));
                }
                this.payload_filled += count;
            }

            // 默认原样透传；只有认证通过的 application_data 才重建记录。
            this.output.clear();
            this.output.reserve(TLS_HEADER_SIZE + length);
            this.output.extend_from_slice(&this.header);
            this.output.extend_from_slice(&this.payload);

            if this.header[0] == TLS_RECORD_HANDSHAKE
                && this.read_hmac.is_none()
                && this.payload.first().copied() == Some(TLS_HANDSHAKE_SERVER_HELLO)
            {
                // 首个 ServerHello/HRR 只 seed 一次；后续 ServerHello 不重置链。
                let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + length);
                frame.extend_from_slice(&this.header);
                frame.extend_from_slice(&this.payload);
                if let Some(server_random) = extract_server_random(&frame) {
                    let mut read_hmac = HmacContext::with_key(&this.key);
                    read_hmac.update(&server_random);
                    this.read_hmac_key = Some(kdf(this.password.as_ref(), &server_random));
                    this.is_tls13 = server_hello_supports_tls13(&frame);
                    if !this.is_tls13 {
                        this.authorized = true;
                    }
                    this.server_random = Some(server_random);
                    this.read_hmac = Some(read_hmac);
                }
            } else if this.header[0] == TLS_RECORD_APPLICATION_DATA {
                this.authorized = false;
                // 与上游 `len(buffer) > tlsHmacHeaderSize` 一致：完整记录
                // （5 字节记录头 + payload）必须严格大于 9 字节才校验。
                let has_chain = this.read_hmac.is_some()
                    && this.read_hmac_key.is_some()
                    && this.payload.len() > HMAC_SIZE;
                if has_chain {
                    let tag_ok = {
                        let mut check = this.read_hmac.as_ref().unwrap().clone();
                        check.update(&this.payload[HMAC_SIZE..]);
                        let tag = check.sign();
                        constant_time_eq(&tag.as_ref()[..HMAC_SIZE], &this.payload[..HMAC_SIZE])
                    };
                    if !tag_ok {
                        // 失败关闭：不把未经认证的记录交给上层。
                        this.failed = true;
                        this.output.clear();
                        this.output_offset = 0;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ShadowTLS 记录校验失败",
                        )));
                    }
                    // 与上游 streamWrapper 一致：读取链只推进 payload。
                    this.read_hmac
                        .as_mut()
                        .unwrap()
                        .update(&this.payload[HMAC_SIZE..]);
                    let mut plain = this.payload[HMAC_SIZE..].to_vec();
                    xor(&mut plain, this.read_hmac_key.as_ref().unwrap());
                    this.output.clear();
                    this.output.push(TLS_RECORD_APPLICATION_DATA);
                    this.output.extend_from_slice(&[3, 3]);
                    let output_len = match u16::try_from(plain.len()) {
                        Ok(value) => value,
                        Err(_) => {
                            this.failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "ShadowTLS 记录长度溢出",
                            )));
                        }
                    };
                    this.output.extend_from_slice(&output_len.to_be_bytes());
                    this.output.extend_from_slice(&plain);
                    this.authorized = true;
                }
            }
            this.header_filled = 0;
            this.payload_filled = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // TLS 握手记录（ClientHello/Finished 等）必须原样透传，不能加 HMAC。
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

/// 认证后的内层记录层：双向 HMAC 链与 16 KiB 分片。
struct ClientVerified<S> {
    inner: S,
    /// server->client 链，seed 为 `server_random || "S"`。
    read_hmac: HmacContext,
    /// client->server 链，seed 为 `server_random || "C"`。
    write_hmac: HmacContext,
    /// 握手期 server->client 链的最终状态；只用于丢弃首条残留记录。
    hmac_ignore: Option<HmacContext>,
    buffer: Vec<u8>,
    offset: usize,
    header: [u8; TLS_HEADER_SIZE],
    header_filled: usize,
    payload: Vec<u8>,
    payload_filled: usize,
    pending: Vec<u8>,
    pending_offset: usize,
    pending_len: usize,
    read_failed: bool,
    shutdown_started: bool,
}

impl<S> ClientVerified<S> {
    fn new(
        inner: S,
        key: Key,
        server_random: [u8; TLS_RANDOM_SIZE],
        hmac_ignore: Option<HmacContext>,
    ) -> Self {
        let mut read_hmac = HmacContext::with_key(&key);
        read_hmac.update(&server_random);
        read_hmac.update(b"S");
        let mut write_hmac = HmacContext::with_key(&key);
        write_hmac.update(&server_random);
        write_hmac.update(b"C");
        Self {
            inner,
            read_hmac,
            write_hmac,
            hmac_ignore,
            buffer: Vec::new(),
            offset: 0,
            header: [0; TLS_HEADER_SIZE],
            header_filled: 0,
            payload: Vec::new(),
            payload_filled: 0,
            pending: Vec::new(),
            pending_offset: 0,
            pending_len: 0,
            read_failed: false,
            shutdown_started: false,
        }
    }

    fn reset_record(&mut self) {
        self.header_filled = 0;
        self.payload_filled = 0;
    }
}

impl<S: DetourStream> DetourStream for ClientVerified<S> {
    fn abort_linger(&self) {
        self.inner.abort_linger();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientVerified<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.read_failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS 内层记录层已失败",
            )));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.offset < this.buffer.len() {
                let count = buf.remaining().min(this.buffer.len() - this.offset);
                if count == 0 {
                    return Poll::Ready(Ok(()));
                }
                buf.put_slice(&this.buffer[this.offset..this.offset + count]);
                this.offset += count;
                return Poll::Ready(Ok(()));
            }
            this.buffer.clear();
            this.offset = 0;

            while this.header_filled < TLS_HEADER_SIZE {
                let mut read = ReadBuf::new(&mut this.header[this.header_filled..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(if this.header_filled == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ShadowTLS 内层记录头截断",
                        ))
                    });
                }
                this.header_filled += count;
            }
            let length = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
            if this.payload.len() != length {
                this.payload.resize(length, 0);
            }
            this.payload_filled = 0;
            while this.payload_filled < length {
                let mut read = ReadBuf::new(&mut this.payload[this.payload_filled..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ShadowTLS 内层记录截断",
                    )));
                }
                this.payload_filled += count;
            }

            match this.header[0] {
                TLS_RECORD_ALERT => {
                    // alert 不是正常 EOF，必须让上层看到连接异常。
                    this.read_failed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "ShadowTLS 对端发送 alert",
                    )));
                }
                TLS_RECORD_APPLICATION_DATA => {
                    if length < HMAC_SIZE || this.header[1] != 3 || this.header[2] != 3 {
                        this.read_failed = true;
                        if this.pending.is_empty() {
                            send_alert(&mut this.inner, cx);
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ShadowTLS 内层记录类型或长度无效",
                        )));
                    }
                    // 握手期残留记录使用旧链（payload-only）。匹配时保留并推进旧链，
                    // 以连续丢弃多张 NewSessionTicket 等残留记录；首次不匹配才
                    // 丢弃旧链并回到认证后的 payload+tag 链。
                    let mut ignore_matched = false;
                    let mut ignore_mismatch = false;
                    if let Some(ignore) = this.hmac_ignore.as_mut() {
                        let mut check = ignore.clone();
                        check.update(&this.payload[HMAC_SIZE..]);
                        let tag = check.sign();
                        if constant_time_eq(&tag.as_ref()[..HMAC_SIZE], &this.payload[..HMAC_SIZE])
                        {
                            ignore.update(&this.payload[HMAC_SIZE..]);
                            ignore_matched = true;
                        } else {
                            ignore_mismatch = true;
                        }
                    }
                    if ignore_mismatch {
                        this.hmac_ignore = None;
                    }
                    if ignore_matched {
                        this.reset_record();
                        continue;
                    }
                    let tag_ok = {
                        let mut check = this.read_hmac.clone();
                        check.update(&this.payload[HMAC_SIZE..]);
                        let tag = check.sign();
                        constant_time_eq(&tag.as_ref()[..HMAC_SIZE], &this.payload[..HMAC_SIZE])
                    };
                    if !tag_ok {
                        this.read_failed = true;
                        if this.pending.is_empty() {
                            send_alert(&mut this.inner, cx);
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ShadowTLS 内层应用数据校验失败",
                        )));
                    }
                    // 认证后的读取链：先 payload，再 tag。
                    this.read_hmac.update(&this.payload[HMAC_SIZE..]);
                    this.read_hmac.update(&this.payload[..HMAC_SIZE]);
                    this.buffer.extend_from_slice(&this.payload[HMAC_SIZE..]);
                    this.reset_record();
                }
                _ => {
                    this.read_failed = true;
                    if this.pending.is_empty() {
                        send_alert(&mut this.inner, cx);
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ShadowTLS 内层记录类型无效",
                    )));
                }
            }
            if this.buffer.is_empty() {
                continue;
            }
            let count = buf.remaining().min(this.buffer.len());
            buf.put_slice(&this.buffer[..count]);
            this.offset = count;
            return Poll::Ready(Ok(()));
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ClientVerified<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ShadowTLS 内层写方向已关闭",
            )));
        }
        if this.pending.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let count = buf.len().min(MAX_WRITE_RECORD);
            let payload = &buf[..count];
            let mut chain = this.write_hmac.clone();
            chain.update(payload);
            let tag = chain.sign();
            // 认证后的写入链：先 payload，再 tag。
            this.write_hmac.update(payload);
            this.write_hmac.update(&tag.as_ref()[..HMAC_SIZE]);
            this.pending.clear();
            this.pending.reserve(TLS_HMAC_HEADER_SIZE + count);
            this.pending.push(TLS_RECORD_APPLICATION_DATA);
            this.pending.extend_from_slice(&[3, 3]);
            let length = match u16::try_from(count + HMAC_SIZE) {
                Ok(value) => value,
                Err(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ShadowTLS 内层记录长度溢出",
                    )));
                }
            };
            this.pending.extend_from_slice(&length.to_be_bytes());
            this.pending.extend_from_slice(&tag.as_ref()[..HMAC_SIZE]);
            this.pending.extend_from_slice(payload);
            this.pending_offset = 0;
            this.pending_len = count;
        }
        // pending 未排空时不接收新数据；完成后再返回本段长度。
        ready!(poll_drain_pending(
            &mut this.inner,
            &this.pending,
            &mut this.pending_offset,
            cx
        ))?;
        let count = this.pending_len;
        this.pending.clear();
        this.pending_offset = 0;
        this.pending_len = 0;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        ready!(poll_drain_pending(
            &mut this.inner,
            &this.pending,
            &mut this.pending_offset,
            cx
        ))?;
        this.pending.clear();
        this.pending_offset = 0;
        this.pending_len = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        let this = self.get_mut();
        this.shutdown_started = true;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn poll_drain_pending<S: AsyncWrite + Unpin>(
    inner: &mut S,
    pending: &[u8],
    offset: &mut usize,
    cx: &mut TaskContext<'_>,
) -> Poll<io::Result<()>> {
    while *offset < pending.len() {
        match Pin::new(&mut *inner).poll_write(cx, &pending[*offset..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ShadowTLS 内层记录写入失败",
                )));
            }
            Poll::Ready(Ok(written)) => *offset += written,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

/// 校验真实 TLS 层的认证结果；v3 客户端只接受 TLS 1.3 外层。
fn take_authenticated(state: HandshakeState) -> io::Result<([u8; TLS_RANDOM_SIZE], HmacContext)> {
    if !state.is_tls13 {
        // TLS 1.2 回落无法完成 v3 application_data 的 HMAC 证明。
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ShadowTLS 外层未协商 TLS 1.3",
        ));
    }
    if !state.authorized {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ShadowTLS 流量未通过认证",
        ));
    }
    match (state.server_random, state.read_hmac) {
        (Some(server_random), Some(read_hmac)) => Ok((server_random, read_hmac)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowTLS 握手状态不完整",
        )),
    }
}

/// 固定上游 ShadowTLS v3 出站。
pub(crate) struct ShadowTlsClient {
    password: Arc<[u8]>,
    tls: Arc<ClientTls>,
}

impl fmt::Debug for ShadowTlsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShadowTlsClient { password: [REDACTED] }")
    }
}

impl ShadowTlsClient {
    pub(crate) fn new(password: &str, tls: Arc<ClientTls>) -> io::Result<Arc<Self>> {
        let password = password.as_bytes();
        if password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowTLS 密码不得为空",
            ));
        }
        if password.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowTLS 密码超过 4096 字节",
            ));
        }
        Ok(Arc::new(Self {
            password: Arc::from(password),
            tls,
        }))
    }

    /// 在已建立的 TCP 流上完成外层 TLS 与 ShadowTLS v3 认证。
    ///
    /// 只能通过记录层切换拿到真实 TLS 流，不能使用 `tokio_rustls`；
    /// 任何阶段失败都会丢弃 `stream`，从而关闭底层连接。
    pub(crate) async fn connect(&self, stream: Upstream) -> io::Result<Upstream> {
        let password = self.password.clone();
        let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, password.as_ref());
        let mut config = (*self.tls.config).clone();
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        config.alpn_protocols.clear();
        config.reality = Some(Arc::new(RealityConfig::new_allow_hrr(Arc::new(
            SidBuilder::new(password.clone()),
        ))));

        let stream = ShadowTlsStream::new(stream, password);
        let mut controlled =
            Controlled::connect(stream, Arc::new(config), self.tls.server_name.clone()).await?;
        controlled.write_direct()?;
        controlled.read_direct()?;
        // write_direct 只在 flush 屏障后才真正切换到原始写方向。
        poll_fn(|cx| Pin::new(&mut controlled).poll_flush(cx)).await?;
        let (raw, state) = controlled.into_raw()?.finish()?;
        let (server_random, hmac_ignore) = take_authenticated(state)?;
        tracing::debug!(event = "shadowtls_client_authenticated");

        let (inner, local_addr, session) = raw.into_parts();
        let verified = ClientVerified::new(inner, key, server_random, Some(hmac_ignore));
        // HMAC 上下文只 Send 不 Sync；锁包装同时保留 local_addr 与管理句柄。
        Ok(Upstream::from_parts_send(verified, local_addr, session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::shadowtls::{
        HMAC_SIZE, MAX_WRITE_RECORD, TLS_HANDSHAKE_SERVER_HELLO, TLS_HEADER_SIZE, TLS_RANDOM_SIZE,
        TLS_RECORD_ALERT, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_HANDSHAKE,
    };
    use aws_lc_rs::hmac::{Context as HmacContext, Key, sign as hmac_sign};
    use std::{io, sync::Arc};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    fn password_key(password: &[u8]) -> Key {
        Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, password)
    }

    fn zero_hello(session_id_len: u8, extra: usize) -> Vec<u8> {
        // 4 字节握手头 + 2 字节版本 + 32 字节 random + 1 字节 SID 长度 + 32 字节 SID。
        let mut hello = vec![0u8; CLIENT_HELLO_MIN_LEN + extra];
        hello[0] = 1;
        let handshake_len = u16::try_from(hello.len() - 4).unwrap();
        hello[1..3].copy_from_slice(&handshake_len.to_be_bytes());
        hello[4] = 3;
        hello[5] = 3;
        for (index, byte) in hello[6..SESSION_ID_LENGTH_INDEX].iter_mut().enumerate() {
            *byte = 0x11u8.wrapping_add(index as u8);
        }
        hello[SESSION_ID_LENGTH_INDEX] = session_id_len;
        for (index, byte) in hello[SESSION_ID_START + SESSION_ID_SIZE..]
            .iter_mut()
            .enumerate()
        {
            *byte = 0x80u8.wrapping_add(index as u8);
        }
        hello
    }

    fn server_hello(random: [u8; TLS_RANDOM_SIZE], tls13: bool) -> Vec<u8> {
        let extension_len = if tls13 { 6usize } else { 0 };
        let total = 49 + extension_len;
        let mut frame = vec![0u8; total];
        frame[0] = TLS_RECORD_HANDSHAKE;
        frame[1] = 3;
        frame[2] = 3;
        let record_len = u16::try_from(total - TLS_HEADER_SIZE).unwrap();
        frame[3..5].copy_from_slice(&record_len.to_be_bytes());
        frame[5] = TLS_HANDSHAKE_SERVER_HELLO;
        let handshake_len = u32::try_from(total - 9).unwrap();
        frame[6..9].copy_from_slice(&handshake_len.to_be_bytes()[1..]);
        frame[9] = 3;
        frame[10] = 3;
        frame[11..43].copy_from_slice(&random);
        frame[43] = 0;
        if tls13 {
            frame[47..49].copy_from_slice(&6u16.to_be_bytes());
            frame[49..51].copy_from_slice(&43u16.to_be_bytes());
            frame[51..53].copy_from_slice(&2u16.to_be_bytes());
            frame[53..55].copy_from_slice(&0x0304u16.to_be_bytes());
        }
        frame
    }

    fn application_record(payload: &[u8], tag: &[u8]) -> Vec<u8> {
        let mut record = vec![TLS_RECORD_APPLICATION_DATA, 3, 3];
        let length = u16::try_from(payload.len() + tag.len()).unwrap();
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(tag);
        record.extend_from_slice(payload);
        record
    }

    fn shadow_wire(
        payload: &[u8],
        server_random: &[u8; TLS_RANDOM_SIZE],
        password: &[u8],
    ) -> Vec<u8> {
        let mut wire = payload.to_vec();
        xor(&mut wire, &kdf(password, server_random));
        wire
    }

    fn client_verified(
        capacity: usize,
        key: &Key,
        server_random: [u8; TLS_RANDOM_SIZE],
        hmac_ignore: Option<HmacContext>,
    ) -> (DuplexStream, ClientVerified<DuplexStream>) {
        let (peer, inner) = duplex(capacity);
        (
            peer,
            ClientVerified::new(inner, key.clone(), server_random, hmac_ignore),
        )
    }

    fn read_chain(key: &Key, server_random: &[u8; TLS_RANDOM_SIZE]) -> HmacContext {
        let mut chain = HmacContext::with_key(key);
        chain.update(server_random);
        chain.update(b"S");
        chain
    }

    fn write_chain(key: &Key, server_random: &[u8; TLS_RANDOM_SIZE]) -> HmacContext {
        let mut chain = HmacContext::with_key(key);
        chain.update(server_random);
        chain.update(b"C");
        chain
    }

    async fn read_wire_record<R: AsyncRead + Unpin>(reader: &mut R) -> (Vec<u8>, Vec<u8>) {
        let mut header = [0u8; TLS_HEADER_SIZE];
        reader.read_exact(&mut header).await.unwrap();
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).await.unwrap();
        (header.to_vec(), body)
    }

    #[test]
    fn sid_builder_matches_manual_hmac_and_rejects_bad_shape() {
        let password = b"shadowtls-client-password";
        let builder = SidBuilder::new(Arc::from(&password[..]));
        let hello = zero_hello(32, 7);

        let sid = builder.sid_for(&hello).unwrap();
        assert!(
            sid[..SESSION_ID_SIZE - HMAC_SIZE]
                .iter()
                .any(|byte| *byte != 0),
            "28 字节随机部分不得全零"
        );

        let mut input = Vec::new();
        input.extend_from_slice(&hello[..SESSION_ID_START]);
        input.extend_from_slice(&sid[..SESSION_ID_SIZE - HMAC_SIZE]);
        input.extend_from_slice(&[0u8; HMAC_SIZE]);
        input.extend_from_slice(&hello[SESSION_ID_START + SESSION_ID_SIZE..]);
        let expected = hmac_sign(&password_key(password), &input);
        assert_eq!(
            &sid[SESSION_ID_SIZE - HMAC_SIZE..],
            &expected.as_ref()[..HMAC_SIZE]
        );

        let mut short = zero_hello(32, 0);
        short.truncate(CLIENT_HELLO_MIN_LEN - 1);
        assert!(builder.sid_for(&short).is_err());
        assert!(builder.sid_for(&zero_hello(31, 7)).is_err());
        assert!(builder.sid_for(&zero_hello(32, 0)).is_ok());
    }

    #[tokio::test]
    async fn shadow_stream_seeds_once_and_unwraps_application_data() {
        let (mut peer, inner) = duplex(65536);
        let password: Arc<[u8]> = Arc::from(&b"stream-password"[..]);
        let mut stream = ShadowTlsStream::new(inner, password.clone());
        let server_random = [0x42u8; TLS_RANDOM_SIZE];
        let hello = server_hello(server_random, true);
        peer.write_all(&hello).await.unwrap();
        let mut passthrough = vec![0u8; hello.len()];
        stream.read_exact(&mut passthrough).await.unwrap();
        assert_eq!(passthrough, hello);

        let mut chain = HmacContext::with_key(&password_key(&password));
        chain.update(&server_random);
        let plaintext = b"encrypted-tls-record";
        let wire = shadow_wire(plaintext, &server_random, &password);
        let mut check = chain.clone();
        check.update(&wire);
        let tag = check.sign();
        chain.update(&wire);
        let record = application_record(&wire, &tag.as_ref()[..HMAC_SIZE]);
        peer.write_all(&record).await.unwrap();
        let mut output = vec![0u8; TLS_HEADER_SIZE + plaintext.len()];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(
            &output[..TLS_HEADER_SIZE],
            &[
                TLS_RECORD_APPLICATION_DATA,
                3,
                3,
                u16::try_from(plaintext.len()).unwrap().to_be_bytes()[0],
                u16::try_from(plaintext.len()).unwrap().to_be_bytes()[1],
            ]
        );
        assert_eq!(&output[TLS_HEADER_SIZE..], plaintext);

        // 第二个 ServerHello（例如 HRR 后的真实 ServerHello）不得重置读取链。
        let second_hello = server_hello([0x24u8; TLS_RANDOM_SIZE], true);
        peer.write_all(&second_hello).await.unwrap();
        let mut passthrough = vec![0u8; second_hello.len()];
        stream.read_exact(&mut passthrough).await.unwrap();
        assert_eq!(passthrough, second_hello);

        let second_plaintext = b"second-payload";
        let second_wire = shadow_wire(second_plaintext, &server_random, &password);
        let mut check = chain.clone();
        check.update(&second_wire);
        let second_tag = check.sign();
        let second_record = application_record(&second_wire, &second_tag.as_ref()[..HMAC_SIZE]);
        peer.write_all(&second_record).await.unwrap();
        let mut output = vec![0u8; TLS_HEADER_SIZE + second_plaintext.len()];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output[TLS_HEADER_SIZE..], second_plaintext);

        let (_inner, state) = stream.finish().unwrap();
        assert!(state.is_tls13);
        assert!(state.authorized);
        assert_eq!(state.server_random, Some(server_random));
        assert!(state.read_hmac.is_some());
    }

    #[tokio::test]
    async fn shadow_stream_rejects_tampered_application_data() {
        let (mut peer, inner) = duplex(4096);
        let password: Arc<[u8]> = Arc::from(&b"pw"[..]);
        let mut stream = ShadowTlsStream::new(inner, password.clone());
        let server_random = [0x11u8; TLS_RANDOM_SIZE];
        let hello = server_hello(server_random, true);
        peer.write_all(&hello).await.unwrap();
        let mut passthrough = vec![0u8; hello.len()];
        stream.read_exact(&mut passthrough).await.unwrap();

        let wire = shadow_wire(b"data", &server_random, &password);
        let record = application_record(&wire, &[0u8; HMAC_SIZE]);
        peer.write_all(&record).await.unwrap();
        let mut output = [0u8; 1];
        let error = stream.read_exact(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn tls12_server_hello_is_rejected_after_wrapper_auth() {
        let (mut peer, inner) = duplex(4096);
        let password: Arc<[u8]> = Arc::from(&b"pw"[..]);
        let mut stream = ShadowTlsStream::new(inner, password);
        let hello = server_hello([0x31u8; TLS_RANDOM_SIZE], false);
        peer.write_all(&hello).await.unwrap();
        let mut passthrough = vec![0u8; hello.len()];
        stream.read_exact(&mut passthrough).await.unwrap();
        let (_inner, state) = stream.finish().unwrap();
        // streamWrapper 在非 TLS 1.3 ServerHello 上会把 authorized 置真，
        // 但客户端策略仍必须拒绝 TLS 1.2 外层。
        assert!(!state.is_tls13);
        assert!(state.authorized);
        let error = take_authenticated(state).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);

        let unauthorized = HandshakeState {
            read_hmac: None,
            server_random: Some([0u8; TLS_RANDOM_SIZE]),
            is_tls13: true,
            authorized: false,
        };
        let error = take_authenticated(unauthorized).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn verified_read_uses_read_chain() {
        let key = password_key(b"verified-password");
        let server_random = [0x5Au8; TLS_RANDOM_SIZE];
        let (mut peer, mut verified) = client_verified(8192, &key, server_random, None);
        let mut chain = read_chain(&key, &server_random);

        let first = b"first";
        let mut check = chain.clone();
        check.update(first);
        let first_tag = check.sign();
        chain.update(first);
        chain.update(&first_tag.as_ref()[..HMAC_SIZE]);
        peer.write_all(&application_record(first, &first_tag.as_ref()[..HMAC_SIZE]))
            .await
            .unwrap();
        let mut got = vec![0u8; first.len()];
        verified.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], &first[..]);

        let second = b"second-record";
        let mut check = chain.clone();
        check.update(second);
        let second_tag = check.sign();
        peer.write_all(&application_record(
            second,
            &second_tag.as_ref()[..HMAC_SIZE],
        ))
        .await
        .unwrap();
        let mut got = vec![0u8; second.len()];
        verified.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], &second[..]);
    }

    #[tokio::test]
    async fn verified_ignores_consecutive_old_chain_records() {
        let key = password_key(b"ignore-password");
        let server_random = [0x77u8; TLS_RANDOM_SIZE];
        let mut ignore = HmacContext::with_key(&key);
        ignore.update(&server_random);
        let (mut peer, mut verified) = client_verified(8192, &key, server_random, Some(ignore));
        let mut chain = read_chain(&key, &server_random);
        let mut stale_chain = HmacContext::with_key(&key);
        stale_chain.update(&server_random);

        // 两张连续的握手期残留记录（例如 TLS 1.3 NewSessionTicket）都必须
        // 由旧链丢弃，旧链跨记录继续推进，不能只丢第一张。
        let stale_first = b"handshake-record-1";
        stale_chain.update(stale_first);
        let stale_first_tag = stale_chain.clone().sign();
        let stale_second = b"handshake-record-2";
        stale_chain.update(stale_second);
        let stale_second_tag = stale_chain.sign();
        let fresh = b"post-auth";
        let mut check = chain.clone();
        check.update(fresh);
        let fresh_tag = check.sign();
        chain.update(fresh);
        chain.update(&fresh_tag.as_ref()[..HMAC_SIZE]);

        peer.write_all(&application_record(
            stale_first,
            &stale_first_tag.as_ref()[..HMAC_SIZE],
        ))
        .await
        .unwrap();
        peer.write_all(&application_record(
            stale_second,
            &stale_second_tag.as_ref()[..HMAC_SIZE],
        ))
        .await
        .unwrap();
        peer.write_all(&application_record(fresh, &fresh_tag.as_ref()[..HMAC_SIZE]))
            .await
            .unwrap();
        let mut got = vec![0u8; fresh.len()];
        verified.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], &fresh[..]);
    }

    #[tokio::test]
    async fn verified_write_uses_write_chain_and_chunks_at_16k() {
        let key = password_key(b"write-password");
        let server_random = [0x19u8; TLS_RANDOM_SIZE];
        let (mut peer, mut verified) = client_verified(131072, &key, server_random, None);
        let mut chain = write_chain(&key, &server_random);

        verified.write_all(b"reply").await.unwrap();
        let (header, body) = read_wire_record(&mut peer).await;
        assert_eq!(&header, &[TLS_RECORD_APPLICATION_DATA, 3, 3, 0, 9]);
        let mut check = chain.clone();
        check.update(b"reply");
        let tag = check.sign();
        assert_eq!(&body[..HMAC_SIZE], &tag.as_ref()[..HMAC_SIZE]);
        assert_eq!(&body[HMAC_SIZE..], b"reply");
        chain.update(b"reply");
        chain.update(&tag.as_ref()[..HMAC_SIZE]);

        verified.write_all(b"next").await.unwrap();
        let (header, body) = read_wire_record(&mut peer).await;
        assert_eq!(&header, &[TLS_RECORD_APPLICATION_DATA, 3, 3, 0, 8]);
        let mut check = chain.clone();
        check.update(b"next");
        let tag = check.sign();
        assert_eq!(&body[..HMAC_SIZE], &tag.as_ref()[..HMAC_SIZE]);
        assert_eq!(&body[HMAC_SIZE..], b"next");
        chain.update(b"next");
        chain.update(&tag.as_ref()[..HMAC_SIZE]);

        // 大段写入必须拆成 16384 字节的记录，且链跨记录推进。
        let data = vec![0xA5u8; 20_000];
        verified.write_all(&data).await.unwrap();
        let mut expected = chain;
        let mut check = expected.clone();
        check.update(&data[..MAX_WRITE_RECORD]);
        let first_tag = check.sign();
        expected.update(&data[..MAX_WRITE_RECORD]);
        expected.update(&first_tag.as_ref()[..HMAC_SIZE]);
        let (first_header, first_body) = read_wire_record(&mut peer).await;
        assert_eq!(
            &first_header,
            &[
                TLS_RECORD_APPLICATION_DATA,
                3,
                3,
                u16::try_from(MAX_WRITE_RECORD + HMAC_SIZE)
                    .unwrap()
                    .to_be_bytes()[0],
                u16::try_from(MAX_WRITE_RECORD + HMAC_SIZE)
                    .unwrap()
                    .to_be_bytes()[1],
            ]
        );
        assert_eq!(&first_body[..HMAC_SIZE], &first_tag.as_ref()[..HMAC_SIZE]);
        assert_eq!(&first_body[HMAC_SIZE..], &data[..MAX_WRITE_RECORD]);

        let rest = &data[MAX_WRITE_RECORD..];
        let mut check = expected.clone();
        check.update(rest);
        let second_tag = check.sign();
        let (second_header, second_body) = read_wire_record(&mut peer).await;
        assert_eq!(
            &second_header,
            &[
                TLS_RECORD_APPLICATION_DATA,
                3,
                3,
                u16::try_from(rest.len() + HMAC_SIZE).unwrap().to_be_bytes()[0],
                u16::try_from(rest.len() + HMAC_SIZE).unwrap().to_be_bytes()[1],
            ]
        );
        assert_eq!(&second_body[..HMAC_SIZE], &second_tag.as_ref()[..HMAC_SIZE]);
        assert_eq!(&second_body[HMAC_SIZE..], rest);
    }

    #[tokio::test]
    async fn verified_rejects_bad_tag_type_and_alert() {
        let key = password_key(b"error-password");
        let server_random = [0x66u8; TLS_RANDOM_SIZE];

        // 坏 tag。
        let (mut peer, mut verified) = client_verified(4096, &key, server_random, None);
        let mut record = application_record(b"x", &[0u8; HMAC_SIZE]);
        record[TLS_HEADER_SIZE] ^= 0xff;
        peer.write_all(&record).await.unwrap();
        let mut output = [0u8; 1];
        let error = verified.read_exact(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        // 非 application_data 的明文记录。
        let (mut peer, mut verified) = client_verified(4096, &key, server_random, None);
        peer.write_all(&[TLS_RECORD_HANDSHAKE, 3, 3, 0, HMAC_SIZE as u8, 0, 0, 0, 0])
            .await
            .unwrap();
        let error = verified.read_exact(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        // alert 不能被当作正常 EOF。
        let (mut peer, mut verified) = client_verified(4096, &key, server_random, None);
        peer.write_all(&[TLS_RECORD_ALERT, 3, 3, 0, 2, 1, 0])
            .await
            .unwrap();
        let error = verified.read_exact(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[test]
    fn client_password_bounds_and_debug_redaction() {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let tls = Arc::new(ClientTls {
            config: Arc::new(config),
            server_name: crate::tls::parse_server_name("example.com").unwrap(),
        });
        assert!(ShadowTlsClient::new("", tls.clone()).is_err());
        assert!(ShadowTlsClient::new(&"a".repeat(4097), tls.clone()).is_err());
        let client = ShadowTlsClient::new("super-secret", tls).unwrap();
        assert!(!format!("{client:?}").contains("super-secret"));
    }
}
