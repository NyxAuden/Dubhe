//! AnyTLS 出站客户端的共享线格式与低层单流适配；运行时会话池见 `pool`。
//!
//! 低层已提供承载的调用发送密码前导、Settings 与 SYN/目标PSH，随后按正式
//! 帧收发。Context生产路径由独立池持续分派控制/业务ID并复用空闲TLS会话；
//! 不把整流FIN误称TCP半关闭。两条路径共用前导/地址/帧与padding算法。

use super::anytls_padding::{PaddingState, SharedScheme};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::session::{Host, Target};

const PASSWORD_LEN: usize = 32;
const FRAME_OVERHEAD: usize = 7;
const COMMAND_SYN: u8 = 1;
const COMMAND_PSH: u8 = 2;
const COMMAND_FIN: u8 = 3;
const COMMAND_SETTINGS: u8 = 4;
const COMMAND_SYNACK: u8 = 7;
const COMMAND_SERVER_SETTINGS: u8 = 10;
const COMMAND_ALERT: u8 = 5;
const COMMAND_UPDATE_PADDING_SCHEME: u8 = 6;
const COMMAND_HEART_REQUEST: u8 = 8;
const COMMAND_HEART_RESPONSE: u8 = 9;
const STREAM_ID: u32 = 1;
const MAX_FRAME: usize = u16::MAX as usize;

#[cfg(test)]
mod tests;

fn frame(command: u8, id: u32, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "AnyTLS 帧过长"));
    }
    let mut out = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    out.push(command);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn address(target: &Target) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    match &target.host {
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 255
                || !domain.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "AnyTLS 目标域名无效",
                ));
            }
            out.push(3);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

pub(crate) mod pool;

fn prologue(password: &str, scheme: &super::anytls_padding::Scheme) -> io::Result<Vec<u8>> {
    let padding_len = scheme.handshake_size()?;
    let digest: [u8; PASSWORD_LEN] = Sha256::digest(password.as_bytes()).into();
    let mut prologue = Vec::with_capacity(PASSWORD_LEN + 2 + padding_len);
    prologue.extend_from_slice(&digest);
    prologue.extend_from_slice(&(padding_len as u16).to_be_bytes());
    prologue.resize(PASSWORD_LEN + 2 + padding_len, 0);
    Ok(prologue)
}
fn settings(scheme: &super::anytls_padding::Scheme) -> io::Result<Vec<u8>> {
    frame(
        COMMAND_SETTINGS,
        0,
        format!("client=dubhe\npadding-md5={}\nv=2", scheme.md5()).as_bytes(),
    )
}

/// 在已完成的TLS流上发送正式认证/方案声明与目标，方案按出站独立共享。
pub(crate) async fn connect_with_scheme<S>(
    mut stream: S,
    target: &Target,
    password: &str,
    schemes: Arc<SharedScheme>,
) -> io::Result<ClientStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let scheme = schemes.snapshot();
    stream.write_all(&prologue(password, &scheme)?).await?;
    let mut first = settings(&scheme)?;
    first.extend(frame(COMMAND_SYN, STREAM_ID, &[])?);
    first.extend(frame(COMMAND_PSH, STREAM_ID, &address(target)?)?);
    let mut padding = PaddingState::default();
    for block in padding.shape(&first, &scheme)? {
        stream.write_all(&block).await?;
    }
    stream.flush().await?;
    let (read, write) = tokio::io::split(stream);
    Ok(ClientStream {
        read,
        write,
        buffer: Vec::new(),
        offset: 0,
        closed: false,
        pending: Vec::new(),
        pending_block: 0,
        pending_offset: 0,
        schemes,
        padding,
        header: [0; FRAME_OVERHEAD],
        header_offset: 0,
        payload: Vec::new(),
        payload_offset: 0,
        failure: None,
        peer_fin: false,
        shutdown_started: false,
        fin_queued: false,
        shutdown_done: false,
    })
}

pub(crate) struct ClientStream<S> {
    read: tokio::io::ReadHalf<S>,
    write: tokio::io::WriteHalf<S>,
    buffer: Vec<u8>,
    offset: usize,
    closed: bool,
    pending: Vec<Vec<u8>>,
    pending_block: usize,
    pending_offset: usize,
    schemes: Arc<SharedScheme>,
    padding: PaddingState,
    /// header/payload 的已读游标跨 Poll::Pending 保留，不能在栈上重建。
    header: [u8; FRAME_OVERHEAD],
    header_offset: usize,
    payload: Vec<u8>,
    payload_offset: usize,
    failure: Option<io::ErrorKind>,
    /// 对端已发 FIN；本地关闭时不再回送 FIN。
    peer_fin: bool,
    shutdown_started: bool,
    fin_queued: bool,
    shutdown_done: bool,
}

impl<S: AsyncRead + Unpin> ClientStream<S> {
    /// 跨 `Poll::Pending` 保留帧头与载荷游标；不能把半帧留在栈上丢弃。
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            while self.header_offset < FRAME_OVERHEAD {
                let mut read = ReadBuf::new(&mut self.header[self.header_offset..]);
                ready!(Pin::new(&mut self.read).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
                self.header_offset += count;
            }
            if self.payload.is_empty() && self.payload_offset == 0 {
                let length = usize::from(u16::from_be_bytes([self.header[5], self.header[6]]));
                self.payload = vec![0u8; length];
            }
            while self.payload_offset < self.payload.len() {
                let mut read = ReadBuf::new(&mut self.payload[self.payload_offset..]);
                ready!(Pin::new(&mut self.read).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
                self.payload_offset += count;
            }
            let command = self.header[0];
            let id = u32::from_be_bytes([
                self.header[1],
                self.header[2],
                self.header[3],
                self.header[4],
            ]);
            self.header_offset = 0;
            self.payload_offset = 0;
            let payload = std::mem::take(&mut self.payload);
            match command {
                COMMAND_PSH if id == STREAM_ID => {
                    if !payload.is_empty() {
                        self.buffer = payload;
                        self.offset = 0;
                        return Poll::Ready(Ok(true));
                    }
                }
                COMMAND_SYNACK if id == STREAM_ID => {
                    if !payload.is_empty() {
                        // 对端文本不受信，不直接进入终端；只暴露固定拒绝类别。
                        self.failure = Some(io::ErrorKind::ConnectionRefused);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "AnyTLS 目标连接被拒绝",
                        )));
                    }
                }
                COMMAND_FIN if id == STREAM_ID => {
                    self.closed = true;
                    self.peer_fin = true;
                    return Poll::Ready(Ok(false));
                }
                COMMAND_FIN => {}
                COMMAND_ALERT if !payload.is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "AnyTLS 对端发送告警",
                    )));
                }
                COMMAND_UPDATE_PADDING_SCHEME => {
                    self.schemes.update(&payload);
                }
                COMMAND_SERVER_SETTINGS | COMMAND_HEART_REQUEST | COMMAND_HEART_RESPONSE => {}
                _ => {}
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.as_mut().get_mut();
        if let Some(kind) = this.failure {
            return Poll::Ready(Err(io::Error::new(kind, "AnyTLS 流已失败")));
        }
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.offset < this.buffer.len() {
                let count = out.remaining().min(this.buffer.len() - this.offset);
                out.put_slice(&this.buffer[this.offset..this.offset + count]);
                this.offset += count;
                return Poll::Ready(Ok(()));
            }
            this.buffer.clear();
            this.offset = 0;
            match this.poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => {
                    this.failure = Some(error.kind());
                    return Poll::Ready(Err(error));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ClientStream<S> {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(kind) = self.failure {
            return Poll::Ready(Err(io::Error::new(kind, "AnyTLS流已失败")));
        }
        while self.pending_block < self.pending.len() {
            let block = &self.pending[self.pending_block];
            if self.pending_offset == block.len() {
                self.pending_block += 1;
                self.pending_offset = 0;
                continue;
            }
            match Pin::new(&mut self.write).poll_write(cx, &block[self.pending_offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    self.failure = Some(io::ErrorKind::WriteZero);
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(count)) => self.pending_offset += count,
                Poll::Ready(Err(error)) => {
                    self.failure = Some(error.kind());
                    return Poll::Ready(Err(error));
                }
            }
        }
        self.pending.clear();
        self.pending_block = 0;
        self.pending_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if let Some(kind) = this.failure {
            return Poll::Ready(Err(io::Error::new(kind, "AnyTLS 流已失败")));
        }
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS 流已关闭",
            )));
        }
        ready!(this.flush_pending(cx))?;
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buffer.len().min(MAX_FRAME);
        let data = frame(COMMAND_PSH, STREAM_ID, &buffer[..take])?;
        this.pending = this.padding.shape(&data, &this.schemes.snapshot())?;
        this.pending_block = 0;
        this.pending_offset = 0;
        // 完整有界批次由实例接受；下次write/flush/shutdown排空，取消不虚报新buffer。
        Poll::Ready(Ok(take))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        ready!(this.flush_pending(cx))?;
        Pin::new(&mut this.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let Some(kind) = this.failure {
            return Poll::Ready(Err(io::Error::new(kind, "AnyTLS 流已失败")));
        }
        if this.shutdown_done {
            return Pin::new(&mut this.write).poll_shutdown(cx);
        }
        if !this.shutdown_started {
            this.shutdown_started = true;
            this.closed = true;
        }
        ready!(this.flush_pending(cx))?;
        if !this.fin_queued && !this.peer_fin {
            this.pending = this.padding.shape(
                &frame(COMMAND_FIN, STREAM_ID, &[])?,
                &this.schemes.snapshot(),
            )?;
            this.pending_block = 0;
            this.pending_offset = 0;
            this.fin_queued = true;
        }
        ready!(this.flush_pending(cx))?;
        ready!(Pin::new(&mut this.write).poll_flush(cx))?;
        this.shutdown_done = true;
        Pin::new(&mut this.write).poll_shutdown(cx)
    }
}
