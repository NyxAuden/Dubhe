//! 成熟 WebSocket 引擎下方的窄原始帧头护栏，不实现消息或 continuation 状态机。
//!
//! 集成时使用 `from_raw_socket(Guard::new(io, http_tail), ...)`；不得再把 HTTP
//! 尾部传给引擎的 partially-read 接口，否则这些字节会绕过校验及预算。外层每次
//! WS poll_read/write/flush/shutdown 开始时调用一次 begin_poll，而不是每次底层
//! read 时调用。原始 EOF 仅在帧边界透传，由成熟引擎判定缺少 Close 的异常结束。
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_FRAME_BYTES: u64 = 1_048_576;
const HEADERS_PER_POLL: usize = 32;
const BYTES_PER_POLL: usize = 65_536;

/// HTTP 尾部的唯一回放游标，位于所有帧头检查与原始字节预算的下方。
struct RawIo<S> {
    io: S,
    prefix: Vec<u8>,
    offset: usize,
}

impl<S: AsyncRead + Unpin> RawIo<S> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        maximum: usize,
        bytes_left: &mut usize,
    ) -> Poll<io::Result<usize>> {
        if *bytes_left == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let limit = out.remaining().min(maximum).min(*bytes_left);
        let n = if self.offset < self.prefix.len() {
            let n = limit.min(self.prefix.len() - self.offset);
            out.put_slice(&self.prefix[self.offset..self.offset + n]);
            self.offset += n;
            if self.offset == self.prefix.len() {
                // 不保留已经回放的 HTTP 预读分配，也不另建第二个游标。
                self.prefix = Vec::new();
                self.offset = 0;
            }
            n
        } else {
            // 直接借用调用者的载荷空间，不按声明长度分配或缓存载荷。
            let mut limited = ReadBuf::new(out.initialize_unfilled_to(limit));
            std::task::ready!(Pin::new(&mut self.io).poll_read(cx, &mut limited))?;
            let n = limited.filled().len();
            out.advance(n);
            n
        };
        *bytes_left -= n;
        Poll::Ready(Ok(n))
    }
}

#[derive(Clone, Copy)]
enum ReadState {
    Header,
    Replay {
        sent: usize,
        length: usize,
        payload: usize,
    },
    Payload {
        remaining: usize,
    },
    Eof,
}

pub(super) struct Guard<S> {
    raw: RawIo<S>,
    header: [u8; 14],
    filled: usize,
    state: ReadState,
    headers_left: usize,
    bytes_left: usize,
    failure: Option<(io::ErrorKind, String)>,
}

impl<S> Guard<S> {
    pub(super) fn new(io: S, prefix: Vec<u8>) -> Self {
        Self {
            raw: RawIo {
                io,
                prefix,
                offset: 0,
            },
            header: [0; 14],
            filled: 0,
            state: ReadState::Header,
            headers_left: HEADERS_PER_POLL,
            bytes_left: BYTES_PER_POLL,
            failure: None,
        }
    }

    /// 仅外层 WS poll 的入口调用；部分头、回放和载荷游标都不能重置。
    pub(super) fn begin_poll(&mut self) {
        self.headers_left = HEADERS_PER_POLL;
        self.bytes_left = BYTES_PER_POLL;
    }

    /// 供外层关闭状态机直接结束底层 IO；不得通过它绕过护栏读取。
    pub(super) fn get_mut(&mut self) -> &mut S {
        &mut self.raw.io
    }

    fn error(&self) -> Option<io::Error> {
        self.failure
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }

    fn finish<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if let Poll::Ready(Err(error)) = &result {
            self.failure = Some((error.kind(), error.to_string()));
        }
        result
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// 调用时长度字段已完整；在等待 mask key 或任何 payload 之前拒绝恶意声明。
fn declared_payload(header: &[u8]) -> io::Result<usize> {
    if header[1] & 0x80 == 0 {
        return Err(invalid("WebSocket 客户端帧缺少 mask"));
    }
    let length = match header[1] & 0x7f {
        126 => {
            let length = u16::from_be_bytes([header[2], header[3]]) as u64;
            if length < 126 {
                return Err(invalid("WebSocket 126 长度编码非最短"));
            }
            length
        }
        127 => {
            let length = u64::from_be_bytes([
                header[2], header[3], header[4], header[5], header[6], header[7], header[8],
                header[9],
            ]);
            if length & (1 << 63) != 0 {
                return Err(invalid("WebSocket 64 位长度高位非零"));
            }
            if length < 65_536 {
                return Err(invalid("WebSocket 127 长度编码非最短"));
            }
            length
        }
        length => u64::from(length),
    };
    if length > MAX_FRAME_BYTES {
        return Err(invalid("WebSocket 帧声明长度超限"));
    }
    if header[0] & 0x08 != 0 && (header[0] & 0x80 == 0 || length > 125) {
        return Err(invalid("WebSocket 控制帧必须 FIN 且不超过 125 字节"));
    }
    // 长度已限制为 1 MiB，再转换不会在支持的平台上截断。
    // RSV、opcode、continuation、解 mask、消息累计及 Close 校验仍由成熟引擎处理。
    Ok(length as usize)
}

impl<S: AsyncRead + Unpin> AsyncRead for Guard<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match this.state {
                ReadState::Header => {
                    if this.filled == 0 && this.headers_left == 0 {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    let needed = if this.filled < 2 {
                        2
                    } else {
                        let length_end = match this.header[1] & 0x7f {
                            126 => 4,
                            127 => 10,
                            _ => 2,
                        };
                        if this.filled < length_end {
                            length_end
                        } else {
                            let payload = match declared_payload(&this.header[..length_end]) {
                                Ok(payload) => payload,
                                Err(error) => return this.finish(Poll::Ready(Err(error))),
                            };
                            let full_length = length_end + 4;
                            if this.filled == full_length {
                                this.state = ReadState::Replay {
                                    sent: 0,
                                    length: full_length,
                                    payload,
                                };
                                continue;
                            }
                            full_length
                        }
                    };
                    let mut part = ReadBuf::new(&mut this.header[this.filled..needed]);
                    let result = this.raw.poll_read(
                        cx,
                        &mut part,
                        needed - this.filled,
                        &mut this.bytes_left,
                    );
                    let n = match result {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return this.finish(Poll::Ready(Err(error))),
                        Poll::Ready(Ok(n)) => n,
                    };
                    if n == 0 {
                        if this.filled != 0 {
                            return this.finish(Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "WebSocket 帧头被截断",
                            ))));
                        }
                        this.state = ReadState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    if this.filled == 0 {
                        this.headers_left -= 1;
                    }
                    this.filled += n;
                }
                ReadState::Replay {
                    sent,
                    length,
                    payload,
                } => {
                    let n = out.remaining().min(length - sent);
                    out.put_slice(&this.header[sent..sent + n]);
                    if sent + n == length {
                        this.filled = 0;
                        this.state = if payload == 0 {
                            ReadState::Header
                        } else {
                            ReadState::Payload { remaining: payload }
                        };
                    } else {
                        this.state = ReadState::Replay {
                            sent: sent + n,
                            length,
                            payload,
                        };
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Payload { remaining } => {
                    let n = match this.raw.poll_read(cx, out, remaining, &mut this.bytes_left) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return this.finish(Poll::Ready(Err(error))),
                        Poll::Ready(Ok(n)) => n,
                    };
                    if n == 0 {
                        return this.finish(Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "WebSocket 帧载荷被截断",
                        ))));
                    }
                    this.state = if n == remaining {
                        ReadState::Header
                    } else {
                        ReadState::Payload {
                            remaining: remaining - n,
                        }
                    };
                    return Poll::Ready(Ok(()));
                }
                ReadState::Eof => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guard<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.raw.io).poll_write(cx, bytes);
        this.finish(result)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.raw.io).poll_flush(cx);
        this.finish(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.raw.io).poll_shutdown(cx);
        this.finish(result)
    }

    fn is_write_vectored(&self) -> bool {
        self.raw.io.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.raw.io).poll_write_vectored(cx, buffers);
        this.finish(result)
    }
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;
