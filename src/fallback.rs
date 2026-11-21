//! VLESS fallback：认证失败时把已读取的原始字节连同 PROXY protocol 头发给本地目标。
//!
//! 只回放失败前确实消费的字节，绝不重写或解密；超过回放上限则 fail-closed。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::config::{Endpoint, Fallback};
use crate::forward::{self, AsyncStream, Context};
use crate::session::{Host, Target};

const MAX_RECORDED: usize = 4_096;

/// 记录手写认证阶段消费的字节；成功路径继续作为普通流使用。
pub(crate) struct Recording<S> {
    io: S,
    recorded: Vec<u8>,
    overflow: bool,
}

impl<S> Recording<S> {
    pub(crate) fn new(io: S) -> Self {
        Self {
            io,
            recorded: Vec::new(),
            overflow: false,
        }
    }

    fn into_parts(self) -> (Vec<u8>, S, bool) {
        (self.recorded, self.io, self.overflow)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Recording<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        std::task::ready!(Pin::new(&mut self.io).poll_read(cx, buf))?;
        let read = buf.filled().len() - before;
        if read > 0 && !self.overflow {
            if self.recorded.len() + read > MAX_RECORDED {
                self.overflow = true;
            } else {
                self.recorded.extend_from_slice(&buf.filled()[before..]);
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recording<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// 认证失败后转入 fallback；任何不确定情况都返回错误而不是投递残缺数据。
pub(crate) async fn relay<S: AsyncRead + AsyncWrite + Unpin>(
    client: Recording<S>,
    fallbacks: &[Fallback],
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Context,
    sni: Option<&str>,
    alpn: Option<&str>,
) -> io::Result<()> {
    let (mut recorded, mut io, mut overflow) = client.into_parts();
    if overflow {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fallback 回放字节超限",
        ));
    }
    // path 匹配需要首个请求行；只做一次有界补读，失败则视为无 path。
    if fallbacks.iter().any(|fallback| fallback.path.is_some())
        && !recorded.windows(2).any(|window| window == b"\r\n")
    {
        let mut buffer = [0u8; 1024];
        loop {
            if recorded.len() >= MAX_RECORDED {
                overflow = true;
                break;
            }
            let read = tokio::time::timeout(Duration::from_millis(250), io.read(&mut buffer)).await;
            match read {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(read)) => {
                    recorded.extend_from_slice(&buffer[..read]);
                    if recorded.windows(2).any(|window| window == b"\r\n") {
                        break;
                    }
                }
                Ok(Err(_)) => break,
            }
        }
    }
    if overflow {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fallback 回放字节超限",
        ));
    }
    let path = request_path(&recorded);
    let fallback = fallbacks
        .iter()
        .find(|fallback| fallback.matches(sni, alpn, path.as_deref()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "无匹配 fallback"))?;
    let endpoint = fallback
        .dest
        .endpoint()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fallback 目标无效"))?;
    let mut upstream: Box<dyn AsyncStream> = match endpoint {
        Endpoint::Tcp { host, port } => {
            let host = match host.parse::<IpAddr>() {
                Ok(ip) => Host::Ip(ip),
                Err(_) => Host::Domain(host.to_ascii_lowercase()),
            };
            let target = Target { host, port };
            let addresses = ctx.dns.resolve(&target).await?;
            let stream = timeout(
                Duration::from_millis(ctx.limits.dial_timeout_ms),
                forward::dial_addresses(
                    &addresses,
                    Duration::from_millis(ctx.limits.dial_attempt_timeout_ms),
                ),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fallback 拨号超时"))??;
            Box::new(stream)
        }
        Endpoint::Unix(path) => {
            #[cfg(unix)]
            {
                let stream = timeout(
                    Duration::from_millis(ctx.limits.dial_timeout_ms),
                    UnixStream::connect(path),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fallback Unix 拨号超时"))??;
                Box::new(stream)
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "当前平台不支持 Unix 套接字 fallback",
                ));
            }
        }
    };

    match fallback.xver {
        0 => {}
        1 => write_or_closed(&mut upstream, &proxy_v1(peer, local)).await?,
        _ => write_or_closed(&mut upstream, &proxy_v2(peer, local)).await?,
    }
    if !recorded.is_empty() {
        write_or_closed(&mut upstream, &recorded).await?;
    }
    forward::relay(io, upstream, ctx.stats.clone()).await
}

/// 目标可能在收到完整请求前就写出响应并关闭；此时仍应把已到达的响应
/// 交给客户端，而不是因为回放写失败丢掉目标数据。其他写错误保持失败关闭。
async fn write_or_closed<W: AsyncWrite + Unpin>(target: &mut W, bytes: &[u8]) -> io::Result<()> {
    match target.write_all(bytes).await {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn proxy_v1(peer: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let family = match (peer, local) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => "TCP4",
        _ => "TCP6",
    };
    format!(
        "PROXY {family} {} {} {} {}\r\n",
        peer.ip(),
        local.ip(),
        peer.port(),
        local.port()
    )
    .into_bytes()
}

fn proxy_v2(peer: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
    out.extend_from_slice(&[0x21]); // version 2, PROXY
    match (peer, local) {
        (SocketAddr::V4(peer), SocketAddr::V4(local)) => {
            out.extend_from_slice(&[0x11, 0, 12]);
            out.extend_from_slice(&peer.ip().octets());
            out.extend_from_slice(&local.ip().octets());
            out.extend_from_slice(&peer.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
        }
        (SocketAddr::V6(peer), SocketAddr::V6(local)) => {
            out.extend_from_slice(&[0x21, 0, 36]);
            out.extend_from_slice(&peer.ip().octets());
            out.extend_from_slice(&local.ip().octets());
            out.extend_from_slice(&peer.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
        }
        _ => {
            // 混合族无法用单一 PROXY v2 地址块表达。
            out.extend_from_slice(&[0x00, 0, 0]);
        }
    }
    out
}

/// 从回放字节的首行提取 HTTP 请求路径；非 HTTP 输入返回 None。
fn request_path(recorded: &[u8]) -> Option<String> {
    let end = recorded.windows(2).position(|window| window == b"\r\n")?;
    let line = std::str::from_utf8(&recorded[..end]).ok()?;
    let mut parts = line.split_whitespace();
    let _method = parts.next()?;
    let target = parts.next()?;
    if target.starts_with('/') {
        return Some(target.split('?').next().unwrap_or(target).to_owned());
    }
    let uri = target.parse::<::http::Uri>().ok()?;
    uri.path_and_query()
        .map(|value| value.path().to_owned())
        .filter(|path| path.starts_with('/'))
}
