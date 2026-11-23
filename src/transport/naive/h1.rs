//! 显式sing-box H1模式：200头不填充，头后早字节仅回放一次到正式PaddedData。
use super::*;
use crate::transport::{naive_padding::PaddedStream, xhttp::PrefixReader};
use std::{future::Future, pin::Pin};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub(super) fn serve<'a, S>(
    mut stream: S,
    tag: &'a str,
    users: &'a [crate::config::User],
    ctx: Arc<Context>,
    deadline: Instant,
    handshake: crate::runtime::HandshakePermits,
) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 固定建连边界，避免将新增UoT/拨号状态逐层内联到默认线程栈。
    Box::pin(async move {
        let accepted = timeout_at(
            deadline,
            proxy_http::handshake_naive_padded(&mut stream, users),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive H1请求头超时"))??;
        drop(handshake);
        let user = accepted.request.user.clone();
        let target = &accepted.request.target;
        let uot = (target.port == 0)
            .then(|| crate::udp::uot_version(target))
            .flatten();
        let wait = Duration::from_millis(ctx.limits.handshake_timeout_ms);
        let upstream = if uot.is_some() {
            None
        } else {
            match ctx.connect(tag, target).await {
                Ok(upstream) => Some(upstream),
                Err(error) => {
                    let _ = tokio::time::timeout(wait, proxy_http::status_reply(&mut stream, 502))
                        .await;
                    return Err(error);
                }
            }
        };
        let padding = crate::transport::naive_padding::header_value()?;
        let mut response = b"HTTP/1.1 200 Connection Established\r\nPadding: ".to_vec();
        response.extend_from_slice(&padding);
        response.extend_from_slice(b"\r\n\r\n");
        tokio::time::timeout(wait, async {
            stream.write_all(&response).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive H1响应超时"))??;
        let app = PaddedStream::new(PrefixReader::new(accepted.early, stream), true);
        if let Some(version) = uot {
            crate::udp::uot(app, ctx, tag.to_owned(), version, user.as_deref()).await
        } else {
            let app = ctx.stats.count_user(tag, user.as_deref(), app);
            crate::forward::relay(app, upstream.expect("非UoT已建目标"), ctx.stats.clone()).await
        }
    })
}

#[cfg(test)]
mod tests;
