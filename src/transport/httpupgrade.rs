//! HTTPUpgrade 入站：WebSocket 形状的 HTTP/1.1 Upgrade，但升级后是原始字节流。
//!
//! 本模块只建立承载：严格解析并校验请求行/头、写出 101、把残留字节接回字节流，
//! 之后的 VLESS/VMess/Trojan 认证与业务全部复用 `xhttp::dispatch`。
//! 调用方须用同一个绝对期限包住 TLS、升级与首个协议认证；本模块不刷新期限。

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::config::{HttpUpgrade, Inbound};
use crate::forward::Context;
use crate::protocol::vmess;
use crate::transport::xhttp::{self, PrefixReader};

const MAX_HEAD: usize = 8_192;
const MAX_HEADERS: usize = 64;
const READ_CHUNK: usize = 1_024;

/// 入口驱动的唯一调用点：TLS（存在时）只接受 http/1.1 ALPN。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    stream: TcpStream,
    config: Arc<Inbound>,
    security: Option<crate::tls::InboundSecurity>,
    vmess: Option<std::sync::Arc<vmess::Prepared>>,
    ctx: std::sync::Arc<Context>,
    handshake: crate::runtime::HandshakePermits,
    _stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let expected = config
        .httpupgrade()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "入口不是 HTTPUpgrade"))?
        .clone();

    let _ = &force;
    match security {
        Some(security) => {
            let (accepted, alpn) = match security.accept(stream, &ctx, deadline).await? {
                crate::tls::AcceptedInbound::Fallback => return Ok(()),
                crate::tls::AcceptedInbound::Stream { io, alpn } => (io, alpn),
            };
            match alpn.as_deref() {
                Some(b"http/1.1") | None => {}
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTPUpgrade ALPN不受支持",
                    ));
                }
            }
            // 许可由认证成功释放，不是升级完成。
            let auth = crate::runtime::AuthSlot::new(handshake);
            let (app, early) = timeout_at(deadline, accept(accepted, &expected))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTPUpgrade升级超时"))??;
            xhttp::dispatch(
                PrefixReader::new(early, app),
                &config,
                &vmess,
                &ctx,
                deadline,
                None,
                Some(&auth),
            )
            .await
        }
        None => {
            let auth = crate::runtime::AuthSlot::new(handshake);
            let (app, early) = timeout_at(deadline, accept(stream, &expected))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTPUpgrade升级超时"))??;
            xhttp::dispatch(
                PrefixReader::new(early, app),
                &config,
                &vmess,
                &ctx,
                deadline,
                None,
                Some(&auth),
            )
            .await
        }
    }
}

impl Inbound {
    fn httpupgrade(&self) -> Option<&HttpUpgrade> {
        match self {
            Self::VlessHttpUpgrade { httpupgrade, .. }
            | Self::VmessHttpUpgrade { httpupgrade, .. }
            | Self::TrojanHttpUpgrade { httpupgrade, .. } => Some(httpupgrade),
            _ => None,
        }
    }
}

/// 成功时 101 已完整写出，`early` 是升级前同一 TCP 段里夹带的业务字节。
async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    config: &HttpUpgrade,
) -> io::Result<(S, Vec<u8>)> {
    let (buffer, head_end) = read_head(&mut io).await?;
    if let Err(rejection) = check_head(&buffer[..head_end], config) {
        return reject(&mut io, rejection).await;
    }
    let leftover = buffer[head_end..].to_vec();
    io.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    )
    .await
    .map_err(|error| io::Error::new(error.kind(), "HTTPUpgrade响应写入失败"))?;
    io.flush()
        .await
        .map_err(|error| io::Error::new(error.kind(), "HTTPUpgrade响应刷新失败"))?;
    Ok((io, leftover))
}

#[derive(Clone, Copy)]
enum Rejection {
    BadRequest,
    NotFound,
}

impl Rejection {
    fn response(self) -> &'static [u8] {
        match self {
            Self::BadRequest => {
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::NotFound => {
                b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
        }
    }
}

async fn reject<S: AsyncWrite + Unpin, T>(io: &mut S, rejection: Rejection) -> io::Result<T> {
    io.write_all(rejection.response())
        .await
        .map_err(|error| io::Error::new(error.kind(), "HTTPUpgrade拒绝响应写入失败"))?;
    io.flush()
        .await
        .map_err(|error| io::Error::new(error.kind(), "HTTPUpgrade拒绝响应刷新失败"))?;
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTPUpgrade握手被拒绝",
    ))
}

pub(crate) async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<(Vec<u8>, usize)> {
    crate::util::read_http_head(io, MAX_HEAD, READ_CHUNK, "HTTPUpgrade").await
}

/// 只接受 GET + HTTP/1.1 + `Connection: Upgrade` + `Upgrade: websocket` + 精确路径。
fn check_head(head: &[u8], config: &HttpUpgrade) -> Result<(), Rejection> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(Rejection::BadRequest),
    }
    if request.method != Some("GET") || request.path.is_none() || request.version != Some(1) {
        return Err(Rejection::BadRequest);
    }
    let target = request.path.unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default();
    if path != config.path {
        return Err(Rejection::NotFound);
    }

    let mut host_count = 0;
    let mut connection = 0u32;
    let mut upgrade = 0u32;
    let mut transfer_encoding = 0u32;
    let mut content_length = 0u32;
    for header in request.headers.iter() {
        let value = header.value;
        if !value.is_ascii() {
            return Err(Rejection::BadRequest);
        }
        let value = std::str::from_utf8(value).map_err(|_| Rejection::BadRequest)?;
        match header.name.to_ascii_lowercase().as_str() {
            "host" => host_count += 1,
            "connection" => {
                connection += 1;
                if !has_token(value, "upgrade") {
                    return Err(Rejection::BadRequest);
                }
            }
            "upgrade" => {
                upgrade += 1;
                if !value.trim().eq_ignore_ascii_case("websocket") {
                    return Err(Rejection::BadRequest);
                }
            }
            "transfer-encoding" => transfer_encoding += 1,
            "content-length" => {
                content_length += 1;
                if value.trim() != "0" {
                    return Err(Rejection::BadRequest);
                }
            }
            _ => {}
        }
    }
    if host_count > 1 || connection != 1 || upgrade != 1 || transfer_encoding != 0 {
        return Err(Rejection::BadRequest);
    }
    let _ = content_length;
    if let Some(expected) = &config.host {
        let host = request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("host"))
            .map(|header| String::from_utf8_lossy(header.value).into_owned())
            .unwrap_or_default();
        let host = host.split(':').next().unwrap_or_default();
        if !host.eq_ignore_ascii_case(expected) {
            return Err(Rejection::NotFound);
        }
    }
    Ok(())
}

fn has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}
