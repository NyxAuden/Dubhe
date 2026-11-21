//! HTTP 与 Mixed 入站的 HTTP 代理部分：CONNECT 隧道与绝对 URI 转发。
//!
//! 只解析请求头并完成代理认证；拨号、路由与统计由运行时负责。
//! 绝对 URI 转发会把请求行改写为 origin-form 并强制 `Connection: close`，
//! 避免把代理专用的持久连接语义泄漏给目标服务器。

use std::io;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use httparse::EMPTY_HEADER;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::config::User;
use crate::session::{Command, Host, Request, Target};

const MAX_HEAD: usize = 8_192;
const MAX_HEADERS: usize = 64;
const READ_CHUNK: usize = 1_024;

#[cfg(test)]
mod tests;

/// 代理请求的成功结果：已经过认证并带出目标与需要转发的字节。
pub struct Accepted {
    pub request: Request,
    /// 绝对 URI 转发时要发给目标服务器的请求头（origin-form）；CONNECT 为 None。
    pub rewritten: Option<Vec<u8>>,
    /// 与请求头同批到达的正文前缀。
    pub early: Vec<u8>,
}

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[User],
) -> io::Result<Accepted> {
    handshake_impl(io, users, false).await
}

/// 仅显式填充Naive H1使用；不放宽HTTP/Mixed或默认裸Naive的目标和方法策略。
pub(crate) async fn handshake_naive_padded<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[User],
) -> io::Result<Accepted> {
    handshake_impl(io, users, true).await
}

async fn handshake_impl<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[User],
    naive_padded: bool,
) -> io::Result<Accepted> {
    let (buffer, head_end) = read_head(io).await?;
    if head_end > MAX_HEAD {
        return fail(io, 400, "HTTP 代理请求头超长").await;
    }
    let head = &buffer[..head_end];
    let early = buffer[head_end..].to_vec();
    let mut headers = [EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return fail(io, 400, "无效 HTTP 代理请求头").await,
    }
    if request.version != Some(1) {
        return fail(io, 400, "只支持 HTTP/1.1 代理请求").await;
    }
    let Some(method) = request.method else {
        return fail(io, 400, "缺少请求方法").await;
    };
    let Some(target) = request.path else {
        return fail(io, 400, "缺少请求目标").await;
    };

    if naive_padded {
        if method != "CONNECT" {
            return fail(io, 400, "Naive H1只接受CONNECT").await;
        }
        let mut padding = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("padding"));
        if padding.next().is_none_or(|header| header.value.is_empty()) || padding.next().is_some() {
            return fail(io, 400, "Naive H1需要单一非空Padding头").await;
        }
    }
    let user = authenticate(io, users, &request).await?;

    if method == "CONNECT" {
        let authority = target
            .parse::<http::uri::Authority>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "CONNECT 目标无效"))?;
        let port = authority
            .port_u16()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "CONNECT 缺少端口"))?;
        let target = if naive_padded && port == 0 && authority.host() == crate::udp::UOT_V2_MAGIC {
            Target {
                host: Host::Domain(authority.host().to_owned()),
                port: 0,
            }
        } else {
            make_target(authority.host(), port)?
        };
        return Ok(Accepted {
            request: Request {
                command: Command::Connect,
                target,
                user,
            },
            rewritten: None,
            early,
        });
    }

    let uri = target
        .parse::<http::Uri>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "代理请求目标无效"))?;
    if uri.scheme_str() != Some("http") {
        return fail(io, 400, "代理请求必须使用 http:// 或 CONNECT").await;
    }
    let authority = uri
        .authority()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "代理目标缺少主机"))?;
    let target = make_target(authority.host(), authority.port_u16().unwrap_or(80))?;
    let origin = uri.path_and_query().map_or("/", |value| value.as_str());
    let rewritten = rewrite_head(method, origin, request.headers.iter());
    Ok(Accepted {
        request: Request {
            command: Command::Connect,
            target,
            user,
        },
        rewritten: Some(rewritten),
        early,
    })
}

/// 代理认证失败或请求不合法时尽量写回 HTTP 错误，不泄漏细节。
async fn fail<S: AsyncWrite + Unpin, T>(
    io: &mut S,
    status: u16,
    reason: &'static str,
) -> io::Result<T> {
    let _ = status_reply(io, status).await;
    Err(io::Error::new(io::ErrorKind::InvalidData, reason))
}

pub async fn status_reply<S: AsyncWrite + Unpin>(io: &mut S, status: u16) -> io::Result<()> {
    let line = match status {
        200 => "HTTP/1.1 200 Connection Established\r\n\r\n".to_owned(),
        400 | 407 | 502 => format!(
            "HTTP/1.1 {status} {}\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
            match status {
                400 => "Bad Request",
                407 => "Proxy Authentication Required",
                _ => "Bad Gateway",
            },
            if status == 407 {
                "Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
            } else {
                ""
            }
        ),
        _ => {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
        }
    };
    io.write_all(line.as_bytes()).await?;
    io.flush().await
}

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[User],
    request: &httparse::Request<'_, '_>,
) -> io::Result<Option<String>> {
    if users.is_empty() {
        return Ok(None);
    }
    let mut values = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("proxy-authorization"));
    let (Some(header), None) = (values.next(), values.next()) else {
        return fail(io, 407, "缺少或重复代理认证").await;
    };
    let value = std::str::from_utf8(header.value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "代理认证编码无效"))?;
    match authenticate_header(Some(value), users) {
        Ok(identity) => Ok(identity),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fail(io, 407, "代理认证失败").await
        }
        Err(error) => Err(error),
    }
}

/// Basic 认证的共享实现；`Err(PermissionDenied)` 由承载层转成 407。
pub fn authenticate_header(value: Option<&str>, users: &[User]) -> io::Result<Option<String>> {
    if users.is_empty() {
        return Ok(None);
    }
    let Some(value) = value else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "缺少代理认证",
        ));
    };
    let Some(encoded) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "不支持的代理认证方案",
        ));
    };
    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "代理认证编码无效"))?;
    let Some(index) = decoded.iter().position(|byte| *byte == b':') else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "代理认证格式无效",
        ));
    };
    let (name, password) = (&decoded[..index], &decoded[index + 1..]);
    let mut identity = None;
    for user in users {
        let matches = name.ct_eq(user.name.as_bytes()) & password.ct_eq(user.password.as_bytes());
        if bool::from(matches) {
            identity = Some(user.name.clone());
        }
    }
    match identity {
        Some(identity) => Ok(Some(identity)),
        None => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "代理认证失败",
        )),
    }
}

/// CONNECT 目标必须是带端口的 authority。
pub fn authority_target(value: &str) -> io::Result<Target> {
    let authority = value
        .parse::<http::uri::Authority>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "CONNECT 目标无效"))?;
    let port = authority
        .port_u16()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "CONNECT 缺少端口"))?;
    make_target(authority.host(), port)
}

fn rewrite_head<'a>(
    method: &str,
    origin: &str,
    headers: impl Iterator<Item = &'a httparse::Header<'a>>,
) -> Vec<u8> {
    let mut out = format!("{method} {origin} HTTP/1.1\r\n").into_bytes();
    for header in headers {
        let name = header.name;
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

fn make_target(host: &str, port: u16) -> io::Result<Target> {
    if port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "端口不得为0"));
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = match host.parse::<IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => {
            if host.is_empty()
                || host.len() > 255
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'@')
            {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "目标主机无效"));
            }
            Host::Domain(host.to_ascii_lowercase())
        }
    };
    Ok(Target { host, port })
}

async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<(Vec<u8>, usize)> {
    crate::util::read_http_head(io, MAX_HEAD, READ_CHUNK, "HTTP 代理").await
}
