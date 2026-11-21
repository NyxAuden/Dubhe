//! Naive 入站：TLS 上的 HTTP CONNECT 代理，支持 HTTP/1.1 与 HTTP/2 多路复用。
//!
//! 只负责H1/H2承载与代理认证；H3见 `naive_h3`，拨号/路由/统计共用运行时。
//! H1默认裸流对齐forwardproxy；显式h1_padding对齐sing-box，不根据相同能力头猜测。

use std::io;
use std::sync::Arc;
use std::time::Duration;

use h2::server::SendResponse;
use http::{HeaderValue, Response, StatusCode};
use prost::bytes::Bytes;
use tokio::io::AsyncRead;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::config::Inbound;
use crate::forward::Context;
use crate::protocol::http as proxy_http;
use crate::transport::xhttp::{H2Reader, H2Writer, Tunnel};

mod h1;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    stream: TcpStream,
    config: Inbound,
    tls: Option<crate::tls::ServerTls>,
    ctx: Arc<Context>,
    handshake: OwnedSemaphorePermit,
    global_streams: Arc<Semaphore>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let acceptor = tls.ok_or_else(|| io::Error::other("Naive 入口需要 TLS"))?;
    let accepted = timeout_at(deadline, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive TLS握手超时"))??;
    let alpn = accepted.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let (tag, users, h1_padding) = match &config {
        Inbound::Naive {
            tag,
            users,
            h1_padding,
            ..
        } => (tag.clone(), users.clone(), *h1_padding),
        _ => return Err(io::Error::other("入口不是 Naive")),
    };
    match alpn.as_deref() {
        Some(b"h2") => {
            serve_h2(
                accepted,
                &tag,
                &users,
                &ctx,
                deadline,
                handshake,
                global_streams,
                stop,
                force,
            )
            .await
        }
        Some(b"http/1.1") | None => {
            if h1_padding {
                return h1::serve(accepted, &tag, &users, ctx, deadline, handshake).await;
            }
            let timeout = Duration::from_millis(ctx.limits.handshake_timeout_ms);
            crate::runtime::serve_http(accepted, &tag, &users, None, ctx, timeout, handshake).await
        }
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Naive ALPN不受支持",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_h2<S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    io: S,
    tag: &str,
    users: &[crate::config::User],
    ctx: &Arc<Context>,
    deadline: Instant,
    handshake: OwnedSemaphorePermit,
    global_streams: Arc<Semaphore>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let mut builder = h2::server::Builder::new();
    builder.max_concurrent_streams(ctx.limits.max_grpc_streams_per_connection as u32);
    builder.max_header_list_size(8192);
    let mut connection = timeout_at(deadline, builder.handshake(io))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive h2握手超时"))?
        .map_err(io::Error::other)?;
    drop(handshake);
    let mut streams = JoinSet::new();
    let slots = Arc::new(Semaphore::new(ctx.limits.max_grpc_streams_per_connection));
    let mut draining = false;
    let mut shutdown_deadline = Instant::now();
    loop {
        if draining && streams.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled(), if !draining => {
                draining = true;
                shutdown_deadline = Instant::now() + Duration::from_millis(ctx.limits.shutdown_timeout_ms);
                connection.graceful_shutdown();
            }
            _ = tokio::time::sleep_until(shutdown_deadline), if draining => break,
            accepted = connection.accept() => {
                let Some(request) = accepted else { break };
                let (request, mut respond) = request.map_err(io::Error::other)?;
                if draining {
                    respond.send_reset(h2::Reason::REFUSED_STREAM); continue;
                }
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    ctx.stats.reject(); respond.send_reset(h2::Reason::REFUSED_STREAM); continue;
                };
                let Ok(global_slot) = global_streams.clone().try_acquire_owned() else {
                    ctx.stats.reject(); respond.send_reset(h2::Reason::REFUSED_STREAM); continue;
                };
                let (tag, users, ctx) = (tag.to_owned(), users.to_vec(), ctx.clone());
                let children = ctx.children.clone();
                streams.spawn(children.track_future(async move {
                    let _slot = slot;
                    let _global = global_slot;
                    handle_stream(request, respond, &tag, &users, &ctx).await
                }));
            }
            result = streams.join_next(), if !streams.is_empty() => {
                if result.is_some_and(|result| result.is_err()) {
                    return Err(io::Error::other("Naive 流任务异常"));
                }
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
    Ok(())
}

async fn handle_stream(
    request: ::http::Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    tag: &str,
    users: &[crate::config::User],
    ctx: &Arc<Context>,
) -> io::Result<()> {
    if request.method() != ::http::Method::CONNECT {
        return reject(&mut respond, StatusCode::METHOD_NOT_ALLOWED);
    }
    let authority = request
        .uri()
        .authority()
        .map(|value| value.as_str().to_owned())
        .or_else(|| Some(request.uri().path().to_owned()))
        .unwrap_or_default();
    let target = match authority_target(&authority) {
        Ok(target) => target,
        Err(_) => return reject(&mut respond, StatusCode::BAD_REQUEST),
    };
    // 客户端以 CONNECT 请求中的 `padding` 头声明能力；服务端仅在声明时
    // 启用 PaddedData，避免改变普通浏览器/未实现该扩展客户端的字节流。
    let padding = request
        .headers()
        .get("padding")
        .is_some_and(|value| !value.is_empty());
    let mut credentials = request.headers().get_all("proxy-authorization").iter();
    let authorization = credentials.next().and_then(|value| value.to_str().ok());
    if credentials.next().is_some()
        || proxy_http::authenticate_header(authorization, users).is_err()
    {
        let _ = respond.send_response(
            Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("proxy-authenticate", "Basic realm=\"proxy\"")
                .body(())
                .expect("响应头合法"),
            true,
        );
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Naive 代理认证失败",
        ));
    }
    let uot = (target.port == 0)
        .then(|| crate::udp::uot_version(&target))
        .flatten();
    let upstream = if uot.is_some() {
        None
    } else {
        match ctx.connect(tag, &target).await {
            Ok(target) => Some(target),
            Err(error) => {
                reject(&mut respond, StatusCode::BAD_GATEWAY)?;
                return Err(error);
            }
        }
    };
    let mut response = Response::builder().status(StatusCode::OK);
    if padding {
        let value = crate::transport::naive_padding::header_value()?;
        response = response.header(
            "padding",
            HeaderValue::from_bytes(&value).map_err(io::Error::other)?,
        );
    }
    let send = respond
        .send_response(response.body(()).expect("响应头合法"), false)
        .map_err(io::Error::other)?;
    let tunnel = Tunnel::new(H2Reader::new(request.into_body()), H2Writer::new(send));
    let tunnel = crate::transport::naive_padding::PaddedStream::new(tunnel, padding);
    if let Some(version) = uot {
        crate::udp::uot(tunnel, ctx.clone(), tag.to_owned(), version, None).await
    } else {
        crate::forward::relay(tunnel, upstream.expect("非UoT已建目标"), ctx.stats.clone()).await
    }
}

/// 只有正式UoT魔数允许0端口占位；普通HTTP代理目标规则保持不变。
pub(super) fn authority_target(value: &str) -> io::Result<crate::session::Target> {
    if let Ok(authority) = value.parse::<http::uri::Authority>()
        && authority.port_u16() == Some(0)
        && authority.host() == super::naive_client::UOT_HOST
    {
        return Ok(crate::session::Target {
            host: crate::session::Host::Domain(authority.host().to_owned()),
            port: 0,
        });
    }
    proxy_http::authority_target(value)
}

fn reject(respond: &mut SendResponse<Bytes>, status: StatusCode) -> io::Result<()> {
    respond
        .send_response(
            Response::builder()
                .status(status)
                .body(())
                .expect("响应头合法"),
            true,
        )
        .map(|_| ())
        .map_err(io::Error::other)
}
