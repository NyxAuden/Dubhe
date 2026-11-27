//! V2Ray HTTP 传输服务端（sing-box `v2ray-http` 语义）。
//!
//! - 明文 TCP：HTTP/1.1 请求头校验后写 `200`，随后整条连接就是业务字节流；
//! - TLS：协商 h2，每个请求流承载一条独立的 VLESS/VMess/Trojan 连接。
//!
//! 不支持 HTTP/2 prior-knowledge（明文 h2c）与分块请求体：当前目标客户端
//! 在明文下发送无 `Content-Length` 的原始请求体，在 TLS 下使用 h2 流。

use std::{io, sync::Arc, time::Duration};

use h2::RecvStream;
use h2::server::SendResponse;
use http::{HeaderValue, Request, Response, StatusCode};
use prost::bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    task::JoinSet,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Inbound, V2rayHttp},
    forward::Context,
    protocol::vmess,
    transport::{
        httpupgrade::read_head,
        v2ray_tunnel::dispatch,
        xhttp::{H2Reader, H2Writer, PrefixReader, Tunnel},
    },
};

const MAX_HEADERS: usize = 64;

// 入站入口的固定句柄集合；每个入口签名都保持一致。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    stream: TcpStream,
    inbound: Arc<Inbound>,
    tls: Option<crate::tls::ServerTls>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    handshake: crate::runtime::HandshakePermits,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let http = http_config(&inbound)?.clone();
    let deadline = Instant::now() + Duration::from_millis(ctx.limits.handshake_timeout_ms);
    stream.set_nodelay(true)?;
    match tls {
        Some(acceptor) => {
            let accepted = timeout_at(deadline, acceptor.accept(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray HTTP TLS握手超时"))??;
            match accepted.get_ref().1.alpn_protocol() {
                Some(b"h2") => {
                    serve_h2(
                        accepted, inbound, http, vmess, ctx, handshake, stop, force, deadline,
                    )
                    .await
                }
                Some(b"http/1.1") => {
                    serve_h1(accepted, inbound, http, vmess, ctx, handshake, deadline).await
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "V2Ray HTTP TLS必须协商h2或http/1.1",
                )),
            }
        }
        None => serve_h1(stream, inbound, http, vmess, ctx, handshake, deadline).await,
    }
}

fn http_config(inbound: &Inbound) -> io::Result<&V2rayHttp> {
    match inbound {
        Inbound::VlessHttp { http, .. }
        | Inbound::VmessHttp { http, .. }
        | Inbound::TrojanHttp { http, .. } => Ok(http),
        _ => Err(io::Error::other("入口不是 V2Ray HTTP 传输")),
    }
}

async fn serve_h1<S>(
    mut io: S,
    config: Arc<Inbound>,
    http: V2rayHttp,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    handshake: crate::runtime::HandshakePermits,
    deadline: Instant,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (buffer, head_end) = timeout_at(deadline, read_head(&mut io))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray HTTP 请求头超时"))??;
    match check_h1(&buffer[..head_end], &http) {
        Ok(()) => {}
        Err(status) => {
            let response = rejection(status);
            let _ = io.write_all(&response).await;
            let _ = io.flush().await;
            return Ok(());
        }
    }
    let leftover = buffer[head_end..].to_vec();
    io.write_all(&accept_response(&http))
        .await
        .map_err(|error| io::Error::new(error.kind(), "V2Ray HTTP 响应写入失败"))?;
    io.flush()
        .await
        .map_err(|error| io::Error::new(error.kind(), "V2Ray HTTP 响应刷新失败"))?;
    let auth = crate::runtime::AuthSlot::new(handshake);
    dispatch(
        PrefixReader::new(leftover, io),
        config,
        vmess,
        false,
        ctx,
        deadline,
        Some(&auth),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn serve_h2<S>(
    io: S,
    config: Arc<Inbound>,
    http: V2rayHttp,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    permit: crate::runtime::HandshakePermits,
    stop: CancellationToken,
    force: CancellationToken,
    deadline: Instant,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let per_connection = ctx.limits.max_grpc_streams_per_connection.max(1);
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(per_connection as u32)
        .initial_window_size(1 << 20)
        .initial_connection_window_size(1 << 20)
        .max_frame_size(16_384)
        .header_table_size(4_096)
        .max_header_list_size(8_192)
        .max_send_buffer_size(65_536)
        .max_concurrent_reset_streams(32)
        .max_pending_accept_reset_streams(16)
        .max_local_error_reset_streams(Some(64))
        .data_frame_budget(32_768);
    let mut connection: h2::server::Connection<S, Bytes> =
        timeout_at(deadline, builder.handshake(io))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray HTTP h2握手超时"))?
            .map_err(io::Error::other)?;
    let shutdown = Duration::from_millis(ctx.limits.shutdown_timeout_ms);
    let auth = crate::runtime::AuthSlot::new(permit);
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            _ = tokio::time::sleep_until(deadline), if auth.pending() => {
                if auth.pending() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "V2Ray HTTP h2首次认证超时"));
                }
            }
            accepted = connection.accept() => {
                let Some(request) = accepted else { break };
                let (request, mut respond) = request.map_err(io::Error::other)?;
                if let Err(status) = check_h2(&request, &http) {
                    reject_h2(&mut respond, status).await;
                    continue;
                }
                let mut response = Response::new(());
                *response.status_mut() = StatusCode::OK;
                let headers = response.headers_mut();
                headers.insert("cache-control", HeaderValue::from_static("no-store"));
                for (name, value) in &http.headers {
                    // 配置加载时已校验为合法 token/可见ASCII。
                    if let (Ok(name), Ok(value)) = (
                        http::header::HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(value),
                    ) {
                        headers.insert(name, value);
                    }
                }
                let send = match respond.send_response(response, false) {
                    Ok(send) => send,
                    Err(_) => break,
                };
                let stream = Tunnel::new(H2Reader::new(request.into_body()), H2Writer::new(send));
                let config = config.clone();
                let vmess = vmess.clone();
                let ctx = ctx.clone();
                let auth = auth.clone();
                let stream_deadline = if auth.pending() {
                    deadline
                } else {
                    Instant::now() + Duration::from_millis(ctx.limits.handshake_timeout_ms)
                };
                // 登记到 tracker：外层 force 会直接丢掉连接 future，函数末尾的
                // drain 执行不到，只有 tracker 能保证停机等到流任务真正 drop。
                let tracker = ctx.children.clone();
                streams.spawn(tracker.track_future(async move {
                    let _ = dispatch(
                        stream,
                        config,
                        vmess,
                        true,
                        ctx,
                        stream_deadline,
                        Some(&auth),
                    )
                    .await;
                }));
            }
            Some(_) = streams.join_next() => {}
        }
    }
    let _ = timeout_at(Instant::now() + shutdown, async {
        while streams.join_next().await.is_some() {}
    })
    .await;
    streams.abort_all();
    Ok(())
}

fn check_h1(head: &[u8], http: &V2rayHttp) -> Result<(), StatusCode> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    if request.version != Some(1) || request.path.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(expected) = &http.method
        && request.method != Some(expected.as_str())
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let target = request.path.unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default();
    if !path.starts_with(&http.normalized_path()) {
        return Err(StatusCode::NOT_FOUND);
    }
    if !http.host.is_empty() {
        let host = request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("host"))
            .and_then(|header| std::str::from_utf8(header.value).ok())
            .ok_or(StatusCode::BAD_REQUEST)?;
        if !http
            .host
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Ok(())
}

fn check_h2(request: &Request<RecvStream>, http: &V2rayHttp) -> Result<(), StatusCode> {
    if let Some(expected) = &http.method
        && request.method().as_str() != expected.as_str()
    {
        return Err(StatusCode::NOT_FOUND);
    }
    if !request.uri().path().starts_with(&http.normalized_path()) {
        return Err(StatusCode::NOT_FOUND);
    }
    if !http.host.is_empty() {
        let host = request
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| {
                request
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|value| value.to_str().ok())
            })
            .ok_or(StatusCode::BAD_REQUEST)?;
        if !http
            .host
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Ok(())
}

fn accept_response(http: &V2rayHttp) -> Vec<u8> {
    let mut response = Vec::with_capacity(128);
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nCache-Control: no-store\r\n");
    for (name, value) in &http.headers {
        response.extend_from_slice(name.as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"\r\n");
    response
}

fn rejection(status: StatusCode) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("Bad Request");
    format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        status.as_u16(),
        reason
    )
    .into_bytes()
}

async fn reject_h2(respond: &mut SendResponse<Bytes>, status: StatusCode) {
    let _ = respond.send_response(
        Response::builder()
            .status(status)
            .body(())
            .expect("响应头合法"),
        true,
    );
}
