//! 管理/统计 API：回环监听、Bearer 认证的最小 HTTP/1.1 服务。
//!
//! 只提供只读端点和固定 JSON；不支持请求体、HTTP/2 或长连接，每个请求
//! 处理完成后关闭连接。token 不写入日志。

use std::{io, sync::Arc, time::Duration};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::ApiConfig, connections::Registry, telemetry::Stats, transport::httpupgrade::read_head,
};

/// 管理连接并发上限与请求期限；管理面不应占用代理业务额度。
const MAX_CONNECTIONS: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADERS: usize = 32;

pub(crate) async fn serve(
    listener: TcpListener,
    config: ApiConfig,
    stats: Arc<Stats>,
    connections: Arc<Registry>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    // token 文件只在管理面启动时读取一次；轮换 token 需要重启进程。
    let token = Arc::new(
        config
            .load_token()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?,
    );
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            some = tasks.join_next(), if !tasks.is_empty() => {
                let _ = some;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let token = token.clone();
                let stats = stats.clone();
                let connections = connections.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = handle(stream, &token, &stats, &connections).await;
                });
            }
        }
    }
    tasks.abort_all();
    Ok(())
}

async fn handle(
    mut stream: TcpStream,
    token: &str,
    stats: &Stats,
    connections: &Registry,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let (buffer, head_end) = timeout_at(deadline, read_head(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "管理 API 请求头超时"))??;
    let request = match parse(&buffer[..head_end]) {
        Some(request) => request,
        None => return respond(&mut stream, deadline, 400, "Bad Request", "", b"").await,
    };
    let bearer = request
        .authorization
        .and_then(parse_bearer)
        .is_some_and(|candidate| secure_eq(candidate.as_bytes(), token.as_bytes()));
    if !bearer {
        return respond(
            &mut stream,
            deadline,
            401,
            "Unauthorized",
            "WWW-Authenticate: Bearer\r\n",
            b"",
        )
        .await;
    }
    let known = matches!(
        request.path,
        "/healthz" | "/stats" | "/stats/users" | "/metrics" | "/connections"
    ) || request.path.starts_with("/connections/");
    // `/metrics` 是只读端点，不接受 DELETE；其余管理端点允许 GET/DELETE。
    if request.path == "/metrics" && request.method != "GET" {
        return respond(
            &mut stream,
            deadline,
            405,
            "Method Not Allowed",
            "Allow: GET\r\n",
            b"",
        )
        .await;
    }
    if !matches!(request.method, "GET" | "DELETE") {
        let (code, reason, headers) = if known {
            (405, "Method Not Allowed", "Allow: GET, DELETE\r\n")
        } else {
            (404, "Not Found", "")
        };
        return respond(&mut stream, deadline, code, reason, headers, b"").await;
    }
    match (request.method, request.path) {
        ("GET", "/healthz") => {
            respond(&mut stream, deadline, 200, "OK", "", br#"{"status":"ok"}"#).await
        }
        ("GET", "/stats") => {
            let body = serde_json::to_vec(&stats.snapshot())
                .map_err(|_| io::Error::other("统计序列化失败"))?;
            respond(&mut stream, deadline, 200, "OK", "", &body).await
        }
        ("GET", "/stats/users") => {
            let body = serde_json::to_vec(&stats.user_snapshots())
                .map_err(|_| io::Error::other("用户统计序列化失败"))?;
            respond(&mut stream, deadline, 200, "OK", "", &body).await
        }
        ("GET", "/metrics") => {
            let body = stats.prometheus();
            respond_text(&mut stream, deadline, 200, "OK", body.as_bytes()).await
        }
        ("GET", "/connections") => {
            let body = serde_json::to_vec(&serde_json::json!({
                "connections": connections.snapshot()
            }))
            .map_err(|_| io::Error::other("连接列表序列化失败"))?;
            respond(&mut stream, deadline, 200, "OK", "", &body).await
        }
        ("DELETE", "/connections") => {
            let count = connections.close_all();
            tracing::info!(event = "api_close_connections", count);
            respond(&mut stream, deadline, 204, "No Content", "", b"").await
        }
        ("DELETE", path) if path.starts_with("/connections/") => {
            let id = path
                .strip_prefix("/connections/")
                .and_then(|id| id.parse::<u64>().ok());
            match id {
                None => respond(&mut stream, deadline, 400, "Bad Request", "", b"").await,
                Some(id) if connections.close(id) => {
                    tracing::info!(event = "api_close_connection", id);
                    respond(&mut stream, deadline, 204, "No Content", "", b"").await
                }
                Some(_) => respond(&mut stream, deadline, 404, "Not Found", "", b"").await,
            }
        }
        _ => respond(&mut stream, deadline, 404, "Not Found", "", b"").await,
    }
}

struct Request<'a> {
    method: &'a str,
    path: &'a str,
    authorization: Option<&'a str>,
}

fn parse(head: &[u8]) -> Option<Request<'_>> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    if !matches!(request.parse(head), Ok(httparse::Status::Complete(_))) {
        return None;
    }
    if request.version != Some(1) {
        return None;
    }
    let method = request.method?;
    let path = request.path?;
    if path.contains('?') {
        return None;
    }
    let authorization = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))
        .and_then(|header| std::str::from_utf8(header.value).ok());
    Some(Request {
        method,
        path,
        authorization,
    })
}

fn parse_bearer(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

/// 定长比较，避免按字节提前返回泄露 token 前缀。
fn secure_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

async fn respond(
    stream: &mut TcpStream,
    deadline: Instant,
    code: u16,
    reason: &str,
    extra_headers: &str,
    body: &[u8],
) -> io::Result<()> {
    respond_with(
        stream,
        deadline,
        code,
        reason,
        "application/json",
        extra_headers,
        body,
    )
    .await
}

async fn respond_text(
    stream: &mut TcpStream,
    deadline: Instant,
    code: u16,
    reason: &str,
    body: &[u8],
) -> io::Result<()> {
    respond_with(
        stream,
        deadline,
        code,
        reason,
        "text/plain; version=0.0.4; charset=utf-8",
        "",
        body,
    )
    .await
}

async fn respond_with(
    stream: &mut TcpStream,
    deadline: Instant,
    code: u16,
    reason: &str,
    content_type: &str,
    extra_headers: &str,
    body: &[u8],
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{extra_headers}\r\n",
        body.len()
    );
    timeout_at(deadline, async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "管理 API 响应超时"))?
}
