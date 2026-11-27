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
    apply::ApplyState, config::ApiConfig, connections::Registry, telemetry::Stats,
    transport::httpupgrade::read_head,
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
    apply: Option<Arc<ApplyState>>,
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
                // 管理端口的 accept 错误必须和普通入口一致地分类：
                // 可恢复的（FD 耗尽等）退避重试，只有真正致命的才向上报。
                // 用 `?` 直接抛出会让**整个 Server 停止**——一个管理端口
                // 的瞬时 FD 耗竭不该带走所有代理入口。
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) if crate::runtime::recoverable_accept_error(&error) => {
                        tokio::time::sleep(crate::runtime::ACCEPT_BACKOFF).await;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let token = token.clone();
                let stats = stats.clone();
                let connections = connections.clone();
                let apply = apply.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = handle(stream, &token, &stats, &connections, apply.as_deref()).await;
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
    apply: Option<&ApplyState>,
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
    // 路由按**不含查询串**的路径匹配；`?inbound=` 等参数另行解析。
    let route = request
        .path
        .split_once('?')
        .map_or(request.path, |(path, _)| path);
    let known = matches!(
        route,
        "/healthz"
            | "/status"
            | "/stats"
            | "/stats/users"
            | "/stats/users/reset"
            | "/stats/users/limits"
            | "/metrics"
            | "/connections"
    ) || route.starts_with("/connections/");
    // 只读端点不接受 DELETE/POST；其余管理端点允许 GET/DELETE/POST。
    if matches!(route, "/metrics" | "/status") && request.method != "GET" {
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
    // POST 只有两个写端点；其余路径一律按方法不允许处理，避免
    // `POST /stats` 之类落到 404（那会误导成「端点不存在」）。
    let post_allowed = route == "/stats/users/reset" || route == "/stats/users/limits";
    let method_ok =
        matches!(request.method, "GET" | "DELETE") || (request.method == "POST" && post_allowed);
    if !method_ok {
        let (code, reason, headers) = if known {
            (405, "Method Not Allowed", "Allow: GET, DELETE\r\n")
        } else {
            (404, "Not Found", "")
        };
        return respond(&mut stream, deadline, code, reason, headers, b"").await;
    }
    let (inbound, user) = if request.method == "POST"
        && matches!(route, "/stats/users/reset" | "/stats/users/limits")
    {
        match query_filters(request.path) {
            Ok(filters) => filters,
            Err(error) => {
                return respond(
                    &mut stream,
                    deadline,
                    400,
                    "Bad Request",
                    "",
                    error.as_bytes(),
                )
                .await;
            }
        }
    } else {
        (None, None)
    };
    match (request.method, route) {
        ("GET", "/healthz") => {
            respond(&mut stream, deadline, 200, "OK", "", br#"{"status":"ok"}"#).await
        }
        // 配置应用结果。已认证读取成功一律 200，包括 `result:"rejected"`：
        // 这表示「读取成功」，不是「部署成功」；判定见 `rolled_back`。
        ("GET", "/status") => {
            let Some(apply) = apply else {
                // 嵌入式库实例没有重载协调器，不给假版本号。
                return respond(
                    &mut stream,
                    deadline,
                    503,
                    "Service Unavailable",
                    "",
                    br#"{"error_code":"apply_status_unavailable"}"#,
                )
                .await;
            };
            let body = apply.snapshot().to_json();
            respond(&mut stream, deadline, 200, "OK", "", &body).await
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
        ("POST", "/stats/users/reset") => {
            let count = stats.reset_users(inbound.as_deref(), user.as_deref());
            let body = serde_json::to_vec(&serde_json::json!({ "reset": count }))
                .map_err(|_| io::Error::other("重置结果序列化失败"))?;
            respond(&mut stream, deadline, 200, "OK", "", &body).await
        }
        // 设置软配额与到期时间（`?quota_bytes=` / `?expires_at_ms=`）。
        // 只影响之后的新连接，不断开已有连接。
        ("POST", "/stats/users/limits") => {
            // 两个参数各自可选，但**给了就必须能解析**：此前分别 `.ok()`，
            // 一个写错、另一个合法时仍返回 200 并静默忽略错误字段。
            let quota = match parse_optional(request.path, "quota_bytes") {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &mut stream,
                        deadline,
                        400,
                        "Bad Request",
                        "",
                        error.as_bytes(),
                    )
                    .await;
                }
            };
            let expires = match parse_optional(request.path, "expires_at_ms") {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &mut stream,
                        deadline,
                        400,
                        "Bad Request",
                        "",
                        error.as_bytes(),
                    )
                    .await;
                }
            };
            if quota.is_none() && expires.is_none() {
                return respond(
                    &mut stream,
                    deadline,
                    400,
                    "Bad Request",
                    "",
                    br#"{"error":"quota_bytes or expires_at_ms required"}"#,
                )
                .await;
            }
            let count = stats.set_user_limits(inbound.as_deref(), user.as_deref(), quota, expires);
            let body = serde_json::to_vec(&serde_json::json!({ "updated": count }))
                .map_err(|_| io::Error::other("限额结果序列化失败"))?;
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

/// 从 `?a=b&c=d` 形式的路径里取查询串。
fn query_of(path: &str) -> Option<&str> {
    path.split_once('?').map(|(_, query)| query)
}

/// 查询参数可选；出现但不是合法 `u64` 时返回字段级错误，由调用方回 400。
fn parse_optional(path: &str, name: &str) -> Result<Option<u64>, String> {
    match query_value(path, name) {
        None => Ok(None),
        Some(value) => value
            .parse()
            .map(Some)
            .map_err(|_| format!(r#"{{"error":"invalid {name}"}}"#)),
    }
}

fn query_value(path: &str, key: &str) -> Option<String> {
    query_of(path)?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| percent_decode(value))
}

/// 只有真正省略才允许扩大范围。
fn query_filters(path: &str) -> Result<(Option<String>, Option<String>), String> {
    let (mut inbound, mut user) = (None, None);
    for pair in query_of(path).unwrap_or_default().split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key);
        let slot = match key.as_str() {
            "inbound" => &mut inbound,
            "user" => &mut user,
            _ => continue,
        };
        let value = percent_decode(value);
        if slot.is_some() || value.trim().is_empty() {
            return Err(format!(r#"{{"error":"invalid {key}"}}"#));
        }
        *slot = Some(value);
    }
    Ok((inbound, user))
}

/// 只解码 `%XX` 与 `+`；这两个接口的取值是 tag 与用户名，不含其它需要转义的字符。
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
                match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
    // 查询串是合法输入（`/stats/users/reset?inbound=x`），保留原样交给路由层；
    // 早期实现直接拒绝带 `?` 的请求，导致所有带参数的端点都回 400。
    if path.len() > 2048 {
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
