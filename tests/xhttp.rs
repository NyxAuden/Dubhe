mod common;
#[path = "common/vmess.rs"]
mod vmess_client;

use std::{net::SocketAddr, sync::Arc};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Echo, Running};
use dubhe::config::{Xhttp, XhttpPadding};
use prost::bytes::{Buf, Bytes};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn config(mode: &str) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-xhttp",
            "tag": "xh",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "xudp": false,
            "allow_insecure_transport": true,
            "xhttp": {"path": "/GunService/Tun", "mode": mode}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

fn uuid_bytes() -> Vec<u8> {
    UUID.split('-')
        .flat_map(|part| {
            (0..part.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&part[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn vless_request(target: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0u8];
    bytes.extend_from_slice(&uuid_bytes());
    bytes.push(0); // addons
    bytes.push(1); // command TCP
    bytes.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            bytes.push(2);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes
}

async fn connect(running: &Running) -> TcpStream {
    TcpStream::connect(running.address).await.unwrap()
}

async fn read_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8(buffer).unwrap();
    (head, Vec::new())
}

async fn read_chunked_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line = read_line(stream).await;
        let size = usize::from_str_radix(line.split(';').next().unwrap().trim(), 16).unwrap();
        if size == 0 {
            return out;
        }
        let mut body = vec![0u8; size];
        stream.read_exact(&mut body).await.unwrap();
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.unwrap();
        out.extend_from_slice(&body);
        if out.windows(needle.len()).any(|window| window == needle) {
            return out;
        }
    }
}

async fn read_line(stream: &mut TcpStream) -> String {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line).unwrap();
        }
    }
}

async fn post(running: &Running, target: &str, body: &[u8]) -> String {
    let mut stream = connect(running).await;
    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let (head, _) = read_head(&mut stream).await;
    head
}

/// 回归：认证前的排队负载必须受**全入口共享字节预算**约束。
///
/// 此前只有「每会话条数」上限（`sc_max_buffered_posts`），会话数上限又是
/// 入口级的：最坏名义容量是 `单条上限 × 条数 × 会话数`，默认可达 GiB 级，
/// 且全部发生在认证之前。这里把预算调到很小，然后推送远超预算的数据。
///
/// 期望：服务端拒绝，而不是无限接收后把内存吃满。
#[tokio::test]
async fn unauthenticated_posts_are_bounded_by_shared_byte_budget() {
    let mut value = config("auto");
    value["limits"] = json!({"xhttp_buffer_bytes": 4096});
    let running = Running::start(value).await;

    // 单条就超过预算。允许两种 fail-closed 结果：
    // 返回非 200，或直接断开（服务端不做无界接收）。
    let oversized = vec![0x41u8; 16 * 1024];
    let mut stream = connect(&running).await;
    let head = format!(
        "POST /GunService/Tun/sess-big/0 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        oversized.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&oversized).await;
    let mut buffer = [0u8; 64];
    let verdict = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await;
    match verdict {
        // 断开（读到 EOF 或错误）：可接受。
        Ok(Ok(0)) | Ok(Err(_)) => {}
        // 有响应时必须不是 200。
        Ok(Ok(read)) => {
            let text = String::from_utf8_lossy(&buffer[..read]).to_string();
            assert!(
                !text.starts_with("HTTP/1.1 200"),
                "超过共享字节预算的未认证 POST 不得被接受，实际返回 {text}"
            );
        }
        Err(_) => panic!("超过共享字节预算的未认证 POST 既未被拒也未断开（挂起）"),
    }
    running.shutdown().await;
}

#[tokio::test]
async fn packet_up_posts_feed_a_get_downlink() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("auto")).await;
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"hello");
    let response = post(&running, "/GunService/Tun/sess1/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let mut stream = connect(&running).await;
    stream
        .write_all(b"GET /GunService/Tun/sess1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("text/event-stream"), "{head}");
    let data = read_chunked_until(&mut stream, b"hello").await;
    assert!(data.windows(5).any(|window| window == b"hello"));
}

#[tokio::test]
async fn stream_one_echoes_point_to_point() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("auto")).await;
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"ping");
    let mut stream = connect(&running).await;
    let head = format!(
        "POST /GunService/Tun HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let data = read_chunked_until(&mut stream, b"ping").await;
    assert!(data.windows(4).any(|window| window == b"ping"));
}

#[tokio::test]
async fn wrong_path_and_oversized_padding_are_rejected() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("auto")).await;
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"x");
    let response = post(&running, "/wrong/sess/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    let mut stream = connect(&running).await;
    let pad = "A".repeat(5_000);
    let head = format!(
        "POST /GunService/Tun/s2/0?x_padding={pad} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");

    // 配置 Host 后，不匹配的 Host 必须拒绝；响应与错误路径一致（404），不泄露匹配细节。
    let mut value = config("auto");
    value["inbounds"][0]["xhttp"]["host"] = json!("example.com");
    let running = Running::start(value).await;
    let response = post(&running, "/GunService/Tun/h/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");

    // 非 GET/POST 方法在形状判定阶段即被拒绝。
    let running = Running::start(config("auto")).await;
    let mut stream = connect(&running).await;
    let head = format!(
        "PUT /GunService/Tun HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
}

#[tokio::test]
async fn h2c_stream_one_relays_through_the_h2_adapter() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("auto")).await;
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"h2-ping");
    let tcp = TcpStream::connect(running.address).await.unwrap();
    let (mut client, connection) = h2::client::handshake(tcp).await.unwrap();
    tokio::spawn(connection);
    let request = http::Request::builder()
        .method("POST")
        .uri("/GunService/Tun")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    send.send_data(body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut incoming = response.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = incoming.data().await {
        out.extend_from_slice(&chunk.unwrap());
        if out.windows(7).any(|window| window == b"h2-ping") {
            break;
        }
    }
    assert!(out.windows(7).any(|window| window == b"h2-ping"));
}

#[tokio::test]
async fn custom_headers_and_cookie_session_are_supported() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config("auto");
    value["inbounds"][0]["xhttp"]["headers"] = json!({"x-custom": "yes"});
    let running = Running::start(value).await;

    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"cookie");
    let mut stream = connect(&running).await;
    let head = format!(
        "POST /GunService/Tun/cook1/0 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    let mut stream = connect(&running).await;
    stream
        .write_all(
            b"GET /GunService/Tun HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: x_session=cook1\r\n\r\n",
        )
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("x-custom: yes"),
        "{head}"
    );
    let data = read_chunked_until(&mut stream, b"cookie").await;
    assert!(data.windows(6).any(|window| window == b"cookie"));
}

fn trojan_config() -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "trojan-xhttp",
            "tag": "xt",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": "secret"}],
            "allow_insecure_transport": true,
            "xhttp": {"path": "/GunService/Tun", "mode": "auto"}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

#[tokio::test]
async fn trojan_packet_up_relays_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(trojan_config()).await;
    let mut body = common::trojan_header(1, common::address(echo.address), "secret");
    body.extend_from_slice(b"trojan");
    let response = post(&running, "/GunService/Tun/ts1/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let mut stream = connect(&running).await;
    stream
        .write_all(b"GET /GunService/Tun/ts1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let data = read_chunked_until(&mut stream, b"trojan").await;
    assert!(data.windows(6).any(|window| window == b"trojan"));
}

#[tokio::test]
async fn h2c_trojan_stream_one_relays_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(trojan_config()).await;
    let (mut client, connection) = h2::client::handshake(connect(&running).await)
        .await
        .unwrap();
    tokio::spawn(connection);
    let mut body = common::trojan_header(1, common::address(echo.address), "secret");
    body.extend_from_slice(b"trojan-h2");
    let request = http::Request::builder()
        .method("POST")
        .uri("/GunService/Tun")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    send.send_data(body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut incoming = response.into_body();
    let mut out = Vec::new();
    while out.windows(9).all(|window| window != b"trojan-h2") {
        let chunk = timeout(Duration::from_secs(3), incoming.data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        out.extend_from_slice(&chunk);
    }
}

#[tokio::test]
async fn stream_up_keeps_downlink_open_after_upload_end() {
    let echo = Echo::tcp("127.0.0.1", true).await;
    let running = Running::start(config("auto")).await;
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"up");
    let mut upload = connect(&running).await;
    let head = "POST /GunService/Tun/su1 HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    upload.write_all(head.as_bytes()).await.unwrap();
    let chunk = format!("{:x}\r\n", body.len());
    upload.write_all(chunk.as_bytes()).await.unwrap();
    upload.write_all(&body).await.unwrap();
    upload.write_all(b"\r\n").await.unwrap();
    let (head, _) = timeout(Duration::from_secs(3), read_head(&mut upload))
        .await
        .unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // 上行结束不强制关闭下行。
    upload.write_all(b"0\r\n\r\n").await.unwrap();
    upload.flush().await.unwrap();

    let mut stream = connect(&running).await;
    stream
        .write_all(b"GET /GunService/Tun/su1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = timeout(Duration::from_secs(3), read_head(&mut stream))
        .await
        .unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let data = timeout(
        Duration::from_secs(3),
        read_chunked_until(&mut stream, b"up"),
    )
    .await
    .unwrap();
    assert!(data.windows(2).any(|window| window == b"up"));
}

fn vmess_config(cert: &common::Certificate) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "vmess-xhttp",
            "tag": "vx",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": vmess_client::UUID}],
            "xhttp": {"path": "/GunService/Tun", "mode": "auto"},
            "allow_insecure_body": true,
            "allow_authenticated_length": true,
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

async fn pump_chunks<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    mut src: R,
    mut dst: W,
) {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = src.read(&mut buffer).await.unwrap();
        if read == 0 {
            dst.write_all(b"0\r\n\r\n").await.unwrap();
            dst.flush().await.unwrap();
            return;
        }
        let head = format!("{:x}\r\n", read);
        dst.write_all(head.as_bytes()).await.unwrap();
        dst.write_all(&buffer[..read]).await.unwrap();
        dst.write_all(b"\r\n").await.unwrap();
        dst.flush().await.unwrap();
    }
}

async fn pump_dechunk<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    mut src: R,
    mut dst: W,
) {
    loop {
        let mut line = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            src.read_exact(&mut byte).await.unwrap();
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        let text = String::from_utf8(line).unwrap();
        let size = usize::from_str_radix(text.trim(), 16).unwrap();
        if size == 0 {
            return;
        }
        let mut body = vec![0u8; size];
        src.read_exact(&mut body).await.unwrap();
        let mut crlf = [0u8; 2];
        src.read_exact(&mut crlf).await.unwrap();
        dst.write_all(&body).await.unwrap();
        dst.flush().await.unwrap();
    }
}

#[tokio::test]
async fn vmess_stream_one_over_tls_relays_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let running = Running::start(vmess_config(&cert)).await;
    let mut tls = cert.connect_alpn(running.address, &[b"http/1.1"]).await;
    tls.write_all(
        b"POST /GunService/Tun HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .await
    .unwrap();
    let (head, _) = read_head_tls(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_io);
    let (tls_read, tls_write) = tokio::io::split(tls);
    let up = tokio::spawn(pump_chunks(server_read, tls_write));
    let down = tokio::spawn(pump_dechunk(tls_read, server_write));

    let request = vmess_client::Request::new(1, vmess_client::target(echo.address), 5, 0);
    let mut client =
        vmess_client::Client::start(&mut client_io, request, Some(b"vmess-xhttp")).await;
    let expected = b"vmess-xhttp";
    assert_eq!(client.read(expected.len()).await, expected);
    client.finish().await;
    up.await.unwrap();
    let _ = down.await;
}

async fn read_head_tls<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> (String, Vec<u8>) {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return (String::from_utf8(buffer).unwrap(), Vec::new());
        }
    }
}

#[tokio::test]
async fn packet_up_out_of_order_is_delivered_in_sequence() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("auto")).await;
    let mut first = vless_request(echo.address);
    first.extend_from_slice(b"hello");
    let response = post(&running, "/GunService/Tun/ord/1", b"world").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let response = post(&running, "/GunService/Tun/ord/0", &first).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let mut stream = connect(&running).await;
    stream
        .write_all(b"GET /GunService/Tun/ord HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let data = read_chunked_until(&mut stream, b"helloworld").await;
    assert!(
        data.windows(10).any(|window| window == b"helloworld"),
        "{data:?}"
    );
}

#[tokio::test]
async fn sessions_are_isolated() {
    let first_echo = Echo::tcp("127.0.0.1", false).await;
    let second_echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("auto")).await;
    for (session, echo, text) in [
        ("a", first_echo.address, "alpha"),
        ("b", second_echo.address, "beta"),
    ] {
        let mut body = vless_request(echo);
        body.extend_from_slice(text.as_bytes());
        let response = post(&running, &format!("/GunService/Tun/{session}/0"), &body).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
    for (session, needle, other) in [("a", "alpha", "beta"), ("b", "beta", "alpha")] {
        let mut stream = connect(&running).await;
        stream
            .write_all(
                format!("GET /GunService/Tun/{session} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let (head, _) = read_head(&mut stream).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let data = read_chunked_until(&mut stream, needle.as_bytes()).await;
        assert!(
            data.windows(needle.len())
                .any(|window| window == needle.as_bytes())
        );
        assert!(
            !data
                .windows(other.len())
                .any(|window| window == other.as_bytes())
        );
    }
}

fn tuned_config(xhttp: Value, limits: Value) -> Value {
    let mut value = config("auto");
    value["inbounds"][0]["xhttp"] = xhttp;
    value["limits"] = limits;
    value
}

async fn expect_closed(running: &Running, target: &str, body: &[u8]) {
    let mut stream = connect(running).await;
    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut byte = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await;
    match result {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("预期连接被拒绝，但收到数据"),
        Err(_) => panic!("预期连接关闭，但仍在等待"),
    }
}

#[tokio::test]
async fn duplicate_sequence_oversized_body_and_session_cap_fail_closed() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let body = vless_request(echo.address);
    let running = Running::start(config("auto")).await;
    let response = post(&running, "/GunService/Tun/dup/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    expect_closed(&running, "/GunService/Tun/dup/0", &body).await;

    let mut oversized = vless_request(echo.address);
    oversized.extend_from_slice(&[0x41; 128]);
    let running = Running::start(tuned_config(
        json!({"path": "/GunService/Tun", "sc_max_each_post_bytes": 64}),
        json!({}),
    ))
    .await;
    let response = post(&running, "/GunService/Tun/big/0", &oversized).await;
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");

    let running = Running::start(tuned_config(
        json!({"path": "/GunService/Tun"}),
        json!({"max_xhttp_sessions": 1}),
    ))
    .await;
    let response = post(&running, "/GunService/Tun/one/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    expect_closed(&running, "/GunService/Tun/two/0", &body).await;
}

#[tokio::test]
async fn expired_session_late_get_creates_new_pending_session() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let body = vless_request(echo.address);
    let running = Running::start(tuned_config(
        json!({"path": "/GunService/Tun", "session_ttl_ms": 1000}),
        json!({}),
    ))
    .await;
    let response = post(&running, "/GunService/Tun/old/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    let mut stream = connect(&running).await;
    stream
        .write_all(b"GET /GunService/Tun/old HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await;
    // 与 Xray 一致：GET 可先于 POST 建立待上行会话；旧会话已过期，
    // 这里是新会话，不应回放旧连接的业务数据。
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
}

#[tokio::test]
async fn tls_h2_stream_one_relays() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let mut value = config("auto");
    value["inbounds"][0]["allow_insecure_transport"] = json!(false);
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;
    let tls = cert.connect_alpn(running.address, &[b"h2"]).await;
    let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(connection);
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"tls-h2");
    let request = http::Request::builder()
        .method("POST")
        .uri("/GunService/Tun")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    send.send_data(body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut incoming = response.into_body();
    let mut out = Vec::new();
    while out.windows(6).all(|window| window != b"tls-h2") {
        let chunk = incoming.data().await.unwrap().unwrap();
        out.extend_from_slice(&chunk);
    }
}

#[tokio::test]
async fn h2c_packet_up_sessions_stay_isolated() {
    let first = Echo::tcp("127.0.0.1", false).await;
    let second = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("packet-up")).await;
    let (mut client, connection) = h2::client::handshake(connect(&running).await)
        .await
        .unwrap();
    tokio::spawn(connection);

    for (session, echo, payload) in [
        ("a", &first, b"h2-a".as_slice()),
        ("b", &second, b"h2-b".as_slice()),
    ] {
        let mut body = vless_request(echo.address);
        body.extend_from_slice(payload);
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("/GunService/Tun/{session}/0"))
            .body(())
            .unwrap();
        let (response, mut send) = client.send_request(request, false).unwrap();
        send.send_data(body.into(), true).unwrap();
        assert_eq!(response.await.unwrap().status(), http::StatusCode::OK);

        let request = http::Request::builder()
            .method("GET")
            .uri("/GunService/Tun")
            .header("cookie", format!("x_session={session}"))
            .body(())
            .unwrap();
        let (response, _send) = client.send_request(request, true).unwrap();
        let response = timeout(Duration::from_secs(3), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut incoming = response.into_body();
        let mut out = Vec::new();
        while out.windows(payload.len()).all(|window| window != payload) {
            let chunk = timeout(Duration::from_secs(3), incoming.data())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            out.extend_from_slice(&chunk);
        }
    }
}

#[tokio::test]
async fn tls_xhttp_rejects_unoffered_alpn() {
    let cert = common::Certificate::new();
    let mut value = config("auto");
    value["inbounds"][0]["allow_insecure_transport"] = json!(false);
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;
    assert!(
        cert.try_connect_alpn(running.address, &[b"nope"])
            .await
            .is_err(),
        "TLS 客户端未提供 h2/http1.1 时必须握手失败"
    );
}

#[tokio::test]
async fn explicit_packet_up_mode_accepts_downlink_get_without_sequence() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("packet-up")).await;
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"packet-mode");
    let response = post(&running, "/GunService/Tun/mode0/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let mut stream = connect(&running).await;
    stream
        .write_all(b"GET /GunService/Tun/mode0 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let data = read_chunked_until(&mut stream, b"packet-mode").await;
    assert!(data.windows(11).any(|window| window == b"packet-mode"));

    // GET 带序号不属于 packet-up 的下行形状。
    let mut stream = connect(&running).await;
    stream
        .write_all(b"GET /GunService/Tun/other/0 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
}

#[tokio::test]
async fn h2c_stream_up_and_custom_headers_relay() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config("stream-up");
    value["inbounds"][0]["xhttp"]["headers"] = json!({"x-custom": "h2-yes"});
    let running = Running::start(value).await;
    let (mut client, connection) = h2::client::handshake(connect(&running).await)
        .await
        .unwrap();
    tokio::spawn(connection);

    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"h2-up");
    let request = http::Request::builder()
        .method("POST")
        .uri("/GunService/Tun/up")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    send.send_data(body.into(), true).unwrap();
    assert_eq!(response.await.unwrap().status(), http::StatusCode::OK);

    let request = http::Request::builder()
        .method("GET")
        .uri("/GunService/Tun/up")
        .body(())
        .unwrap();
    let (response, _send) = client.send_request(request, true).unwrap();
    let response = timeout(Duration::from_secs(3), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-custom")
            .and_then(|value| value.to_str().ok()),
        Some("h2-yes")
    );
    let mut incoming = response.into_body();
    let mut out = Vec::new();
    while out.windows(5).all(|window| window != b"h2-up") {
        let chunk = timeout(Duration::from_secs(3), incoming.data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        out.extend_from_slice(&chunk);
    }
}

#[tokio::test]
async fn bad_authentication_never_dials_target() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let running = Running::start(config("auto")).await;
    let mut body = vec![0u8];
    body.extend_from_slice(&[0x22; 16]);
    body.push(0);
    body.push(1);
    body.extend_from_slice(&target.port().to_be_bytes());
    body.push(1);
    let std::net::IpAddr::V4(ip) = target.ip() else {
        unreachable!("回环监听固定为 IPv4")
    };
    body.extend_from_slice(&ip.octets());
    body.extend_from_slice(b"bad-uuid");
    let response = post(&running, "/GunService/Tun", &body).await;
    assert!(response.starts_with("HTTP/1.1 "), "{response}");
    assert!(
        timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "错误身份的请求不得拨号目标"
    );
}

#[tokio::test]
async fn vmess_tls_h2_stream_one_relays_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let value = json!({
        "version": 1,
        "inbounds": [{
            "type": "vmess-xhttp",
            "tag": "xh",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": vmess_client::UUID}],
            "allow_insecure_body": true,
            "allow_authenticated_length": true,
            "xhttp": {"path": "/GunService/Tun", "mode": "auto"},
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    });
    let running = Running::start(value).await;
    let tls = cert.connect_alpn(running.address, &[b"h2"]).await;
    let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(connection);
    let request = http::Request::builder()
        .method("POST")
        .uri("/GunService/Tun")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    let response = timeout(Duration::from_secs(3), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    // 把 h2 的请求/响应流桥接到本地双工流，供既有 VMess 测试客户端使用。
    let mut incoming = response.into_body();
    let (app, bridge) = tokio::io::duplex(64 * 1024);
    let (mut down_read, mut down_write) = tokio::io::split(bridge);
    tokio::spawn(async move {
        while let Some(chunk) = incoming.data().await {
            match chunk {
                Ok(chunk) => {
                    if down_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match down_read.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let _ = send.send_data(Vec::new().into(), true);
                    break;
                }
                Ok(read) => {
                    if send
                        .send_data(buffer[..read].to_vec().into(), false)
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    let vmess = vmess_client::Request::new(1, vmess_client::target(echo.address), 5, 0);
    let mut client = vmess_client::Client::start(app, vmess, Some(b"vmess-h2")).await;
    assert_eq!(client.read(8).await, b"vmess-h2");
}

// ---------- XHTTP/3（QUIC） ----------

fn h3_config(cert: &common::Certificate, mode: &str) -> Value {
    let mut value = config(mode);
    value["inbounds"][0]["allow_insecure_transport"] = json!(false);
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    value["inbounds"][0]["xhttp"]["h3"] = json!(true);
    value
}

/// 最小 HTTP/3 客户端：信任测试自签证书，ALPN 固定 `h3`。
struct H3Client {
    endpoint: quinn::Endpoint,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: tokio::task::JoinHandle<()>,
}

async fn h3_connect(running: &Running, cert: &common::Certificate) -> H3Client {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).unwrap();
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(5)).unwrap(),
    ));
    client.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client);
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(running.address, "localhost").unwrap(),
    )
    .await
    .expect("QUIC 握手不应挂起")
    .expect("QUIC 握手应成功");

    let (mut connection, send) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.wait_idle().await;
    });
    H3Client {
        endpoint,
        send,
        driver,
    }
}

impl Drop for H3Client {
    fn drop(&mut self) {
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
        self.driver.abort();
    }
}

async fn h3_read_body(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(chunk) = timeout(Duration::from_secs(3), stream.recv_data())
            .await
            .expect("等待 HTTP/3 响应体超时")
            .unwrap()
        else {
            return out;
        };
        let mut chunk = chunk;
        let size = chunk.remaining();
        out.extend_from_slice(&chunk.copy_to_bytes(size));
    }
}

/// 下行是长连接事件流，读到目标字节即可，不等待流结束。
async fn h3_read_until(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    needle: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(chunk) = timeout(Duration::from_secs(3), stream.recv_data())
            .await
            .expect("等待 HTTP/3 下行超时")
            .unwrap()
        else {
            return out;
        };
        let mut chunk = chunk;
        let size = chunk.remaining();
        out.extend_from_slice(&chunk.copy_to_bytes(size));
        if out.windows(needle.len()).any(|window| window == needle) {
            return out;
        }
    }
}

#[tokio::test]
async fn h3_stream_one_relays_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let running = Running::start(h3_config(&cert, "auto")).await;
    let mut client = h3_connect(&running, &cert).await;

    let request = http::Request::builder()
        .method("POST")
        .uri("https://localhost/GunService/Tun")
        .body(())
        .unwrap();
    let mut stream = timeout(Duration::from_secs(3), client.send.send_request(request))
        .await
        .expect("h3 建流超时")
        .unwrap();

    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"h3-stream-one");
    stream.send_data(Bytes::from(body)).await.unwrap();
    stream.finish().await.unwrap();

    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let data = h3_read_until(&mut stream, b"h3-stream-one").await;
    assert!(
        data.windows(b"h3-stream-one".len())
            .any(|window| window == b"h3-stream-one"),
        "{data:?}"
    );
}

#[tokio::test]
async fn h3_packet_up_posts_feed_a_get_downlink() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let running = Running::start(h3_config(&cert, "packet-up")).await;
    let mut client = h3_connect(&running, &cert).await;

    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"h3-packet");
    let request = http::Request::builder()
        .method("POST")
        .uri("https://localhost/GunService/Tun/h3sess/0")
        .body(())
        .unwrap();
    let mut upload = client.send.send_request(request).await.unwrap();
    upload.send_data(Bytes::from(body)).await.unwrap();
    upload.finish().await.unwrap();
    let response = timeout(Duration::from_secs(3), upload.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(h3_read_body(&mut upload).await.is_empty());

    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/GunService/Tun/h3sess")
        .body(())
        .unwrap();
    let mut downlink = client.send.send_request(request).await.unwrap();
    let response = timeout(Duration::from_secs(3), downlink.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let data = h3_read_until(&mut downlink, b"h3-packet").await;
    assert!(
        data.windows(b"h3-packet".len())
            .any(|window| window == b"h3-packet"),
        "{data:?}"
    );
}

// --- Xray extra 配置兼容：解析、冲突、拒绝与运行时生效 ---

fn parse_xhttp(value: Value) -> Result<Xhttp, serde_json::Error> {
    serde_json::from_value(value)
}

#[test]
fn xray_extra_maps_supported_server_fields() {
    let xhttp = parse_xhttp(json!({
        "path": "/GunService/Tun",
        "extra": {
            "xPaddingBytes": "128-512",
            "scMaxEachPostBytes": "2048-4096",
            "scMaxBufferedPosts": 7,
            "noSSEHeader": true
        }
    }))
    .unwrap();
    assert_eq!(xhttp.x_padding, Some(XhttpPadding { from: 128, to: 512 }));
    assert_eq!(xhttp.sc_max_each_post_bytes, 4096);
    assert_eq!(xhttp.sc_max_buffered_posts, 7);
    assert!(xhttp.no_sse_header);
    xhttp.validate(0).unwrap();

    // 上游 Int32Range 也接受纯整数。
    let xhttp = parse_xhttp(json!({
        "path": "/GunService/Tun",
        "extra": {"xPaddingBytes": 256, "scMaxEachPostBytes": 900000}
    }))
    .unwrap();
    assert_eq!(xhttp.x_padding, Some(XhttpPadding { from: 256, to: 256 }));
    assert_eq!(xhttp.sc_max_each_post_bytes, 900_000);

    // 0 / 0 按 Xray 归一化为默认值；from > to 时交换。
    let xhttp = parse_xhttp(json!({
        "path": "/GunService/Tun",
        "extra": {"xPaddingBytes": 0, "scMaxBufferedPosts": 0}
    }))
    .unwrap();
    assert_eq!(
        xhttp.x_padding,
        Some(XhttpPadding {
            from: 100,
            to: 1000
        })
    );
    assert_eq!(xhttp.sc_max_buffered_posts, 30);
    let xhttp = parse_xhttp(json!({"path": "/x", "extra": {"xPaddingBytes": "1000-100"}})).unwrap();
    assert_eq!(
        xhttp.x_padding,
        Some(XhttpPadding {
            from: 100,
            to: 1000
        })
    );
}

#[test]
fn xray_extra_maps_obfs_padding_and_placement_fields() {
    let xhttp = parse_xhttp(json!({
        "path": "/GunService/Tun",
        "extra": {
            "xPaddingObfsMode": true,
            "xPaddingKey": "pad",
            "xPaddingHeader": "X-Pad",
            "xPaddingPlacement": "cookie",
            "xPaddingMethod": "repeat-x",
            "sessionIDPlacement": "header",
            "sessionIDKey": "X-Sid",
            "seqPlacement": "query",
            "seqKey": "seq",
            "uplinkDataPlacement": "cookie",
            "uplinkDataKey": "bin",
            "serverMaxHeaderBytes": 16384
        }
    }))
    .unwrap();
    assert!(xhttp.x_padding_obfs_mode);
    assert_eq!(xhttp.x_padding_key, "pad");
    assert_eq!(xhttp.x_padding_header, "X-Pad");
    assert_eq!(xhttp.x_padding_placement, "cookie");
    assert_eq!(xhttp.x_padding_method, "repeat-x");
    assert_eq!(xhttp.session_id_placement, "header");
    assert_eq!(xhttp.session_id_key.as_deref(), Some("X-Sid"));
    assert_eq!(xhttp.seq_placement, "query");
    assert_eq!(xhttp.seq_key.as_deref(), Some("seq"));
    assert_eq!(xhttp.uplink_data_placement, "cookie");
    assert_eq!(xhttp.uplink_data_key.as_deref(), Some("bin"));
    assert_eq!(xhttp.server_max_header_bytes(), 16384);
    xhttp.validate(0).unwrap();

    // tokenish 需要 HPACK Huffman 长度表；当前明确拒绝而不是假装支持。
    let xhttp = parse_xhttp(json!({
        "path": "/x", "extra": {"xPaddingMethod": "tokenish"}
    }))
    .unwrap();
    let error = xhttp.validate(0).unwrap_err().to_string();
    assert!(error.contains("tokenish"), "{error}");
}

#[test]
fn xray_extra_conflicts_with_top_level_are_rejected() {
    for (field, value) in [
        (
            "xPaddingBytes",
            json!({"path": "/x", "x_padding": {"from": 100, "to": 200},
                   "extra": {"xPaddingBytes": "64-64"}}),
        ),
        (
            "scMaxEachPostBytes",
            json!({"path": "/x", "sc_max_each_post_bytes": 1024,
                   "extra": {"scMaxEachPostBytes": 2048}}),
        ),
        (
            "scMaxBufferedPosts",
            json!({"path": "/x", "sc_max_buffered_posts": 8,
                   "extra": {"scMaxBufferedPosts": 9}}),
        ),
        (
            "noSSEHeader",
            json!({"path": "/x", "no_sse_header": false,
                   "extra": {"noSSEHeader": true}}),
        ),
    ] {
        let error = parse_xhttp(value).unwrap_err().to_string();
        assert!(error.contains(field), "{error}");
        assert!(error.contains("冲突"), "{error}");
    }

    // 完整 Config 嵌套路径同样拒绝，而不只是单独反序列化 Xhttp。
    let mut value = config("auto");
    value["inbounds"][0]["xhttp"] = json!({
        "path": "/GunService/Tun",
        "x_padding": {"from": 100, "to": 200},
        "extra": {"xPaddingBytes": "64-64"}
    });
    assert!(dubhe::Config::from_json(&value.to_string()).is_err());
    value["inbounds"][0]["xhttp"] = json!({
        "path": "/GunService/Tun",
        "extra": {"downloadSettings": {}}
    });
    assert!(dubhe::Config::from_json(&value.to_string()).is_err());
}

#[test]
fn xray_extra_rejects_wire_changing_fields() {
    for field in [
        "downloadSettings",
        "host",
        "path",
        "mode",
        "headers",
        "uplinkHTTPMethod",
        "sessionIDTable",
        "sessionIDLength",
        "uplinkChunkSize",
        "noGRPCHeader",
        "scMinPostsIntervalMs",
        "scStreamUpServerSecs",
        "xmux",
        "h2Params",
        "extra",
    ] {
        let mut extra = serde_json::Map::new();
        extra.insert(field.to_owned(), json!(true));
        let error = parse_xhttp(json!({"path": "/x", "extra": extra}))
            .unwrap_err()
            .to_string();
        assert!(error.contains(field), "{error}");
        assert!(error.contains("不受支持"), "{error}");
    }

    // 未知字段仍由 deny_unknown_fields 拒绝（extra 内与顶层各验证一次）。
    let error = parse_xhttp(json!({"path": "/x", "extra": {"madeUp": 1}}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown field"), "{error}");
    let error = parse_xhttp(json!({"path": "/x", "madeUp": 1}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown field"), "{error}");
}

#[test]
fn xray_extra_values_fail_closed_and_respect_bounds() {
    for (needle, value) in [
        (
            "不能禁用",
            json!({"path": "/x", "extra": {"xPaddingBytes": -1}}),
        ),
        (
            "不能禁用",
            json!({"path": "/x", "extra": {"xPaddingBytes": "0-100"}}),
        ),
        (
            "正整数",
            json!({"path": "/x", "extra": {"scMaxEachPostBytes": -5}}),
        ),
        (
            "非负整数",
            json!({"path": "/x", "extra": {"scMaxBufferedPosts": -1}}),
        ),
        (
            "范围字符串",
            json!({"path": "/x", "extra": {"xPaddingBytes": "abc"}}),
        ),
    ] {
        let error = parse_xhttp(value).unwrap_err().to_string();
        assert!(error.contains(needle), "{error}");
    }

    // 映射后仍走统一 validate 的资源上限。
    assert!(
        parse_xhttp(json!({"path": "/x", "extra": {"xPaddingBytes": "1-20000"}}))
            .unwrap()
            .validate(0)
            .is_err()
    );
    assert!(
        parse_xhttp(json!({"path": "/x", "extra": {"scMaxEachPostBytes": 32}}))
            .unwrap()
            .validate(0)
            .is_err()
    );
    assert!(
        parse_xhttp(json!({"path": "/x", "extra": {"scMaxBufferedPosts": 2048}}))
            .unwrap()
            .validate(0)
            .is_err()
    );
}

#[tokio::test]
async fn xray_extra_limits_and_no_sse_header_apply_to_live_inbound() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let body = vless_request(echo.address);
    let running = Running::start(tuned_config(
        json!({
            "path": "/GunService/Tun",
            "extra": {"scMaxEachPostBytes": 64, "noSSEHeader": true}
        }),
        json!({}),
    ))
    .await;

    let mut oversized = body.clone();
    oversized.extend_from_slice(&[0x41; 128]);
    let response = post(&running, "/GunService/Tun/extra/0", &oversized).await;
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");

    let response = post(&running, "/GunService/Tun/extra/0", &body).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let mut stream = connect(&running).await;
    stream
        .write_all(b"GET /GunService/Tun/extra HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        !head
            .to_ascii_lowercase()
            .contains("content-type: text/event-stream"),
        "{head}"
    );
}

#[tokio::test]
async fn xray_extra_server_max_header_bytes_limits_live_h1() {
    let request = format!(
        "GET /GunService/Tun HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Fill: {}\r\n\r\n",
        "A".repeat(600)
    );

    // 默认 8192 上限接受该请求，随后因缺少会话返回 400。
    let running = Running::start(config("auto")).await;
    let mut stream = connect(&running).await;
    stream.write_all(request.as_bytes()).await.unwrap();
    let (head, _) = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");

    // 显式 512 上限在解析阶段拒绝，连接直接关闭且不产生 HTTP 响应。
    let running = Running::start(tuned_config(
        json!({
            "path": "/GunService/Tun",
            "extra": {"serverMaxHeaderBytes": 512}
        }),
        json!({}),
    ))
    .await;
    let mut stream = connect(&running).await;
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buffer = [0u8; 64];
    let read = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await;
    match read {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
        Ok(Ok(size)) => panic!("超限请求不应产生响应: {:?}", &buffer[..size]),
    }
}

#[tokio::test]
async fn xray_extra_obfs_padding_header_meta_and_uplink_data_apply_live() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"obfs-packet");
    let encoded = URL_SAFE_NO_PAD.encode(&body);
    let running = Running::start(tuned_config(
        json!({
            "path": "/GunService/Tun",
            "extra": {
                "xPaddingObfsMode": true,
                "xPaddingKey": "pad",
                "xPaddingHeader": "X-Pad",
                "xPaddingPlacement": "header",
                "xPaddingBytes": "8-8",
                "sessionIDPlacement": "header",
                "sessionIDKey": "X-Sid",
                "seqPlacement": "header",
                "seqKey": "X-Seq",
                "uplinkDataPlacement": "header",
                "uplinkDataKey": "X-Data"
            }
        }),
        json!({}),
    ))
    .await;

    let mut stream = connect(&running).await;
    let head = format!(
        "POST /GunService/Tun HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: XXXXXXXX\r\nX-Sid: obfs1\r\nX-Seq: 0\r\nX-Data-0: {encoded}\r\nContent-Length: 0\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let (response, _) = read_head(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("X-Pad: XXXXXXXX"), "{response}");

    // 混淆 padding 缺失或长度不符必须拒绝，而不是静默跳过。
    for (padding, expected) in [("", "HTTP/1.1 400"), ("X-Pad: XXX\r\n", "HTTP/1.1 400")] {
        let mut bad = connect(&running).await;
        let head = format!(
            "POST /GunService/Tun HTTP/1.1\r\nHost: 127.0.0.1\r\n{padding}X-Sid: obfs1\r\nX-Seq: 1\r\nX-Data-0: {encoded}\r\nContent-Length: 0\r\n\r\n"
        );
        bad.write_all(head.as_bytes()).await.unwrap();
        let (response, _) = read_head(&mut bad).await;
        assert!(response.starts_with(expected), "{response}");
    }

    let mut downlink = connect(&running).await;
    downlink
        .write_all(
            b"GET /GunService/Tun HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: XXXXXXXX\r\nX-Sid: obfs1\r\n\r\n",
        )
        .await
        .unwrap();
    let (head, _) = read_head(&mut downlink).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("X-Pad: XXXXXXXX"), "{head}");
    let data = timeout(
        Duration::from_secs(3),
        read_chunked_until(&mut downlink, b"obfs-packet"),
    )
    .await
    .unwrap();
    assert!(
        data.windows(b"obfs-packet".len())
            .any(|window| window == b"obfs-packet"),
        "{data:?}"
    );
}
