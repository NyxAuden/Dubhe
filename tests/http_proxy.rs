mod common;

use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Echo, Running};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn config(kind: &str, users: Value) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": kind,
            "tag": "proxy",
            "listen": "127.0.0.1:0",
            "users": users
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

fn authority(address: SocketAddr) -> String {
    match address.ip() {
        std::net::IpAddr::V4(ip) => format!("{ip}:{}", address.port()),
        std::net::IpAddr::V6(ip) => format!("[{ip}]:{}", address.port()),
    }
}

async fn read_head(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return String::from_utf8_lossy(&buffer).into_owned();
        }
    }
}

async fn read_some(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = [0u8; 1024];
    let read = stream.read(&mut buffer).await.unwrap();
    buffer[..read].to_vec()
}

async fn socks5_connect<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    target: SocketAddr,
) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0]);
    let mut request = vec![5, 1, 0, 1];
    match target.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => {
            request[3] = 4;
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
}

#[tokio::test]
async fn connect_tunnel_relays_bytes() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("http", json!([]))).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        authority(echo.address),
        authority(echo.address)
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    stream.write_all(b"tunnel").await.unwrap();
    let mut data = Vec::new();
    while data.windows(6).all(|window| window != b"tunnel") {
        let chunk = read_some(&mut stream).await;
        assert!(!chunk.is_empty());
        data.extend_from_slice(&chunk);
    }
}

#[tokio::test]
async fn absolute_form_is_rewritten_to_origin_form() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("http", json!([]))).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();
    let request = format!(
        "GET http://{}/hello?q=1 HTTP/1.1\r\nHost: {}\r\nProxy-Connection: keep-alive\r\n\r\n",
        authority(echo.address),
        authority(echo.address)
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let echoed = read_some(&mut stream).await;
    let echoed = String::from_utf8_lossy(&echoed);
    assert!(
        echoed.starts_with("GET /hello?q=1 HTTP/1.1\r\n"),
        "{echoed}"
    );
    assert!(!echoed.contains("http://"), "{echoed}");
    assert!(!echoed.to_ascii_lowercase().contains("proxy-connection"));
    assert!(echoed.contains("Connection: close"), "{echoed}");
}

#[tokio::test]
async fn mixed_detects_socks5_and_http() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("mixed", json!([]))).await;

    let mut stream = TcpStream::connect(running.address).await.unwrap();
    socks5_connect(&mut stream, echo.address).await;
    stream.write_all(b"socks").await.unwrap();
    let mut data = Vec::new();
    while data.windows(5).all(|window| window != b"socks") {
        let chunk = read_some(&mut stream).await;
        assert!(!chunk.is_empty());
        data.extend_from_slice(&chunk);
    }

    let mut stream = TcpStream::connect(running.address).await.unwrap();
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        authority(echo.address),
        authority(echo.address)
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
}

#[tokio::test]
async fn basic_auth_is_required_when_users_exist() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config("http", json!([{"name": "u", "password": "p"}]))).await;
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        authority(echo.address),
        authority(echo.address)
    );

    let mut stream = TcpStream::connect(running.address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");

    let credentials = STANDARD.encode("u:p");
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n",
        authority(echo.address),
        authority(echo.address)
    );
    let mut stream = TcpStream::connect(running.address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
}

#[tokio::test]
async fn tls_connect_tunnel_relays_bytes() {
    let cert = common::Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config("http", json!([]));
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;
    let mut stream = cert.connect(running.address).await;
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        authority(echo.address),
        authority(echo.address)
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
        "{:?}",
        String::from_utf8_lossy(&head)
    );
    stream.write_all(b"http-tls").await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0; b"http-tls".len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"http-tls");
}

#[tokio::test]
async fn tls_h2_connect_tunnel_relays_bytes() {
    let cert = common::Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config("http", json!([]));
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;
    let tls = cert.connect_alpn(running.address, &[b"h2"]).await;
    let (mut send, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(authority(echo.address))
        .body(())
        .unwrap();
    let (response, mut stream) = send.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    stream
        .send_data(bytes::Bytes::from_static(b"http-h2"), false)
        .unwrap();
    let mut body = response.into_body();
    let mut echoed = Vec::new();
    while let Some(chunk) = body.data().await {
        echoed.extend_from_slice(&chunk.unwrap());
        if echoed.len() >= b"http-h2".len() {
            break;
        }
    }
    assert_eq!(&echoed[..b"http-h2".len()], b"http-h2");
    driver.abort();
}

#[tokio::test]
async fn tls_mixed_supports_http_and_socks_connect() {
    let cert = common::Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config("mixed", json!([]));
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;

    let mut http = cert.connect(running.address).await;
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        authority(echo.address),
        authority(echo.address)
    );
    http.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        http.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));

    let mut socks = cert.connect(running.address).await;
    socks5_connect(&mut socks, echo.address).await;
    socks.write_all(b"mixed-tls").await.unwrap();
    socks.flush().await.unwrap();
    let mut echoed = vec![0; b"mixed-tls".len()];
    socks.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"mixed-tls");
}

#[tokio::test]
async fn mixed_and_https_close_silent_handshakes() {
    // 认证前的等待必须有绝对期限：不发送任何字节的连接不能长期占住握手槽。
    let mut value = config("mixed", json!([]));
    value["limits"] = json!({"handshake_timeout_ms": 300, "shutdown_timeout_ms": 300});
    let running = Running::start(value).await;
    let mut silent = TcpStream::connect(running.address).await.unwrap();
    let started = std::time::Instant::now();
    let mut buffer = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), silent.read(&mut buffer))
        .await
        .expect("Mixed 静默连接必须在上限内被关闭，而不是一直挂起");
    assert!(matches!(read, Ok(0) | Err(_)), "预期关闭，得到 {read:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    drop(silent);
    running.shutdown().await;

    let cert = common::Certificate::new();
    let mut value = config("http", json!([]));
    value["limits"] = json!({"handshake_timeout_ms": 300, "shutdown_timeout_ms": 300});
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;
    // 连上但不发 TLS ClientHello。
    let mut silent = TcpStream::connect(running.address).await.unwrap();
    let started = std::time::Instant::now();
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), silent.read(&mut buffer))
        .await
        .expect("HTTPS 静默连接必须在上限内被关闭，而不是一直挂起");
    assert!(matches!(read, Ok(0) | Err(_)), "预期关闭，得到 {read:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    drop(silent);
    running.shutdown().await;
}

/// H2 的握手名额必须「首次认证成功或期限到达」就归还。
///
/// 历史上有两种错误：把许可留到整条连接结束（长连接永久占名额），
/// 以及握手后立刻释放（未认证的空闲连接完全不受期限约束）。
/// 这条用例验证的是后者：只做 TLS、不发 CONNECT 的连接
/// 必须在 `handshake_timeout_ms` 内被服务端关闭。
#[tokio::test]
async fn unauthenticated_h2_connection_is_closed_by_handshake_deadline() {
    let cert = common::Certificate::new();
    let mut value = config("http", json!([]));
    value["limits"] = json!({
        "handshake_timeout_ms": 400,
        "shutdown_timeout_ms": 300,
        // 空闲超时远大于握手期限：若不生效，连接会一直挂着。
        "idle_timeout_ms": 60_000
    });
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;

    let mut stream = cert.connect_alpn(running.address, &[b"h2"]).await;
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut buffer = [0u8; 256];
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(_)) => continue,
            Err(_) => panic!("未认证的 H2 连接没有在握手期限内关闭"),
        }
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "关闭应在握手期限内完成，实际 {:?}",
        started.elapsed()
    );
    drop(stream);
    running.shutdown().await;
}
