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

/// H2 首次认证必须受绝对期限约束，且认证成功即归还握手名额。
///
/// 用 `max_handshakes: 1` 把「是否持有许可」变成可观测行为：
/// - 未认证的连接到期限必须结束，否则第二条连接永远拿不到名额；
/// - 已认证的长隧道不能继续占名额，否则第二条连接同样拿不到。
///
/// 这两条是「许可计数」的行为等价物，不需要侵入内部计数器。
#[tokio::test]
async fn h2_handshake_permit_is_bounded_and_released_on_auth() {
    let cert = common::Certificate::new();

    // 场景 1：未认证连接占用名额 —— 到期限后必须释放。
    let mut value = config("http", json!([]));
    value["limits"] = json!({
        "handshake_timeout_ms": 400,
        "shutdown_timeout_ms": 300,
        "max_handshakes": 1,
        "per_ip_handshakes": 1,
        "idle_timeout_ms": 60_000
    });
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;

    // 关键：先完成 H2 握手（发出 preface/SETTINGS），但一个 CONNECT 都不发。
    // 只做 TLS 不发 preface 时，服务端会卡在传输层握手的期限内，测不到
    // 「认证前」这一段。
    let silent = cert.connect_alpn(running.address, &[b"h2"]).await;
    let (silent_request, silent_connection) = h2::client::handshake(silent).await.unwrap();
    let silent_driver = tokio::spawn(async move {
        let _ = silent_connection.await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        cert.try_connect_alpn(running.address, &[b"h2"])
            .await
            .is_err(),
        "未认证连接在期限内必须占住唯一的握手名额"
    );
    let second = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = cert.try_connect_alpn(running.address, &[b"h2"]).await {
                return stream;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("未认证连接必须在期限内释放握手名额");
    drop(second);
    let _ = &silent_request;
    silent_driver.abort();
    running.shutdown().await;

    // 场景 2：认证成功的长隧道必须立刻归还名额。
    let mut value = config("http", json!([{"name": "u", "password": "p"}]));
    value["limits"] = json!({
        "handshake_timeout_ms": 5000,
        "shutdown_timeout_ms": 300,
        "max_handshakes": 1,
        "per_ip_handshakes": 1,
        "idle_timeout_ms": 60_000
    });
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let target = authority(echo.address);

    // 第一条：TLS + 认证 + CONNECT，保持长隧道。
    let first = cert.connect_alpn(running.address, &[b"h2"]).await;
    let (mut send_request, connection) = h2::client::handshake(first).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let encoded = STANDARD.encode("u:p");
    let request = ::http::Request::builder()
        .method("CONNECT")
        .uri(&target)
        .header("host", &target)
        .header("proxy-authorization", format!("Basic {encoded}"))
        .body(())
        .unwrap();
    let (response, _tunnel) = send_request.send_request(request, false).unwrap();
    let status = response.await.unwrap().status().as_u16();
    assert_eq!(status, 200, "认证成功后应建立隧道");

    // 第二条必须能拿到名额，且不用等第一条隧道结束。
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        cert.try_connect_alpn(running.address, &[b"h2"]),
    )
    .await
    .expect("已认证的长隧道不得继续占用握手名额")
    .expect("第二条连接应能完成 TLS");
    drop(second);
    drop(_tunnel);
    driver.abort();
    running.shutdown().await;
}
