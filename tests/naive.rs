mod common;

use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Certificate, Echo, Running};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(cert: &Certificate) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "naive",
            "tag": "naive",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": "p"}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
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

fn credentials() -> String {
    STANDARD.encode("u:p")
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
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

#[tokio::test]
async fn http1_connect_relays_and_requires_auth() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;

    let mut stream = cert.connect_alpn(running.address, &[b"http/1.1"]).await;
    stream
        .write_all(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                authority(echo.address),
                authority(echo.address)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");

    let mut stream = cert.connect_alpn(running.address, &[b"http/1.1"]).await;
    stream
        .write_all(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
                authority(echo.address),
                authority(echo.address),
                credentials()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    stream.write_all(b"opaque").await.unwrap();
    let mut data = Vec::new();
    while data.windows(6).all(|window| window != b"opaque") {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0);
        data.extend_from_slice(&chunk[..read]);
    }
}

fn padded(payload: &[u8], padding: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(3 + payload.len() + padding);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.push(padding as u8);
    frame.extend_from_slice(payload);
    frame.resize(3 + payload.len() + padding, 0);
    frame
}

async fn read_padded(body: &mut h2::RecvStream, expected: usize) -> Vec<u8> {
    let mut prefix = Vec::new();
    while prefix.len() < 3 {
        prefix.extend_from_slice(&body.data().await.unwrap().unwrap());
    }
    let original = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    let padding = usize::from(prefix[2]);
    assert!(original <= expected);
    let mut rest = prefix[3..].to_vec();
    while rest.len() < original + padding {
        rest.extend_from_slice(&body.data().await.unwrap().unwrap());
    }
    rest[..original].to_vec()
}

#[tokio::test]
async fn http2_padding_capability_header_and_padded_data() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let tls = cert.connect_alpn(running.address, &[b"h2"]).await;
    let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(connection);

    let request = http::Request::builder()
        .method("CONNECT")
        .uri(authority(echo.address))
        .header("proxy-authorization", format!("Basic {}", credentials()))
        .header("padding", "1")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let value = response
        .headers()
        .get("padding")
        .expect("Naive padding 能力响应头")
        .as_bytes()
        .to_vec();
    assert!(
        (30..=61).contains(&value.len()),
        "padding 头长度 {}",
        value.len()
    );
    assert!(
        value[..16]
            .iter()
            .all(|byte| b"!#$()+<>?@[]^`{}".contains(byte))
    );

    let payload = b"naive-padding";
    send.send_data(bytes::Bytes::from(padded(payload, 5)), false)
        .unwrap();
    let mut body = response.into_body();
    let echoed = read_padded(&mut body, payload.len()).await;
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn http2_connect_multiplexes_streams() {
    let first = Echo::tcp("127.0.0.1", false).await;
    let second = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let tls = cert.connect_alpn(running.address, &[b"h2"]).await;
    let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(connection);

    let mut streams = Vec::new();
    for (echo, payload) in [(first.address, b"one"), (second.address, b"two")] {
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(authority(echo))
            .header("proxy-authorization", format!("Basic {}", credentials()))
            .body(())
            .unwrap();
        let (response, send) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        streams.push((response.into_body(), send, payload));
    }
    for (mut incoming, mut send, payload) in streams {
        send.send_data(payload.to_vec().into(), false).unwrap();
        let mut out = Vec::new();
        while out.windows(payload.len()).all(|window| window != payload) {
            let chunk = incoming.data().await.unwrap().unwrap();
            out.extend_from_slice(&chunk);
        }
    }
}
