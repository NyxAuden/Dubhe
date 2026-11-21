mod common;
#[path = "common/vmess.rs"]
mod vmess_client;

use std::net::SocketAddr;
use std::time::Duration;

use common::{Echo, Running};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PATH: &str = "/GunService/Tun";

fn config() -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-httpupgrade",
            "tag": "hu",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "xudp": false,
            "allow_insecure_transport": true,
            "httpupgrade": {"path": PATH}
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

fn upgrade_head(path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    )
}

async fn read_head(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(buffer).unwrap()
}

async fn read_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.unwrap();
        if read == 0 {
            return out;
        }
        out.extend_from_slice(&chunk[..read]);
        if out.windows(needle.len()).any(|window| window == needle) {
            return out;
        }
    }
}

async fn dial(running: &Running) -> TcpStream {
    TcpStream::connect(running.address).await.unwrap()
}

#[tokio::test]
async fn tls_alpn_http11_upgrade_relays() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let mut value = config();
    value["inbounds"][0]["allow_insecure_transport"] = json!(false);
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let running = Running::start(value).await;
    let mut stream = cert.connect_alpn(running.address, &[b"http/1.1"]).await;
    stream
        .write_all(
            format!(
                "GET {PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = tokio::time::timeout(Duration::from_secs(3), read_head_tls(&mut stream))
        .await
        .unwrap();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"tls-upgrade");
    stream.write_all(&body).await.unwrap();
    let data = tokio::time::timeout(
        Duration::from_secs(3),
        read_until_tls(&mut stream, b"tls-upgrade"),
    )
    .await
    .unwrap();
    assert!(data.windows(11).any(|window| window == b"tls-upgrade"));
}

async fn read_head_tls<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buffer).unwrap();
        }
    }
}

async fn read_until_tls<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, needle: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.unwrap();
        if read == 0 {
            return out;
        }
        out.extend_from_slice(&chunk[..read]);
        if out.windows(needle.len()).any(|window| window == needle) {
            return out;
        }
    }
}

#[tokio::test]
async fn upgraded_stream_relays_vless_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config()).await;
    let mut stream = dial(&running).await;
    stream
        .write_all(upgrade_head(PATH).as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.contains("Upgrade: websocket"), "{head}");

    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"upgraded");
    stream.write_all(&body).await.unwrap();
    let data = read_until(&mut stream, b"upgraded").await;
    assert!(
        data.windows(8).any(|window| window == b"upgraded"),
        "{data:?}"
    );
}

#[tokio::test]
async fn early_data_after_head_is_relayed() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config()).await;
    let mut stream = dial(&running).await;
    let mut body = vless_request(echo.address);
    body.extend_from_slice(b"early-bird");
    let mut request = upgrade_head(PATH).into_bytes();
    request.extend_from_slice(&body);
    stream.write_all(&request).await.unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let data = read_until(&mut stream, b"early-bird").await;
    assert!(
        data.windows(10).any(|window| window == b"early-bird"),
        "{data:?}"
    );
}

#[tokio::test]
async fn wrong_path_and_missing_upgrade_are_rejected() {
    let running = Running::start(config()).await;

    let mut stream = dial(&running).await;
    stream
        .write_all(upgrade_head("/wrong").as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");

    let mut stream = dial(&running).await;
    stream
        .write_all(b"GET /GunService/Tun HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");

    let mut stream = dial(&running).await;
    stream
        .write_all(
            b"GET /GunService/Tun HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
}

fn trojan_config() -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "trojan-httpupgrade",
            "tag": "hu",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": "secret"}],
            "allow_insecure_transport": true,
            "httpupgrade": {"path": PATH}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

#[tokio::test]
async fn trojan_over_httpupgrade_relays_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(trojan_config()).await;
    let mut stream = dial(&running).await;
    stream
        .write_all(upgrade_head(PATH).as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let mut request = common::trojan_header(1, common::address(echo.address), "secret");
    request.extend_from_slice(b"trojan-upgrade");
    stream.write_all(&request).await.unwrap();
    let data = read_until(&mut stream, b"trojan-upgrade").await;
    assert!(data.windows(14).any(|window| window == b"trojan-upgrade"));
}

#[tokio::test]
async fn vmess_over_tls_httpupgrade_relays_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let value = json!({
        "version": 1,
        "inbounds": [{
            "type": "vmess-httpupgrade",
            "tag": "hu",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": vmess_client::UUID}],
            "allow_insecure_body": true,
            "allow_authenticated_length": true,
            "httpupgrade": {"path": PATH},
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    });
    let running = Running::start(value).await;
    let mut tls = cert.connect_alpn(running.address, &[b"http/1.1"]).await;
    tls.write_all(
        format!(
            "GET {PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_head_tls(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let request = vmess_client::Request::new(1, vmess_client::target(echo.address), 5, 0);
    let mut client = vmess_client::Client::start(&mut tls, request, Some(b"vmess-upgrade")).await;
    assert_eq!(client.read(13).await, b"vmess-upgrade");
}
