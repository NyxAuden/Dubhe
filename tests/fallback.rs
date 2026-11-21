mod common;

use std::net::SocketAddr;

use common::{Certificate, Echo, Running};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn config(cert: &Certificate, dest: u16, xver: u8) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "vless",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "fallbacks": [{"dest": dest, "xver": xver}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
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

fn address_ip(target: SocketAddr) -> std::net::Ipv4Addr {
    match target.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!(),
    }
}

fn vless_tcp(target: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0u8];
    bytes.extend_from_slice(&uuid_bytes());
    bytes.push(0);
    bytes.push(1);
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&address_ip(target).octets());
    bytes
}

async fn read_some<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut buffer = [0u8; 1024];
    let read = stream.read(&mut buffer).await.unwrap();
    buffer[..read].to_vec()
}

#[tokio::test]
async fn failed_auth_forwards_plain_bytes_to_dest() {
    let dest = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let mut value = config(&cert, dest.address.port(), 0);
    let running = Running::start(value.clone()).await;
    let mut stream = cert.connect(running.address).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut data = Vec::new();
    while data.windows(3).all(|window| window != b"GET") {
        let chunk = read_some(&mut stream).await;
        assert!(!chunk.is_empty());
        data.extend_from_slice(&chunk);
    }
    assert!(data.starts_with(b"GET / HTTP/1.1"), "{data:?}");

    // 合法 VLESS 请求不受 fallback 影响。
    value["inbounds"][0]["fallbacks"] = json!([]);
    let running = Running::start(value).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut stream = cert.connect(running.address).await;
    let mut body = vless_tcp(echo.address);
    body.extend_from_slice(b"ok");
    stream.write_all(&body).await.unwrap();
    let mut data = Vec::new();
    while data.windows(2).all(|window| window != b"ok") {
        let chunk = read_some(&mut stream).await;
        assert!(!chunk.is_empty());
        data.extend_from_slice(&chunk);
    }
}

#[tokio::test]
async fn xver_one_prepends_proxy_protocol_line() {
    let dest = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert, dest.address.port(), 1)).await;
    let mut stream = cert.connect(running.address).await;
    stream.write_all(b"hello").await.unwrap();
    let mut data = Vec::new();
    while data.windows(5).all(|window| window != b"hello") {
        let chunk = read_some(&mut stream).await;
        assert!(!chunk.is_empty());
        data.extend_from_slice(&chunk);
    }
    assert!(data.starts_with(b"PROXY TCP4 "), "{data:?}");
    assert!(data.ends_with(b"hello"), "{data:?}");
}

#[tokio::test]
async fn valid_vless_with_fallback_configured_still_relays() {
    let dest = Echo::tcp("127.0.0.1", false).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert, dest.address.port(), 0)).await;
    let mut stream = cert.connect(running.address).await;
    let mut body = vless_tcp(echo.address);
    body.extend_from_slice(b"ok");
    stream.write_all(&body).await.unwrap();
    let mut data = Vec::new();
    while data.windows(2).all(|window| window != b"ok") {
        let chunk = read_some(&mut stream).await;
        assert!(!chunk.is_empty());
        data.extend_from_slice(&chunk);
    }
}

async fn banner(text: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            // 先消费 fallback 回放的请求，避免目标立即关闭时 Linux 产生 RST
            // 丢弃已写出的 banner；这不是放宽匹配语义。
            let mut request = [0u8; 256];
            let _ = stream.read(&mut request).await;
            stream.write_all(text).await.unwrap();
        }
    });
    (address, task)
}

fn matched_config(cert: &Certificate, fallbacks: Value) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "vless",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "fallbacks": fallbacks,
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

async fn first_bytes<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut buffer = [0u8; 8];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    buffer[..read].to_vec()
}

#[tokio::test]
async fn path_and_name_and_alpn_matching_select_entries() {
    let cert = Certificate::new();

    let (a, _a_task) = banner(b"A").await;
    let (b, _b_task) = banner(b"B").await;
    let running = Running::start(matched_config(
        &cert,
        json!([
            {"dest": a.port(), "path": "/a"},
            {"dest": b.port(), "path": "/b"}
        ]),
    ))
    .await;
    let mut stream = cert.connect(running.address).await;
    stream
        .write_all(b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(first_bytes(&mut stream).await, b"B");

    let (a, _a_task) = banner(b"A").await;
    let (b, _b_task) = banner(b"B").await;
    let running = Running::start(matched_config(
        &cert,
        json!([
            {"dest": a.port(), "name": "localhost"},
            {"dest": b.port(), "name": "other.example"}
        ]),
    ))
    .await;
    let mut stream = cert.connect(running.address).await;
    stream.write_all(b"hello").await.unwrap();
    assert_eq!(first_bytes(&mut stream).await, b"A");

    // 服务端未协商 ALPN，带 alpn 的条目落空后由通配条目承接。
    let (a, _a_task) = banner(b"A").await;
    let (b, _b_task) = banner(b"B").await;
    let running = Running::start(matched_config(
        &cert,
        json!([
            {"dest": a.port(), "alpn": "h2"},
            {"dest": b.port()}
        ]),
    ))
    .await;
    let mut stream = cert.connect(running.address).await;
    stream.write_all(b"hello").await.unwrap();
    assert_eq!(first_bytes(&mut stream).await, b"B");
}

#[tokio::test]
async fn trojan_fallback_forwards_and_valid_auth_is_unaffected() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let value = json!({
        "version": 1,
        "inbounds": [{
            "type": "trojan",
            "tag": "trojan",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": "secret"}],
            "fallbacks": [{"dest": echo.address.port()}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    });
    let running = Running::start(value).await;
    let mut stream = cert.connect(running.address).await;
    let garbage = format!("plain-http{}", " ".repeat(64));
    stream.write_all(garbage.as_bytes()).await.unwrap();
    let mut data = Vec::new();
    while data.windows(10).all(|window| window != b"plain-http") {
        let chunk = read_some(&mut stream).await;
        assert!(!chunk.is_empty());
        data.extend_from_slice(&chunk);
    }

    let mut stream = cert.connect(running.address).await;
    let mut request = common::trojan_header(1, common::address(echo.address), "secret");
    request.extend_from_slice(b"trojan-ok");
    stream.write_all(&request).await.unwrap();
    let mut data = Vec::new();
    while data.windows(9).all(|window| window != b"trojan-ok") {
        let chunk = read_some(&mut stream).await;
        assert!(!chunk.is_empty());
        data.extend_from_slice(&chunk);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_dest_forwards_plain_bytes() {
    let cert = Certificate::new();
    let path = cert.dir.path().join("fallback.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 256];
        let read = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..read]).await.unwrap();
    });
    let running = Running::start(matched_config(
        &cert,
        json!([{"dest": path.to_str().unwrap()}]),
    ))
    .await;
    let mut stream = cert.connect(running.address).await;
    stream
        .write_all(b"GET /unix HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buffer = [0u8; 32];
    let read = stream.read(&mut buffer).await.unwrap();
    assert!(
        buffer[..read].starts_with(b"GET /unix HTTP/1.1"),
        "{:?}",
        &buffer[..read]
    );
    task.await.unwrap();
}
