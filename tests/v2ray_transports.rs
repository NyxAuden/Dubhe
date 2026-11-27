//! V2Ray HTTP / QUIC 传输回环测试。
//!
//! HTTP/1.1 请求头、HTTP/2 流与 QUIC 双向流都由测试侧独立构造，
//! 内层 VLESS/VMess/Trojan 报文同样不调用生产封装。

mod common;

#[path = "common/vmess.rs"]
mod vmess_client;

use common::*;
use prost::bytes::Bytes;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const UUID: &str = "11111111-1111-4111-8111-111111111111";
const ID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

fn config(inbound: Value) -> Value {
    let mut value = socks_config();
    value["inbounds"] = json!([inbound]);
    value
}

fn vless_request(command: u8, target: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend(ID);
    bytes.extend([0, command]);
    bytes.extend(target.port().to_be_bytes());
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            bytes.push(3);
            bytes.extend(ip.octets());
        }
    }
    bytes
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = (payload.len() as u16).to_be_bytes().to_vec();
    bytes.extend(payload);
    bytes
}

async fn response<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut head = [9; 2];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head, [0, 0]);
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while buffer.len() < 8_192 {
        stream.read_exact(&mut byte).await.unwrap();
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return buffer;
        }
    }
    panic!("响应头超过上限");
}

fn trojan_request(target: SocketAddr) -> Vec<u8> {
    use sha2::{Digest, Sha224};
    let hash = Sha224::digest(PASSWORD.as_bytes());
    let mut request = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_bytes();
    request.extend_from_slice(b"\r\n");
    request.push(1);
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            request.push(1);
            request.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request.push(3);
            request.extend(ip.octets());
        }
    }
    request.extend(target.port().to_be_bytes());
    request.extend_from_slice(b"\r\n");
    request
}

#[tokio::test]
async fn vless_tcp_and_udp_over_http1() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let udp = Echo::udp("127.0.0.1").await;
    let server = Running::start(config(json!({
        "type":"vless-http","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "allow_insecure_transport": true,
        "http":{"path":"/tunnel","host":["example.com"],"method":"PUT",
                "headers":{"x-transport":"v2ray"}}
    })))
    .await;

    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream
        .write_all(b"PUT /tunnel?token=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let head = read_head(&mut stream).await;
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("x-transport: v2ray"), "{head}");
    stream
        .write_all(&vless_request(1, tcp.address))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"http1-tcp").await;

    let mut packets = TcpStream::connect(server.address).await.unwrap();
    packets
        .write_all(b"PUT /tunnel HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    assert!(read_head(&mut packets).await.starts_with(b"HTTP/1.1 200"));
    packets
        .write_all(&vless_request(2, udp.address))
        .await
        .unwrap();
    response(&mut packets).await;
    packets.write_all(&frame(b"http1-udp")).await.unwrap();
    let mut length = [0u8; 2];
    packets.read_exact(&mut length).await.unwrap();
    let mut payload = vec![0u8; u16::from_be_bytes(length) as usize];
    packets.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, b"http1-udp");
    server.shutdown().await;
}

#[tokio::test]
async fn vless_over_http2_tls() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let server = Running::start(config(json!({
        "type":"vless-http","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "http":{"path":"/h2","host":["localhost"]},
        "certificate": cert.dir.path().join("cert.pem"),
        "private_key": cert.dir.path().join("key.pem")
    })))
    .await;
    let tls = cert.connect_alpn(server.address, &[b"h2"]).await;
    let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(connection);

    let request = http::Request::builder()
        .method("PUT")
        .uri("https://localhost/h2")
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut incoming = response.into_body();

    send.send_data(Bytes::from(vless_request(1, tcp.address)), false)
        .unwrap();
    let mut reply = [0u8; 2];
    let chunk = incoming.data().await.unwrap().unwrap();
    assert_eq!(chunk.len(), 2);
    reply.copy_from_slice(&chunk);
    assert_eq!(reply, [0, 0]);

    send.send_data(Bytes::from_static(b"h2-tcp"), false)
        .unwrap();
    let mut echoed = Vec::new();
    while echoed.len() < 6 {
        let chunk = incoming.data().await.unwrap().unwrap();
        echoed.extend_from_slice(&chunk);
    }
    assert_eq!(echoed, b"h2-tcp");
    server.shutdown().await;
}

#[tokio::test]
async fn http2_unused_connection_releases_handshake_permit_at_deadline() {
    let cert = Certificate::new();
    let mut cfg = config(json!({
        "type":"vless-http","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "http":{"path":"/h2","host":["localhost"]},
        "certificate": cert.dir.path().join("cert.pem"),
        "private_key": cert.dir.path().join("key.pem")
    }));
    cfg["limits"] = json!({"handshake_timeout_ms": 300, "max_handshakes": 1});
    let server = Running::start(cfg).await;

    let tls = cert.connect_alpn(server.address, &[b"h2"]).await;
    let (client, connection) = h2::client::handshake(tls).await.unwrap();
    let mut driver = tokio::spawn(connection);
    timeout(Duration::from_secs(2), &mut driver)
        .await
        .expect("未使用的 H2 连接必须在握手期限后关闭")
        .unwrap()
        .ok();
    drop(client);

    // 到期连接必须归还唯一的握手名额，新连接仍可进行 TLS 握手。
    drop(cert.connect_alpn(server.address, &[b"h2"]).await);
    server.shutdown().await;
}

/// 回归：V2Ray HTTP/2 的握手许可必须在**首个流认证成功**后归还。
///
/// 此前 H1 在认证后归还，H2 却一直持到整条连接关闭。于是一个正常的长连接
/// 会长期占住全局/每源 IP 的握手槽：把 `max_handshakes` 设为 1 时，
/// 第一条已认证的长连接会让后续所有连接都被拒。
#[tokio::test]
async fn http2_releases_handshake_permit_after_authentication() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let mut cfg = config(json!({
        "type":"vless-http","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "http":{"path":"/h2","host":["localhost"]},
        "certificate": cert.dir.path().join("cert.pem"),
        "private_key": cert.dir.path().join("key.pem")
    }));
    // 只给 1 个握手名额：许可不归还时第二条连接必然被拒。
    cfg["limits"] = json!({"max_handshakes": 1, "per_ip_handshakes": 4});
    let server = Running::start(cfg).await;

    // 第一条：完成认证并保持打开。
    let tls = cert.connect_alpn(server.address, &[b"h2"]).await;
    let (mut first, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(connection);
    let (response, mut send) = first
        .send_request(
            http::Request::builder()
                .method("PUT")
                .uri("https://localhost/h2")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut incoming = response.into_body();
    send.send_data(Bytes::from(vless_request(1, tcp.address)), false)
        .unwrap();
    let _ = incoming.data().await.unwrap().unwrap();
    // 认证已完成；**不关闭**这条连接。

    // 第二条：必须能建立。许可若未归还，这里会连不上。
    let tls2 = timeout(
        Duration::from_secs(3),
        cert.connect_alpn(server.address, &[b"h2"]),
    )
    .await
    .expect("首条 H2 已认证后，握手名额必须已归还");
    let (mut second, connection2) = h2::client::handshake(tls2).await.unwrap();
    tokio::spawn(connection2);
    let (response2, mut send2) = second
        .send_request(
            http::Request::builder()
                .method("PUT")
                .uri("https://localhost/h2")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    let response2 = response2.await.unwrap();
    assert_eq!(response2.status(), http::StatusCode::OK);
    let mut incoming2 = response2.into_body();
    send2
        .send_data(Bytes::from(vless_request(1, tcp.address)), false)
        .unwrap();
    let _ = incoming2.data().await.unwrap().unwrap();

    // 断言已通过；先断开再停机，否则 shutdown 会等连接排空。
    drop((send, send2));
    drop(incoming);
    drop(incoming2);
    drop(first);
    drop(second);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), server.shutdown()).await;
}

#[tokio::test]
async fn vmess_over_http1_plain_transport() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(json!({
        "type":"vmess-http","tag":"vmess","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":vmess_client::UUID}],
        "allow_insecure_body": true,
        "http":{"path":"/vm"}
    })))
    .await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream
        .write_all(b"PUT /vm HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    assert!(read_head(&mut stream).await.starts_with(b"HTTP/1.1 200"));
    let mut client = vmess_client::Client::start(
        stream,
        vmess_client::Request::new(1, vmess_client::target(tcp.address), 5, 0),
        Some(b"vmess-http"),
    )
    .await;
    assert_eq!(client.read(10).await, b"vmess-http");
    client.send(b"ping").await;
    assert_eq!(client.read(4).await, b"ping");
    server.shutdown().await;
}

#[tokio::test]
async fn trojan_over_http1_plain_transport() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(json!({
        "type":"trojan-http","tag":"trojan","listen":"127.0.0.1:0",
        "users":[{"name":"test","password":PASSWORD}],
        "allow_insecure_transport": true,
        "http":{"path":"/tj"}
    })))
    .await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream
        .write_all(b"PUT /tj HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    assert!(read_head(&mut stream).await.starts_with(b"HTTP/1.1 200"));
    let mut hello = trojan_request(tcp.address);
    hello.extend_from_slice(b"trojan-http");
    stream.write_all(&hello).await.unwrap();
    let mut echoed = vec![0u8; 11];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"trojan-http");
    server.shutdown().await;
}

fn quic_client(cert: &Certificate) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).unwrap();
    quinn::ClientConfig::new(Arc::new(crypto))
}

#[tokio::test]
async fn vless_tcp_and_udp_over_quic() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let udp = Echo::udp("127.0.0.1").await;
    let cert = Certificate::new();
    let server = Running::start(config(json!({
        "type":"vless-quic","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "certificate": cert.dir.path().join("cert.pem"),
        "private_key": cert.dir.path().join("key.pem")
    })))
    .await;

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quic_client(&cert));
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(server.address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&vless_request(1, tcp.address))
        .await
        .unwrap();
    response(&mut recv).await;
    send.write_all(b"quic-tcp").await.unwrap();
    let mut echoed = [0u8; 8];
    recv.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"quic-tcp");
    send.finish().unwrap();

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&vless_request(2, udp.address))
        .await
        .unwrap();
    response(&mut recv).await;
    send.write_all(&frame(b"quic-udp")).await.unwrap();
    let mut length = [0u8; 2];
    recv.read_exact(&mut length).await.unwrap();
    let mut payload = vec![0u8; u16::from_be_bytes(length) as usize];
    recv.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, b"quic-udp");
    send.finish().unwrap();

    drop(connection);
    endpoint.close(0u32.into(), b"");
    server.shutdown().await;
}

#[tokio::test]
async fn http1_rejects_wrong_path_host_and_method() {
    let server = Running::start(config(json!({
        "type":"vless-http","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "allow_insecure_transport": true,
        "http":{"path":"/ok","host":["example.com"],"method":"PUT"}
    })))
    .await;

    assert_eq!(
        status_of(
            server.address,
            b"PUT /wrong HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        .await,
        "404"
    );
    assert_eq!(
        status_of(
            server.address,
            b"PUT /ok HTTP/1.1\r\nHost: other.com\r\n\r\n"
        )
        .await,
        "400"
    );
    assert_eq!(
        status_of(
            server.address,
            b"GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        .await,
        "404"
    );
    server.shutdown().await;
}

async fn status_of(address: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request).await.unwrap();
    let head = String::from_utf8(read_head(&mut stream).await).unwrap();
    head.split(' ').nth(1).unwrap().to_owned()
}

#[tokio::test]
async fn transport_settings_are_validated() {
    let parse = |inbound: Value| dubhe::config::Config::from_json(&config(inbound).to_string());
    assert!(
        parse(json!({
            "type":"vless-http","tag":"vless","listen":"127.0.0.1:0",
            "users":[{"name":"test","uuid":UUID}],
            "allow_insecure_transport": true,
            "http":{"path":"/ok","headers":{"x-bad":"a\r\nb"}}
        }))
        .is_err()
    );
    assert!(
        parse(json!({
            "type":"vless-quic","tag":"vless","listen":"127.0.0.1:0",
            "users":[{"name":"test","uuid":UUID}],
            "quic":{"idle_timeout_ms":0},
            "certificate":"cert.pem","private_key":"key.pem"
        }))
        .is_err()
    );
    assert!(
        parse(json!({
            "type":"vless-http","tag":"vless","listen":"127.0.0.1:0",
            "users":[{"name":"test","uuid":UUID,"flow":"xtls-rprx-vision"}],
            "allow_insecure_transport": true,
            "http":{"path":"/ok"}
        }))
        .is_err()
    );
}
