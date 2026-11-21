//! SOCKS5 BIND 回环测试。
//!
//! 验证 RFC 1928 的两段应答：先返回监听地址，接受一个入站连接后再返回
//! 对端地址，随后双向转发；同时验证域名目标与非法期望对端的失败路径。

mod common;

use std::net::SocketAddr;

use common::Running;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};

fn config() -> serde_json::Value {
    let mut value = common::socks_config();
    value["limits"]["handshake_timeout_ms"] = json!(2000);
    value
}

async fn greet(stream: &mut TcpStream) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
}

async fn reply(stream: &mut TcpStream) -> (u8, SocketAddr) {
    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 5);
    let kind = stream.read_u8().await.unwrap();
    let host = match kind {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            std::net::IpAddr::from(octets)
        }
        3 => panic!("BIND 应答不应返回域名"),
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            std::net::IpAddr::from(octets)
        }
        other => panic!("未知地址类型 {other}"),
    };
    let port = stream.read_u16().await.unwrap();
    (head[1], SocketAddr::new(host, port))
}

async fn bind_request(stream: &mut TcpStream) -> (u8, SocketAddr) {
    // CMD=2 BIND，DST.ADDR=0.0.0.0，DST.PORT=0，表示由服务端选择。
    stream
        .write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    reply(stream).await
}

#[tokio::test]
async fn bind_accepts_one_inbound_connection_and_relays() {
    let server = Running::start(config()).await;
    let mut control = TcpStream::connect(server.address).await.unwrap();
    greet(&mut control).await;
    let (status, bound) = bind_request(&mut control).await;
    assert_eq!(status, 0, "BIND 首个应答应成功");
    assert_eq!(bound.ip(), server.address.ip());

    let mut incoming = TcpStream::connect(bound).await.unwrap();
    let (status, peer) = timeout(Duration::from_secs(2), reply(&mut control))
        .await
        .expect("等待第二段 BIND 应答超时");
    assert_eq!(status, 0, "入站连接到达后应返回成功");
    assert_eq!(peer.ip(), incoming.local_addr().unwrap().ip());

    control.write_all(b"bind-request").await.unwrap();
    let mut from_control = [0u8; 12];
    incoming.read_exact(&mut from_control).await.unwrap();
    assert_eq!(&from_control, b"bind-request");

    incoming.write_all(b"bind-response").await.unwrap();
    let mut from_incoming = [0u8; 13];
    control.read_exact(&mut from_incoming).await.unwrap();
    assert_eq!(&from_incoming, b"bind-response");

    drop(incoming);
    drop(control);
    server.shutdown().await;
}

#[tokio::test]
async fn bind_rejects_domain_target_before_listening() {
    let server = Running::start(config()).await;
    let mut control = TcpStream::connect(server.address).await.unwrap();
    greet(&mut control).await;
    // CMD=2 BIND，ATYP=3（域名）。
    let domain = b"example.test";
    let mut request = vec![5, 2, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain);
    request.extend_from_slice(&80u16.to_be_bytes());
    control.write_all(&request).await.unwrap();
    let (status, _) = reply(&mut control).await;
    assert_ne!(status, 0, "域名目标应被拒绝");
    let mut byte = [0u8; 1];
    let closing = timeout(Duration::from_secs(2), control.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(closing, Ok(0) | Err(_)), "拒绝后应关闭控制连接");
    server.shutdown().await;
}

#[tokio::test]
async fn bind_rejects_foreign_expected_address() {
    let server = Running::start(config()).await;
    let mut control = TcpStream::connect(server.address).await.unwrap();
    greet(&mut control).await;
    // 期望对端为不可达的外部地址，与控制连接的本机地址不符。
    control
        .write_all(&[5, 2, 0, 1, 192, 0, 2, 1, 0, 80])
        .await
        .unwrap();
    let (status, _) = reply(&mut control).await;
    assert_ne!(status, 0, "与本机不符的期望对端应被拒绝");
    drop(control);
    server.shutdown().await;
}
