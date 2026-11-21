//! dokodemo-door 固定目标转发测试。

mod common;

use common::*;
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

#[tokio::test]
async fn tcp_is_forwarded_to_the_fixed_target() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut config = socks_config();
    config["inbounds"] = json!([{
        "type":"dokodemo-door","tag":"demo","listen":"127.0.0.1:0",
        "address": echo.address.ip().to_string(),
        "port": echo.address.port()
    }]);
    let server = Running::start(config).await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    exchange(&mut stream, b"dokodemo").await;
    server.shutdown().await;
}

#[tokio::test]
async fn udp_is_forwarded_to_the_fixed_target() {
    let echo = Echo::udp("127.0.0.1").await;
    let mut config = socks_config();
    config["inbounds"] = json!([{
        "type":"dokodemo-door","tag":"demo","listen":"127.0.0.1:0",
        "address": echo.address.ip().to_string(),
        "port": echo.address.port(),
        "network": "udp"
    }]);
    let server = Running::start(config).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(b"dokodemo-udp", server.address)
        .await
        .unwrap();
    let mut buffer = [0u8; 64];
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"dokodemo-udp");
    // 同一客户端源地址的后续报文复用关联。
    client.send_to(b"again", server.address).await.unwrap();
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"again");
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_and_udp_can_share_the_listened_port() {
    // 固定目标同一端口同时提供 TCP/UDP 回环。
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let tcp_echo = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let udp_echo = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp_echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = copy(&mut read, &mut write).await;
            });
        }
    });
    tokio::spawn(async move {
        let mut buffer = [0u8; 65536];
        while let Ok((length, peer)) = udp_echo.recv_from(&mut buffer).await {
            let _ = udp_echo.send_to(&buffer[..length], peer).await;
        }
    });

    let mut config = socks_config();
    config["inbounds"] = json!([{
        "type":"dokodemo-door","tag":"demo","listen":"127.0.0.1:0",
        "address": "127.0.0.1",
        "port": port,
        "network": "tcp,udp"
    }]);
    let server = Running::start(config).await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    exchange(&mut stream, b"tcp-half").await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"udp-half", server.address).await.unwrap();
    let mut buffer = [0u8; 64];
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"udp-half");
    server.shutdown().await;
}

/// 最小 TLS ClientHello（仅含 SNI 扩展），用于嗅探路由测试。
fn tls_client_hello(server_name: &str) -> Vec<u8> {
    let mut entry = vec![0x00u8];
    entry.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    entry.extend_from_slice(server_name.as_bytes());
    let mut data = (entry.len() as u16).to_be_bytes().to_vec();
    data.extend_from_slice(&entry);
    let mut extension = vec![0x00, 0x00];
    extension.extend_from_slice(&(data.len() as u16).to_be_bytes());
    extension.extend_from_slice(&data);
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0x11; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extension);
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn sniffing_config(
    echo: std::net::SocketAddr,
    kinds: &[&str],
    rules: serde_json::Value,
) -> serde_json::Value {
    let mut config = socks_config();
    config["inbounds"] = json!([{
        "type":"dokodemo-door","tag":"demo","listen":"127.0.0.1:0",
        "address": echo.ip().to_string(),
        "port": echo.port(),
        "sniffing": {"enabled": true, "dest_override": kinds}
    }]);
    config["route"] = json!({"default":"direct","rules":rules});
    // 嗅探得到的域名必须可解析；测试只用静态 hosts，不访问系统 DNS。
    config["dns"] = json!({"hosts": {
        "allowed.test": ["127.0.0.1"],
        "allowed.host": ["127.0.0.1"]
    }});
    config
}

#[tokio::test]
async fn sniffed_tls_sni_controls_routing_without_consuming_bytes() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let rules = json!([{"domains": ["blocked.test"], "outbound": "reject"}]);
    let server = Running::start(sniffing_config(echo.address, &["tls"], rules)).await;

    // 被拒绝的 SNI：不建立目标连接。
    let blocked = tls_client_hello("blocked.test");
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&blocked).await.unwrap();
    let mut buffer = [0u8; 64];
    let read = timeout(Duration::from_secs(2), stream.read(&mut buffer))
        .await
        .expect("拒绝后连接应关闭")
        .unwrap_or(0);
    assert_eq!(read, 0);

    // 未命中规则的 SNI：回环目标原样收到 ClientHello 字节。
    let allowed = tls_client_hello("allowed.test");
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&allowed).await.unwrap();
    let mut echo_buffer = vec![0u8; allowed.len()];
    timeout(Duration::from_secs(2), stream.read_exact(&mut echo_buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo_buffer, allowed);
    server.shutdown().await;
}

#[tokio::test]
async fn sniffed_http_host_controls_routing() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let rules = json!([{"domains": ["blocked.host"], "outbound": "reject"}]);
    let server = Running::start(sniffing_config(echo.address, &["http"], rules)).await;

    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: blocked.host\r\n\r\n")
        .await
        .unwrap();
    let mut buffer = [0u8; 64];
    let read = timeout(Duration::from_secs(2), stream.read(&mut buffer))
        .await
        .expect("拒绝后连接应关闭")
        .unwrap_or(0);
    assert_eq!(read, 0);

    let request = b"GET / HTTP/1.1\r\nHost: allowed.host\r\n\r\n";
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut echo_buffer = vec![0u8; request.len()];
    timeout(Duration::from_secs(2), stream.read_exact(&mut echo_buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo_buffer, request);
    server.shutdown().await;
}

#[test]
fn sniffing_configuration_is_validated() {
    let parse = |network: &str, sniffing: serde_json::Value| {
        let mut config = socks_config();
        config["inbounds"] = json!([{
            "type":"dokodemo-door","tag":"demo","listen":"127.0.0.1:0",
            "address":"127.0.0.1","port":1,"network":network,"sniffing":sniffing
        }]);
        dubhe::config::Config::from_json(&config.to_string())
    };
    assert!(parse("tcp", json!({"dest_override":["tls"]})).is_ok());
    assert!(parse("udp", json!({"dest_override":["tls"]})).is_err());
    assert!(parse("tcp", json!({"enabled":false})).is_ok());
    assert!(parse("tcp", json!({"enabled":false,"dest_override":["tls"]})).is_err());
    assert!(parse("tcp", json!({"dest_override":[]})).is_err());
    assert!(parse("tcp", json!({"dest_override":["tls","tls"]})).is_err());
    assert!(parse("tcp", json!({"dest_override":["quic"]})).is_err());
}

#[test]
fn invalid_networks_and_targets_are_rejected() {
    let parse = |inbound: serde_json::Value| {
        let mut config = socks_config();
        config["inbounds"] = json!([inbound]);
        dubhe::config::Config::from_json(&config.to_string())
    };
    for network in ["", "quic", "tcp,", "tcp,tcp"] {
        assert!(
            parse(json!({
                "type":"dokodemo-door","tag":"demo","listen":"127.0.0.1:0",
                "address":"127.0.0.1","port":1,"network":network
            }))
            .is_err(),
            "{network}"
        );
    }
    assert!(
        parse(json!({
            "type":"dokodemo-door","tag":"demo","listen":"127.0.0.1:0",
            "address":"","port":1
        }))
        .is_err()
    );
    assert!(
        parse(json!({
            "type":"dokodemo-door","tag":"demo","listen":"127.0.0.1:0",
            "address":"127.0.0.1","port":0
        }))
        .is_err()
    );
}
