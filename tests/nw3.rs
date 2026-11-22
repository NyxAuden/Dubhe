//! NW3（Nowhere Protocol v3）Portal 与 vendored Nowhere Vector 客户端的回环测试。
//! 直接使用 vendor 内的上游客户端，不经过本仓库自建的客户端代码。

mod common;

use std::{
    net::{SocketAddr, TcpListener},
    time::Duration,
};

use common::{Certificate, Echo, Running};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const KEY: &str = "0123456789abcdef0123456789abcdef";

/// 取一个测试专用端口。
///
/// 不用 `bind("127.0.0.1:0")`：Linux 的临时端口范围是 32768–60999，
/// 这个范围会被并发测试的 TCP 连接当作源端口占用，导致「释放后再绑定」
/// 间歇性 `AddrInUse`。这里在范围之外顺序探测。
fn free_port() -> u16 {
    // 并发测试必须各自拿到不同端口，否则会互相抢占导致「未就绪」超时。
    static ISSUED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    let issued = ISSUED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    for port in 20000u16..30000 {
        if issued.lock().unwrap().contains(&port) {
            continue;
        }
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            if issued.lock().unwrap().insert(port) {
                return port;
            }
        }
    }
    panic!("没有可用测试端口");
}

fn pin(cert: &Certificate) -> String {
    Sha256::digest(cert.der.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn udp_associate(server: SocketAddr) -> std::io::Result<(TcpStream, UdpSocket)> {
    let mut control = TcpStream::connect(server).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut choice = [0u8; 2];
    control.read_exact(&mut choice).await?;
    if choice != [5, 0] {
        return Err(std::io::Error::other("SOCKS5 方法协商失败"));
    }
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut head = [0u8; 3];
    control.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(std::io::Error::other("SOCKS5 UDP ASSOCIATE 失败"));
    }
    let bound = common::read_address(&mut control).await;
    let relay = if bound.ip().is_unspecified() {
        SocketAddr::new(control.peer_addr()?.ip(), bound.port())
    } else {
        bound
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(relay).await?;
    Ok((control, socket))
}

fn datagram(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend_from_slice(&common::address(target));
    bytes.extend_from_slice(payload);
    bytes
}

fn parse_datagram(bytes: &[u8]) -> (SocketAddr, Vec<u8>) {
    let (host, offset) = match bytes[3] {
        1 => (
            std::net::IpAddr::from(<[u8; 4]>::try_from(&bytes[4..8]).unwrap()),
            8,
        ),
        4 => (
            std::net::IpAddr::from(<[u8; 16]>::try_from(&bytes[4..20]).unwrap()),
            20,
        ),
        other => panic!("未知 ATYP {other}"),
    };
    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    (SocketAddr::new(host, port), bytes[offset + 2..].to_vec())
}

#[tokio::test]
async fn nw3_portal_relays_udp_with_vendored_vector_client() {
    let cert = Certificate::new();
    let port = free_port();
    let socks_port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "direct",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::udp("127.0.0.1").await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:{socks_port}",
        pin(&cert)
    );
    let vector = nowhere::Vector::new(url.parse().unwrap(), nowhere::Logger).unwrap();
    let task = tokio::spawn(vector.run());
    let socks: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let (_control, socket) = timeout(Duration::from_secs(5), async {
        loop {
            match udp_associate(socks).await {
                Ok(pair) => break pair,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Vector SOCKS 未在期限内就绪");
    let payload = b"nw3-udp";
    socket.send(&datagram(echo.address, payload)).await.unwrap();
    let mut buffer = [0u8; 8192];
    let length = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .expect("NW3 UDP 回包超时")
        .unwrap();
    assert_eq!(parse_datagram(&buffer[..length]).1, payload);
    drop(socket);
    drop(_control);
    task.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn nw3_portal_egress_relays_udp_with_vendored_vector_client() {
    let cert = Certificate::new();
    let port = free_port();
    let socks_port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "egress",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "nw3_egress": {
            "tag": "nw3-exit",
            "endpoint": format!("127.0.0.1:{port}"),
            "key": KEY,
            "sni": "localhost",
            "pin": pin(&cert),
            "morph": false
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::udp("127.0.0.1").await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:{socks_port}",
        pin(&cert)
    );
    let vector = nowhere::Vector::new(url.parse().unwrap(), nowhere::Logger).unwrap();
    let task = tokio::spawn(vector.run());
    let socks: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let (_control, socket) = timeout(Duration::from_secs(5), async {
        loop {
            match udp_associate(socks).await {
                Ok(pair) => break pair,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Egress/UDP 未在期限内就绪");
    let payload = b"nw3-egress-udp";
    socket.send(&datagram(echo.address, payload)).await.unwrap();
    let mut buffer = [0u8; 8192];
    let length = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .expect("NW3 Egress UDP 回包超时")
        .unwrap();
    assert_eq!(parse_datagram(&buffer[..length]).1, payload);
    drop(socket);
    drop(_control);
    task.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn nw3_vector_udp_outbound_preserves_targets_and_empty_on_tls_and_quic() {
    let cert = Certificate::new();
    let port = free_port();
    let upstream = Running::start(json!({
        "version":1,
        "inbounds":[{"type":"nw3","tag":"portal","listen":format!("127.0.0.1:{port}"),
            "key":KEY,"morph":false,"out":"direct",
            "certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":500}
    })).await;
    let first = Echo::udp("127.0.0.1").await;
    let second = Echo::udp("127.0.0.1").await;
    for carrier in ["tcp", "udp"] {
        let url = format!(
            "vector://{KEY}@127.0.0.1/{carrier}:{port}?morph=0&sni=localhost&pin={}",
            pin(&cert)
        );
        let downstream = Running::start(json!({
            "version":1,"inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
            "outbounds":[{"type":"nw3-vector","tag":"up","url":url}],"route":{"default":"up"},
            "limits":{"shutdown_timeout_ms":500,"dial_timeout_ms":2000}
        }))
        .await;
        let (control, socket) = udp_associate(downstream.address).await.unwrap();
        for (target, payload) in [
            (first.address, b"nw3-first".as_slice()),
            (second.address, b"nw3-second"),
            (first.address, b""),
            (second.address, b"again"),
        ] {
            socket.send(&datagram(target, payload)).await.unwrap();
            let mut buffer = vec![0; 8192];
            let length = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
                .await
                .expect("NW3 出站 UDP 超时")
                .unwrap();
            let (source, reply) = parse_datagram(&buffer[..length]);
            assert_eq!(source, target);
            assert_eq!(reply, payload);
        }
        drop(socket);
        drop(control);
        downstream.shutdown().await;
    }
    upstream.shutdown().await;
}

#[tokio::test]
async fn nw3_vector_udp_wrong_key_never_falls_back_to_direct() {
    let cert = Certificate::new();
    let port = free_port();
    let upstream=Running::start(json!({"version":1,
        "inbounds":[{"type":"nw3","tag":"portal","listen":format!("127.0.0.1:{port}"),"key":KEY,"morph":false,
            "certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":500}
    })).await;
    let url = format!(
        "vector://11111111111111111111111111111111@127.0.0.1/tcp:{port}?morph=0&sni=localhost&pin={}",
        pin(&cert)
    );
    let downstream = Running::start(json!({"version":1,
        "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"nw3-vector","tag":"up","url":url}],"route":{"default":"up"},
        "limits":{"shutdown_timeout_ms":500,"dial_timeout_ms":300}
    }))
    .await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (control, socket) = udp_associate(downstream.address).await.unwrap();
    socket
        .send(&datagram(target.local_addr().unwrap(), b"denied"))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(600), target.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert_eq!(downstream.stats.snapshot().uplink, 0);
    drop(socket);
    drop(control);
    downstream.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn nw3_udp_reject_route_does_not_open_flow() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let downstream=Running::start(json!({"version":1,
        "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"nw3-vector","tag":"up","url":format!("vector://{KEY}@127.0.0.1:9?morph=0&sni=localhost")},
            {"type":"reject","tag":"blocked"}],
        "route":{"default":"up","rules":[{"networks":["udp"],"outbound":"blocked"}]},
        "limits":{"shutdown_timeout_ms":500}
    })).await;
    let (control, socket) = udp_associate(downstream.address).await.unwrap();
    socket
        .send(&datagram(target.local_addr().unwrap(), b"blocked"))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(150), target.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert!(downstream.stats.snapshot().rejected > 0);
    assert_eq!(downstream.stats.snapshot().uplink, 0);
    drop(socket);
    drop(control);
    downstream.shutdown().await;
}

#[tokio::test]
async fn nw3_vector_outbound_relays_tcp_through_portal() {
    let cert = Certificate::new();
    let port = free_port();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "direct",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:1",
        pin(&cert)
    );
    let downstream = Running::start(json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [{"type": "nw3-vector", "tag": "up", "url": url}],
        "route": {"default": "up"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let (mut tunnel, _) = timeout(
        Duration::from_secs(3),
        common::socks(1, common::address(echo.address), downstream.address),
    )
    .await
    .expect("NW3 Vector 出站建连超时");
    tunnel.write_all(b"nw3-vector").await.unwrap();
    tunnel.flush().await.unwrap();
    let mut echoed = vec![0; b"nw3-vector".len()];
    tunnel.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"nw3-vector");
    drop(tunnel);
    downstream.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn nw3_portal_egress_relays_tcp_with_vendored_vector_client() {
    let cert = Certificate::new();
    let port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "egress",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "nw3_egress": {
            "tag": "nw3-exit",
            "endpoint": format!("127.0.0.1:{port}"),
            "key": KEY,
            "sni": "localhost",
            "pin": pin(&cert),
            "morph": false
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:1",
        pin(&cert)
    );
    let client = nowhere::VectorClient::new(url.parse().unwrap(), nowhere::Logger).unwrap();
    let mut stream = timeout(Duration::from_secs(5), async {
        loop {
            match client.connect_tcp("127.0.0.1", echo.address.port()).await {
                Ok(stream) => break stream,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Egress 未在期限内完成注册");
    stream.write_all(b"nw3-egress").await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0; b"nw3-egress".len()];
    timeout(Duration::from_secs(3), stream.read_exact(&mut echoed))
        .await
        .expect("NW3 Egress 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"nw3-egress");
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn nw3_portal_relays_tcp_with_vendored_vector_client() {
    let cert = Certificate::new();
    let port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "direct",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:1",
        pin(&cert)
    );
    let client = nowhere::VectorClient::new(url.parse().unwrap(), nowhere::Logger).unwrap();
    let mut stream = timeout(Duration::from_secs(5), async {
        loop {
            match client.connect_tcp("127.0.0.1", echo.address.port()).await {
                Ok(stream) => break stream,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Portal 未在期限内就绪");
    stream.write_all(b"nw3-loopback").await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0; b"nw3-loopback".len()];
    timeout(Duration::from_secs(3), stream.read_exact(&mut echoed))
        .await
        .expect("NW3 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"nw3-loopback");
    drop(stream);
    server.shutdown().await;
}
