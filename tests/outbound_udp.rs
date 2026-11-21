//! 上游协议出站的 UDP 回环测试（VLESS / VMess / Trojan / Shadowsocks /
//! AnyTLS UoT / Hysteria2 / TUIC）。
//!
//! 下游实例的 SOCKS5 UDP ASSOCIATE 通过各自的协议出站转发到上游实例；
//! 上游实例使用对应协议的原生 UDP 入站回显。

mod common;

use std::net::SocketAddr;

use common::{Echo, Running};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{Duration, timeout},
};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "outbound-udp-loopback";

fn downstream(outbound: serde_json::Value) -> serde_json::Value {
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [outbound],
        "route": {"default": "up"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    })
}

fn tls(cert: &common::Certificate) -> serde_json::Value {
    json!({
        "ca_file": cert.dir.path().join("cert.pem").to_string_lossy(),
        "server_name": "localhost"
    })
}

async fn udp_associate(server: SocketAddr) -> (TcpStream, UdpSocket) {
    let mut control = TcpStream::connect(server).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    control.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut head = [0u8; 3];
    control.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0, "UDP ASSOCIATE 应成功");
    let bound = common::read_address(&mut control).await;
    let relay = if bound.ip().is_unspecified() {
        SocketAddr::new(control.peer_addr().unwrap().ip(), bound.port())
    } else {
        bound
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    (control, socket)
}

fn datagram(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend_from_slice(&common::address(target));
    bytes.extend_from_slice(payload);
    bytes
}

fn parse_datagram(bytes: &[u8]) -> (SocketAddr, Vec<u8>) {
    assert_eq!(&bytes[..3], &[0, 0, 0], "RSV/FRAG");
    let (host, offset) = match bytes[3] {
        1 => {
            let ip = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[4..8]).unwrap());
            (std::net::IpAddr::from(ip), 8)
        }
        4 => {
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[4..20]).unwrap());
            (std::net::IpAddr::from(ip), 20)
        }
        other => panic!("未知 ATYP {other}"),
    };
    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    (SocketAddr::new(host, port), bytes[offset + 2..].to_vec())
}

async fn assert_udp_relayed(upstream: Running, outbound: serde_json::Value) {
    assert_udp_relayed_payload(upstream, outbound, b"udp-protocol").await;
}

async fn assert_udp_relayed_payload(
    upstream: Running,
    outbound: serde_json::Value,
    expected: &[u8],
) {
    let echo = Echo::udp("127.0.0.1").await;
    let server = Running::start(downstream(outbound)).await;
    let (_control, socket) = udp_associate(server.address).await;
    socket
        .send(&datagram(echo.address, expected))
        .await
        .unwrap();
    let mut buffer = [0u8; 8192];
    let length = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .expect("上游协议 UDP 回包超时")
        .unwrap();
    let (_, payload) = parse_datagram(&buffer[..length]);
    assert_eq!(payload, expected);
    drop(socket);
    drop(_control);
    server.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn vless_outbound_relays_native_udp_per_target() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "vless-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID
    });
    assert_udp_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn trojan_outbound_relays_native_udp() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "trojan",
            "tag": "trojan-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "trojan",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "password": PASSWORD,
        "tls": tls(&cert)
    });
    assert_udp_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn shadowsocks_outbound_relays_native_udp() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "shadowsocks",
            "tag": "ss-up",
            "listen": "127.0.0.1:0",
            "method": "chacha20-ietf-poly1305",
            "password": PASSWORD
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "shadowsocks",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "method": "chacha20-ietf-poly1305",
        "password": PASSWORD
    });
    assert_udp_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vmess_outbound_relays_native_udp() {
    for security in [3, 4] {
        let cert = common::Certificate::new();
        let upstream = Running::start(json!({
            "version": 1,
            "inbounds": [{
                "type": "vmess",
                "tag": "vmess-up",
                "listen": "127.0.0.1:0",
                "users": [{"name": "u", "uuid": UUID}],
                "certificate": cert.dir.path().join("cert.pem"),
                "private_key": cert.dir.path().join("key.pem")
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"default": "direct"},
            "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
        }))
        .await;
        let outbound = json!({
            "type": "vmess",
            "tag": "up",
            "endpoint": upstream.address.to_string(),
            "uuid": UUID,
            "security": security,
            "tls": tls(&cert)
        });
        assert_udp_relayed(upstream, outbound).await;
    }
}

#[tokio::test]
async fn vless_outbound_relays_udp_over_websocket() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-ws",
            "tag": "vless-ws-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "allow_insecure_transport": true,
            "websocket": {"path": "/proxy"}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "transport": {"type": "ws", "path": "/proxy"}
    });
    assert_udp_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vmess_outbound_relays_udp_over_websocket() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vmess-ws",
            "tag": "vmess-ws-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "allow_insecure_body": true,
            "websocket": {"path": "/proxy"}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "vmess",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "transport": {"type": "ws", "path": "/proxy"}
    });
    assert_udp_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vless_outbound_relays_udp_over_grpc() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-grpc",
            "tag": "vless-grpc-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "allow_insecure_transport": true,
            "grpc": {"path": "/GunService/Tun", "multi_path": "/GunService/TunMulti"}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "transport": {"type": "grpc", "path": "/GunService/Tun", "multi": false}
    });
    assert_udp_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vless_outbound_encryption_relays_native_udp() {
    use aws_lc_rs::agreement::{PrivateKey, X25519};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let cert = common::Certificate::new();
    let seed = [0x24u8; 32];
    let private = PrivateKey::from_private_key(&X25519, &seed).unwrap();
    let public = private.compute_public_key().unwrap();
    let private = URL_SAFE_NO_PAD.encode(seed);
    let public = URL_SAFE_NO_PAD.encode(public.as_ref());
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "vless-enc-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "decryption": format!("mlkem768x25519plus.native.0.{private}"),
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "tls": tls(&cert),
        "encryption": format!("mlkem768x25519plus.native.1rtt.{public}")
    });
    assert_udp_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn shadowsocks_outbound_relays_udp_over_tcp() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "shadowsocks",
            "tag": "ss-up",
            "listen": "127.0.0.1:0",
            "method": "chacha20-ietf-poly1305",
            "password": PASSWORD
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "shadowsocks",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "method": "chacha20-ietf-poly1305",
        "password": PASSWORD,
        "udp_over_tcp": true
    });
    assert_udp_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn anytls_outbound_relays_udp_over_tcp() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "anytls",
            "tag": "anytls-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "anytls",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "password": PASSWORD,
        "tls": tls(&cert)
    });
    assert_udp_relayed_payload(upstream, outbound, &vec![0x77; 3000]).await;
}

#[tokio::test]
async fn hysteria2_outbound_relays_udp_datagrams() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hy2-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "hysteria2",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "password": PASSWORD,
        "tls": tls(&cert)
    });
    assert_udp_relayed_payload(upstream, outbound, &vec![0x5a; 3000]).await;
}

#[tokio::test]
async fn tuic_outbound_relays_udp_stream_mode() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "tuic",
            "tag": "tuic-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID, "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "tuic",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "password": PASSWORD,
        "tls": tls(&cert),
        "tuic": {"udp_relay_mode": "quic"}
    });
    assert_udp_relayed_payload(upstream, outbound, &vec![0x3c; 3000]).await;
}

#[tokio::test]
async fn tuic_outbound_relays_udp_datagrams() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "tuic",
            "tag": "tuic-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID, "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let outbound = json!({
        "type": "tuic",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "password": PASSWORD,
        "tls": tls(&cert)
    });
    assert_udp_relayed_payload(upstream, outbound, &vec![0xa5; 3000]).await;
}
