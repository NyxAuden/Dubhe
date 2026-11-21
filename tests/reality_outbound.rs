//! VLESS REALITY 出站闭环：真实 TLS 1.3 target 模板 + 本内核 REALITY 入站。
//! 只使用回环地址、自签证书和临时密钥；不连接公网或官方客户端。

mod common;

#[path = "common/reality.rs"]
mod reality_peer;

use std::{net::SocketAddr, time::Duration};

use aws_lc_rs::{
    agreement::{PrivateKey, X25519},
    signature::{KeyPair as _, ML_DSA_65_SIGNING, PqdsaKeyPair},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Echo, Running};
use reality_peer::{TargetGroup, TargetOptions, TargetPeer};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "reality-outbound-loopback";
const SHORT_ID: &str = "8172635445362718";

fn server_keys() -> ([u8; 32], [u8; 32]) {
    let seed = [0x67; 32];
    let private = PrivateKey::from_private_key(&X25519, &seed).unwrap();
    let public: [u8; 32] = private
        .compute_public_key()
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap();
    (seed, public)
}

async fn tls_target(group: TargetGroup) -> TargetPeer {
    tls_target_with_alpn(group, Vec::new()).await
}

async fn tls_target_with_alpn(group: TargetGroup, alpn: Vec<Vec<u8>>) -> TargetPeer {
    TargetPeer::start(TargetOptions {
        group,
        certificate_padding: 8192,
        alpn,
        behavior: reality_peer::TargetBehavior::Echo,
    })
    .await
    .unwrap()
}

fn reality(target: SocketAddr, seed: [u8; 32]) -> Value {
    json!({
        "target": {"host": target.ip().to_string(), "port": target.port()},
        "private_key": URL_SAFE_NO_PAD.encode(seed),
        "server_names": ["localhost"],
        "short_ids": [SHORT_ID],
        "max_time_diff_ms": 120000,
        "fallback_idle_timeout_ms": 100,
        "fallback_max_duration_ms": 500
    })
}

fn upstream(target: SocketAddr, seed: [u8; 32]) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-reality",
            "tag": "reality-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "reality": reality(target, seed)
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    })
}

fn downstream(upstream: SocketAddr, public: [u8; 32]) -> Value {
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [{
            "type": "vless",
            "tag": "up",
            "endpoint": upstream.to_string(),
            "uuid": UUID,
            "reality": {
                "public_key": URL_SAFE_NO_PAD.encode(public),
                "short_id": SHORT_ID,
                "server_name": "localhost",
                "version": "26.10.31",
                "mldsa65Verify": null
            },
            "tls": null,
            "transport": null
        }],
        "route": {"default": "up"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    })
}

/// VMess/Trojan 的 REALITY 入站与出站闭环；复用同一真实 TLS 模板 target。
async fn relays_protocol_reality(kind: &str) {
    let target = tls_target(TargetGroup::Hybrid).await;
    let (seed, public) = server_keys();
    let inbound = match kind {
        "vmess" => json!({
            "type": "vmess-reality",
            "tag": "reality-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "reality": reality(target.address, seed)
        }),
        "trojan" => json!({
            "type": "trojan-reality",
            "tag": "reality-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "reality": reality(target.address, seed)
        }),
        _ => unreachable!(),
    };
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let mut outbound = json!({
        "type": kind,
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "reality": {
            "public_key": URL_SAFE_NO_PAD.encode(public),
            "short_id": SHORT_ID,
            "server_name": "localhost"
        }
    });
    if kind == "vmess" {
        outbound["uuid"] = json!(UUID);
    } else {
        outbound["password"] = json!(PASSWORD);
    }
    let downstream = Running::start(json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [outbound],
        "route": {"default": "up"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    assert_tcp_echo(downstream.address).await;
    downstream.shutdown().await;
    upstream.shutdown().await;
    target.shutdown().await.unwrap();
}

#[test]
fn reality_outbound_verifies_mldsa65_extension() {
    // ML-DSA-65 的临时证书生成/验签在 debug 构建下占用较大栈；使用独立线程
    // 明确栈上限，避免 libtest 默认 2 MiB 线程栈造成假失败。
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    const MLDSA_SEED: [u8; 32] = [0x42; 32];
                    let target = tls_target(TargetGroup::Hybrid).await;
                    let (seed, public) = server_keys();
                    let mut reality = reality(target.address, seed);
                    reality["mldsa65_seed"] = json!(URL_SAFE_NO_PAD.encode(MLDSA_SEED));
                    let upstream = Running::start(json!({
                        "version": 1,
                        "inbounds": [{
                            "type": "vless-reality",
                            "tag": "reality-up",
                            "listen": "127.0.0.1:0",
                            "users": [{"name": "u", "uuid": UUID}],
                            "reality": reality
                        }],
                        "outbounds": [{"type": "direct", "tag": "direct"}],
                        "route": {"default": "direct"},
                        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
                    }))
                    .await;
                    let mldsa = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &MLDSA_SEED).unwrap();
                    let mldsa_public = mldsa.public_key().as_ref().to_vec();
                    let downstream = Running::start(json!({
                        "version": 1,
                        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
                        "outbounds": [{
                            "type": "vless",
                            "tag": "up",
                            "endpoint": upstream.address.to_string(),
                            "uuid": UUID,
                            "reality": {
                                "public_key": URL_SAFE_NO_PAD.encode(public),
                                "short_id": SHORT_ID,
                                "server_name": "localhost",
                                "mldsa65Verify": URL_SAFE_NO_PAD.encode(&mldsa_public)
                            }
                        }],
                        "route": {"default": "up"},
                        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
                    }))
                    .await;
                    assert_tcp_echo(downstream.address).await;
                    downstream.shutdown().await;
                    upstream.shutdown().await;
                    target.shutdown().await.unwrap();
                });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[tokio::test]
async fn vmess_reality_outbound_relays_tcp() {
    relays_protocol_reality("vmess").await;
}

#[tokio::test]
async fn trojan_reality_outbound_relays_tcp() {
    relays_protocol_reality("trojan").await;
}

#[tokio::test]
async fn vless_reality_outbound_relays_tcp() {
    relays_tcp(TargetGroup::X25519).await;
}

#[tokio::test]
async fn vless_reality_outbound_relays_tcp_hybrid_target() {
    relays_tcp(TargetGroup::Hybrid).await;
}

#[tokio::test]
async fn vless_reality_outbound_relays_vision_tcp() {
    let target = tls_target(TargetGroup::Hybrid).await;
    let (seed, public) = server_keys();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-reality",
            "tag": "reality-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}],
            "reality": reality(target.address, seed)
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let downstream = Running::start(json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [{
            "type": "vless",
            "tag": "up",
            "endpoint": upstream.address.to_string(),
            "uuid": UUID,
            "flow": "xtls-rprx-vision",
            "reality": {
                "public_key": URL_SAFE_NO_PAD.encode(public),
                "short_id": SHORT_ID,
                "server_name": "localhost"
            }
        }],
        "route": {"default": "up"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    assert_tcp_echo(downstream.address).await;
    downstream.shutdown().await;
    upstream.shutdown().await;
    target.shutdown().await.unwrap();
}

async fn relays_tcp(group: TargetGroup) {
    let target = tls_target(group).await;
    let (seed, public) = server_keys();
    let upstream = Running::start(upstream(target.address, seed)).await;
    let downstream = Running::start(downstream(upstream.address, public)).await;
    assert_tcp_echo(downstream.address).await;
    downstream.shutdown().await;
    upstream.shutdown().await;
    target.shutdown().await.unwrap();
}

async fn assert_tcp_echo(server: SocketAddr) {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let (mut tunnel, _) = timeout(
        Duration::from_secs(3),
        common::socks(1, common::address(echo.address), server),
    )
    .await
    .expect("SOCKS 经 REALITY 建连超时");
    tunnel.write_all(b"reality-outbound").await.unwrap();
    tunnel.flush().await.unwrap();
    let mut echoed = vec![0; b"reality-outbound".len()];
    tunnel.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"reality-outbound");
}

#[tokio::test]
async fn vless_vmess_trojan_reality_outbound_over_grpc_relays_tcp() {
    let target = tls_target_with_alpn(TargetGroup::Hybrid, vec![b"h2".to_vec()]).await;
    let (seed, public) = server_keys();
    for kind in ["vless", "vmess", "trojan"] {
        let trojan = kind == "trojan";
        let upstream = Running::start(json!({
            "version": 1,
            "inbounds": [{
                "type": format!("{kind}-grpc"),
                "tag": "reality-grpc-up",
                "listen": "127.0.0.1:0",
                "users": [if trojan {
                    json!({"name": "u", "password": PASSWORD})
                } else {
                    json!({"name": "u", "uuid": UUID})
                }],
                "reality": reality(target.address, seed),
                "grpc": {"path": "/Svc/Tun", "multi_path": "/Svc/TunMulti"}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"default": "direct"},
            "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
        }))
        .await;
        let mut outbound = json!({
            "type": kind,
            "tag": "up",
            "endpoint": upstream.address.to_string(),
            "transport": {"type": "grpc", "path": "/Svc/Tun", "multi": false},
            "reality": {
                "public_key": URL_SAFE_NO_PAD.encode(public),
                "short_id": SHORT_ID,
                "server_name": "localhost"
            }
        });
        if trojan {
            outbound["password"] = json!(PASSWORD);
        } else {
            outbound["uuid"] = json!(UUID);
        }
        let local = Running::start(json!({
            "version": 1,
            "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
            "outbounds": [outbound],
            "route": {"default": "up"},
            "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
        }))
        .await;
        assert_tcp_echo(local.address).await;
        local.shutdown().await;
        upstream.shutdown().await;
    }
    target.shutdown().await.unwrap();
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

#[tokio::test]
async fn vless_reality_outbound_relays_native_udp() {
    let target = tls_target(TargetGroup::X25519).await;
    let (seed, public) = server_keys();
    let upstream = Running::start(upstream(target.address, seed)).await;
    let downstream = Running::start(downstream(upstream.address, public)).await;
    let echo = Echo::udp("127.0.0.1").await;
    let (_control, socket) = udp_associate(downstream.address).await;
    let payload = b"reality-udp";
    socket.send(&datagram(echo.address, payload)).await.unwrap();
    let mut buffer = [0u8; 8192];
    let length = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .expect("REALITY UDP 回包超时")
        .unwrap();
    assert_eq!(parse_datagram(&buffer[..length]).1, payload);
    drop(socket);
    drop(_control);
    downstream.shutdown().await;
    upstream.shutdown().await;
    target.shutdown().await.unwrap();
}

#[test]
fn reality_outbound_rejects_bad_keys_and_tls_conflicts() {
    let base = downstream("127.0.0.1:24443".parse().unwrap(), [0x67; 32]);
    let validate = |value: &Value| {
        dubhe::Config::from_json(&value.to_string())
            .and_then(|config| config.validate().map(|()| config))
    };
    assert!(validate(&base).is_ok());
    for (pointer, value) in [
        ("/outbounds/0/reality/public_key", json!("not-base64")),
        ("/outbounds/0/reality/short_id", json!("123")),
        ("/outbounds/0/reality/server_name", json!("")),
        ("/outbounds/0/reality/server_name", json!("127.0.0.1")),
        ("/outbounds/0/reality/version", json!("26.10")),
        ("/outbounds/0/reality/mldsa65Verify", json!("not-base64")),
        (
            "/outbounds/0/reality/mldsa65Verify",
            json!(URL_SAFE_NO_PAD.encode([0u8; 1951])),
        ),
        ("/outbounds/0/tls", json!({"ca_file": "/tmp/ca.pem"})),
        ("/outbounds/0/transport", json!({"type": "ws"})),
        (
            "/outbounds/0/transport",
            json!({"type": "httpupgrade", "path": "/up"}),
        ),
    ] {
        let mut bad = base.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(validate(&bad).is_err(), "{pointer}");
    }
}
