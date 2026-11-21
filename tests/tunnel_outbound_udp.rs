//! WireGuard UDP 出站：经 SOCKS5 入站、真实隧道服务端、真实 UDP 目标。
//! 全部只连接回环，不运行官方客户端，不改变系统网络。
mod common;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::x25519;
use common::{Echo, Running};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

fn downstream(outbound: Value) -> Value {
    json!({"version":1,
        "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
        "outbounds":[outbound, {"type":"reject","tag":"reject"}],
        "route":{"default":"up"},
        "limits":{"shutdown_timeout_ms":500,"dial_timeout_ms":800,"handshake_timeout_ms":1000}
    })
}
async fn associate(address: SocketAddr) -> (TcpStream, UdpSocket) {
    let mut control = TcpStream::connect(address).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut head = [0; 3];
    control.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0);
    let mut relay = common::read_address(&mut control).await;
    if relay.ip().is_unspecified() {
        relay.set_ip(address.ip());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    (control, socket)
}
fn frame(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut result = vec![0, 0, 0];
    result.extend(common::address(target));
    result.extend(data);
    result
}
fn parse(frame: &[u8]) -> (SocketAddr, &[u8]) {
    assert_eq!(&frame[..3], &[0, 0, 0]);
    let (ip, offset) = match frame[3] {
        1 => (
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(&frame[4..8]).unwrap(),
            )),
            8,
        ),
        4 => (
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[4..20]).unwrap(),
            )),
            20,
        ),
        _ => panic!("回包地址类型无效"),
    };
    (
        SocketAddr::new(ip, u16::from_be_bytes([frame[offset], frame[offset + 1]])),
        &frame[offset + 2..],
    )
}
async fn roundtrip(socket: &UdpSocket, target: SocketAddr, data: &[u8]) {
    socket.send(&frame(target, data)).await.unwrap();
    let mut buffer = vec![0; 65536];
    let length = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .expect("隧道 UDP 回包超时")
        .unwrap();
    let (source, payload) = parse(&buffer[..length]);
    assert_eq!(source, target);
    assert_eq!(payload, data);
}
fn public(secret: [u8; 32]) -> [u8; 32] {
    x25519::PublicKey::from(&x25519::StaticSecret::from(secret)).to_bytes()
}
async fn wireguard() -> (Running, Value) {
    let server_key = [0x51; 32];
    let client_key = [0x52; 32];
    let server = Running::start(json!({"version":1,
        "inbounds":[{"type":"wireguard","tag":"wg","listen":"127.0.0.1:0",
            "private_key":STANDARD.encode(server_key),"address":["10.88.0.1/24","fd00:88::1/64"],
            "peers":[{"public_key":STANDARD.encode(public(client_key)),"allowed_ips":["10.88.0.2/32","fd00:88::2/128"]}]}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":500}
    })).await;
    let outbound = json!({"type":"wireguard","tag":"up","endpoint":server.address.to_string(),
        "wireguard":{"private_key":STANDARD.encode(client_key),"peer_public_key":STANDARD.encode(public(server_key)),
            "address":["10.88.0.2/32","fd00:88::2/128"],"mtu":1420}});
    (server, outbound)
}
async fn exercise(upstream: Running, outbound: Value) {
    let first = Echo::udp("127.0.0.1").await;
    let second = Echo::udp("127.0.0.1").await;
    let running = Running::start(downstream(outbound)).await;
    let (control, socket) = associate(running.address).await;
    for (target, payload) in [
        (first.address, b"first".as_slice()),
        (second.address, b"second"),
        (first.address, b""),
        (second.address, b"again"),
    ] {
        roundtrip(&socket, target, payload).await;
    }
    if UdpSocket::bind("[::1]:0").await.is_ok() {
        let echo = Echo::udp("[::1]").await;
        roundtrip(&socket, echo.address, b"ipv6-over-ipv4-outer").await;
    }
    drop(socket);
    drop(control);
    running.shutdown().await;
    upstream.shutdown().await;
}
#[tokio::test]
async fn wireguard_udp_targets_empty_and_dual_stack() {
    let (upstream, outbound) = wireguard().await;
    exercise(upstream, outbound).await;
}

async fn denied(upstream: Running, outbound: Value) {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let running = Running::start(downstream(outbound)).await;
    let (control, socket) = associate(running.address).await;
    socket
        .send(&frame(target.local_addr().unwrap(), b"must-not-reach"))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(1000), target.recv_from(&mut buffer))
            .await
            .is_err(),
        "认证失败不能直连"
    );
    assert_eq!(running.stats.snapshot().uplink, 0);
    drop(socket);
    drop(control);
    running.shutdown().await;
    upstream.shutdown().await;
}
#[tokio::test]
async fn wireguard_wrong_peer_key_never_falls_back_to_direct() {
    let (upstream, mut outbound) = wireguard().await;
    outbound["wireguard"]["peer_public_key"] = json!(STANDARD.encode(public([0x61; 32])));
    denied(upstream, outbound).await;
}
#[tokio::test]
async fn tunnel_udp_reject_route_prevents_target_traffic() {
    let (upstream, outbound) = wireguard().await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut value = downstream(outbound);
    value["route"]["rules"] = json!([{"networks":["udp"],"outbound":"reject"}]);
    let running = Running::start(value).await;
    let (control, socket) = associate(running.address).await;
    socket
        .send(&frame(target.local_addr().unwrap(), b"blocked-by-route"))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(150), target.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert!(running.stats.snapshot().rejected > 0);
    assert_eq!(running.stats.snapshot().uplink, 0);
    drop(socket);
    drop(control);
    running.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn udp_target_limit_and_oversized_packet_preserve_existing_target() {
    let (upstream, outbound) = wireguard().await;
    let first = Echo::udp("127.0.0.1").await;
    let forbidden = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut value = downstream(outbound);
    value["limits"]["max_udp_targets"] = json!(1);
    let running = Running::start(value).await;
    let (control, socket) = associate(running.address).await;
    roundtrip(&socket, first.address, b"before").await;
    socket
        .send(&frame(forbidden.local_addr().unwrap(), b"over-limit"))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(150), forbidden.recv_from(&mut buffer))
            .await
            .is_err()
    );
    socket
        .send(&frame(first.address, &vec![1; 1600]))
        .await
        .unwrap();
    roundtrip(&socket, first.address, b"after").await;
    drop(socket);
    drop(control);
    running.shutdown().await;
    upstream.shutdown().await;
}
