//! 混合入口资源与计量回归；此文件使用库客户端，不作为独立wire证据。
mod common;
use common::*;
use serde_json::{Value, json};
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    relay::{
        Address,
        tcprelay::ProxyClientStream,
        udprelay::{
            crypto_io::{decrypt_server_payload, encrypt_client_payload},
            options::UdpSocketControlData,
        },
    },
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(3);
fn configuration() -> Value {
    let mut config = socks_config();
    config["inbounds"].as_array_mut().unwrap().push(json!({"type":"shadowsocks","tag":"ss","listen":"127.0.0.1:0","method":"aes-128-gcm","password":PASSWORD}));
    config
}
fn key() -> ServerConfig {
    ServerConfig::new(
        "127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap(),
        PASSWORD,
        CipherKind::AES_128_GCM,
    )
    .unwrap()
}
async fn wait(server: &Running, ready: impl Fn(&dubhe::telemetry::Snapshot) -> bool) {
    timeout(WAIT, async {
        while !ready(&server.stats.snapshot()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn ss_tcp(server: &Running, target: std::net::SocketAddr) -> ProxyClientStream<TcpStream> {
    let stream = TcpStream::connect(server.addresses[1]).await.unwrap();
    ProxyClientStream::from_stream(
        Arc::new(Context::new(ServerType::Local)),
        stream,
        &key(),
        Address::SocketAddress(target),
    )
}
fn wire(target: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let key = key();
    let mut wire = Default::default();
    encrypt_client_payload(
        &Context::new(ServerType::Local),
        key.method(),
        key.key(),
        &Address::SocketAddress(target),
        &UdpSocketControlData::default(),
        &[],
        payload,
        &mut wire,
    );
    wire.to_vec()
}
async fn udp_roundtrip(
    server: &Running,
    client: &UdpSocket,
    target: std::net::SocketAddr,
    payload: &[u8],
) {
    client
        .send_to(&wire(target, payload), server.addresses[1])
        .await
        .unwrap();
    let mut buffer = [0; 65536];
    let (length, _) = client.recv_from(&mut buffer).await.unwrap();
    let key = key();
    let (length, address, _) = decrypt_server_payload(
        &Context::new(ServerType::Local),
        key.method(),
        key.key(),
        &mut buffer[..length],
    )
    .unwrap();
    assert_eq!(address, Address::SocketAddress(target));
    assert_eq!(&buffer[..length], payload);
}

#[tokio::test]
async fn shared_tcp_connection_and_per_inbound_handshake_limits_recover() {
    timeout(Duration::from_secs(10), async {
        let target = Echo::tcp("127.0.0.1", false).await;
        let mut config = configuration();
        config["limits"]["max_connections"] = json!(1);
        let server = Running::start(config).await;
        let (mut incumbent, _) = socks(1, address(target.address), server.address).await;
        exchange(&mut incumbent, b"socks occupies slot").await;
        let mut denied = TcpStream::connect(server.addresses[1]).await.unwrap();
        assert!(matches!(denied.read(&mut [0]).await, Ok(0) | Err(_)));
        drop(incumbent);
        wait(&server, |s| s.connections == 0).await;
        let mut ss = ss_tcp(&server, target.address).await;
        exchange(&mut ss, b"ss reuses slot").await;
        drop(ss);
        wait(&server, |s| s.connections == 0).await;
        server.shutdown().await;
        let mut config = configuration();
        config["limits"]["max_handshakes"] = json!(1);
        config["limits"]["handshake_timeout_ms"] = json!(10000);
        let server = Running::start(config).await;
        let incomplete = TcpStream::connect(server.addresses[1]).await.unwrap();
        wait(&server, |s| s.connections == 1).await;
        let mut denied = TcpStream::connect(server.addresses[1]).await.unwrap();
        assert!(matches!(denied.read(&mut [0]).await, Ok(0) | Err(_)));
        // 握手许可按入口分离，SS半握手不应占用SOCKS握手许可。
        let (mut other, _) = socks(1, address(target.address), server.address).await;
        exchange(&mut other, b"independent gate").await;
        drop((incomplete, other));
        wait(&server, |s| s.connections == 0).await;
        let mut ss = ss_tcp(&server, target.address).await;
        exchange(&mut ss, b"gate recovered").await;
        drop(ss);
        wait(&server, |s| s.connections == 0).await;
        server.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shared_udp_slots_and_bytes_drop_then_recover_with_exact_plaintext_counts() {
    timeout(Duration::from_secs(10), async {
        let target = Echo::udp("127.0.0.1").await;
        let mut config = configuration();
        config["limits"]["max_udp_associations"] = json!(1);
        config["limits"]["udp_idle_timeout_ms"] = json!(10000);
        config["limits"]["udp_queue_bytes"] = json!(256);
        let server = Running::start(config).await;
        let (control, _) = socks(3, address("0.0.0.0:0".parse().unwrap()), server.address).await;
        wait(&server, |s| s.udp_associations == 1).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&wire(target.address, b"denied"), server.addresses[1])
            .await
            .unwrap();
        wait(&server, |s| s.dropped >= 1).await;
        assert_eq!(server.stats.snapshot().uplink, 0);
        drop(control);
        wait(&server, |s| s.udp_associations == 0).await;
        udp_roundtrip(&server, &client, target.address, b"ok").await;
        let before = server.stats.snapshot().dropped;
        // 密文排队也占全局预算，不能只按明文2字节的旧路径处理。
        client
            .send_to(&wire(target.address, &[7; 256]), server.addresses[1])
            .await
            .unwrap();
        wait(&server, |s| s.dropped > before).await;
        udp_roundtrip(&server, &client, target.address, b"after").await;
        assert_eq!(server.stats.snapshot().uplink, 7);
        assert_eq!(server.stats.snapshot().downlink, 7);
        let addresses = server.addresses.clone();
        server.shutdown().await;
        for address in addresses {
            let _tcp = tokio::net::TcpListener::bind(address).await.unwrap();
            let _udp = UdpSocket::bind(address).await.unwrap();
        }
    })
    .await
    .unwrap();
}
