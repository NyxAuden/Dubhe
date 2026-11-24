mod common;

use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use serde_json::{Value, json};
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    relay::{
        Address,
        udprelay::{
            crypto_io::{decrypt_server_payload, encrypt_client_payload},
            options::UdpSocketControlData,
        },
    },
};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

const WAIT: Duration = Duration::from_secs(2);
const METHODS: [&str; 6] = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

fn configuration(method: &str, multiple: bool) -> (Value, Vec<ServerConfig>) {
    let cipher: CipherKind = method.parse().unwrap();
    let identity = if cipher.is_aead_2022() {
        STANDARD.encode(vec![0x73; cipher.key_len()])
    } else {
        PASSWORD.to_owned()
    };
    let mut value = socks_config();
    value["inbounds"] = json!([{"type":"shadowsocks", "tag":"ss", "listen":"127.0.0.1:0", "method":method, "password":identity}]);
    let passwords = if multiple {
        let users: Vec<_> = [0x74, 0x75].into_iter().enumerate().map(|(index, byte)| json!({"name":format!("user{index}"), "password":STANDARD.encode(vec![byte; cipher.key_len()])})).collect();
        value["inbounds"][0]["users"] = json!(users);
        [0x74, 0x75]
            .into_iter()
            .map(|byte| {
                format!(
                    "{}:{}",
                    identity,
                    STANDARD.encode(vec![byte; cipher.key_len()])
                )
            })
            .collect::<Vec<_>>()
    } else {
        vec![identity]
    };
    let clients = passwords
        .into_iter()
        .map(|password| {
            ServerConfig::new(
                "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
                password,
                cipher,
            )
            .unwrap()
        })
        .collect();
    (value, clients)
}

fn request(client: &ServerConfig, target: SocketAddr, packet: u64, payload: &[u8]) -> Vec<u8> {
    let mut control = UdpSocketControlData::default();
    control.client_session_id = 0x123456789;
    control.packet_id = packet;
    let mut wire = Default::default();
    encrypt_client_payload(
        &Context::new(ServerType::Local),
        client.method(),
        client.key(),
        &Address::SocketAddress(target),
        &control,
        client.identity_keys(),
        payload,
        &mut wire,
    );
    wire.to_vec()
}

async fn roundtrip(
    client: &UdpSocket,
    server: SocketAddr,
    key: &ServerConfig,
    target: SocketAddr,
    packet: u64,
    payload: &[u8],
) -> Option<UdpSocketControlData> {
    client
        .send_to(&request(key, target, packet, payload), server)
        .await
        .unwrap();
    let mut buffer = [0; 65536];
    let (length, source) = timeout(WAIT, client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, server);
    let (plain, address, control) = decrypt_server_payload(
        &Context::new(ServerType::Local),
        key.method(),
        key.key(),
        &mut buffer[..length],
    )
    .unwrap();
    assert_eq!(address, Address::SocketAddress(target));
    assert_eq!(&buffer[..plain], payload);
    control
}

#[tokio::test]
async fn all_methods_and_eih_users_native_udp_empty_payload_and_accounting() {
    for method in METHODS {
        for multiple in [false, true] {
            if multiple && ![METHODS[3], METHODS[4]].contains(&method) {
                continue;
            }
            let (value, clients) = configuration(method, multiple);
            let server = Running::start(value).await;
            let target = Echo::udp("127.0.0.1").await;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for key in &clients {
                let first =
                    roundtrip(&socket, server.address, key, target.address, 0, b"first").await;
                let second = roundtrip(&socket, server.address, key, target.address, 1, b"").await;
                if key.method().is_aead_2022() {
                    let first = first.unwrap();
                    let second = second.unwrap();
                    assert_eq!(first.client_session_id, 0x123456789);
                    assert_eq!(first.server_session_id, second.server_session_id);
                    assert_ne!(first.server_session_id, first.client_session_id);
                    assert!(second.packet_id > first.packet_id);
                }
            }
            assert_eq!(server.stats.snapshot().uplink, (clients.len() * 5) as u64);
            assert_eq!(server.stats.snapshot().downlink, (clients.len() * 5) as u64);
            let address = server.address;
            server.shutdown().await;
            let _rebound = UdpSocket::bind(address).await.unwrap();
        }
    }
}

#[tokio::test]
async fn modern_dual_stack_source_port_migration_and_replay_filtering() {
    for method in &METHODS[3..] {
        let (value, clients) = configuration(method, false);
        let server = Running::start(value).await;
        let key = &clients[0];
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
        let mut buffer = [0; 65536];
        first
            .send_to(
                &request(key, v4.local_addr().unwrap(), 10, b"one"),
                server.address,
            )
            .await
            .unwrap();
        let (length, peer4) = timeout(WAIT, v4.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"one");
        second
            .send_to(
                &request(key, v6.local_addr().unwrap(), 12, b"two"),
                server.address,
            )
            .await
            .unwrap();
        let (length, peer6) = timeout(WAIT, v6.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"two");
        assert_eq!(peer4.port(), peer6.port());
        // 迁移后旧目标的延迟回包也必须发给最新端点。
        v4.send_to(b"late", peer4).await.unwrap();
        let (length, _) = timeout(WAIT, second.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let (plain, _, _) = decrypt_server_payload(
            &Context::new(ServerType::Local),
            key.method(),
            key.key(),
            &mut buffer[..length],
        )
        .unwrap();
        assert_eq!(&buffer[..plain], b"late");
        assert!(
            timeout(Duration::from_millis(30), first.recv_from(&mut buffer))
                .await
                .is_err()
        );
        // 重放不能夺回来源；坏tag不推进窗口，合法的窗口内乱序号仍可使用。
        first
            .send_to(
                &request(key, v4.local_addr().unwrap(), 10, b"replay"),
                server.address,
            )
            .await
            .unwrap();
        let mut bad = request(key, v4.local_addr().unwrap(), 11, b"eleven");
        *bad.last_mut().unwrap() ^= 1;
        first.send_to(&bad, server.address).await.unwrap();
        assert!(
            timeout(Duration::from_millis(30), v4.recv_from(&mut buffer))
                .await
                .is_err()
        );
        second
            .send_to(
                &request(key, v4.local_addr().unwrap(), 11, b"eleven"),
                server.address,
            )
            .await
            .unwrap();
        let (length, actual_peer) = timeout(WAIT, v4.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(actual_peer, peer4);
        assert_eq!(&buffer[..length], b"eleven");
        // 从未经发送授权的第三个目标发包，不得进入客户端回程。
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger.send_to(b"unsolicited", peer4).await.unwrap();
        assert!(
            timeout(Duration::from_millis(30), second.recv_from(&mut buffer))
                .await
                .is_err()
        );
        server.shutdown().await;
        let _rebound = UdpSocket::bind(peer4).await.unwrap();
    }
}

#[tokio::test]
async fn wrong_key_and_replayed_legacy_datagrams_do_not_reach_target() {
    for method in METHODS {
        let (value, clients) = configuration(method, false);
        let server = Running::start(value).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let key = &clients[0];
        let wire = request(key, target.local_addr().unwrap(), 1, b"valid");
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        client.send_to(&bad, server.address).await.unwrap();
        let mut buffer = [0; 65536];
        assert!(
            timeout(Duration::from_millis(30), target.recv_from(&mut buffer))
                .await
                .is_err()
        );
        assert_eq!(server.stats.snapshot().udp_associations, 0);
        client.send_to(&wire, server.address).await.unwrap();
        let (length, _) = timeout(WAIT, target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"valid");
        client.send_to(&wire, server.address).await.unwrap();
        assert!(
            timeout(Duration::from_millis(30), target.recv_from(&mut buffer))
                .await
                .is_err()
        );
        server.shutdown().await;
    }
}

/// Shadowsocks 2022 的 UDP 经 SOCKS5 出站转发。
///
/// 修复前 `Dispatcher::process` 调用 `ctx.allowed()`，选到任何代理出站都返回
/// `Unsupported`——链式部署下 SS 的 UDP 直接失败。
///
/// 覆盖范围说明：本实现只支持 2022（modern）模式。2017（legacy）的回程需要
/// 关联自己的加密上下文，且 `Packet` 是 `udp` 模块私有，因此那一支保持
/// fail-closed（选到代理时返回 Unsupported，不会悄悄直连）。
#[tokio::test]
async fn modern_udp_relays_through_a_socks5_outbound() {
    // 落地机：SOCKS5 入口，出站直连。
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "up", "listen": "127.0.0.1:0"}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;

    let echo = Echo::udp("127.0.0.1").await;
    let (mut value, clients) = configuration("2022-blake3-aes-128-gcm", false);
    value["outbounds"] = json!([
        {"type": "direct", "tag": "direct"},
        {"type": "socks5", "tag": "up", "endpoint": upstream.address.to_string()}
    ]);
    value["route"] = json!({"default": "up"});
    let server = Running::start(value).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"ss2022-via-socks";
    let control = roundtrip(
        &client,
        server.address,
        &clients[0],
        echo.address,
        1,
        payload,
    )
    .await;
    assert!(control.is_some(), "2022 应答应带控制块");

    server.shutdown().await;
    upstream.shutdown().await;
}
