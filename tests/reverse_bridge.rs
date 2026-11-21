//! 反向 Mux Bridge 的本机闭环：Bridge 主动拨入 Portal 的命令 4，
//! 用户从 Portal 的 SOCKS 入站经 reverse 出站回到 Bridge 的 Mux 服务端。

mod common;

use std::net::SocketAddr;

use common::{Echo, Running};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::{Duration, sleep},
};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn portal_config(cert: Option<&common::Certificate>, vision: bool) -> Value {
    let mut users = json!([{"name": "u", "uuid": UUID}]);
    let mut inbound = json!({
        "type": "vless",
        "tag": "portal-in",
        "listen": "127.0.0.1:0",
        "users": users
    });
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    }
    if vision {
        users = json!([{"name": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}]);
        inbound["users"] = users;
    }
    json!({
        "version": 1,
        "inbounds": [
            inbound,
            {"type": "socks5", "tag": "users", "listen": "127.0.0.1:0"}
        ],
        "outbounds": [
            {"type": "reverse", "tag": "portal", "domain": "v1.rvs.cool"},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "default": "portal",
            "rules": [{"domains": ["v1.rvs.cool"], "outbound": "portal"}]
        },
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    })
}

fn bridge_config(portal: SocketAddr, cert: Option<&common::Certificate>, vision: bool) -> Value {
    let mut outbound = json!({
        "type": "vless",
        "tag": "portal-link",
        "endpoint": portal.to_string(),
        "uuid": UUID
    });
    if let Some(cert) = cert {
        outbound["tls"] = json!({
            "ca_file": cert.dir.path().join("cert.pem").to_string_lossy(),
            "server_name": "localhost"
        });
    }
    if vision {
        outbound["flow"] = json!("xtls-rprx-vision");
    }
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "reverse_bridges": [{"tag": "bridge", "outbound": "portal-link", "reconnect_ms": 200}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    })
}

async fn assert_reverse_relay(portal: Running, bridge: Running) {
    let echo = Echo::tcp("127.0.0.1", false).await;
    // Bridge 首次拨入是异步的；本机重试间隔 200ms，这里给足注册时间。
    sleep(Duration::from_millis(500)).await;
    let users = portal.addresses[1];
    let (mut tunnel, _) = tokio::time::timeout(
        Duration::from_secs(3),
        common::socks(1, common::address(echo.address), users),
    )
    .await
    .expect("Portal SOCKS 建连超时");
    let payload = [0x5a; 4096];
    tunnel.write_all(&payload).await.unwrap();
    tunnel.flush().await.unwrap();
    let mut echoed = vec![0; payload.len()];
    tunnel.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    drop(tunnel);
    bridge.shutdown().await;
    portal.shutdown().await;
}

#[tokio::test]
async fn bridge_relays_portal_traffic_over_plain_vless() {
    let portal = Running::start(portal_config(None, false)).await;
    let bridge = Running::start(bridge_config(portal.address, None, false)).await;
    assert_reverse_relay(portal, bridge).await;
}

#[tokio::test]
async fn bridge_relays_portal_udp_over_mux() {
    let portal = Running::start(portal_config(None, false)).await;
    let bridge = Running::start(bridge_config(portal.address, None, false)).await;
    sleep(Duration::from_millis(500)).await;
    let echo = Echo::udp("127.0.0.1").await;
    let users = portal.addresses[1];
    let (_control, bound) = common::socks(3, vec![1, 0, 0, 0, 0, 0, 0], users).await;
    let relay = if bound.ip().is_unspecified() {
        SocketAddr::new(users.ip(), bound.port())
    } else {
        bound
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    let mut datagram = vec![0, 0, 0];
    datagram.extend_from_slice(&common::address(echo.address));
    datagram.extend_from_slice(&[0x9c; 2048]);
    socket.send(&datagram).await.unwrap();
    let mut received = [0u8; 4096];
    let length = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut received))
        .await
        .expect("反向 Mux UDP 回包超时")
        .unwrap();
    assert_eq!(&received[..length], &datagram);
    drop(socket);
    drop(_control);
    bridge.shutdown().await;
    portal.shutdown().await;
}

#[tokio::test]
async fn bridge_relays_through_vision_command_four() {
    let cert = common::Certificate::new();
    let portal = Running::start(portal_config(Some(&cert), true)).await;
    let bridge = Running::start(bridge_config(portal.address, Some(&cert), true)).await;
    assert_reverse_relay(portal, bridge).await;
}

#[test]
fn bridge_configuration_requires_an_existing_vless_outbound() {
    let base = bridge_config("127.0.0.1:443".parse().unwrap(), None, false);
    for (pointer, value) in [
        ("/reverse_bridges/0/outbound", json!("missing")),
        ("/reverse_bridges/0/tag", json!("")),
        ("/reverse_bridges/0/reconnect_ms", json!(99)),
    ] {
        let mut bad = base.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            dubhe::Config::from_json(&bad.to_string())
                .and_then(|config| config.validate().map(|()| config))
                .is_err(),
            "{pointer}"
        );
    }
    let mut group = base;
    group["reverse_bridges"][0]["outbound"] = json!("direct");
    assert!(
        dubhe::Config::from_json(&group.to_string())
            .and_then(|config| config.validate().map(|()| config))
            .is_err()
    );
}
