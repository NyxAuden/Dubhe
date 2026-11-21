//! QUIC 出站的受控回环用例；只覆盖 sing-box v2ray-quic 形状。
//! 不使用公网、官方客户端或 Xray 旧 quicSettings 加密/混淆层。

mod common;

use common::{Certificate, Echo, Running};
use dubhe::Config;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, timeout},
};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "quic-outbound-loopback";
const WAIT: Duration = Duration::from_secs(5);

fn outbound(kind: &str, endpoint: String, cert: &Certificate) -> Value {
    let mut value = json!({
        "type": kind, "tag": "up", "endpoint": endpoint,
        "tls": {"ca_file": cert.dir.path().join("cert.pem"), "server_name": "localhost"},
        "transport": {"type": "quic", "quic": {
            "idle_timeout_ms": 30000, "keep_alive_ms": 0, "max_bidi_streams": 2
        }}
    });
    if kind == "trojan" {
        value["password"] = json!(PASSWORD);
    } else {
        value["uuid"] = json!(UUID);
    }
    value
}

fn downstream(outbound: Value) -> Value {
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [outbound], "route": {"default": "up"},
        "limits": {"handshake_timeout_ms": 1500, "dial_timeout_ms": 2000, "shutdown_timeout_ms": 100}
    })
}

async fn upstream(kind: &str, cert: &Certificate) -> Running {
    let users = if kind == "trojan" {
        json!([{"name": "u", "password": PASSWORD}])
    } else {
        json!([{"name": "u", "uuid": UUID}])
    };
    Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": format!("{kind}-quic"), "tag": "remote", "listen": "127.0.0.1:0",
            "users": users, "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem"),
            "quic": {"max_bidi_streams": 2}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"handshake_timeout_ms": 2000, "shutdown_timeout_ms": 100}
    }))
    .await
}

async fn tcp_exchange(server: std::net::SocketAddr, target: std::net::SocketAddr) {
    timeout(WAIT, async {
        let (mut tunnel, _) = common::socks(1, common::address(target), server).await;
        let bytes = [0x5a; 8192];
        tunnel.write_all(&bytes).await.unwrap();
        tunnel.flush().await.unwrap();
        let mut echoed = vec![0; bytes.len()];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, bytes);
    })
    .await
    .expect("QUIC TCP 回环应在期限内完成");
}

#[tokio::test]
async fn all_three_protocols_relay_tcp_over_quic() {
    for kind in ["vless", "vmess", "trojan"] {
        let cert = Certificate::new();
        let remote = upstream(kind, &cert).await;
        let local = Running::start(downstream(outbound(
            kind,
            remote.address.to_string(),
            &cert,
        )))
        .await;
        let echo = Echo::tcp("127.0.0.1", false).await;
        tcp_exchange(local.address, echo.address).await;
        local.shutdown().await;
        remote.shutdown().await;
    }
}

#[tokio::test]
async fn shared_quic_connection_reuses_released_stream_slots() {
    let cert = Certificate::new();
    let remote = upstream("vless", &cert).await;
    let local = Running::start(downstream(outbound(
        "vless",
        remote.address.to_string(),
        &cert,
    )))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    // 每轮同时占满两个本地流额度，下一轮必须能重新取得已释放的额度。
    for _ in 0..3 {
        tokio::join!(
            tcp_exchange(local.address, echo.address),
            tcp_exchange(local.address, echo.address),
        );
    }
    local.shutdown().await;
    remote.shutdown().await;
}

async fn udp_associate(server: std::net::SocketAddr) -> (TcpStream, UdpSocket) {
    let (control, bound) = common::socks(3, vec![1, 0, 0, 0, 0, 0, 0], server).await;
    let relay = if bound.ip().is_unspecified() {
        std::net::SocketAddr::new(server.ip(), bound.port())
    } else {
        bound
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    (control, socket)
}

#[tokio::test]
async fn protocol_udp_frames_are_carried_inside_quic_streams() {
    for kind in ["vless", "vmess", "trojan"] {
        let cert = Certificate::new();
        let remote = upstream(kind, &cert).await;
        let local = Running::start(downstream(outbound(
            kind,
            remote.address.to_string(),
            &cert,
        )))
        .await;
        let echo = Echo::udp("127.0.0.1").await;
        let (control, socket) = timeout(WAIT, udp_associate(local.address)).await.unwrap();
        let mut expected = vec![0, 0, 0];
        expected.extend_from_slice(&common::address(echo.address));
        expected.extend_from_slice(&[0xa5; 3000]);
        socket.send(&expected).await.unwrap();
        let mut bytes = [0; 4096];
        let length = timeout(WAIT, socket.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..length], expected, "{kind} UDP 应保留来源和载荷");
        drop(socket);
        drop(control);
        local.shutdown().await;
        remote.shutdown().await;
    }
}

#[tokio::test]
async fn wrong_ca_and_sni_fail_before_the_target_is_contacted() {
    let cert = Certificate::new();
    let other = Certificate::new();
    let remote = upstream("vless", &cert).await;
    for wrong_ca in [true, false] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut value = outbound("vless", remote.address.to_string(), &cert);
        if wrong_ca {
            value["tls"]["ca_file"] = json!(other.dir.path().join("cert.pem"));
        } else {
            value["tls"]["server_name"] = json!("wrong.test");
        }
        let local = Running::start(downstream(value)).await;
        timeout(WAIT, async {
            let mut socket = TcpStream::connect(local.address).await.unwrap();
            socket.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            socket.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            let mut request = vec![5, 1, 0];
            request.extend_from_slice(&common::address(target.local_addr().unwrap()));
            socket.write_all(&request).await.unwrap();
            let mut head = [0; 3];
            socket.read_exact(&mut head).await.unwrap();
            assert_ne!(head[1], 0, "错误信任不能返回 CONNECT 成功");
        })
        .await
        .unwrap();
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
        local.shutdown().await;
    }
    remote.shutdown().await;
}

#[test]
fn quic_transport_rejects_missing_security_and_misplaced_parameters() {
    let cert = Certificate::new();
    let base = downstream(outbound("vless", "127.0.0.1:24443".into(), &cert));
    assert!(
        Config::from_json(&base.to_string())
            .and_then(|config| config.validate().map(|()| config))
            .is_ok()
    );
    for (pointer, value) in [
        ("/outbounds/0/tls", Value::Null),
        ("/outbounds/0/transport/path", json!("/not-http")),
        ("/outbounds/0/transport/host", json!("localhost")),
        ("/outbounds/0/transport/quic/max_bidi_streams", json!(0)),
        ("/outbounds/0/transport/quic/idle_timeout_ms", json!(0)),
        ("/outbounds/0/transport/type", json!("ws")),
    ] {
        let mut value_at = base.clone();
        if value_at.pointer(pointer).is_some() {
            *value_at.pointer_mut(pointer).unwrap() = value;
        } else {
            let key = pointer.rsplit('/').next().unwrap();
            value_at["outbounds"][0]["transport"][key] = value;
        }
        assert!(
            Config::from_json(&value_at.to_string())
                .and_then(|config| config.validate().map(|()| config))
                .is_err(),
            "{pointer}"
        );
    }
    let mut chained = base;
    chained["outbounds"][0]["via"] = json!("entry");
    chained["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "socks5", "tag": "entry", "endpoint": "127.0.0.1:21080"
    }));
    assert!(
        Config::from_json(&chained.to_string())
            .and_then(|config| config.validate().map(|()| config))
            .is_err()
    );
}
