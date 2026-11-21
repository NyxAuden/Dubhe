//! TUIC出站现代策略的Config/runtime本机回环，不运行官方客户端。
mod common;
use common::{Certificate, Echo, Running};
use dubhe::Config;
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "tuic-modern-loopback-password";
const WAIT: Duration = Duration::from_secs(3);
fn outbound(
    cert: &Certificate,
    address: SocketAddr,
    algorithm: &str,
    early: bool,
    mode: &str,
) -> Value {
    json!({"type":"tuic","tag":"up","endpoint":address.to_string(),"uuid":UUID,"password":PASSWORD,
        "tls":{"ca_file":cert.dir.path().join("cert.pem"),"server_name":"localhost"},
        "tuic":{"congestion_control":algorithm,"zero_rtt_handshake":early,"udp_relay_mode":mode}})
}
fn downstream(proxy: Value) -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],
    "outbounds":[proxy,{"type":"reject","tag":"reject"}],"route":{"default":"up"},
    "limits":{"dial_timeout_ms":800,"handshake_timeout_ms":1500,"shutdown_timeout_ms":500}})
}
async fn upstream(cert: &Certificate) -> Running {
    Running::start(json!({"version":1,"inbounds":[{"type":"tuic","tag":"upstream","listen":"127.0.0.1:0",
        "users":[{"name":"u","uuid":UUID,"password":PASSWORD}],"zero_rtt_handshake":true,
        "certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},
        "limits":{"handshake_timeout_ms":1500,"shutdown_timeout_ms":500}})).await
}
async fn associate(address: SocketAddr) -> (TcpStream, UdpSocket) {
    let (control, mut bound) =
        common::socks(3, common::address("0.0.0.0:0".parse().unwrap()), address).await;
    if bound.ip().is_unspecified() {
        bound.set_ip(address.ip());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(bound).await.unwrap();
    (control, socket)
}
fn packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend(common::address(target));
    bytes.extend(payload);
    bytes
}

#[test]
fn policies_are_explicit_default_safe_and_strict() {
    let cert = Certificate::new();
    let base = downstream(outbound(
        &cert,
        "127.0.0.1:12345".parse().unwrap(),
        "cubic",
        false,
        "native",
    ));
    for algorithm in ["cubic", "new_reno", "new-reno", "bbr"] {
        for early in [false, true] {
            let mut value = base.clone();
            value["outbounds"][0]["tuic"]["congestion_control"] = json!(algorithm);
            value["outbounds"][0]["tuic"]["zero_rtt_handshake"] = json!(early);
            Config::from_json(&value.to_string()).unwrap();
        }
    }
    let mut default = base.clone();
    default["outbounds"][0]["tuic"] = json!({});
    let parsed = Config::from_json(&default.to_string()).unwrap();
    let options = parsed.outbounds[0].tuic.as_ref().unwrap();
    assert!(!options.zero_rtt_handshake);
    assert!(options.congestion_control.is_none());
    for (field, value) in [
        ("congestion_control", json!("reno")),
        ("congestion_control", json!("bbr2")),
        ("congestion_control", json!("BBR")),
        ("zero_rtt_handshake", json!("true")),
        ("zero_rtt_handshake", json!(1)),
        ("udp_over_stream", json!(true)),
    ] {
        let mut config = base.clone();
        config["outbounds"][0]["tuic"][field] = value;
        assert!(Config::from_json(&config.to_string()).is_err(), "{field}");
    }
}

#[tokio::test]
async fn real_controllers_tcp_native_and_stream_udp_use_same_policy() {
    let cert = Certificate::new();
    let up = upstream(&cert).await;
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let udp = Echo::udp("127.0.0.1").await;
    for algorithm in ["cubic", "new_reno", "bbr"] {
        for mode in ["native", "quic"] {
            let running = Running::start(downstream(outbound(
                &cert, up.address, algorithm, true, mode,
            )))
            .await;
            let (mut stream, _) =
                common::socks(1, common::address(tcp.address), running.address).await;
            stream.write_all(b"policy").await.unwrap();
            let mut reply = [0; 6];
            timeout(WAIT, stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply, b"policy");
            let (control, socket) = associate(running.address).await;
            for payload in [b"udp-policy".as_slice(), b""] {
                socket.send(&packet(udp.address, payload)).await.unwrap();
                let mut bytes = [0; 128];
                let count = timeout(WAIT, socket.recv(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&bytes[..count], packet(udp.address, payload));
            }
            drop(stream);
            drop(socket);
            drop(control);
            running.shutdown().await;
        }
    }
    up.shutdown().await;
}

#[tokio::test]
async fn credentials_certificates_and_reject_never_fall_back_to_direct() {
    let cert = Certificate::new();
    let untrusted = Certificate::new();
    let up = upstream(&cert).await;
    for wrong_ca in [false, true] {
        let mut proxy = outbound(
            if wrong_ca { &untrusted } else { &cert },
            up.address,
            "bbr",
            true,
            "native",
        );
        if !wrong_ca {
            proxy["password"] = json!("wrong-password");
        }
        let running = Running::start(downstream(proxy)).await;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(running.address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0x0500);
        let mut request = vec![5, 1, 0];
        request.extend(common::address(tcp.local_addr().unwrap()));
        client.write_all(&request).await.unwrap();
        // TUIC没有成功认证应答，根SOCKS可先成功；无论哪种都不能成为目标业务。
        let mut head = [0; 3];
        client.read_exact(&mut head).await.unwrap();
        if head[1] == 0 {
            let _ = common::read_address(&mut client).await;
            let _ = client.write_all(b"denied").await;
            let mut data = [0; 32];
            assert!(matches!(
                timeout(WAIT, client.read(&mut data)).await.unwrap(),
                Ok(0) | Err(_)
            ));
        }
        assert!(
            timeout(Duration::from_millis(100), tcp.accept())
                .await
                .is_err()
        );
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (control, socket) = associate(running.address).await;
        socket
            .send(&packet(udp.local_addr().unwrap(), b"denied"))
            .await
            .unwrap();
        let mut data = [0; 32];
        assert!(
            timeout(Duration::from_millis(150), udp.recv(&mut data))
                .await
                .is_err()
        );
        assert_eq!(running.stats.snapshot().downlink, 0);
        drop(client);
        drop(socket);
        drop(control);
        running.shutdown().await;
    }
    timeout(WAIT, async {
        while up.stats.snapshot().connections != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let before = up.stats.snapshot().connections;
    let mut value = downstream(outbound(&cert, up.address, "cubic", true, "native"));
    value["route"]["default"] = json!("reject");
    let running = Running::start(value).await;
    let (control, socket) = associate(running.address).await;
    socket
        .send(&packet(target.local_addr().unwrap(), b"reject"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    assert_eq!(up.stats.snapshot().connections, before);
    assert_eq!(running.stats.snapshot().uplink, 0);
    drop(socket);
    drop(control);
    running.shutdown().await;
    up.shutdown().await;
}
