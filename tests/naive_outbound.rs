//! Naive原生H1/H2/H3出站的完整配置/路由回环，不使用官方客户端。
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
const WAIT: Duration = Duration::from_secs(4);
fn upstream(cert: &Certificate) -> Value {
    json!({"version":1,"inbounds":[{"type":"naive","tag":"naive","listen":"127.0.0.1:0","h3":true,"users":[{"name":"test-user","password":"test-password"}],
        "certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],"route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":400,"handshake_timeout_ms":1000,"dial_timeout_ms":1000}})
}
fn proxy(cert: &Certificate, address: SocketAddr, version: &str, udp: bool) -> Value {
    json!({"type":"naive","tag":"up","endpoint":address.to_string(),"username":"test-user","password":"test-password",
        "tls":{"ca_file":cert.dir.path().join("cert.pem"),"server_name":"localhost"},
        "naive":{"http_version":version,"h1_padding":version=="1.1" && udp,"udp_over_tcp":udp,"extra_headers":{"x-test":"extra-value"}}})
}
fn downstream(proxy: Value) -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[proxy,{"type":"reject","tag":"reject"}],
        "route":{"default":"up"},"limits":{"shutdown_timeout_ms":400,"dial_timeout_ms":1200,"handshake_timeout_ms":1200}})
}
async fn associate(address: SocketAddr) -> (TcpStream, UdpSocket) {
    let (control, mut relay) =
        common::socks(3, common::address("0.0.0.0:0".parse().unwrap()), address).await;
    if relay.ip().is_unspecified() {
        relay.set_ip(address.ip());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    (control, socket)
}
fn packet(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend(common::address(target));
    bytes.extend_from_slice(data);
    bytes
}
async fn roundtrip(socket: &UdpSocket, target: SocketAddr, data: &[u8]) {
    socket.send(&packet(target, data)).await.unwrap();
    let mut bytes = vec![0; 65536];
    let count = timeout(WAIT, socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..count], packet(target, data));
}
#[test]
fn strict_configuration_defaults_redaction_header_bounds_and_protocol_combinations() {
    let example = Config::from_json(include_str!("../examples/naive-outbound.json")).unwrap();
    Config::from_json(&serde_json::to_string(&example).unwrap()).unwrap();
    let cert = Certificate::new();
    let address = "127.0.0.1:1234".parse().unwrap();
    for version in ["2", "3"] {
        let value = downstream(proxy(&cert, address, version, true));
        let config = Config::from_json(&value.to_string()).unwrap();
        Config::from_json(&serde_json::to_string(&config).unwrap()).unwrap();
        let debug = format!("{:?}", config.outbounds);
        assert!(!debug.contains("test-password"));
        assert!(!debug.contains("extra-value"));
    }
    for (padding, udp) in [(false, false), (true, false), (true, true)] {
        let mut value = downstream(proxy(&cert, address, "1.1", udp));
        value["outbounds"][0]["naive"]["h1_padding"] = json!(padding);
        let config = Config::from_json(&value.to_string()).unwrap();
        Config::from_json(&serde_json::to_string(&config).unwrap()).unwrap();
        let debug = format!("{:?}", config.outbounds);
        assert!(!debug.contains("test-password"));
        assert!(!debug.contains("extra-value"));
    }
    for version in ["2", "3"] {
        let mut value = downstream(proxy(&cert, address, version, false));
        value["outbounds"][0]["naive"]["h1_padding"] = json!(true);
        assert!(Config::from_json(&value.to_string()).is_err());
    }
    let mut invalid = downstream(proxy(&cert, address, "1.1", true));
    invalid["outbounds"][0]["naive"]["h1_padding"] = json!(false);
    assert!(Config::from_json(&invalid.to_string()).is_err());
    for example in [
        include_str!("../examples/naive-h1-outbound.json"),
        include_str!("../examples/naive-h1-padding-outbound.json"),
    ] {
        let config = Config::from_json(example).unwrap();
        Config::from_json(&serde_json::to_string(&config).unwrap()).unwrap();
    }
    let mut value = downstream(proxy(&cert, address, "2", false));
    value["outbounds"][0]["naive"] = json!({});
    let config = Config::from_json(&value.to_string()).unwrap();
    assert_eq!(
        config.outbounds[0].naive.as_ref().unwrap().http_version,
        dubhe::config::NaiveHttpVersion::H2
    );
    assert!(!config.outbounds[0].naive.as_ref().unwrap().udp_over_tcp);
    for invalid in [json!("1"), json!("auto"), json!(2)] {
        let mut value = value.clone();
        value["outbounds"][0]["naive"]["http_version"] = invalid;
        assert!(Config::from_json(&value.to_string()).is_err());
    }
    for name in [
        ":path",
        "Host",
        "Padding",
        "Proxy-Authorization",
        "Connection",
        "Content-Length",
        "Transfer-Encoding",
        "-force-quic",
    ] {
        let mut value = value.clone();
        value["outbounds"][0]["naive"]["extra_headers"] = json!({name:"bad"});
        assert!(Config::from_json(&value.to_string()).is_err(), "{name}");
    }
    for text in ["injected\r\nx: y", "control\0value", "x\u{7f}y"] {
        let mut value = value.clone();
        value["outbounds"][0]["naive"]["extra_headers"] = json!({"x-test":text});
        assert!(Config::from_json(&value.to_string()).is_err());
    }
    for field in ["tls", "username", "password", "naive"] {
        let mut value = value.clone();
        value["outbounds"][0].as_object_mut().unwrap().remove(field);
        assert!(Config::from_json(&value.to_string()).is_err(), "{field}");
    }
    let mut invalid = value.clone();
    invalid["outbounds"][0]["username"] = json!("bad:name");
    assert!(Config::from_json(&invalid.to_string()).is_err());
    for (field, contents) in [
        ("snell", json!({"psk":"x","version":4})),
        ("udp_over_tcp", json!(true)),
        ("transport", json!({"type":"ws"})),
    ] {
        let mut value = value.clone();
        value["outbounds"][0][field] = contents;
        assert!(Config::from_json(&value.to_string()).is_err());
    }
    let mut invalid = value.clone();
    invalid["outbounds"][0]["naive"]["extra_headers"] = json!({"x-test":"x".repeat(2049)});
    assert!(Config::from_json(&invalid.to_string()).is_err());
    let mut invalid = value.clone();
    invalid["outbounds"][0]["naive"]["extra_headers"] = json!({"x-test":"a","X-Test":"b"});
    assert!(Config::from_json(&invalid.to_string()).is_err());
    let mut invalid = value;
    invalid["outbounds"][0]["type"] = json!("http");
    assert!(Config::from_json(&invalid.to_string()).is_err());
}
#[tokio::test]
async fn all_versions_large_tcp_and_fin_reverse_response() {
    for version in ["1.1", "2", "3"] {
        let cert = Certificate::new();
        let up = Running::start(upstream(&cert)).await;
        let down = Running::start(downstream(proxy(&cert, up.address, version, false))).await;
        let echo = Echo::tcp("127.0.0.1", false).await;
        let (mut stream, _) = common::socks(1, common::address(echo.address), down.address).await;
        for index in 0..10u8 {
            let bytes = vec![index; 24 * 1024];
            stream.write_all(&bytes).await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = vec![0; bytes.len()];
            timeout(WAIT, stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, bytes);
        }
        drop(stream);
        let echo = Echo::tcp("127.0.0.1", true).await;
        let (mut stream, _) = common::socks(1, common::address(echo.address), down.address).await;
        stream.write_all(b"after-write-fin").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"after-write-fin");
        drop(stream);
        down.shutdown().await;
        up.shutdown().await;
    }
}
#[tokio::test]
async fn both_versions_standard_uot_two_targets_empty_ipv6_and_capacity_preserve_sessions() {
    for version in ["2", "3"] {
        let cert = Certificate::new();
        let up = Running::start(upstream(&cert)).await;
        let mut value = downstream(proxy(&cert, up.address, version, true));
        value["limits"]["max_udp_targets"] = json!(2);
        value["limits"]["max_udp_payload"] = json!(4096);
        let down = Running::start(value).await;
        let first = Echo::udp("127.0.0.1").await;
        let second = Echo::udp("127.0.0.1").await;
        let (control, socket) = associate(down.address).await;
        for (target, data) in [
            (first.address, b"first".as_slice()),
            (second.address, b"second"),
            (first.address, b""),
            (second.address, b"again"),
        ] {
            roundtrip(&socket, target, data).await;
        }
        roundtrip(&socket, first.address, &vec![0x55; 4096]).await;
        socket
            .send(&packet(first.address, &vec![0x55; 4097]))
            .await
            .unwrap();
        roundtrip(&socket, second.address, b"still-usable").await;
        let denied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send(&packet(denied.local_addr().unwrap(), b"third"))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), denied.recv(&mut [0; 16]))
                .await
                .is_err()
        );
        drop(control);
        drop(socket);
        if UdpSocket::bind("[::1]:0").await.is_ok() {
            let echo = Echo::udp("[::1]").await;
            let (control, socket) = associate(down.address).await;
            roundtrip(&socket, echo.address, b"ipv6").await;
            drop(socket);
            drop(control);
        }
        down.shutdown().await;
        up.shutdown().await;
    }
}
#[tokio::test]
async fn wrong_identity_ca_and_root_reject_produce_no_target_traffic() {
    for version in ["1.1", "2", "3"] {
        let cert = Certificate::new();
        let other = Certificate::new();
        let up = Running::start(upstream(&cert)).await;
        for wrong_ca in [false, true] {
            let mut out = proxy(&cert, up.address, version, true);
            if wrong_ca {
                out["tls"]["ca_file"] = json!(other.dir.path().join("cert.pem"));
            } else {
                out["password"] = json!("wrong-password");
            }
            let down = Running::start(downstream(out)).await;
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(down.address).await.unwrap();
            client.write_all(&[5, 1, 0]).await.unwrap();
            client.read_exact(&mut [0; 2]).await.unwrap();
            let mut req = vec![5, 1, 0];
            req.extend(common::address(target.local_addr().unwrap()));
            client.write_all(&req).await.unwrap();
            let mut response = [0; 3];
            timeout(WAIT, client.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(response[1], 0);
            assert!(
                timeout(Duration::from_millis(100), target.accept())
                    .await
                    .is_err()
            );
            assert_eq!(down.stats.snapshot().downlink, 0);
            let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (control, socket) = associate(down.address).await;
            socket
                .send(&packet(
                    udp_target.local_addr().unwrap(),
                    b"unauthorized-udp",
                ))
                .await
                .unwrap();
            assert!(
                timeout(Duration::from_millis(150), udp_target.recv(&mut [0; 64]))
                    .await
                    .is_err()
            );
            assert_eq!(down.stats.snapshot().downlink, 0);
            drop(socket);
            drop(control);
            drop(client);
            down.shutdown().await;
        }
        let mut value = downstream(proxy(&cert, up.address, version, true));
        value["route"]["default"] = json!("reject");
        let down = Running::start(value).await;
        let target = Echo::udp("127.0.0.1").await;
        let (control, socket) = associate(down.address).await;
        socket
            .send(&packet(target.address, b"reject"))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), socket.recv(&mut [0; 64]))
                .await
                .is_err()
        );
        assert_eq!(down.stats.snapshot().uplink, 0);
        assert_eq!(up.stats.snapshot().connections, 0);
        drop(socket);
        drop(control);
        down.shutdown().await;
        up.shutdown().await;
    }
}
#[tokio::test]
async fn udp_disabled_is_rejected_without_opening_naive_connection() {
    let cert = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    for version in ["1.1", "2", "3"] {
        let down = Running::start(downstream(proxy(&cert, up.address, version, false))).await;
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (control, socket) = associate(down.address).await;
        socket
            .send(&packet(target.local_addr().unwrap(), b"must-not-reach"))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), target.recv(&mut [0; 64]))
                .await
                .is_err()
        );
        assert_eq!(up.stats.snapshot().connections, 0);
        assert_eq!(down.stats.snapshot().uplink, 0);
        drop(socket);
        drop(control);
        down.shutdown().await;
    }
    up.shutdown().await;
}
#[tokio::test]
async fn h1_h2_chain_either_side_works_and_h3_chain_is_rejected() {
    let cert = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    let socks=Running::start(json!({"version":1,"inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":400}})).await;
    for (version, last) in [("1.1", true), ("1.1", false), ("2", true), ("2", false)] {
        let mut naive = proxy(&cert, up.address, version, false);
        naive["tag"] = json!(if last { "up" } else { "first" });
        let mut hop = json!({"type":"socks5","tag":if last{"first"}else{"up"},"endpoint":socks.address.to_string()});
        if last {
            naive["via"] = json!("first");
        } else {
            hop["via"] = json!("first");
        }
        let mut value = downstream(naive.clone());
        value["outbounds"] = json!([naive.clone(), hop]);
        let down = Running::start(value.clone()).await;
        let echo = Echo::tcp("127.0.0.1", false).await;
        let (mut stream, _) = common::socks(1, common::address(echo.address), down.address).await;
        stream.write_all(b"chain").await.unwrap();
        let mut reply = [0; 5];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"chain");
        drop(stream);
        down.shutdown().await;
        value["outbounds"][0]["naive"]["http_version"] = json!("3");
        assert!(Config::from_json(&value.to_string()).is_err());
    }
    socks.shutdown().await;
    up.shutdown().await;
}
#[tokio::test]
async fn forced_shutdown_releases_tcp_udp_ports_and_blocked_reverse_streams() {
    for version in ["1.1", "2", "3"] {
        let cert = Certificate::new();
        let up = Running::start(upstream(&cert)).await;
        let down = Running::start(downstream(proxy(&cert, up.address, version, false))).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut stream, _) = common::socks(
            1,
            common::address(target.local_addr().unwrap()),
            down.address,
        )
        .await;
        let (mut remote, _) = target.accept().await.unwrap();
        stream.write_all(b"request").await.unwrap();
        remote.read_exact(&mut [0; 7]).await.unwrap();
        // 客户端不再读，服务端持续下行，触发有限窗口与写队列背压。
        let writer = tokio::spawn(async move {
            let bytes = vec![0x77; 1024 * 1024];
            loop {
                if remote.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });
        let local = down.address;
        let upstream = up.address;
        down.shutdown().await;
        up.shutdown().await;
        drop(stream);
        writer.abort();
        let _ = writer.await;
        TcpListener::bind(local).await.unwrap();
        TcpListener::bind(upstream).await.unwrap();
        UdpSocket::bind(upstream).await.unwrap();
    }
}
