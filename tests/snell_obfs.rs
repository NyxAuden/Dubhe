//! Snell v4/v5正式HTTP/TLS obfs的Config/runtime双角色回环，不使用官方客户端。
mod common;
use common::{Echo, Running};
use dubhe::Config;
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
const PSK: &str = "snell-obfs-loopback-psk";
const KEY: &str = "snell-obfs-loopback-user";
const WAIT: Duration = Duration::from_secs(3);
fn configuration(version: u8, obfs: &str) -> Value {
    json!({"version":1,"inbounds":[{"type":"snell","tag":"snell","listen":"127.0.0.1:0","psk":PSK,"version":version,"users":[{"name":"u","userkey":KEY}],"obfs_mode":obfs}],
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],"route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":500,"handshake_timeout_ms":800,"dial_timeout_ms":800}})
}
fn proxy(address: SocketAddr, version: u8, obfs: &str) -> Value {
    let mut options = json!({"psk":PSK,"version":version,"userkey":KEY,"obfs_mode":obfs,"obfs_host":"front.example"});
    if obfs == "http" {
        options["obfs_uri"] = json!("/proxy/resource");
    }
    json!({"type":"snell","tag":"up","endpoint":address.to_string(),"snell":options})
}
fn downstream(proxy: Value) -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[proxy,{"type":"reject","tag":"reject"}],"route":{"default":"up"},
        "limits":{"shutdown_timeout_ms":500,"handshake_timeout_ms":800,"dial_timeout_ms":800}})
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
fn packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend(common::address(target));
    bytes.extend(payload);
    bytes
}
async fn udp_roundtrip(socket: &UdpSocket, target: SocketAddr, payload: &[u8]) {
    socket.send(&packet(target, payload)).await.unwrap();
    let mut bytes = vec![0; 65536];
    let count = timeout(WAIT, socket.recv(&mut bytes))
        .await
        .expect("Snell obfs UDP回包超时")
        .unwrap();
    assert_eq!(&bytes[..count], packet(target, payload));
}
#[test]
fn configurations_reject_v6_obfs_and_header_injection() {
    let address = "127.0.0.1:12345".parse().unwrap();
    for example in [
        include_str!("../examples/snell-obfs.json"),
        include_str!("../examples/snell-obfs-outbound.json"),
    ] {
        let config = Config::from_json(example).unwrap();
        Config::from_json(&serde_json::to_string(&config).unwrap()).unwrap();
    }
    for version in [4, 5] {
        for mode in ["none", "http", "tls"] {
            Config::from_json(&configuration(version, mode).to_string()).unwrap();
        }
    }
    for (field, limit) in [("obfs_host", 253), ("obfs_uri", 1024)] {
        let mut value = downstream(proxy(address, 5, "http"));
        value["outbounds"][0]["snell"][field] = json!(if field == "obfs_uri" {
            format!("/{}", "x".repeat(limit - 1))
        } else {
            "x".repeat(limit)
        });
        Config::from_json(&value.to_string()).unwrap();
        let text = value["outbounds"][0]["snell"][field]
            .as_str()
            .unwrap()
            .to_owned();
        value["outbounds"][0]["snell"][field] = json!(text + "x");
        assert!(Config::from_json(&value.to_string()).is_err());
    }
    for mode in ["http", "tls"] {
        assert!(Config::from_json(&configuration(6, mode).to_string()).is_err());
        let mut value = downstream(proxy(address, 6, mode));
        value["outbounds"][0]["snell"]["psk"] = json!(PSK);
        assert!(Config::from_json(&value.to_string()).is_err());
    }
    for (mode, field, text) in [
        ("none", "obfs_host", "front.example"),
        ("none", "obfs_uri", "/"),
        ("tls", "obfs_uri", "/wrong"),
        ("http", "obfs_host", "host\r\nInjected: yes"),
        ("tls", "obfs_host", "host with space"),
        ("http", "obfs_uri", "/path\r\nInjected:yes"),
        ("http", "obfs_uri", "relative"),
    ] {
        let mut value = downstream(proxy(address, 4, mode));
        value["outbounds"][0]["snell"][field] = json!(text);
        assert!(
            Config::from_json(&value.to_string()).is_err(),
            "{mode}/{field}"
        );
    }
    for version in [4, 5] {
        for mode in ["http", "tls"] {
            let value = downstream(proxy(address, version, mode));
            let config = Config::from_json(&value.to_string()).unwrap();
            let debug = format!("{:?}", config.outbounds);
            assert!(!debug.contains(PSK));
            assert!(!debug.contains(KEY));
        }
    }
}
#[tokio::test]
async fn both_versions_and_obfs_relay_tcp_large_payload_and_zero_block_fin() {
    for version in [4, 5] {
        for mode in ["http", "tls"] {
            let up = Running::start(configuration(version, mode)).await;
            let running = Running::start(downstream(proxy(up.address, version, mode))).await;
            let echo = Echo::tcp("127.0.0.1", false).await;
            let (mut stream, _) =
                common::socks(1, common::address(echo.address), running.address).await;
            let bytes = vec![0x36; 96 * 1024];
            stream.write_all(&bytes).await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = vec![0; bytes.len()];
            timeout(WAIT, stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, bytes);
            drop(stream);
            let echo = Echo::tcp("127.0.0.1", true).await;
            let (mut stream, _) =
                common::socks(1, common::address(echo.address), running.address).await;
            stream.write_all(b"after-fin-response").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            timeout(WAIT, stream.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, b"after-fin-response");
            drop(stream);
            running.shutdown().await;
            up.shutdown().await;
        }
    }
}
#[tokio::test]
async fn both_obfs_relay_udp_targets_empty_and_ipv6() {
    for version in [4, 5] {
        for mode in ["http", "tls"] {
            let up = Running::start(configuration(version, mode)).await;
            let running = Running::start(downstream(proxy(up.address, version, mode))).await;
            let first = Echo::udp("127.0.0.1").await;
            let second = Echo::udp("127.0.0.1").await;
            let (control, socket) = associate(running.address).await;
            for (target, payload) in [
                (first.address, b"first".as_slice()),
                (second.address, b"second"),
                (first.address, b""),
                (second.address, b"again"),
            ] {
                udp_roundtrip(&socket, target, payload).await;
            }
            if UdpSocket::bind("[::1]:0").await.is_ok() {
                let echo = Echo::udp("[::1]").await;
                udp_roundtrip(&socket, echo.address, b"ipv6").await;
            }
            drop(socket);
            drop(control);
            running.shutdown().await;
            up.shutdown().await;
        }
    }
}
#[tokio::test]
async fn obfs_never_skips_identity_or_route_reject() {
    for mode in ["http", "tls"] {
        let up = Running::start(configuration(5, mode)).await;
        let mut wrong = proxy(up.address, 5, mode);
        wrong["snell"]["userkey"] = json!("incorrect-user-key");
        let running = Running::start(downstream(wrong)).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut stream, _) = common::socks(
            1,
            common::address(target.local_addr().unwrap()),
            running.address,
        )
        .await;
        let _ = stream.write_all(b"unauthorized").await;
        let mut bytes = [0; 32];
        assert!(matches!(
            timeout(WAIT, stream.read(&mut bytes)).await.unwrap(),
            Ok(0) | Err(_)
        ));
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (control, socket) = associate(running.address).await;
        socket
            .send(&packet(udp.local_addr().unwrap(), b"denied"))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(150), udp.recv(&mut bytes))
                .await
                .is_err()
        );
        assert_eq!(up.stats.snapshot().uplink, 0);
        assert_eq!(running.stats.snapshot().downlink, 0);
        drop(stream);
        drop(socket);
        drop(control);
        running.shutdown().await;
        let mut value = downstream(proxy(up.address, 5, mode));
        value["route"]["default"] = json!("reject");
        let running = Running::start(value).await;
        let (control, socket) = associate(running.address).await;
        socket
            .send(&packet(udp.local_addr().unwrap(), b"blocked"))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), udp.recv(&mut bytes))
                .await
                .is_err()
        );
        assert_eq!(running.stats.snapshot().uplink, 0);
        drop(socket);
        drop(control);
        running.shutdown().await;
        up.shutdown().await;
    }
}
#[tokio::test]
async fn obfs_tcp_works_on_either_side_of_socks5_chain() {
    let socks=Running::start(json!({"version":1,"inbounds":[{"type":"socks5","tag":"hop","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":500}})).await;
    for mode in ["http", "tls"] {
        let up = Running::start(configuration(5, mode)).await;
        let echo = Echo::tcp("127.0.0.1", false).await;
        for last in [true, false] {
            let mut snell = proxy(up.address, 5, mode);
            snell["tag"] = json!(if last { "up" } else { "first" });
            let mut hop = json!({"type":"socks5","tag":if last{"first"}else{"up"},"endpoint":socks.address.to_string()});
            if last {
                snell["via"] = json!("first");
            } else {
                hop["via"] = json!("first");
            }
            let mut value = downstream(snell.clone());
            value["outbounds"] = json!([snell, hop]);
            let running = Running::start(value).await;
            let (mut stream, _) =
                common::socks(1, common::address(echo.address), running.address).await;
            stream.write_all(b"chain").await.unwrap();
            let mut bytes = [0; 5];
            timeout(WAIT, stream.read_exact(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes, b"chain");
            drop(stream);
            running.shutdown().await;
        }
        up.shutdown().await;
    }
    socks.shutdown().await;
}
#[tokio::test]
async fn partial_obfs_head_is_cancelled_on_shutdown_and_port_is_reusable() {
    for mode in ["http", "tls"] {
        let running = Running::start(configuration(5, mode)).await;
        let address = running.address;
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(if mode == "http" {
                b"GET / HTTP/1.1\r\n"
            } else {
                &[0x16, 3, 1]
            })
            .await
            .unwrap();
        running.shutdown().await;
        drop(stream);
        TcpListener::bind(address).await.unwrap();
    }
}
