//! Snell正式出站：完整Config/runtime回环与独立raw对端，不执行官方客户端。
mod common;

use common::{Echo, Running};
use dubhe::Config;
use serde_json::{Value, json};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

const PSK: &str = "snell-outbound-loopback-psk";
const KEY: &str = "snell-outbound-user-key";
const WAIT: Duration = Duration::from_secs(3);
const MODES: [(u8, Option<&str>); 5] = [
    (4, None),
    (5, None),
    (6, None),
    (6, Some("unshaped")),
    (6, Some("unsafe-raw")),
];

fn options(version: u8, mode: Option<&str>) -> Value {
    let mut value = json!({"psk":PSK,"version":version,"userkey":KEY});
    if let Some(mode) = mode {
        value["mode"] = json!(mode);
    }
    value
}
fn downstream(outbound: Value) -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],
        "outbounds":[outbound,{"type":"reject","tag":"reject"}],"route":{"default":"up"},
        "limits":{"shutdown_timeout_ms":500,"dial_timeout_ms":700,"handshake_timeout_ms":700}})
}
fn outbound(address: SocketAddr, version: u8, mode: Option<&str>) -> Value {
    json!({"type":"snell","tag":"up","endpoint":address.to_string(),"snell":options(version,mode)})
}
async fn upstream(version: u8, mode: Option<&str>, reject: bool) -> Running {
    let mut inbound = json!({"type":"snell","tag":"snell","listen":"127.0.0.1:0","psk":PSK,"version":version,"users":[{"name":"u","userkey":KEY}]});
    if let Some(mode) = mode {
        inbound["mode"] = json!(mode);
    }
    Running::start(json!({"version":1,"inbounds":[inbound],"outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],
        "route":{"default":if reject{"reject"}else{"direct"}},"limits":{"shutdown_timeout_ms":500,"handshake_timeout_ms":700}})).await
}
async fn associate(address: SocketAddr) -> (TcpStream, UdpSocket) {
    let (control, mut bound) =
        common::socks(3, common::address("0.0.0.0:0".parse().unwrap()), address).await;
    if bound.ip().is_unspecified() {
        bound.set_ip(address.ip());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket2::SockRef::from(&socket)
        .set_send_buffer_size(65536)
        .unwrap();
    socket2::SockRef::from(&socket)
        .set_recv_buffer_size(65536)
        .unwrap();
    socket.connect(bound).await.unwrap();
    (control, socket)
}
fn datagram(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0, 0, 0];
    frame.extend(common::address(target));
    frame.extend(payload);
    frame
}
struct LargeEcho {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for LargeEcho {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn large_echo() -> LargeEcho {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket2::SockRef::from(&socket)
        .set_send_buffer_size(65536)
        .unwrap();
    socket2::SockRef::from(&socket)
        .set_recv_buffer_size(65536)
        .unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = vec![0; 65536];
        while let Ok((count, peer)) = socket.recv_from(&mut bytes).await {
            socket.send_to(&bytes[..count], peer).await.unwrap();
        }
    });
    LargeEcho { address, task }
}
async fn roundtrip(socket: &UdpSocket, target: SocketAddr, payload: &[u8]) {
    socket.send(&datagram(target, payload)).await.unwrap();
    let mut buffer = vec![0; 65536];
    let count = timeout(WAIT, socket.recv(&mut buffer))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Snell UDP回包超时，目标={target}，载荷长度={}",
                payload.len()
            )
        })
        .unwrap();
    let expected = datagram(target, payload);
    assert_eq!(&buffer[..count], expected);
}
async fn rejected_connect(address: SocketAddr, target: SocketAddr) {
    // TCP上游按标准可以延迟Reply；根SOCKS成功不等于上游已认证。
    let (mut stream, _) = common::socks(1, common::address(target), address).await;
    let _ = stream.write_all(b"must-not-reach-target").await;
    let mut bytes = [0; 64];
    let result = timeout(WAIT, stream.read(&mut bytes)).await.unwrap();
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "错误应答不能泄露为目标业务"
    );
}

#[test]
fn snell_config_rejects_unimplemented_fields_and_redacts_credentials() {
    for (version, mode) in MODES {
        let value = downstream(outbound("127.0.0.1:12345".parse().unwrap(), version, mode));
        let parsed = Config::from_json(&value.to_string()).unwrap();
        let debug = format!("{:?}", parsed.outbounds);
        assert!(!debug.contains(PSK));
        assert!(!debug.contains(KEY));
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["outbounds"][0]["snell"]["version"],
            version
        );
    }
    let base = downstream(outbound("127.0.0.1:12345".parse().unwrap(), 6, None));
    for (field, value) in [
        ("version", json!(3)),
        ("psk", json!("short")),
        ("userkey", json!("")),
        ("userkey", json!("x".repeat(256))),
        ("mode", json!("shaped")),
        ("obfs_mode", json!("http")),
        ("quic", json!(true)),
        ("reuse", json!("invalid")),
    ] {
        let mut config = base.clone();
        config["outbounds"][0]["snell"][field] = value;
        assert!(Config::from_json(&config.to_string()).is_err(), "{field}");
    }
    for (field, value) in [
        ("password", json!("p")),
        ("username", json!("u")),
        ("tls", json!({"ca_file":"/unused"})),
        ("transport", json!({"type":"ws"})),
        ("method", json!("aes-128-gcm")),
    ] {
        let mut config = base.clone();
        config["outbounds"][0][field] = value;
        assert!(Config::from_json(&config.to_string()).is_err(), "{field}");
    }
    for kind in ["direct", "reject", "socks5", "http", "vless", "anytls"] {
        let mut config = base.clone();
        config["outbounds"][0]["type"] = json!(kind);
        assert!(Config::from_json(&config.to_string()).is_err(), "{kind}");
    }
    let mut config = base;
    config["outbounds"][0]["snell"]["version"] = json!(5);
    config["outbounds"][0]["snell"]["mode"] = json!("default");
    assert!(Config::from_json(&config.to_string()).is_err());
}

#[tokio::test]
async fn snell_tcp_all_versions_modes_and_halfclose() {
    for (version, mode) in MODES {
        let up = upstream(version, mode, false).await;
        let running = Running::start(downstream(outbound(up.address, version, mode))).await;
        let echo = Echo::tcp("127.0.0.1", false).await;
        let (mut stream, _) =
            common::socks(1, common::address(echo.address), running.address).await;
        let payload = vec![0x5c; 80 * 1024];
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = vec![0; payload.len()];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, payload);
        drop(stream);
        let after_fin = Echo::tcp("127.0.0.1", true).await;
        let (mut stream, _) =
            common::socks(1, common::address(after_fin.address), running.address).await;
        stream.write_all(b"respond-after-zero-block").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"respond-after-zero-block");
        drop(stream);
        running.shutdown().await;
        up.shutdown().await;
    }
}

#[tokio::test]
async fn snell_udp_all_versions_targets_empty_dual_stack_and_capacity() {
    for (version, mode) in MODES {
        let up = upstream(version, mode, false).await;
        let running = Running::start(downstream(outbound(up.address, version, mode))).await;
        let first = large_echo().await;
        let second = Echo::udp("127.0.0.1").await;
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
            roundtrip(&socket, echo.address, b"ipv6-inner").await;
        }
        // SOCKS封装也占外层UDP容量，保留足够余量；v6必须实际越过旧v4单记录上限。
        roundtrip(
            &socket,
            first.address,
            &vec![3; if version == 6 { 32000 } else { 16000 }],
        )
        .await;
        drop(socket);
        drop(control);
        running.shutdown().await;
        up.shutdown().await;
    }
}

#[tokio::test]
async fn snell_wrong_psk_userkey_and_upstream_reject_never_direct() {
    for wrong_psk in [true, false] {
        let up = upstream(5, None, false).await;
        let mut proxy = outbound(up.address, 5, None);
        proxy["snell"][if wrong_psk { "psk" } else { "userkey" }] =
            json!("different-valid-length-key");
        let running = Running::start(downstream(proxy)).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        rejected_connect(running.address, target.local_addr().unwrap()).await;
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (control, socket) = associate(running.address).await;
        socket
            .send(&datagram(target.local_addr().unwrap(), b"denied"))
            .await
            .unwrap();
        let mut bytes = [0; 64];
        assert!(
            timeout(Duration::from_millis(850), target.recv(&mut bytes))
                .await
                .is_err()
        );
        assert_eq!(running.stats.snapshot().downlink, 0);
        assert_eq!(up.stats.snapshot().uplink, 0);
        drop(socket);
        drop(control);
        running.shutdown().await;
        up.shutdown().await;
    }
    let up = upstream(6, None, true).await;
    let running = Running::start(downstream(outbound(up.address, 6, None))).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    rejected_connect(running.address, target.local_addr().unwrap()).await;
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    assert_eq!(running.stats.snapshot().downlink, 0);
    running.shutdown().await;
    up.shutdown().await;
}

#[tokio::test]
async fn snell_route_reject_is_zero_upstream_and_udp_limits_preserve_old_target() {
    let fake = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut value = downstream(outbound(fake.local_addr().unwrap(), 5, None));
    value["route"]["default"] = json!("reject");
    let running = Running::start(value).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(stream.read_u16().await.unwrap(), 0x0500);
    let mut request = vec![5, 1, 0];
    request.extend(common::address(target.local_addr().unwrap()));
    stream.write_all(&request).await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), 5);
    assert_ne!(stream.read_u8().await.unwrap(), 0);
    let (control, socket) = associate(running.address).await;
    socket
        .send(&datagram(target.local_addr().unwrap(), b"reject"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), fake.accept())
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    assert_eq!(running.stats.snapshot().uplink, 0);
    drop(stream);
    drop(socket);
    drop(control);
    running.shutdown().await;

    let up = upstream(5, None, false).await;
    let mut value = downstream(outbound(up.address, 5, None));
    value["limits"]["max_udp_targets"] = json!(1);
    let running = Running::start(value).await;
    let echo = Echo::udp("127.0.0.1").await;
    let forbidden = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (control, socket) = associate(running.address).await;
    roundtrip(&socket, echo.address, b"before").await;
    socket
        .send(&datagram(forbidden.local_addr().unwrap(), b"too-many"))
        .await
        .unwrap();
    let mut bytes = [0; 64];
    assert!(
        timeout(Duration::from_millis(100), forbidden.recv(&mut bytes))
            .await
            .is_err()
    );
    socket
        .send(&datagram(echo.address, &vec![0; 17000]))
        .await
        .unwrap();
    roundtrip(&socket, echo.address, b"after").await;
    drop(socket);
    drop(control);
    running.shutdown().await;
    up.shutdown().await;
}

#[tokio::test]
async fn snell_tcp_chains_on_either_side_of_socks5() {
    let up = upstream(5, None, false).await;
    let socks=Running::start(json!({"version":1,"inbounds":[{"type":"socks5","tag":"hop","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":500}})).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    for snell_last in [true, false] {
        let mut snell = outbound(up.address, 5, None);
        snell["tag"] = json!(if snell_last { "up" } else { "first" });
        let mut other = json!({"type":"socks5","tag":if snell_last{"first"}else{"up"},"endpoint":socks.address.to_string()});
        if snell_last {
            snell["via"] = json!("first");
        } else {
            other["via"] = json!("first");
        }
        let mut config = downstream(snell.clone());
        config["outbounds"] = json!([snell, other]);
        let running = Running::start(config).await;
        let (mut stream, _) =
            common::socks(1, common::address(echo.address), running.address).await;
        stream.write_all(b"two-hop").await.unwrap();
        let mut bytes = [0; 7];
        timeout(WAIT, stream.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"two-hop");
        drop(stream);
        running.shutdown().await;
    }
    socks.shutdown().await;
    up.shutdown().await;
}

#[tokio::test]
async fn snell_corrupt_aead_reply_never_becomes_business_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut salt_and_header = [0; 16 + 23];
        stream.read_exact(&mut salt_and_header).await.unwrap();
        // 有效长度的随机salt与损坏tag；服务端身份校验必须失败，不能当裸业务。
        stream.write_all(&[0x23; 16 + 23]).await.unwrap();
    });
    let running = Running::start(downstream(outbound(address, 5, None))).await;
    let (mut stream, _) = common::socks(
        1,
        common::address("127.0.0.1:9".parse().unwrap()),
        running.address,
    )
    .await;
    let mut data = [0; 64];
    assert!(matches!(
        timeout(WAIT, stream.read(&mut data)).await.unwrap(),
        Ok(0) | Err(_)
    ));
    assert_eq!(running.stats.snapshot().downlink, 0);
    peer.await.unwrap();
    drop(stream);
    running.shutdown().await;
}

async fn raw_read(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 7];
    stream.read_exact(&mut header).await?;
    assert_eq!(&header[..5], &[4, 0, 0, 0, 0]);
    let mut payload = vec![0; usize::from(u16::from_be_bytes([header[5], header[6]]))];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}
async fn raw_write(stream: &mut TcpStream, payload: &[u8]) {
    let mut bytes = vec![4, 0, 0, 0, 0];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    for chunk in bytes.chunks(2) {
        stream.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn snell_delayed_first_reply_and_error_are_checked_with_independent_raw_peer() {
    for bad in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = raw_read(&mut stream).await.unwrap();
            assert_eq!(&request[..3], &[1, 5, KEY.len() as u8]);
            assert_eq!(&request[3..3 + KEY.len()], KEY.as_bytes());
            let payload = raw_read(&mut stream).await.unwrap();
            assert_eq!(payload, b"request-before-reply");
            raw_write(
                &mut stream,
                if bad {
                    &[2, 1, 3, b'b', b'a', b'd']
                } else {
                    b"\0first-reply-data"
                },
            )
            .await;
            if !bad {
                assert!(raw_read(&mut stream).await.unwrap().is_empty());
                raw_write(&mut stream, &[]).await;
            }
        });
        let running = Running::start(downstream(outbound(address, 6, Some("unsafe-raw")))).await;
        let (mut stream, _) = common::socks(
            1,
            common::address("127.0.0.1:12345".parse().unwrap()),
            running.address,
        )
        .await;
        stream.write_all(b"request-before-reply").await.unwrap();
        if bad {
            let mut data = [0; 64];
            assert!(matches!(
                timeout(WAIT, stream.read(&mut data)).await.unwrap(),
                Ok(0) | Err(_)
            ));
            assert_eq!(running.stats.snapshot().downlink, 0);
        } else {
            let mut data = [0; b"first-reply-data".len()];
            timeout(WAIT, stream.read_exact(&mut data))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&data, b"first-reply-data");
            stream.shutdown().await.unwrap();
            let mut rest = Vec::new();
            timeout(WAIT, stream.read_to_end(&mut rest))
                .await
                .unwrap()
                .unwrap();
            assert!(rest.is_empty());
        }
        timeout(WAIT, peer).await.unwrap().unwrap();
        drop(stream);
        running.shutdown().await;
    }
}

#[tokio::test]
async fn snell_shutdown_cancels_partial_udp_reply_and_releases_ports() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (connected, accepted) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = raw_read(&mut stream).await.unwrap();
        stream.write_all(&[4, 0, 0]).await.unwrap();
        let _ = connected.send(());
        let mut bytes = [0; 1];
        let _ = stream.read(&mut bytes).await;
    });
    let running = Running::start(downstream(outbound(address, 6, Some("unsafe-raw")))).await;
    let port = running.address;
    let (control, socket) = associate(port).await;
    socket
        .send(&datagram("127.0.0.1:12345".parse().unwrap(), b"pending"))
        .await
        .unwrap();
    timeout(WAIT, accepted).await.unwrap().unwrap();
    running.shutdown().await;
    drop(socket);
    drop(control);
    timeout(WAIT, peer).await.unwrap().unwrap();
    TcpListener::bind(port).await.unwrap();
}
