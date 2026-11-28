mod common;
#[path = "common/reality.rs"]
mod reality_peer;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Running, socks_config, test_binary};
use dubhe::{Config, Server};
use reality_peer::{ClientOptions, PreparedClient, TargetBehavior, TargetOptions, TargetPeer};
use serde_json::{Value, json};
use std::{io, net::SocketAddr, process::Stdio, sync::atomic::Ordering, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(4);

fn udp_frame(id: u16, address: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([1, 1, 2]);
    metadata.extend(address.port().to_be_bytes());
    match address.ip() {
        std::net::IpAddr::V4(ip) => {
            metadata.push(1);
            metadata.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            metadata.push(3);
            metadata.extend(ip.octets());
        }
    }
    let mut frame = (metadata.len() as u16).to_be_bytes().to_vec();
    frame.extend(metadata);
    frame.extend((payload.len() as u16).to_be_bytes());
    frame.extend(payload);
    frame
}
async fn udp_roundtrip_capture(
    client: &mut reality_peer::Outer,
    socket: &UdpSocket,
    command: u8,
    vision: bool,
    payload: &[u8],
) -> SocketAddr {
    let address = socket.local_addr().unwrap();
    let mut request = reality_peer::vless_request(
        command,
        vision.then_some("xtls-rprx-vision"),
        reality_peer::ID,
        address,
    );
    let body = if command == 2 {
        [
            (payload.len() as u16).to_be_bytes().to_vec(),
            payload.to_vec(),
        ]
        .concat()
    } else {
        udp_frame(7, address, payload)
    };
    request.extend(if vision {
        reality_peer::vision_block(true, 1, &body, 7)
    } else {
        body
    });
    client.send(&request).await.unwrap();
    assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
    let mut bytes = [0; 2048];
    let (n, mapping) = timeout(WAIT, socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], payload);
    socket.send_to(payload, mapping).await.unwrap();
    if vision {
        assert_eq!(client.plain(16).await.unwrap(), reality_peer::ID);
        let header = client.plain(5).await.unwrap();
        assert_eq!(header[0], 1);
        let length = u16::from_be_bytes([header[1], header[2]]) as usize;
        let pad = u16::from_be_bytes([header[3], header[4]]) as usize;
        let data = client.plain(length).await.unwrap();
        client.plain(pad).await.unwrap();
        assert!(data.ends_with(payload));
    } else if command == 2 {
        assert_eq!(
            client.plain(2).await.unwrap(),
            (payload.len() as u16).to_be_bytes()
        );
        assert_eq!(client.plain(payload.len()).await.unwrap(), payload);
    } else {
        let length = client.plain(2).await.unwrap();
        client
            .plain(u16::from_be_bytes([length[0], length[1]]) as usize)
            .await
            .unwrap();
        assert_eq!(
            client.plain(2).await.unwrap(),
            (payload.len() as u16).to_be_bytes()
        );
        assert_eq!(client.plain(payload.len()).await.unwrap(), payload);
    }
    mapping
}

#[tokio::test]
async fn force_joins_live_vision_tcp_native_udp_xudp_and_old_socks_together() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let mut configuration = config(target.address);
    configuration["limits"]["handshake_timeout_ms"] = json!(3000);
    configuration["limits"]["udp_idle_timeout_ms"] = json!(30000);
    configuration["limits"]["max_udp_associations"] = json!(4);
    let mut vision = inbound(target.address, "vision");
    vision["users"][0]["flow"] = json!("xtls-rprx-vision");
    configuration["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(vision);
    configuration["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"socks5","tag":"old","listen":"127.0.0.1:0"}));
    let server = Running::start(configuration).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = common::Echo::tcp("127.0.0.1", false).await;
    let mut native = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    let native_mapping = udp_roundtrip_capture(&mut native, &udp, 2, false, b"native").await;
    let mut xudp = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    let xudp_mapping = udp_roundtrip_capture(&mut xudp, &udp, 3, false, b"xudp").await;
    let mut vision_udp = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.addresses[1])
        .await
        .unwrap();
    let vision_mapping = udp_roundtrip_capture(&mut vision_udp, &udp, 3, true, b"vision-udp").await;
    let mut vision_tcp = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.addresses[1])
        .await
        .unwrap();
    let mut request =
        reality_peer::vless_request(1, Some("xtls-rprx-vision"), reality_peer::ID, tcp.address);
    request.extend(reality_peer::vision_block(true, 1, b"vision-tcp", 3));
    vision_tcp.send(&request).await.unwrap();
    assert_eq!(vision_tcp.plain(2).await.unwrap(), [0, 0]);
    assert_eq!(vision_tcp.plain(16).await.unwrap(), reality_peer::ID);
    let header = vision_tcp.plain(5).await.unwrap();
    assert_eq!(header[0], 1);
    let n = u16::from_be_bytes([header[1], header[2]]) as usize;
    let pad = u16::from_be_bytes([header[3], header[4]]) as usize;
    assert_eq!(vision_tcp.plain(n).await.unwrap(), b"vision-tcp");
    vision_tcp.plain(pad).await.unwrap();
    let (mut old, relay) = common::socks(
        3,
        common::address("0.0.0.0:0".parse().unwrap()),
        server.addresses[2],
    )
    .await;
    let datagrams = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let frame = [
        vec![0, 0, 0],
        common::address(udp.local_addr().unwrap()),
        b"old".to_vec(),
    ]
    .concat();
    datagrams.send_to(&frame, relay).await.unwrap();
    let mut bytes = [0; 1024];
    let (n, old_mapping) = timeout(WAIT, udp.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], b"old");
    udp.send_to(b"old", old_mapping).await.unwrap();
    timeout(WAIT, datagrams.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    until(|| {
        let s = server.stats.snapshot();
        s.udp_associations == 4 && s.tcp_flows == 1 && s.connections == 5
    })
    .await;
    let addresses = server.addresses.clone();
    let stats = server.stats.clone();
    let start = Instant::now();
    server.shutdown().await;
    assert!(start.elapsed() >= Duration::from_millis(80));
    for mapping in [
        native_mapping,
        xudp_mapping,
        vision_mapping,
        old_mapping,
        relay,
    ] {
        drop(
            UdpSocket::bind(mapping)
                .await
                .expect("stop/join返回后UDP映射或监听仍占用"),
        );
    }
    for stream in [
        &mut native.io,
        &mut xudp.io,
        &mut vision_udp.io,
        &mut vision_tcp.io,
        &mut old,
    ] {
        closed(stream).await;
    }
    rebind(&addresses).await;
    let s = stats.snapshot();
    assert_eq!((s.connections, s.tcp_flows, s.udp_associations), (0, 0, 0));
    assert_eq!((s.uplink, s.downlink), (33, 33));
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn active_native_xudp_vision_and_old_udp_share_limit_and_force_join_mapping_ports() {
    for (command, vision) in [(2, false), (3, false), (3, true)] {
        let target = TargetPeer::start(Default::default()).await.unwrap();
        let mut configuration = config(target.address);
        configuration["limits"]["handshake_timeout_ms"] = json!(3000);
        configuration["limits"]["udp_idle_timeout_ms"] = json!(30000);
        configuration["limits"]["max_udp_associations"] = json!(1);
        configuration["limits"]["max_udp_targets"] = json!(1);
        configuration["inbounds"][0]["users"][0]["flow"] =
            json!(if vision { "xtls-rprx-vision" } else { "" });
        configuration["inbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"socks5","tag":"old","listen":"127.0.0.1:0"}));
        let server = Running::start(configuration).await;
        let business = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = PreparedClient::new(Default::default())
            .unwrap()
            .connect(server.address)
            .await
            .unwrap();
        let mapping =
            udp_roundtrip_capture(&mut client, &business, command, vision, b"resource-payload")
                .await;
        until(|| server.stats.snapshot().udp_associations == 1).await;
        let mut denied = TcpStream::connect(server.addresses[1]).await.unwrap();
        denied.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        denied.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        denied
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0; 3];
        denied.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 1, 0]);
        common::read_address(&mut denied).await;
        closed(&mut denied).await;
        drop(client);
        until(|| server.stats.snapshot().udp_associations == 0).await;
        drop(
            UdpSocket::bind(mapping)
                .await
                .expect("关闭REALITY承载后映射未归还"),
        );
        let (mut old, relay) = common::socks(
            3,
            common::address("0.0.0.0:0".parse().unwrap()),
            server.addresses[1],
        )
        .await;
        let datagrams = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = b"old";
        let frame = [
            vec![0, 0, 0],
            common::address(business.local_addr().unwrap()),
            payload.to_vec(),
        ]
        .concat();
        datagrams.send_to(&frame, relay).await.unwrap();
        let mut buffer = [0; 2048];
        let (n, old_mapping) = timeout(WAIT, business.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], payload);
        business.send_to(payload, old_mapping).await.unwrap();
        timeout(WAIT, datagrams.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        // 旧入口占用同一UDP名额时，新REALITY原生UDP无成功响应，XUDP仅返回受限结束帧。
        let mut denied = PreparedClient::new(Default::default())
            .unwrap()
            .connect(server.address)
            .await
            .unwrap();
        let request =
            reality_peer::vless_request(2, None, reality_peer::ID, business.local_addr().unwrap());
        denied.send(&request).await.unwrap();
        assert!(denied.plain(2).await.is_err());
        drop(denied);
        let addresses = server.addresses.clone();
        let stats = server.stats.clone();
        server.shutdown().await;
        closed(&mut old).await;
        drop(
            UdpSocket::bind(old_mapping)
                .await
                .expect("强停后旧映射未归还"),
        );
        drop(UdpSocket::bind(relay).await.expect("旧UDP监听未归还"));
        rebind(&addresses).await;
        assert_eq!(
            (
                stats.snapshot().connections,
                stats.snapshot().udp_associations
            ),
            (0, 0)
        );
        target.shutdown().await.unwrap();
    }
}

fn inbound(target: SocketAddr, tag: &str) -> Value {
    json!({"type":"vless-reality","tag":tag,"listen":"127.0.0.1:0",
        "users":[{"name":"alice","uuid":reality_peer::UUID}],"xudp":true,
        "reality":{"target":{"host":target.ip().to_string(),"port":target.port()},
            "private_key":URL_SAFE_NO_PAD.encode(reality_peer::SERVER_PRIVATE_KEY),
            "server_names":["localhost"],"short_ids":["8172635445362718"],
            "max_time_diff_ms":120000,"fallback_idle_timeout_ms":100,
            "fallback_max_duration_ms":300}})
}
fn config(target: SocketAddr) -> Value {
    let mut config = socks_config();
    config["inbounds"] = json!([inbound(target, "reality")]);
    config["limits"]["handshake_timeout_ms"] = json!(300);
    config
}
async fn until(mut predicate: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !predicate() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("状态未在期限内收敛");
}
async fn closed(io: &mut TcpStream) {
    let mut byte = [0; 1];
    match timeout(WAIT, io.read(&mut byte))
        .await
        .expect("连接未在期限内关闭")
    {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ) => {}
        other => panic!("预期关闭却得到 {other:?}"),
    }
}
fn zero_business(server: &Running) {
    let s = server.stats.snapshot();
    assert_eq!(
        (s.tcp_flows, s.udp_associations, s.uplink, s.downlink),
        (0, 0, 0, 0)
    );
}
async fn rebind(addresses: &[SocketAddr]) {
    let mut listeners = Vec::new();
    for address in addresses {
        listeners.push(TcpListener::bind(address).await.expect("监听端口未归还"));
    }
}
async fn raw_send(address: SocketAddr, wire: &[u8]) -> TcpStream {
    let mut io = TcpStream::connect(address).await.unwrap();
    io.write_all(wire).await.unwrap();
    io
}
fn wire(raw: &[u8]) -> Vec<u8> {
    [
        vec![22, 3, 3],
        (raw.len() as u16).to_be_bytes().to_vec(),
        raw.to_vec(),
    ]
    .concat()
}
fn append_extension(raw: &[u8], kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut raw = raw.to_vec();
    let sid = usize::from(raw[38]);
    let mut pos = 39 + sid;
    let suites = usize::from(u16::from_be_bytes([raw[pos], raw[pos + 1]]));
    pos += 2 + suites;
    let compression = usize::from(raw[pos]);
    pos += 1 + compression;
    let old = usize::from(u16::from_be_bytes([raw[pos], raw[pos + 1]]));
    raw.extend(kind.to_be_bytes());
    raw.extend((payload.len() as u16).to_be_bytes());
    raw.extend(payload);
    raw[pos..pos + 2].copy_from_slice(&((old + 4 + payload.len()) as u16).to_be_bytes());
    let length = raw.len() - 4;
    raw[1..4].copy_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
    raw
}

#[tokio::test]
async fn malformed_psk_early_data_and_oversized_records_never_dial_target() {
    let target = TargetPeer::start(TargetOptions::default()).await.unwrap();
    let server = Running::start(config(target.address)).await;
    let prepared = PreparedClient::new(ClientOptions::default()).unwrap();
    let cases = [
        vec![22, 3, 3, 0x48, 1],
        vec![22, 3, 3, 0, 4, 1, 1, 0, 0],
        vec![23, 3, 3, 0, 0],
        wire(&append_extension(&prepared.raw_ch, 41, &[])),
        wire(&append_extension(&prepared.raw_ch, 42, &[])),
        wire(&append_extension(&prepared.raw_ch, 43, &[2, 3, 4])),
    ];
    for bytes in cases {
        let mut io = raw_send(server.address, &bytes).await;
        closed(&mut io).await;
    }
    until(|| server.stats.snapshot().connections == 0).await;
    assert_eq!(target.observation.accepted.load(Ordering::SeqCst), 0);
    zero_business(&server);
    let addresses = server.addresses.clone();
    server.shutdown().await;
    rebind(&addresses).await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn wrong_auth_policy_only_reaches_fixed_target_with_exact_original_prefix() {
    let marker = b"fixed-target-only";
    let target = TargetPeer::start(TargetOptions {
        behavior: TargetBehavior::Raw(marker.to_vec()),
        ..Default::default()
    })
    .await
    .unwrap();
    let server = Running::start(config(target.address)).await;
    let options = [
        ClientOptions {
            short_id: [0; 8],
            ..Default::default()
        },
        ClientOptions {
            server_name: "untrusted-sni.test".into(),
            ..Default::default()
        },
        ClientOptions {
            unix_seconds: 0,
            ..Default::default()
        },
        ClientOptions {
            reserved: 1,
            ..Default::default()
        },
        ClientOptions {
            server_public_key: reality_peer::public_key(&[0x67; 32]),
            ..Default::default()
        },
    ];
    for (index, options) in options.into_iter().enumerate() {
        let p = PreparedClient::new(options).unwrap();
        let original = p.initial_wire.clone();
        let mut client = raw_send(server.address, &original).await;
        let mut response = vec![0; marker.len()];
        timeout(WAIT, client.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, marker);
        client.write_all(b"fallback-payload").await.unwrap();
        let mut echo = [0; 16];
        timeout(WAIT, client.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echo, b"fallback-payload");
        client.shutdown().await.unwrap();
        closed(&mut client).await;
        until(|| target.observation.connections.lock().unwrap().len() > index).await;
        let got = target.observation.connections.lock().unwrap()[index]
            .received_wire
            .clone();
        assert_eq!(got, [original, b"fallback-payload".to_vec()].concat());
    }
    until(|| server.stats.snapshot().connections == 0).await;
    assert_eq!(target.observation.accepted.load(Ordering::SeqCst), 5);
    zero_business(&server);
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn replay_survives_failed_handshake_across_equivalent_private_keys_and_max_window() {
    let target = TargetPeer::start(TargetOptions {
        behavior: TargetBehavior::Silent,
        ..Default::default()
    })
    .await
    .unwrap();
    let mut configuration = config(target.address);
    let mut first = inbound(target.address, "short");
    let mut second = inbound(target.address, "long");
    first["reality"]["max_time_diff_ms"] = json!(1000);
    second["reality"]["max_time_diff_ms"] = json!(600000);
    let mut equivalent = reality_peer::SERVER_PRIVATE_KEY;
    equivalent[0] ^= 7;
    equivalent[31] ^= 0x80;
    second["reality"]["private_key"] = json!(URL_SAFE_NO_PAD.encode(equivalent));
    configuration["inbounds"] = json!([first, second]);
    let server = Running::start(configuration).await;
    let p = PreparedClient::new(ClientOptions::default()).unwrap();
    let original = p.initial_wire.clone();
    let first = raw_send(server.addresses[0], &original).await;
    until(|| target.observation.accepted.load(Ordering::SeqCst) == 1).await;
    drop(first);
    until(|| server.stats.snapshot().connections == 0).await;
    // 如果错误使用短入口的 TTL(3000ms)，此时原 CH 在长窗口入口将被再次接纳。
    sleep(Duration::from_millis(3100)).await;
    let mut duplicate = raw_send(server.addresses[1], &original).await;
    closed(&mut duplicate).await;
    assert_eq!(target.observation.accepted.load(Ordering::SeqCst), 1);
    zero_business(&server);
    let addresses = server.addresses.clone();
    server.shutdown().await;
    rebind(&addresses).await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn replay_capacity_full_never_falls_back_or_evicts_committed_key() {
    let target = TargetPeer::start(TargetOptions {
        behavior: TargetBehavior::Silent,
        ..Default::default()
    })
    .await
    .unwrap();
    let mut configuration = config(target.address);
    configuration["limits"]["max_reality_replay_entries"] = json!(1);
    let server = Running::start(configuration).await;
    let p = PreparedClient::new(ClientOptions::default()).unwrap();
    let original = p.initial_wire.clone();
    let first = raw_send(server.address, &original).await;
    until(|| target.observation.accepted.load(Ordering::SeqCst) == 1).await;
    drop(first);
    until(|| server.stats.snapshot().connections == 0).await;
    let unique = PreparedClient::new(ClientOptions::default()).unwrap();
    for bytes in [&unique.initial_wire, &original] {
        let mut client = raw_send(server.address, bytes).await;
        closed(&mut client).await;
    }
    until(|| server.stats.snapshot().connections == 0).await;
    assert_eq!(target.observation.accepted.load(Ordering::SeqCst), 1);
    zero_business(&server);
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn idle_and_total_fallback_deadlines_close_without_business_counting() {
    let target = TargetPeer::start(TargetOptions {
        behavior: TargetBehavior::Raw(vec![0x42]),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut configuration = config(target.address);
    configuration["inbounds"][0]["reality"]["fallback_idle_timeout_ms"] = json!(120);
    configuration["inbounds"][0]["reality"]["fallback_max_duration_ms"] = json!(350);
    let server = Running::start(configuration).await;
    let wrong = || {
        PreparedClient::new(ClientOptions {
            short_id: [0; 8],
            ..Default::default()
        })
        .unwrap()
    };
    let mut idle = wrong().begin(server.address).await.unwrap();
    let mut marker = [0; 1];
    idle.io.read_exact(&mut marker).await.unwrap();
    let start = Instant::now();
    closed(&mut idle.io).await;
    assert!(start.elapsed() < Duration::from_secs(2));
    let mut busy = wrong().begin(server.address).await.unwrap();
    busy.io.read_exact(&mut marker).await.unwrap();
    let start = Instant::now();
    let mut echoed = 0;
    loop {
        sleep(Duration::from_millis(25)).await;
        if busy.io.write_all(b"x").await.is_err() {
            break;
        }
        match timeout(Duration::from_secs(1), busy.io.read(&mut marker))
            .await
            .unwrap()
        {
            Ok(1) => echoed += 1,
            Ok(0) | Err(_) => break,
            other => panic!("{other:?}"),
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "持续流量不得延长总期限"
        );
    }
    assert!(echoed >= 3);
    assert!(start.elapsed() < Duration::from_secs(2));
    until(|| server.stats.snapshot().connections == 0).await;
    zero_business(&server);
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn half_hello_handshake_saturation_deadline_and_slot_recovery() {
    let target = TargetPeer::start(TargetOptions {
        behavior: TargetBehavior::Raw(vec![0x42]),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut configuration = config(target.address);
    configuration["limits"]["max_handshakes"] = json!(1);
    configuration["limits"]["handshake_timeout_ms"] = json!(100);
    let server = Running::start(configuration).await;
    let mut half = raw_send(server.address, &[22, 3, 3, 0, 100, 1]).await;
    until(|| server.stats.snapshot().connections == 1).await;
    let mut denied = TcpStream::connect(server.address).await.unwrap();
    closed(&mut denied).await;
    assert_eq!(target.observation.accepted.load(Ordering::SeqCst), 0);
    closed(&mut half).await;
    until(|| server.stats.snapshot().connections == 0).await;
    let mut recovered = PreparedClient::new(ClientOptions {
        short_id: [0; 8],
        ..Default::default()
    })
    .unwrap()
    .begin(server.address)
    .await
    .unwrap();
    let mut marker = [0; 1];
    timeout(WAIT, recovered.io.read_exact(&mut marker))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(marker, [0x42]);
    drop(recovered);
    until(|| server.stats.snapshot().connections == 0).await;
    zero_business(&server);
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn forced_shutdown_cancels_blocked_target_template_wait() {
    let target = TargetPeer::start(TargetOptions {
        behavior: TargetBehavior::Silent,
        ..Default::default()
    })
    .await
    .unwrap();
    let mut configuration = config(target.address);
    configuration["limits"]["handshake_timeout_ms"] = json!(30000);
    let server = Running::start(configuration).await;
    let mut client = PreparedClient::new(ClientOptions::default())
        .unwrap()
        .begin(server.address)
        .await
        .unwrap();
    until(|| target.observation.accepted.load(Ordering::SeqCst) == 1).await;
    let addresses = server.addresses.clone();
    let stats = server.stats.clone();
    let start = Instant::now();
    server.shutdown().await;
    assert!(start.elapsed() < Duration::from_secs(2));
    closed(&mut client.io).await;
    rebind(&addresses).await;
    let s = stats.snapshot();
    assert_eq!(
        (
            s.connections,
            s.tcp_flows,
            s.udp_associations,
            s.uplink,
            s.downlink
        ),
        (0, 0, 0, 0, 0)
    );
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn handshake_slots_release_on_fallback_and_global_slots_span_old_inbounds() {
    let target = TargetPeer::start(TargetOptions {
        behavior: TargetBehavior::Raw(vec![0x42]),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut configuration = config(target.address);
    configuration["limits"]["max_handshakes"] = json!(1);
    configuration["limits"]["max_connections"] = json!(2);
    configuration["inbounds"][0]["reality"]["fallback_idle_timeout_ms"] = json!(3000);
    configuration["inbounds"][0]["reality"]["fallback_max_duration_ms"] = json!(3000);
    configuration["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"socks5","tag":"old","listen":"127.0.0.1:0"}));
    let server = Running::start(configuration).await;
    let wrong = || {
        PreparedClient::new(ClientOptions {
            short_id: [0; 8],
            ..Default::default()
        })
        .unwrap()
    };
    let mut first = wrong().begin(server.address).await.unwrap();
    let mut marker = [0; 1];
    first.io.read_exact(&mut marker).await.unwrap();
    let mut second = wrong().begin(server.address).await.unwrap();
    second.io.read_exact(&mut marker).await.unwrap();
    assert_eq!(target.observation.accepted.load(Ordering::SeqCst), 2);
    let mut old = TcpStream::connect(server.addresses[1]).await.unwrap();
    closed(&mut old).await;
    drop(first);
    until(|| server.stats.snapshot().connections == 1).await;
    let mut recovered = TcpStream::connect(server.addresses[1]).await.unwrap();
    recovered.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    timeout(WAIT, recovered.read_exact(&mut method))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(method, [5, 0]);
    drop(recovered);
    drop(second);
    until(|| server.stats.snapshot().connections == 0).await;
    zero_business(&server);
    let addresses = server.addresses.clone();
    server.shutdown().await;
    rebind(&addresses).await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn forced_shutdown_joins_half_header_and_active_fallback_and_returns_ports() {
    let target = TargetPeer::start(TargetOptions {
        behavior: TargetBehavior::Raw(vec![0x42]),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut configuration = config(target.address);
    configuration["limits"]["handshake_timeout_ms"] = json!(30000);
    configuration["inbounds"][0]["reality"]["fallback_idle_timeout_ms"] = json!(10000);
    configuration["inbounds"][0]["reality"]["fallback_max_duration_ms"] = json!(60000);
    let server = Running::start(configuration).await;
    let mut half = raw_send(server.address, &[22, 3, 3, 0, 100, 1]).await;
    let mut active = PreparedClient::new(ClientOptions {
        short_id: [0; 8],
        ..Default::default()
    })
    .unwrap()
    .begin(server.address)
    .await
    .unwrap();
    let mut marker = [0; 1];
    active.io.read_exact(&mut marker).await.unwrap();
    until(|| server.stats.snapshot().connections == 2).await;
    let addresses = server.addresses.clone();
    let stats = server.stats.clone();
    let start = Instant::now();
    server.shutdown().await;
    assert!(start.elapsed() < Duration::from_secs(2));
    closed(&mut half).await;
    closed(&mut active.io).await;
    rebind(&addresses).await;
    assert_eq!(
        (
            stats.snapshot().connections,
            stats.snapshot().uplink,
            stats.snapshot().downlink
        ),
        (0, 0, 0)
    );
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn later_bind_failure_returns_prepared_reality_port_without_dialing_target() {
    let target = TargetPeer::start(TargetOptions::default()).await.unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = candidate.local_addr().unwrap();
    drop(candidate);
    let mut configuration = config(target.address);
    configuration["inbounds"][0]["listen"] = json!(address);
    configuration["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"socks5","tag":"later","listen":occupied.local_addr().unwrap()}));
    let parsed = Config::from_json(&configuration.to_string()).unwrap();
    assert!(Server::bind(parsed).await.is_err());
    rebind(&[address]).await;
    assert_eq!(target.observation.accepted.load(Ordering::SeqCst), 0);
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn check_cli_is_local_no_bind_no_target_and_secret_safe_on_errors() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut configuration = config(target.local_addr().unwrap());
    configuration["inbounds"][0]["listen"] = json!(occupied.local_addr().unwrap());
    let seed = URL_SAFE_NO_PAD.encode([0x45; 32]);
    configuration["inbounds"][0]["reality"]["mldsa65_seed"] = json!(seed);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    for invalid in [false, true] {
        let mut value = configuration.clone();
        if invalid {
            value["inbounds"][0]["reality"]["max_time_diff_ms"] = json!(0);
        }
        std::fs::write(&path, value.to_string()).unwrap();
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let stdout = dir.path().join("stdout");
        let stderr = dir.path().join("stderr");
        let child = std::process::Command::new(test_binary())
            .args(["check", "-c"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        let status = timeout(WAIT, async {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let output = std::process::Output {
            status,
            stdout: std::fs::read(stdout).unwrap(),
            stderr: std::fs::read(stderr).unwrap(),
        };
        assert_eq!(output.status.success(), !invalid);
        let logs = [output.stdout, output.stderr].concat();
        let text = String::from_utf8_lossy(&logs);
        for secret in [
            URL_SAFE_NO_PAD.encode(reality_peer::SERVER_PRIVATE_KEY),
            seed.clone(),
            "8172635445362718".to_owned(),
            reality_peer::UUID.to_owned(),
        ] {
            assert!(!text.contains(&secret));
        }
        assert!(
            timeout(Duration::from_millis(30), target.accept())
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(30), occupied.accept())
                .await
                .is_err()
        );
    }
    let mut no_dns = configuration;
    no_dns["inbounds"][0]["reality"]["target"]["host"] = json!("must-not-resolve.invalid");
    Server::check(&Config::from_json(&no_dns.to_string()).unwrap()).unwrap();
}
