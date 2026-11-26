mod common;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use common::*;
use dubhe::telemetry::{Snapshot, Stats};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(3);

async fn wait_stats(stats: &Arc<Stats>, ready: impl Fn(&Snapshot) -> bool) -> Snapshot {
    timeout(WAIT, async {
        loop {
            let snapshot = stats.snapshot();
            if ready(&snapshot) {
                return snapshot;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("业务计量未在期限内收敛：{:?}", stats.snapshot()))
}

fn empty(snapshot: &Snapshot) -> bool {
    snapshot.connections == 0 && snapshot.tcp_flows == 0 && snapshot.udp_associations == 0
}

async fn closed<R: AsyncRead + Unpin>(stream: &mut R) {
    let result = timeout(WAIT, stream.read(&mut [0])).await.unwrap();
    assert!(matches!(result, Ok(0) | Err(_)), "连接仍返回业务数据");
}

fn packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend(address(target));
    bytes.extend(payload);
    bytes
}

async fn udp_exchange(client: &UdpSocket, relay: SocketAddr, target: SocketAddr, payload: &[u8]) {
    let expected = packet(target, payload);
    client.send_to(&expected, relay).await.unwrap();
    let mut buffer = vec![0; 65536];
    let (length, source) = timeout(WAIT, client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, relay);
    assert_eq!(&buffer[..length], expected);
}

// 目标由测试直接接收和回包，从而能验证拒绝请求未到达目标以及映射端口释放。
async fn controlled_exchange(
    client: &UdpSocket,
    relay: SocketAddr,
    target: &UdpSocket,
    payload: &[u8],
) -> SocketAddr {
    client
        .send_to(&packet(target.local_addr().unwrap(), payload), relay)
        .await
        .unwrap();
    let mut buffer = vec![0; 65536];
    let (length, mapping) = timeout(WAIT, target.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], payload);
    target.send_to(payload, mapping).await.unwrap();
    let (length, source) = timeout(WAIT, client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, relay);
    assert_eq!(
        &buffer[..length],
        packet(target.local_addr().unwrap(), payload)
    );
    mapping
}

async fn request_without_reply(command: u8, target: SocketAddr, inbound: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(inbound).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    read_exact(&mut stream, &mut method).await;
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, command, 0];
    request.extend(address(target));
    stream.write_all(&request).await.unwrap();
    stream
}

#[tokio::test]
async fn global_connection_limit_spans_inbounds_and_recovers_after_close() {
    let target = Echo::tcp("127.0.0.1", false).await;
    let mut config = socks_config();
    config["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "type": "socks5", "tag": "second", "listen": "127.0.0.1:0"
        }));
    config["limits"]["max_connections"] = 1.into();
    let server = Running::start(config).await;
    let (mut first, _) = socks(1, address(target.address), server.address).await;
    exchange(&mut first, b"first-slot").await;
    wait_stats(&server.stats, |s| s.connections == 1 && s.tcp_flows == 1).await;

    let mut denied = TcpStream::connect(server.addresses[1]).await.unwrap();
    closed(&mut denied).await;
    wait_stats(&server.stats, |s| s.rejected >= 1).await;
    exchange(&mut first, b"incumbent-remains-active").await;
    drop(first);
    wait_stats(&server.stats, empty).await;

    let (mut recovered, _) = socks(1, address(target.address), server.addresses[1]).await;
    exchange(&mut recovered, b"reused-global-slot").await;
    drop(recovered);
    wait_stats(&server.stats, empty).await;
    server.shutdown().await;
}

#[tokio::test]
#[ignore = "使用默认 10s 期限的本地验收"]
async fn default_handshake_limits_recover_after_deadline() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut config = socks_config();
    config.as_object_mut().unwrap().remove("limits");
    let server = Running::start(config).await;
    let probe = || async {
        let (mut client, _) = socks(1, address(echo.address), server.address).await;
        exchange(&mut client, b"available").await;
    };
    probe().await;
    wait_stats(&server.stats, empty).await;
    let inbound = server.address;
    let connect = |ip| async move {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::from(([127, 0, 0, ip], 0))).unwrap();
        timeout(WAIT, socket.connect(inbound))
            .await
            .unwrap()
            .unwrap()
    };
    let started = Instant::now();
    let mut held = Vec::new();
    for ip in 1..=8 {
        for _ in 0..8 {
            held.push(connect(ip).await);
        }
        if ip == 1 {
            wait_stats(&server.stats, |s| s.connections == 8).await;
            closed(&mut connect(1).await).await;
            wait_stats(&server.stats, |s| s.rejected == 1).await;
        }
    }
    wait_stats(&server.stats, |s| s.connections == 64).await;
    for _ in 0..16 {
        closed(&mut connect(9).await).await;
    }
    wait_stats(&server.stats, |s| s.rejected == 17 && s.connections == 64).await;
    assert!(started.elapsed() < Duration::from_secs(3));
    timeout(Duration::from_secs(11), async {
        for client in &mut held {
            let result = client.read(&mut [0]).await;
            assert!(matches!(result, Ok(0) | Err(_)));
        }
    })
    .await
    .expect("未完成的握手必须关闭");
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(9));
    assert!(elapsed < Duration::from_secs(11));
    wait_stats(&server.stats, empty).await;
    probe().await;
    eprintln!(
        "SOCKS default limits: 64 closed in {:.3}s; 1 per-IP + 16 per-inbound rejected",
        elapsed.as_secs_f64()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn global_udp_association_limit_spans_inbounds_and_recovers() {
    let target = Echo::udp("127.0.0.1").await;
    let mut config = socks_config();
    config["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "type": "socks5", "tag": "second", "listen": "127.0.0.1:0"
        }));
    config["limits"]["max_udp_associations"] = 1.into();
    config["limits"]["udp_idle_timeout_ms"] = 3000.into();
    let server = Running::start(config).await;
    let unspecified = "0.0.0.0:0".parse().unwrap();
    let (control, relay) = socks(3, address(unspecified), server.address).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&client, relay, target.address, b"occupied").await;

    let mut denied = request_without_reply(3, unspecified, server.addresses[1]).await;
    let mut failure_reply = [0; 3];
    read_exact(&mut denied, &mut failure_reply).await;
    assert_eq!(failure_reply, [5, 1, 0]);
    let _bound = read_address(&mut denied).await;
    closed(&mut denied).await;
    wait_stats(&server.stats, |s| {
        s.connections == 1 && s.udp_associations == 1 && s.rejected >= 1
    })
    .await;
    udp_exchange(&client, relay, target.address, b"still-live").await;
    drop(control);
    wait_stats(&server.stats, empty).await;

    let (control, relay) = socks(3, address(unspecified), server.addresses[1]).await;
    udp_exchange(
        &client,
        relay,
        target.address,
        b"association-slot-recovered",
    )
    .await;
    drop(control);
    wait_stats(&server.stats, empty).await;
    server.shutdown().await;
}

#[tokio::test]
async fn udp_target_limit_drops_new_destination_and_reclaims_expired_mapping() {
    let one = Echo::udp("127.0.0.1").await;
    let two = Echo::udp("127.0.0.1").await;
    let three = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = socks_config();
    config["limits"]["max_udp_targets"] = 2.into();
    config["limits"]["udp_idle_timeout_ms"] = 500.into();
    let server = Running::start(config).await;
    let (control, relay) = socks(3, address("0.0.0.0:0".parse().unwrap()), server.address).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_exchange(&client, relay, one.address, b"old-mapping").await;
    udp_exchange(&client, relay, two.address, b"keepalive-mapping").await;
    client
        .send_to(
            &packet(three.local_addr().unwrap(), b"must-not-arrive"),
            relay,
        )
        .await
        .unwrap();
    wait_stats(&server.stats, |s| s.dropped >= 1).await;
    assert!(
        timeout(Duration::from_millis(50), three.recv_from(&mut [0; 128]))
            .await
            .is_err()
    );

    // 刷新第二个目标，保持关联存活；第一个目标不再使用，超过其空闲期限。
    for _ in 0..6 {
        sleep(Duration::from_millis(100)).await;
        udp_exchange(&client, relay, two.address, b"keepalive").await;
    }
    controlled_exchange(&client, relay, &three, b"expired-slot-reused").await;
    assert_eq!(server.stats.snapshot().udp_associations, 1);
    drop(control);
    wait_stats(&server.stats, empty).await;
    server.shutdown().await;
}

#[tokio::test]
async fn socks_udp_control_close_and_idle_release_relay_mapping_and_slot() {
    for idle_expiry in [false, true] {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = socks_config();
        config["limits"]["max_udp_associations"] = 1.into();
        config["limits"]["udp_idle_timeout_ms"] = 160.into();
        let server = Running::start(config).await;
        let (mut control, relay) =
            socks(3, address("0.0.0.0:0".parse().unwrap()), server.address).await;
        let mapping = controlled_exchange(&client, relay, &target, b"before-close").await;
        if idle_expiry {
            closed(&mut control).await;
        }
        drop(control);
        wait_stats(&server.stats, empty).await;
        let released_relay = UdpSocket::bind(relay).await.unwrap();
        let released_mapping = UdpSocket::bind(mapping).await.unwrap();
        drop((released_relay, released_mapping));

        let (control, relay) =
            socks(3, address("0.0.0.0:0".parse().unwrap()), server.address).await;
        controlled_exchange(&client, relay, &target, b"after-release").await;
        drop(control);
        wait_stats(&server.stats, empty).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn trojan_udp_stream_close_and_idle_release_mapping_and_slot() {
    let certificate = Certificate::new();
    for idle_expiry in [false, true] {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = socks_config();
        config["inbounds"] = serde_json::json!([certificate.inbound()]);
        config["limits"]["max_udp_associations"] = 1.into();
        config["limits"]["udp_idle_timeout_ms"] = 160.into();
        let server = Running::start(config).await;
        let mut stream = certificate.connect(server.address).await;
        stream
            .write_all(&trojan_header(
                3,
                address(target.local_addr().unwrap()),
                PASSWORD,
            ))
            .await
            .unwrap();
        stream
            .write_all(&trojan_udp(target.local_addr().unwrap(), b"before-close"))
            .await
            .unwrap();
        let mut buffer = [0; 128];
        let (length, mapping) = timeout(WAIT, target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"before-close");
        target.send_to(&buffer[..length], mapping).await.unwrap();
        assert_eq!(
            timeout(WAIT, trojan_recv(&mut stream)).await.unwrap().1,
            b"before-close"
        );
        if idle_expiry {
            closed(&mut stream).await;
        }
        drop(stream);
        wait_stats(&server.stats, empty).await;
        drop(UdpSocket::bind(mapping).await.unwrap());

        let echo = Echo::udp("127.0.0.1").await;
        let mut recovered = certificate.connect(server.address).await;
        recovered
            .write_all(&trojan_header(3, address(echo.address), PASSWORD))
            .await
            .unwrap();
        recovered
            .write_all(&trojan_udp(echo.address, b"slot-recovered"))
            .await
            .unwrap();
        assert_eq!(
            timeout(WAIT, trojan_recv(&mut recovered)).await.unwrap(),
            (echo.address, b"slot-recovered".to_vec())
        );
        drop(recovered);
        wait_stats(&server.stats, empty).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn forced_shutdown_closes_live_tcp_and_udp_for_both_protocols() {
    let certificate = Certificate::new();
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap();
    let mut config = socks_config();
    config["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(certificate.inbound());
    config["limits"]["shutdown_timeout_ms"] = 120.into();
    config["limits"]["udp_idle_timeout_ms"] = 30000.into();
    let server = Running::start(config).await;
    let addresses = server.addresses.clone();
    let (mut socks_tcp, _) = socks(1, address(tcp.address), addresses[0]).await;
    exchange(&mut socks_tcp, b"socks-tcp").await;
    let (mut socks_udp, relay) =
        socks(3, address("0.0.0.0:0".parse().unwrap()), addresses[0]).await;
    let datagrams = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socks_mapping = controlled_exchange(&datagrams, relay, &udp, b"socks-udp").await;
    let mut trojan_tcp = certificate.connect(addresses[1]).await;
    trojan_tcp
        .write_all(&trojan_header(1, address(tcp.address), PASSWORD))
        .await
        .unwrap();
    exchange(&mut trojan_tcp, b"trojan-tcp").await;
    let mut trojan_udp_stream = certificate.connect(addresses[1]).await;
    trojan_udp_stream
        .write_all(&trojan_header(3, address(udp_address), PASSWORD))
        .await
        .unwrap();
    trojan_udp_stream
        .write_all(&trojan_udp(udp_address, b"trojan-udp"))
        .await
        .unwrap();
    let mut udp_buffer = [0; 128];
    let (length, trojan_mapping) = timeout(WAIT, udp.recv_from(&mut udp_buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&udp_buffer[..length], b"trojan-udp");
    udp.send_to(&udp_buffer[..length], trojan_mapping)
        .await
        .unwrap();
    assert_eq!(
        timeout(WAIT, trojan_recv(&mut trojan_udp_stream))
            .await
            .unwrap()
            .1,
        b"trojan-udp"
    );
    wait_stats(&server.stats, |s| {
        s.connections == 4 && s.tcp_flows == 2 && s.udp_associations == 2
    })
    .await;
    let started = Instant::now();
    server.shutdown().await;
    // 停机返回时映射接收任务必须已结束，不能只提前减少活动计数。
    let released_socks_mapping = UdpSocket::bind(socks_mapping).await.unwrap();
    let released_trojan_mapping = UdpSocket::bind(trojan_mapping).await.unwrap();
    drop((released_socks_mapping, released_trojan_mapping));
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "未等待配置的排空期限"
    );
    assert!(started.elapsed() < WAIT, "强制停机没有在期限内结束");
    closed(&mut socks_tcp).await;
    closed(&mut socks_udp).await;
    closed(&mut trojan_tcp).await;
    closed(&mut trojan_udp_stream).await;
    for address in addresses {
        drop(TcpListener::bind(address).await.unwrap());
    }
    drop(UdpSocket::bind(relay).await.unwrap());
}

#[tokio::test]
async fn five_second_local_tcp_udp_churn_recovers_slots_and_counts_payload_only() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let udp = Echo::udp("127.0.0.1").await;
    let mut config = socks_config();
    config["limits"]["max_connections"] = 1.into();
    config["limits"]["max_udp_associations"] = 1.into();
    config["limits"]["max_udp_targets"] = 1.into();
    let server = Running::start(config).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let started = Instant::now();
    let mut cycles = 0u64;
    let mut expected_bytes = 0u64;
    // 断言的是「连接与 UDP 关联能被反复创建/回收」，不是吞吐量。
    // 原来用固定的 5.2 秒墙钟窗口，负载高时单轮超过 2.6 秒就会失败；
    // 改为「跑够 3 轮或超时」，超时值只作为防止永久挂起的上限。
    while cycles < 3 && started.elapsed() < Duration::from_secs(60) {
        let payload = format!("controlled-cycle-{cycles:05}");
        let (mut stream, _) = socks(1, address(tcp.address), server.address).await;
        exchange(&mut stream, payload.as_bytes()).await;
        stream.shutdown().await.unwrap();
        let mut remainder = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut remainder))
            .await
            .unwrap()
            .unwrap();
        assert!(remainder.is_empty());
        drop(stream);
        wait_stats(&server.stats, empty).await;
        expected_bytes += payload.len() as u64;

        let (control, relay) =
            socks(3, address("0.0.0.0:0".parse().unwrap()), server.address).await;
        let payload = if cycles.is_multiple_of(3) {
            b"".as_slice()
        } else {
            payload.as_bytes()
        };
        udp_exchange(&client, relay, udp.address, payload).await;
        expected_bytes += payload.len() as u64;
        drop(control);
        let snapshot = wait_stats(&server.stats, empty).await;
        assert_eq!(snapshot.uplink, expected_bytes);
        assert_eq!(snapshot.downlink, expected_bytes);
        assert_eq!(snapshot.dropped, 0);
        assert_eq!(snapshot.rejected, 0);
        cycles += 1;
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(cycles, 3, "必须完成多轮连接和关联创建/回收");
    eprintln!(
        "本地循环转发：{cycles} 轮，耗时 {:?}，单向业务字节 {expected_bytes}",
        started.elapsed()
    );
    server.shutdown().await;
}

// 队列占用和共享字节预算没有公开观测接口；这里不以丢包概率冒充上限证明。
