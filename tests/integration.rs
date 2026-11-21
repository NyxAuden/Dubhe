mod common;
use common::*;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

#[tokio::test]
async fn socks_tcp_domain_half_close_and_counting() {
    let echo = Echo::tcp("127.0.0.1", true).await;
    let server = Running::start(socks_config()).await;
    let (mut client, _) = socks(1, domain("localhost", echo.address.port()), server.address).await;
    client.write_all(b"half-close").await.unwrap();
    client.shutdown().await.unwrap();
    let mut b = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b, b"half-close");
    assert_eq!(server.stats.snapshot().uplink, 10);
    assert_eq!(server.stats.snapshot().downlink, 10);
    server.shutdown().await;
}

#[tokio::test]
async fn socks_udp_multi_target_zero_payload_and_source_validation() {
    let one = Echo::udp("127.0.0.1").await;
    let two = Echo::udp("127.0.0.1").await;
    let server = Running::start(socks_config()).await;
    let (control, relay) = socks(3, address("0.0.0.0:0".parse().unwrap()), server.address).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = [0; 1024];
    for (target, payload) in [
        (one.address, b"one".as_slice()),
        (two.address, b"two".as_slice()),
        (one.address, b"".as_slice()),
    ] {
        let mut packet = vec![0, 0, 0];
        packet.extend(address(target));
        packet.extend(payload);
        client.send_to(&packet, relay).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], packet);
    }
    let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0];
    packet.extend(address(one.address));
    packet.extend(b"intruder");
    intruder.send_to(&packet, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(60), intruder.recv_from(&mut buffer))
            .await
            .is_err()
    );
    packet[2] = 1;
    client.send_to(&packet, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(60), client.recv_from(&mut buffer))
            .await
            .is_err()
    );
    drop(control);
    server.shutdown().await;
}

#[tokio::test]
async fn trojan_tcp_coalesced_and_fragmented_header() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut config = socks_config();
    config["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(cert.inbound());
    let server = Running::start(config).await;
    let mut s = cert.connect(server.addresses[1]).await;
    let mut data = trojan_header(1, address(echo.address), PASSWORD);
    data.extend(b"coalesced");
    s.write_all(&data).await.unwrap();
    let mut reply = [0; 9];
    read_exact(&mut s, &mut reply).await;
    assert_eq!(&reply, b"coalesced");
    let mut fragmented = cert.connect(server.addresses[1]).await;
    for byte in trojan_header(1, address(echo.address), PASSWORD) {
        fragmented.write_all(&[byte]).await.unwrap();
    }
    exchange(&mut fragmented, b"fragmented").await;
    let (mut socks_client, _) = socks(1, address(echo.address), server.address).await;
    exchange(&mut socks_client, b"simultaneous").await;
    server.shutdown().await;
}

#[tokio::test]
async fn trojan_udp_multiple_frames_and_zero_payload() {
    let cert = Certificate::new();
    let one = Echo::udp("127.0.0.1").await;
    let two = Echo::udp("127.0.0.1").await;
    let mut config = socks_config();
    config["inbounds"] = serde_json::json!([cert.inbound()]);
    let server = Running::start(config).await;
    let mut client = cert.connect(server.address).await;
    client
        .write_all(&trojan_header(3, address(one.address), PASSWORD))
        .await
        .unwrap();
    let mut frames = trojan_udp(one.address, b"first");
    frames.extend(trojan_udp(two.address, b"second"));
    client.write_all(&frames).await.unwrap();
    let first = timeout(Duration::from_secs(2), trojan_recv(&mut client))
        .await
        .unwrap();
    let second = timeout(Duration::from_secs(2), trojan_recv(&mut client))
        .await
        .unwrap();
    let results = [first, second];
    assert!(results.contains(&(one.address, b"first".to_vec())));
    assert!(results.contains(&(two.address, b"second".to_vec())));
    for byte in trojan_udp(one.address, b"") {
        client.write_all(&[byte]).await.unwrap();
    }
    assert_eq!(
        timeout(Duration::from_secs(2), trojan_recv(&mut client))
            .await
            .unwrap(),
        (one.address, Vec::new())
    );
    server.shutdown().await;
}

#[tokio::test]
async fn trojan_wrong_password_never_dials() {
    let cert = Certificate::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = socks_config();
    config["inbounds"] = serde_json::json!([cert.inbound()]);
    let server = Running::start(config).await;
    let mut client = cert.connect(server.address).await;
    client
        .write_all(&trojan_header(
            1,
            address(target.local_addr().unwrap()),
            "wrong",
        ))
        .await
        .unwrap();
    let mut b = [0];
    let result = timeout(Duration::from_secs(1), client.read(&mut b))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    assert!(
        timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn startup_failure_releases_prepared_listener() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let free = first.local_addr().unwrap();
    drop(first);
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = socks_config();
    config["inbounds"] = serde_json::json!([
        {"type":"socks5","tag":"one","listen":free},
        {"type":"socks5","tag":"two","listen":occupied.local_addr().unwrap()}
    ]);
    let config = dubhe::Config::from_json(&config.to_string()).unwrap();
    assert!(dubhe::Server::bind(config).await.is_err());
    let _rebound = TcpListener::bind(free).await.unwrap();
}

#[tokio::test]
async fn handshake_limit_timeout_and_recovery() {
    let mut config = socks_config();
    config["limits"]["max_handshakes"] = 1.into();
    config["limits"]["handshake_timeout_ms"] = 80.into();
    let server = Running::start(config).await;
    let mut first = TcpStream::connect(server.address).await.unwrap();
    first.write_all(&[5]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut second = TcpStream::connect(server.address).await.unwrap();
    let mut b = [0; 1];
    let result = timeout(Duration::from_millis(200), second.read(&mut b))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    let result = timeout(Duration::from_millis(200), first.read(&mut b))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    let echo = Echo::tcp("127.0.0.1", false).await;
    let (mut next, _) = socks(1, address(echo.address), server.address).await;
    exchange(&mut next, b"recovered").await;
    server.shutdown().await;
}

#[tokio::test]
async fn route_reject_does_not_connect() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = socks_config();
    config["route"]["default"] = "reject".into();
    let server = Running::start(config).await;
    let mut client = TcpStream::connect(server.address).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut b = [0; 2];
    read_exact(&mut client, &mut b).await;
    let mut request = vec![5, 1, 0];
    request.extend(address(target.local_addr().unwrap()));
    client.write_all(&request).await.unwrap();
    read_exact(&mut client, &mut b).await;
    assert_eq!(b, [5, 2]);
    assert!(
        timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn ipv6_tcp_udp_when_available() {
    if TcpListener::bind("[::1]:0").await.is_err() {
        eprintln!("SKIP: IPv6 loopback unavailable");
        return;
    }
    let tcp = Echo::tcp("[::1]", false).await;
    let udp = Echo::udp("[::1]").await;
    let server = Running::start(socks_config()).await;
    let (mut client, _) = socks(1, address(tcp.address), server.address).await;
    exchange(&mut client, b"ipv6").await;
    let (_control, relay) = socks(3, address("0.0.0.0:0".parse().unwrap()), server.address).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0];
    packet.extend(address(udp.address));
    packet.extend(b"ipv6udp");
    client.send_to(&packet, relay).await.unwrap();
    let mut b = [0; 128];
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], packet);
    server.shutdown().await;
}
