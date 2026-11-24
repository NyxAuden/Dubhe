mod common;
use common::*;
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::client::TlsStream;

fn config(cert: &Certificate) -> Value {
    let mut value = socks_config();
    value["inbounds"] = json!([{
        "type":"vless", "tag":"vless", "listen":"127.0.0.1:0", "xudp":true,
        "users":[{"name":"one","uuid":"11111111-1111-1111-1111-111111111111"},
                 {"name":"two","uuid":"22222222-2222-2222-2222-222222222222"}],
        "certificate":cert.dir.path().join("cert.pem"), "private_key":cert.dir.path().join("key.pem")
    }]);
    value
}

async fn connect(cert: &Certificate, server: &Running, identity: u8) -> TlsStream<TcpStream> {
    let mut s = cert.connect(server.address).await;
    let mut header = vec![0];
    header.extend_from_slice(&[identity; 16]);
    header.extend_from_slice(&[0, 3]);
    s.write_all(&header).await.unwrap();
    s.flush().await.unwrap();
    let mut response = [0xff; 2];
    read_exact(&mut s, &mut response).await;
    assert_eq!(response, [0, 0]);
    s
}

// 独立测试端按公开帧布局编码，不调用服务端 codec。
fn target(addr: SocketAddr) -> Vec<u8> {
    let mut b = addr.port().to_be_bytes().to_vec();
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            b.push(1);
            b.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            b.push(3);
            b.extend(ip.octets());
        }
    }
    b
}
fn frame_network(
    id: u16,
    status: u8,
    network: u8,
    address: Option<Vec<u8>>,
    global: Option<[u8; 8]>,
    data: Option<&[u8]>,
) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([status, u8::from(data.is_some())]);
    if let Some(address) = address {
        metadata.push(network);
        metadata.extend(address);
    }
    if let Some(global) = global {
        metadata.extend(global);
    }
    let mut bytes = (metadata.len() as u16).to_be_bytes().to_vec();
    bytes.extend(metadata);
    if let Some(data) = data {
        bytes.extend((data.len() as u16).to_be_bytes());
        bytes.extend(data);
    }
    bytes
}
fn frame(
    id: u16,
    status: u8,
    address: Option<Vec<u8>>,
    global: bool,
    data: Option<&[u8]>,
) -> Vec<u8> {
    frame_network(id, status, 2, address, global.then_some([0x77; 8]), data)
}
// GlobalID 只在同一服务实例内复用；不同测试各自启动独立实例，互不接管。
fn frame_gid(
    id: u16,
    status: u8,
    address: Option<Vec<u8>>,
    global: [u8; 8],
    data: Option<&[u8]>,
) -> Vec<u8> {
    frame_network(id, status, 2, address, Some(global), data)
}
fn tcp_frame(id: u16, status: u8, address: Option<Vec<u8>>, data: Option<&[u8]>) -> Vec<u8> {
    frame_network(id, status, 1, address, None, data)
}
async fn send<S: AsyncWrite + Unpin>(s: &mut S, bytes: &[u8]) {
    s.write_all(bytes).await.unwrap();
    s.flush().await.unwrap();
}
async fn recv<S: AsyncRead + Unpin>(s: &mut S) -> (Vec<u8>, Vec<u8>) {
    timeout(Duration::from_secs(3), async {
        let length = s.read_u16().await.unwrap();
        assert!((4..=512).contains(&length));
        let mut metadata = vec![0; length as usize];
        s.read_exact(&mut metadata).await.unwrap();
        let mut data = vec![];
        if metadata[3] & 1 != 0 {
            let length = s.read_u16().await.unwrap();
            data.resize(length as usize, 0);
            s.read_exact(&mut data).await.unwrap();
        }
        (metadata, data)
    })
    .await
    .unwrap()
}
async fn expect<S: AsyncRead + Unpin>(s: &mut S, id: u16, addr: SocketAddr, data: &[u8]) {
    let (metadata, payload) = recv(s).await;
    let mut expected = id.to_be_bytes().to_vec();
    expected.extend([2, 1, 2]);
    expected.extend(target(addr));
    assert_eq!(metadata, expected);
    assert_eq!(payload, data);
}
async fn expect_tcp<S: AsyncRead + Unpin>(s: &mut S, id: u16, data: &[u8]) {
    let (metadata, payload) = recv(s).await;
    let [hi, lo] = id.to_be_bytes();
    // TCP 回程没有说明目标，仅携带会话号/Keep/Data。
    assert_eq!(metadata, [hi, lo, 2, 1]);
    assert_eq!(payload, data);
}
async fn end<S: AsyncRead + Unpin>(s: &mut S, id: u16, error: bool) {
    let (metadata, payload) = recv(s).await;
    let [hi, lo] = id.to_be_bytes();
    assert_eq!(metadata, [hi, lo, 3, if error { 2 } else { 0 }]);
    assert!(payload.is_empty());
}
async fn closed<S: AsyncRead + Unpin>(s: &mut S) {
    let result = timeout(Duration::from_secs(3), s.read_u8()).await.unwrap();
    assert!(result.is_err());
}
async fn associations(server: &Running, count: usize) {
    timeout(Duration::from_secs(3), async {
        while server.stats.snapshot().udp_associations != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn multiple_sessions_targets_fragmentation_and_accounting() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let a = Echo::udp("127.0.0.1").await;
    let b = Echo::udp("127.0.0.1").await;
    let mut s = connect(&cert, &server, 0x11).await;
    let mut merged = frame_gid(7, 1, Some(target(a.address)), [0x11; 8], Some(b"first"));
    merged.extend(frame(9, 1, Some(target(b.address)), false, Some(b"other")));
    send(&mut s, &merged).await;
    let mut seen = vec![];
    for _ in 0..2 {
        let (m, p) = recv(&mut s).await;
        seen.push((u16::from_be_bytes([m[0], m[1]]), p));
    }
    seen.sort();
    assert_eq!(seen, vec![(7, b"first".to_vec()), (9, b"other".to_vec())]);
    // 同会话改目标，然后无目标 Keep 回到初始目标。
    send(
        &mut s,
        &frame(7, 2, Some(target(b.address)), false, Some(b"switch")),
    )
    .await;
    expect(&mut s, 7, b.address, b"switch").await;
    let bytes = frame(7, 2, None, false, Some(&[0x5a; 300]));
    for byte in bytes {
        s.write_u8(byte).await.unwrap();
    }
    s.flush().await.unwrap();
    expect(&mut s, 7, a.address, &[0x5a; 300]).await;
    // 域名目标与空包，不计入业务字节；非空回复仍携带实际IP。
    let mut domain = a.address.port().to_be_bytes().to_vec();
    domain.extend(b"\x02\x09localhost");
    send(&mut s, &frame(7, 2, Some(domain), false, Some(b"domain"))).await;
    expect(&mut s, 7, a.address, b"domain").await;
    send(&mut s, &frame(7, 2, None, false, Some(b""))).await;
    send(&mut s, &frame(7, 2, None, false, Some(b"last"))).await;
    // Mux 保留零长度 UDP 边界：空请求的回包也是零长度 Keep+Data。
    expect(&mut s, 7, a.address, b"").await;
    expect(&mut s, 7, a.address, b"last").await;
    assert_eq!(server.stats.snapshot().uplink, 326);
    assert_eq!(server.stats.snapshot().downlink, 326);
    server.shutdown().await;
}

#[tokio::test]
async fn global_id_takeover_moves_sink_and_old_session_gets_error() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target_socket.local_addr().unwrap();
    // 续接只在同一账户内成立；跨账户隔离由下面单独的用例覆盖。
    let mut one = connect(&cert, &server, 0x11).await;
    let mut two = connect(&cert, &server, 0x11).await;
    send(
        &mut one,
        &frame_gid(0, 1, Some(target(addr)), [0x22; 8], Some(b"one")),
    )
    .await;
    let mut buf = [0; 64];
    let (n, peer_shared) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"one");
    // 同一账户、同一入口、同一 GlobalID：迁移 sink，而不是隔离。
    send(
        &mut two,
        &frame_gid(0, 1, Some(target(addr)), [0x22; 8], Some(b"two")),
    )
    .await;
    let (n, peer_two) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"two");
    assert_eq!(peer_two, peer_shared, "存活 GlobalID 必须复用同一 UDP 关联");
    end(&mut one, 0, true).await;
    target_socket
        .send_to(b"reply-two", peer_shared)
        .await
        .unwrap();
    expect(&mut two, 0, addr, b"reply-two").await;

    // 旧连接只丢失该会话，仍可承载其他无 GlobalID 会话。
    send(
        &mut one,
        &frame(7, 1, Some(target(addr)), false, Some(b"other")),
    )
    .await;
    let (n, peer_other) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"other");
    assert_ne!(peer_other, peer_shared);
    target_socket
        .send_to(b"reply-other", peer_other)
        .await
        .unwrap();
    expect(&mut one, 7, addr, b"reply-other").await;

    // End 后关联进入 1 分钟宽限期：同一 GlobalID 复用原 UDP 关联，
    // 而不是像无 GlobalID 的会话那样立即释放。
    send(&mut two, &frame(0, 3, None, false, None)).await;
    associations(&server, 1).await;
    send(
        &mut two,
        &frame_gid(0, 1, Some(target(addr)), [0x22; 8], Some(b"new")),
    )
    .await;
    let (n, peer_new) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"new");
    assert_eq!(peer_new, peer_shared, "宽限期内必须复用同一 UDP 关联");
    target_socket.send_to(b"fresh", peer_new).await.unwrap();
    expect(&mut two, 0, addr, b"fresh").await;

    send(&mut one, &frame(7, 3, None, false, None)).await;
    send(&mut two, &frame(0, 3, None, false, None)).await;
    associations(&server, 0).await;
    server.shutdown().await;
}

/// Xray 在最后一个会话结束后保留 XUDP 关联 60 秒；到期才释放套接字。
#[tokio::test]
async fn global_id_survives_grace_period_then_expires() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target_socket.local_addr().unwrap();
    let mut s = connect(&cert, &server, 0x11).await;
    send(
        &mut s,
        &frame_gid(0, 1, Some(target(addr)), [0x33; 8], Some(b"grace")),
    )
    .await;
    let mut buf = [0; 32];
    let (n, peer) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"grace");

    // 显式结束后关联进入宽限期；期间套接字仍由登记表持有。
    send(&mut s, &frame(0, 3, None, false, None)).await;
    associations(&server, 0).await;
    assert!(
        UdpSocket::bind(peer).await.is_err(),
        "宽限期内不应释放源端口"
    );
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;
    // 到期清理后读任务被 abort，重试到套接字真正关闭。
    let _rebound = rebind_udp(peer).await;
    server.shutdown().await;
}

#[tokio::test]
async fn global_limit_route_changes_and_target_limit_release_sessions() {
    let cert = Certificate::new();
    let a = Echo::udp("127.0.0.1").await;
    let b = Echo::udp("127.0.0.1").await;
    let mut value = config(&cert);
    value["limits"]["max_udp_associations"] = json!(1);
    value["limits"]["max_udp_targets"] = json!(1);
    value["route"]["rules"] = json!([{"ports":[{"start":1,"end":1}],"outbound":"reject"}]);
    let server = Running::start(value).await;
    let mut s = connect(&cert, &server, 0x11).await;
    send(
        &mut s,
        &frame(1, 1, Some(target(a.address)), false, Some(b"ok")),
    )
    .await;
    expect(&mut s, 1, a.address, b"ok").await;
    send(
        &mut s,
        &frame(2, 1, Some(target(a.address)), false, Some(b"limit")),
    )
    .await;
    end(&mut s, 2, true).await;
    send(
        &mut s,
        &frame(
            1,
            2,
            Some(target("127.0.0.1:1".parse().unwrap())),
            false,
            Some(b"reject"),
        ),
    )
    .await;
    end(&mut s, 1, true).await;
    associations(&server, 0).await;
    send(
        &mut s,
        &frame(3, 1, Some(target(a.address)), false, Some(b"ok")),
    )
    .await;
    expect(&mut s, 3, a.address, b"ok").await;
    send(
        &mut s,
        &frame(3, 2, Some(target(b.address)), false, Some(b"target-limit")),
    )
    .await;
    end(&mut s, 3, true).await;
    associations(&server, 0).await;
    send(
        &mut s,
        &frame(4, 1, Some(target(b.address)), false, Some(b"released")),
    )
    .await;
    expect(&mut s, 4, b.address, b"released").await;
    server.shutdown().await;
}

#[tokio::test]
async fn keepalive_does_not_pin_udp_mappings_and_partial_frame_closes_connection() {
    let cert = Certificate::new();
    let mut value = config(&cert);
    value["limits"]["udp_idle_timeout_ms"] = json!(200);
    let server = Running::start(value).await;
    let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = destination.local_addr().unwrap();
    let mut s = connect(&cert, &server, 0x11).await;
    send(
        &mut s,
        &frame(1, 1, Some(target(addr)), false, Some(b"first")),
    )
    .await;
    let mut buf = [0; 64];
    let (n, first) = destination.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"first");
    // KeepAlive 不延长目标映射；会话本身也不会按 UDP idle 单独关闭。
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(45)).await;
        send(&mut s, &frame(0, 4, None, false, None)).await;
    }
    send(&mut s, &frame(1, 2, None, false, Some(b"again"))).await;
    let (n, second) = destination.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"again");
    assert_ne!(second, first, "KeepAlive 后映射应已过期并重建");
    destination.send_to(b"stale", first).await.unwrap();
    destination.send_to(b"fresh", second).await.unwrap();
    expect(&mut s, 1, addr, b"fresh").await;

    // 截断帧破坏边界，整条 Mux 连接 fail-closed，不伪造 End；关闭写侧让 EOF 可被观测。
    send(&mut s, b"\x00\x0c\x00").await;
    s.shutdown().await.unwrap();
    closed(&mut s).await;
    associations(&server, 0).await;
    server.shutdown().await;
    let _rebound = rebind_udp(first).await;
    let _rebound2 = rebind_udp(second).await;
}

#[tokio::test]
async fn per_session_errors_and_tcp_sessions_keep_mux_connection_usable() {
    let cert = Certificate::new();
    let mut value = config(&cert);
    value["limits"]["max_udp_payload"] = json!(4);
    let server = Running::start(value).await;
    let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target_socket.local_addr().unwrap();
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let mut s = connect(&cert, &server, 0x11).await;

    // 未知会话：回无 Error 的 End，连接继续。
    send(&mut s, &frame(99, 2, None, false, Some(b"no"))).await;
    end(&mut s, 99, false).await;

    // 同一连接上的 TCP 会话是命令 3 的合法成员。
    send(
        &mut s,
        &tcp_frame(9, 1, Some(target(tcp.address)), Some(b"tcp")),
    )
    .await;
    expect_tcp(&mut s, 9, b"tcp").await;
    send(&mut s, &tcp_frame(9, 2, None, Some(b"more"))).await;
    expect_tcp(&mut s, 9, b"more").await;
    send(&mut s, &tcp_frame(9, 3, None, None)).await;

    // 超限 UDP 载荷只结束该会话，不结束 Mux 连接。
    send(&mut s, &frame(7, 1, Some(target(addr)), false, Some(b"ok"))).await;
    let mut buf = [0; 32];
    let (n, first) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ok");
    send(&mut s, &frame(7, 2, None, false, Some(b"long!"))).await;
    end(&mut s, 7, true).await;
    associations(&server, 0).await;
    let _first = rebind_udp(first).await;

    // 重复 New 替换旧会话，不发送 End；旧关联释放并建立新映射。
    send(
        &mut s,
        &frame(1, 1, Some(target(addr)), false, Some(b"old")),
    )
    .await;
    let (n, old) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"old");
    send(
        &mut s,
        &frame(1, 1, Some(target(addr)), false, Some(b"new")),
    )
    .await;
    let (n, new) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"new");
    assert_ne!(new, old);
    // 下行同样受 max_udp_payload=4 限制。
    target_socket.send_to(b"rep", new).await.unwrap();
    expect(&mut s, 1, addr, b"rep").await;
    let _old = rebind_udp(old).await;

    send(&mut s, &frame(1, 3, None, false, None)).await;
    associations(&server, 0).await;
    server.shutdown().await;
    let _new = rebind_udp(new).await;
}

#[tokio::test]
async fn malformed_frames_fail_closed_without_forwarding() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for bytes in [
        vec![2, 1],                     // metaLen 513
        vec![0, 4, 0, 0, 5, 0],         // 未知 status
        vec![0, 4, 0, 0, 1, 4],         // 未知 option
        vec![0, 5, 0, 0, 1, 0, 7],      // 未知 network
        frame(0, 1, None, false, None), // New 缺少目标
    ] {
        let mut s = connect(&cert, &server, 0x11).await;
        send(&mut s, &bytes).await;
        closed(&mut s).await;
        associations(&server, 0).await;
    }
    let mut buf = [0; 32];
    assert!(
        timeout(Duration::from_millis(50), target_socket.recv_from(&mut buf))
            .await
            .is_err()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn command_three_without_xudp_accepts_mux_but_gates_udp_per_session() {
    let cert = Certificate::new();
    let mut value = config(&cert);
    value["inbounds"][0]["xudp"] = json!(false);
    let server = Running::start(value).await;
    let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target_socket.local_addr().unwrap();
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let mut s = connect(&cert, &server, 0x11).await;
    send(
        &mut s,
        &frame(1, 1, Some(target(addr)), false, Some(b"denied")),
    )
    .await;
    end(&mut s, 1, true).await;
    associations(&server, 0).await;
    // UDP 被逐会话拒绝后，同一 Mux 连接仍可建立 TCP 会话。
    send(
        &mut s,
        &tcp_frame(2, 1, Some(target(tcp.address)), Some(b"tcp")),
    )
    .await;
    expect_tcp(&mut s, 2, b"tcp").await;
    server.shutdown().await;
    let mut buf = [0; 32];
    assert!(
        timeout(Duration::from_millis(50), target_socket.recv_from(&mut buf))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn source_filter_and_forced_stop_reclaim_sockets() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = destination.local_addr().unwrap();
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut s = connect(&cert, &server, 0x11).await;
    send(
        &mut s,
        &frame(5, 1, Some(target(addr)), false, Some(b"start")),
    )
    .await;
    let mut buf = [0; 64];
    let (_, peer) = destination.recv_from(&mut buf).await.unwrap();
    attacker.send_to(b"spoofed", peer).await.unwrap();
    destination.send_to(b"valid", peer).await.unwrap();
    expect(&mut s, 5, addr, b"valid").await;
    server.shutdown().await;
    closed(&mut s).await;
    let _rebound = rebind_udp(peer).await;
}

#[tokio::test]
async fn ipv6_xudp_when_available() {
    if UdpSocket::bind("[::1]:0").await.is_err() {
        eprintln!("SKIP IPv6 unavailable");
        return;
    }
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let echo = Echo::udp("[::1]").await;
    let mut s = connect(&cert, &server, 0x11).await;
    send(
        &mut s,
        &frame(65535, 1, Some(target(echo.address)), false, Some(b"v6")),
    )
    .await;
    expect(&mut s, 65535, echo.address, b"v6").await;
    server.shutdown().await;
}

/// Mux 子流的用户字节必须**等于**业务字节，不能因为外层承载也计数而翻倍。
///
/// 独立审查实测：5 字节业务配 Mux 后 `/stats` 为 5/5，而 `/stats/users`
/// 为 26/20——多出来的是 Mux 帧头，被外层 `UserCounted` 与子流各算一次。
#[tokio::test]
async fn mux_user_bytes_equal_business_payload() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let tcp = Echo::tcp("127.0.0.1", false).await;
    // identity 0x11 对应 users[0]（name = "one"）。
    let mut s = connect(&cert, &server, 0x11).await;

    let payload = b"hello";
    send(
        &mut s,
        &tcp_frame(1, 1, Some(target(tcp.address)), Some(payload)),
    )
    .await;
    expect_tcp(&mut s, 1, payload).await;
    send(&mut s, &tcp_frame(1, 2, None, None)).await;
    // 等统计落账：子流结束时才可能补计。
    tokio::time::sleep(Duration::from_millis(200)).await;

    let users = server.stats.user_snapshots();
    let one = users
        .iter()
        .find(|u| u.user == "one")
        .expect("one 应有条目");
    assert_eq!(
        one.uplink,
        payload.len() as u64,
        "上行必须等于业务字节（{}），实际 {}：说明外层承载也计了数",
        payload.len(),
        one.uplink
    );
    assert_eq!(
        one.downlink,
        payload.len() as u64,
        "下行必须等于业务字节（{}），实际 {}",
        payload.len(),
        one.downlink
    );

    drop(s);
    server.shutdown().await;
}

/// 同一 GlobalID 在不同账户之间必须隔离：不能复用对方的 UDP 关联，
/// 也不能把回包投到对方的连接上。
#[tokio::test]
async fn global_id_is_not_shared_across_accounts() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target_socket.local_addr().unwrap();
    let mut one = connect(&cert, &server, 0x11).await;
    let mut two = connect(&cert, &server, 0x22).await;
    let mut buf = [0; 64];

    send(
        &mut one,
        &frame_gid(0, 1, Some(target(addr)), [0x77; 8], Some(b"alice")),
    )
    .await;
    let (n, peer_one) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"alice");

    // 另一个账户声明同一个 GlobalID：必须得到不同的 UDP 关联。
    send(
        &mut two,
        &frame_gid(0, 1, Some(target(addr)), [0x77; 8], Some(b"bob")),
    )
    .await;
    let (n, peer_two) = target_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"bob");
    assert_ne!(peer_two, peer_one, "不同账户不得共用同一个 GlobalID 关联");

    // 回包各归各的连接。
    target_socket.send_to(b"for-bob", peer_two).await.unwrap();
    expect(&mut two, 0, addr, b"for-bob").await;
    target_socket.send_to(b"for-alice", peer_one).await.unwrap();
    expect(&mut one, 0, addr, b"for-alice").await;

    send(&mut one, &frame(0, 3, None, false, None)).await;
    send(&mut two, &frame(0, 3, None, false, None)).await;
    associations(&server, 0).await;
    server.shutdown().await;
}
