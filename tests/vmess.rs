#[path = "common/vmess.rs"]
mod client;
mod common;

use client::{Client, Request};
use common::*;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

fn config(cert: Option<&Certificate>) -> Value {
    let mut v = socks_config();
    let mut inbound = json!({"type":"vmess","tag":"vmess","listen":"127.0.0.1:0","users":[{"name":"test","uuid":client::UUID}]});
    if let Some(c) = cert {
        inbound["certificate"] = json!(c.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(c.dir.path().join("key.pem"));
    }
    v["inbounds"] = json!([inbound]);
    v
}
async fn idle(server: &Running) {
    timeout(Duration::from_secs(2), async {
        while server.stats.snapshot().connections != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn udp_count(server: &Running, n: usize) {
    timeout(Duration::from_secs(2), async {
        while server.stats.snapshot().udp_associations != n {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_direct_all_security_options_pipeline_half_close_and_payload_accounting() {
    let echo = Echo::tcp("127.0.0.1", true).await;
    let mut v = config(None);
    v["inbounds"][0]["allow_insecure_body"] = json!(true);
    v["inbounds"][0]["allow_authenticated_length"] = json!(true);
    let server = Running::start(v).await;
    let mut total = 0u64;
    for security in [3, 4, 5] {
        let options: &[u8] = if security == 5 {
            &[0, 1]
        } else {
            &[0, 1, 4, 5, 12, 13, 16, 17, 20, 21, 28, 29]
        };
        for &option in options {
            let io = TcpStream::connect(server.address).await.unwrap();
            let mut c = Client::start(
                io,
                Request::new(1, client::target(echo.address), security, option),
                Some(b"first-binary\x00\xff"),
            )
            .await;
            let data = vec![0x73; 20001];
            c.send(&data).await;
            c.finish().await;
            let mut expected = b"first-binary\x00\xff".to_vec();
            expected.extend(data);
            assert_eq!(
                c.read(expected.len()).await,
                expected,
                "security={security},options={option}"
            );
            c.eof().await;
            total += expected.len() as u64;
        }
    }
    idle(&server).await;
    let s = server.stats.snapshot();
    assert_eq!(s.uplink, total);
    assert_eq!(s.downlink, total);
    server.shutdown().await;
}

#[tokio::test]
async fn standard_tls_wire5_auto_equivalent_and_server_first_without_client_body() {
    let cert = Certificate::new();
    let server = Running::start(config(Some(&cert))).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target = tokio::spawn(async move {
        for _ in 0..4 {
            let (mut io, _) = listener.accept().await.unwrap();
            io.write_all(b"server-first").await.unwrap();
            let mut b = [0; 4];
            io.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"ping");
            io.shutdown().await.unwrap();
        }
    });
    for (security, options) in [(3, 13), (4, 5), (5, 0), (5, 1)] {
        let io = cert.connect(server.address).await;
        let mut c = Client::start(
            io,
            Request::new(
                1,
                client::domain("localhost", addr.port()),
                security,
                options,
            ),
            None,
        )
        .await;
        assert_eq!(c.read(12).await, b"server-first");
        c.send(b"ping").await;
        c.finish().await;
        c.eof().await;
    }
    timeout(Duration::from_secs(3), target)
        .await
        .unwrap()
        .unwrap();
    idle(&server).await;
    assert_eq!(server.stats.snapshot().uplink, 16);
    assert_eq!(server.stats.snapshot().downlink, 48);
    server.shutdown().await;
}

#[tokio::test]
async fn bad_identity_time_options_security_and_default_extensions_never_dial_or_reply() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap();
    let server = Running::start(config(None)).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut bad = vec![
        Request::at(1, client::target(addr), 3, 1, [0x33; 16], now, None),
        Request::at(1, client::target(addr), 3, 1, client::ID, now - 121, None),
        Request::at(1, client::target(addr), 3, 1, client::ID, now + 122, None),
        Request::new(1, client::target(addr), 5, 0),
        Request::new(1, client::target(addr), 5, 1),
        Request::new(1, client::target(addr), 3, 17),
        // 命令 3 现在合法进入 Mux，不能列为必须拒绝的输入。
        Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 3, 1),
    ];
    for security in [0, 1, 2, 6, 15] {
        bad.push(Request::new(1, client::target(addr), security, 1));
    }
    for options in [2, 8, 9, 32, 255] {
        bad.push(Request::new(1, client::target(addr), 3, options));
    }
    let mut tag = Request::new(1, client::target(addr), 3, 1);
    *tag.wire.last_mut().unwrap() ^= 1;
    bad.push(tag);
    for r in bad {
        let mut io = TcpStream::connect(server.address).await.unwrap();
        io.write_all(&r.wire).await.unwrap();
        client::closed(&mut io).await;
    }
    assert!(
        timeout(Duration::from_millis(40), target.accept())
            .await
            .is_err()
    );
    idle(&server).await;
    assert_eq!(server.stats.snapshot().uplink, 0);
    assert_eq!(server.stats.snapshot().downlink, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn native_udp_each_chunk_one_packet_security_matrix_and_empty_termination() {
    let echo = Echo::udp("127.0.0.1").await;
    let mut v = config(None);
    v["inbounds"][0]["allow_insecure_body"] = json!(true);
    v["inbounds"][0]["allow_authenticated_length"] = json!(true);
    let server = Running::start(v).await;
    let mut total = 0u64;
    for (security, options) in [(3, 0), (3, 13), (3, 29), (4, 1), (4, 5), (4, 28), (5, 1)] {
        let io = TcpStream::connect(server.address).await.unwrap();
        let mut c = Client::start(
            io,
            Request::new(2, client::target(echo.address), security, options),
            None,
        )
        .await;
        let a = b"first\x00\xff";
        let b = vec![0x5a; 4096];
        let mut wire = c.wire(a);
        wire.extend(c.wire(&b));
        wire.extend(c.wire(b"last"));
        c.io.write_all(&wire).await.unwrap();
        c.io.flush().await.unwrap();
        for expected in [a.as_slice(), b.as_slice(), b"last"] {
            assert_eq!(c.recv().await, expected);
            total += expected.len() as u64;
        }
        c.finish().await;
        client::closed(&mut c.io).await;
        drop(c);
        udp_count(&server, 0).await;
    }
    let s = server.stats.snapshot();
    assert_eq!(s.uplink, total);
    assert_eq!(s.downlink, total);
    server.shutdown().await;
}

#[tokio::test]
async fn native_udp_limits_bad_tag_truncation_idle_and_actual_source_filtering() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap();
    let mut v = config(None);
    v["limits"]["max_udp_payload"] = json!(16);
    v["limits"]["max_udp_associations"] = json!(1);
    v["limits"]["udp_idle_timeout_ms"] = json!(200);
    let server = Running::start(v).await;
    let mut c = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(2, client::target(addr), 3, 1),
        None,
    )
    .await;
    let mut extra = TcpStream::connect(server.address).await.unwrap();
    extra
        .write_all(&Request::new(2, client::target(addr), 3, 1).wire)
        .await
        .unwrap();
    client::closed(&mut extra).await;
    c.send(&[0x22; 17]).await;
    c.send(b"okay").await;
    let mut b = [0; 64];
    let (n, peer) = timeout(Duration::from_secs(2), target.recv_from(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"okay");
    let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    spoof.send_to(b"spoof", peer).await.unwrap();
    target.send_to(b"real", peer).await.unwrap();
    assert_eq!(c.recv().await, b"real");
    let mut malformed = c.wire(b"bad");
    *malformed.last_mut().unwrap() ^= 1;
    c.io.write_all(&malformed).await.unwrap();
    client::closed(&mut c.io).await;
    udp_count(&server, 0).await;
    assert!(server.stats.snapshot().dropped >= 1);
    assert_eq!(server.stats.snapshot().uplink, 4);
    assert_eq!(server.stats.snapshot().downlink, 4);
    let mut c = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(2, client::target(addr), 4, 5),
        None,
    )
    .await;
    let bytes = c.wire(b"truncated");
    c.io.write_all(&bytes[..bytes.len() - 1]).await.unwrap();
    c.io.shutdown().await.unwrap();
    client::closed(&mut c.io).await;
    udp_count(&server, 0).await;
    let mut c = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(2, client::target(addr), 3, 1),
        None,
    )
    .await;
    client::closed(&mut c.io).await;
    udp_count(&server, 0).await;
    server.shutdown().await;
    let _rebound = rebind_udp(peer).await;
}

#[tokio::test]
async fn packetaddr_ipv4_ipv6_interleaved_empty_payload_real_source_and_accounting() {
    let a = Echo::udp("127.0.0.1").await;
    let b = Echo::udp("::1").await;
    let mut v = config(None);
    v["inbounds"][0]["packetaddr"] = json!(true);
    let server = Running::start(v).await;
    let mut c = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 4, 13),
        None,
    )
    .await;
    for (addr, data) in [
        (a.address, b"v4".as_slice()),
        (b.address, b"v6".as_slice()),
        (a.address, b"".as_slice()),
        (b.address, b"".as_slice()),
    ] {
        let bytes = client::packetaddr(addr, data);
        c.send(&bytes).await;
        assert_eq!(c.recv().await, bytes);
    }
    assert_eq!(server.stats.snapshot().uplink, 4);
    assert_eq!(server.stats.snapshot().downlink, 4);
    server.shutdown().await;
}

#[tokio::test]
async fn packetaddr_bad_header_does_not_join_next_chunk_or_reach_target() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut v = config(None);
    v["inbounds"][0]["packetaddr"] = json!(true);
    let server = Running::start(v).await;
    for bad in [
        vec![1, 127, 0],
        vec![2; 18],
        vec![3; 19],
        vec![1, 127, 0, 0, 1, 0, 0],
    ] {
        let mut c = Client::start(
            TcpStream::connect(server.address).await.unwrap(),
            Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 3, 1),
            None,
        )
        .await;
        let mut wire = c.wire(&bad);
        wire.extend(c.wire(&client::packetaddr(
            target.local_addr().unwrap(),
            b"must-not-arrive",
        )));
        c.io.write_all(&wire).await.unwrap();
        client::closed(&mut c.io).await;
    }
    assert!(
        timeout(Duration::from_millis(40), target.recv_from(&mut [0; 64]))
            .await
            .is_err()
    );
    assert_eq!(server.stats.snapshot().uplink, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn mux_body_multisession_switch_end_reuse_and_tcp_session() {
    let a = Echo::udp("127.0.0.1").await;
    let b = Echo::udp("127.0.0.1").await;
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let mut v = config(None);
    v["inbounds"][0]["xudp"] = json!(true);
    let server = Running::start(v).await;
    let mut c = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(3, vec![], 3, 13),
        None,
    )
    .await;
    c.send(&client::xframe_gid(
        7,
        1,
        Some(client::target(a.address)),
        [0x11; 8],
        Some(b"first"),
    ))
    .await;
    client::xexpect(&mut c, 7, a.address, b"first").await;
    let mut frames = client::xframe(9, 1, Some(client::target(b.address)), false, Some(b"other"));
    frames.extend(client::xframe(
        7,
        2,
        Some(client::target(b.address)),
        false,
        Some(b"switch"),
    ));
    c.send(&frames).await;
    let mut seen = vec![];
    for _ in 0..2 {
        let (m, p) = client::xrecv(&mut c).await;
        seen.push((u16::from_be_bytes([m[0], m[1]]), p));
    }
    seen.sort();
    assert_eq!(seen, vec![(7, b"switch".to_vec()), (9, b"other".to_vec())]);
    let frame = client::xframe(7, 2, None, false, Some(b"initial"));
    for byte in frame {
        c.send(&[byte]).await;
    }
    client::xexpect(&mut c, 7, a.address, b"initial").await;
    c.send(&client::xframe(7, 3, None, false, None)).await;
    udp_count(&server, 1).await;
    c.send(&client::xframe_gid(
        7,
        1,
        Some(client::target(a.address)),
        [0x11; 8],
        Some(b"reuse"),
    ))
    .await;
    client::xexpect(&mut c, 7, a.address, b"reuse").await;
    // 命令 3 是完整 Mux：同一 VMess 正文上的 TCP New 也是合法会话。
    let mut tcp_new = client::xframe(
        10,
        1,
        Some(client::target(tcp.address)),
        false,
        Some(b"tcp"),
    );
    tcp_new[6] = 1;
    c.send(&tcp_new).await;
    let (metadata, payload) = client::xrecv(&mut c).await;
    assert_eq!(metadata, [0, 10, 2, 1]);
    assert_eq!(payload, b"tcp");
    c.send(&client::xframe(10, 2, None, false, Some(b"more")))
        .await;
    let (metadata, payload) = client::xrecv(&mut c).await;
    assert_eq!(metadata, [0, 10, 2, 1]);
    assert_eq!(payload, b"more");
    c.send(&client::xframe(10, 3, None, false, None)).await;
    // TCP 会话结束后，原 UDP 会话仍可继续使用。
    c.send(&client::xframe(7, 2, None, false, Some(b"after")))
        .await;
    client::xexpect(&mut c, 7, a.address, b"after").await;
    server.shutdown().await;
}

#[tokio::test]
async fn global_id_takeover_moves_sink_and_old_vmess_session_gets_error() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap();
    let mut v = config(None);
    v["inbounds"][0]["xudp"] = json!(true);
    let server = Running::start(v).await;
    let mut one = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(3, vec![], 4, 5),
        None,
    )
    .await;
    let mut two = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(3, vec![], 4, 5),
        None,
    )
    .await;
    let mut b = [0; 32];
    one.send(&client::xframe_gid(
        0,
        1,
        Some(client::target(addr)),
        [0x22; 8],
        Some(b"one"),
    ))
    .await;
    let (n, shared) = timeout(Duration::from_secs(2), target.recv_from(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"one");
    // 同一 GlobalID 跨连接复用关联并迁移 sink；旧会话收到 End+Error。
    two.send(&client::xframe_gid(
        0,
        1,
        Some(client::target(addr)),
        [0x22; 8],
        Some(b"two"),
    ))
    .await;
    let (n, second) = timeout(Duration::from_secs(2), target.recv_from(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"two");
    assert_eq!(second, shared);
    let (metadata, payload) = client::xrecv(&mut one).await;
    assert_eq!(metadata, [0, 0, 3, 2]);
    assert!(payload.is_empty());
    target.send_to(b"reply-two", shared).await.unwrap();
    client::xexpect(&mut two, 0, addr, b"reply-two").await;

    // 旧 VMess 承载仍可继续承载其他无 GlobalID 会话。
    one.send(&client::xframe(
        7,
        1,
        Some(client::target(addr)),
        false,
        Some(b"other"),
    ))
    .await;
    let (n, other) = timeout(Duration::from_secs(2), target.recv_from(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"other");
    assert_ne!(other, shared);
    target.send_to(b"reply-other", other).await.unwrap();
    client::xexpect(&mut one, 7, addr, b"reply-other").await;

    two.send(&client::xframe(0, 3, None, false, None)).await;
    udp_count(&server, 1).await;
    // 宽限期内映射与源端口仍由全局关联持有，不能被重新绑定。
    assert!(
        UdpSocket::bind(shared).await.is_err(),
        "宽限期内不应释放源端口"
    );
    two.send(&client::xframe_gid(
        0,
        1,
        Some(client::target(addr)),
        [0x22; 8],
        Some(b"new"),
    ))
    .await;
    let (_, fresh) = timeout(Duration::from_secs(2), target.recv_from(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fresh, shared, "宽限期内必须复用同一 UDP 关联");
    target.send_to(b"fresh", fresh).await.unwrap();
    client::xexpect(&mut two, 0, addr, b"fresh").await;

    one.send(&client::xframe(7, 3, None, false, None)).await;
    two.send(&client::xframe(0, 3, None, false, None)).await;
    udp_count(&server, 0).await;
    // 实例停机主动释放宽限期关联后，源端口才可用。
    server.shutdown().await;
    let _free1 = rebind_udp(fresh).await;
    let _free2 = rebind_udp(other).await;
}

#[tokio::test]
async fn replay_identity_shared_between_inbounds_session_material_and_capacity_fail_closed() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut v = config(None);
    let mut second = v["inbounds"][0].clone();
    second["tag"] = json!("other");
    v["inbounds"].as_array_mut().unwrap().push(second);
    v["limits"]["max_vmess_replay_entries"] = json!(4);
    let server = Running::start(v).await;
    let r = Request::new(1, client::target(echo.address), 3, 1);
    let mut c = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        r.clone(),
        None,
    )
    .await;
    c.send(b"good").await;
    assert_eq!(c.read(4).await, b"good");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for r in [
        r.clone(),
        Request::at(
            1,
            client::target(echo.address),
            3,
            1,
            client::ID,
            now,
            Some((r.key, r.iv)),
        ),
        Request::new(1, client::target(echo.address), 3, 1),
    ] {
        let mut io = TcpStream::connect(server.addresses[1]).await.unwrap();
        io.write_all(&r.wire).await.unwrap();
        client::closed(&mut io).await;
    }
    c.send(b"live").await;
    assert_eq!(c.read(4).await, b"live");
    server.shutdown().await;
    for capacity in [1, 2] {
        let mut v = config(None);
        v["limits"]["max_vmess_replay_entries"] = json!(capacity);
        let server = Running::start(v).await;
        let mut io = TcpStream::connect(server.address).await.unwrap();
        let r = Request::new(1, client::target(echo.address), 3, 1);
        if capacity == 1 {
            io.write_all(&r.wire).await.unwrap();
            client::closed(&mut io).await;
        } else {
            let mut c = Client::start(io, r, None).await;
            c.send(b"two").await;
            assert_eq!(c.read(3).await, b"two");
        }
        server.shutdown().await;
    }
}

#[tokio::test]
async fn mixed_shared_connection_handshake_udp_limits_and_force_join_ports() {
    let echo = Echo::udp("127.0.0.1").await;
    let mut v = config(None);
    v["inbounds"][0]["packetaddr"] = json!(true);
    v["inbounds"][0]["xudp"] = json!(true);
    v["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}));
    v["limits"]["max_connections"] = json!(6);
    v["limits"]["max_handshakes"] = json!(1);
    v["limits"]["max_udp_associations"] = json!(3);
    v["limits"]["handshake_timeout_ms"] = json!(10000);
    v["limits"]["udp_idle_timeout_ms"] = json!(10000);
    v["limits"]["shutdown_timeout_ms"] = json!(20);
    let server = Running::start(v).await;
    let mut native = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(2, client::target(echo.address), 3, 1),
        None,
    )
    .await;
    native.send(b"native").await;
    assert_eq!(native.recv().await, b"native");
    let mut packet = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 4, 5),
        None,
    )
    .await;
    packet
        .send(&client::packetaddr(echo.address, b"packet"))
        .await;
    assert_eq!(
        packet.recv().await,
        client::packetaddr(echo.address, b"packet")
    );
    let mut xudp = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(3, vec![], 3, 13),
        None,
    )
    .await;
    xudp.send(&client::xframe(
        1,
        1,
        Some(client::target(echo.address)),
        false,
        Some(b"xudp"),
    ))
    .await;
    client::xexpect(&mut xudp, 1, echo.address, b"xudp").await;
    let mut socks = TcpStream::connect(server.addresses[1]).await.unwrap();
    socks.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    read_exact(&mut socks, &mut method).await;
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 3, 0];
    request.extend(common::address("0.0.0.0:0".parse().unwrap()));
    socks.write_all(&request).await.unwrap();
    let mut failure = [0; 10];
    read_exact(&mut socks, &mut failure).await;
    assert_eq!(&failure[..3], &[5, 1, 0]);
    client::closed(&mut socks).await;
    // 认证完成后的半body不再占握手许可；半头仍占本入口许可。
    native.io.write_all(&[0]).await.unwrap();
    let mut half = TcpStream::connect(server.address).await.unwrap();
    half.write_all(&[0; 8]).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while server.stats.snapshot().connections < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut denied = TcpStream::connect(server.address).await.unwrap();
    denied
        .write_all(&Request::new(1, client::target(echo.address), 3, 1).wire)
        .await
        .unwrap();
    client::closed(&mut denied).await;
    let addresses = server.addresses.clone();
    assert!(server.stats.snapshot().connections >= 4);
    assert_eq!(server.stats.snapshot().udp_associations, 3);
    server.shutdown().await;
    for addr in addresses {
        let _free = TcpListener::bind(addr).await.unwrap();
    }
}

#[tokio::test]
async fn documented_vmess_templates_cli_check_and_real_start_after_placeholder_replacement() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    for (tls, text) in [
        (false, include_str!("../examples/vmess.json")),
        (true, include_str!("../examples/vmess-tls.json")),
    ] {
        let mut value: Value = serde_json::from_str(text).unwrap();
        value["inbounds"][0]["listen"] = json!("127.0.0.1:0");
        value["inbounds"][0]["users"][0]["uuid"] = json!(client::UUID);
        if tls {
            value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
            value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::write(&path, value.to_string()).unwrap();
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_dubhe"))
            .arg("check")
            .arg("-c")
            .arg(path)
            .output()
            .unwrap();
        assert!(result.status.success(), "{:?}", result);
        let server = Running::start(value).await;
        let request = Request::new(1, client::target(echo.address), 3, 13);
        if tls {
            let mut c = Client::start(cert.connect(server.address).await, request, None).await;
            c.send(b"documented-vmess-tls").await;
            assert_eq!(c.read(20).await, b"documented-vmess-tls");
        } else {
            let mut c = Client::start(
                TcpStream::connect(server.address).await.unwrap(),
                request,
                None,
            )
            .await;
            c.send(b"documented-vmess").await;
            assert_eq!(c.read(16).await, b"documented-vmess");
        }
        server.shutdown().await;
    }
}

#[tokio::test]
async fn security_five_native_udp_and_xudp_raw_chunked_work_on_actual_tls() {
    let cert = Certificate::new();
    let echo = Echo::udp("127.0.0.1").await;
    let mut value = config(Some(&cert));
    value["inbounds"][0]["xudp"] = json!(true);
    let server = Running::start(value).await;
    for options in [0, 1] {
        let mut c = Client::start(
            cert.connect(server.address).await,
            Request::new(3, vec![], 5, options),
            None,
        )
        .await;
        c.send(&client::xframe(
            1,
            1,
            Some(client::target(echo.address)),
            false,
            Some(b"tls-five"),
        ))
        .await;
        client::xexpect(&mut c, 1, echo.address, b"tls-five").await;
    }
    let mut native = Client::start(
        cert.connect(server.address).await,
        Request::new(2, client::target(echo.address), 5, 1),
        None,
    )
    .await;
    native.send(b"tls-native-five").await;
    assert_eq!(native.recv().await, b"tls-native-five");
    server.shutdown().await;
}

#[tokio::test]
async fn native_and_packetaddr_large_datagrams_keep_boundaries_near_wire_limits() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let options = socket2::SockRef::from(&socket);
    options.set_send_buffer_size(131072).unwrap();
    options.set_recv_buffer_size(131072).unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let mut bytes = vec![0; 65536];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            assert_eq!(socket.send_to(&bytes[..n], peer).await.unwrap(), n);
        }
    });
    let mut value = config(None);
    value["inbounds"][0]["packetaddr"] = json!(true);
    value["inbounds"][0]["allow_authenticated_length"] = json!(true);
    value["limits"]["udp_idle_timeout_ms"] = json!(3000);
    let server = Running::start(value).await;
    // 上下行padding序列不同，带P按最坏63字节保守取值；不能只为
    // 测试端当前padding选长度而假定服务端同值。A无P可承载65507+7。
    for (packetaddr, options, size) in [
        (false, 1, 65507),
        (false, 13, 65456),
        (true, 13, 65449),
        (true, 17, 65507),
        (true, 29, 65465),
    ] {
        let target = if packetaddr {
            client::domain("sp.packet-addr.v2fly.arpa", 0)
        } else {
            client::target(address)
        };
        let mut c = Client::start(
            TcpStream::connect(server.address).await.unwrap(),
            Request::new(2, target, 3, options),
            None,
        )
        .await;
        let payload = vec![0x64; size];
        let bytes = if packetaddr {
            client::packetaddr(address, &payload)
        } else {
            payload
        };
        c.send(&bytes).await;
        assert_eq!(c.recv().await, bytes);
        let expected = if packetaddr {
            client::packetaddr(address, b"after")
        } else {
            b"after".to_vec()
        };
        c.send(&expected).await;
        assert_eq!(c.recv().await, expected);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn packetaddr_reply_too_large_is_dropped_without_consuming_next_nonce() {
    let socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let options = socket2::SockRef::from(&socket);
    options.set_send_buffer_size(131072).unwrap();
    options.set_recv_buffer_size(131072).unwrap();
    let mut value = config(None);
    value["inbounds"][0]["packetaddr"] = json!(true);
    let server = Running::start(value).await;
    let mut c = Client::start(
        TcpStream::connect(server.address).await.unwrap(),
        Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 3, 1),
        None,
    )
    .await;
    c.send(&client::packetaddr(address, b"trigger")).await;
    let mut bytes = [0; 32];
    let (n, peer) = timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], b"trigger");
    // 65507业务 + IPv6头19 + tag16 > u16长度上限，不能发送或拆成两包。
    socket.send_to(&vec![0x66; 65507], peer).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while server.stats.snapshot().dropped == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    socket.send_to(b"after", peer).await.unwrap();
    assert_eq!(c.recv().await, client::packetaddr(address, b"after"));
    assert_eq!(server.stats.snapshot().downlink, 5);
    assert_eq!(server.stats.snapshot().uplink, 7);
    server.shutdown().await;
}

#[tokio::test]
async fn shared_global_connections_reject_old_listener_then_recover_after_auth_timeout() {
    let mut v = config(None);
    v["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}));
    v["limits"]["max_connections"] = json!(1);
    v["limits"]["handshake_timeout_ms"] = json!(150);
    let server = Running::start(v).await;
    let mut half = TcpStream::connect(server.address).await.unwrap();
    half.write_all(&[0; 8]).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while server.stats.snapshot().connections != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut old = TcpStream::connect(server.addresses[1]).await.unwrap();
    client::closed(&mut old).await;
    client::closed(&mut half).await;
    idle(&server).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let (mut old, _) = common::socks(1, common::address(echo.address), server.addresses[1]).await;
    exchange(&mut old, b"recovered").await;
    drop(old);
    server.shutdown().await;
}

/// VMess 命令 2（fixed 单目标 UDP）经 SOCKS5 出站转发。
///
/// 修复前 `src/udp/vmess.rs` 在握手期调用 `ctx.allowed()`，它内部是
/// `selected(..., allow_udp_proxy: false)`——选到代理出站就直接返回
/// `Unsupported`，使 fixed 模式在链式部署下握手即失败。而数据面
/// （`Association::send`）本来就用 `udp_selected`、允许代理，两侧不一致。
#[tokio::test]
async fn native_udp_fixed_target_relays_through_a_socks5_outbound() {
    // 落地机：SOCKS5 入口，出站直连。
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "up", "listen": "127.0.0.1:0"}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;

    // 中转机：VMess 入口，全部经 SOCKS5 出站。
    let echo = Echo::udp("127.0.0.1").await;
    let mut v = config(None);
    v["outbounds"] = json!([
        {"type": "direct", "tag": "direct"},
        {"type": "socks5", "tag": "up", "endpoint": upstream.address.to_string()}
    ]);
    v["route"] = json!({"default": "up"});
    let server = Running::start(v).await;

    let io = TcpStream::connect(server.address).await.unwrap();
    let mut c = Client::start(
        io,
        Request::new(2, client::target(echo.address), 3, 0),
        None,
    )
    .await;
    let payload = b"vmess-via-socks";
    let frame = c.wire(payload);
    c.io.write_all(&frame).await.unwrap();
    c.io.flush().await.unwrap();
    assert_eq!(c.recv().await, payload, "经 SOCKS5 出站的 UDP 回程应一致");
    c.finish().await;

    drop(c);
    idle(&server).await;
    server.shutdown().await;
    upstream.shutdown().await;
}
