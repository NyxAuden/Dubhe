mod common;
#[path = "common/reality.rs"]
mod peer;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Echo, Running, socks_config};
use peer::{ClientOptions, Outer, PreparedClient, TargetGroup, TargetOptions, TargetPeer};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

fn config(target: SocketAddr, vision: bool, mldsa: bool) -> Value {
    let mut value = socks_config();
    value["limits"]["handshake_timeout_ms"] = json!(3000);
    value["inbounds"] = json!([{"type":"vless-reality","tag":"reality","listen":"127.0.0.1:0",
        "xudp":true,"users":[{"name":"test","uuid":peer::UUID,"flow":if vision {"xtls-rprx-vision"} else {""}}],
        "reality":{"target":{"host":target.ip().to_string(),"port":target.port()},
            "private_key":URL_SAFE_NO_PAD.encode(peer::SERVER_PRIVATE_KEY),
            "server_names":["localhost"],"short_ids":["8172635445362718"]}}]);
    if mldsa {
        value["inbounds"][0]["reality"]["mldsa65_seed"] = json!(URL_SAFE_NO_PAD.encode([0x42; 32]));
    }
    value
}
fn options(ordinary: bool, mldsa: bool) -> ClientOptions {
    use aws_lc_rs::signature::{KeyPair, ML_DSA_65_SIGNING, PqdsaKeyPair};
    ClientOptions {
        ordinary_share: ordinary,
        mldsa65_public_key: mldsa.then(|| {
            PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &[0x42; 32])
                .unwrap()
                .public_key()
                .as_ref()
                .to_vec()
        }),
        ..Default::default()
    }
}
async fn idle(server: &Running) {
    timeout(Duration::from_secs(3), async {
        while server.stats.snapshot().connections != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn block(client: &mut Outer, first: bool) -> (u8, Vec<u8>) {
    if first {
        assert_eq!(client.plain(16).await.unwrap(), peer::ID);
    }
    let h = client.plain(5).await.unwrap();
    let n = u16::from_be_bytes([h[1], h[2]]) as usize;
    let padding = u16::from_be_bytes([h[3], h[4]]) as usize;
    let payload = client.plain(n).await.unwrap();
    client.plain(padding).await.unwrap();
    (h[0], payload)
}
fn address(target: SocketAddr) -> Vec<u8> {
    let mut out = target.port().to_be_bytes().to_vec();
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            out.push(1);
            out.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(3);
            out.extend(ip.octets());
        }
    }
    out
}
fn xudp(id: u16, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([1, 1, 2]);
    metadata.extend(address(target));
    let mut out = (metadata.len() as u16).to_be_bytes().to_vec();
    out.extend(metadata);
    out.extend((payload.len() as u16).to_be_bytes());
    out.extend(payload);
    out
}
async fn xudp_response(client: &mut Outer) -> (Vec<u8>, Vec<u8>) {
    let h = client.plain(2).await.unwrap();
    let metadata = client
        .plain(u16::from_be_bytes([h[0], h[1]]) as usize)
        .await
        .unwrap();
    let h = client.plain(2).await.unwrap();
    let body = client
        .plain(u16::from_be_bytes([h[0], h[1]]) as usize)
        .await
        .unwrap();
    (metadata, body)
}

#[tokio::test]
async fn tcp_plain_all_groups_auth_shares_mldsa_halfclose_and_payload_only_accounting() {
    for (group, ordinary) in [
        (TargetGroup::X25519, true),
        (TargetGroup::Hybrid, true),
        (TargetGroup::Hybrid, false),
    ] {
        for mldsa in [false, true] {
            let target = TargetPeer::start(TargetOptions {
                group,
                ..Default::default()
            })
            .await
            .unwrap();
            let server = Running::start(config(target.address, false, mldsa)).await;
            let echo = Echo::tcp("127.0.0.1", true).await;
            let mut client = PreparedClient::new(options(ordinary, mldsa))
                .unwrap()
                .connect(server.address)
                .await
                .unwrap();
            let mut request = peer::vless_request(1, None, peer::ID, echo.address);
            request.extend(b"first\0\xff");
            client.send(&request).await.unwrap();
            assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
            let more = vec![0x67; 20001];
            client.send(&more).await.unwrap();
            client.close_notify().await.unwrap();
            let mut expected = b"first\0\xff".to_vec();
            expected.extend(more);
            assert_eq!(client.plain(expected.len()).await.unwrap(), expected);
            {
                let log = client.log.lock().unwrap();
                assert!(!log.raw_sh.is_empty());
            }
            drop(client);
            idle(&server).await;
            let stats = server.stats.snapshot();
            assert_eq!(stats.uplink, expected.len() as u64);
            assert_eq!(stats.downlink, expected.len() as u64);
            assert_eq!(stats.udp_associations, 0);
            server.shutdown().await;
            target.shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
async fn example_placeholder_replacement_real_check_start_and_vision_data() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let mut value: Value =
        serde_json::from_str(include_str!("../examples/vless-reality.json")).unwrap();
    assert!(dubhe::Config::from_json(&value.to_string()).is_err());
    value["inbounds"][0]["listen"] = json!("127.0.0.1:0");
    value["inbounds"][0]["users"][0]["uuid"] = json!(peer::UUID);
    value["inbounds"][0]["reality"]["private_key"] =
        json!(URL_SAFE_NO_PAD.encode(peer::SERVER_PRIVATE_KEY));
    value["inbounds"][0]["reality"]["short_ids"] = json!(["8172635445362718"]);
    value["inbounds"][0]["reality"]["target"]["port"] = json!(target.address.port());
    let cfg = dubhe::Config::from_json(&value.to_string()).unwrap();
    dubhe::Server::check(&cfg).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("reality.json");
    std::fs::write(&file, value.to_string()).unwrap();
    let checked = std::process::Command::new(env!("CARGO_BIN_EXE_dubhe"))
        .args(["check", "-c"])
        .arg(file)
        .output()
        .unwrap();
    assert!(checked.status.success());
    let server = Running::start(value).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut c = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    let mut request = peer::vless_request(1, Some("xtls-rprx-vision"), peer::ID, echo.address);
    request.extend(peer::vision_block(true, 1, b"example", 0));
    c.send(&request).await.unwrap();
    assert_eq!(c.plain(2).await.unwrap(), [0, 0]);
    assert_eq!(block(&mut c, true).await.1, b"example");
    drop(c);
    idle(&server).await;
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_server_first_without_body_and_reject_before_business_dial_or_response() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let business = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"server-first").await.unwrap();
        let mut bytes = [0; 4];
        socket.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
    });
    let server = Running::start(config(target.address, false, false)).await;
    let mut c = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    c.send(&peer::vless_request(1, None, peer::ID, business))
        .await
        .unwrap();
    assert_eq!(c.plain(14).await.unwrap(), b"\0\0server-first");
    c.send(b"ping").await.unwrap();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    drop(c);
    idle(&server).await;
    server.shutdown().await;
    let mut v = config(target.address, false, false);
    v["route"]["default"] = json!("reject");
    let server = Running::start(v).await;
    let denied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut c = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    c.send(&peer::vless_request(
        1,
        None,
        peer::ID,
        denied.local_addr().unwrap(),
    ))
    .await
    .unwrap();
    assert!(c.plain(2).await.is_err());
    assert!(
        timeout(Duration::from_millis(50), denied.accept())
            .await
            .is_err()
    );
    drop(c);
    idle(&server).await;
    assert_eq!(
        (
            server.stats.snapshot().uplink,
            server.stats.snapshot().downlink
        ),
        (0, 0)
    );
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn native_udp_ipv4_ipv6_boundaries_empty_drop_and_actual_payload_counting() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let server = Running::start(config(target.address, false, false)).await;
    let mut total = 0;
    for ip in ["127.0.0.1", "::1"] {
        let echo = Echo::udp(ip).await;
        let mut c = PreparedClient::new(Default::default())
            .unwrap()
            .connect(server.address)
            .await
            .unwrap();
        let mut request = peer::vless_request(2, None, peer::ID, echo.address);
        request.extend([0, 0]); // 空包丢弃，不影响下一个数据报。
        for body in [b"one".as_slice(), b"two-binary\0\xff".as_slice()] {
            request.extend((body.len() as u16).to_be_bytes());
            request.extend(body);
        }
        c.send(&request).await.unwrap();
        assert_eq!(c.plain(2).await.unwrap(), [0, 0]);
        for body in [b"one".as_slice(), b"two-binary\0\xff".as_slice()] {
            assert_eq!(c.plain(2).await.unwrap(), (body.len() as u16).to_be_bytes());
            assert_eq!(c.plain(body.len()).await.unwrap(), body);
            total += body.len() as u64;
        }
        drop(c);
    }
    idle(&server).await;
    assert_eq!(
        (
            server.stats.snapshot().uplink,
            server.stats.snapshot().downlink
        ),
        (total, total)
    );
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn xudp_plain_and_vision_multitarget_no_duplicate_response() {
    for vision in [false, true] {
        let target = TargetPeer::start(Default::default()).await.unwrap();
        let server = Running::start(config(target.address, vision, false)).await;
        let a = Echo::udp("127.0.0.1").await;
        let b = Echo::udp("::1").await;
        let mut c = PreparedClient::new(Default::default())
            .unwrap()
            .connect(server.address)
            .await
            .unwrap();
        let mut request =
            peer::vless_request(3, vision.then_some("xtls-rprx-vision"), peer::ID, a.address);
        let mut frames = xudp(7, a.address, b"first");
        frames.extend(xudp(9, b.address, b"second"));
        request.extend(if vision {
            peer::vision_block(true, 1, &frames, 13)
        } else {
            frames
        });
        c.send(&request).await.unwrap();
        assert_eq!(c.plain(2).await.unwrap(), [0, 0]);
        let mut seen = Vec::new();
        if vision {
            let (command, body) = block(&mut c, true).await;
            assert_eq!(command, 1);
            let mut body = body.as_slice();
            loop {
                let n = body.read_u16().await.unwrap() as usize;
                let mut metadata = vec![0; n];
                body.read_exact(&mut metadata).await.unwrap();
                let n = body.read_u16().await.unwrap() as usize;
                let mut payload = vec![0; n];
                body.read_exact(&mut payload).await.unwrap();
                seen.push((metadata, payload));
                if body.is_empty() {
                    break;
                }
            }
            if seen.len() == 1 {
                seen.push(xudp_response(&mut c).await);
            }
        } else {
            seen.push(xudp_response(&mut c).await);
            seen.push(xudp_response(&mut c).await);
        }
        seen.sort_by_key(|(m, _)| m[..2].to_vec());
        assert_eq!(seen[0].1, b"first");
        assert_eq!(seen[1].1, b"second");
        assert_eq!(&seen[0].0[5..], address(a.address));
        assert_eq!(&seen[1].0[5..], address(b.address));
        drop(c);
        idle(&server).await;
        assert_eq!(
            (
                server.stats.snapshot().uplink,
                server.stats.snapshot().downlink
            ),
            (11, 11)
        );
        server.shutdown().await;
        target.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn vision_direct_drains_last_tls_tail_then_raw_reverse_stays_tls() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let server = Running::start(config(target.address, true, false)).await;
    let echo = Echo::tcp("127.0.0.1", true).await;
    let mut c = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    let mut request = peer::vless_request(1, Some("xtls-rprx-vision"), peer::ID, echo.address);
    request.extend(peer::vision_block(true, 2, b"direct", 7));
    request.extend(b"tail");
    // 一次原始 socket write 合并最后一条外层 record 与首批 Direct 原文。
    std::io::Write::write_all(&mut c.tls.writer(), &request).unwrap();
    let mut wire = Vec::new();
    while c.tls.wants_write() {
        c.tls.write_tls(&mut wire).unwrap();
    }
    wire.extend(b"raw");
    c.io.write_all(&wire).await.unwrap();
    c.io.shutdown().await.unwrap();
    assert_eq!(c.plain(2).await.unwrap(), [0, 0]);
    let (command, body) = block(&mut c, true).await;
    assert_eq!(command, 1);
    assert_eq!(body, b"directtailraw");
    drop(c);
    idle(&server).await;
    assert_eq!(
        (
            server.stats.snapshot().uplink,
            server.stats.snapshot().downlink
        ),
        (13, 13)
    );
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

fn inner_output(inner: &mut rustls::ClientConnection) -> Vec<u8> {
    let mut wire = Vec::new();
    while inner.wants_write() {
        inner.write_tls(&mut wire).unwrap();
    }
    wire
}
fn inner_input(inner: &mut rustls::ClientConnection, wire: &[u8]) {
    let mut wire = wire;
    while !wire.is_empty() {
        assert!(inner.read_tls(&mut wire).unwrap() > 0);
        inner.process_new_packets().unwrap();
    }
}

#[tokio::test]
async fn real_inner_tls12_end_and_tls13_direct_both_directions_on_reality() {
    use std::sync::Arc;
    for tls13 in [false, true] {
        let target = TargetPeer::start(Default::default()).await.unwrap();
        let server = Running::start(config(target.address, true, false)).await;
        let certificate = common::Certificate::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut inner_server = (*dubhe::tls::load(
            &certificate.dir.path().join("cert.pem"),
            &certificate.dir.path().join("key.pem"),
        )
        .unwrap())
        .clone();
        inner_server.send_tls13_tickets = 0;
        let inner_peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(inner_server))
                .accept(socket)
                .await
                .unwrap();
            stream.write_all(b"hello-inner").await.unwrap();
            stream.flush().await.unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.der.clone()).unwrap();
        let version = if tls13 {
            &rustls::version::TLS13
        } else {
            &rustls::version::TLS12
        };
        let inner_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        timeout(Duration::from_secs(6), async {
            let mut outer = PreparedClient::new(Default::default())
                .unwrap()
                .connect(server.address)
                .await
                .unwrap();
            let mut inner = rustls::ClientConnection::new(
                Arc::new(inner_config),
                "localhost".try_into().unwrap(),
            )
            .unwrap();
            let mut request = peer::vless_request(1, Some("xtls-rprx-vision"), peer::ID, address);
            request.extend(peer::vision_block(true, 0, &inner_output(&mut inner), 5));
            outer.send(&request).await.unwrap();
            assert_eq!(outer.plain(2).await.unwrap(), [0, 0]);
            let mut first = true;
            let mut mode = 0;
            let mut greeting = Vec::new();
            while inner.is_handshaking() || greeting.len() < 11 {
                let wire = match mode {
                    0 => {
                        let (command, body) = block(&mut outer, first).await;
                        first = false;
                        mode = command;
                        body
                    }
                    1 => {
                        let mut h = outer.plain(5).await.unwrap();
                        let n = u16::from_be_bytes([h[3], h[4]]) as usize;
                        h.extend(outer.plain(n).await.unwrap());
                        h
                    }
                    2 => peer::raw_record(&mut outer.io).await.unwrap(),
                    _ => panic!("unexpected Vision command"),
                };
                inner_input(&mut inner, &wire);
                let output = inner_output(&mut inner);
                if !output.is_empty() {
                    outer
                        .send(&peer::vision_block(false, 0, &output, 0))
                        .await
                        .unwrap();
                }
                let mut buffer = [0; 64];
                match std::io::Read::read(&mut inner.reader(), &mut buffer) {
                    Ok(n) => greeting.extend_from_slice(&buffer[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => panic!("inner TLS plaintext failed"),
                }
            }
            assert_eq!(greeting, b"hello-inner");
            assert_eq!(mode, if tls13 { 2 } else { 1 });
            std::io::Write::write_all(&mut inner.writer(), b"ping").unwrap();
            let output = inner_output(&mut inner);
            if tls13 {
                outer
                    .send(&peer::vision_block(false, 2, &[], 0))
                    .await
                    .unwrap();
                outer.io.write_all(&output).await.unwrap();
            } else {
                outer
                    .send(&peer::vision_block(false, 1, &output, 0))
                    .await
                    .unwrap();
            }
            let mut pong = Vec::new();
            while pong.len() < 4 {
                let wire = if tls13 {
                    peer::raw_record(&mut outer.io).await.unwrap()
                } else {
                    let mut h = outer.plain(5).await.unwrap();
                    let n = u16::from_be_bytes([h[3], h[4]]) as usize;
                    h.extend(outer.plain(n).await.unwrap());
                    h
                };
                inner_input(&mut inner, &wire);
                let mut bytes = [0; 4];
                match std::io::Read::read(&mut inner.reader(), &mut bytes) {
                    Ok(n) => pong.extend_from_slice(&bytes[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => panic!("inner TLS pong failed"),
                }
            }
            assert_eq!(pong, b"pong");
            inner_peer.await.unwrap();
            drop(outer);
        })
        .await
        .unwrap();
        idle(&server).await;
        server.shutdown().await;
        target.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn vision_end_single_record_then_unframed_payload_and_half_close() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let server = Running::start(config(target.address, true, false)).await;
    let echo = Echo::tcp("127.0.0.1", true).await;
    let mut c = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    let mut request = peer::vless_request(1, Some("xtls-rprx-vision"), peer::ID, echo.address);
    request.extend(peer::vision_block(true, 1, b"framed", 17));
    request.extend(b"same-record-tail");
    c.send(&request).await.unwrap();
    assert_eq!(c.plain(2).await.unwrap(), [0, 0]);
    c.send(b"next-record").await.unwrap();
    c.close_notify().await.unwrap();
    let mut received = block(&mut c, true).await.1;
    let expected = b"framedsame-record-tailnext-record";
    while received.len() < expected.len() {
        received.extend(c.plain(expected.len() - received.len()).await.unwrap());
    }
    assert_eq!(received, expected);
    drop(c);
    idle(&server).await;
    assert_eq!(
        (
            server.stats.snapshot().uplink,
            server.stats.snapshot().downlink
        ),
        (expected.len() as u64, expected.len() as u64)
    );
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

/// 独立构造带 SNI 的最小 TLS ClientHello 记录。
fn tls_client_hello(server_name: &str) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.push(0x00);
    entry.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    entry.extend_from_slice(server_name.as_bytes());
    let mut data = Vec::new();
    data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    data.extend_from_slice(&entry);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&data);

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x11; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[tokio::test]
async fn sniffed_tls_sni_over_reality_uses_dest_override() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let mut value = config(target.address, false, false);
    value["dns"] = json!({"hosts": {"sniffed.test": ["127.0.0.1"]}});
    value["sniffing"] = json!({
        "enabled": true,
        "inbounds": ["reality"],
        "dest_override": ["tls"],
        "timeout_ms": 500
    });
    let server = Running::start(value).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    // 原始目标不可达；只有 dest_override 经 hosts 解析后才会命中回环 echo。
    let unreachable = SocketAddr::new("192.0.2.1".parse().unwrap(), echo.address.port());
    let hello = tls_client_hello("sniffed.test");

    let mut client = PreparedClient::new(options(true, false))
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    let mut request = peer::vless_request(1, None, peer::ID, unreachable);
    request.extend_from_slice(&hello);
    client.send(&request).await.unwrap();
    assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
    assert_eq!(client.plain(hello.len()).await.unwrap(), hello);
    assert_eq!(server.stats.snapshot().uplink, hello.len() as u64);
    assert_eq!(server.stats.snapshot().downlink, hello.len() as u64);

    drop(client);
    idle(&server).await;
    server.shutdown().await;
    target.shutdown().await.unwrap();
}
