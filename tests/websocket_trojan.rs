//! 独立 WS/WSS Trojan 端到端夹具；Trojan 本身不发送成功应答。
//! 只用 WS 会话 Close，不承诺客户端单向 FIN 后仍可收包。
//! Server 没有公开的 DNS 注入/计数接口：目标观察只证明零拨号/零数据报，
//! 不能把它等同于动态验证了零 DNS 调用。
mod common;
#[path = "common/websocket.rs"]
mod ws;

use common::*;
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const SECOND_PASSWORD: &str = "second-test-only-trojan-ws-password";
const WAIT: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(50);

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Client = ws::Peer<Box<dyn Io>>;

fn config(cert: Option<&Certificate>) -> Value {
    let mut value = socks_config();
    let mut inbound = json!({
        "type":"trojan-ws", "tag":"trojan-ws", "listen":"127.0.0.1:0",
        "websocket":{"path":"/proxy"},
        "users":[
            {"name":"first", "password":PASSWORD},
            {"name":"second", "password":SECOND_PASSWORD}
        ]
    });
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    } else {
        inbound["allow_insecure_transport"] = json!(true);
    }
    value["inbounds"] = json!([inbound]);
    value["limits"]["handshake_timeout_ms"] = json!(3000);
    value["limits"]["udp_idle_timeout_ms"] = json!(5000);
    value
}

async fn connect(server: &Running, cert: Option<&Certificate>, raw_prefix: &[u8]) -> Client {
    let io: Box<dyn Io> = match cert {
        Some(cert) => {
            let stream = cert.connect(server.address).await;
            stream.get_ref().0.set_nodelay(true).unwrap();
            Box::new(stream)
        }
        None => {
            let stream = TcpStream::connect(server.address).await.unwrap();
            stream.set_nodelay(true).unwrap();
            Box::new(stream)
        }
    };
    ws::upgrade(io, "/proxy", "", raw_prefix).await
}

async fn until(mut predicate: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !predicate() {
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("业务计量或会话资源未及时收敛");
}

async fn idle(server: &Running) {
    until(|| {
        let stats = server.stats.snapshot();
        stats.connections == 0 && stats.tcp_flows == 0 && stats.udp_associations == 0
    })
    .await;
}

async fn counts(server: &Running, uplink: usize, downlink: usize) {
    until(|| {
        let stats = server.stats.snapshot();
        (stats.uplink, stats.downlink) == (uplink as u64, downlink as u64)
    })
    .await;
}

async fn quiet(client: &mut Client) {
    let mut byte = [0];
    assert!(
        timeout(QUIET, client.read(&mut byte)).await.is_err(),
        "活跃 Trojan 会话不应产生额外应答、业务数据或提前结束"
    );
}

async fn finish(client: &mut Client) {
    client.close().await;
    ws::closed(client).await;
}

async fn roundtrip(client: &mut Client, payload: &[u8]) {
    client.write_all(payload).await.unwrap();
    client.flush().await.unwrap();
    let mut reply = vec![0; payload.len()];
    read_exact(client, &mut reply).await;
    // Trojan 没有成功应答；第一个业务字节必须就是目标回包。
    assert_eq!(reply, payload);
}

async fn no_tcp(listener: &TcpListener) {
    assert!(
        timeout(QUIET, listener.accept()).await.is_err(),
        "认证或路由拒绝后不应拨号目标"
    );
}

async fn no_udp(socket: &UdpSocket) {
    let mut bytes = [0; 2048];
    assert!(
        timeout(QUIET, socket.recv_from(&mut bytes)).await.is_err(),
        "拒绝、超限或截断的数据报不应到达目标"
    );
}

async fn receive(socket: &UdpSocket, expected: &[u8]) -> SocketAddr {
    let mut bytes = vec![0; 65536];
    let (length, source) = timeout(WAIT, socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..length], expected);
    source
}

async fn datagram(client: &mut Client, source: SocketAddr, expected: &[u8]) {
    let received = timeout(WAIT, trojan_recv(client)).await.unwrap();
    assert_eq!(received, (source, expected.to_vec()));
}

// 域名帧也由测试端独立编码，不调用生产协议编解码。
fn domain_udp(name: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = domain(name, port);
    bytes.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend(b"\r\n");
    bytes.extend(payload);
    bytes
}

async fn split_messages(client: &mut Client, bytes: &[u8]) {
    let mut offset = 0;
    for length in [1, 7, 17].into_iter().cycle() {
        if offset == bytes.len() {
            break;
        }
        let end = (offset + length).min(bytes.len());
        client.send_message(2, &bytes[offset..end]).await;
        offset = end;
    }
}

#[test]
fn plaintext_opt_in_does_not_relax_legacy_trojan_tls() {
    let mut value = config(None);
    assert!(dubhe::Config::from_json(&value.to_string()).is_ok());
    value["inbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("allow_insecure_transport");
    assert!(dubhe::Config::from_json(&value.to_string()).is_err());
    value["inbounds"][0]["allow_insecure_transport"] = json!(false);
    assert!(dubhe::Config::from_json(&value.to_string()).is_err());
    value["inbounds"] = json!([{
        "type":"trojan", "tag":"legacy", "listen":"127.0.0.1:0",
        "users":[{"name":"first", "password":PASSWORD}]
    }]);
    assert!(dubhe::Config::from_json(&value.to_string()).is_err());
}

#[tokio::test]
async fn ws_wss_tcp_multi_user_first_payload_and_arbitrary_message_boundaries() {
    let certificate = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    for cert in [None, Some(&certificate)] {
        let server = Running::start(config(cert)).await;
        let mut total = 0;
        for password in [PASSWORD, SECOND_PASSWORD] {
            for mode in 0..4 {
                let payload = b"\0first-payload\r\nnot-a-trojan-response";
                let mut request = trojan_header(1, address(echo.address), password);
                request.extend(payload);
                let prefix = if mode == 0 {
                    ws::masked(true, 2, &request)
                } else {
                    Vec::new()
                };
                let mut client = connect(&server, cert, &prefix).await;
                match mode {
                    0 => {} // HTTP 头与掩码首帧在同一次写入中合并。
                    1 => {
                        for byte in &request {
                            client.send_message(2, &[*byte]).await;
                        }
                    }
                    2 => {
                        client.send_fragment(false, 2, &request[..57]).await;
                        client.send_message(9, b"between-fragments").await;
                        client.send_fragment(false, 0, &request[57..61]).await;
                        client.send_fragment(true, 0, &request[61..]).await;
                    }
                    3 => {
                        client.send_message(2, b"").await;
                        split_messages(&mut client, &request).await;
                        client.send_message(2, b"").await;
                    }
                    _ => unreachable!(),
                }
                let mut reply = vec![0; payload.len()];
                read_exact(&mut client, &mut reply).await;
                assert_eq!(reply, payload);
                quiet(&mut client).await;
                roundtrip(&mut client, b"second-exchange").await;
                total += payload.len() + b"second-exchange".len();
                counts(&server, total, total).await;
                quiet(&mut client).await;
                finish(&mut client).await;
                idle(&server).await;
                counts(&server, total, total).await;
            }
        }
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_native_udp_multi_user_targets_empty_and_split_coalesced_messages() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_one = one.local_addr().unwrap();
        let addr_two = two.local_addr().unwrap();
        let server = Running::start(config(cert)).await;
        let mut total_uplink = 0;
        let mut total_downlink = 0;
        for password in [PASSWORD, SECOND_PASSWORD] {
            let mut bytes = trojan_header(3, address("0.0.0.0:0".parse().unwrap()), password);
            // 首地址不是固定目的地；每个数据报独立携带地址。
            // 数字域名避免依赖外部 DNS，回程仍必须是实际 IP 来源。
            bytes.extend(domain_udp("127.0.0.1", addr_one.port(), b"first"));
            bytes.extend(trojan_udp(addr_two, b"second"));
            let mut client = connect(&server, cert, &ws::masked(true, 2, &bytes)).await;
            let mapping_one = receive(&one, b"first").await;
            let mapping_two = receive(&two, b"second").await;
            quiet(&mut client).await;
            one.send_to(b"from-one", mapping_one).await.unwrap();
            datagram(&mut client, addr_one, b"from-one").await;
            two.send_to(b"from-two", mapping_two).await.unwrap();
            datagram(&mut client, addr_two, b"from-two").await;

            for byte in trojan_udp(addr_two, b"") {
                client.send_message(2, &[byte]).await;
            }
            assert_eq!(receive(&two, b"").await, mapping_two);
            two.send_to(b"", mapping_two).await.unwrap();
            datagram(&mut client, addr_two, b"").await;

            let large: Vec<_> = (0..300).map(|index| (index % 251) as u8).collect();
            let wire = trojan_udp(addr_two, &large);
            split_messages(&mut client, &wire).await;
            assert_eq!(receive(&two, &large).await, mapping_two);
            two.send_to(&large, mapping_two).await.unwrap();
            datagram(&mut client, addr_two, &large).await;

            let mut merged = trojan_udp(addr_one, b"again-one");
            merged.extend(trojan_udp(addr_two, b"again-two"));
            client.send_fragment(false, 2, &merged[..9]).await;
            client.send_message(9, b"udp-fragment-ping").await;
            client.send_fragment(true, 0, &merged[9..]).await;
            // 数字域名与 IP 地址可拥有不同映射，不能假设端口复用。
            let next_one = receive(&one, b"again-one").await;
            assert_eq!(receive(&two, b"again-two").await, mapping_two);
            one.send_to(b"last-one", next_one).await.unwrap();
            datagram(&mut client, addr_one, b"last-one").await;
            two.send_to(b"last-two", mapping_two).await.unwrap();
            datagram(&mut client, addr_two, b"last-two").await;

            let uplink = b"first".len() + b"second".len() + large.len() + 2 * b"again-one".len();
            let downlink = 2 * b"from-one".len() + large.len() + 2 * b"last-one".len();
            // 两方向正文长度故意不同，排除协议头、WS framing、空包的误计。
            total_uplink += uplink;
            total_downlink += downlink;
            counts(&server, total_uplink, total_downlink).await;
            quiet(&mut client).await;
            finish(&mut client).await;
            idle(&server).await;
        }
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_native_udp_wrong_source_and_oversized_reply_never_reach_client() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        for ip in ["127.0.0.1", "::1"] {
            let Ok(target) = UdpSocket::bind(SocketAddr::new(ip.parse().unwrap(), 0)).await else {
                assert_eq!(ip, "::1", "IPv4 回环必须可用");
                eprintln!("SKIP Trojan WS/WSS UDP IPv6 来源验证：当前回环不可用");
                continue;
            };
            let attacker = UdpSocket::bind(SocketAddr::new(ip.parse().unwrap(), 0))
                .await
                .unwrap();
            let destination = target.local_addr().unwrap();
            let mut value = config(cert);
            value["limits"]["max_udp_payload"] = json!(8);
            let server = Running::start(value).await;
            let mut request = trojan_header(3, address(destination), SECOND_PASSWORD);
            request.extend(trojan_udp(destination, b"start"));
            let mut client = connect(&server, cert, &ws::masked(true, 2, &request)).await;
            let mapping = receive(&target, b"start").await;
            attacker.send_to(b"spoof", mapping).await.unwrap();
            target.send_to(b"oversized", mapping).await.unwrap();
            target.send_to(b"valid", mapping).await.unwrap();
            datagram(&mut client, destination, b"valid").await;
            quiet(&mut client).await;
            counts(&server, b"start".len(), b"valid".len()).await;
            until(|| server.stats.snapshot().dropped >= 1).await;
            finish(&mut client).await;
            idle(&server).await;
            counts(&server, b"start".len(), b"valid".len()).await;
            no_udp(&target).await;
            server.shutdown().await;
        }
    }
}

#[tokio::test]
async fn ws_wss_ipv6_tcp_and_udp_switch_between_v4_v6_when_available() {
    let Ok(probe) = TcpListener::bind("[::1]:0").await else {
        eprintln!("SKIP Trojan WS/WSS IPv6 TCP：当前回环不可用");
        return;
    };
    drop(probe);
    let Ok(v6) = UdpSocket::bind("[::1]:0").await else {
        eprintln!("SKIP Trojan WS/WSS IPv6 UDP：当前回环不可用");
        return;
    };
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = Echo::tcp("[::1]", false).await;
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let server = Running::start(config(cert)).await;
        let mut client = connect(&server, cert, &[]).await;
        client
            .send_message(2, &trojan_header(1, address(tcp.address), PASSWORD))
            .await;
        roundtrip(&mut client, b"ipv6-tcp").await;
        finish(&mut client).await;
        idle(&server).await;

        let mut packets = connect(&server, cert, &[]).await;
        packets
            .send_message(
                2,
                &trojan_header(3, address(v4.local_addr().unwrap()), SECOND_PASSWORD),
            )
            .await;
        let mut total = b"ipv6-tcp".len();
        for (target, payload) in [
            (&v4, b"first-v4".as_slice()),
            (&v6, b"then-v6".as_slice()),
            (&v4, b"back-v4".as_slice()),
        ] {
            let destination = target.local_addr().unwrap();
            split_messages(&mut packets, &trojan_udp(destination, payload)).await;
            let mapping = receive(target, payload).await;
            target.send_to(payload, mapping).await.unwrap();
            datagram(&mut packets, destination, payload).await;
            total += payload.len();
        }
        counts(&server, total, total).await;
        finish(&mut packets).await;
        idle(&server).await;
        server.shutdown().await;
    }
}

fn invalid_requests(command: u8, target: SocketAddr) -> Vec<(String, Vec<u8>)> {
    let valid = trojan_header(command, address(target), PASSWORD);
    let mut cases = Vec::new();
    for index in [0, 55] {
        let mut bytes = valid.clone();
        bytes[index] = if bytes[index] == b'0' { b'1' } else { b'0' };
        cases.push((format!("digest-{index}"), bytes));
    }
    let mut uppercase = valid.clone();
    uppercase[..56].make_ascii_uppercase();
    assert_ne!(&uppercase[..56], &valid[..56]);
    cases.push(("uppercase-digest".into(), uppercase));
    for byte in [b'g', 0xff, 0] {
        let mut bytes = valid.clone();
        bytes[12] = byte;
        cases.push((format!("non-lowercase-hex-{byte}"), bytes));
    }
    cases.push((
        "unknown-user".into(),
        trojan_header(command, address(target), "not-one-of-the-configured-users"),
    ));
    for index in [56, 57, valid.len() - 2, valid.len() - 1] {
        let mut bytes = valid.clone();
        bytes[index] = 0;
        cases.push((format!("header-crlf-{index}"), bytes));
    }
    for unsupported in [0, 2, 4, 0xff] {
        cases.push((
            format!("command-{unsupported}"),
            trojan_header(unsupported, address(target), PASSWORD),
        ));
    }
    for atyp in [0, 2, 5, 0xff] {
        let mut bytes = valid.clone();
        bytes[59] = atyp;
        cases.push((format!("address-type-{atyp}"), bytes));
    }
    for name in ["", "bad name", "bad\0name", "bad\r\nname", "非ASCII.test"] {
        cases.push((
            format!("invalid-domain-{name:?}"),
            trojan_header(command, domain(name, target.port()), PASSWORD),
        ));
    }
    let mut shorter = valid.clone();
    shorter.remove(55);
    cases.push(("digest-too-short".into(), shorter));
    let mut longer = valid;
    longer.insert(56, b'0');
    cases.push(("digest-too-long".into(), longer));
    cases
}

#[tokio::test]
async fn ws_wss_invalid_digest_crlf_command_address_and_length_never_reach_targets() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = Running::start(config(cert)).await;
        for (command, target) in [
            (1, tcp.local_addr().unwrap()),
            (3, udp.local_addr().unwrap()),
        ] {
            for (case, mut request) in invalid_requests(command, target) {
                if command == 1 {
                    request.extend(b"must-not-be-relayed");
                } else {
                    request.extend(trojan_udp(target, b"must-not-be-sent"));
                }
                let mut client = connect(&server, cert, &ws::masked(true, 2, &request)).await;
                ws::closed(&mut client).await;
                drop(client);
                idle(&server).await;
                let stats = server.stats.snapshot();
                assert_eq!((stats.uplink, stats.downlink), (0, 0), "{case}");
                assert_eq!((stats.tcp_flows, stats.udp_associations), (0, 0), "{case}");
            }
        }
        no_tcp(&tcp).await;
        no_udp(&udp).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_every_truncated_tcp_and_udp_auth_header_closes_without_business_bytes() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Running::start(config(cert)).await;
        for command in [1, 3] {
            for destination in [
                address(target.local_addr().unwrap()),
                address("[::1]:9".parse().unwrap()),
                domain("localhost", target.local_addr().unwrap().port()),
            ] {
                let request = trojan_header(command, destination, SECOND_PASSWORD);
                for end in 0..request.len() {
                    let mut client = connect(&server, cert, &[]).await;
                    client.send_message(2, &request[..end]).await;
                    // 正常 WS Close 截断的是 Trojan 头，不把 Close 当 TCP 单向 FIN。
                    client.close().await;
                    ws::closed(&mut client).await;
                    drop(client);
                    idle(&server).await;
                    let stats = server.stats.snapshot();
                    assert_eq!((stats.uplink, stats.downlink), (0, 0));
                }
            }
        }
        no_tcp(&target).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_native_udp_bad_crlf_address_and_declared_lengths_fail_before_body() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let mut value = config(cert);
        value["limits"]["max_udp_payload"] = json!(8);
        let server = Running::start(value).await;
        let valid = trojan_udp(destination, b"four");
        let address_len = address(destination).len();
        let mut cases = Vec::new();
        for index in [address_len + 2, address_len + 3] {
            let mut bytes = valid.clone();
            bytes[index] = 0;
            cases.push(bytes);
        }
        for atyp in [0, 2, 5, 0xff] {
            let mut bytes = valid.clone();
            bytes[0] = atyp;
            cases.push(bytes);
        }
        cases.push(domain_udp("", destination.port(), b"four"));
        cases.push(domain_udp("bad name", destination.port(), b"four"));
        // 只发送声明，不发送 CRLF/正文；超限必须立即失败，不能等 idle。
        for length in [9u16, 256, u16::MAX] {
            let mut bytes = address(destination);
            bytes.extend(length.to_be_bytes());
            cases.push(bytes);
        }
        for bytes in cases {
            let mut client = connect(&server, cert, &[]).await;
            let mut request = trojan_header(3, address(destination), PASSWORD);
            request.extend(bytes);
            client.send_message(2, &request).await;
            timeout(Duration::from_millis(1000), ws::closed(&mut client))
                .await
                .expect("非法 UDP 头必须先于读取声明正文和 idle 期限被拒绝");
            drop(client);
            idle(&server).await;
            counts(&server, 0, 0).await;
        }
        no_udp(&target).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_native_udp_every_truncated_datagram_has_no_partial_delivery() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let server = Running::start(config(cert)).await;
        let v4 = trojan_udp(destination, b"not-a-partial-packet");
        let v6 = trojan_udp("[::1]:9".parse().unwrap(), b"not-a-partial-packet");
        let named = domain_udp("127.0.0.1", destination.port(), b"not-a-partial-packet");
        for datagram in [v4, v6, named] {
            for end in 0..datagram.len() {
                let mut client = connect(&server, cert, &[]).await;
                client
                    .send_message(2, &trojan_header(3, address(destination), SECOND_PASSWORD))
                    .await;
                // 确认真正完成认证并进入关联；没有伪造任何 Trojan 成功应答。
                until(|| server.stats.snapshot().udp_associations == 1).await;
                client.send_message(2, &datagram[..end]).await;
                client.close().await;
                ws::closed(&mut client).await;
                drop(client);
                idle(&server).await;
                counts(&server, 0, 0).await;
            }
        }
        no_udp(&target).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_native_udp_exact_payload_limit_and_empty_datagrams_count_only_payload() {
    let certificate = Certificate::new();
    let echo = Echo::udp("127.0.0.1").await;
    for cert in [None, Some(&certificate)] {
        let mut value = config(cert);
        value["limits"]["max_udp_payload"] = json!(8);
        let server = Running::start(value).await;
        let mut client = connect(&server, cert, &[]).await;
        client
            .send_message(2, &trojan_header(3, address(echo.address), PASSWORD))
            .await;
        quiet(&mut client).await;
        for payload in [b"".as_slice(), b"1".as_slice(), b"12345678".as_slice()] {
            split_messages(&mut client, &trojan_udp(echo.address, payload)).await;
            datagram(&mut client, echo.address, payload).await;
        }
        counts(&server, 9, 9).await;
        let mut oversized = address(echo.address);
        oversized.extend(9u16.to_be_bytes());
        client.send_message(2, &oversized).await;
        timeout(Duration::from_millis(1000), ws::closed(&mut client))
            .await
            .expect("超限声明不应等待正文");
        drop(client);
        idle(&server).await;
        counts(&server, 9, 9).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_reject_tcp_and_per_datagram_udp_before_network_and_success_bytes() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut value = config(cert);
        value["route"]["default"] = json!("reject");
        let server = Running::start(value).await;
        for target in [
            address(tcp.local_addr().unwrap()),
            domain("127.0.0.1", tcp.local_addr().unwrap().port()),
        ] {
            let mut request = trojan_header(1, target, SECOND_PASSWORD);
            request.extend(b"not-forwarded");
            let mut client = connect(&server, cert, &ws::masked(true, 2, &request)).await;
            ws::closed(&mut client).await;
            drop(client);
            idle(&server).await;
        }
        let mut client = connect(&server, cert, &[]).await;
        let mut request = trojan_header(3, address(udp.local_addr().unwrap()), PASSWORD);
        request.extend(trojan_udp(udp.local_addr().unwrap(), b"not-sent"));
        request.extend(domain_udp(
            "127.0.0.1",
            udp.local_addr().unwrap().port(),
            b"not-sent",
        ));
        client.send_message(2, &request).await;
        until(|| server.stats.snapshot().rejected == 4).await;
        // 原生 Trojan UDP 的逐包 Reject 丢包而非发伪成功应答；承载仍可活跃。
        quiet(&mut client).await;
        no_tcp(&tcp).await;
        no_udp(&udp).await;
        counts(&server, 0, 0).await;
        finish(&mut client).await;
        idle(&server).await;
        counts(&server, 0, 0).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_udp_route_is_checked_for_each_target_not_only_initial_header() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let allowed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rejected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let denied_port = rejected.local_addr().unwrap().port();
        let mut value = config(cert);
        value["route"]["rules"] = json!([{
            "networks":["udp"],
            "ports":[{"start":denied_port, "end":denied_port}],
            "outbound":"reject"
        }]);
        let server = Running::start(value).await;
        let mut client = connect(&server, cert, &[]).await;
        let mut request = trojan_header(3, address(allowed.local_addr().unwrap()), PASSWORD);
        request.extend(trojan_udp(rejected.local_addr().unwrap(), b"blocked-first"));
        request.extend(trojan_udp(allowed.local_addr().unwrap(), b"allowed"));
        request.extend(trojan_udp(rejected.local_addr().unwrap(), b"blocked-last"));
        client.send_message(2, &request).await;
        let mapping = receive(&allowed, b"allowed").await;
        allowed.send_to(b"reply", mapping).await.unwrap();
        datagram(&mut client, allowed.local_addr().unwrap(), b"reply").await;
        until(|| server.stats.snapshot().rejected == 2).await;
        no_udp(&rejected).await;
        quiet(&mut client).await;
        counts(&server, b"allowed".len(), b"reply".len()).await;
        finish(&mut client).await;
        idle(&server).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_tcp_server_first_without_client_fin_or_success_preamble() {
    let certificate = Certificate::new();
    for cert in [None, Some(&certificate)] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Running::start(config(cert)).await;
        let mut uplink = 0;
        let mut downlink = 0;
        for password in [PASSWORD, SECOND_PASSWORD] {
            let mut client = connect(&server, cert, &[]).await;
            client
                .send_message(
                    2,
                    &trojan_header(1, address(target.local_addr().unwrap()), password),
                )
                .await;
            let (mut upstream, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
            quiet(&mut client).await;
            counts(&server, uplink, downlink).await;
            let banner = b"server-first\0\r\n";
            upstream.write_all(banner).await.unwrap();
            upstream.flush().await.unwrap();
            let mut reply = vec![0; banner.len()];
            read_exact(&mut client, &mut reply).await;
            assert_eq!(reply, banner);
            client.send_message(2, b"request-after-banner").await;
            let mut request = [0; 20];
            read_exact(&mut upstream, &mut request).await;
            assert_eq!(&request, b"request-after-banner");
            upstream.write_all(b"reply-after-request").await.unwrap();
            upstream.flush().await.unwrap();
            let mut response = [0; 19];
            read_exact(&mut client, &mut response).await;
            assert_eq!(&response, b"reply-after-request");
            uplink += request.len();
            downlink += banner.len() + response.len();
            counts(&server, uplink, downlink).await;
            finish(&mut client).await;
            drop(upstream);
            idle(&server).await;
        }
        server.shutdown().await;
    }
}
