//! Naive显式H1填充入站；独立TLS端按正式wire编码，不调用生产padding codec。
mod common;
use common::{Certificate, Echo, Running};
use dubhe::{Config, Server};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;
const WAIT: Duration = Duration::from_secs(4);
const MAGIC: &str = "sp.v2.udp-over-tcp.arpa:0";
fn config(cert: &Certificate, padding: bool) -> Value {
    json!({"version":1,
        "inbounds":[{"type":"naive","tag":"up","listen":"127.0.0.1:0","h1_padding":padding,
            "users":[{"name":"u","password":"p"}],"certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],"route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":300,"handshake_timeout_ms":800,"dial_timeout_ms":800}})
}
fn request(target: &str) -> Vec<u8> {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nPadding: yes\r\nProxy-Authorization: Basic dTpw\r\n\r\n").into_bytes()
}
fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 65535);
    let mut bytes = (payload.len() as u16).to_be_bytes().to_vec();
    bytes.push(2);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&[0, 0]);
    bytes
}
async fn read_head<S: AsyncRead + Unpin>(wire: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        bytes.push(wire.read_u8().await.unwrap());
        assert!(bytes.len() <= 8192);
        if bytes.ends_with(b"\r\n\r\n") {
            return bytes;
        }
    }
}
fn verify_response(head: &[u8]) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    assert!(response.parse(head).unwrap().is_complete());
    assert_eq!(response.version, Some(1));
    assert_eq!(response.code, Some(200));
    let padding: Vec<_> = response
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("padding"))
        .collect();
    assert_eq!(padding.len(), 1);
    let value = padding[0].value;
    assert!((30..=61).contains(&value.len()));
    assert!(
        value[..16]
            .iter()
            .all(|byte| b"!#$()+<>?@[]^`{}".contains(byte))
    );
    assert!(value[16..].iter().all(|byte| *byte == b'~'));
    assert!(
        !response
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("content-length")
                || h.name.eq_ignore_ascii_case("transfer-encoding"))
    );
}
struct Client {
    wire: TlsStream<tokio::net::TcpStream>,
    writes: usize,
    reads: usize,
    stash: Vec<u8>,
}
impl Client {
    async fn open(
        cert: &Certificate,
        address: SocketAddr,
        target: &str,
        early: Option<(&[u8], usize)>,
    ) -> Self {
        let mut wire = cert.connect_alpn(address, &[b"http/1.1"]).await;
        let mut head = request(target);
        let mut remaining = None;
        if let Some((payload, split)) = early {
            let bytes = frame(payload);
            let split = split.min(bytes.len());
            head.extend_from_slice(&bytes[..split]);
            remaining = Some(bytes[split..].to_vec());
        }
        wire.write_all(&head).await.unwrap();
        wire.flush().await.unwrap();
        verify_response(&timeout(WAIT, read_head(&mut wire)).await.unwrap());
        if let Some(remaining) = remaining {
            wire.write_all(&remaining).await.unwrap();
            wire.flush().await.unwrap();
        }
        Self {
            wire,
            writes: usize::from(early.is_some()),
            reads: 0,
            stash: Vec::new(),
        }
    }
    async fn send(&mut self, payload: &[u8]) {
        let bytes = if self.writes < 8 {
            frame(payload)
        } else {
            payload.to_vec()
        };
        self.wire.write_all(&bytes).await.unwrap();
        self.wire.flush().await.unwrap();
        self.writes += 1;
    }
    async fn fill(&mut self, needed: usize) {
        while self.stash.len() < needed {
            if self.reads < 8 {
                let length = timeout(WAIT, self.wire.read_u16()).await.unwrap().unwrap() as usize;
                let padding = self.wire.read_u8().await.unwrap() as usize;
                let mut bytes = vec![0; length];
                self.wire.read_exact(&mut bytes).await.unwrap();
                let mut waste = vec![0; padding];
                self.wire.read_exact(&mut waste).await.unwrap();
                assert!(waste.iter().all(|byte| *byte == 0));
                self.stash.extend(bytes);
                self.reads += 1;
            } else {
                let mut bytes = [0; 8192];
                let n = timeout(WAIT, self.wire.read(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert_ne!(n, 0, "raw尾流提前结束");
                self.stash.extend_from_slice(&bytes[..n]);
            }
        }
    }
    async fn expect(&mut self, payload: &[u8]) {
        self.fill(payload.len()).await;
        assert_eq!(&self.stash[..payload.len()], payload);
        self.stash.drain(..payload.len());
    }
    async fn datagram(&mut self, target: SocketAddr, payload: &[u8], connect: bool) {
        let mut data = if connect {
            Vec::new()
        } else {
            uot_address(target)
        };
        data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        data.extend_from_slice(payload);
        self.send(&data).await;
        self.expect(&data).await;
    }
}
fn uot_address(target: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            bytes.push(0);
            bytes.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes
}
fn initial(target: SocketAddr, connect: bool) -> Vec<u8> {
    let mut bytes = vec![u8::from(connect)];
    bytes.extend(common::address(target));
    bytes
}

#[test]
fn defaults_example_roundtrip_and_strict_boolean_are_explicit() {
    for text in [
        include_str!("../examples/naive.json"),
        include_str!("../examples/naive-h1-padding.json"),
    ] {
        let config = Config::from_json(text).unwrap();
        Config::from_json(&serde_json::to_string(&config).unwrap()).unwrap();
    }
    let cert = Certificate::new();
    let mut value = config(&cert, false);
    value["inbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("h1_padding");
    let parsed = Config::from_json(&value.to_string()).unwrap();
    let serialized = serde_json::to_value(parsed).unwrap();
    assert_eq!(serialized["inbounds"][0]["h1_padding"], false);
    for invalid in [json!(1), json!("true"), Value::Null] {
        value["inbounds"][0]["h1_padding"] = invalid;
        assert!(Config::from_json(&value.to_string()).is_err());
    }
    value["inbounds"][0]["type"] = json!("http");
    value["inbounds"][0]["h1_padding"] = json!(true);
    assert!(Config::from_json(&value.to_string()).is_err());
}

#[tokio::test]
async fn independent_tls_early_split_payload_first_eight_ninth_and_large_bidirectional_tcp() {
    let cert = Certificate::new();
    let up = Running::start(config(&cert, true)).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    for split in [1, 2, 3, 7, usize::MAX] {
        let mut client = Client::open(
            &cert,
            up.address,
            &echo.address.to_string(),
            Some((b"early-payload", split)),
        )
        .await;
        client.expect(b"early-payload").await;
        for index in 1..8u8 {
            let bytes = vec![index; 4096];
            client.send(&bytes).await;
            client.expect(&bytes).await;
        }
        assert_eq!(client.writes, 8);
        client.send(b"ninth-raw\0\0").await;
        client.expect(b"ninth-raw\0\0").await;
        let bytes = vec![0x33; 192 * 1024];
        client.send(&bytes).await;
        client.expect(&bytes).await;
    }
    assert!(up.stats.snapshot().uplink >= 5 * (13 + 7 * 4096 + 11 + 192 * 1024));
    up.shutdown().await;
}

#[tokio::test]
async fn independent_tls_half_close_keeps_reverse_after_eof_for_both_small_and_large() {
    let cert = Certificate::new();
    let up = Running::start(config(&cert, true)).await;
    for size in [7, 128 * 1024] {
        let echo = Echo::tcp("127.0.0.1", true).await;
        let mut client = Client::open(&cert, up.address, &echo.address.to_string(), None).await;
        let bytes = vec![0x66; size];
        for chunk in bytes.chunks(16000) {
            client.send(chunk).await;
        }
        client.wire.shutdown().await.unwrap();
        client.expect(&bytes).await;
    }
    up.shutdown().await;
}

#[tokio::test]
async fn independent_uot_connect_and_packet_targets_empty_ipv6_limits_and_route_reject() {
    let cert = Certificate::new();
    let first = Echo::udp("127.0.0.1").await;
    let second = Echo::udp("127.0.0.1").await;
    let denied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut value = config(&cert, true);
    value["limits"]["max_udp_targets"] = json!(2);
    value["limits"]["max_udp_payload"] = json!(4096);
    value["route"]["rules"] = json!([{"outbound":"reject","ports":[{"start":denied.local_addr().unwrap().port(),"end":denied.local_addr().unwrap().port()}]}]);
    let up = Running::start(value).await;
    for connect in [true, false] {
        let mut client = Client::open(
            &cert,
            up.address,
            MAGIC,
            Some((&initial(first.address, connect), 3)),
        )
        .await;
        client.datagram(first.address, b"first", connect).await;
        client.datagram(first.address, b"", connect).await;
        if !connect {
            client.datagram(second.address, b"second", false).await;
            let mut reject = uot_address(denied.local_addr().unwrap());
            reject.extend_from_slice(b"\0\x03bad");
            client.send(&reject).await;
            assert!(
                timeout(Duration::from_millis(80), denied.recv(&mut [0; 16]))
                    .await
                    .is_err()
            );
        }
        client
            .datagram(first.address, &vec![0x44; 4096], connect)
            .await;
        if !connect {
            let third = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = uot_address(third.local_addr().unwrap());
            packet.extend_from_slice(b"\0\x05third");
            client.send(&packet).await;
            assert!(
                timeout(Duration::from_millis(80), third.recv(&mut [0; 16]))
                    .await
                    .is_err()
            );
            client.datagram(second.address, b"still-works", false).await;
        }
    }
    if UdpSocket::bind("[::1]:0").await.is_ok() {
        let echo = Echo::udp("[::1]").await;
        let mut client = Client::open(
            &cert,
            up.address,
            MAGIC,
            Some((&initial(echo.address, true), usize::MAX)),
        )
        .await;
        client.datagram(echo.address, b"ipv6", true).await;
    }
    up.shutdown().await;
}

#[tokio::test]
async fn missing_duplicate_padding_wrong_auth_method_zero_port_and_oversize_headers_no_target_bytes()
 {
    let cert = Certificate::new();
    let up = Running::start(config(&cert, true)).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let original = String::from_utf8(request(&target.local_addr().unwrap().to_string())).unwrap();
    for text in [
        original.replace("Padding: yes\r\n", ""),
        original.replace("Padding: yes", "Padding:"),
        original.replace("Padding: yes", "Padding: yes\r\npAdDiNg: again"),
        original.replace("Basic dTpw", "Basic dTpx"),
        original.replace("Proxy-Authorization: Basic dTpw\r\n", ""),
        original.replace(
            "Padding: yes",
            "Padding: yes\r\nProxy-Authorization: Basic dTpw",
        ),
        original.replacen("CONNECT", "GET", 1),
        original.replace("HTTP/1.1", "HTTP/1.0"),
        String::from_utf8(request("example.test:0")).unwrap(),
        original.replace("Padding: yes", &format!("Padding: {}", "x".repeat(8200))),
    ] {
        let mut wire = cert.connect_alpn(up.address, &[b"http/1.1"]).await;
        wire.write_all(text.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ = timeout(WAIT, wire.read_to_end(&mut response))
            .await
            .unwrap();
        assert!(!response.starts_with(b"HTTP/1.1 200"));
    }
    assert!(
        timeout(Duration::from_millis(80), target.accept())
            .await
            .is_err()
    );
    assert_eq!(up.stats.snapshot().uplink, 0);
    assert_eq!(up.stats.snapshot().downlink, 0);
    up.shutdown().await;
}

#[tokio::test]
async fn raw_h1_http_and_mixed_still_reject_uot_zero_port_without_creating_association() {
    let cert = Certificate::new();
    let raw = Running::start(config(&cert, false)).await;
    let mut tls = cert.connect_alpn(raw.address, &[b"http/1.1"]).await;
    tls.write_all(&request(MAGIC)).await.unwrap();
    let mut reply = Vec::new();
    let _ = timeout(WAIT, tls.read_to_end(&mut reply)).await.unwrap();
    assert!(!reply.starts_with(b"HTTP/1.1 200"));
    assert_eq!(raw.stats.snapshot().udp_associations, 0);
    raw.shutdown().await;
    for kind in ["http", "mixed"] {
        let value = json!({"version":1,"inbounds":[{"type":kind,"tag":"up","listen":"127.0.0.1:0","users":[{"name":"u","password":"p"}]}],
            "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"}});
        let up = Running::start(value).await;
        let mut wire = tokio::net::TcpStream::connect(up.address).await.unwrap();
        wire.write_all(&request(MAGIC)).await.unwrap();
        let mut reply = Vec::new();
        let _ = timeout(WAIT, wire.read_to_end(&mut reply)).await.unwrap();
        assert!(!reply.starts_with(b"HTTP/1.1 200"));
        assert_eq!(up.stats.snapshot().udp_associations, 0);
        up.shutdown().await;
    }
}

#[tokio::test]
async fn truncated_padding_closes_target_without_leaking_partial_business() {
    let cert = Certificate::new();
    let up = Running::start(config(&cert, true)).await;
    for bytes in [b"\0".as_slice(), b"\0\x05\0ab", b"\0\x01\x02a\0"] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = Client::open(
            &cert,
            up.address,
            &target.local_addr().unwrap().to_string(),
            None,
        )
        .await;
        let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
        client.wire.write_all(bytes).await.unwrap();
        client.wire.shutdown().await.unwrap();
        let mut leaked = Vec::new();
        let _ = timeout(WAIT, remote.read_to_end(&mut leaked))
            .await
            .unwrap();
        assert!(leaked.is_empty());
    }
    assert_eq!(up.stats.snapshot().uplink, 0);
    up.shutdown().await;
}

#[tokio::test]
async fn production_h1_outbound_to_padded_inbound_tcp_and_uot_two_targets() {
    let cert = Certificate::new();
    let up = Running::start(config(&cert, true)).await;
    let down=Running::start(json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"naive","tag":"up","endpoint":up.address.to_string(),"username":"u","password":"p",
            "tls":{"ca_file":cert.dir.path().join("cert.pem"),"server_name":"localhost"},
            "naive":{"http_version":"1.1","h1_padding":true,"udp_over_tcp":true}}],"route":{"default":"up"},"limits":{"shutdown_timeout_ms":300}})).await;
    let echo = Echo::tcp("127.0.0.1", true).await;
    let (mut stream, _) = common::socks(1, common::address(echo.address), down.address).await;
    stream.write_all(b"production").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"production");
    let first = Echo::udp("127.0.0.1").await;
    let second = Echo::udp("127.0.0.1").await;
    let (control, mut relay) = common::socks(
        3,
        common::address("0.0.0.0:0".parse().unwrap()),
        down.address,
    )
    .await;
    if relay.ip().is_unspecified() {
        relay.set_ip(down.address.ip());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    for (target, payload) in [
        (first.address, b"one".as_slice()),
        (second.address, b"two"),
        (first.address, b""),
    ] {
        let packet = [vec![0, 0, 0], common::address(target), payload.to_vec()].concat();
        socket.send(&packet).await.unwrap();
        let mut reply = [0; 1024];
        let n = timeout(WAIT, socket.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..n], packet);
    }
    drop(control);
    drop(socket);
    drop(stream);
    down.shutdown().await;
    up.shutdown().await;
}

#[tokio::test]
async fn successful_h1_releases_handshake_slot_slow_header_isolated_and_forced_stop_rebinds_port() {
    let cert = Certificate::new();
    let mut value = config(&cert, true);
    value["limits"]["max_handshakes"] = json!(2);
    value["limits"]["max_connections"] = json!(4);
    let up = Running::start(value).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut active = Client::open(&cert, up.address, &echo.address.to_string(), None).await;
    let mut slow = cert.connect_alpn(up.address, &[b"http/1.1"]).await;
    slow.write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nPadding: ")
        .await
        .unwrap();
    let mut second = Client::open(&cert, up.address, &echo.address.to_string(), None).await;
    active.send(b"active").await;
    active.expect(b"active").await;
    second.send(b"second").await;
    second.expect(b"second").await;
    let mut rest = Vec::new();
    let _ = timeout(WAIT, slow.read_to_end(&mut rest)).await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    drop(second);
    let blocked = Client::open(
        &cert,
        up.address,
        &target.local_addr().unwrap().to_string(),
        None,
    )
    .await;
    let (mut remote, _) = target.accept().await.unwrap();
    let writer = tokio::spawn(async move {
        let bytes = vec![0x55; 1024 * 1024];
        while remote.write_all(&bytes).await.is_ok() {}
    });
    let address = up.address;
    up.shutdown().await;
    drop(active);
    drop(blocked);
    drop(slow);
    writer.abort();
    let _ = writer.await;
    TcpListener::bind(address).await.unwrap();
}

#[tokio::test]
async fn h1_option_keeps_h2_plain_and_padded_connect_and_shared_connection_admission() {
    let cert = Certificate::new();
    let mut value = config(&cert, true);
    value["limits"]["max_connections"] = json!(2);
    let up = Running::start(value).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut h1 = Client::open(&cert, up.address, &echo.address.to_string(), None).await;
    let tls = cert.connect_alpn(up.address, &[b"h2"]).await;
    let (mut requests, driver) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(driver);
    for padded in [false, true] {
        let mut request = http::Request::builder()
            .method("CONNECT")
            .uri(echo.address.to_string())
            .header("proxy-authorization", "Basic dTpw");
        if padded {
            request = request.header("padding", "yes");
        }
        let (response, mut send) = requests
            .send_request(request.body(()).unwrap(), false)
            .unwrap();
        let response = timeout(WAIT, response).await.unwrap().unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.headers().contains_key("padding"), padded);
        let bytes = if padded {
            frame(b"h2-independent")
        } else {
            b"h2-independent".to_vec()
        };
        send.send_data(bytes::Bytes::from(bytes), false).unwrap();
        let mut body = response.into_body();
        let mut received = Vec::new();
        let expected = if padded { 3 + 14 } else { 14 };
        while received.len() < expected {
            let data = timeout(WAIT, body.data()).await.unwrap().unwrap().unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            received.extend_from_slice(&data);
        }
        if padded {
            let len = u16::from_be_bytes([received[0], received[1]]) as usize;
            let total = 3 + len + received[2] as usize;
            while received.len() < total {
                let data = timeout(WAIT, body.data()).await.unwrap().unwrap().unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                received.extend_from_slice(&data);
            }
            assert_eq!(&received[3..3 + len], b"h2-independent");
        } else {
            assert_eq!(received, b"h2-independent");
        }
        send.send_reset(h2::Reason::CANCEL);
    }
    assert!(
        cert.try_connect_alpn(up.address, &[b"http/1.1"])
            .await
            .is_err(),
        "H1/H2必须共用连接上限"
    );
    h1.send(b"still-alive").await;
    h1.expect(b"still-alive").await;
    drop(h1);
    drop(requests);
    driver.abort();
    let _ = driver.await;
    up.shutdown().await;
}

#[tokio::test]
async fn uot_oversize_or_half_packet_closes_session_and_preserves_zero_target_bytes() {
    let cert = Certificate::new();
    let mut value = config(&cert, true);
    value["limits"]["max_udp_payload"] = json!(16);
    let up = Running::start(value).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for malformed in [b"\0".as_slice(), b"\0\x05ab", b"\0\x11"] {
        let mut client = Client::open(
            &cert,
            up.address,
            MAGIC,
            Some((&initial(target.local_addr().unwrap(), true), usize::MAX)),
        )
        .await;
        client.send(malformed).await;
        client.wire.shutdown().await.unwrap();
        let mut rest = Vec::new();
        let _ = timeout(WAIT, client.wire.read_to_end(&mut rest))
            .await
            .unwrap();
        assert!(rest.is_empty());
    }
    assert!(
        timeout(Duration::from_millis(80), target.recv(&mut [0; 32]))
            .await
            .is_err()
    );
    assert_eq!(up.stats.snapshot().uplink, 0);
    up.shutdown().await;
}

#[tokio::test]
async fn route_only_reload_keeps_old_padded_stream_and_profile_change_requires_restart() {
    let cert = Certificate::new();
    let value = config(&cert, true);
    let server = Server::bind(Config::from_json(&value.to_string()).unwrap())
        .await
        .unwrap();
    let address = server.local_addr("up").unwrap();
    let hot = server.hot_reload_handle();
    let stats = server.stats();
    let stop = CancellationToken::new();
    let task = tokio::spawn(server.run(stop.clone()));
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut client = Client::open(&cert, address, &echo.address.to_string(), None).await;
    let mut changed = value.clone();
    changed["route"]["default"] = json!("reject");
    assert!(
        hot.reload(&Config::from_json(&changed.to_string()).unwrap())
            .unwrap()
    );
    client.send(b"old-snapshot").await;
    client.expect(b"old-snapshot").await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut denied = cert.connect_alpn(address, &[b"http/1.1"]).await;
    denied
        .write_all(&request(&target.local_addr().unwrap().to_string()))
        .await
        .unwrap();
    assert!(read_head(&mut denied).await.starts_with(b"HTTP/1.1 502"));
    assert!(
        timeout(Duration::from_millis(80), target.accept())
            .await
            .is_err()
    );
    changed["inbounds"][0]["h1_padding"] = json!(false);
    assert!(
        !hot.reload(&Config::from_json(&changed.to_string()).unwrap())
            .unwrap()
    );
    drop(client);
    drop(denied);
    stop.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    assert_eq!(stats.snapshot().connections, 0);
    TcpListener::bind(address).await.unwrap();
}
