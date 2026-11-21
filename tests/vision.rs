mod common;
use common::*;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

// 独立外层对端按一条TLS记录读取，避免测试客户端自己预读Direct后的raw。
struct Outer {
    io: TcpStream,
    tls: rustls::ClientConnection,
}
impl Outer {
    async fn new(cert: &Certificate, addr: SocketAddr) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der.clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut out = Self {
            io: TcpStream::connect(addr).await.unwrap(),
            tls: rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap())
                .unwrap(),
        };
        while out.tls.is_handshaking() {
            out.flush_tls().await;
            if out.tls.is_handshaking() {
                out.record().await;
            }
        }
        out.flush_tls().await;
        out
    }
    async fn flush_tls(&mut self) {
        let mut wire = vec![];
        while self.tls.wants_write() {
            self.tls.write_tls(&mut wire).unwrap();
        }
        self.io.write_all(&wire).await.unwrap();
    }
    async fn send(&mut self, data: &[u8]) {
        std::io::Write::write_all(&mut self.tls.writer(), data).unwrap();
        self.flush_tls().await;
    }
    async fn record(&mut self) {
        let wire = raw_record(&mut self.io).await;
        let mut data = wire.as_slice();
        while !data.is_empty() {
            self.tls.read_tls(&mut data).unwrap();
            self.tls.process_new_packets().unwrap();
        }
    }
    async fn plain(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0; n];
        let mut used = 0;
        while used < n {
            match std::io::Read::read(&mut self.tls.reader(), &mut out[used..]) {
                Ok(count) if count > 0 => used += count,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => self.record().await,
                other => panic!("outer plaintext {other:?}"),
            }
        }
        out
    }
    async fn block(&mut self, first: bool) -> (u8, Vec<u8>) {
        if first {
            assert_eq!(self.plain(16).await, ID);
        }
        let header = self.plain(5).await;
        let n = u16::from_be_bytes([header[1], header[2]]) as usize;
        let pad = u16::from_be_bytes([header[3], header[4]]) as usize;
        let body = self.plain(n).await;
        self.plain(pad).await;
        (header[0], body)
    }
}
async fn raw_record<S: AsyncRead + Unpin>(io: &mut S) -> Vec<u8> {
    let mut header = [0; 5];
    read_exact(io, &mut header).await;
    let n = u16::from_be_bytes([header[3], header[4]]) as usize;
    assert!(n <= 18432);
    let mut body = vec![0; n];
    read_exact(io, &mut body).await;
    let mut out = header.to_vec();
    out.extend(body);
    out
}
fn inner_output(inner: &mut rustls::ClientConnection) -> Vec<u8> {
    let mut wire = vec![];
    while inner.wants_write() {
        inner.write_tls(&mut wire).unwrap();
    }
    wire
}
fn inner_input(inner: &mut rustls::ClientConnection, wire: &[u8]) {
    let mut wire = wire;
    while !wire.is_empty() {
        inner.read_tls(&mut wire).unwrap();
        inner.process_new_packets().unwrap();
    }
}

const ID: [u8; 16] = [0x11; 16];
#[tokio::test]
async fn vision_example_checks_starts_and_transfers_after_placeholder_replacement() {
    let cert = Certificate::new();
    let mut value: Value =
        serde_json::from_str(include_str!("../examples/vless-vision.json")).unwrap();
    assert!(dubhe::Config::from_json(&value.to_string()).is_err());
    value["inbounds"][0]["listen"] = json!("127.0.0.1:0");
    value["inbounds"][0]["users"][0]["uuid"] = json!("11111111-1111-1111-1111-111111111111");
    value["inbounds"][0]["certificate"] = json!(cert.dir.path().join("cert.pem"));
    value["inbounds"][0]["private_key"] = json!(cert.dir.path().join("key.pem"));
    let cfg = dubhe::Config::from_json(&value.to_string()).unwrap();
    dubhe::Server::check(&cfg).unwrap();
    let path = cert.dir.path().join("vision-config.json");
    std::fs::write(&path, value.to_string()).unwrap();
    let checked = std::process::Command::new(env!("CARGO_BIN_EXE_dubhe"))
        .args(["check", "-c"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(checked.status.success());
    let server = Running::start(value).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut s = connect(&cert, server.address, true).await;
    let mut bytes = request(1, true, 0x11, echo.address);
    bytes.extend(block(true, 1, b"example", 0));
    send(&mut s, &bytes).await;
    reply(&mut s).await;
    assert_eq!(read_block(&mut s, true).await.1, b"example");
    drop(s);
    server.shutdown().await;
}

fn config(cert: &Certificate) -> Value {
    let mut value = socks_config();
    value["inbounds"] = json!([{"type":"vless","tag":"vision","listen":"127.0.0.1:0","xudp":true,
        "users":[{"name":"vision","uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision"},
            {"name":"plain","uuid":"22222222-2222-2222-2222-222222222222"}],
        "certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}]);
    value
}
async fn connect(cert: &Certificate, addr: SocketAddr, tls13: bool) -> TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let version = if tls13 {
        &rustls::version::TLS13
    } else {
        &rustls::version::TLS12
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
        .connect(
            "localhost".try_into().unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap()
}
fn target(addr: SocketAddr) -> Vec<u8> {
    let mut out = addr.port().to_be_bytes().to_vec();
    match addr.ip() {
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
fn request(command: u8, flow: bool, id: u8, addr: SocketAddr) -> Vec<u8> {
    let mut out = vec![0];
    out.extend([id; 16]);
    if flow {
        out.extend([18, 10, 16]);
        out.extend(b"xtls-rprx-vision");
    } else {
        out.push(0);
    }
    out.push(command);
    if command != 3 {
        out.extend(target(addr));
    }
    out
}
// 独立金样，不调用生产 Vision 编解码。
fn block(first: bool, command: u8, body: &[u8], pad: usize) -> Vec<u8> {
    let mut out = vec![];
    if first {
        out.extend(ID);
    }
    out.push(command);
    out.extend((body.len() as u16).to_be_bytes());
    out.extend((pad as u16).to_be_bytes());
    out.extend(body);
    out.extend(vec![0x77; pad]);
    out
}
async fn reply<S: AsyncRead + Unpin>(io: &mut S) {
    let mut b = [9; 2];
    read_exact(io, &mut b).await;
    assert_eq!(b, [0, 0]);
}
async fn read_block<S: AsyncRead + Unpin>(io: &mut S, first: bool) -> (u8, Vec<u8>) {
    if first {
        let mut b = [0; 16];
        read_exact(io, &mut b).await;
        assert_eq!(b, ID);
    }
    let command = io.read_u8().await.unwrap();
    let n = io.read_u16().await.unwrap() as usize;
    let pad = io.read_u16().await.unwrap() as usize;
    let mut body = vec![0; n];
    read_exact(io, &mut body).await;
    let mut padding = vec![0; pad];
    read_exact(io, &mut padding).await;
    (command, body)
}
async fn send<S: AsyncWrite + Unpin>(s: &mut S, b: &[u8]) {
    s.write_all(b).await.unwrap();
    s.flush().await.unwrap();
}

#[tokio::test]
async fn non_tls_end_fragmented_payload_and_mixed_plain_users() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let echo = Echo::tcp("127.0.0.1", true).await;
    for split in [false, true] {
        let mut s = connect(&cert, server.address, true).await;
        let mut bytes = request(1, true, 0x11, echo.address);
        bytes.extend(block(true, 0, b"\0binary", 3));
        bytes.extend(block(false, 1, b"tail", 0));
        bytes.extend(b"after-end");
        if split {
            for byte in bytes {
                send(&mut s, &[byte]).await;
            }
        } else {
            send(&mut s, &bytes).await;
        }
        reply(&mut s).await;
        s.shutdown().await.unwrap();
        let (cmd, body) = read_block(&mut s, true).await;
        assert_eq!(cmd, 1);
        assert_eq!(body, b"\0binarytailafter-end");
        let mut rest = vec![];
        s.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }
    for tls13 in [false, true] {
        let mut s = connect(&cert, server.address, tls13).await;
        let mut bytes = request(1, false, 0x22, echo.address);
        bytes.extend(b"plain");
        send(&mut s, &bytes).await;
        reply(&mut s).await;
        s.shutdown().await.unwrap();
        let mut body = vec![];
        s.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"plain");
    }
    let expected = 2 * b"\0binarytailafter-end".len() as u64 + 2 * b"plain".len() as u64;
    assert_eq!(server.stats.snapshot().uplink, expected);
    assert_eq!(server.stats.snapshot().downlink, expected);
    server.shutdown().await;
}

#[tokio::test]
async fn receive_direct_preserves_plaintext_tail_then_raw_while_reverse_stays_tls() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let echo = Echo::tcp("127.0.0.1", true).await;
    let mut s = connect(&cert, server.address, true).await;
    let mut bytes = request(1, true, 0x11, echo.address);
    bytes.extend(block(true, 2, b"direct", 7));
    bytes.extend(b"tail");
    send(&mut s, &bytes).await;
    // 最后一批外层输出已flush，接下来的原始字节不得再经TLS加密。
    s.get_mut().0.write_all(b"raw").await.unwrap();
    s.get_mut().0.shutdown().await.unwrap();
    reply(&mut s).await;
    let (cmd, body) = read_block(&mut s, true).await;
    assert_eq!(cmd, 1);
    assert_eq!(body, b"directtailraw");
    assert_eq!(server.stats.snapshot().uplink, 13);
    assert_eq!(server.stats.snapshot().downlink, 13);
    server.shutdown().await;
}

#[tokio::test]
async fn wrong_uuid_flow_tls_version_and_reject_route_never_connect() {
    let cert = Certificate::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Running::start(config(&cert)).await;
    for (tls13, flow, id, cmd) in [
        (true, true, 0x33, 1),
        (true, false, 0x11, 1),
        (true, true, 0x22, 1),
        (false, true, 0x11, 1),
        (true, true, 0x11, 2),
    ] {
        let mut s = connect(&cert, server.address, tls13).await;
        send(&mut s, &request(cmd, flow, id, addr)).await;
        let mut b = [0; 1];
        let result = timeout(Duration::from_secs(2), s.read(&mut b))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(server.stats.snapshot().uplink, 0);
    assert_eq!(server.stats.snapshot().downlink, 0);
    server.shutdown().await;
    let mut value = config(&cert);
    value["route"]["default"] = json!("reject");
    let server = Running::start(value).await;
    let mut s = connect(&cert, server.address, true).await;
    send(&mut s, &request(1, true, 0x11, addr)).await;
    // 与 Xray 一致，VLESS 应答先于出站拨号：拒绝路由时客户端先收到
    // 成功应答，随后连接关闭，且不会连接任何上游目标。
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(2), s.read_to_end(&mut rest)).await;
    assert_eq!(rest, vec![0, 0]);
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn real_inner_tls12_end_and_tls13_direct_both_directions() {
    for tls13 in [false, true] {
        let cert = Certificate::new();
        let inner_cert = Certificate::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut inner_server = (*dubhe::tls::load(
            &inner_cert.dir.path().join("cert.pem"),
            &inner_cert.dir.path().join("key.pem"),
        )
        .unwrap())
        .clone();
        // 强制目标协商版本，不靠测试字节伪造ServerHello。
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(inner_cert.der.clone()).unwrap();
        let version = if tls13 {
            &rustls::version::TLS13
        } else {
            &rustls::version::TLS12
        };
        let inner_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        inner_server.send_tls13_tickets = 0;
        let target = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut s = tokio_rustls::TlsAcceptor::from(Arc::new(inner_server))
                .accept(socket)
                .await
                .unwrap();
            s.write_all(b"hello-inner").await.unwrap();
            s.flush().await.unwrap();
            let mut b = [0; 4];
            s.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"ping");
            s.write_all(b"pong").await.unwrap();
            s.shutdown().await.unwrap();
        });
        let server = Running::start(config(&cert)).await;
        timeout(Duration::from_secs(5), async {
            let mut outer = Outer::new(&cert, server.address).await;
            let mut inner = rustls::ClientConnection::new(
                Arc::new(inner_config),
                "localhost".try_into().unwrap(),
            )
            .unwrap();
            let hello = inner_output(&mut inner);
            let mut bytes = request(1, true, 0x11, addr);
            bytes.extend(block(true, 0, &hello, 5));
            outer.send(&bytes).await;
            assert_eq!(outer.plain(2).await, [0, 0]);
            let mut first = true;
            let mut mode = 0;
            let mut greeting = Vec::new();
            while inner.is_handshaking() || greeting.len() < 11 {
                let wire = match mode {
                    0 => {
                        let (command, wire) = outer.block(first).await;
                        first = false;
                        mode = command;
                        wire
                    }
                    1 => {
                        let header = outer.plain(5).await;
                        let n = u16::from_be_bytes([header[3], header[4]]) as usize;
                        let mut wire = header;
                        wire.extend(outer.plain(n).await);
                        wire
                    }
                    2 => raw_record(&mut outer.io).await,
                    _ => panic!("bad command"),
                };
                inner_input(&mut inner, &wire);
                let output = inner_output(&mut inner);
                if !output.is_empty() {
                    outer.send(&block(false, 0, &output, 0)).await;
                }
                let mut buffer = [0; 64];
                match std::io::Read::read(&mut inner.reader(), &mut buffer) {
                    Ok(n) => greeting.extend_from_slice(&buffer[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("inner read {e}"),
                }
            }
            assert_eq!(greeting, b"hello-inner");
            assert_eq!(mode, if tls13 { 2 } else { 1 });
            std::io::Write::write_all(&mut inner.writer(), b"ping").unwrap();
            let output = inner_output(&mut inner);
            if tls13 {
                // 上行Direct块完成后切raw；此处未将未来raw交给外层TLS。
                outer.send(&block(false, 2, &[], 0)).await;
                outer.io.write_all(&output).await.unwrap();
            } else {
                outer.send(&block(false, 1, &output, 0)).await;
            }
            let mut pong = Vec::new();
            while pong.len() < 4 {
                let wire = if tls13 {
                    raw_record(&mut outer.io).await
                } else {
                    let h = outer.plain(5).await;
                    let n = u16::from_be_bytes([h[3], h[4]]) as usize;
                    let mut w = h;
                    w.extend(outer.plain(n).await);
                    w
                };
                inner_input(&mut inner, &wire);
                let mut b = [0; 4];
                match std::io::Read::read(&mut inner.reader(), &mut b) {
                    Ok(n) => pong.extend_from_slice(&b[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("pong {e}"),
                }
            }
            assert_eq!(pong, b"pong");
            target.await.unwrap();
        })
        .await
        .unwrap();
        server.shutdown().await;
    }
}

#[tokio::test]
async fn preparation_failure_returns_earlier_vision_listener() {
    let cert = Certificate::new();
    let available = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = available.local_addr().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut value = config(&cert);
    value["inbounds"][0]["listen"] = json!(address);
    value["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"socks5","tag":"occupied","listen":occupied.local_addr().unwrap()}));
    drop(available);
    let cfg = dubhe::Config::from_json(&value.to_string()).unwrap();
    assert!(dubhe::Server::bind(cfg).await.is_err());
    let rebound = TcpListener::bind(address).await.unwrap();
    drop(rebound);
}

async fn wait_for(server: &Running, ready: impl Fn(&dubhe::telemetry::Snapshot) -> bool) {
    timeout(Duration::from_secs(2), async {
        loop {
            if ready(&server.stats.snapshot()) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shared_connection_handshake_and_udp_limits_recover() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config(&cert);
    value["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}));
    value["limits"]["max_connections"] = json!(1);
    let server = Running::start(value).await;
    let mut s = connect(&cert, server.address, true).await;
    let mut bytes = request(1, true, 0x11, echo.address);
    bytes.extend(block(true, 1, b"one", 0));
    send(&mut s, &bytes).await;
    reply(&mut s).await;
    assert_eq!(read_block(&mut s, true).await.1, b"one");
    wait_for(&server, |v| v.connections == 1 && v.tcp_flows == 1).await;
    let mut denied = TcpStream::connect(server.addresses[1]).await.unwrap();
    assert!(
        timeout(Duration::from_secs(1), denied.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    drop(s);
    wait_for(&server, |v| v.connections == 0).await;
    let (mut recovered, _) = socks(1, address(echo.address), server.addresses[1]).await;
    exchange(&mut recovered, b"recovered").await;
    drop(recovered);
    server.shutdown().await;

    let mut value = config(&cert);
    value["limits"]["max_handshakes"] = json!(1);
    value["limits"]["handshake_timeout_ms"] = json!(100);
    let server = Running::start(value).await;
    let mut partial = TcpStream::connect(server.address).await.unwrap();
    partial.write_all(&[22]).await.unwrap();
    wait_for(&server, |v| v.connections == 1).await;
    let mut denied = TcpStream::connect(server.address).await.unwrap();
    assert!(
        timeout(Duration::from_secs(1), denied.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        timeout(Duration::from_secs(1), partial.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    wait_for(&server, |v| v.connections == 0).await;
    let mut s = connect(&cert, server.address, true).await;
    send(&mut s, &request(1, true, 0x11, echo.address)).await;
    reply(&mut s).await;
    drop(s);
    server.shutdown().await;

    let udp = Echo::udp("127.0.0.1").await;
    let mut value = config(&cert);
    value["limits"]["max_udp_associations"] = json!(1);
    let server = Running::start(value).await;
    let mut s = connect(&cert, server.address, true).await;
    let mut bytes = request(3, true, 0x11, udp.address);
    bytes.extend(block(true, 1, &xudp(7, udp.address, b"first", 2), 0));
    send(&mut s, &bytes).await;
    reply(&mut s).await;
    let (_, data) = read_block(&mut s, true).await;
    assert_eq!(packet(&mut data.as_slice()).await.1, b"first");
    wait_for(&server, |v| v.udp_associations == 1).await;
    send(&mut s, &xudp(9, udp.address, b"denied", 2)).await;
    let n = s.read_u16().await.unwrap();
    let mut metadata = vec![0; n as usize];
    read_exact(&mut s, &mut metadata).await;
    assert_eq!(metadata, [0, 9, 3, 2]);
    drop(s);
    wait_for(&server, |v| v.udp_associations == 0).await;
    let mut s = connect(&cert, server.address, false).await;
    let mut bytes = request(2, false, 0x11, udp.address);
    bytes.extend(b"\x00\x03udp");
    send(&mut s, &bytes).await;
    reply(&mut s).await;
    assert_eq!(s.read_u16().await.unwrap(), 3);
    let mut body = [0; 3];
    read_exact(&mut s, &mut body).await;
    assert_eq!(&body, b"udp");
    drop(s);
    server.shutdown().await;
}

#[tokio::test]
async fn bounded_slow_reader_and_partial_body_force_stop_release_resources() {
    for direct in [false, true] {
        let cert = Certificate::new();
        let server = Running::start(config(&cert)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let buffer = vec![0x55; 65536];
            let mut sent = 0;
            let blocked = timeout(Duration::from_millis(500), async {
                for _ in 0..1024 {
                    socket.write_all(&buffer).await.unwrap();
                    sent += buffer.len();
                }
            })
            .await
            .is_err();
            tx.send((blocked, sent)).unwrap();
            // 保持目标连接，观察内核force后真正归还，而不是测试对端主动断开。
            let mut bytes = vec![];
            let _ = socket.read_to_end(&mut bytes).await;
        });
        let mut slow = connect(&cert, server.address, true).await;
        let mut bytes = request(1, true, 0x11, target);
        bytes.extend(block(true, if direct { 2 } else { 0 }, &[], 0));
        send(&mut slow, &bytes).await;
        reply(&mut slow).await;
        let (blocked, sent) = timeout(Duration::from_secs(2), rx).await.unwrap().unwrap();
        assert!(blocked);
        assert!(sent <= 64 * 1024 * 1024);
        let udp = Echo::udp("127.0.0.1").await;
        let mut association = connect(&cert, server.address, true).await;
        let mut bytes = request(3, true, 0x11, udp.address);
        bytes.extend(block(true, 1, &xudp(1, udp.address, b"udp", 2), 0));
        send(&mut association, &bytes).await;
        reply(&mut association).await;
        let (_, body) = read_block(&mut association, true).await;
        assert_eq!(packet(&mut body.as_slice()).await.1, b"udp");
        let mut half = connect(&cert, server.address, true).await;
        let mut bytes = request(1, true, 0x11, target);
        bytes.extend(&ID[..7]);
        send(&mut half, &bytes).await;
        reply(&mut half).await;
        wait_for(&server, |v| v.tcp_flows == 2 && v.udp_associations == 1).await;
        let addresses = server.addresses.clone();
        server.shutdown().await;
        timeout(Duration::from_secs(2), writer)
            .await
            .unwrap()
            .unwrap();
        for addr in addresses {
            let rebound = TcpListener::bind(addr).await.unwrap();
            drop(rebound);
        }
        assert!(
            timeout(Duration::from_secs(1), association.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        drop((slow, half));
    }
}

fn xudp(id: u16, addr: SocketAddr, payload: &[u8], network: u8) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([1, 1, network]);
    metadata.extend(target(addr));
    let mut out = (metadata.len() as u16).to_be_bytes().to_vec();
    out.extend(metadata);
    out.extend((payload.len() as u16).to_be_bytes());
    out.extend(payload);
    out
}
async fn packet<S: AsyncRead + Unpin>(s: &mut S) -> (Vec<u8>, Vec<u8>) {
    let n = s.read_u16().await.unwrap() as usize;
    assert!(n <= 512);
    let mut m = vec![0; n];
    read_exact(s, &mut m).await;
    let n = s.read_u16().await.unwrap() as usize;
    let mut p = vec![0; n];
    read_exact(s, &mut p).await;
    (m, p)
}

#[tokio::test]
async fn vision_and_plain_xudp_native_udp_tls12_exceptions() {
    let cert = Certificate::new();
    let server = Running::start(config(&cert)).await;
    let a = Echo::udp("127.0.0.1").await;
    let b = Echo::udp("127.0.0.1").await;
    let tcp = Echo::tcp("127.0.0.1", false).await;
    for (flow, tls13) in [(true, true), (false, false)] {
        let mut s = connect(&cert, server.address, tls13).await;
        let mut frames = xudp(7, a.address, b"first", 2);
        frames.extend(xudp(9, b.address, b"second", 2));
        let mut bytes = request(3, flow, 0x11, a.address);
        if flow {
            bytes.extend(block(true, 1, &frames, 11));
        } else {
            bytes.extend(frames);
        }
        send(&mut s, &bytes).await;
        reply(&mut s).await;
        let mut seen = vec![];
        if flow {
            let (cmd, mut data) = read_block(&mut s, true).await;
            assert_eq!(cmd, 1);
            let mut cursor = data.as_slice();
            let (m, p) = packet(&mut cursor).await;
            seen.push((m, p));
            if cursor.is_empty() {
                seen.push(packet(&mut s).await);
            } else {
                let (m, p) = packet(&mut cursor).await;
                seen.push((m, p));
            }
            data.clear();
        } else {
            seen.push(packet(&mut s).await);
            seen.push(packet(&mut s).await);
        }
        seen.sort_by_key(|(m, _)| m[..2].to_vec());
        assert_eq!(seen[0].1, b"first");
        assert_eq!(seen[1].1, b"second");
        assert_eq!(seen[0].0[4], 2);
        assert_eq!(&seen[0].0[5..], target(a.address));
        assert_eq!(&seen[1].0[5..], target(b.address));
        // TCP New 与 UDP 会话可共存于同一 Mux 承载；回程无目标字段。
        send(&mut s, &xudp(11, tcp.address, b"over-tcp", 1)).await;
        let (metadata, payload) = packet(&mut s).await;
        assert_eq!(metadata, [0, 11, 2, 1]);
        assert_eq!(payload, b"over-tcp");
        // TCP 会话存在期间，原 UDP 会话仍可独立继续使用。
        send(&mut s, &xudp(7, a.address, b"after", 2)).await;
        let (metadata, payload) = packet(&mut s).await;
        let mut expected = vec![0, 7, 2, 1, 2];
        expected.extend(target(a.address));
        assert_eq!(metadata, expected);
        assert_eq!(payload, b"after");
    }
    let mut s = connect(&cert, server.address, false).await;
    let mut bytes = request(2, false, 0x11, a.address);
    bytes.extend([0, 3]);
    bytes.extend(b"udp");
    send(&mut s, &bytes).await;
    reply(&mut s).await;
    assert_eq!(s.read_u16().await.unwrap(), 3);
    let mut data = [0; 3];
    read_exact(&mut s, &mut data).await;
    assert_eq!(&data, b"udp");
    drop(s);
    server.shutdown().await;
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
async fn sniffed_tls_sni_over_vision_uses_dest_override() {
    let cert = Certificate::new();
    let mut value = config(&cert);
    value["dns"] = json!({"hosts": {"sniffed.test": ["127.0.0.1"]}});
    value["sniffing"] = json!({
        "enabled": true,
        "inbounds": ["vision"],
        "dest_override": ["tls"],
        "timeout_ms": 500
    });
    let server = Running::start(value).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    // 原始目标不可达；只有 dest_override 经 hosts 解析后才会命中回环 echo。
    let unreachable = SocketAddr::new("192.0.2.1".parse().unwrap(), echo.address.port());
    let hello = tls_client_hello("sniffed.test");

    let mut bytes = request(1, true, 0x11, unreachable);
    bytes.extend(block(true, 0, &hello, 0));
    let mut client = connect(&cert, server.address, true).await;
    send(&mut client, &bytes).await;
    reply(&mut client).await;
    let (_, body) = read_block(&mut client, true).await;
    assert_eq!(body, hello, "Vision 内层首包应被嗅探并原样回放");
    assert_eq!(server.stats.snapshot().uplink, hello.len() as u64);
    assert_eq!(server.stats.snapshot().downlink, hello.len() as u64);
    server.shutdown().await;
}
