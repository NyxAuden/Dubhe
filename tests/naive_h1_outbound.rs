//! 固定sing-box H1的独立TLS/padding/UoT参考对端；不编译运行上游、不用生产codec。
mod common;
use common::{Certificate, Echo, Running};
use dubhe::Config;
use serde_json::{Value, json};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
const WAIT: Duration = Duration::from_secs(4);

struct Peer {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<String>>>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Peer {
    async fn start(cert: &Certificate) -> Self {
        let mut tls = (*dubhe::tls::load(
            &cert.dir.path().join("cert.pem"),
            &cert.dir.path().join("key.pem"),
        )
        .unwrap())
        .clone();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let stop = CancellationToken::new();
        let (signal, accepts, seen) = (stop.clone(), count.clone(), targets.clone());
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! { biased;
                    _ = signal.cancelled() => break,
                    accepted = listener.accept() => {
                        let (wire, _) = accepted.unwrap();
                        accepts.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let seen = seen.clone();
                        connections.spawn(async move {
                            let Ok(mut wire) = acceptor.accept(wire).await else { return; };
                            assert_eq!(wire.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
                            let mut head = Vec::new();
                            loop {
                                let Ok(byte) = wire.read_u8().await else { return; };
                                head.push(byte);
                                assert!(head.len() <= 8192);
                                if head.ends_with(b"\r\n\r\n") { break; }
                            }
                            let target = {
                                let mut headers = [httparse::EMPTY_HEADER; 64];
                                let mut request = httparse::Request::new(&mut headers);
                                assert!(request.parse(&head).unwrap().is_complete());
                                assert_eq!(request.method, Some("CONNECT"));
                                assert_eq!(request.version, Some(1));
                                let auth = request.headers.iter().find(|h| h.name.eq_ignore_ascii_case("proxy-authorization")).unwrap();
                                if auth.value != b"Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=" {
                                    wire.write_all(b"HTTP/1.1 407 Denied\r\n\r\n").await.unwrap();
                                    return;
                                }
                                assert!(request.headers.iter().any(|h| h.name.eq_ignore_ascii_case("padding") && !h.value.is_empty()));
                                request.path.unwrap().to_owned()
                            };
                            seen.lock().unwrap().push(target.clone());
                            wire.write_all(b"HTTP/1.1 200 OK\r\nPadding: independent-singbox-profile\r\n\r\n").await.unwrap();
                            wire.flush().await.unwrap();
                            let (app, codec) = tokio::io::duplex(64 * 1024);
                            let (wire_read, wire_write) = tokio::io::split(wire);
                            let (codec_read, codec_write) = tokio::io::split(codec);
                            // 三个future同属连接任务；没有脱离生命周期的codec子任务。
                            let _ = tokio::join!(decode(wire_read, codec_write), encode(codec_read, wire_write), serve(app, target));
                        });
                    },
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
            connections.abort_all();
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    assert!(error.is_cancelled());
                }
            }
        });
        Self {
            address,
            count,
            targets,
            stop,
            task: Some(task),
        }
    }
    async fn shutdown(mut self) {
        self.stop.cancel();
        timeout(WAIT, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        TcpListener::bind(self.address).await.unwrap();
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
async fn decode<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut wire: R,
    mut app: W,
) -> io::Result<()> {
    for _ in 0..8 {
        let mut head = [0; 3];
        if wire.read(&mut head[..1]).await? == 0 {
            return app.shutdown().await;
        }
        wire.read_exact(&mut head[1..]).await?;
        let length = u16::from_be_bytes([head[0], head[1]]) as usize;
        let mut payload = vec![0; length];
        wire.read_exact(&mut payload).await?;
        let mut padding = vec![0; head[2] as usize];
        wire.read_exact(&mut padding).await?;
        assert!(padding.iter().all(|byte| *byte == 0));
        app.write_all(&payload).await?;
    }
    tokio::io::copy(&mut wire, &mut app).await?;
    app.shutdown().await
}
async fn encode<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut app: R,
    mut wire: W,
) -> io::Result<()> {
    let mut count = 0;
    let mut bytes = vec![0; 16 * 1024];
    loop {
        let length = app.read(&mut bytes).await?;
        if length == 0 {
            return wire.shutdown().await;
        }
        if count < 8 {
            wire.write_all(&(length as u16).to_be_bytes()).await?;
            wire.write_all(&[2]).await?;
        }
        wire.write_all(&bytes[..length]).await?;
        if count < 8 {
            wire.write_all(&[0, 0]).await?;
        }
        wire.flush().await?;
        count += 1;
    }
}
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut app: S, target: String) -> io::Result<()> {
    if target != "sp.v2.udp-over-tcp.arpa:0" {
        let address: SocketAddr = target.parse().unwrap();
        assert!(address.ip().is_loopback());
        let mut remote = TcpStream::connect(address).await?;
        tokio::io::copy_bidirectional(&mut app, &mut remote).await?;
        return Ok(());
    }
    assert_eq!(app.read_u8().await?, 1, "正式v2 isConnect=true");
    let destination = common::read_address(&mut app).await;
    assert!(destination.ip().is_loopback());
    let socket = UdpSocket::bind(if destination.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .await?;
    socket.connect(destination).await?;
    loop {
        let mut head = [0; 2];
        if app.read(&mut head[..1]).await? == 0 {
            return app.shutdown().await;
        }
        app.read_exact(&mut head[1..]).await?;
        let length = u16::from_be_bytes(head) as usize;
        let mut payload = vec![0; length];
        app.read_exact(&mut payload).await?;
        socket.send(&payload).await?;
        let mut reply = vec![0; 65536];
        let received = socket.recv(&mut reply).await?;
        app.write_all(&(received as u16).to_be_bytes()).await?;
        app.write_all(&reply[..received]).await?;
        app.flush().await?;
    }
}
fn proxy(cert: &Certificate, address: SocketAddr, udp: bool) -> Value {
    json!({"type":"naive","tag":"up","endpoint":address.to_string(),"username":"test-user","password":"test-password",
        "tls":{"ca_file":cert.dir.path().join("cert.pem"),"server_name":"localhost"},
        "naive":{"http_version":"1.1","h1_padding":true,"udp_over_tcp":udp}})
}
fn downstream(proxy: Value) -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[proxy,{"type":"reject","tag":"reject"}],
        "route":{"default":"up"},"limits":{"shutdown_timeout_ms":300,"handshake_timeout_ms":1000,"dial_timeout_ms":1200}})
}
fn packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    [vec![0, 0, 0], common::address(target), payload.to_vec()].concat()
}
async fn association(address: SocketAddr) -> (TcpStream, UdpSocket) {
    let (control, mut relay) =
        common::socks(3, common::address("0.0.0.0:0".parse().unwrap()), address).await;
    if relay.ip().is_unspecified() {
        relay.set_ip(address.ip());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    (control, socket)
}
async fn datagram(socket: &UdpSocket, target: SocketAddr, bytes: &[u8]) {
    socket.send(&packet(target, bytes)).await.unwrap();
    let mut reply = vec![0; 65536];
    let n = timeout(WAIT, socket.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..n], packet(target, bytes));
}

/// 等待端口释放后重新绑定 TCP；最多 3 秒。
async fn bind_retry(address: std::net::SocketAddr) -> TcpListener {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match TcpListener::bind(address).await {
            Ok(listener) => return listener,
            Err(error) if std::time::Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("停止后端口无法重新绑定: {error}"),
        }
    }
}

/// 同上，用于 UDP 端口。
async fn bind_udp_retry(address: std::net::SocketAddr) -> UdpSocket {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match UdpSocket::bind(address).await {
            Ok(socket) => return socket,
            Err(error) if std::time::Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("停止后 UDP 端口无法重新绑定: {error}"),
        }
    }
}

#[tokio::test]
async fn padded_h1_tcp_large_payload_reverse_fin_and_no_connection_pool() {
    let cert = Certificate::new();
    let peer = Peer::start(&cert).await;
    let down = Running::start(downstream(proxy(&cert, peer.address, false))).await;
    for after_eof in [false, true] {
        let echo = Echo::tcp("127.0.0.1", after_eof).await;
        let (mut stream, _) = common::socks(1, common::address(echo.address), down.address).await;
        let bytes = vec![0x55; 160 * 1024];
        stream.write_all(&bytes).await.unwrap();
        if after_eof {
            stream.shutdown().await.unwrap();
        }
        let mut reply = vec![0; bytes.len()];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, bytes);
        drop(stream);
    }
    assert_eq!(peer.count.load(Ordering::SeqCst), 2);
    assert_eq!(peer.targets.lock().unwrap().len(), 2);
    let local = down.address;
    down.shutdown().await;
    TcpListener::bind(local).await.unwrap();
    peer.shutdown().await;
}

#[tokio::test]
async fn padded_h1_uot_multiple_targets_empty_ipv6_and_target_payload_limits() {
    let cert = Certificate::new();
    let peer = Peer::start(&cert).await;
    let mut value = downstream(proxy(&cert, peer.address, true));
    value["limits"]["max_udp_targets"] = json!(2);
    value["limits"]["max_udp_payload"] = json!(4096);
    let down = Running::start(value).await;
    let first = Echo::udp("127.0.0.1").await;
    let second = Echo::udp("127.0.0.1").await;
    let (control, socket) = association(down.address).await;
    for (target, bytes) in [
        (first.address, b"one".as_slice()),
        (second.address, b"two"),
        (first.address, b""),
        (second.address, b"again"),
    ] {
        datagram(&socket, target, bytes).await;
    }
    datagram(&socket, first.address, &vec![0x5a; 4096]).await;
    socket
        .send(&packet(first.address, &vec![0; 4097]))
        .await
        .unwrap();
    datagram(&socket, second.address, b"survives-limit").await;
    let denied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send(&packet(denied.local_addr().unwrap(), b"third"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), denied.recv(&mut [0; 64]))
            .await
            .is_err()
    );
    assert_eq!(peer.count.load(Ordering::SeqCst), 2);
    drop(socket);
    drop(control);
    if UdpSocket::bind("[::1]:0").await.is_ok() {
        let echo = Echo::udp("[::1]").await;
        let (control, socket) = association(down.address).await;
        datagram(&socket, echo.address, b"v6").await;
        drop(socket);
        drop(control);
    }
    assert!(
        peer.targets
            .lock()
            .unwrap()
            .iter()
            .all(|target| target == "sp.v2.udp-over-tcp.arpa:0")
    );
    let address = down.address;
    down.shutdown().await;
    // shutdown 返回与内核释放监听端口之间不保证同步；并发全量下需要重试，
    // 断言本身仍是「停止后端口可以再次绑定」。
    let listener = bind_retry(address).await;
    drop(listener);
    let socket = bind_udp_retry(address).await;
    drop(socket);
    peer.shutdown().await;
}

#[tokio::test]
async fn padded_h1_tcp_chain_both_sides_and_udp_via_rejected_without_dial() {
    let cert = Certificate::new();
    let peer = Peer::start(&cert).await;
    let socks = Running::start(common::socks_config()).await;
    for last in [true, false] {
        let mut naive = proxy(&cert, peer.address, false);
        naive["tag"] = json!(if last { "up" } else { "first" });
        let mut hop = json!({"type":"socks5","tag":if last {"first"} else {"up"},"endpoint":socks.address.to_string()});
        if last {
            naive["via"] = json!("first");
        } else {
            hop["via"] = json!("first");
        }
        let mut value = downstream(naive.clone());
        value["outbounds"] = json!([naive, hop]);
        let down = Running::start(value).await;
        let echo = Echo::tcp("127.0.0.1", false).await;
        let (mut stream, _) = common::socks(1, common::address(echo.address), down.address).await;
        stream.write_all(b"chain-profile").await.unwrap();
        let mut reply = [0; 13];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"chain-profile");
        drop(stream);
        down.shutdown().await;
    }
    let before = peer.count.load(Ordering::SeqCst);
    let mut out = proxy(&cert, peer.address, true);
    out["via"] = json!("first");
    let mut value = downstream(out);
    value["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"socks5","tag":"first","endpoint":socks.address.to_string()}));
    Config::from_json(&value.to_string()).unwrap();
    let down = Running::start(value).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (control, socket) = association(down.address).await;
    socket
        .send(&packet(target.local_addr().unwrap(), b"must-not-dial"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), target.recv(&mut [0; 64]))
            .await
            .is_err()
    );
    assert_eq!(peer.count.load(Ordering::SeqCst), before);
    drop(control);
    drop(socket);
    down.shutdown().await;
    socks.shutdown().await;
    peer.shutdown().await;
}

#[tokio::test]
async fn padded_h1_wrong_identity_ca_and_route_reject_do_not_reach_targets() {
    let cert = Certificate::new();
    let other = Certificate::new();
    let peer = Peer::start(&cert).await;
    for scenario in 0..3 {
        let mut out = proxy(&cert, peer.address, true);
        if scenario == 0 {
            out["password"] = json!("wrong-password");
        }
        if scenario == 1 {
            out["tls"]["ca_file"] = json!(other.dir.path().join("cert.pem"));
        }
        let mut value = downstream(out);
        if scenario == 2 {
            value["route"]["default"] = json!("reject");
        }
        let before = peer.count.load(Ordering::SeqCst);
        let down = Running::start(value).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(down.address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        client.read_exact(&mut [0; 2]).await.unwrap();
        let mut request = vec![5, 1, 0];
        request.extend(common::address(target.local_addr().unwrap()));
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 3];
        timeout(WAIT, client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(reply[1], 0);
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (control, socket) = association(down.address).await;
        socket
            .send(&packet(udp.local_addr().unwrap(), b"not-authorized"))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(150), udp.recv(&mut [0; 64]))
                .await
                .is_err()
        );
        assert_eq!(down.stats.snapshot().uplink, 0);
        assert_eq!(down.stats.snapshot().downlink, 0);
        assert!(peer.targets.lock().unwrap().is_empty());
        if scenario == 2 {
            assert_eq!(peer.count.load(Ordering::SeqCst), before);
        }
        drop(client);
        drop(control);
        drop(socket);
        down.shutdown().await;
    }
    peer.shutdown().await;
}

#[tokio::test]
async fn forced_shutdown_releases_padded_h1_blocked_stream_and_udp_association() {
    let cert = Certificate::new();
    let peer = Peer::start(&cert).await;
    let down = Running::start(downstream(proxy(&cert, peer.address, true))).await;
    let echo = Echo::udp("127.0.0.1").await;
    let (control, socket) = association(down.address).await;
    datagram(&socket, echo.address, b"active-uot").await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stream, _) = common::socks(
        1,
        common::address(target.local_addr().unwrap()),
        down.address,
    )
    .await;
    let (mut remote, _) = target.accept().await.unwrap();
    let writer = tokio::spawn(async move {
        let bytes = vec![0x44; 1024 * 1024];
        while remote.write_all(&bytes).await.is_ok() {}
    });
    let address = down.address;
    down.shutdown().await;
    drop(stream);
    drop(control);
    drop(socket);
    writer.abort();
    let _ = writer.await;
    TcpListener::bind(address).await.unwrap();
    UdpSocket::bind(address).await.unwrap();
    peer.shutdown().await;
}
