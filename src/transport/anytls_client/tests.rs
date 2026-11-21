use super::super::anytls_padding::DEFAULT_SCHEME;
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, timeout},
};
const WAIT: Duration = Duration::from_secs(2);
const PASSWORD: &str = "anytls-padding-client-test";
fn target() -> Target {
    "127.0.0.1:80"
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into()
}
async fn packet<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, u32, Vec<u8>) {
    let mut header = [0; 7];
    stream.read_exact(&mut header).await.unwrap();
    let id = u32::from_be_bytes(header[1..5].try_into().unwrap());
    let mut payload = vec![0; usize::from(u16::from_be_bytes([header[5], header[6]]))];
    stream.read_exact(&mut payload).await.unwrap();
    (header[0], id, payload)
}
async fn prologue<S: AsyncRead + Unpin>(stream: &mut S) -> usize {
    let mut digest = [0; 32];
    stream.read_exact(&mut digest).await.unwrap();
    assert_eq!(
        digest,
        <[u8; 32]>::from(Sha256::digest(PASSWORD.as_bytes()))
    );
    let length = usize::from(stream.read_u16().await.unwrap());
    let mut padding = vec![0; length];
    stream.read_exact(&mut padding).await.unwrap();
    assert!(padding.iter().all(|byte| *byte == 0));
    length
}
async fn opening<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let settings = packet(stream).await;
    assert_eq!((settings.0, settings.1), (4, 0));
    assert_eq!(packet(stream).await, (1, 1, Vec::new()));
    let first = packet(stream).await;
    assert_eq!((first.0, first.1), (2, 1));
    assert_eq!(first.2, [1, 127, 0, 0, 1, 0, 80]);
    settings.2
}
async fn business<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, Vec<u8>, Vec<usize>) {
    let mut waste = Vec::new();
    loop {
        let (command, id, payload) = packet(stream).await;
        if command == 0 {
            assert_eq!(id, 0);
            assert!(payload.iter().all(|byte| *byte == 0));
            waste.push(payload.len());
        } else {
            assert_eq!(id, 1);
            return (command, payload, waste);
        }
    }
}

#[tokio::test]
async fn default_handshake_settings_and_remote_update_change_new_session_without_cross_outbound_leak()
 {
    const UPDATE: &str = "stop=9\n0=7-7\n1=160-160\n2=80-80\n3=90-90\n";
    let shared = Arc::new(SharedScheme::default());
    let other = Arc::new(SharedScheme::default());
    let (wire, mut peer) = tokio::io::duplex(8192);
    let mut client = connect_with_scheme(wire, &target(), PASSWORD, shared.clone())
        .await
        .unwrap();
    assert_eq!(prologue(&mut peer).await, 30);
    let settings = String::from_utf8(opening(&mut peer).await).unwrap();
    assert_eq!(
        settings,
        format!("client=dubhe\npadding-md5={}\nv=2", shared.snapshot().md5())
    );
    peer.write_all(&frame(6, 0, UPDATE.as_bytes()).unwrap())
        .await
        .unwrap();
    peer.write_all(&frame(2, 1, b"ready").unwrap())
        .await
        .unwrap();
    let mut ready = [0; 5];
    client.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"ready");
    assert_eq!(shared.snapshot().raw(), UPDATE);
    assert_eq!(other.snapshot().raw(), DEFAULT_SCHEME);
    client.write_all(b"data").await.unwrap();
    client.flush().await.unwrap();
    let (command, payload, _) = business(&mut peer).await;
    assert_eq!(command, 2);
    assert_eq!(payload, b"data");
    // 该业务批次packet2为80字节，PSH占11字节，其余为Waste头7+payload62。
    let waste = packet(&mut peer).await;
    assert_eq!((waste.0, waste.1, waste.2.len()), (0, 0, 62));
    drop(client);
    let (wire, mut peer) = tokio::io::duplex(8192);
    let client = connect_with_scheme(wire, &target(), PASSWORD, shared.clone())
        .await
        .unwrap();
    assert_eq!(prologue(&mut peer).await, 7);
    let settings = String::from_utf8(opening(&mut peer).await).unwrap();
    assert!(settings.contains(&format!("padding-md5={}", shared.snapshot().md5())));
    drop(client);
}

#[tokio::test]
async fn invalid_or_truncated_update_keeps_old_scheme_and_no_bytes_are_business() {
    let shared = Arc::new(SharedScheme::default());
    let original = shared.snapshot().md5().to_owned();
    let (wire, mut peer) = tokio::io::duplex(8192);
    let mut client = connect_with_scheme(wire, &target(), PASSWORD, shared.clone())
        .await
        .unwrap();
    prologue(&mut peer).await;
    opening(&mut peer).await;
    peer.write_all(&frame(6, 0, b"stop=8\n1=99999999-99999999").unwrap())
        .await
        .unwrap();
    peer.write_all(&frame(2, 1, b"good").unwrap())
        .await
        .unwrap();
    let mut bytes = [0; 4];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"good");
    assert_eq!(shared.snapshot().md5(), original);
    let mut truncated = frame(6, 0, b"stop=4\n0=9-9").unwrap();
    truncated.truncate(truncated.len() - 2);
    peer.write_all(&truncated).await.unwrap();
    peer.shutdown().await.unwrap();
    assert_eq!(
        client.read(&mut bytes).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(shared.snapshot().md5(), original);
    assert!(client.write(b"after-failure").await.is_err());
}

struct Gate {
    inner: tokio::io::DuplexStream,
    blocked: Arc<AtomicBool>,
}
impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.blocked.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        let count = bytes.len().min(2);
        Pin::new(&mut self.inner).poll_write(cx, &bytes[..count])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn short_writes_cancelled_next_write_flush_and_fin_keep_exact_business_once() {
    let schemes = Arc::new(SharedScheme::default());
    assert!(schemes.update(b"stop=4\n0=0-0\n1=200-200\n2=80-80\n3=100-100"));
    let (wire, mut peer) = tokio::io::duplex(16384);
    let blocked = Arc::new(AtomicBool::new(false));
    let mut client = connect_with_scheme(
        Gate {
            inner: wire,
            blocked: blocked.clone(),
        },
        &target(),
        PASSWORD,
        schemes,
    )
    .await
    .unwrap();
    assert_eq!(prologue(&mut peer).await, 0);
    opening(&mut peer).await;
    blocked.store(true, Ordering::SeqCst);
    assert_eq!(client.write(b"first").await.unwrap(), 5);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(
        Pin::new(&mut client)
            .poll_write(&mut cx, b"cancelled")
            .is_pending()
    );
    blocked.store(false, Ordering::SeqCst);
    client.flush().await.unwrap();
    client.write_all(b"second").await.unwrap();
    client.shutdown().await.unwrap();
    let first = business(&mut peer).await;
    assert_eq!((first.0, first.1), (2, b"first".to_vec()));
    let second = business(&mut peer).await;
    assert_eq!((second.0, second.1), (2, b"second".to_vec()));
    let end = business(&mut peer).await;
    assert_eq!((end.0, end.1), (3, Vec::new()));
    assert!(client.write(b"late").await.is_err());
    let mut rest = Vec::new();
    timeout(WAIT, peer.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn real_runtime_tcp_and_uot_share_updated_scheme_but_other_outbound_does_not() {
    use crate::{config::Config, forward::Context as KernelContext};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio_util::sync::CancellationToken;
    const CUSTOM: &str = "stop=5\n0=7-7\n1=200-200\n2=300-300,c";
    let directory = tempfile::tempdir().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    std::fs::write(&cert, certificate.cert.pem()).unwrap();
    std::fs::write(&key, certificate.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config=Config::from_json(&serde_json::json!({"version":1,"inbounds":[{"type":"anytls","tag":"anytls","listen":"127.0.0.1:0","users":[{"name":"u","password":PASSWORD}],"certificate":cert,"private_key":key,"padding_scheme":CUSTOM}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":500}}).to_string()).unwrap();
    let server = crate::runtime::Server::bind(config).await.unwrap();
    let address = server.local_addr("anytls").unwrap();
    let stop = CancellationToken::new();
    let run = tokio::spawn(server.run(stop.clone()));
    let proxy = serde_json::json!({"type":"anytls","tag":"up","endpoint":address.to_string(),"password":PASSWORD,"tls":{"ca_file":cert,"server_name":"localhost"}});
    let mut other = proxy.clone();
    other["tag"] = serde_json::json!("other");
    let config=Config::from_json(&serde_json::json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[proxy,other],"route":{"default":"up"},"limits":{"dial_timeout_ms":1000,"udp_queue_bytes":4,"udp_queue_packets":1}}).to_string()).unwrap();
    let ctx = Arc::new(KernelContext::new(&config).unwrap());
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut peer, _) = tcp.accept().await.unwrap();
            let mut bytes = [0; 4];
            peer.read_exact(&mut bytes).await.unwrap();
            peer.write_all(&bytes).await.unwrap();
            peer.shutdown().await.unwrap();
        }
    });
    let mut tcp = ctx.connect("local", &tcp_address.into()).await.unwrap();
    tcp.write_all(b"tcp1").await.unwrap();
    tcp.flush().await.unwrap();
    let mut reply = [0; 4];
    timeout(WAIT, tcp.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"tcp1");
    let shared = ctx
        .router
        .proxy_by_tag("up")
        .unwrap()
        .anytls_padding
        .clone()
        .unwrap();
    assert_eq!(shared.snapshot().raw(), CUSTOM);
    assert_eq!(
        ctx.router
            .proxy_by_tag("other")
            .unwrap()
            .anytls_padding
            .as_ref()
            .unwrap()
            .snapshot()
            .raw(),
        DEFAULT_SCHEME
    );
    drop(tcp);
    // 下一条正式TCP与UoT都使用同一出站factory，非测试专用connect路径。
    let mut tcp = ctx.connect("local", &tcp_address.into()).await.unwrap();
    tcp.write_all(b"tcp2").await.unwrap();
    tcp.flush().await.unwrap();
    timeout(WAIT, tcp.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"tcp2");
    drop(tcp);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap();
    let udp_echo = tokio::spawn(async move {
        let mut bytes = [0; 32];
        let (count, peer) = udp.recv_from(&mut bytes).await.unwrap();
        udp.send_to(&bytes[..count], peer).await.unwrap();
    });
    let mut routed = crate::udp::RoutedUdp::new(ctx.clone(), "local".into(), udp_address.into())
        .await
        .unwrap();
    let held = ctx.udp_bytes.clone().acquire_many_owned(3).await.unwrap();
    assert_eq!(
        routed.send(b"no").await.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(held);
    routed.send(b"uot").await.unwrap();
    let reply = timeout(WAIT, routed.recv()).await.unwrap().unwrap();
    assert_eq!(reply.payload, b"uot");
    assert_eq!(
        ctx.udp_bytes.available_permits(),
        1,
        "回包仍持有业务字节预算"
    );
    drop(reply);
    assert_eq!(ctx.udp_bytes.available_permits(), 4);
    drop(routed);
    assert_eq!(shared.snapshot().handshake_size().unwrap(), 7);
    ctx.outbound_stop.cancel();
    ctx.children.close();
    timeout(WAIT, ctx.children.wait()).await.unwrap();
    assert_eq!(ctx.udp_bytes.available_permits(), 4);
    assert_eq!(
        ctx.udp_slots.available_permits(),
        ctx.limits.max_udp_associations
    );
    echo.await.unwrap();
    udp_echo.await.unwrap();
    stop.cancel();
    timeout(WAIT, run).await.unwrap().unwrap().unwrap();
    TcpListener::bind(address).await.unwrap();
}

#[tokio::test]
async fn zero_capacity_read_does_not_consume_a_padding_update() {
    let shared = Arc::new(SharedScheme::default());
    let (wire, mut peer) = tokio::io::duplex(8192);
    let mut client = connect_with_scheme(wire, &target(), PASSWORD, shared.clone())
        .await
        .unwrap();
    prologue(&mut peer).await;
    opening(&mut peer).await;
    peer.write_all(&frame(6, 0, b"stop=0\n0=7-7").unwrap())
        .await
        .unwrap();
    peer.write_all(&frame(2, 1, b"x").unwrap()).await.unwrap();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut empty = ReadBuf::new(&mut []);
    assert!(
        Pin::new(&mut client)
            .poll_read(&mut cx, &mut empty)
            .is_ready()
    );
    assert_eq!(shared.snapshot().handshake_size().unwrap(), 30);
    assert_eq!(client.read_u8().await.unwrap(), b'x');
    assert_eq!(shared.snapshot().handshake_size().unwrap(), 7);
}
