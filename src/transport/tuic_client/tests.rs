use super::*;
use crate::{config::Config, session::Target};
use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(3);
const UUID: [u8; 16] = [0x31; 16];
const PASSWORD: &str = "tuic-modern-test-password";

#[derive(Debug)]
struct Tickets {
    inner: ClientSessionMemoryCache,
    inserted: AtomicUsize,
}
impl Tickets {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: ClientSessionMemoryCache::new(8),
            inserted: AtomicUsize::new(0),
        })
    }
    async fn wait_for(&self, minimum: usize) {
        timeout(WAIT, async {
            while self.inserted.load(Ordering::SeqCst) < minimum {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
impl ClientSessionStore for Tickets {
    fn set_kx_hint(&self, name: ServerName<'static>, group: rustls::NamedGroup) {
        self.inner.set_kx_hint(name, group);
    }
    fn kx_hint(&self, name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.inner.kx_hint(name)
    }
    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(name, value);
    }
    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(name)
    }
    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        self.inner.remove_tls12_session(name);
    }
    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.inner.insert_tls13_ticket(name, value);
        self.inserted.fetch_add(1, Ordering::SeqCst);
    }
    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(name)
    }
}
fn tls() -> (rustls::ServerConfig, Arc<ClientConfig>, Arc<Tickets>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate: CertificateDer<'static> = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
    server.max_early_data_size = u32::MAX;
    server.send_tls13_tickets = 4;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tickets = Tickets::new();
    client.resumption = rustls::client::Resumption::store(tickets.clone());
    (server, Arc::new(client), tickets)
}
fn quic_server(tls: rustls::ServerConfig) -> quinn::ServerConfig {
    quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ))
}
fn context() -> Context {
    let config=Config::from_json(r#"{"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"dial_timeout_ms":1000}}"#).unwrap();
    Context::new(&config).unwrap()
}
fn header() -> Vec<u8> {
    vec![5, 1, 1, 127, 0, 0, 1, 0, 9]
}
async fn auth(connection: &quinn::Connection) {
    let mut auth = timeout(WAIT, connection.accept_uni())
        .await
        .unwrap()
        .unwrap();
    let frame = timeout(WAIT, auth.read_to_end(50)).await.unwrap().unwrap();
    assert_eq!(frame.len(), 50);
    assert_eq!(&frame[..2], &[5, 0]);
    assert_eq!(&frame[2..18], &UUID);
    let mut token = [0; 32];
    connection
        .export_keying_material(&mut token, &UUID, PASSWORD.as_bytes())
        .unwrap();
    assert_eq!(&frame[18..], &token);
}
async fn serve_tcp(connection: quinn::Connection) {
    auth(&connection).await;
    let (mut send, mut recv) = timeout(WAIT, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let mut request = [0; 9];
    recv.read_exact(&mut request).await.unwrap();
    assert_eq!(request, header().as_slice());
    let mut payload = [0; 4];
    recv.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"ping");
    send.write_all(b"pong").await.unwrap();
    send.finish().unwrap();
    // 一次连接只应收到一个Connect；拒绝恢复不能产生第二份目标请求。
    assert!(!matches!(
        timeout(Duration::from_millis(40), connection.accept_bi()).await,
        Ok(Ok(_))
    ));
    let _ = connection.closed().await;
}
async fn exchange(client: &ClientPrepared, context: &Context) -> (State, bool, bool) {
    let (state, stream) = client.start(context, Some(&header())).await.unwrap();
    let attempted = state.attempted_early;
    let accepted = state.accepted_early;
    let (mut send, mut recv) = stream.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let data = timeout(WAIT, recv.read_to_end(4)).await.unwrap().unwrap();
    assert_eq!(data, b"pong");
    (state, attempted, accepted)
}

#[tokio::test]
async fn ticket_resumption_uses_real_early_path_and_rebuilds_only_rejected_metadata() {
    for reject_early in [false, true] {
        let (server_tls, client_tls, tickets) = tls();
        let endpoint = Endpoint::server(
            quic_server(server_tls.clone()),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let incoming = endpoint.clone();
        let server = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let connection = incoming.accept().await.unwrap().await.unwrap();
                tasks.spawn(serve_tcp(connection));
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let client = ClientPrepared::new(
            address.into(),
            client_tls,
            "localhost".into(),
            UUID,
            PASSWORD.into(),
            TuicClientOptions {
                zero_rtt_handshake: true,
                congestion_control: Some("bbr".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let context = context();
        let (first, attempted, accepted) = exchange(&client, &context).await;
        assert!(!attempted && !accepted, "无票据首连不能宣称0-RTT");
        tickets.wait_for(1).await;
        // 保留同一证书与有状态ticket store，只关闭接受early_data；TLS恢复仍可成功。
        if reject_early {
            let mut config = server_tls;
            config.max_early_data_size = 0;
            endpoint.set_server_config(Some(quic_server(config)));
        }
        let (second, attempted, accepted) = exchange(&client, &context).await;
        assert!(attempted, "有票据必须真实调用并成功进入into_0rtt");
        assert_eq!(accepted, !reject_early);
        let local = client
            .endpoints
            .lock()
            .await
            .v4
            .as_ref()
            .unwrap()
            .0
            .local_addr()
            .unwrap();
        drop(first);
        drop(second);
        drop(client);
        timeout(WAIT, server).await.unwrap().unwrap();
        endpoint.close(0u32.into(), b"done");
        timeout(WAIT, async {
            loop {
                match UdpSocket::bind(local).await {
                    Ok(socket) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        tokio::task::yield_now().await
                    }
                    Err(error) => panic!("{error}"),
                }
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn both_udp_carriers_resume_with_heartbeat_but_send_business_after_authentication() {
    for mode in [
        crate::config::TuicUdpRelayMode::Native,
        crate::config::TuicUdpRelayMode::Quic,
    ] {
        let (server_tls, client_tls, tickets) = tls();
        let endpoint =
            Endpoint::server(quic_server(server_tls), "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let incoming = endpoint.clone();
        let server = tokio::spawn(async move {
            let first = incoming.accept().await.unwrap().await.unwrap();
            let warm = tokio::spawn(serve_tcp(first));
            let connection = incoming.accept().await.unwrap().await.unwrap();
            auth(&connection).await;
            if mode == crate::config::TuicUdpRelayMode::Native {
                loop {
                    let frame = timeout(WAIT, connection.read_datagram())
                        .await
                        .unwrap()
                        .unwrap();
                    if frame[..] == [5, 4] {
                        continue;
                    }
                    assert_eq!(&frame[..2], &[5, 2]);
                    let decoded = wire::decode_udp_body(&frame[2..]).unwrap();
                    assert_eq!(decoded.payload, b"udp-resume");
                    connection.send_datagram(frame).unwrap();
                    break;
                }
            } else {
                let mut stream = timeout(WAIT, connection.accept_uni())
                    .await
                    .unwrap()
                    .unwrap();
                let frame = stream.read_to_end(1024).await.unwrap();
                assert_eq!(&frame[..2], &[5, 2]);
                let decoded = wire::decode_udp_body(&frame[2..]).unwrap();
                assert_eq!(decoded.payload, b"udp-resume");
                let mut reply = connection.open_uni().await.unwrap();
                reply.write_all(&frame).await.unwrap();
                reply.finish().unwrap();
            }
            let _ = connection.closed().await;
            warm.await.unwrap();
        });
        let client = ClientPrepared::new(
            address.into(),
            client_tls,
            "localhost".into(),
            UUID,
            PASSWORD.into(),
            TuicClientOptions {
                zero_rtt_handshake: true,
                ..Default::default()
            },
        )
        .unwrap();
        let context = context();
        let (first, _, _) = exchange(&client, &context).await;
        tickets.wait_for(1).await;
        let mut parts = client.open_udp(&context, mode).await.unwrap();
        assert!(parts.keepalive.0.attempted_early);
        assert!(parts.keepalive.0.accepted_early);
        let target: Target = "127.0.0.1:9"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        parts.sender.send(&target, b"udp-resume").await.unwrap();
        let (source, payload) = timeout(WAIT, parts.receiver.recv()).await.unwrap().unwrap();
        assert_eq!(source, target);
        assert_eq!(payload, b"udp-resume");
        drop(parts);
        drop(first);
        drop(client);
        timeout(WAIT, server).await.unwrap().unwrap();
        endpoint.close(0u32.into(), b"done");
    }
}

#[tokio::test]
async fn native_udp_requires_negotiated_datagrams_before_business_packets() {
    let (server_tls, client_tls, _) = tls();
    let mut config = quic_server(server_tls);
    let mut transport = quinn::TransportConfig::default();
    // 服务端不接收QUIC数据报；Native载体在握手后即可判定不可用。
    transport.datagram_receive_buffer_size(None);
    config.transport_config(Arc::new(transport));
    let endpoint = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let incoming = endpoint.clone();
    let (authenticated, wait_authenticated) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        // Native 失败连接可能在认证帧被服务端读完前关闭；先接收两条连接，
        // 避免等待其关闭拖过客户端第二次握手的期限。
        let failed = incoming.accept().await.unwrap().await.unwrap();
        let streamed = incoming.accept().await.unwrap().await.unwrap();
        // 流载体连接必须完成正式认证；客户端等确认后再释放会话。
        auth(&streamed).await;
        let _ = authenticated.send(());
        let _ = timeout(WAIT, failed.closed()).await;
        let _ = streamed.closed().await;
    });
    let client = ClientPrepared::new(
        address.into(),
        client_tls,
        "localhost".into(),
        UUID,
        PASSWORD.into(),
        TuicClientOptions::default(),
    )
    .unwrap();
    let context = context();
    let error = client
        .open_udp(&context, crate::config::TuicUdpRelayMode::Native)
        .await
        .err()
        .expect("未协商DATAGRAM的Native载体必须提前失败");
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    // 流载体不依赖QUIC DATAGRAM，不能因Native能力缺失被误拒绝。
    let parts = client
        .open_udp(&context, crate::config::TuicUdpRelayMode::Quic)
        .await
        .unwrap();
    timeout(WAIT, wait_authenticated).await.unwrap().unwrap();
    drop(parts);
    drop(client);
    timeout(WAIT, server).await.unwrap().unwrap();
    endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn cancelled_early_connection_is_closed_without_background_auth_task() {
    let (server_tls, client_tls, tickets) = tls();
    let endpoint =
        Endpoint::server(quic_server(server_tls), "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let incoming = endpoint.clone();
    let (seen, received) = tokio::sync::oneshot::channel();
    let (resume, continue_accepting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let first = incoming.accept().await.unwrap().await.unwrap();
        let first_task = tokio::spawn(serve_tcp(first));
        let second = incoming.accept().await.unwrap();
        let _ = seen.send(());
        let _ = continue_accepting.await;
        let outcome = timeout(WAIT, second).await;
        if let Ok(Ok(connection)) = outcome {
            let _ = timeout(WAIT, connection.closed()).await.unwrap();
        }
        first_task.await.unwrap();
    });
    let client = ClientPrepared::new(
        address.into(),
        client_tls,
        "localhost".into(),
        UUID,
        PASSWORD.into(),
        TuicClientOptions {
            zero_rtt_handshake: true,
            ..Default::default()
        },
    )
    .unwrap();
    let context = context();
    let (first, _, _) = exchange(&client, &context).await;
    tickets.wait_for(1).await;
    let request = header();
    let mut connecting = Box::pin(client.start(&context, Some(&request)));
    tokio::select! { result=&mut connecting=>panic!("服务端未接受时不应完成: {}",result.is_ok()), _=received=>{} }
    drop(connecting);
    let _ = resume.send(());
    drop(first);
    drop(client);
    timeout(WAIT, server).await.unwrap().unwrap();
    endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn default_disabled_never_sends_early_even_after_receiving_tickets() {
    let (server_tls, client_tls, tickets) = tls();
    let endpoint =
        Endpoint::server(quic_server(server_tls), "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let incoming = endpoint.clone();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..2 {
            tasks.spawn(serve_tcp(incoming.accept().await.unwrap().await.unwrap()));
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });
    let client = ClientPrepared::new(
        address.into(),
        client_tls,
        "localhost".into(),
        UUID,
        PASSWORD.into(),
        TuicClientOptions::default(),
    )
    .unwrap();
    let context = context();
    let (first, attempted, _) = exchange(&client, &context).await;
    assert!(!attempted);
    tickets.wait_for(1).await;
    let (second, attempted, accepted) = exchange(&client, &context).await;
    assert!(!attempted && !accepted);
    drop(first);
    drop(second);
    drop(client);
    timeout(WAIT, server).await.unwrap().unwrap();
    endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn endpoint_owner_drop_preserves_live_stream_and_final_drop_releases_socket() {
    let (server_tls, client_tls, _) = tls();
    let endpoint =
        Endpoint::server(quic_server(server_tls), "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let incoming = endpoint.clone();
    let server = tokio::spawn(async move {
        serve_tcp(incoming.accept().await.unwrap().await.unwrap()).await;
    });
    let client = ClientPrepared::new(
        address.into(),
        client_tls,
        "localhost".into(),
        UUID,
        PASSWORD.into(),
        TuicClientOptions::default(),
    )
    .unwrap();
    let context = context();
    let target: Target = "127.0.0.1:9"
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into();
    let mut stream = client.connect(&context, &target).await.unwrap();
    let local = client
        .endpoints
        .lock()
        .await
        .v4
        .as_ref()
        .unwrap()
        .0
        .local_addr()
        .unwrap();
    drop(client);
    stream.write_all(b"ping").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"pong");
    drop(stream);
    timeout(WAIT, server).await.unwrap().unwrap();
    endpoint.close(0u32.into(), b"done");
    timeout(WAIT, async {
        loop {
            match UdpSocket::bind(local).await {
                Ok(socket) => break socket,
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("{error}"),
            }
        }
    })
    .await
    .unwrap();
}
