//! 真实 REALITY preflight 会话上的 Controlled/Vision IO 边界。
//! 此处隔离承载而直接提供 AuthKey；SessionID/auth 两遍独立客户端在集成测试覆盖。
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    future::poll_fn,
    io::{Read, Write},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context as PollContext, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::time::timeout;

const AUTH: [u8; 32] = [0x12; 32];
const UUID: [u8; 16] = [0x42; 16];
const LIMIT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct VerifyHmac;
impl ServerCertVerifier for VerifyHmac {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let invalid = || rustls::Error::General("独立 REALITY 承载单测证书验证失败".into());
        if !intermediates.is_empty() {
            return Err(invalid());
        }
        // yasna 解析真实 DER，不调用受测证书模块或盲固定偏移。
        let (tbs, signature) = yasna::parse_der(cert, |reader| {
            reader.read_sequence(|reader| {
                let tbs = reader.next().read_der()?;
                reader.next().read_der()?;
                let (signature, bits) = reader.next().read_bitvec_bytes()?;
                if bits != 512 {
                    return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                }
                Ok((tbs, signature))
            })
        })
        .map_err(|_| invalid())?;
        let public = yasna::parse_der(&tbs, |reader| {
            reader.read_sequence(|reader| {
                for _ in 0..6 {
                    reader.next().read_der()?;
                }
                let public = reader.next().read_sequence(|reader| {
                    reader.next().read_sequence(|reader| {
                        if reader.next().read_oid()?.components().as_slice() != [1, 3, 101, 112] {
                            return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                        }
                        Ok(())
                    })?;
                    let (public, bits) = reader.next().read_bitvec_bytes()?;
                    if bits != 256 {
                        return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                    }
                    Ok(public)
                })?;
                while reader.read_optional(|reader| reader.read_der())?.is_some() {}
                Ok(public)
            })
        })
        .map_err(|_| invalid())?;
        aws_lc_rs::hmac::verify(
            &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA512, &AUTH),
            &public,
            &signature,
        )
        .map_err(|_| invalid())?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("单测仅TLS1.3".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

struct Gate {
    blocked: AtomicBool,
    pending: AtomicUsize,
    short: AtomicUsize,
    waker: std::sync::Mutex<Option<Waker>>,
}
impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            blocked: AtomicBool::new(false),
            pending: AtomicUsize::new(0),
            short: AtomicUsize::new(0),
            waker: std::sync::Mutex::new(None),
        })
    }
    fn set(&self, blocked: bool) {
        self.blocked.store(blocked, Ordering::SeqCst);
        if !blocked && let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}
struct ShortIo {
    io: DuplexStream,
    gate: Arc<Gate>,
    chunk: usize,
    pending_next: bool,
}
impl AsyncRead for ShortIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut PollContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut bytes = [0; 17];
        let mut buffer = ReadBuf::new(&mut bytes[..self.chunk.min(out.remaining())]);
        match Pin::new(&mut self.io).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) => {
                out.put_slice(buffer.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl AsyncWrite for ShortIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut PollContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.gate.blocked.load(Ordering::SeqCst) {
            self.gate.pending.fetch_add(1, Ordering::SeqCst);
            *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.pending_next = !self.pending_next;
        if self.pending_next {
            self.gate.pending.fetch_add(1, Ordering::SeqCst);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let limit = self.chunk.min(bytes.len());
        let result = Pin::new(&mut self.io).poll_write(cx, &bytes[..limit]);
        if let Poll::Ready(Ok(n)) = result
            && n < bytes.len()
        {
            self.gate.short.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut PollContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut PollContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
struct Peer {
    io: DuplexStream,
    tls: ClientConnection,
}
impl Peer {
    fn output(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut out).unwrap();
        }
        out
    }
    async fn flush(&mut self) {
        let out = self.output();
        self.io.write_all(&out).await.unwrap();
    }
    async fn record(&mut self) {
        let mut header = [0; 5];
        self.io.read_exact(&mut header).await.unwrap();
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        assert!(length <= 18432);
        let mut wire = header.to_vec();
        wire.resize(length + 5, 0);
        self.io.read_exact(&mut wire[5..]).await.unwrap();
        let mut input = wire.as_slice();
        while !input.is_empty() {
            self.tls.read_tls(&mut input).unwrap();
            self.tls.process_new_packets().unwrap();
        }
    }
    async fn handshake(&mut self) {
        while self.tls.is_handshaking() {
            self.record().await;
        }
        self.flush().await;
    }
    async fn send(&mut self, bytes: &[u8]) {
        self.tls.writer().write_all(bytes).unwrap();
        self.flush().await;
    }
    async fn plain(&mut self, count: usize) -> Vec<u8> {
        let mut out = vec![0; count];
        let mut offset = 0;
        while offset < count {
            match self.tls.reader().read(&mut out[offset..]) {
                Ok(n) if n > 0 => offset += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.record().await,
                other => panic!("独立对端明文: {other:?}"),
            }
        }
        out
    }
    async fn eof(&mut self) {
        loop {
            match self.tls.reader().read(&mut [0; 1]) {
                Ok(0) => return,
                Ok(_) => panic!("未预期的关闭前明文"),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.record().await,
                Err(e) => panic!("真实TLS关闭失败 {e}"),
            }
        }
    }
}

async fn setup(chunk: usize) -> (Controlled<ShortIo>, Peer, Arc<Gate>) {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let client_config = ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(VerifyHmac))
        .with_no_client_auth();
    let mut client =
        ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap()).unwrap();
    let mut ch = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut ch).unwrap();
    }
    let hello = hello::read(&mut ch.as_slice()).await.unwrap();
    // 独立普通 target 只生成同一 CH 的真实 SH；不会向其证书信任回退。
    let target_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let target_certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&target_key)
        .unwrap();
    let mut target_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![target_certificate.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(target_key.serialize_der()).into(),
        )
        .unwrap();
    target_config.send_tls13_tickets = 0;
    assert!(target_config.reality.is_none());
    let mut target = ServerConnection::new(Arc::new(target_config)).unwrap();
    target.read_tls(&mut ch.as_slice()).unwrap();
    target.process_new_packets().unwrap();
    let mut flight = Vec::new();
    while target.wants_write() {
        target.write_tls(&mut flight).unwrap();
    }
    let sh_length = usize::from(u16::from_be_bytes([flight[3], flight[4]]));
    let raw_sh = flight[5..5 + sh_length].to_vec();
    let plan =
        rustls::server::reality::RecordPlan::new(sh_length + 5, 6, vec![4096], None).unwrap();
    let config: Reality = serde_json::from_value(serde_json::json!({"target":{"host":"127.0.0.1","port":9443},
        "private_key":URL_SAFE_NO_PAD.encode([0x59;32]),"server_names":["localhost"],"short_ids":[""]})).unwrap();
    let imported = config.prepare().unwrap();
    let prepared = Prepared::new(
        config,
        imported,
        Arc::new(replay::ReplayPool::new(1).unwrap()),
        Duration::from_secs(241),
        Arc::from([]),
        Vec::new(),
    )
    .unwrap();
    let session = prepared
        .prepare_session(&hello, AUTH, raw_sh, plan)
        .unwrap();
    let (client_io, server_io) = tokio::io::duplex(128);
    let gate = Gate::new();
    let mut peer = Peer {
        io: client_io,
        tls: client,
    };
    let io = ShortIo {
        io: server_io,
        gate: gate.clone(),
        chunk,
        pending_next: false,
    };
    let (stream, ()) = timeout(LIMIT, async {
        tokio::join!(Controlled::accept_prepared(io, session), peer.handshake())
    })
    .await
    .unwrap();
    assert!(!peer.tls.is_handshaking());
    assert!(gate.pending.load(Ordering::SeqCst) > 0);
    assert!(gate.short.load(Ordering::SeqCst) > 0);
    (stream.unwrap(), peer, gate)
}

#[tokio::test]
async fn reality_prepared_short_pending_io_preserves_both_directions_and_close() {
    for chunk in [1, 7, 17] {
        let (mut server, mut peer, _) = setup(chunk).await;
        timeout(LIMIT, async {
            let server_side = async {
                let mut bytes = [0; 24];
                server.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"short-input-exactly-once");
                server
                    .write_all(b"short-output-exactly-once")
                    .await
                    .unwrap();
                server.shutdown().await.unwrap();
            };
            let client_side = async {
                peer.send(b"short-input-exactly-once").await;
                assert_eq!(peer.plain(25).await, b"short-output-exactly-once");
                peer.eof().await;
            };
            tokio::join!(server_side, client_side);
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn reality_prepared_vision_shutdown_first_pending_rejects_new_counted_payload() {
    use crate::{
        telemetry::{Counted, Stats},
        tls::vision::Vision,
    };
    for chunk in [1, 7] {
        for initial in [&b""[..], &b"\x16"[..]] {
            let (server, mut peer, gate) = setup(chunk).await;
            let stats = Arc::new(Stats::default());
            let mut server = Counted {
                inner: Vision::new(server, UUID),
                stats: stats.clone(),
                uplink: false,
            };
            server.write_all(initial).await.unwrap();
            let before = stats.snapshot().downlink;
            gate.set(true);
            poll_fn(|cx| {
                assert!(Pin::new(&mut server).poll_shutdown(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(
                server.write(b"late-before-close").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(stats.snapshot().downlink, before);
            gate.set(false);
            timeout(LIMIT, async {
                let close = async {
                    if !initial.is_empty() {
                        let prefix = peer.plain(22).await;
                        assert_eq!(&prefix[..16], &UUID);
                        assert_eq!(&prefix[16..19], &[0, 0, 1]);
                        assert_eq!(prefix[21], initial[0]);
                        let padding = usize::from(u16::from_be_bytes([prefix[19], prefix[20]]));
                        peer.plain(padding).await;
                    }
                    peer.eof().await;
                };
                let (result, ()) = tokio::join!(server.shutdown(), close);
                result.unwrap();
            })
            .await
            .unwrap();
            assert_eq!(
                server.write(b"late-after-close").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(stats.snapshot().downlink, before);
            assert_eq!(stats.snapshot().uplink, 0);
        }
    }
}

#[tokio::test]
async fn reality_prepared_output_gate_does_not_stop_ready_authenticated_read_or_keyupdate() {
    let (mut server, mut peer, gate) = setup(7).await;
    peer.tls.refresh_traffic_keys().unwrap();
    peer.send(b"ready-input").await;
    gate.set(true);
    server.write_all(b"queued-output").await.unwrap();
    let mut bytes = [0; 11];
    timeout(Duration::from_millis(250), server.read_exact(&mut bytes))
        .await
        .expect("输出 gate 阻塞时已就绪认证记录仍须前进")
        .unwrap();
    assert_eq!(&bytes, b"ready-input");
    assert!(gate.blocked.load(Ordering::SeqCst));
    gate.set(false);
    timeout(LIMIT, async {
        let (result, bytes) = tokio::join!(server.flush(), peer.plain(13));
        result.unwrap();
        assert_eq!(bytes, b"queued-output");
    })
    .await
    .unwrap();
}
