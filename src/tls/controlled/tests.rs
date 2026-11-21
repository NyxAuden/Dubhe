use super::*;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::{Duration, timeout};

fn configs(
    version: &'static rustls::SupportedProtocolVersion,
) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

// 独立对端仅使用 rustls 密码学 API，手写记录读写，不调用受测承载。
struct Peer {
    io: DuplexStream,
    session: ClientConnection,
}
impl Peer {
    async fn connect(io: DuplexStream, config: Arc<ClientConfig>) -> Self {
        let mut peer = Self {
            io,
            session: ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap(),
        };
        while peer.session.is_handshaking() {
            peer.flush().await;
            if !peer.session.is_handshaking() {
                break;
            }
            peer.record().await;
        }
        peer.flush().await;
        peer
    }
    fn output(&mut self) -> Vec<u8> {
        let mut output = Vec::new();
        while self.session.wants_write() {
            self.session.write_tls(&mut output).unwrap();
        }
        output
    }
    async fn flush(&mut self) {
        let out = self.output();
        self.io.write_all(&out).await.unwrap();
    }
    async fn record(&mut self) {
        let mut header = [0; 5];
        self.io.read_exact(&mut header).await.unwrap();
        let mut bytes = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
        self.io.read_exact(&mut bytes).await.unwrap();
        let mut wire = header.to_vec();
        wire.extend(bytes);
        let mut slice = wire.as_slice();
        while !slice.is_empty() {
            self.session.read_tls(&mut slice).unwrap();
            self.session.process_new_packets().unwrap();
        }
    }
    async fn plain(&mut self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        let mut offset = 0;
        while offset < length {
            match self.session.reader().read(&mut bytes[offset..]) {
                Ok(n) if n > 0 => offset += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.record().await,
                other => panic!("unexpected read: {other:?}"),
            }
        }
        bytes
    }
    async fn send(&mut self, bytes: &[u8]) {
        self.session.writer().write_all(bytes).unwrap();
        self.flush().await;
    }
}

struct Short<S> {
    io: S,
    chunk: usize,
    pending: bool,
}
impl<S: AsyncRead + Unpin> AsyncRead for Short<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let limit = out.remaining().min(self.chunk);
        let mut local = vec![0; limit];
        let mut buf = ReadBuf::new(&mut local);
        match Pin::new(&mut self.io).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                out.put_slice(buf.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Short<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.pending = !self.pending;
        if self.pending {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = bytes.len().min(self.chunk);
        Pin::new(&mut self.io).poll_write(cx, &bytes[..n])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn tls12_tls13_handshake_and_fragmented_io() {
    for (version, expected) in [
        (&rustls::version::TLS12, ProtocolVersion::TLSv1_2),
        (&rustls::version::TLS13, ProtocolVersion::TLSv1_3),
    ] {
        let (sc, cc) = configs(version);
        let (client, server) = tokio::io::duplex(1024);
        timeout(Duration::from_secs(5), async {
            let server = async {
                let mut s = Controlled::accept(
                    Short {
                        io: server,
                        chunk: 7,
                        pending: false,
                    },
                    sc,
                )
                .await
                .unwrap();
                assert_eq!(s.protocol_version(), Some(expected));
                let mut b = [0; 4];
                s.read_exact(&mut b).await.unwrap();
                assert_eq!(&b, b"ping");
                s.write_all(b"pong").await.unwrap();
                s.flush().await.unwrap();
                s.shutdown().await.unwrap();
            };
            let client = async {
                let mut p = Peer::connect(client, cc).await;
                p.send(b"ping").await;
                assert_eq!(p.plain(4).await, b"pong");
                let mut closed = Vec::new();
                p.io.read_to_end(&mut closed).await.unwrap();
                assert!(!closed.is_empty());
            };
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }
}

// 写 gate 只阻止密文输出，不改变同一 IO 的读就绪状态。
struct WriteGate<S> {
    io: S,
    blocked: Arc<std::sync::atomic::AtomicBool>,
    write_waker: Option<std::task::Waker>,
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteGate<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteGate<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.blocked.load(std::sync::atomic::Ordering::SeqCst) {
            // 持有被阻塞写操作的 waker；测试读取完成前始终不会打开 gate。
            self.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn ready_tls_input_progresses_while_application_output_is_backpressured() {
    let (sc, cc) = configs(&rustls::version::TLS13);
    let (client, server) = tokio::io::duplex(4096);
    let blocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = WriteGate {
        io: server,
        blocked: blocked.clone(),
        write_waker: None,
    };
    let (server, client) = timeout(Duration::from_secs(5), async {
        tokio::join!(Controlled::accept(server, sc), Peer::connect(client, cc))
    })
    .await
    .unwrap();
    let mut server = server.unwrap();
    let mut client = client;

    // 先把 ping 完整写入对端读缓冲，排除对端写等待或调度造成的超时。
    client.send(b"ping").await;
    blocked.store(true, std::sync::atomic::Ordering::SeqCst);
    // 明文已被本地 rustls writer 接受，密文尚未尝试通过已关闭的 gate。
    server.write_all(b"queued-downlink").await.unwrap();
    let mut ping = [0; 4];
    let result = timeout(Duration::from_millis(100), server.read_exact(&mut ping)).await;
    // 两端保持存活直至断言，绝不靠 close_notify/drop/BrokenPipe 驱动测试。
    assert!(
        result.is_ok(),
        "写方向背压阻止已就绪的 TLS 入站 record 被读取"
    );
    result.unwrap().unwrap();
    assert_eq!(&ping, b"ping");
    assert!(blocked.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn vision_shutdown_rejects_late_counted_writes_before_and_after_close() {
    use crate::{
        telemetry::{Counted, Stats},
        tls::vision::Vision,
    };
    use std::sync::atomic::Ordering;

    // 空下行及尚未识别完 TLS 的 Continue 下行都仍处于 framed 分支。
    for initial in [&b""[..], &b"\x16"[..]] {
        for pending_shutdown in [false, true] {
            let (sc, cc) = configs(&rustls::version::TLS13);
            let (client, server) = tokio::io::duplex(4096);
            let blocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let server = WriteGate {
                io: server,
                blocked: blocked.clone(),
                write_waker: None,
            };
            timeout(Duration::from_secs(5), async {
                let (server, mut client) =
                    tokio::join!(Controlled::accept(server, sc), Peer::connect(client, cc));
                let stats = Arc::new(Stats::default());
                let mut server = Counted {
                    inner: Vision::new(server.unwrap(), [0x42; 16]),
                    stats: stats.clone(),
                    uplink: false,
                };
                server.write_all(initial).await.unwrap();
                let before = stats.snapshot().downlink;
                assert_eq!(before, initial.len() as u64);

                if pending_shutdown {
                    blocked.store(true, Ordering::SeqCst);
                    poll_fn(|cx| {
                        assert!(Pin::new(&mut server).poll_shutdown(cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    // 即使首个 shutdown 还在排封装块/close_notify，也不能接受新正文。
                    assert_eq!(
                        server.write(b"late-before-close").await.unwrap_err().kind(),
                        io::ErrorKind::BrokenPipe
                    );
                    assert_eq!(stats.snapshot().downlink, before);
                    blocked.store(false, Ordering::SeqCst);
                }

                let receive_close = async {
                    let mut plaintext = Vec::new();
                    let mut bytes = [0; 2048];
                    loop {
                        match client.session.reader().read(&mut bytes) {
                            Ok(0) => break,
                            Ok(n) => plaintext.extend_from_slice(&bytes[..n]),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                client.record().await;
                            }
                            Err(error) => panic!("TLS close_notify 前读取失败：{error}"),
                        }
                    }
                    plaintext
                };
                let (shutdown, plaintext) = tokio::join!(server.shutdown(), receive_close);
                shutdown.unwrap();
                // 此时双方仍存活，对端已真正解密 close_notify，而非因 drop 得到 EOF。
                if initial.is_empty() {
                    assert!(plaintext.is_empty());
                } else {
                    assert_eq!(&plaintext[..16], &[0x42; 16]);
                    assert_eq!(&plaintext[16..19], &[0, 0, 1]); // Continue, content_len = 1。
                    assert_eq!(plaintext[21], 0x16);
                    let padding = usize::from(u16::from_be_bytes([plaintext[19], plaintext[20]]));
                    assert_eq!(plaintext.len(), 22 + padding);
                }
                assert_eq!(
                    server.write(b"late-after-close").await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                assert_eq!(stats.snapshot().downlink, before);
                assert_eq!(stats.snapshot().uplink, 0);
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn coalesced_last_record_plaintext_tail_and_raw_preserve_order() {
    for chunk in [1, 2, 5, 17, 16384] {
        let (sc, cc) = configs(&rustls::version::TLS13);
        let (client, server) = tokio::io::duplex(4096);
        timeout(Duration::from_secs(5), async {
            let s = async {
                let mut s = Controlled::accept(
                    Short {
                        io: server,
                        chunk,
                        pending: false,
                    },
                    sc,
                )
                .await
                .unwrap();
                let mut b = [0; 2];
                s.read_exact(&mut b).await.unwrap();
                assert_eq!(&b, b"go");
                s.read_direct().unwrap();
                let mut b = [0; 7];
                s.read_exact(&mut b).await.unwrap();
                assert_eq!(&b, b"TAILraw");
                // 读向 Raw 不改变写向；应答仍是外层 TLS。
                s.write_all(b"tls").await.unwrap();
                s.flush().await.unwrap();
                let mut b = [0; 2];
                s.read_exact(&mut b).await.unwrap();
                assert_eq!(&b, b"ok");
                s.shutdown().await.unwrap();
            };
            let c = async {
                let mut p = Peer::connect(client, cc).await;
                p.session.writer().write_all(b"goTAIL").unwrap();
                let mut out = p.output();
                out.extend_from_slice(b"raw");
                p.io.write_all(&out).await.unwrap();
                assert_eq!(p.plain(3).await, b"tls");
                p.io.write_all(b"ok").await.unwrap();
                let mut closed = Vec::new();
                p.io.read_to_end(&mut closed).await.unwrap();
                assert!(!closed.is_empty());
            };
            tokio::join!(s, c);
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn final_tls_write_drains_before_raw_and_raw_shutdown_has_no_alert() {
    let (sc, cc) = configs(&rustls::version::TLS13);
    let (client, server) = tokio::io::duplex(128);
    timeout(Duration::from_secs(5), async {
        let s = async {
            let mut s = Controlled::accept(
                Short {
                    io: server,
                    chunk: 1,
                    pending: false,
                },
                sc,
            )
            .await
            .unwrap();
            s.write_all(b"final").await.unwrap();
            s.write_direct().unwrap();
            s.write_all(b"raw").await.unwrap();
            s.shutdown().await.unwrap();
        };
        let c = async {
            let mut p = Peer::connect(client, cc).await;
            assert_eq!(p.plain(5).await, b"final");
            let mut raw = Vec::new();
            p.io.read_to_end(&mut raw).await.unwrap();
            assert_eq!(raw, b"raw");
        };
        tokio::join!(s, c);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn key_update_before_direct_is_processed_and_after_write_direct_cannot_inject_records() {
    let (sc, cc) = configs(&rustls::version::TLS13);
    let (client, server) = tokio::io::duplex(4096);
    timeout(Duration::from_secs(5), async {
        let s = async {
            let mut s = Controlled::accept(server, sc).await.unwrap();
            let mut b = [0; 1];
            s.read_exact(&mut b).await.unwrap();
            assert_eq!(b, [1]);
            s.write_all(&[2]).await.unwrap();
            s.flush().await.unwrap();
            s.write_direct().unwrap();
            s.flush().await.unwrap();
            // 新 KeyUpdate 请求将要求在已 Raw 方向写 TLS，应失败而不是混入 raw。
            assert!(s.read_exact(&mut b).await.is_err());
            assert!(s.write_all(b"late").await.is_err());
        };
        let c = async {
            let mut p = Peer::connect(client, cc).await;
            p.session.refresh_traffic_keys().unwrap();
            p.send(&[1]).await;
            assert_eq!(p.plain(1).await, [2]);
            p.session.refresh_traffic_keys().unwrap();
            p.send(&[3]).await;
        };
        tokio::join!(s, c);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_truncated_records_and_handshake_cancellation_are_finite() {
    let (sc, _) = configs(&rustls::version::TLS13);
    for bytes in [
        &b"\x16\x03\x03\xff\xff"[..],
        b"\x16\x03",
        b"\x16\x03\x03\x00\x03x",
    ] {
        let (mut c, s) = tokio::io::duplex(64);
        c.write_all(bytes).await.unwrap();
        c.shutdown().await.unwrap();
        assert!(
            timeout(Duration::from_secs(1), Controlled::accept(s, sc.clone()))
                .await
                .unwrap()
                .is_err()
        );
    }
    let (_c, s) = tokio::io::duplex(64);
    assert!(
        timeout(Duration::from_millis(10), Controlled::accept(s, sc))
            .await
            .is_err()
    );
}
