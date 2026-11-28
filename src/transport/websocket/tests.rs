//! 独立原始帧及受控短写夹具，不用另一份生产适配器自证。
use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![if fin { 0x80 | opcode } else { opcode }];
    match payload.len() {
        n @ 0..=125 => bytes.push(0x80 | n as u8),
        n @ 126..=65535 => {
            bytes.push(0xfe);
            bytes.extend((n as u16).to_be_bytes());
        }
        n => {
            bytes.push(0xff);
            bytes.extend((n as u64).to_be_bytes());
        }
    }
    let mask = [1, 7, 17, 31];
    bytes.extend(mask);
    bytes.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    bytes
}
fn decode_server(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut offset = 0;
    let mut result = Vec::new();
    while offset < bytes.len() {
        let first = bytes[offset];
        let second = bytes[offset + 1];
        assert_eq!(first & 0x80, 0x80);
        assert_eq!(second & 0x80, 0);
        let (header, length) = match second {
            126 => (
                4,
                u16::from_be_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()) as usize,
            ),
            127 => (
                10,
                u64::from_be_bytes(bytes[offset + 2..offset + 10].try_into().unwrap()) as usize,
            ),
            n => (2, n as usize),
        };
        result.push((
            first & 15,
            bytes[offset + header..offset + header + length].to_vec(),
        ));
        offset += header + length;
    }
    result
}
struct Probe {
    input: Vec<u8>,
    offset: usize,
    output: Arc<Mutex<Vec<u8>>>,
    limit: usize,
    pending: bool,
    block: Arc<AtomicBool>,
    eof: bool,
    reads: Arc<AtomicUsize>,
}
impl Probe {
    fn new(input: Vec<u8>, limit: usize) -> Self {
        Self {
            input,
            offset: 0,
            output: Arc::default(),
            limit,
            pending: false,
            block: Arc::new(AtomicBool::new(false)),
            eof: false,
            reads: Arc::default(),
        }
    }
}
impl AsyncRead for Probe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.offset == self.input.len() && !self.eof {
            return Poll::Pending;
        }
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = out
            .remaining()
            .min(self.limit)
            .min(self.input.len() - self.offset);
        out.put_slice(&self.input[self.offset..self.offset + n]);
        self.offset += n;
        self.pending = true;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Probe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.block.load(Ordering::Relaxed) {
            return Poll::Pending;
        }
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = bytes.len().min(self.limit);
        self.output.lock().unwrap().extend(&bytes[..n]);
        self.pending = true;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.block.load(Ordering::Relaxed) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn early_data_raw_prefix_fragmentation_empty_binary_and_controls_are_ordered_once() {
    let mut raw = frame(true, 2, b"");
    raw.extend(frame(false, 2, b"first"));
    raw.extend(frame(true, 9, b"ping"));
    raw.extend(frame(true, 0, b"second"));
    raw.extend(frame(true, 2, b"third"));
    raw.extend(frame(true, 8, &1000u16.to_be_bytes()));
    for split in 0..=raw.len() {
        let io = Probe::new(raw[split..].to_vec(), 7);
        let written = io.output.clone();
        let mut socket = WebSocket::new(io, raw[..split].to_vec(), b"early".to_vec()).await;
        let mut result = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut result))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, b"earlyfirstsecondthird");
        socket.shutdown().await.unwrap();
        socket.shutdown().await.unwrap();
        assert_eq!(
            socket.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let messages = decode_server(&written.lock().unwrap());
        assert_eq!(
            messages,
            vec![(10, b"ping".to_vec()), (8, 1000u16.to_be_bytes().to_vec())]
        );
    }
}

#[tokio::test]
async fn outbound_lengths_flush_and_replaced_pending_slice_match_the_wire() {
    let io = Probe::new(vec![], 8192);
    let written = io.output.clone();
    let block = io.block.clone();
    let mut socket = WebSocket::new(io, vec![], vec![]).await;
    socket.write_all(b"ok").await.unwrap();
    socket.flush().await.unwrap();
    assert_eq!(written.lock().unwrap().as_slice(), b"\x82\x02ok");
    let mut expected = written.lock().unwrap().clone();
    for (n, header) in [
        (125, &[125][..]),
        (126, &[126, 0, 126]),
        (65535, &[126, 255, 255]),
        (65536, &[127, 0, 0, 0, 0, 0, 1, 0, 0]),
    ] {
        let payload = vec![n as u8; n];
        socket.write_all(&payload).await.unwrap();
        expected.push(0x82);
        expected.extend_from_slice(header);
        expected.extend_from_slice(&payload);
    }
    socket.flush().await.unwrap();
    block.store(true, Ordering::Relaxed);
    let data = vec![0x76; 65537];
    assert_eq!(socket.write(&data).await.unwrap(), 65536);
    assert!(futures_util::poll!(std::pin::pin!(socket.write(b"discard"))).is_pending());
    block.store(false, Ordering::Relaxed);
    // 可复现的伪随机短写；每次 Pending 后都可改用新的业务切片。
    let mut seed = 7u32;
    std::future::poll_fn(|cx| {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        socket.socket.get_mut().get_mut().limit = 1 + (seed >> 20) as usize;
        Pin::new(&mut socket).poll_write(cx, &data[65536..])
    })
    .await
    .map(|n| assert_eq!(n, 1))
    .unwrap();
    socket.flush().await.unwrap();
    expected.extend_from_slice(&[0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]);
    expected.extend_from_slice(&data[..65536]);
    expected.extend_from_slice(&[0x82, 1, 0x76]);
    assert_eq!(*written.lock().unwrap(), expected);
}

#[tokio::test(start_paused = true)]
async fn short_writes_and_pending_accept_each_business_byte_once_with_fixed_segments() {
    for limit in [1, 7, 17] {
        let io = Probe::new(vec![], limit);
        let written = io.output.clone();
        let mut socket = WebSocket::new(io, vec![], vec![]).await;
        let data: Vec<u8> = (0..80_019).map(|n| (n % 251) as u8).collect();
        // Probe 每次短写都主动唤醒。虚拟期限抓漏唤醒；poll 上限抓只唤醒不推进。
        let mut write = std::pin::pin!(async {
            socket.write_all(&data).await.unwrap();
            socket.flush().await.unwrap();
        });
        let mut polls = 0;
        tokio::time::timeout(
            Duration::from_secs(15),
            std::future::poll_fn(|cx| {
                polls += 1;
                assert!(polls <= 4 * data.len(), "短写未在有界 poll 内完成");
                std::future::Future::poll(write.as_mut(), cx)
            }),
        )
        .await
        .unwrap();
        let messages = decode_server(&written.lock().unwrap());
        assert!(
            messages
                .iter()
                .all(|(opcode, b)| *opcode == 2 && b.len() <= MAX_WRITE)
        );
        assert_eq!(
            messages
                .into_iter()
                .flat_map(|(_, b)| b)
                .collect::<Vec<_>>(),
            data
        );
    }
}

#[tokio::test]
async fn write_backpressure_does_not_prevent_binary_input_or_ping_processing() {
    let mut input = frame(true, 9, b"probe");
    input.extend(frame(true, 2, b"upstream"));
    let io = Probe::new(input, 17);
    let block = io.block.clone();
    let written = io.output.clone();
    block.store(true, Ordering::Relaxed);
    let mut socket = WebSocket::new(io, vec![], vec![]).await;
    let accepted = socket.write(&[0x79; MAX_WRITE]).await.unwrap();
    assert_eq!(accepted, MAX_WRITE);
    let mut data = [0; 8];
    tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data, b"upstream");
    block.store(false, Ordering::Relaxed);
    socket.flush().await.unwrap();
    let messages = decode_server(&written.lock().unwrap());
    assert_eq!(
        messages,
        vec![(2, vec![0x79; MAX_WRITE]), (10, b"probe".to_vec())]
    );
}

#[tokio::test]
async fn real_tcp_downstream_backpressure_still_reads_upstream_and_flushes_once_after_resume() {
    use tokio::net::{TcpListener, TcpStream};
    tokio::time::timeout(Duration::from_secs(15), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        server.set_nodelay(true).unwrap();
        client.set_nodelay(true).unwrap();
        socket2::SockRef::from(&server)
            .set_send_buffer_size(1024)
            .unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut socket = WebSocket::new(server, vec![], vec![]).await;
            let mut accepted = 0usize;
            std::future::poll_fn(|cx| {
                loop {
                    match Pin::new(&mut socket).poll_write(cx, &[0x6d; MAX_WRITE]) {
                        Poll::Ready(Ok(n)) => {
                            accepted += n;
                            assert!(
                                accepted <= 16 * MAX_MESSAGE,
                                "受控客户端未读时应在有限量后形成真实背压"
                            );
                        }
                        Poll::Ready(Err(error)) => panic!("下行写失败: {error}"),
                        Poll::Pending => return Poll::Ready(()),
                    }
                }
            })
            .await;
            let mut input = [0; 8];
            socket.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"upstream");
            tx.send(accepted).unwrap();
            socket.flush().await.unwrap();
        });
        let mut input = frame(true, 9, b"ping");
        input.extend(frame(true, 2, b"upstream"));
        client.write_all(&input).await.unwrap();
        let accepted = rx.await.expect("下行背压不得阻止上行处理");
        let mut actual = 0;
        let mut pong = false;
        while actual < accepted || !pong {
            let first = client.read_u8().await.unwrap();
            let second = client.read_u8().await.unwrap();
            assert_eq!(first & 0x80, 0x80);
            assert_eq!(second & 0x80, 0);
            let length = match second {
                126 => client.read_u16().await.unwrap() as usize,
                127 => client.read_u64().await.unwrap() as usize,
                n => n as usize,
            };
            assert!(length <= MAX_WRITE);
            let mut payload = vec![0; length];
            client.read_exact(&mut payload).await.unwrap();
            match first & 15 {
                2 => {
                    assert!(payload.iter().all(|b| *b == 0x6d));
                    actual += length;
                }
                10 => {
                    assert!(!pong);
                    assert_eq!(payload, b"ping");
                    pong = true;
                }
                opcode => panic!("意外服务端帧: {opcode}"),
            }
        }
        assert_eq!(actual, accepted);
        task.await.unwrap();
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_frames_and_truncation_fail_permanently_without_reinterpreting_tail() {
    let mut cases = vec![
        frame(true, 1, b"text"),
        frame(true, 0, b"orphan"),
        frame(true, 3, b"reserved"),
        vec![0x82, 0],
        vec![0x82, 0xfe, 0, 1],
        vec![0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0],
        frame(false, 9, b"ping"),
    ];
    let mut rsv = frame(true, 2, b"reserved");
    rsv[0] |= 0x40;
    cases.push(rsv);
    let complete = frame(true, 2, b"payload");
    for end in 0..complete.len() {
        cases.push(complete[..end].to_vec());
    }
    for raw in cases {
        let mut io = Probe::new(raw, 17);
        io.eof = true;
        let mut socket = WebSocket::new(io, vec![], vec![]).await;
        let mut data = [0; 64];
        let error = socket.read(&mut data).await.unwrap_err();
        assert_eq!(
            socket.read(&mut data).await.unwrap_err().kind(),
            error.kind()
        );
        assert!(socket.write(b"late").await.is_err());
    }
}

#[tokio::test]
async fn unfinished_fragment_followed_by_close_never_delivers_a_partial_business_message() {
    let mut raw = frame(false, 2, b"unfinished");
    raw.extend(frame(true, 8, &1000u16.to_be_bytes()));
    let io = Probe::new(raw, 17);
    let mut socket = WebSocket::new(io, vec![], vec![]).await;
    let mut data = Vec::new();
    socket.read_to_end(&mut data).await.unwrap();
    assert!(data.is_empty(), "Close前未完成的分片不能伪造完整业务数据");
}

#[tokio::test]
async fn fragmented_message_limit_is_cumulative() {
    let mut raw = frame(false, 2, &vec![0; MAX_MESSAGE]);
    raw.extend(frame(true, 0, b"x"));
    let mut io = Probe::new(raw, 16_384);
    io.eof = true;
    let mut socket = WebSocket::new(io, vec![], vec![]).await;
    assert_eq!(
        socket.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn shutdown_latches_before_pending_and_times_out_without_a_peer_close() {
    let io = Probe::new(vec![], 17);
    let block = io.block.clone();
    let written = io.output.clone();
    block.store(true, Ordering::Relaxed);
    let mut socket = WebSocket::new(io, vec![], vec![]).await;
    socket.write_all(b"accepted").await.unwrap();
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut socket).poll_shutdown(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        socket.write(b"late").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    block.store(false, Ordering::Relaxed);
    tokio::time::pause();
    let error = socket.shutdown().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let messages = decode_server(&written.lock().unwrap());
    assert_eq!(messages[0], (2, b"accepted".to_vec()));
    assert_eq!(messages[1].0, 8);
}

#[tokio::test]
async fn peer_close_normal_no_status_and_abnormal_codes_are_distinct() {
    for payload in [
        vec![],
        1000u16.to_be_bytes().to_vec(),
        1001u16.to_be_bytes().to_vec(),
        vec![1],
    ] {
        let io = Probe::new(frame(true, 8, &payload), 17);
        let mut socket = WebSocket::new(io, vec![], vec![]).await;
        let result = socket.read(&mut [0; 1]).await;
        if payload.is_empty() || payload == 1000u16.to_be_bytes() {
            assert_eq!(result.unwrap(), 0);
            socket.shutdown().await.unwrap();
        } else {
            assert!(result.is_err());
        }
    }
}

#[tokio::test]
async fn local_close_waits_for_peer_and_preserves_complete_input_until_reader_consumes_it() {
    let mut raw = frame(true, 2, b"in-flight");
    raw.extend(frame(true, 8, &1000u16.to_be_bytes()));
    let io = Probe::new(raw, 17);
    let written = io.output.clone();
    let mut socket = WebSocket::new(io, vec![], vec![]).await;
    std::future::poll_fn(|cx| {
        let _ = Pin::new(&mut socket).poll_shutdown(cx);
        Poll::Ready(())
    })
    .await;
    let mut data = [0; 9];
    socket.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"in-flight");
    socket.shutdown().await.unwrap();
    let messages = decode_server(&written.lock().unwrap());
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, 8);
}

#[tokio::test]
async fn real_tls_truncation_and_partial_frames_are_errors_not_clean_close() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der())
                .into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    for raw in [
        vec![],
        frame(true, 2, b"complete"),
        frame(true, 2, b"partial")[..8].to_vec(),
    ] {
        let (a, b) = tokio::io::duplex(65536);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server.clone()));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client.clone()));
        let (server, client) = tokio::join!(
            acceptor.accept(a),
            connector.connect("localhost".try_into().unwrap(), b)
        );
        let mut client = client.unwrap();
        client.write_all(&raw).await.unwrap();
        client.flush().await.unwrap();
        // 直接丢弃TLS，故意不发close_notify，也没有WS Close。
        drop(client);
        let mut socket = WebSocket::new(server.unwrap(), vec![], vec![]).await;
        let mut received = Vec::new();
        let error = socket.read_to_end(&mut received).await.unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionAborted
        ));
        if raw == frame(true, 2, b"complete") {
            assert_eq!(received, b"complete");
        } else {
            assert!(received.is_empty());
        }
    }
}

#[tokio::test]
async fn shutdown_pending_late_write_is_not_counted_and_completed_close_stays_complete() {
    let io = Probe::new(frame(true, 8, &1000u16.to_be_bytes()), 17);
    let block = io.block.clone();
    let stats = Arc::new(crate::telemetry::Stats::default());
    let mut counted = crate::telemetry::Counted {
        inner: WebSocket::new(io, vec![], vec![]).await,
        stats: stats.clone(),
        uplink: false,
    };
    block.store(true, Ordering::Relaxed);
    counted.write_all(b"one").await.unwrap();
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut counted).poll_shutdown(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        counted.write(b"late").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(stats.snapshot().downlink, 3);
    block.store(false, Ordering::Relaxed);
    counted.shutdown().await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    counted.shutdown().await.unwrap();
    assert_eq!(counted.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(stats.snapshot().downlink, 3);
}

#[tokio::test]
async fn empty_continuation_train_yields_after_bounded_raw_headers() {
    let mut raw = frame(false, 2, b"");
    for _ in 0..1000 {
        raw.extend(frame(false, 0, b""));
    }
    raw.extend(frame(true, 0, b"end"));
    let io = Probe::new(vec![], 17);
    let mut socket = WebSocket::new(io, raw, vec![]).await;
    std::future::poll_fn(|cx| {
        let mut bytes = [0; 3];
        let mut out = ReadBuf::new(&mut bytes);
        assert!(Pin::new(&mut socket).poll_read(cx, &mut out).is_pending());
        // 有限prefix尚未排完，底层socket不应被访问；精确32头由Guard单测观测。
        assert_eq!(
            socket
                .socket
                .get_mut()
                .get_mut()
                .reads
                .load(Ordering::Relaxed),
            0
        );
        Poll::Ready(())
    })
    .await;
    let mut data = [0; 3];
    socket.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"end");
}
