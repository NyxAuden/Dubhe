//! 独立H1参考对端，不调用生产HTTP头编码或padding写入器生成向量。
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

mod uot;

fn h1_fixture(padding: bool, peer: std::net::SocketAddr) -> Fixture {
    let mut fixture = fixture(NaiveHttpVersion::H1, peer);
    let proxy = Arc::make_mut(&mut fixture.proxy);
    let options = Arc::make_mut(proxy.naive.as_mut().unwrap());
    options.h1_padding = padding;
    options.udp_over_tcp = padding;
    fixture
}
async fn read_head<S: AsyncRead + Unpin>(peer: &mut S) -> Vec<u8> {
    let mut head = Vec::new();
    loop {
        head.push(peer.read_u8().await.unwrap());
        assert!(head.len() <= MAX_HEAD);
        if head.ends_with(b"\r\n\r\n") {
            return head;
        }
    }
}
fn verify_head(head: &[u8], authority: &str) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    assert!(request.parse(head).unwrap().is_complete());
    assert_eq!(request.version, Some(1));
    assert_eq!(request.method, Some("CONNECT"));
    assert_eq!(request.path, Some(authority));
    for (name, expected) in [
        ("host", authority),
        ("proxy-authorization", "Basic dTpw"),
        ("x-extra", "independent-peer"),
    ] {
        let values: Vec<_> = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name))
            .collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].value, expected.as_bytes());
    }
    let padding = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("padding"))
        .unwrap();
    assert!(!padding.value.is_empty());
    assert!(!request.headers.iter().any(|h| matches!(
        h.name.to_ascii_lowercase().as_str(),
        "content-length" | "transfer-encoding" | "connection"
    )));
}

#[tokio::test]
async fn raw_h1_preserves_early_bytes_ignores_padding_and_body_framing_and_keeps_reverse_fin() {
    for padding_header in [false, true] {
        let fixture = h1_fixture(false, "127.0.0.1:1".parse().unwrap());
        let (wire, mut peer) = tokio::io::duplex(65536);
        let early = b"\0\x05\x02not-padded\0HTTP/1.1\r\n\r\n";
        let peer_task = tokio::spawn(async move {
            verify_head(&read_head(&mut peer).await, "127.0.0.1:443");
            let mut response = b"HTTP/1.1 200 Connection Established\r\nContent-Length: 900\r\nTransfer-Encoding: chunked\r\n".to_vec();
            if padding_header {
                response.extend_from_slice(b"Padding: same-header-both-profiles\r\n");
            }
            response.extend_from_slice(b"\r\n");
            response.extend_from_slice(early);
            peer.write_all(&response).await.unwrap();
            let mut uplink = Vec::new();
            peer.read_to_end(&mut uplink).await.unwrap();
            assert_eq!(uplink, b"\0\x03\x01raw-uplink-not-a-frame");
            peer.write_all(b"reverse-after-fin").await.unwrap();
            peer.shutdown().await.unwrap();
        });
        let local = "127.0.0.1:12345".parse().unwrap();
        let mut stream = connect_h1::connect(
            Upstream::new_send(wire, Some(local)),
            &fixture.proxy,
            &target(),
        )
        .await
        .unwrap();
        assert_eq!(stream.local_addr().unwrap(), local);
        stream
            .write_all(b"\0\x03\x01raw-uplink-not-a-frame")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut downlink = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut downlink))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(downlink, [early.as_slice(), b"reverse-after-fin"].concat());
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        timeout(WAIT, peer_task).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn explicit_padded_h1_first_eight_and_ninth_both_directions_with_split_headers() {
    let fixture = h1_fixture(true, "127.0.0.1:1".parse().unwrap());
    let (wire, mut peer) = tokio::io::duplex(256 * 1024);
    let peer_task = tokio::spawn(async move {
        verify_head(&read_head(&mut peer).await, "[::1]:443");
        for byte in b"HTTP/1.1 200 OK\r\nPadding: yes\r\n\r\n" {
            peer.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut wire = Vec::new();
        peer.read_to_end(&mut wire).await.unwrap();
        let mut offset = 0;
        for index in 0..8u8 {
            let size = u16::from_be_bytes([wire[offset], wire[offset + 1]]) as usize;
            let padding = wire[offset + 2] as usize;
            assert_eq!(&wire[offset + 3..offset + 3 + size], vec![index; 4096]);
            assert!(
                wire[offset + 3 + size..offset + 3 + size + padding]
                    .iter()
                    .all(|b| *b == 0)
            );
            offset += 3 + size + padding;
        }
        assert_eq!(&wire[offset..], b"plain-ninth");
        for index in 0..8u8 {
            for byte in frame(&[index]) {
                peer.write_all(&[byte]).await.unwrap();
            }
        }
        peer.write_all(b"plain-ninth").await.unwrap();
        peer.shutdown().await.unwrap();
    });
    let destination = "[::1]:443".parse::<std::net::SocketAddr>().unwrap().into();
    let mut stream =
        connect_h1::connect(Upstream::new_send(wire, None), &fixture.proxy, &destination)
            .await
            .unwrap();
    for index in 0..8u8 {
        stream.write_all(&vec![index; 4096]).await.unwrap();
        stream.flush().await.unwrap();
    }
    stream.write_all(b"plain-ninth").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut downlink = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut downlink))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        downlink,
        [vec![0, 1, 2, 3, 4, 5, 6, 7], b"plain-ninth".to_vec()].concat()
    );
    timeout(WAIT, peer_task).await.unwrap().unwrap();
}

async fn response_result(response: Vec<u8>, padding: bool) -> io::Result<Upstream> {
    let fixture = h1_fixture(padding, "127.0.0.1:1".parse().unwrap());
    let (wire, mut peer) = tokio::io::duplex(65536);
    let peer_task = tokio::spawn(async move {
        read_head(&mut peer).await;
        let _ = peer.write_all(&response).await;
        let _ = peer.shutdown().await;
        let mut bytes = Vec::new();
        let _ = peer.read_to_end(&mut bytes).await;
        assert!(bytes.is_empty(), "失败不能自动重放CONNECT或发送业务");
    });
    let result = timeout(
        WAIT,
        connect_h1::connect(Upstream::new_send(wire, None), &fixture.proxy, &target()),
    )
    .await
    .unwrap();
    if result.is_err() {
        timeout(WAIT, peer_task).await.unwrap().unwrap();
    } else {
        // 成功流仍属调用者；对端已half-close且没有任何派生任务。
        peer_task.abort();
        let _ = peer_task.await;
    }
    result
}

#[tokio::test]
async fn rejects_non_200_invalid_version_duplicate_padding_truncation_and_missing_capability() {
    for response in [
        b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
        b"HTTP/1.1 201 Created\r\n\r\n",
        b"HTTP/1.1 407 private-untrusted-error\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        b"HTTP/1.0 200 OK\r\n\r\n",
        b"HTTP/2 200 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nPadding: a\r\npAdDiNg: b\r\n\r\n",
        b"HTTP/1.1 200 OK\nX: y\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: a\r\n folded\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: \0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nPadding: yes\r\n",
        b"HTTP/1.1 200",
        b"",
    ] {
        let error = response_result(response.to_vec(), false).await.unwrap_err();
        assert!(!error.to_string().contains("private-untrusted-error"));
    }
    for padding in [b"".as_slice(), b"Padding: \r\n"] {
        let response = [b"HTTP/1.1 200 OK\r\n".as_slice(), padding, b"\r\n"].concat();
        assert!(response_result(response, true).await.is_err());
    }
}

#[tokio::test]
async fn head_bytes_header_count_and_informational_responses_have_exact_bounds() {
    let base = b"HTTP/1.1 200 OK\r\nX: \r\n\r\n";
    let mut exact = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    exact.extend(vec![b'x'; MAX_HEAD - base.len()]);
    exact.extend_from_slice(b"\r\n\r\n");
    assert_eq!(exact.len(), MAX_HEAD);
    assert!(response_result(exact.clone(), false).await.is_ok());
    exact.insert(exact.len() - 4, b'x');
    assert!(response_result(exact, false).await.is_err());
    for count in [64, 65] {
        let response = [
            b"HTTP/1.1 200 OK\r\n".to_vec(),
            b"X: y\r\n".repeat(count),
            b"\r\n".to_vec(),
        ]
        .concat();
        assert_eq!(response_result(response, false).await.is_ok(), count == 64);
    }
    let final_response = b"HTTP/1.1 200 OK\r\n\r\n";
    let info = b"HTTP/1.1 103 Early Hints\r\nLink: </not-followed>\r\n\r\n";
    for count in [1, 4, 5] {
        let response = [info.repeat(count), final_response.to_vec()].concat();
        assert_eq!(response_result(response, false).await.is_ok(), count <= 4);
    }
    for status in [100, 102] {
        let response = [
            format!("HTTP/1.1 {status} Info\r\n\r\n").into_bytes(),
            final_response.to_vec(),
        ]
        .concat();
        assert!(response_result(response, false).await.is_ok());
    }
    let mut large_info = b"HTTP/1.1 103 Info\r\nX: ".to_vec();
    large_info.extend(vec![b'a'; MAX_HEAD - large_info.len() - 4]);
    large_info.extend_from_slice(b"\r\n\r\n");
    large_info.extend_from_slice(final_response);
    assert!(response_result(large_info, false).await.is_err());
}

struct Gate {
    inner: tokio::io::DuplexStream,
    budget: Arc<AtomicUsize>,
    flushed: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        assert!(
            self.flushed.load(Ordering::SeqCst),
            "必须先实际flush请求再读取响应"
        );
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}
impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let remaining = self.budget.load(Ordering::SeqCst);
        if remaining == 0 {
            return Poll::Pending;
        }
        let count = bytes.len().min(remaining).min(3);
        let result = Pin::new(&mut self.inner).poll_write(cx, &bytes[..count]);
        if let Poll::Ready(Ok(written)) = &result {
            self.budget.fetch_sub(*written, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.flushed.store(true, Ordering::SeqCst);
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
fn gate(
    wire: tokio::io::DuplexStream,
    budget: usize,
) -> (Upstream, Arc<AtomicBool>, Arc<AtomicBool>) {
    let flushed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    (
        Upstream::new_send(
            Gate {
                inner: wire,
                budget: Arc::new(AtomicUsize::new(budget)),
                flushed: flushed.clone(),
                dropped: dropped.clone(),
            },
            None,
        ),
        flushed,
        dropped,
    )
}

#[tokio::test]
async fn short_request_writes_flush_and_cancelling_partial_request_or_response_destroy_wire() {
    for partial_request in [false, true] {
        let fixture = h1_fixture(false, "127.0.0.1:1".parse().unwrap());
        let (wire, mut peer) = tokio::io::duplex(65536);
        let (wire, flushed, dropped) = gate(wire, if partial_request { 3 } else { usize::MAX });
        let destination = target();
        let mut operation = Box::pin(connect_h1::connect(wire, &fixture.proxy, &destination));
        if partial_request {
            let mut prefix = [0; 3];
            tokio::select! { result = &mut operation => panic!("不应写完: {result:?}"), _ = peer.read_exact(&mut prefix) => {} }
            assert_eq!(&prefix, b"CON");
            assert!(!flushed.load(Ordering::SeqCst));
        } else {
            tokio::select! { result = &mut operation => panic!("慢头不应成功: {result:?}"), head = read_head(&mut peer) => verify_head(&head, "127.0.0.1:443") }
            // 真正推进到flush和半响应读取后再取消。
            peer.write_all(b"HTTP/1.1 200 OK\r\nPadding: par")
                .await
                .unwrap();
            assert!(
                timeout(Duration::from_millis(10), &mut operation)
                    .await
                    .is_err()
            );
            assert!(flushed.load(Ordering::SeqCst));
        }
        drop(operation);
        assert!(dropped.load(Ordering::SeqCst));
        let mut rest = Vec::new();
        timeout(WAIT, peer.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(rest.is_empty());
    }
}

#[tokio::test]
async fn stopped_or_timed_out_tcp_handshake_drops_stream_without_children() {
    for stop_now in [false, true] {
        let fixture = h1_fixture(false, "127.0.0.1:1".parse().unwrap());
        let (wire, mut peer) = tokio::io::duplex(65536);
        let (wire, _, dropped) = gate(wire, usize::MAX);
        let ctx = context();
        let destination = target();
        let mut operation = Box::pin(connect_tcp(
            wire,
            &fixture.proxy,
            &destination,
            ctx.children.clone(),
            ctx.outbound_stop.clone(),
            Duration::from_millis(30),
        ));
        tokio::select! { result = &mut operation => panic!("应等待响应: {result:?}"), _ = read_head(&mut peer) => {} }
        if stop_now {
            ctx.outbound_stop.cancel();
        }
        let error = timeout(WAIT, operation).await.unwrap().unwrap_err();
        assert_eq!(
            error.kind(),
            if stop_now {
                io::ErrorKind::ConnectionAborted
            } else {
                io::ErrorKind::TimedOut
            }
        );
        assert!(dropped.load(Ordering::SeqCst));
        assert!(ctx.children.is_empty());
        finish(&ctx).await;
    }
}

#[tokio::test]
async fn cancelled_real_h1_tls_or_response_header_has_no_socket_or_child_owner_left() {
    for before_tls in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = h1_fixture(false, listener.local_addr().unwrap());
        let address = listener.local_addr().unwrap();
        let tls = fixture.tls.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut wire, _) = listener.accept().await.unwrap();
            if before_tls {
                let mut prefix = [0; 5];
                wire.read_exact(&mut prefix).await.unwrap();
                assert_eq!(prefix[0], 0x16);
                ready_tx.send(()).unwrap();
                let mut rest = Vec::new();
                timeout(WAIT, wire.read_to_end(&mut rest))
                    .await
                    .unwrap()
                    .unwrap();
            } else {
                let mut wire = tokio_rustls::TlsAcceptor::from(tls)
                    .accept(wire)
                    .await
                    .unwrap();
                verify_head(&read_head(&mut wire).await, "127.0.0.1:443");
                wire.write_all(b"HTTP/1.1 200 OK\r\nPadding: partial")
                    .await
                    .unwrap();
                ready_tx.send(()).unwrap();
                let mut rest = Vec::new();
                let _ = timeout(WAIT, wire.read_to_end(&mut rest)).await.unwrap();
                assert!(rest.is_empty());
            }
        });
        let ctx = context();
        let destination = target();
        let mut operation = connect(&ctx, &fixture.proxy, &destination);
        tokio::select! { result = &mut operation => panic!("不完整握手不应完成: {result:?}"), result = ready_rx => result.unwrap() }
        drop(operation);
        timeout(WAIT, peer).await.unwrap().unwrap();
        assert!(ctx.children.is_empty());
        tokio::net::TcpListener::bind(address).await.unwrap();
        finish(&ctx).await;
    }
}

#[tokio::test]
async fn h1_tls_accepts_explicit_or_absent_alpn_and_rejects_mismatch_before_connect() {
    for negotiated in [Some(b"http/1.1".as_slice()), None, Some(b"h2".as_slice())] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = h1_fixture(false, listener.local_addr().unwrap());
        Arc::make_mut(&mut fixture.tls).alpn_protocols =
            negotiated.into_iter().map(Vec::from).collect();
        let tls = fixture.tls.clone();
        let peer = tokio::spawn(async move {
            let (wire, _) = listener.accept().await.unwrap();
            let accepted = tokio_rustls::TlsAcceptor::from(tls).accept(wire).await;
            if negotiated == Some(b"h2".as_slice()) {
                assert!(accepted.is_err());
                return;
            }
            let mut wire = accepted.unwrap();
            assert_eq!(wire.get_ref().1.alpn_protocol(), negotiated);
            verify_head(&read_head(&mut wire).await, "127.0.0.1:443");
            wire.write_all(b"HTTP/1.1 200 OK\r\nPadding: yes\r\n\r\nraw")
                .await
                .unwrap();
            wire.shutdown().await.unwrap();
            let mut uplink = Vec::new();
            let _ = wire.read_to_end(&mut uplink).await;
        });
        let ctx = context();
        let result = timeout(WAIT, connect(&ctx, &fixture.proxy, &target()))
            .await
            .unwrap();
        if negotiated == Some(b"h2".as_slice()) {
            assert!(result.is_err());
        } else {
            let mut stream = result.unwrap();
            let mut reply = [0; 3];
            timeout(WAIT, stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply, b"raw");
            stream.shutdown().await.unwrap();
            drop(stream);
        }
        timeout(WAIT, peer).await.unwrap().unwrap();
        assert!(ctx.children.is_empty());
        finish(&ctx).await;
    }
}
