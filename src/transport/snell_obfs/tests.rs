use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};
const WAIT: Duration = Duration::from_secs(3);

#[test]
fn tls_first_messages_match_fixed_offsets_and_independent_prefixes() {
    let payload = vec![0x5a; 20_000];
    let host = "obfs.example";
    let wire = client_hello(host, &payload, 0x01020304, [0x11; 28], [0x22; 32]).unwrap();
    assert_eq!(&wire[..3], &[0x16, 3, 1]);
    assert_eq!(
        usize::from(u16::from_be_bytes([wire[3], wire[4]])),
        0xd4 + host.len() + 1024
    );
    assert_eq!(&wire[5..11], &[1, 0, 0x04, (0xd0 + host.len()) as u8, 3, 3]);
    assert_eq!(&wire[11..15], &[1, 2, 3, 4]);
    assert_eq!(&wire[15..43], &[0x11; 28]);
    assert_eq!(wire[43], 32);
    assert_eq!(&wire[44..76], &[0x22; 32]);
    assert_eq!(&wire[76..78], &[0, 0x38]);
    assert_eq!(
        &wire[136..142],
        &[0x04, (0x4f + host.len()) as u8, 0, 0x23, 4, 0]
    );
    assert_eq!(&wire[0x8e..0x8e + 1024], &payload[..1024]);
    let name = 0x8e + 1024;
    assert_eq!(&wire[name..name + 2], &[0, 0]);
    assert_eq!(&wire[name + 9..name + 9 + host.len()], host.as_bytes());
    let end = 0xd9 + host.len() + 1024;
    assert_eq!(&wire[end..end + 5], &[0x17, 3, 3, 0x40, 0]);
    assert_eq!(&wire[end + 5..end + 5 + 16384], &payload[1024..17408]);
    let tail = end + 5 + 16384;
    assert_eq!(
        usize::from(u16::from_be_bytes([wire[tail + 3], wire[tail + 4]])),
        payload.len() - 17408
    );
    assert_eq!(&wire[tail + 5..], &payload[17408..]);

    let reply = server_hello(&payload, 0x01020304, [0x33; 28], [0x44; 32]);
    assert_eq!(&reply[..11], &[0x16, 3, 1, 0, 91, 2, 0, 0, 0x57, 3, 3]);
    assert_eq!(&reply[11..15], &[1, 2, 3, 4]);
    assert_eq!(&reply[44..76], &[0x44; 32]);
    assert_eq!(&reply[96..107], &[0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0x40, 0]);
    assert_eq!(&reply[0x6b..0x6b + 16384], &payload[..16384]);
    assert_eq!(&reply[0x6b + 16384..0x6b + 16384 + 3], &[0x17, 3, 3]);
}

#[test]
fn http_first_head_is_once_per_direction_and_payload_is_not_websocket() {
    let wire = http_first(true, "front.example", "/path", b"first").unwrap();
    let end = wire
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let head = std::str::from_utf8(&wire[..end]).unwrap();
    assert!(head.starts_with("GET /path HTTP/1.1\r\nHost: front.example\r\n"));
    assert!(head.contains("\r\nContent-Length: 5\r\n"));
    assert!(head.contains("Upgrade: websocket\r\nConnection: Upgrade\r\n"));
    assert_eq!(&wire[end..], b"first");
    let second = http_first(true, "other.example", "/other", b"second").unwrap();
    let key = |wire: &[u8]| -> String {
        std::str::from_utf8(wire)
            .unwrap()
            .lines()
            .find(|line| line.starts_with("Sec-WebSocket-Key:"))
            .unwrap()
            .to_owned()
    };
    assert_eq!(key(&wire), key(&second), "上游指纹按进程固定，不逐流改变");
    let response = http_first(false, "", "", b"response").unwrap();
    let end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(String::from_utf8_lossy(&response[..end]).contains("\r\nDate: "));
    assert_eq!(&response[end..], b"response");
}

#[tokio::test]
async fn both_roles_roundtrip_first_larger_than_ticket_and_halfclose() {
    for mode in [Mode::Http, Mode::Tls] {
        let (client, server) = tokio::io::duplex(4096);
        let mut client = Stream::client(client, mode, None, None);
        let mut server = Stream::server(server, mode);
        let payload = vec![0x4c; 48 * 1024];
        let expected = payload.clone();
        let peer = tokio::spawn(async move {
            let mut bytes = Vec::new();
            server.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, expected);
            server.write_all(&bytes).await.unwrap();
            server.shutdown().await.unwrap();
        });
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(WAIT, client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, payload);
        peer.await.unwrap();
    }
}

struct Gate {
    inner: tokio::io::DuplexStream,
    blocked: Arc<AtomicBool>,
}
impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}
impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.blocked.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        let count = data.len().min(2);
        Pin::new(&mut self.inner).poll_write(cx, &data[..count])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn short_write_cancelled_next_buffer_and_flush_do_not_duplicate_first_message() {
    for mode in [Mode::Http, Mode::Tls] {
        for client_role in [true, false] {
            let (wire, peer) = tokio::io::duplex(16 * 1024);
            let blocked = Arc::new(AtomicBool::new(true));
            let gate = Gate {
                inner: wire,
                blocked: blocked.clone(),
            };
            let mut stream = if client_role {
                Stream::client(gate, mode, None, None)
            } else {
                Stream::server(gate, mode)
            };
            assert_eq!(stream.write(b"first").await.unwrap(), 5);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut cx, b"cancelled")
                    .is_pending()
            );
            blocked.store(false, Ordering::SeqCst);
            stream.flush().await.unwrap();
            stream.write_all(b"second").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut peer = if client_role {
                Stream::server(peer, mode)
            } else {
                Stream::client(peer, mode, None, None)
            };
            let mut bytes = Vec::new();
            timeout(WAIT, peer.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bytes, b"firstsecond");
            assert!(stream.write(b"late").await.is_err());
        }
    }
}

#[tokio::test]
async fn cancelled_split_first_header_payload_and_tail_keep_read_cursor() {
    for mode in [Mode::Http, Mode::Tls] {
        for client_role in [true, false] {
            let wire = if mode == Mode::Http {
                http_first(!client_role, "front.example", "/", b"first").unwrap()
            } else if client_role {
                server_hello(b"first", 0, [1; 28], [2; 32])
            } else {
                client_hello("front.example", b"first", 0, [1; 28], [2; 32]).unwrap()
            };
            let (mut send, recv) = tokio::io::duplex(8192);
            let mut stream = if client_role {
                Stream::client(recv, mode, None, None)
            } else {
                Stream::server(recv, mode)
            };
            let mut bytes = [0; 5];
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut empty = ReadBuf::new(&mut []);
            assert!(
                Pin::new(&mut stream)
                    .poll_read(&mut cx, &mut empty)
                    .is_ready()
            );
            assert!(stream.input.is_empty());
            send.write_all(&wire[..3]).await.unwrap();
            assert!(
                timeout(Duration::from_millis(10), stream.read(&mut bytes))
                    .await
                    .is_err()
            );
            send.write_all(&wire[3..]).await.unwrap();
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"first");
            let next = if mode == Mode::Http {
                b"second".to_vec()
            } else {
                records(b"second")
            };
            send.write_all(&next).await.unwrap();
            send.shutdown().await.unwrap();
            let mut rest = Vec::new();
            timeout(WAIT, stream.read_to_end(&mut rest))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(rest, b"second");
        }
    }
}

/// 精确停在指定wire偏移：验证已经写出部分首消息后取消，下一buffer不被虚报接受。
struct CutWriter {
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    remaining: Arc<std::sync::atomic::AtomicUsize>,
}
impl AsyncWrite for CutWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let count = self
            .remaining
            .load(Ordering::SeqCst)
            .min(2)
            .min(bytes.len());
        if count == 0 {
            return Poll::Pending;
        }
        self.bytes
            .lock()
            .unwrap()
            .extend_from_slice(&bytes[..count]);
        self.remaining.fetch_sub(count, Ordering::SeqCst);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[test]
fn cancelled_mid_first_write_keeps_exact_prefix_and_does_not_repeat_or_accept_new_buffer() {
    for mode in [Mode::Http, Mode::Tls] {
        for client_role in [true, false] {
            let written = Arc::new(std::sync::Mutex::new(Vec::new()));
            let remaining = Arc::new(std::sync::atomic::AtomicUsize::new(3));
            let inner = CutWriter {
                bytes: written.clone(),
                remaining: remaining.clone(),
            };
            let mut stream = if client_role {
                Stream::client(inner, mode, None, None)
            } else {
                Stream::server(inner, mode)
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b"first"),
                Poll::Ready(Ok(5))
            ));
            let expected = stream.pending.clone();
            assert_eq!(written.lock().unwrap().as_slice(), &expected[..3]);
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut cx, b"cancelled")
                    .is_pending()
            );
            assert_eq!(written.lock().unwrap().len(), 3);
            remaining.store(100000, Ordering::SeqCst);
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(*written.lock().unwrap(), expected);
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b"next"),
                Poll::Ready(Ok(4))
            ));
            assert!(matches!(
                Pin::new(&mut stream).poll_shutdown(&mut cx),
                Poll::Ready(Ok(()))
            ));
            let tail = if mode == Mode::Http {
                b"next".to_vec()
            } else {
                records(b"next")
            };
            assert_eq!(*written.lock().unwrap(), [expected, tail].concat());
        }
    }
}

#[tokio::test]
async fn tls_payload_sni_tail_and_following_record_resolve_after_each_cancel_point() {
    for client_role in [true, false] {
        let first = if client_role {
            server_hello(b"first", 0, [1; 28], [2; 32])
        } else {
            client_hello("front.example", b"first", 0, [1; 28], [2; 32]).unwrap()
        };
        let prefix_len = if client_role {
            SERVER_PREFIX
        } else {
            CLIENT_PREFIX
        };
        let mut cuts = vec![
            3,
            prefix_len - 1,
            prefix_len,
            prefix_len + 2,
            first.len(),
            first.len() + 2,
            first.len() + 5 + 2,
        ];
        if !client_role {
            cuts.extend([prefix_len + 5 + 4, prefix_len + 5 + 9 + 2, first.len() - 1]);
        }
        let wire = [first, records(b"second")].concat();
        for cut in cuts {
            let (mut send, recv) = tokio::io::duplex(8192);
            let mut stream = if client_role {
                Stream::client(recv, Mode::Tls, None, None)
            } else {
                Stream::server(recv, Mode::Tls)
            };
            send.write_all(&wire[..cut]).await.unwrap();
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut received = Vec::new();
            loop {
                let mut bytes = [0; 3];
                let mut output = ReadBuf::new(&mut bytes);
                match Pin::new(&mut stream).poll_read(&mut cx, &mut output) {
                    Poll::Pending => break, // 丢弃本次read future，然后从实例保存的游标恢复。
                    Poll::Ready(Ok(())) => {
                        assert!(!output.filled().is_empty(), "切点{cut}不能误报EOF");
                        received.extend_from_slice(output.filled());
                    }
                    Poll::Ready(Err(error)) => panic!("切点{cut}不应失败: {error}"),
                }
            }
            send.write_all(&wire[cut..]).await.unwrap();
            send.shutdown().await.unwrap();
            timeout(WAIT, stream.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, b"firstsecond", "角色={client_role} 切点={cut}");
        }
    }
}

struct BrokenWriter {
    bytes: Vec<u8>,
    kind: io::ErrorKind,
}
impl AsyncWrite for BrokenWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.bytes.is_empty() {
            let count = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..count]);
            return Poll::Ready(Ok(count));
        }
        if self.kind == io::ErrorKind::WriteZero {
            Poll::Ready(Ok(0))
        } else {
            Poll::Ready(Err(self.kind.into()))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[test]
fn write_zero_and_transport_errors_after_partial_first_message_are_sticky() {
    for mode in [Mode::Http, Mode::Tls] {
        for client in [true, false] {
            for kind in [io::ErrorKind::WriteZero, io::ErrorKind::ConnectionReset] {
                let inner = BrokenWriter {
                    bytes: Vec::new(),
                    kind,
                };
                let mut stream = if client {
                    Stream::client(inner, mode, None, None)
                } else {
                    Stream::server(inner, mode)
                };
                let mut cx = Context::from_waker(std::task::Waker::noop());
                // 已接受的有界批次只认领一次，底层错误在下一操作明确返回。
                assert!(matches!(
                    Pin::new(&mut stream).poll_write(&mut cx, b"first"),
                    Poll::Ready(Ok(5))
                ));
                assert_eq!(stream.failure, Some(kind));
                assert_eq!(stream.inner.bytes.len(), 3);
                assert!(matches!(
                    Pin::new(&mut stream).poll_flush(&mut cx),
                    Poll::Ready(Err(error)) if error.kind() == kind
                ));
                assert!(matches!(
                    Pin::new(&mut stream).poll_write(&mut cx, b"different"),
                    Poll::Ready(Err(error)) if error.kind() == kind
                ));
                assert!(matches!(
                    Pin::new(&mut stream).poll_shutdown(&mut cx),
                    Poll::Ready(Err(error)) if error.kind() == kind
                ));
                assert_eq!(stream.inner.bytes.len(), 3);
            }
        }
    }
}

#[tokio::test]
async fn malformed_truncated_and_over_limit_heads_fail_closed() {
    for (mode, client, wire) in [
        (Mode::Http, false, vec![b'x'; MAX_HTTP_HEAD + 1]),
        (Mode::Http, true, b"HTTP/1.1 unfinished\r\n".to_vec()),
        (Mode::Tls, false, vec![0x16, 3]),
        (Mode::Tls, true, vec![0x16, 3, 1]),
        (Mode::Tls, true, {
            let mut wire = server_hello(b"payload", 0, [0; 28], [0; 32]);
            wire.pop();
            wire
        }),
        (Mode::Tls, false, {
            let mut wire = client_hello("front.example", b"payload", 0, [0; 28], [0; 32]).unwrap();
            wire.truncate(CLIENT_PREFIX + 3);
            wire
        }),
        (Mode::Tls, false, {
            let mut wire = client_hello("front.example", b"payload", 0, [0; 28], [0; 32]).unwrap();
            wire.pop();
            wire
        }),
        (Mode::Tls, false, {
            let mut wire = client_hello("front.example", b"payload", 0, [0; 28], [0; 32]).unwrap();
            let offset = CLIENT_PREFIX + b"payload".len() + 7;
            wire[offset..offset + 2].copy_from_slice(&254u16.to_be_bytes());
            wire
        }),
        (Mode::Tls, true, {
            let mut wire = server_hello(b"first", 0, [0; 28], [0; 32]);
            wire.extend([0x17, 3, 3, 0x40, 1]);
            wire
        }),
        (Mode::Tls, true, {
            let mut wire = server_hello(b"first", 0, [0; 28], [0; 32]);
            wire.extend([0x16, 3, 3, 0, 1, 1]);
            wire
        }),
        (Mode::Tls, false, {
            let mut wire = vec![0x16, 3, 1];
            wire.resize(CLIENT_PREFIX, 0);
            wire[CLIENT_PREFIX - 2..].copy_from_slice(&1025u16.to_be_bytes());
            wire
        }),
        (Mode::Tls, true, {
            let mut wire = vec![0x16, 3, 1];
            wire.resize(SERVER_PREFIX, 0);
            wire[SERVER_PREFIX - 2..].copy_from_slice(&16385u16.to_be_bytes());
            wire
        }),
    ] {
        let (mut send, recv) = tokio::io::duplex(16384);
        send.write_all(&wire).await.unwrap();
        send.shutdown().await.unwrap();
        let mut stream = if client {
            Stream::client(recv, mode, None, None)
        } else {
            Stream::server(recv, mode)
        };
        let mut bytes = Vec::new();
        assert!(
            timeout(WAIT, stream.read_to_end(&mut bytes))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(stream.failure, Some(io::ErrorKind::InvalidData));
        assert!(stream.write(b"not-usable").await.is_err());
    }
    // 零记录跳过但一次poll工作有界，后续合法payload仍可读。
    let (mut send, recv) = tokio::io::duplex(16384);
    let mut wire = server_hello(&[], 0, [0; 28], [0; 32]);
    for _ in 0..100 {
        wire.extend([0x17, 3, 3, 0, 0]);
    }
    wire.extend(records(b"ok"));
    send.write_all(&wire).await.unwrap();
    send.shutdown().await.unwrap();
    let mut stream = Stream::client(recv, Mode::Tls, None, None);
    let mut bytes = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"ok");
}
