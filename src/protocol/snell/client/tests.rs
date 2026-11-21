use super::*;
use crate::config::Secret;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) struct Gate {
    pub(super) inner: tokio::io::DuplexStream,
    pub(super) blocked: Arc<AtomicBool>,
}
impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}
impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.blocked.load(Ordering::Relaxed) {
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
fn options(version: u8, mode: Option<&str>) -> SnellClientOptions {
    SnellClientOptions {
        psk: Secret("test-snell-client-psk".into()),
        version,
        userkey: Some(Secret("test-key".into())),
        mode: mode.map(str::to_owned),
        obfs_mode: None,
        obfs_host: None,
        obfs_uri: None,
        reuse: false,
    }
}

#[test]
fn request_and_reply_match_fixed_upstream_formats() {
    let options = options(5, None);
    let target: Target = "[::1]:443".parse::<SocketAddr>().unwrap().into();
    let bytes = request(&options, Some(&target)).unwrap();
    assert_eq!(&bytes[..3], &[1, 5, 8]);
    assert_eq!(&bytes[3..11], b"test-key");
    assert_eq!(&bytes[11..], b"\x03::1\x01\xbb");
    assert_eq!(request(&options, None).unwrap(), b"\x01\x06\x08test-key");
    assert_eq!(reply(b"\0early").unwrap(), b"early");
    assert_eq!(
        reply(&[2, 1, 3, b'b', b'a', b'd']).unwrap_err().kind(),
        io::ErrorKind::ConnectionRefused
    );
    for malformed in [&[][..], &[1], &[2, 1], &[2, 1, 4, b'b', b'a', b'd']] {
        assert!(reply(malformed).is_err());
    }
}

#[tokio::test]
async fn shaped_long_userkey_and_host_keep_complete_request_in_first_record() {
    let mut options = options(6, None);
    options.userkey = Some(Secret("k".repeat(255)));
    let (wire, mut peer) = tokio::io::duplex(65536);
    let target = Target {
        host: Host::Domain(
            [
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61),
            ]
            .join("."),
        ),
        port: 443,
    };
    let stream = connect(Upstream::new_send(wire, None), &options, &target)
        .await
        .unwrap();
    let mut reader = ShapedV6Reader::new(&mut peer, options.psk.0.as_bytes());
    let record = reader.read_record().await.unwrap().unwrap();
    assert_eq!(record, request(&options, Some(&target)).unwrap());
    let (decoded, early) = parse_request(&record, 6).unwrap();
    assert_eq!(decoded.target, Some(target));
    assert!(early.is_empty());
    drop(stream);
}

#[tokio::test]
async fn owned_record_futures_preserve_cancelled_write_and_first_reply() {
    for (version, mode) in [
        (5, None),
        (6, None),
        (6, Some("unshaped")),
        (6, Some("unsafe-raw")),
    ] {
        let options = options(version, mode);
        let selected = options.record_mode();
        let psk = options.psk.0.as_bytes().to_vec();
        let (wire, mut peer) = tokio::io::duplex(16384);
        let blocked = Arc::new(AtomicBool::new(false));
        let stream = Upstream::new_send(
            Gate {
                inner: wire,
                blocked: blocked.clone(),
            },
            None,
        );
        let target: Target = "127.0.0.1:443".parse::<SocketAddr>().unwrap().into();
        let mut client = connect(stream, &options, &target).await.unwrap();
        let (read, write) = tokio::io::split(&mut peer);
        let mut reader = match selected {
            Mode::Shaped | Mode::Unshaped => Reader::Aead(
                RecordReader::new(read, &psk, selected == Mode::Shaped)
                    .await
                    .unwrap(),
            ),
            Mode::Default => Reader::ShapedV6(ShapedV6Reader::new(read, &psk)),
            Mode::UnsafeRaw => Reader::Raw(RawReader::new(read)),
        };
        assert!(
            reader
                .read_record()
                .await
                .unwrap()
                .unwrap()
                .starts_with(&[1, 5, 8])
        );
        blocked.store(true, Ordering::Relaxed);
        assert_eq!(client.write(b"first").await.unwrap(), 5);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            Pin::new(&mut client)
                .poll_write(&mut cx, b"cancelled")
                .is_pending()
        );
        blocked.store(false, Ordering::Relaxed);
        client.flush().await.unwrap();
        assert_eq!(reader.read_record().await.unwrap(), Some(b"first".to_vec()));
        client.write_all(b"second").await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(
            reader.read_record().await.unwrap(),
            Some(b"second".to_vec())
        );
        client.shutdown().await.unwrap();
        client.shutdown().await.unwrap();
        assert!(reader.read_record().await.unwrap().is_none());
        assert!(client.write(b"after-fin").await.is_err());
        // 读future在首应答salt/头尚未到达时Pending，取消后仍可继续。
        let mut scratch = [0; 64];
        let mut output = ReadBuf::new(&mut scratch);
        assert!(
            Pin::new(&mut client)
                .poll_read(&mut cx, &mut output)
                .is_pending()
        );
        let mut direction = TunnelIo::new(write, selected);
        let writer = direction.writer(&psk).await.unwrap();
        writer.write_record(b"\0reply-after-fin").await.unwrap();
        writer.write_zero().await.unwrap();
        writer.flush().await.unwrap();
        let mut payload = Vec::new();
        client.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"reply-after-fin");
    }
}

#[tokio::test]
async fn cancelled_udp_write_cannot_be_reused_or_finished_after_half_frame() {
    let (wire, mut peer) = tokio::io::duplex(64);
    let blocked = Arc::new(AtomicBool::new(true));
    let (read, write) = tokio::io::split(Upstream::new_send(
        Gate {
            inner: wire,
            blocked: blocked.clone(),
        },
        None,
    ));
    let mut direction = TunnelIo::new(write, Mode::UnsafeRaw);
    let _ = direction.writer(b"test-snell-client-psk").await.unwrap();
    let mut session = UdpSession {
        read: Reader::Raw(RawReader::new(read)),
        write: direction.writer.take().unwrap(),
        target: "127.0.0.1:9".parse::<SocketAddr>().unwrap().into(),
        prefix: vec![1, 0, 4, 127, 0, 0, 1, 0, 9],
        failure: false,
    };
    assert!(
        timeout(Duration::from_millis(10), session.send(b"pending"))
            .await
            .is_err()
    );
    assert!(session.failure);
    blocked.store(false, Ordering::Relaxed);
    assert_eq!(
        session.send(b"new").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    session.close().await;
    drop(session);
    let mut wire = Vec::new();
    peer.read_to_end(&mut wire).await.unwrap();
    assert!(wire.is_empty(), "取消写之后不能补写旧帧或FIN");
}

#[tokio::test]
async fn raw_receive_cancelled_mid_header_and_aead_v6_capacity() {
    let (mut send, recv) = tokio::io::duplex(64);
    let mut reader = RawReader::new(recv);
    send.write_all(&[4, 0, 0]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(10), reader.read_record())
            .await
            .is_err()
    );
    send.write_all(&[0, 0, 0, 1, 7]).await.unwrap();
    assert_eq!(reader.read_record().await.unwrap(), Some(vec![7]));
    for pad in [true, false] {
        let (write, read) = tokio::io::duplex(200000);
        let psk = b"test-snell-client-psk";
        let mut writer = RecordWriter::new(write, psk, pad).await.unwrap();
        let mut reader = RecordReader::new(read, psk, pad).await.unwrap();
        let bytes = vec![3; u16::MAX as usize];
        let result = writer.write_record(&bytes).await;
        if pad {
            assert!(result.is_err());
        } else {
            result.unwrap();
            assert_eq!(reader.read_record().await.unwrap(), Some(bytes));
            assert!(writer.write_record(&vec![0; 65536]).await.is_err());
        }
    }
    let (write, read) = tokio::io::duplex(200000);
    let mut writer = RawWriter::new(write);
    let mut reader = RawReader::new(read);
    let bytes = vec![5; 65535];
    writer.write_record(&bytes).await.unwrap();
    assert_eq!(reader.read_record().await.unwrap(), Some(bytes));
    assert!(writer.write_record(&vec![0; 65536]).await.is_err());
}

#[tokio::test]
async fn udp_discards_wrong_source_preserves_empty_and_cancelled_receive() {
    let options = options(6, Some("unsafe-raw"));
    let (wire, mut peer) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(Upstream::new_send(wire, None));
    let mut direction = TunnelIo::new(write, Mode::UnsafeRaw);
    let writer = direction.writer(options.psk.0.as_bytes()).await.unwrap();
    writer.write_record(&[1, 6, 0]).await.unwrap();
    let read = Reader::Raw(RawReader::new(read));
    let write = direction.writer.take().unwrap();
    let target: Target = "127.0.0.1:12345".parse::<SocketAddr>().unwrap().into();
    let mut session = UdpSession {
        read,
        write,
        target: target.clone(),
        prefix: vec![1, 0, 4, 127, 0, 0, 1, 0x30, 0x39],
        failure: false,
    };
    let mut request = [0; 10];
    peer.read_exact(&mut request).await.unwrap();
    peer.write_all(&[4, 0, 0]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(10), session.recv())
            .await
            .is_err()
    );
    // 先发错来源，再发合法空包；不能将空数据报当结束。
    peer.write_all(&[
        0, 0, 0, 7, 4, 127, 0, 0, 2, 0x30, 0x39, 4, 0, 0, 0, 0, 0, 7, 4, 127, 0, 0, 1, 0x30, 0x39,
    ])
    .await
    .unwrap();
    assert!(session.recv().await.unwrap().is_empty());
    assert_eq!(
        session.send(&vec![0; 65536]).await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(!session.failure);
}
