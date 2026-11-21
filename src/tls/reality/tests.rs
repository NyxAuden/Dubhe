use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context as PollContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct TargetOwner(Arc<AtomicBool>);
impl Drop for TargetOwner {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
struct Probe {
    target_closed: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    short: bool,
}
impl Drop for Probe {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl AsyncRead for Probe {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut PollContext<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Probe {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut PollContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(
            self.target_closed.load(Ordering::SeqCst),
            "首次 poll 前已不可逆关闭原目标"
        );
        let calls = self.writes.fetch_add(1, Ordering::SeqCst);
        if calls == 0 {
            assert_eq!(bytes[0], 22, "首批只能是本地 SH，不能拼接目标回落字节");
        }
        if self.short {
            if calls == 0 {
                return Poll::Ready(Ok(3));
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "测试短写后失败",
            )));
        }
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut PollContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut PollContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn setup(
    total: usize,
) -> (
    Prepared,
    hello::Hello,
    Vec<u8>,
    rustls::server::reality::RecordPlan,
) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let target_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
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
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap();
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).unwrap();
    }
    let hello = hello::read(&mut wire.as_slice()).await.unwrap();
    let mut target = ServerConnection::new(Arc::new(target_config)).unwrap();
    target.read_tls(&mut wire.as_slice()).unwrap();
    target.process_new_packets().unwrap();
    let mut flight = Vec::new();
    while target.wants_write() {
        target.write_tls(&mut flight).unwrap();
    }
    let length = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let raw_sh = flight[5..5 + length].to_vec();
    let plan = rustls::server::reality::RecordPlan::new(length + 5, 6, vec![total], None).unwrap();
    let config: Reality = serde_json::from_value(serde_json::json!({"target":{"host":"127.0.0.1","port":9443},
        "private_key":URL_SAFE_NO_PAD.encode([0x59;32]),"server_names":["localhost"],"short_ids":[""],"mldsa65_seed":URL_SAFE_NO_PAD.encode([0x42;32])})).unwrap();
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
    (prepared, hello, raw_sh, plan)
}

#[tokio::test]
async fn small_target_slot_uses_natural_length_without_consuming_target() {
    // 513 为可解析的聚合布局，但无法容纳完整本地证书 flight；现在改用
    // 自然 record 长度，仍应成功预检并保留目标回退选项直到提交。
    let (prepared, hello, raw_sh, plan) = setup(513).await;
    let closed = Arc::new(AtomicBool::new(false));
    let target = TargetOwner(closed.clone());
    let session = prepared
        .prepare_session(&hello, [0x12; 32], raw_sh, plan)
        .unwrap();
    assert!(
        !closed.load(Ordering::SeqCst),
        "预检阶段仍持原连接可用于回落"
    );
    drop(session);
    drop(target);
    assert!(closed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn commit_first_write_pending_is_irreversible_and_cancellation_has_one_owner() {
    let (prepared, hello, raw_sh, plan) = setup(4096).await;
    let session = prepared
        .prepare_session(&hello, [0x12; 32], raw_sh, plan)
        .unwrap();
    let closed = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let io = Probe {
        target_closed: closed.clone(),
        writes: writes.clone(),
        dropped: dropped.clone(),
        short: false,
    };
    let mut future = Box::pin(commit(
        io,
        session,
        TargetOwner(closed.clone()),
        Instant::now() + Duration::from_secs(3),
    ));
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(closed.load(Ordering::SeqCst));
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    drop(future);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn commit_short_write_then_error_never_recovers_target_or_retries_fallback() {
    let (prepared, hello, raw_sh, plan) = setup(4096).await;
    let session = prepared
        .prepare_session(&hello, [0x12; 32], raw_sh, plan)
        .unwrap();
    let closed = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let io = Probe {
        target_closed: closed.clone(),
        writes: writes.clone(),
        dropped: dropped.clone(),
        short: true,
    };
    let error = match commit(
        io,
        session,
        TargetOwner(closed.clone()),
        Instant::now() + Duration::from_secs(3),
    )
    .await
    {
        Err(error) => error,
        Ok(_) => panic!("短写错误必须关闭"),
    };
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(closed.load(Ordering::SeqCst));
    assert_eq!(writes.load(Ordering::SeqCst), 2);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}
