use super::*;
use crate::Config;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
const WAIT: Duration = Duration::from_secs(3);
const PASSWORD: &str = "anytls-pool-test-password";

fn target(port: u16) -> Target {
    format!("127.0.0.1:{port}")
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into()
}
fn pool(options: AnyTlsClientOptions) -> Arc<Pool> {
    let shared = Arc::new(SharedScheme::default());
    // 确定性合法方案：测试独立帧/生命周期，不依赖随机Waste块划分。
    assert!(shared.update(b"stop=0\n0=7-7"));
    Arc::new(Pool::new(options, shared))
}
async fn prologue(peer: &mut DuplexStream) {
    let mut digest = [0; 32];
    peer.read_exact(&mut digest).await.unwrap();
    assert_eq!(
        digest,
        <[u8; 32]>::from(Sha256::digest(PASSWORD.as_bytes()))
    );
    let size = peer.read_u16().await.unwrap();
    let mut bytes = vec![0; size as usize];
    peer.read_exact(&mut bytes).await.unwrap();
    assert!(bytes.iter().all(|b| *b == 0));
    assert_eq!(size, 7);
}
async fn packet(peer: &mut DuplexStream) -> (u8, u32, Vec<u8>) {
    let mut header = [0; 7];
    timeout(WAIT, peer.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let id = u32::from_be_bytes(header[1..5].try_into().unwrap());
    let size = u16::from_be_bytes(header[5..7].try_into().unwrap()) as usize;
    let mut body = vec![0; size];
    peer.read_exact(&mut body).await.unwrap();
    (header[0], id, body)
}
async fn opening(peer: &mut DuplexStream, first: bool, id: u32, port: u16) {
    if first {
        prologue(peer).await;
        let (command, stream, data) = packet(peer).await;
        assert_eq!((command, stream), (4, 0));
        assert_eq!(
            data,
            format!(
                "client=dubhe\npadding-md5={}\nv=2",
                super::super::super::anytls_padding::md5_text("stop=0\n0=7-7")
            )
            .as_bytes()
        );
    }
    assert_eq!(packet(peer).await, (1, id, Vec::new()));
    let mut addr = vec![1, 127, 0, 0, 1];
    addr.extend_from_slice(&port.to_be_bytes());
    assert_eq!(packet(peer).await, (2, id, addr));
}
async fn idle(pool: &Pool, count: usize) {
    timeout(WAIT, async {
        loop {
            if pool.state.lock().unwrap().idle.len() == count {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn finish(tracker: &TaskTracker, stop: &CancellationToken) {
    stop.cancel();
    tracker.close();
    timeout(WAIT, tracker.wait()).await.unwrap();
}
async fn connect(
    pool: &Arc<Pool>,
    tracker: &TaskTracker,
    stop: &CancellationToken,
    wire: DuplexStream,
    port: u16,
) -> Upstream {
    pool.connect(
        PASSWORD,
        &target(port),
        tracker.clone(),
        stop.clone(),
        WAIT,
        || async move { Ok(Upstream::new_send(wire, None)) },
    )
    .await
    .unwrap()
}
async fn reused(
    pool: &Arc<Pool>,
    tracker: &TaskTracker,
    stop: &CancellationToken,
    port: u16,
) -> Upstream {
    pool.connect(
        PASSWORD,
        &target(port),
        tracker.clone(),
        stop.clone(),
        WAIT,
        || async { Err(io::Error::other("ready会话不能再次拨号")) },
    )
    .await
    .unwrap()
}

#[test]
fn options_defaults_limits_redaction_and_outbound_instances_are_isolated() {
    let options = AnyTlsClientOptions::default();
    assert!(!options.disable_reuse);
    assert_eq!(options.idle_session_check_interval_ms, 30000);
    assert_eq!(options.idle_session_timeout_ms, 30000);
    assert_eq!(options.min_idle_session, 0);
    let value = serde_json::json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[
        {"type":"anytls","tag":"up","endpoint":"127.0.0.1:1234","password":PASSWORD,"tls":{"ca_file":"/not-used"},"anytls":{}}],"route":{"default":"up"}});
    let config = Config::from_json(&value.to_string()).unwrap();
    assert!(!format!("{:?}", config.outbounds).contains(PASSWORD));
    Config::from_json(&serde_json::to_string(&config).unwrap()).unwrap();
    for (key, text) in [
        ("idle_session_check_interval_ms", serde_json::json!(5000)),
        ("idle_session_timeout_ms", serde_json::json!(86400001)),
        ("min_idle_session", serde_json::json!(65)),
        ("disable_reuse", serde_json::json!("true")),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut invalid = value.clone();
        invalid["outbounds"][0]["anytls"][key] = text;
        assert!(Config::from_json(&invalid.to_string()).is_err());
    }
    let mut invalid = value.clone();
    invalid["outbounds"][0]["anytls"] =
        serde_json::json!({"disable_reuse":true,"min_idle_session":1});
    assert!(Config::from_json(&invalid.to_string()).is_err());
    let mut invalid = value;
    invalid["outbounds"][0]["type"] = serde_json::json!("http");
    assert!(Config::from_json(&invalid.to_string()).is_err());
    let first = pool(options.clone());
    let other = pool(options);
    assert!(!Arc::ptr_eq(&first, &other));
    assert!(!Arc::ptr_eq(&first.schemes, &other.schemes));
    // 编译出站的TLS材料须真实加载，实际实例隔离另由集成用例覆盖。
}

#[tokio::test]
async fn sequential_sessions_have_one_prologue_increasing_ids_and_idle_control_updates() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(65536);
    let mut first = connect(&pool, &tracker, &stop, wire, 443).await;
    opening(&mut peer, true, 1, 443).await;
    first.write_all(b"first").await.unwrap();
    first.flush().await.unwrap();
    assert_eq!(packet(&mut peer).await, (2, 1, b"first".to_vec()));
    peer.write_all(&frame(10, 0, b"v=2").unwrap())
        .await
        .unwrap();
    peer.write_all(&frame(2, 1, b"reply1").unwrap())
        .await
        .unwrap();
    peer.write_all(&frame(3, 1, &[]).unwrap()).await.unwrap();
    let mut reply = Vec::new();
    first.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"reply1");
    drop(first);
    idle(&pool, 1).await;
    peer.write_all(&frame(6, 0, b"stop=0\n0=9-9").unwrap())
        .await
        .unwrap();
    peer.write_all(&frame(8, 77, &[]).unwrap()).await.unwrap();
    assert_eq!(packet(&mut peer).await, (9, 77, Vec::new()));
    assert_eq!(
        pool.schemes.snapshot().handshake_size().unwrap(),
        9,
        "无业务read也持续消费cmd6"
    );
    let mut second = reused(&pool, &tracker, &stop, 8443).await;
    opening(&mut peer, false, 2, 8443).await;
    peer.write_all(&frame(2, 1, b"late-old-data").unwrap())
        .await
        .unwrap();
    peer.write_all(&frame(3, 1, &[]).unwrap()).await.unwrap();
    peer.write_all(&frame(6, 0, b"stop=bad").unwrap())
        .await
        .unwrap();
    peer.write_all(&frame(2, 2, b"reply2").unwrap())
        .await
        .unwrap();
    let mut reply = [0; 6];
    second.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply2");
    second.write_all(b"next").await.unwrap();
    second.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    assert_eq!(packet(&mut peer).await, (2, 2, b"next".to_vec()));
    assert_eq!(packet(&mut peer).await, (3, 2, Vec::new()));
    drop(second);
    assert_eq!(pool.schemes.snapshot().handshake_size().unwrap(), 9);
    finish(&tracker, &stop).await;
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn multi_id_dispatch_synack_failure_and_peer_fin_do_not_close_other_stream() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(65536);
    let session = Session::create(
        Upstream::new_send(wire, None),
        PASSWORD,
        &pool,
        &tracker,
        stop.clone(),
        WAIT,
    )
    .await
    .unwrap();
    let mut first = session.open(address(&target(443)).unwrap()).await.unwrap();
    opening(&mut peer, true, 1, 443).await;
    let mut second = session.open(address(&target(8443)).unwrap()).await.unwrap();
    opening(&mut peer, false, 2, 8443).await;
    peer.write_all(&frame(2, 2, b"two").unwrap()).await.unwrap();
    peer.write_all(&frame(2, 1, b"one").unwrap()).await.unwrap();
    let mut data = [0; 3];
    first.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"one");
    second.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"two");
    peer.write_all(&frame(7, 1, b"untrusted refusal body").unwrap())
        .await
        .unwrap();
    let err = first.read(&mut data).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    assert!(!err.to_string().contains("untrusted"));
    assert_eq!(packet(&mut peer).await, (3, 1, Vec::new()));
    peer.write_all(&frame(2, 2, b"yes").unwrap()).await.unwrap();
    second.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"yes");
    peer.write_all(&frame(3, 2, &[]).unwrap()).await.unwrap();
    assert_eq!(second.read(&mut data).await.unwrap(), 0);
    drop(first);
    drop(second);
    finish(&tracker, &stop).await;
    assert_eq!(peer.read(&mut data).await.unwrap(), 0, "对端FIN不回送");
}

#[tokio::test]
async fn slow_stream_queue_is_bounded_and_local_close_unblocks_other_id() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(65536);
    let session = Session::create(
        Upstream::new_send(wire, None),
        PASSWORD,
        &pool,
        &tracker,
        stop.clone(),
        WAIT,
    )
    .await
    .unwrap();
    let first = session.open(address(&target(443)).unwrap()).await.unwrap();
    opening(&mut peer, true, 1, 443).await;
    let mut second = session.open(address(&target(8443)).unwrap()).await.unwrap();
    opening(&mut peer, false, 2, 8443).await;
    for _ in 0..READ_QUEUE + 2 {
        peer.write_all(&frame(2, 1, b"slow").unwrap())
            .await
            .unwrap();
    }
    peer.write_all(&frame(2, 2, b"other").unwrap())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(10), second.read(&mut [0; 8]))
            .await
            .is_err()
    );
    assert_eq!(first.rx.len(), READ_QUEUE);
    drop(first);
    let mut data = [0; 5];
    timeout(WAIT, second.read_exact(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data, b"other");
    drop(second);
    finish(&tracker, &stop).await;
}

#[tokio::test]
async fn alert_truncated_header_payload_and_transport_failure_are_session_wide() {
    for bytes in [
        frame(5, 0, b"untrusted-alert").unwrap(),
        vec![2, 0, 0],
        vec![2, 0, 0, 0, 1, 0, 5, 7],
    ] {
        let pool = pool(AnyTlsClientOptions::default());
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let (wire, mut peer) = tokio::io::duplex(65536);
        let mut stream = connect(&pool, &tracker, &stop, wire, 443).await;
        opening(&mut peer, true, 1, 443).await;
        peer.write_all(&bytes).await.unwrap();
        peer.shutdown().await.unwrap();
        let err = timeout(WAIT, stream.read(&mut [0; 8]))
            .await
            .unwrap()
            .unwrap_err();
        assert!(!err.to_string().contains("untrusted"));
        assert!(stream.write(b"late").await.is_err());
        drop(stream);
        finish(&tracker, &stop).await;
        assert!(pool.take().is_none());
    }
}

struct Gate {
    inner: DuplexStream,
    blocked: Arc<AtomicBool>,
    waker: Arc<AtomicWaker>,
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
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.waker.register(cx.waker());
        if self.blocked.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        let take = bytes.len().min(2);
        Pin::new(&mut self.inner).poll_write(cx, &bytes[..take])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn queued_short_write_cancelled_flush_next_buffer_and_fin_are_exactly_once() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(65536);
    let blocked = Arc::new(AtomicBool::new(false));
    let waker = Arc::new(AtomicWaker::new());
    let inner = Upstream::new_send(
        Gate {
            inner: wire,
            blocked: blocked.clone(),
            waker: waker.clone(),
        },
        None,
    );
    let mut stream = pool
        .connect(
            PASSWORD,
            &target(443),
            tracker.clone(),
            stop.clone(),
            WAIT,
            || async { Ok(inner) },
        )
        .await
        .unwrap();
    opening(&mut peer, true, 1, 443).await;
    blocked.store(true, Ordering::Release);
    stream.write_all(b"accepted").await.unwrap();
    assert!(
        timeout(Duration::from_millis(10), stream.flush())
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(10), stream.write(b"cancelled-buffer"))
            .await
            .is_err()
    );
    blocked.store(false, Ordering::Release);
    waker.wake();
    stream.flush().await.unwrap();
    assert_eq!(packet(&mut peer).await, (2, 1, b"accepted".to_vec()));
    stream.write_all(b"second").await.unwrap();
    stream.shutdown().await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(packet(&mut peer).await, (2, 1, b"second".to_vec()));
    assert_eq!(packet(&mut peer).await, (3, 1, Vec::new()));
    drop(stream);
    finish(&tracker, &stop).await;
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn reused_v2_stream_watchdog_times_out_but_complete_header_disarms_it() {
    for disarm in [false, true] {
        let pool = pool(AnyTlsClientOptions::default());
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let (wire, mut peer) = tokio::io::duplex(65536);
        let first = connect(&pool, &tracker, &stop, wire, 443).await;
        opening(&mut peer, true, 1, 443).await;
        peer.write_all(&frame(10, 0, b"v=2").unwrap())
            .await
            .unwrap();
        peer.write_all(&frame(3, 1, &[]).unwrap()).await.unwrap();
        drop(first);
        idle(&pool, 1).await;
        let mut second = reused(&pool, &tracker, &stop, 8443).await;
        opening(&mut peer, false, 2, 8443).await;
        if disarm {
            // 只有一个完整帧头即解除，不能错误等整个负载；部分负载由原read任务保存。
            peer.write_all(&[2, 0, 0, 0, 2, 0, 2, b'o']).await.unwrap();
            timeout(WAIT, async {
                loop {
                    let session = pool.state.lock().unwrap().sessions[0].upgrade().unwrap();
                    if session.watchdog.borrow().is_none() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        tokio::time::advance(OPEN_TIMEOUT + Duration::from_millis(1)).await;
        if disarm {
            peer.write_all(b"k").await.unwrap();
            let mut bytes = [0; 2];
            second.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ok");
        } else {
            assert_eq!(
                second.read(&mut [0; 1]).await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
        drop(second);
        finish(&tracker, &stop).await;
    }
}

#[tokio::test(start_paused = true)]
async fn idle_expiry_minimum_retention_and_disabled_reuse_never_predial() {
    for disabled in [false, true] {
        let options = AnyTlsClientOptions {
            disable_reuse: disabled,
            idle_session_timeout_ms: 6000,
            idle_session_check_interval_ms: 6000,
            min_idle_session: usize::from(!disabled),
        };
        let pool = pool(options);
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let mut peers = Vec::new();
        let mut clients = Vec::new();
        for _ in 0..2 {
            let (wire, mut peer) = tokio::io::duplex(65536);
            let client = connect(&pool, &tracker, &stop, wire, 443).await;
            opening(&mut peer, true, 1, 443).await;
            clients.push(client);
            peers.push(peer);
        }
        for client in &mut clients {
            client.shutdown().await.unwrap();
        }
        for peer in &mut peers {
            assert_eq!(packet(peer).await, (3, 1, Vec::new()));
        }
        drop(clients);
        if disabled {
            for peer in &mut peers {
                assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            }
        } else {
            idle(&pool, 2).await;
            tokio::time::advance(Duration::from_secs(13)).await;
            pool.clean();
            idle(&pool, 1).await;
        }
        // 没有新的受控open工厂调用，minIdle只保留已有会话；弱条目可随清理回收。
        assert!(pool.state.lock().unwrap().sessions.len() <= 2);
        finish(&tracker, &stop).await;
    }
}

#[tokio::test]
async fn pool_cache_cap_and_id_exhaustion_fail_closed_without_reusing_ids() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let mut clients = Vec::new();
    let mut peers = Vec::new();
    for _ in 0..CACHE + 1 {
        let (wire, mut peer) = tokio::io::duplex(65536);
        let client = connect(&pool, &tracker, &stop, wire, 443).await;
        opening(&mut peer, true, 1, 443).await;
        clients.push(client);
        peers.push(peer);
    }
    for client in &mut clients {
        client.shutdown().await.unwrap();
    }
    drop(clients);
    idle(&pool, CACHE).await;
    let session = pool.take().unwrap();
    session.core.lock().unwrap().next_id = u32::MAX;
    assert!(session.open(address(&target(80)).unwrap()).await.is_err());
    assert!(session.draining.load(Ordering::Acquire));
    assert!(session.cancel.is_cancelled());
    finish(&tracker, &stop).await;
}

#[tokio::test]
async fn retiring_pool_preserves_active_flow_and_closes_idle_and_all_background_tasks() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(65536);
    let mut live = connect(&pool, &tracker, &stop, wire, 443).await;
    opening(&mut peer, true, 1, 443).await;
    let (wire, mut idle_peer) = tokio::io::duplex(65536);
    let mut old = connect(&pool, &tracker, &stop, wire, 8443).await;
    opening(&mut idle_peer, true, 1, 8443).await;
    old.shutdown().await.unwrap();
    assert_eq!(packet(&mut idle_peer).await, (3, 1, Vec::new()));
    drop(old);
    idle(&pool, 1).await;
    pool.close();
    assert_eq!(idle_peer.read(&mut [0; 1]).await.unwrap(), 0);
    live.write_all(b"live").await.unwrap();
    live.flush().await.unwrap();
    assert_eq!(packet(&mut peer).await, (2, 1, b"live".to_vec()));
    peer.write_all(&frame(2, 1, b"yes").unwrap()).await.unwrap();
    live.read_exact(&mut [0; 3]).await.unwrap();
    let calls = AtomicUsize::new(0);
    assert!(
        pool.connect(
            PASSWORD,
            &target(80),
            tracker.clone(),
            stop.clone(),
            WAIT,
            || async {
                calls.fetch_add(1, Ordering::Relaxed);
                Err(closed())
            }
        )
        .await
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    live.shutdown().await.unwrap();
    assert_eq!(packet(&mut peer).await, (3, 1, Vec::new()));
    drop(live);
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    tracker.close();
    timeout(WAIT, tracker.wait()).await.unwrap();
}

#[tokio::test]
async fn peer_fin_keeps_buffered_data_and_eof_after_session_transport_ends() {
    for disabled in [false, true] {
        let options = AnyTlsClientOptions {
            disable_reuse: disabled,
            ..AnyTlsClientOptions::default()
        };
        let pool = pool(options);
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let (wire, mut peer) = tokio::io::duplex(65536);
        let session = Session::create(
            Upstream::new_send(wire, None),
            PASSWORD,
            &pool,
            &tracker,
            stop.clone(),
            WAIT,
        )
        .await
        .unwrap();
        let mut flow = session.open(address(&target(443)).unwrap()).await.unwrap();
        opening(&mut peer, true, 1, 443).await;
        peer.write_all(&frame(2, 1, b"before-fin").unwrap())
            .await
            .unwrap();
        peer.write_all(&frame(3, 1, &[]).unwrap()).await.unwrap();
        peer.shutdown().await.unwrap();
        timeout(WAIT, async {
            while !session.cancel.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut bytes = Vec::new();
        flow.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"before-fin");
        assert_eq!(flow.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(flow.write(b"late").await.is_err());
        drop(flow);
        finish(&tracker, &stop).await;
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0, "peer FIN不回送");
    }
}

#[tokio::test]
async fn full_write_queue_drop_fails_session_instead_of_reusing_without_fin() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(65536);
    let blocked = Arc::new(AtomicBool::new(false));
    let waker = Arc::new(AtomicWaker::new());
    let inner = Upstream::new_send(
        Gate {
            inner: wire,
            blocked: blocked.clone(),
            waker,
        },
        None,
    );
    let session = Session::create(inner, PASSWORD, &pool, &tracker, stop.clone(), WAIT)
        .await
        .unwrap();
    let mut flow = session.open(address(&target(443)).unwrap()).await.unwrap();
    opening(&mut peer, true, 1, 443).await;
    blocked.store(true, Ordering::Release);
    flow.write_all(b"inflight").await.unwrap();
    tokio::task::yield_now().await;
    for _ in 0..WRITE_QUEUE {
        flow.write_all(b"queued").await.unwrap();
    }
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(
        Pin::new(&mut flow)
            .poll_write(&mut cx, b"not-accepted")
            .is_pending()
    );
    assert_eq!(session.tx.capacity(), 0);
    drop(flow);
    assert!(session.cancel.is_cancelled());
    let mut wire = Vec::new();
    timeout(WAIT, peer.read_to_end(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert!(wire.is_empty(), "阻塞写不能在取消后补半帧或无所有者FIN");
    timeout(WAIT, async {
        while !tracker.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(pool.take().is_none());
    finish(&tracker, &stop).await;
}

#[tokio::test]
async fn cancelled_reused_open_never_redials_or_returns_half_written_session() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(65536);
    let blocked = Arc::new(AtomicBool::new(false));
    let waker = Arc::new(AtomicWaker::new());
    let inner = Upstream::new_send(
        Gate {
            inner: wire,
            blocked: blocked.clone(),
            waker,
        },
        None,
    );
    let mut first = pool
        .connect(
            PASSWORD,
            &target(443),
            tracker.clone(),
            stop.clone(),
            WAIT,
            || async { Ok(inner) },
        )
        .await
        .unwrap();
    opening(&mut peer, true, 1, 443).await;
    first.shutdown().await.unwrap();
    assert_eq!(packet(&mut peer).await, (3, 1, Vec::new()));
    drop(first);
    idle(&pool, 1).await;
    blocked.store(true, Ordering::Release);
    let calls = AtomicUsize::new(0);
    assert!(
        timeout(
            Duration::from_millis(10),
            pool.connect(
                PASSWORD,
                &target(8443),
                tracker.clone(),
                stop.clone(),
                WAIT,
                || async {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Err(closed())
                }
            )
        )
        .await
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        timeout(WAIT, peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(pool.take().is_none());
    finish(&tracker, &stop).await;
}

#[tokio::test]
async fn stream_limit_and_id_exhaustion_retire_without_closing_existing_ids() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(65536);
    let session = Session::create(
        Upstream::new_send(wire, None),
        PASSWORD,
        &pool,
        &tracker,
        stop.clone(),
        WAIT,
    )
    .await
    .unwrap();
    let mut flows = Vec::new();
    for index in 1..=STREAMS as u32 {
        flows.push(session.open(address(&target(443)).unwrap()).await.unwrap());
        opening(&mut peer, index == 1, index, 443).await;
    }
    assert!(
        matches!(session.open(address(&target(80)).unwrap()).await, Err(e) if e.kind() == io::ErrorKind::WouldBlock)
    );
    peer.write_all(&frame(3, STREAMS as u32, &[]).unwrap())
        .await
        .unwrap();
    assert_eq!(
        flows.last_mut().unwrap().read(&mut [0; 1]).await.unwrap(),
        0
    );
    session.core.lock().unwrap().next_id = u32::MAX;
    assert!(session.open(address(&target(80)).unwrap()).await.is_err());
    assert!(session.draining.load(Ordering::Acquire));
    assert!(!session.cancel.is_cancelled(), "ID耗尽不能中止既有ID");
    flows[0].write_all(b"existing").await.unwrap();
    flows[0].flush().await.unwrap();
    assert_eq!(packet(&mut peer).await, (2, 1, b"existing".to_vec()));
    for id in 1..STREAMS as u32 {
        peer.write_all(&frame(3, id, &[]).unwrap()).await.unwrap();
    }
    timeout(WAIT, async {
        while !session.cancel.is_cancelled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(flows);
    finish(&tracker, &stop).await;
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn review_peer_fin_does_not_confirm_unflushed_writes_or_cancelled_barriers() {
    for pending_flush in [false, true] {
        let options = AnyTlsClientOptions {
            disable_reuse: true,
            ..AnyTlsClientOptions::default()
        };
        let pool = pool(options);
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let (wire, mut peer) = tokio::io::duplex(65536);
        let blocked = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(AtomicWaker::new());
        let session = Session::create(
            Upstream::new_send(
                Gate {
                    inner: wire,
                    blocked: blocked.clone(),
                    waker,
                },
                None,
            ),
            PASSWORD,
            &pool,
            &tracker,
            stop.clone(),
            WAIT,
        )
        .await
        .unwrap();
        let mut flow = session.open(address(&target(443)).unwrap()).await.unwrap();
        opening(&mut peer, true, 1, 443).await;
        blocked.store(true, Ordering::Release);
        flow.write_all(b"accepted-not-flushed").await.unwrap();
        if pending_flush {
            assert!(
                timeout(Duration::from_millis(10), flow.flush())
                    .await
                    .is_err()
            );
        }
        peer.write_all(&frame(COMMAND_FIN, 1, &[]).unwrap())
            .await
            .unwrap();
        timeout(WAIT, async {
            while !flow.state.peer_fin.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            flow.shutdown().await.is_err(),
            "peer FIN不能确认未写出的业务或未确认flush"
        );
        drop(flow);
        finish(&tracker, &stop).await;
        assert_eq!(
            peer.read(&mut [0; 1]).await.unwrap(),
            0,
            "失败后不补业务或FIN"
        );
    }
}

#[tokio::test]
async fn review_full_queue_backpressures_heartbeat_or_refusal_without_failing_other_id() {
    for refusal in [false, true] {
        let pool = pool(AnyTlsClientOptions::default());
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let (wire, mut peer) = tokio::io::duplex(65536);
        let blocked = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(AtomicWaker::new());
        let session = Session::create(
            Upstream::new_send(
                Gate {
                    inner: wire,
                    blocked: blocked.clone(),
                    waker: waker.clone(),
                },
                None,
            ),
            PASSWORD,
            &pool,
            &tracker,
            stop.clone(),
            WAIT,
        )
        .await
        .unwrap();
        let first = session.open(address(&target(443)).unwrap()).await.unwrap();
        opening(&mut peer, true, 1, 443).await;
        let mut second = session.open(address(&target(8443)).unwrap()).await.unwrap();
        opening(&mut peer, false, 2, 8443).await;
        blocked.store(true, Ordering::Release);
        second.write_all(b"inflight").await.unwrap();
        timeout(WAIT, async {
            while session.tx.capacity() != WRITE_QUEUE {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for _ in 0..WRITE_QUEUE {
            second.write_all(b"queued").await.unwrap();
        }
        assert_eq!(session.tx.capacity(), 0);
        peer.write_all(
            &frame(
                if refusal {
                    COMMAND_SYNACK
                } else {
                    COMMAND_HEART_REQUEST
                },
                if refusal { 1 } else { 77 },
                if refusal { b"denied" } else { b"" },
            )
            .unwrap(),
        )
        .await
        .unwrap();
        peer.write_all(&frame(COMMAND_PSH, 2, b"alive").unwrap())
            .await
            .unwrap();
        let mut data = [0; 5];
        assert!(
            timeout(Duration::from_millis(10), second.read_exact(&mut data))
                .await
                .is_err(),
            "控制帧应背压等队列，而不是中止第二ID"
        );
        assert!(!session.cancel.is_cancelled(), "暂满不能升级为会话故障");
        blocked.store(false, Ordering::Release);
        waker.wake();
        timeout(WAIT, second.read_exact(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data, b"alive");
        assert_eq!(
            packet(&mut peer).await,
            (COMMAND_PSH, 2, b"inflight".to_vec())
        );
        for _ in 0..WRITE_QUEUE {
            assert_eq!(
                packet(&mut peer).await,
                (COMMAND_PSH, 2, b"queued".to_vec())
            );
        }
        assert_eq!(
            packet(&mut peer).await,
            if refusal {
                (COMMAND_FIN, 1, Vec::new())
            } else {
                (COMMAND_HEART_RESPONSE, 77, Vec::new())
            }
        );
        assert!(!session.cancel.is_cancelled());
        drop(first);
        drop(second);
        finish(&tracker, &stop).await;
    }
}

#[tokio::test]
async fn cancelled_initial_open_closes_half_written_frame_and_leaves_no_detached_tasks() {
    let pool = pool(AnyTlsClientOptions::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let (wire, mut peer) = tokio::io::duplex(64);
    assert!(
        timeout(
            Duration::from_millis(10),
            pool.connect(
                PASSWORD,
                &target(443),
                tracker.clone(),
                stop.clone(),
                WAIT,
                || async { Ok(Upstream::new_send(wire, None)) }
            )
        )
        .await
        .is_err()
    );
    let mut bytes = Vec::new();
    timeout(WAIT, peer.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(!bytes.is_empty());
    timeout(WAIT, async {
        while !tracker.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(pool.take().is_none());
    finish(&tracker, &stop).await;
}
