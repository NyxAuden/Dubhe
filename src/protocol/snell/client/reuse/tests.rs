use super::*;
use crate::config::{Config, Secret};
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
const WAIT: Duration = Duration::from_secs(3);

fn options(version: u8, mode: Option<&str>) -> SnellClientOptions {
    SnellClientOptions {
        psk: Secret("test-snell-reuse-psk".into()),
        version,
        userkey: Some(Secret("test-key".into())),
        mode: mode.map(str::to_owned),
        obfs_mode: None,
        obfs_host: None,
        obfs_uri: None,
        reuse: true,
    }
}
fn target(port: u16) -> Target {
    SocketAddr::from(([127, 0, 0, 1], port)).into()
}
async fn open(
    pool: &Arc<Pool>,
    options: &SnellClientOptions,
    tracker: &TaskTracker,
    stop: &CancellationToken,
    wire: DuplexStream,
) -> Upstream {
    pool.connect(
        options,
        &target(443),
        tracker.clone(),
        stop.clone(),
        || async move { Ok(Upstream::new_send(wire, None)) },
    )
    .await
    .unwrap()
}
async fn wait_ready(pool: &Pool, count: usize) {
    timeout(WAIT, async {
        loop {
            if pool.ready.lock().unwrap().len() == count {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn stop_tasks(tracker: &TaskTracker, stop: &CancellationToken) {
    stop.cancel();
    tracker.close();
    timeout(WAIT, tracker.wait()).await.unwrap();
}
async fn raw_record(wire: &mut DuplexStream) -> Option<Vec<u8>> {
    let mut header = [0; 7];
    timeout(WAIT, wire.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&header[..5], &[4, 0, 0, 0, 0]);
    let length = u16::from_be_bytes([header[5], header[6]]) as usize;
    if length == 0 {
        return None;
    }
    let mut bytes = vec![0; length];
    wire.read_exact(&mut bytes).await.unwrap();
    Some(bytes)
}
async fn raw_write(wire: &mut DuplexStream, payload: &[u8]) {
    let mut bytes = vec![4, 0, 0, 0, 0];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    wire.write_all(&bytes).await.unwrap();
}

#[test]
fn reuse_is_default_false_strict_boolean_and_pools_are_per_outbound() {
    let value = serde_json::json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"snell","tag":"first","endpoint":"127.0.0.1:1234","snell":{"psk":"test-snell-reuse-psk","version":6}},
        {"type":"snell","tag":"second","endpoint":"127.0.0.1:1234","snell":{"psk":"test-snell-reuse-psk","version":6,"reuse":true}}],"route":{"default":"second"}});
    let example = Config::from_json(include_str!(
        "../../../../../examples/snell-reuse-outbound.json"
    ))
    .unwrap();
    assert!(example.outbounds[0].snell.as_ref().unwrap().reuse);
    Config::from_json(&serde_json::to_string(&example).unwrap()).unwrap();
    let config = Config::from_json(&value.to_string()).unwrap();
    assert!(!config.outbounds[0].snell.as_ref().unwrap().reuse);
    let router = crate::route::Router::new(&config).unwrap();
    assert!(router.proxy_by_tag("first").unwrap().snell_pool.is_none());
    let second = router.proxy_by_tag("second").unwrap();
    let other = crate::route::Router::new(&config)
        .unwrap()
        .proxy_by_tag("second")
        .unwrap();
    assert!(!Arc::ptr_eq(
        second.snell_pool.as_ref().unwrap(),
        other.snell_pool.as_ref().unwrap()
    ));
    assert!(!format!("{second:?}").contains("test-snell-reuse-psk"));
    for invalid in [
        serde_json::json!("true"),
        serde_json::json!(1),
        serde_json::json!(null),
    ] {
        let mut value = value.clone();
        value["outbounds"][1]["snell"]["reuse"] = invalid;
        assert!(Config::from_json(&value.to_string()).is_err());
    }
}

#[tokio::test]
async fn independent_raw_peer_preserves_target_order_lazy_reply_and_discards_old_data() {
    let pool = Arc::new(Pool::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let options = options(6, Some("unsafe-raw"));
    let (wire, mut peer) = tokio::io::duplex(65536);
    let (resumed, resume) = tokio::sync::oneshot::channel();
    let expected = options.clone();
    let task = tokio::spawn(async move {
        assert_eq!(
            raw_record(&mut peer).await.unwrap(),
            request(&expected, Some(&target(443))).unwrap()
        );
        assert_eq!(raw_record(&mut peer).await.unwrap(), b"first");
        raw_write(&mut peer, b"\0reply").await;
        assert!(raw_record(&mut peer).await.is_none(), "FIN只发送一次");
        raw_write(&mut peer, b"old-response-not-for-next-target").await;
        resume.await.unwrap();
        raw_write(&mut peer, &[]).await;
        assert_eq!(
            raw_record(&mut peer).await.unwrap(),
            request(&expected, Some(&target(8443))).unwrap()
        );
        assert_eq!(raw_record(&mut peer).await.unwrap(), b"second");
        raw_write(&mut peer, b"\0new-reply").await;
        assert!(raw_record(&mut peer).await.is_none());
        raw_write(&mut peer, &[]).await;
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    });
    let mut first = open(&pool, &options, &tracker, &stop, wire).await;
    first.write_all(b"first").await.unwrap();
    let mut reply = [0; 5];
    first.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");
    drop(first);
    tokio::task::yield_now().await;
    assert!(pool.take().is_none(), "未收零块不能把waiting当ready");
    resumed.send(()).unwrap();
    wait_ready(&pool, 1).await;
    let mut second = pool
        .connect(
            &options,
            &target(8443),
            tracker.clone(),
            stop.clone(),
            || async {
                panic!("ready池不能重新拨号");
                #[allow(unreachable_code)]
                Ok::<_, io::Error>(Upstream::new_send(tokio::io::duplex(1).0, None))
            },
        )
        .await
        .unwrap();
    second.write_all(b"second").await.unwrap();
    second.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    let mut reply = Vec::new();
    second.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"new-reply");
    drop(second);
    wait_ready(&pool, 1).await;
    stop_tasks(&tracker, &stop).await;
    timeout(WAIT, task).await.unwrap().unwrap();
}

#[tokio::test]
async fn every_record_mode_and_obfs_keep_single_salt_nonce_and_first_message_across_targets() {
    for (version, mode, obfs) in [
        (4, None, None),
        (5, None, None),
        (6, None, None),
        (6, Some("unshaped"), None),
        (6, Some("unsafe-raw"), None),
        (4, None, Some("http")),
        (4, None, Some("tls")),
        (5, None, Some("http")),
        (5, None, Some("tls")),
    ] {
        let mut options = options(version, mode);
        options.obfs_mode = obfs.map(str::to_owned);
        let selected = options.record_mode();
        let psk = options.psk.0.as_bytes().to_vec();
        let pool = Arc::new(Pool::default());
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let (wire, peer) = tokio::io::duplex(65536);
        let obfs = crate::transport::snell_obfs::Mode::parse(obfs).unwrap();
        let expected = options.clone();
        let task = tokio::spawn(async move {
            let stream = Upstream::new_send(
                crate::transport::snell_obfs::Stream::server(peer, obfs),
                None,
            );
            let (read, write) = tokio::io::split(stream);
            let mut reader = match selected {
                Mode::Shaped | Mode::Unshaped => Reader::Aead(
                    RecordReader::new(read, &psk, selected == Mode::Shaped)
                        .await
                        .unwrap(),
                ),
                Mode::Default => Reader::ShapedV6(ShapedV6Reader::new(read, &psk)),
                Mode::UnsafeRaw => Reader::Raw(RawReader::new(read)),
            };
            let mut direction = TunnelIo::new(write, selected);
            for port in [443, 8443] {
                assert_eq!(
                    reader.read_record().await.unwrap().unwrap(),
                    request(&expected, Some(&target(port))).unwrap()
                );
                assert_eq!(reader.read_record().await.unwrap().unwrap(), b"business");
                assert!(reader.read_record().await.unwrap().is_none());
                let writer = direction.writer(&psk).await.unwrap();
                writer.write_packet(b"\0response").await.unwrap();
                writer.write_zero().await.unwrap();
            }
        });
        let mut client = open(&pool, &options, &tracker, &stop, wire).await;
        for index in 0..2 {
            client.write_all(b"business").await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"response");
            drop(client);
            wait_ready(&pool, 1).await;
            if index == 0 {
                client = pool
                    .connect(
                        &options,
                        &target(8443),
                        tracker.clone(),
                        stop.clone(),
                        || async { Err(io::Error::other("不应重新拨号")) },
                    )
                    .await
                    .unwrap();
            } else {
                break;
            }
        }
        timeout(WAIT, task).await.unwrap().unwrap();
        stop_tasks(&tracker, &stop).await;
    }
}

#[tokio::test]
async fn invalid_reply_and_unread_reply_never_return_to_pool_or_replay() {
    for reply in [
        None,
        Some(b"\x02\x01\x03bad".as_slice()),
        Some(b"\x09invalid".as_slice()),
    ] {
        let pool = Arc::new(Pool::default());
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let options = options(6, Some("unsafe-raw"));
        let (wire, mut peer) = tokio::io::duplex(65536);
        let mut client = open(&pool, &options, &tracker, &stop, wire).await;
        raw_record(&mut peer).await.unwrap();
        if let Some(reply) = reply {
            raw_write(&mut peer, reply).await;
            assert!(client.read(&mut [0; 8]).await.is_err());
        }
        drop(client);
        assert_eq!(
            peer.read(&mut [0; 8]).await.unwrap(),
            0,
            "失败流不追加FIN或业务"
        );
        assert!(pool.take().is_none());
        let opens = AtomicUsize::new(0);
        assert!(
            pool.connect(
                &options,
                &target(443),
                tracker.clone(),
                stop.clone(),
                || async {
                    opens.fetch_add(1, Ordering::Relaxed);
                    Err(io::Error::other("新的受控拨号失败"))
                }
            )
            .await
            .is_err()
        );
        assert_eq!(opens.load(Ordering::Relaxed), 1);
        stop_tasks(&tracker, &stop).await;
    }
}

#[tokio::test]
async fn pending_read_and_buffered_short_write_are_drained_without_repeating_fin() {
    let pool = Arc::new(Pool::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let options = options(6, Some("unsafe-raw"));
    let (wire, mut peer) = tokio::io::duplex(128);
    let blocked = Arc::new(AtomicBool::new(false));
    let inner = super::super::tests::Gate {
        inner: wire,
        blocked: blocked.clone(),
    };
    let mut client = pool
        .connect(
            &options,
            &target(443),
            tracker.clone(),
            stop.clone(),
            || async { Ok(Upstream::new_send(inner, None)) },
        )
        .await
        .unwrap();
    raw_record(&mut peer).await.unwrap();
    raw_write(&mut peer, b"\0ok").await;
    let mut first = [0; 2];
    client.read_exact(&mut first).await.unwrap();
    blocked.store(true, Ordering::Relaxed);
    client.write_all(b"accepted").await.unwrap();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(Pin::new(&mut client).poll_shutdown(&mut cx).is_pending());
    assert!(
        Pin::new(&mut client)
            .poll_read(&mut cx, &mut ReadBuf::new(&mut [0; 1]))
            .is_pending()
    );
    // 阻塞底层write不留活跃等待；Drop回收任务会用新的waker继续，且不接受取消的buffer。
    blocked.store(false, Ordering::Relaxed);
    drop(client);
    assert_eq!(raw_record(&mut peer).await.unwrap(), b"accepted");
    assert!(raw_record(&mut peer).await.is_none());
    raw_write(&mut peer, b"old").await;
    raw_write(&mut peer, &[]).await;
    wait_ready(&pool, 1).await;
    stop_tasks(&tracker, &stop).await;
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn waiting_and_ready_share_ten_slots_and_over_limit_drain_closes() {
    let pool = Arc::new(Pool::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let options = options(6, Some("unsafe-raw"));
    let mut peers = Vec::new();
    for _ in 0..=POOL_SIZE {
        let (wire, mut peer) = tokio::io::duplex(65536);
        let mut client = open(&pool, &options, &tracker, &stop, wire).await;
        raw_record(&mut peer).await.unwrap();
        raw_write(&mut peer, b"\0ok").await;
        client.read_exact(&mut [0; 2]).await.unwrap();
        drop(client);
        peers.push(peer);
    }
    assert_eq!(pool.slots.available_permits(), 0);
    let mut excess = peers.pop().unwrap();
    assert_eq!(excess.read(&mut [0; 1]).await.unwrap(), 0);
    assert!(raw_record(&mut peers[0]).await.is_none());
    raw_write(&mut peers[0], &[]).await;
    wait_ready(&pool, 1).await;
    assert_eq!(pool.slots.available_permits(), 0, "ready仍占额度");
    let mut client = pool
        .connect(
            &options,
            &target(8443),
            tracker.clone(),
            stop.clone(),
            || async { Err(io::Error::other("不能新拨号")) },
        )
        .await
        .unwrap();
    raw_record(&mut peers[0]).await.unwrap();
    assert_eq!(pool.slots.available_permits(), 1, "取出ready即释放池额度");
    raw_write(&mut peers[0], b"\0ok").await;
    client.read_exact(&mut [0; 2]).await.unwrap();
    drop(client);
    assert!(raw_record(&mut peers[0]).await.is_none());
    // 达到0x80001而不是超过后才失败；对端不提供零块。
    for _ in 0..8 {
        raw_write(&mut peers[0], &vec![0x33; 65535]).await;
    }
    raw_write(&mut peers[0], &[0x33; 9]).await;
    assert_eq!(
        timeout(WAIT, peers[0].read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(pool.take().is_none());
    stop_tasks(&tracker, &stop).await;
    assert_eq!(pool.slots.available_permits(), POOL_SIZE);
}

#[tokio::test(start_paused = true)]
async fn waiting_timeout_idle_expiry_and_stop_release_all_tasks_and_sockets() {
    let pool = Arc::new(Pool::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let options = options(6, Some("unsafe-raw"));
    let (wire, mut peer) = tokio::io::duplex(65536);
    let mut client = open(&pool, &options, &tracker, &stop, wire).await;
    raw_record(&mut peer).await.unwrap();
    raw_write(&mut peer, b"\0ok").await;
    client.read_exact(&mut [0; 2]).await.unwrap();
    drop(client);
    assert!(raw_record(&mut peer).await.is_none());
    tokio::time::advance(DRAIN_TIMEOUT + Duration::from_secs(1)).await;
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    assert!(pool.take().is_none());
    let (wire, mut peer) = tokio::io::duplex(65536);
    let mut client = open(&pool, &options, &tracker, &stop, wire).await;
    raw_record(&mut peer).await.unwrap();
    raw_write(&mut peer, b"\0ok").await;
    raw_write(&mut peer, &[]).await;
    let mut result = Vec::new();
    client.read_to_end(&mut result).await.unwrap();
    client.shutdown().await.unwrap();
    drop(client);
    assert!(raw_record(&mut peer).await.is_none());
    wait_ready(&pool, 1).await;
    tokio::time::advance(POOL_MAX_AGE - Duration::from_secs(1)).await;
    assert_eq!(pool.ready.lock().unwrap().len(), 1);
    tokio::time::advance(TIMER_INTERVAL + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(pool.take().is_none());
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    stop_tasks(&tracker, &stop).await;
}

#[tokio::test]
async fn dropping_pool_preserves_live_lease_but_cancels_waiting_and_idle_without_cycles() {
    let pool = Arc::new(Pool::default());
    let weak = Arc::downgrade(&pool);
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let options = options(6, Some("unsafe-raw"));
    let (wire, mut peer) = tokio::io::duplex(65536);
    let mut client = open(&pool, &options, &tracker, &stop, wire).await;
    raw_record(&mut peer).await.unwrap();
    raw_write(&mut peer, b"\0ok").await;
    client.read_exact(&mut [0; 2]).await.unwrap();
    let (wire, mut waiting_peer) = tokio::io::duplex(65536);
    let mut waiting = open(&pool, &options, &tracker, &stop, wire).await;
    raw_record(&mut waiting_peer).await.unwrap();
    raw_write(&mut waiting_peer, b"\0ok").await;
    waiting.read_exact(&mut [0; 2]).await.unwrap();
    drop(waiting);
    assert!(raw_record(&mut waiting_peer).await.is_none());
    drop(pool);
    assert!(weak.upgrade().is_none());
    assert_eq!(waiting_peer.read(&mut [0; 1]).await.unwrap(), 0);
    client.write_all(b"still-live").await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(raw_record(&mut peer).await.unwrap(), b"still-live");
    raw_write(&mut peer, b"after-reload").await;
    let mut bytes = [0; 12];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"after-reload");
    drop(client);
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    tracker.close();
    timeout(WAIT, tracker.wait()).await.unwrap();
}

#[tokio::test]
async fn bad_aead_reply_and_transport_eof_without_zero_never_become_ready() {
    for corrupt in [true, false] {
        let pool = Arc::new(Pool::default());
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let options = options(5, None);
        let psk = options.psk.0.as_bytes().to_vec();
        let (wire, peer) = tokio::io::duplex(65536);
        let mut client = open(&pool, &options, &tracker, &stop, wire).await;
        let (read, write) = tokio::io::split(peer);
        let mut reader = RecordReader::new(read, &psk, true).await.unwrap();
        assert!(reader.read_record().await.unwrap().is_some());
        let mut writer = RecordWriter::new(write, &psk, true).await.unwrap();
        if corrupt {
            writer
                .inner
                .write_all(&[0; HEADER_CIPHER_LEN])
                .await
                .unwrap();
            assert!(client.read(&mut [0; 8]).await.is_err());
        } else {
            writer.write_record(b"\0ok").await.unwrap();
            client.read_exact(&mut [0; 2]).await.unwrap();
        }
        writer.inner.shutdown().await.unwrap(); // 没有正式逻辑零块。
        if !corrupt {
            assert!(client.read(&mut [0; 8]).await.is_err());
        }
        drop(client);
        let mut raw = Vec::new();
        reader.inner.read_to_end(&mut raw).await.unwrap();
        assert!(raw.is_empty(), "失败后不补FIN或重放业务");
        assert!(pool.take().is_none());
        stop_tasks(&tracker, &stop).await;
    }
}

#[tokio::test]
async fn explicit_pool_retirement_closes_ready_and_waiting_but_keeps_live_flow() {
    let pool = Arc::new(Pool::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let options = options(6, Some("unsafe-raw"));
    let (wire, mut peer) = tokio::io::duplex(65536);
    let mut client = open(&pool, &options, &tracker, &stop, wire).await;
    raw_record(&mut peer).await.unwrap();
    raw_write(&mut peer, b"\0ok").await;
    client.read_exact(&mut [0; 2]).await.unwrap();
    let (wire, mut idle_peer) = tokio::io::duplex(65536);
    let mut idle = open(&pool, &options, &tracker, &stop, wire).await;
    raw_record(&mut idle_peer).await.unwrap();
    raw_write(&mut idle_peer, b"\0ok").await;
    raw_write(&mut idle_peer, &[]).await;
    idle.read_to_end(&mut Vec::new()).await.unwrap();
    idle.shutdown().await.unwrap();
    assert!(raw_record(&mut idle_peer).await.is_none());
    drop(idle);
    wait_ready(&pool, 1).await;
    pool.close();
    assert!(pool.take().is_none());
    assert_eq!(idle_peer.read(&mut [0; 1]).await.unwrap(), 0);
    client.write_all(b"after-retire").await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(raw_record(&mut peer).await.unwrap(), b"after-retire");
    assert!(
        pool.connect(
            &options,
            &target(443),
            tracker.clone(),
            stop.clone(),
            || async {
                panic!("旧池停用后不能拨号");
                #[allow(unreachable_code)]
                Err(io::Error::other("不可到达"))
            }
        )
        .await
        .is_err()
    );
    drop(client);
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    tracker.close();
    timeout(WAIT, tracker.wait()).await.unwrap();
}

#[tokio::test]
async fn cancelled_reused_request_destroys_half_written_state_and_returns_no_lease() {
    let pool = Arc::new(Pool::default());
    let tracker = TaskTracker::new();
    let stop = CancellationToken::new();
    let options = options(6, Some("unsafe-raw"));
    let (wire, mut peer) = tokio::io::duplex(64);
    let mut client = open(&pool, &options, &tracker, &stop, wire).await;
    raw_record(&mut peer).await.unwrap();
    raw_write(&mut peer, b"\0ok").await;
    raw_write(&mut peer, &[]).await;
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).await.unwrap();
    client.shutdown().await.unwrap();
    assert!(raw_record(&mut peer).await.is_none());
    drop(client);
    let mut huge = options.clone();
    huge.userkey = Some(Secret("k".repeat(255)));
    assert!(
        timeout(
            Duration::from_millis(10),
            pool.connect(
                &huge,
                &target(8443),
                tracker.clone(),
                stop.clone(),
                || async { Err(io::Error::other("不应拨号")) }
            )
        )
        .await
        .is_err()
    );
    let mut partial = Vec::new();
    peer.read_to_end(&mut partial).await.unwrap();
    assert!(!partial.is_empty());
    assert!(pool.take().is_none());
    assert_eq!(pool.slots.available_permits(), POOL_SIZE);
    stop_tasks(&tracker, &stop).await;
}
