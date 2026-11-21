//! UDP生命周期与预算测试，不把同源codec单元测试当作独立wire证据。
use super::*;
use crate::{config::Config, protocol::shadowsocks::replay::ReplayPool};
use ::shadowsocks::{
    config::ServerConfig, crypto::CipherKind, relay::udprelay::crypto_io::encrypt_client_payload,
};
use base64::{Engine, engine::general_purpose::STANDARD};

fn dispatcher() -> (
    Dispatcher,
    mpsc::Receiver<Packet>,
    mpsc::Receiver<ModernReply>,
) {
    let config = Config::from_json(&serde_json::json!({
        "version":1, "inbounds":[{"type":"shadowsocks", "tag":"ss", "listen":"127.0.0.1:0", "method":"2022-blake3-aes-128-gcm", "password":STANDARD.encode([0x11;16])}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},
        "limits":{"max_udp_associations":1,"udp_idle_timeout_ms":1,"udp_queue_bytes":4096,"udp_queue_packets":1}
    }).to_string()).unwrap();
    let ctx = Arc::new(Context::new(&config).unwrap());
    let (legacy_tx, legacy_rx) = mpsc::channel(1);
    let (modern_tx, modern_rx) = mpsc::channel(1);
    let prepared = Arc::new(Prepared {
        keys: crate::config::ShadowsocksKeys {
            method: CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            key: vec![0x11; 16],
            users: None,
        },
        inbound: 0,
        replay: Arc::new(ReplayPool::new(8)),
    });
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    (
        Dispatcher {
            ctx,
            prepared,
            tag: "ss".into(),
            socket: Arc::new(UdpSocket::from_std(socket.into()).unwrap()),
            crypto: CryptoContext::new(ServerType::Server),
            legacy: HashMap::new(),
            modern: HashMap::new(),
            legacy_tx,
            modern_tx,
            readers: JoinSet::new(),
            generation: 0,
        },
        legacy_rx,
        modern_rx,
    )
}

fn packet(
    dispatcher: &Dispatcher,
    destination: SocketAddr,
    sequence: u64,
    source: SocketAddr,
) -> EncryptedPacket {
    let client = ServerConfig::new(
        "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
        STANDARD.encode([0x11; 16]),
        dispatcher.prepared.keys.method,
    )
    .unwrap();
    let mut control = UdpSocketControlData::default();
    control.client_session_id = 7;
    control.packet_id = sequence;
    encode_packet(
        dispatcher,
        client.key(),
        &Address::SocketAddress(destination),
        &control,
        None,
        source,
    )
}

fn encode_packet(
    dispatcher: &Dispatcher,
    key: &[u8],
    address: &Address,
    control: &UdpSocketControlData,
    identity: Option<&[u8]>,
    source: SocketAddr,
) -> EncryptedPacket {
    // 让公共参数的目标类型推导库内Bytes，不为生命周期测试增加直接依赖。
    let identities: Vec<_> = identity
        .into_iter()
        .map(|key| key.to_vec().into())
        .collect();
    let mut wire = Default::default();
    encrypt_client_payload(
        &CryptoContext::new(ServerType::Local),
        dispatcher.prepared.keys.method,
        key,
        address,
        control,
        &identities,
        b"one",
        &mut wire,
    );
    EncryptedPacket {
        source,
        _budget: dispatcher
            .ctx
            .udp_bytes
            .clone()
            .try_acquire_many_owned(wire.len() as u32)
            .unwrap(),
        wire: wire.to_vec(),
    }
}

#[tokio::test(start_paused = true)]
async fn counter_exhaustion_keeps_tombstone_and_slot_for_at_least_sixty_seconds() {
    let (mut dispatcher, legacy_rx, modern_rx) = dispatcher();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap();
    let source: SocketAddr = "127.0.0.1:23456".parse().unwrap();
    dispatcher
        .process(packet(&dispatcher, destination, 1, source), true)
        .await
        .unwrap();
    assert_eq!(dispatcher.ctx.udp_slots.available_permits(), 0);
    let key = SessionKey {
        identity: 0,
        client: 7,
    };
    let server_id = dispatcher.modern[&key].server;
    let generation = dispatcher.modern[&key].generation;
    // 私有测试计数器初始化，生产不暴露设置接口。
    dispatcher.modern.get_mut(&key).unwrap().counter = SendCounter::exhausted_for_test();
    let reply = ModernReply {
        session: key,
        generation,
        target: destination,
        payload: b"blocked".to_vec(),
        _budget: dispatcher
            .ctx
            .udp_bytes
            .clone()
            .try_acquire_many_owned(7)
            .unwrap(),
    };
    assert!(dispatcher.modern_reply(reply).await.is_err());
    assert!(dispatcher.modern[&key].transport.is_none());
    assert!(
        dispatcher
            .process(packet(&dispatcher, destination, 2, source), true)
            .await
            .is_err()
    );
    assert_eq!(dispatcher.modern[&key].server, server_id);
    tokio::time::advance(Duration::from_secs(59)).await;
    dispatcher.expire().await;
    assert_eq!(dispatcher.modern.len(), 1);
    assert_eq!(dispatcher.ctx.udp_slots.available_permits(), 0);
    tokio::time::advance(Duration::from_secs(1)).await;
    dispatcher.expire().await;
    assert!(dispatcher.modern.is_empty());
    assert_eq!(dispatcher.ctx.udp_slots.available_permits(), 1);
    dispatcher.close().await;
    drop(legacy_rx);
    drop(modern_rx);
    assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
}

#[tokio::test]
async fn no_new_sessions_after_stop_and_old_generation_cannot_return_payload() {
    let (mut dispatcher, legacy_rx, modern_rx) = dispatcher();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap();
    let source = "127.0.0.1:23456".parse().unwrap();
    assert!(
        dispatcher
            .process(packet(&dispatcher, destination, 1, source), false)
            .await
            .is_err()
    );
    assert!(dispatcher.modern.is_empty());
    dispatcher
        .process(packet(&dispatcher, destination, 1, source), true)
        .await
        .unwrap();
    // stop只禁止新会话，已有会话仍可在统一排空期限内处理新认证报文。
    dispatcher
        .process(packet(&dispatcher, destination, 2, source), false)
        .await
        .unwrap();
    let key = SessionKey {
        identity: 0,
        client: 7,
    };
    let generation = dispatcher.modern[&key].generation;
    let reply = ModernReply {
        session: key,
        generation: generation + 1,
        target: destination,
        payload: b"old".to_vec(),
        _budget: dispatcher
            .ctx
            .udp_bytes
            .clone()
            .try_acquire_many_owned(3)
            .unwrap(),
    };
    assert!(dispatcher.modern_reply(reply).await.is_err());
    dispatcher.close().await;
    drop(legacy_rx);
    drop(modern_rx);
    assert_eq!(dispatcher.ctx.udp_slots.available_permits(), 1);
    assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
    assert_eq!(dispatcher.ctx.stats.snapshot().udp_associations, 0);
}

#[tokio::test(start_paused = true)]
async fn finished_reader_keeps_window_and_capacity_until_protection_expires() {
    let (mut dispatcher, legacy_rx, modern_rx) = dispatcher();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap();
    let source = "127.0.0.1:23456".parse().unwrap();
    dispatcher
        .process(packet(&dispatcher, destination, 8192, source), true)
        .await
        .unwrap();
    let key = SessionKey {
        identity: 0,
        client: 7,
    };
    let session = &dispatcher.modern[&key];
    let generation = session.generation;
    session.transport.as_ref().unwrap().task.abort();
    dispatcher.readers.join_next().await.unwrap().unwrap_err();
    assert!(
        dispatcher
            .process(packet(&dispatcher, destination, 8193, source), true)
            .await
            .is_err()
    );
    assert_eq!(dispatcher.modern[&key].generation, generation);
    assert_eq!(dispatcher.ctx.udp_slots.available_permits(), 0);
    let mut other = UdpSocketControlData::default();
    other.client_session_id = 8;
    other.packet_id = 1;
    assert!(
        dispatcher
            .process(
                encode_packet(
                    &dispatcher,
                    &[0x11; 16],
                    &Address::SocketAddress(destination),
                    &other,
                    None,
                    source
                ),
                true
            )
            .await
            .is_err()
    );
    assert_eq!(dispatcher.modern.len(), 1);
    tokio::time::advance(Duration::from_secs(59)).await;
    dispatcher.expire().await;
    assert_eq!(dispatcher.modern.len(), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    dispatcher.expire().await;
    assert_eq!(dispatcher.ctx.udp_slots.available_permits(), 1);
    dispatcher
        .process(packet(&dispatcher, destination, 8193, source), true)
        .await
        .unwrap();
    assert_ne!(dispatcher.modern[&key].generation, generation);
    dispatcher.close().await;
    drop((legacy_rx, modern_rx));
    assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
}

#[tokio::test]
async fn authenticated_invalid_semantics_do_not_move_endpoint_or_window() {
    timeout(Duration::from_secs(3), async {
        let (mut dispatcher, legacy_rx, modern_rx) = dispatcher();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let source = "127.0.0.1:23456".parse().unwrap();
        let moved = "127.0.0.1:34567".parse().unwrap();
        dispatcher
            .process(packet(&dispatcher, destination, 1, source), true)
            .await
            .unwrap();
        let mut buffer = [0; 64];
        target.recv_from(&mut buffer).await.unwrap();
        let key = SessionKey {
            identity: 0,
            client: 7,
        };
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 7;
        control.packet_id = 10000;
        // 完整认证但地址语义非法；不能推进到10000或迁移回程。
        assert!(
            dispatcher
                .process(
                    encode_packet(
                        &dispatcher,
                        &[0x11; 16],
                        &Address::SocketAddress("127.0.0.1:0".parse().unwrap()),
                        &control,
                        None,
                        moved
                    ),
                    true
                )
                .await
                .is_err()
        );
        assert_eq!(dispatcher.modern[&key].endpoint, source);
        dispatcher
            .process(packet(&dispatcher, destination, 2, source), true)
            .await
            .unwrap();
        target.recv_from(&mut buffer).await.unwrap(); // 若窗口被无效10000推进，2已在窗口外。
        dispatcher
            .process(packet(&dispatcher, destination, 10000, moved), true)
            .await
            .unwrap();
        target.recv_from(&mut buffer).await.unwrap();
        assert_eq!(dispatcher.modern[&key].endpoint, moved);
        assert!(
            dispatcher
                .process(packet(&dispatcher, destination, 10000, source), true)
                .await
                .is_err()
        );
        assert_eq!(dispatcher.modern[&key].endpoint, moved);
        assert_eq!(dispatcher.modern.len(), 1);
        dispatcher.close().await;
        drop((legacy_rx, modern_rx));
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn eih_same_sid_uses_independent_sockets_and_queued_reply_follows_latest_endpoint() {
    use ::shadowsocks::{
        config::{ServerUser, ServerUserManager},
        relay::udprelay::crypto_io::decrypt_server_payload,
    };
    timeout(Duration::from_secs(3), async {
        let (mut dispatcher, legacy_rx, mut modern_rx) = dispatcher();
        let ctx = Arc::get_mut(&mut dispatcher.ctx).unwrap();
        ctx.limits.max_udp_associations = 2;
        ctx.udp_slots = Arc::new(tokio::sync::Semaphore::new(2));
        let mut users = ServerUserManager::new();
        for byte in [0x22, 0x33] {
            users.add_user(ServerUser::new(format!("user-{byte}"), vec![byte; 16]));
        }
        Arc::get_mut(&mut dispatcher.prepared).unwrap().keys.users = Some(Arc::new(users));
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let moved = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 7;
        control.packet_id = 1;
        let mut peers = Vec::new();
        let mut buffer = [0; 4096];
        for (byte, client) in [(0x22, &first), (0x33, &second)] {
            let packet = encode_packet(
                &dispatcher,
                &[byte; 16],
                &Address::SocketAddress(destination),
                &control,
                Some(&[0x11; 16]),
                client.local_addr().unwrap(),
            );
            dispatcher.process(packet, true).await.unwrap();
            let (_, peer) = target.recv_from(&mut buffer).await.unwrap();
            peers.push(peer);
        }
        assert_ne!(peers[0].port(), peers[1].port());
        assert_eq!(dispatcher.modern.len(), 2);
        target.send_to(b"queued", peers[0]).await.unwrap();
        let queued = modern_rx.recv().await.unwrap();
        // 回程已排队后再迁移，ModernReply不可固化旧客户端端点。
        control.packet_id = 2;
        dispatcher
            .process(
                encode_packet(
                    &dispatcher,
                    &[0x22; 16],
                    &Address::SocketAddress(destination),
                    &control,
                    Some(&[0x11; 16]),
                    moved.local_addr().unwrap(),
                ),
                true,
            )
            .await
            .unwrap();
        let (_, peer) = target.recv_from(&mut buffer).await.unwrap();
        assert_eq!(peer, peers[0]);
        dispatcher.modern_reply(queued).await.unwrap();
        let (length, _) = moved.recv_from(&mut buffer).await.unwrap();
        let (length, address, control) = decrypt_server_payload(
            &CryptoContext::new(ServerType::Local),
            dispatcher.prepared.keys.method,
            &[0x22; 16],
            &mut buffer[..length],
        )
        .unwrap();
        assert_eq!(address, Address::SocketAddress(destination));
        assert_eq!(&buffer[..length], b"queued");
        assert_eq!(control.unwrap().client_session_id, 7);
        assert!(
            timeout(Duration::from_millis(20), first.recv_from(&mut buffer))
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(20), second.recv_from(&mut buffer))
                .await
                .is_err()
        );
        dispatcher.close().await;
        drop((legacy_rx, modern_rx));
        assert_eq!(dispatcher.ctx.udp_slots.available_permits(), 2);
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
        for peer in peers {
            let _rebound = UdpSocket::bind(peer).await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn target_cap_and_reject_before_dns_keep_existing_destination_usable() {
    use crate::{dns::Dns, route::Router};
    use hickory_resolver::config::ResolverOpts;
    timeout(Duration::from_secs(3), async {
        let (mut dispatcher, legacy_rx, modern_rx) = dispatcher();
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let route = Config::from_json(r#"{"version":1,"inbounds":[{"type":"socks5","tag":"ss","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],"route":{"default":"direct","rules":[{"domains":["never-query.invalid"],"outbound":"reject"}]}}"#).unwrap();
        let ctx = Arc::get_mut(&mut dispatcher.ctx).unwrap();
        ctx.limits.max_udp_targets = 1;
        ctx.router = Router::new(&route).unwrap();
        ctx.dns = Dns::new(
            crate::dns::udp_resolver(dns.local_addr().unwrap(), ResolverOpts::default()).unwrap(),
            1,
            Duration::from_millis(100),
        );
        let source = "127.0.0.1:23456".parse().unwrap();
        let one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 7;
        control.packet_id = 10000;
        assert_eq!(dispatcher.process(encode_packet(&dispatcher, &[0x11;16], &Address::DomainNameAddress("never-query.invalid".into(), 53), &control, None, source), true).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(dispatcher.modern.is_empty());
        let mut buffer = [0;128];
        assert!(timeout(Duration::from_millis(20), dns.recv_from(&mut buffer)).await.is_err());
        dispatcher.process(packet(&dispatcher, one.local_addr().unwrap(), 1, source), true).await.unwrap();
        one.recv_from(&mut buffer).await.unwrap();
        assert_eq!(dispatcher.process(packet(&dispatcher, two.local_addr().unwrap(), 2, source), true).await.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(timeout(Duration::from_millis(20), two.recv_from(&mut buffer)).await.is_err());
        dispatcher.process(packet(&dispatcher, one.local_addr().unwrap(), 3, source), true).await.unwrap();
        one.recv_from(&mut buffer).await.unwrap();
        assert_eq!(dispatcher.ctx.stats.snapshot().uplink, 6);
        let session = dispatcher.modern.values().next().unwrap();
        assert_eq!(session.transport.as_ref().unwrap().allowed.lock().unwrap().len(), 1);
        dispatcher.close().await;
        drop((legacy_rx, modern_rx));
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
    }).await.unwrap();
}

#[tokio::test]
async fn failed_client_socket_send_does_not_count_plaintext_or_reuse_packet_id() {
    timeout(Duration::from_secs(3), async {
        let (mut dispatcher, legacy_rx, modern_rx) = dispatcher();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        dispatcher
            .process(
                packet(
                    &dispatcher,
                    destination,
                    1,
                    "127.0.0.1:23456".parse().unwrap(),
                ),
                true,
            )
            .await
            .unwrap();
        let key = SessionKey {
            identity: 0,
            client: 7,
        };
        // 入站socket固定为IPv4，故回程发到本机IPv6地址在OS层确定失败，无外部网络。
        dispatcher.modern.get_mut(&key).unwrap().endpoint = "[::1]:23456".parse().unwrap();
        let generation = dispatcher.modern[&key].generation;
        let reply = ModernReply {
            session: key,
            generation,
            target: destination,
            payload: b"not-sent".to_vec(),
            _budget: dispatcher
                .ctx
                .udp_bytes
                .clone()
                .try_acquire_many_owned(8)
                .unwrap(),
        };
        assert!(dispatcher.modern_reply(reply).await.is_err());
        assert_eq!(dispatcher.ctx.stats.snapshot().uplink, 3);
        assert_eq!(dispatcher.ctx.stats.snapshot().downlink, 0);
        assert_eq!(
            dispatcher.modern.get_mut(&key).unwrap().counter.next(),
            Some(1)
        );
        dispatcher.close().await;
        drop((legacy_rx, modern_rx));
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
    })
    .await
    .unwrap();
}

#[test]
fn legacy_reply_salt_collision_has_eight_attempt_limit_and_capacity_is_fail_closed() {
    let prepared = Prepared {
        keys: crate::config::ShadowsocksKeys {
            method: CipherKind::AES_128_GCM,
            key: vec![0x11; 16],
            users: None,
        },
        inbound: 0,
        replay: Arc::new(ReplayPool::new(2)),
    };
    let domain = Domain {
        inbound: 0,
        identity: 0,
    };
    prepared
        .replay
        .admit(domain, &[1; 16], Window::Aead2017)
        .unwrap();
    let mut calls = 0;
    assert!(
        admitted_legacy_reply(&prepared, || {
            calls += 1;
            vec![1; 32]
        })
        .is_err()
    );
    assert_eq!(calls, 8);
    calls = 0;
    let wire = admitted_legacy_reply(&prepared, || {
        calls += 1;
        vec![if calls == 1 { 1 } else { 2 }; 32]
    })
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(wire, [2; 32]);
    calls = 0;
    assert_eq!(
        admitted_legacy_reply(&prepared, || {
            calls += 1;
            vec![3; 32]
        })
        .unwrap_err()
        .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(calls, 1); // 池满不是随机salt碰撞，立即拒绝，不做无意义重试。
}

#[tokio::test]
async fn legacy_full_replay_pool_cannot_emit_unregistered_reply_or_count_downlink() {
    timeout(Duration::from_secs(3), async {
        let (mut dispatcher, mut legacy_rx, modern_rx) = dispatcher();
        let prepared = Arc::get_mut(&mut dispatcher.prepared).unwrap();
        prepared.keys.method = CipherKind::AES_128_GCM;
        prepared.replay = Arc::new(ReplayPool::new(1));
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = client.local_addr().unwrap();
        let destination = target.local_addr().unwrap();
        dispatcher
            .process(
                encode_packet(
                    &dispatcher,
                    &[0x11; 16],
                    &Address::SocketAddress(destination),
                    &UdpSocketControlData::default(),
                    None,
                    source,
                ),
                true,
            )
            .await
            .unwrap();
        let mut buffer = [0; 128];
        let (_, peer) = target.recv_from(&mut buffer).await.unwrap();
        target.send_to(b"reply", peer).await.unwrap();
        let reply = legacy_rx.recv().await.unwrap();
        assert_eq!(
            dispatcher.legacy_reply(reply).await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            timeout(Duration::from_millis(20), client.recv_from(&mut buffer))
                .await
                .is_err()
        );
        assert_eq!(dispatcher.ctx.stats.snapshot().uplink, 3);
        assert_eq!(dispatcher.ctx.stats.snapshot().downlink, 0);
        dispatcher.close().await;
        drop((legacy_rx, modern_rx));
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
        let _rebound = UdpSocket::bind(peer).await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn receiver_enforces_ciphertext_limit_on_ipv6_before_queueing() {
    timeout(Duration::from_secs(3), async {
        let (mut dispatcher, legacy_rx, modern_rx) = dispatcher();
        let ctx = Arc::get_mut(&mut dispatcher.ctx).unwrap();
        ctx.limits.udp_queue_bytes = 131072;
        ctx.udp_bytes = Arc::new(tokio::sync::Semaphore::new(131072));
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        prepare_buffers(&socket).unwrap();
        let address = socket.local_addr().unwrap();
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        prepare_buffers(&client).unwrap();
        // 本测试特意发送超过内核保守上限的一包，测试端缓冲需覆盖它。
        socket2::SockRef::from(&client)
            .set_send_buffer_size(131072)
            .unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let done = CancellationToken::new();
        let mut tasks = JoinSet::new();
        tasks.spawn(receiver(
            Arc::new(socket),
            dispatcher.ctx.clone(),
            tx,
            done.clone(),
        ));
        client.send_to(&vec![7; 65508], address).await.unwrap();
        while dispatcher.ctx.stats.snapshot().dropped == 0 {
            tokio::task::yield_now().await;
        }
        assert!(rx.is_empty());
        client.send_to(&vec![8; 65507], address).await.unwrap();
        let packet = rx.recv().await.unwrap();
        assert_eq!(packet.wire.len(), 65507);
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 131072 - 65507);
        drop(packet);
        done.cancel();
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        drop((rx, legacy_rx, modern_rx));
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 131072);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn recvmsg_reports_truncation_instead_of_accepting_prefix() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&[7; 128], socket.local_addr().unwrap())
        .await
        .unwrap();
    let mut buffer = [0; 16];
    let (length, truncated, source) =
        timeout(Duration::from_secs(1), receive(&socket, &mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert!(truncated);
    assert_eq!(length, 16);
    assert_eq!(source, sender.local_addr().unwrap());
}

#[tokio::test]
async fn receiver_drops_when_shared_byte_budget_is_exhausted_and_recovers() {
    timeout(Duration::from_secs(3), async {
        let (dispatcher, legacy_rx, modern_rx) = dispatcher();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let done = CancellationToken::new();
        let mut tasks = JoinSet::new();
        tasks.spawn(receiver(
            Arc::new(socket),
            dispatcher.ctx.clone(),
            tx,
            done.clone(),
        ));
        // 模拟其他入口队列持有同一个全局预算，而非只触发本入口packet容量。
        let held = dispatcher
            .ctx
            .udp_bytes
            .clone()
            .try_acquire_many_owned(4096)
            .unwrap();
        client.send_to(&[7; 64], address).await.unwrap();
        while dispatcher.ctx.stats.snapshot().dropped == 0 {
            tokio::task::yield_now().await;
        }
        assert!(rx.is_empty());
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 0);
        drop(held);
        client.send_to(&[8; 64], address).await.unwrap();
        let packet = rx.recv().await.unwrap();
        assert_eq!(packet.wire, [8; 64]);
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096 - 64);
        drop(packet);
        done.cancel();
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        drop((rx, legacy_rx, modern_rx));
        assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
        let _rebound = UdpSocket::bind(address).await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ciphertext_queue_and_byte_budget_are_bounded_and_returned_on_cancel() {
    let (dispatcher, legacy_rx, modern_rx) = dispatcher();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (tx, rx) = mpsc::channel(1);
    let done = CancellationToken::new();
    let mut readers = JoinSet::new();
    readers.spawn(receiver(
        Arc::new(socket),
        dispatcher.ctx.clone(),
        tx,
        done.clone(),
    ));
    for _ in 0..8 {
        sender.send_to(&[7; 1024], address).await.unwrap();
    }
    timeout(Duration::from_secs(1), async {
        while dispatcher.ctx.stats.snapshot().dropped < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(rx.len(), 1);
    assert!(dispatcher.ctx.udp_bytes.available_permits() >= 2048);
    done.cancel();
    while let Some(result) = readers.join_next().await {
        result.unwrap().unwrap();
    }
    drop(rx);
    drop(legacy_rx);
    drop(modern_rx);
    assert_eq!(dispatcher.ctx.udp_bytes.available_permits(), 4096);
    let _rebound = UdpSocket::bind(address).await.unwrap();
}
