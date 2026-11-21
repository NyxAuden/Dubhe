use super::*;
use crate::{
    protocol::xudp::{self as wire, Frame, Status},
    telemetry::Guard,
};

struct Session {
    association: Association,
    initial: Target,
    generation: u64,
    last_used: Instant,
    _slot: OwnedSemaphorePermit,
    _gauge: Guard,
}

struct Received {
    frame: Frame,
    _budget: Option<OwnedSemaphorePermit>,
}

async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    deadline: Duration,
) -> io::Result<()> {
    timeout(deadline, async {
        writer.write_all(bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP 写入超时"))?
}

async fn close(sessions: &mut HashMap<u16, Session>, id: u16) {
    if let Some(mut session) = sessions.remove(&id) {
        session.association.close().await;
    }
}

async fn relay_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: Packet,
    sessions: &mut HashMap<u16, Session>,
    ctx: &Context,
    idle: Duration,
) -> io::Result<bool> {
    let session = packet.session.and_then(|(id, generation)| {
        sessions
            .get_mut(&id)
            .filter(|s| s.generation == generation)
            .map(|s| (id, s))
    });
    let Some((id, session)) = session else {
        ctx.stats.drop_packet();
        return Ok(false);
    };
    if packet.payload.is_empty() {
        ctx.stats.drop_packet();
        return Ok(false);
    }
    let bytes = wire::datagram(id, &packet.target, &packet.payload)?;
    write(writer, &bytes, idle).await?;
    ctx.stats
        .downlink
        .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
    session.last_used = Instant::now();
    Ok(true)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    ctx: Arc<Context>,
    inbound: String,
) -> io::Result<()> {
    timeout(
        Duration::from_millis(ctx.limits.handshake_timeout_ms),
        vless::reply(&mut stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP 应答超时"))??;
    serve_body(stream, ctx, inbound).await
}

/// 已应答入口供 Vision body 适配使用，不能再将 VLESS 响应包入正文。
pub(crate) async fn serve_body<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
) -> io::Result<()> {
    serve_inner(stream, ctx, inbound, false, None).await
}

/// gRPC等按RPC回收的上层使用；需由本入口发送唯一 VLESS 应答。
pub(crate) async fn serve_scoped<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    ctx: Arc<Context>,
    inbound: String,
    lease: Option<Lease>,
) -> io::Result<()> {
    timeout(
        Duration::from_millis(ctx.limits.handshake_timeout_ms),
        vless::reply(&mut stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP 应答超时"))??;
    serve_inner(stream, ctx, inbound, false, lease).await
}

pub(crate) async fn serve_body_scoped<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
    lease: Option<Lease>,
) -> io::Result<()> {
    serve_inner(stream, ctx, inbound, false, lease).await
}

/// WS 入口先检查首个 UDP New 的目标与准入，再发送唯一 VLESS 应答。
/// 旧 TLS/Vision/VMess 入口不改变既有应答时序。
pub(crate) async fn serve_deferred<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
) -> io::Result<()> {
    serve_inner(stream, ctx, inbound, true, None).await
}

/// gRPC等按RPC回收的上层使用；reader/mapping共享`lease`直到任务结束。
pub(crate) async fn serve_deferred_scoped<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
    lease: Option<Lease>,
) -> io::Result<()> {
    serve_inner(stream, ctx, inbound, true, lease).await
}

async fn serve_inner<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
    mut pending_response: bool,
    lease: Option<Lease>,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel(ctx.limits.udp_queue_packets);
    let (responses, mut replies) = mpsc::channel::<Packet>(ctx.limits.udp_queue_packets);
    let reader_ctx = ctx.clone();
    let reader_lease = lease.clone();
    let mut readers = JoinSet::new();
    // 不在 select 内读半帧；控制帧不能因队列满而丢失或重排。
    readers.spawn(ctx.children.track_future(async move {
        let _lease = reader_lease;
        loop {
            let item =
                match wire::read_optional(&mut reader, reader_ctx.limits.max_udp_payload).await {
                    Ok(None) => break,
                    Ok(Some(mut frame)) => {
                        let budget = if let Some(payload) = &frame.payload {
                            let permit = reader_ctx
                                .udp_bytes
                                .clone()
                                .try_acquire_many_owned(payload.len().max(1) as u32)
                                .ok();
                            if permit.is_none() || payload.is_empty() {
                                reader_ctx.stats.drop_packet();
                                frame.payload = None;
                            }
                            permit
                        } else {
                            None
                        };
                        Ok(Received {
                            frame,
                            _budget: budget,
                        })
                    }
                    Err(error) => Err(error),
                };
            let failed = item.is_err();
            if tx.send(item).await.is_err() || failed {
                break;
            }
        }
    }));
    let mut sessions: HashMap<u16, Session> = HashMap::new();
    let idle = Duration::from_millis(ctx.limits.udp_idle_timeout_ms);
    let dial = Duration::from_millis(ctx.limits.dial_timeout_ms);
    let mut deadline = Instant::now() + idle;
    let mut generation = 0u64;
    let result = async {
        loop {
            // 每会话独立空闲；KeepAlive 不延长会话期限。
            let expired: Vec<_> = sessions.iter()
                .filter(|(_, s)| s.last_used.elapsed() >= idle)
                .map(|(&id, _)| id).collect();
            for id in expired {
                close(&mut sessions, id).await;
                write(&mut writer, &wire::end(id, false), idle).await?;
            }
            if Instant::now() >= deadline { break; }
            let next = sessions.values().map(|s| s.last_used + idle).min()
                .map_or(deadline, |session_deadline| session_deadline.min(deadline));
            tokio::select! {
                _ = tokio::time::sleep_until(next) => {},
                item = rx.recv() => {
                    let Some(item) = item else { break; };
                    let received = item?;
                    let Frame { id, status, target, payload } = received.frame;
                    if pending_response && status != Status::New {
                        return Err(invalid("XUDP 首帧必须为 UDP New"));
                    }
                    match status {
                        Status::End => { close(&mut sessions, id).await; }
                        Status::KeepAlive => {},
                        Status::New | Status::Keep => {
                            if status == Status::New {
                                if sessions.contains_key(&id) { return Err(invalid("重复 XUDP 会话")); }
                                let initial = target.as_ref().ok_or_else(|| invalid("缺少 XUDP 目标"))?;
                                let slot = ctx.udp_slots.clone().try_acquire_owned();
                                let allowed =
                                    ctx.allowed(&inbound, Network::Udp, initial).await;
                                if pending_response {
                                    allowed?;
                                    if slot.is_err() {
                                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "UDP 关联上限"));
                                    }
                                    timeout(Duration::from_millis(ctx.limits.handshake_timeout_ms), vless::reply(&mut writer))
                                        .await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP 应答超时"))??;
                                    pending_response = false;
                                } else if allowed.is_err() || slot.is_err() {
                                    write(&mut writer, &wire::end(id, true), idle).await?;
                                    continue;
                                }
                                generation = generation.checked_add(1).ok_or_else(|| invalid("XUDP 会话代次耗尽"))?;
                                sessions.insert(id, Session {
                                    association: Association::with_replies(ctx.clone(), inbound.clone(), responses.clone(), Some((id, generation)), lease.clone()),
                                    initial: initial.clone(), generation, last_used: Instant::now(),
                                    _slot: slot.expect("已验证名额"), _gauge: ctx.stats.enter(Gauge::Udp),
                                });
                            }
                            let session = sessions.get_mut(&id).ok_or_else(|| invalid("未知 XUDP 会话"))?;
                            if let Some(payload) = payload {
                                let target = target.unwrap_or_else(|| session.initial.clone());
                                if timeout(dial, session.association.send(target, &payload)).await.is_ok_and(|r| r.is_ok()) {
                                    session.last_used = Instant::now();
                                } else {
                                    ctx.stats.drop_packet();
                                    close(&mut sessions, id).await;
                                    write(&mut writer, &wire::end(id, true), idle).await?;
                                }
                            }
                        }
                    }
                    deadline = Instant::now() + idle;
                }
                Some(packet) = replies.recv() => {
                    if relay_reply(&mut writer, packet, &mut sessions, &ctx, idle).await? {
                        deadline = Instant::now() + idle;
                    }
                }
            }
        }
        Ok(())
    }.await;
    readers.abort_all();
    while readers.join_next().await.is_some() {}
    for (_, mut session) in sessions.drain() {
        session.association.close().await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, protocol::test_io::Wire};

    fn context() -> Arc<Context> {
        let config = Config::from_json(
            &serde_json::json!({
                "version":1,"inbounds":[{"type":"socks5","tag":"test","listen":"127.0.0.1:0"}],
                "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},
                "limits":{"udp_queue_bytes":4,"udp_queue_packets":1}
            })
            .to_string(),
        )
        .unwrap();
        Arc::new(Context::new(&config).unwrap())
    }

    #[tokio::test]
    async fn queued_old_generation_cannot_reach_reused_session() {
        let ctx = context();
        let target: Target = "127.0.0.1:53".parse::<SocketAddr>().unwrap().into();
        let mut old = Packet::reserve(&ctx, target.clone(), b"old".to_vec()).unwrap();
        old.session = Some((7, 1));
        let (tx, _rx) = mpsc::channel(1);
        let mut sessions = HashMap::from([(
            7,
            Session {
                association: Association::with_replies(
                    ctx.clone(),
                    "test".into(),
                    tx,
                    Some((7, 2)),
                    None,
                ),
                initial: target.clone(),
                generation: 2,
                last_used: Instant::now(),
                _slot: ctx.udp_slots.clone().try_acquire_owned().unwrap(),
                _gauge: ctx.stats.enter(Gauge::Udp),
            },
        )]);
        let mut writer = Wire::new(vec![]);
        assert!(
            !relay_reply(
                &mut writer,
                old,
                &mut sessions,
                &ctx,
                Duration::from_secs(1)
            )
            .await
            .unwrap()
        );
        assert!(writer.output.is_empty());
        assert_eq!(ctx.stats.snapshot().downlink, 0);
        assert_eq!(ctx.udp_bytes.available_permits(), 4);
        let mut fresh = Packet::reserve(&ctx, target, b"new".to_vec()).unwrap();
        fresh.session = Some((7, 2));
        assert!(
            relay_reply(
                &mut writer,
                fresh,
                &mut sessions,
                &ctx,
                Duration::from_secs(1)
            )
            .await
            .unwrap()
        );
        assert_eq!(&writer.output[writer.output.len() - 3..], b"new");
        assert_eq!(ctx.stats.snapshot().downlink, 3);
        close(&mut sessions, 7).await;
        assert_eq!(
            ctx.udp_slots.available_permits(),
            ctx.limits.max_udp_associations
        );
    }

    #[tokio::test]
    async fn exhausted_byte_budget_keeps_end_and_returns_all_resources() {
        let ctx = context();
        let held = ctx.udp_bytes.clone().try_acquire_many_owned(4).unwrap();
        let (server, mut client) = tokio::io::duplex(256);
        let task = tokio::spawn(serve(server, ctx.clone(), "test".into()));
        let mut reply = [0xff; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0, 0]);
        // New 的业务数据因预算不足丢弃；控制仍创建会话并接受 End。
        client
            .write_all(b"\x00\x0c\x00\x01\x01\x01\x02\x00\x35\x01\x7f\x00\x00\x01\x00\x01x")
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while ctx.stats.snapshot().udp_associations != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(ctx.stats.snapshot().uplink, 0);
        assert_eq!(ctx.stats.snapshot().dropped, 1);
        client.write_all(b"\x00\x04\x00\x01\x03\x00").await.unwrap();
        timeout(Duration::from_secs(1), async {
            while ctx.stats.snapshot().udp_associations != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(held);
        client.shutdown().await.unwrap();
        // End 后恰在帧边界结束是正常关闭；半长度/半帧仍由 read_optional 拒绝。
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        ctx.children.close();
        ctx.children.wait().await;
        assert_eq!(ctx.udp_bytes.available_permits(), 4);
        assert_eq!(
            ctx.udp_slots.available_permits(),
            ctx.limits.max_udp_associations
        );
    }
}
