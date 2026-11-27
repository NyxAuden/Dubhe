//! dokodemo-door 入站：裸 TCP/UDP 字节直接转发到一个固定目标。
//!
//! 目标仍经过本内核的路由与出站选择；没有协议认证层，因此必须由监听
//! 地址和网络边界保证访问控制。UDP 按客户端源地址维护独立关联：每个
//! 关联一个上游套接字或一个 SOCKS5 UDP 中继，受
//! `limits.max_udp_associations`、`udp_queue_packets` 与空闲回收约束。
//! 路由到链式出站或 HTTP 上游时 UDP 失败关闭（不产生目标流量）。

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, mpsc},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Inbound, SniffKind},
    forward::{Context, UdpRelay, dial_udp_relay},
    route::ProxyOutbound,
    session::{Host, Target},
    telemetry::Gauge,
    transport::sniff::{MAX_SNIFF, Sniffed, http_host, tls_server_name},
};

pub(crate) async fn serve(
    stream: TcpStream,
    config: Arc<Inbound>,
    ctx: Arc<Context>,
    handshake: crate::runtime::HandshakePermits,
    deadline: Instant,
) -> io::Result<()> {
    let (tag, target) = match &*config {
        Inbound::DokodemoDoor {
            tag, address, port, ..
        } => {
            let target = crate::config::DokodemoDoor {
                address: address.clone(),
                port: *port,
                network: "tcp".to_owned(),
                sniffing: None,
            }
            .target();
            (tag.clone(), target)
        }
        _ => return Err(io::Error::other("入口不是 dokodemo-door")),
    };
    stream.set_nodelay(true)?;
    // 嗅探按 dest_override 改写目标域名（端口不变），与 Xray 的 destOverride
    // 语义一致；它只看首包，不消费业务字节。
    let mut target = target;
    if let Inbound::DokodemoDoor {
        sniffing: Some(sniffing),
        ..
    } = &*config
        && sniffing.enabled
        && matches!(target.host, Host::Ip(_))
        && let Some(domain) = sniff_server_name(&stream, deadline, &sniffing.dest_override).await
    {
        target.host = Host::Domain(domain);
    }
    let upstream = tokio::time::timeout_at(deadline, ctx.connect(&tag, &target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dokodemo-door 连接目标超时"))??;
    drop(handshake);
    crate::forward::relay(stream, upstream, ctx.stats.clone()).await
}

/// 通过 `peek` 观察首包，返回可用于路由的域名。
///
/// `peek` 在缓冲区已有数据时会立即完成，因此“仍需要更多字节”时按小间隔
/// 等待，直到握手期限；解析失败或类型未启用则回落到配置目标。
async fn sniff_server_name(
    stream: &TcpStream,
    deadline: Instant,
    kinds: &[SniffKind],
) -> Option<String> {
    let mut buffer = vec![0u8; MAX_SNIFF];
    let mut previous = 0;
    loop {
        let length = match tokio::time::timeout_at(deadline, stream.peek(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(length)) => length,
        };
        if length == buffer.len() {
            return None;
        }
        let observed = &buffer[..length];
        let outcome = if observed.first() == Some(&0x16) {
            if !kinds.contains(&SniffKind::Tls) {
                return None;
            }
            tls_server_name(observed)
        } else {
            if !kinds.contains(&SniffKind::Http) {
                return None;
            }
            http_host(observed)
        };
        match outcome {
            Sniffed::Domain(domain) => return Some(domain),
            Sniffed::Invalid => return None,
            Sniffed::NeedMore => {
                if length == previous
                    && tokio::time::timeout_at(
                        deadline,
                        tokio::time::sleep(Duration::from_millis(2)),
                    )
                    .await
                    .is_err()
                {
                    return None;
                }
                previous = length;
            }
        }
    }
}

/// 一个待发送的上游数据报；额度在真正写出前一直持有。
struct Datagram {
    payload: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

struct Session {
    tx: mpsc::Sender<Datagram>,
    last_used: Arc<Mutex<Instant>>,
}

#[allow(clippy::large_enum_variant)] // 配置期构造一次，每个包只匹配。
enum Destination {
    Direct(SocketAddr),
    Proxy(ProxyOutbound),
}

/// UDP 监听入口：固定目标、按客户端源地址分配关联。
pub(crate) async fn serve_udp(
    socket: UdpSocket,
    config: Arc<Inbound>,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let (tag, target) = match &*config {
        Inbound::DokodemoDoor {
            tag, address, port, ..
        } => {
            let target = crate::config::DokodemoDoor {
                address: address.clone(),
                port: *port,
                network: "udp".to_owned(),
                sniffing: None,
            }
            .target();
            (tag.clone(), target)
        }
        _ => return Err(io::Error::other("入口不是 dokodemo-door")),
    };

    // 固定目标只选路一次；拒绝或不可承载的 UDP 出站不产生目标流量。
    let destination = match ctx.udp_selected(&tag, &target).await {
        Ok(selected) => match selected.udp_proxied() {
            Err(error) => {
                tracing::warn!(
                    event = "dokodemo_udp",
                    inbound = %tag,
                    error = %error,
                    "路由拒绝或该 UDP 出站不受支持，失败关闭"
                );
                None
            }
            Ok(false) => match ctx.direct_udp_address(&selected, &target).await {
                Ok(address) => Some(Destination::Direct(address)),
                Err(error) => {
                    tracing::warn!(
                        event = "dokodemo_udp",
                        inbound = %tag,
                        error = %error,
                        "目标解析失败，丢弃 UDP 数据报"
                    );
                    None
                }
            },
            Ok(true) => selected
                .proxy
                .map(|proxy| Destination::Proxy((*proxy).clone())),
        },
        Err(error) => {
            tracing::warn!(
                event = "dokodemo_udp",
                inbound = %tag,
                error = %error,
                "路由拒绝或该 UDP 出站不受支持，失败关闭"
            );
            None
        }
    };

    let mut buffer = vec![0u8; 65536];
    let Some(destination) = destination else {
        // 保持监听存活但丢弃全部数据报；与“失败关闭”一致，不回落到直连。
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled() => return Ok(()),
                _ = force.cancelled() => return Ok(()),
                received = socket.recv_from(&mut buffer) => {
                    if received.is_err() {
                        return Ok(());
                    }
                    ctx.stats.drop_packet();
                }
            }
        }
    };

    let socket = Arc::new(socket);
    let ttl = Duration::from_millis(ctx.limits.udp_idle_timeout_ms);
    let prune = (ttl / 2).clamp(Duration::from_millis(50), Duration::from_secs(1));
    let mut tick = tokio::time::interval(prune);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sessions: HashMap<SocketAddr, Session> = HashMap::new();
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            _ = force.cancelled() => break,
            received = socket.recv_from(&mut buffer) => {
                let (length, peer) = received?;
                if length > ctx.limits.max_udp_payload {
                    ctx.stats.drop_packet();
                    continue;
                }
                let Ok(budget) = ctx
                    .udp_bytes
                    .clone()
                    .try_acquire_many_owned(length.max(1) as u32)
                else {
                    ctx.stats.drop_packet();
                    continue;
                };
                let payload = buffer[..length].to_vec();
                if let Some(session) = sessions.get_mut(&peer) {
                    *session.last_used.lock().unwrap_or_else(|error| error.into_inner()) = Instant::now();
                    if session
                        .tx
                        .try_send(Datagram {
                            payload,
                            _budget: budget,
                        })
                        .is_err()
                    {
                        ctx.stats.drop_packet();
                    }
                    continue;
                }
                let Ok(slot) = ctx.udp_slots.clone().try_acquire_owned() else {
                    ctx.stats.drop_packet();
                    continue;
                };
                let upstream = match &destination {
                    Destination::Direct(address) => match direct_socket(*address).await {
                        Ok(socket) => Upstream::Direct(socket),
                        Err(error) => {
                            tracing::warn!(
                                event = "dokodemo_udp",
                                inbound = %tag,
                                error = %error,
                                "上游 UDP 套接字创建失败"
                            );
                            ctx.stats.drop_packet();
                            continue;
                        }
                    },
                    Destination::Proxy(proxy) => match dial_udp_relay(&ctx, proxy).await {
                        Ok(relay) => Upstream::Proxy(relay),
                        Err(error) => {
                            tracing::warn!(
                                event = "dokodemo_udp",
                                inbound = %tag,
                                error = %error,
                                "SOCKS5 UDP 中继建立失败"
                            );
                            ctx.stats.drop_packet();
                            continue;
                        }
                    },
                };
                let (tx, rx) = mpsc::channel::<Datagram>(ctx.limits.udp_queue_packets);
                let last_used = Arc::new(Mutex::new(Instant::now()));
                let reader = socket.clone();
                let task_ctx = ctx.clone();
                let task_last = last_used.clone();
                let task_target = target.clone();
                tasks.spawn(async move {
                    let _slot = slot;
                    let _gauge = task_ctx.stats.enter(Gauge::Udp);
                    run_session(
                        upstream,
                        rx,
                        reader,
                        peer,
                        task_target,
                        task_ctx,
                        task_last,
                    )
                    .await;
                });
                if tx
                    .try_send(Datagram {
                        payload,
                        _budget: budget,
                    })
                    .is_err()
                {
                    ctx.stats.drop_packet();
                }
                sessions.insert(peer, Session { tx, last_used });
            }
            _ = tick.tick() => {
                sessions.retain(|_, session| {
                    session.last_used.lock().unwrap_or_else(|error| error.into_inner()).elapsed() < ttl
                });
                while tasks.try_join_next().is_some() {}
            }
        }
    }

    // 关闭写端让会话任务看到 `recv` 返回 None；再统一中止，保证额度归还。
    sessions.clear();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

enum Upstream {
    Direct(UdpSocket),
    Proxy(UdpRelay),
}

async fn direct_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(crate::udp::wildcard(address.ip())).await?;
    crate::udp::shadowsocks::prepare_buffers(&socket)?;
    socket.connect(address).await?;
    Ok(socket)
}

async fn send_upstream(upstream: &Upstream, target: &Target, payload: &[u8]) -> io::Result<bool> {
    match upstream {
        Upstream::Direct(socket) => Ok(socket.send(payload).await? == payload.len()),
        Upstream::Proxy(relay) => {
            let datagram = crate::outbound::socks5_udp_encode(target, payload)?;
            Ok(relay.socket.send(&datagram).await? == datagram.len())
        }
    }
}

async fn recv_upstream(upstream: &Upstream, buffer: &mut [u8]) -> io::Result<Option<Vec<u8>>> {
    let length = match upstream {
        Upstream::Direct(socket) => socket.recv(buffer).await?,
        Upstream::Proxy(relay) => relay.socket.recv(buffer).await?,
    };
    match upstream {
        Upstream::Direct(_) => Ok(Some(buffer[..length].to_vec())),
        Upstream::Proxy(_) => {
            // 固定目标关联不依赖回程源地址；分片与畸形报文直接丢弃。
            Ok(crate::outbound::socks5_udp_parse(&buffer[..length])
                .map(|(_, payload)| payload.to_vec()))
        }
    }
}

async fn run_session(
    upstream: Upstream,
    mut rx: mpsc::Receiver<Datagram>,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    target: Target,
    ctx: Arc<Context>,
    last_used: Arc<Mutex<Instant>>,
) {
    let mut buffer = vec![0u8; 65536];
    loop {
        tokio::select! {
            biased;
            datagram = rx.recv() => match datagram {
                Some(datagram) => {
                    match send_upstream(&upstream, &target, &datagram.payload).await {
                        Ok(true) => {
                            ctx.stats
                                .uplink
                                .fetch_add(datagram.payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                            *last_used.lock().unwrap_or_else(|error| error.into_inner()) = Instant::now();
                        }
                        Ok(false) => ctx.stats.drop_packet(),
                        Err(_) => ctx.stats.drop_packet(),
                    }
                }
                None => break,
            },
            received = recv_upstream(&upstream, &mut buffer) => {
                let payload = match received {
                    Ok(Some(payload)) => payload,
                    // 无法解析或分片的报文：丢弃并继续。
                    Ok(None) => {
                        ctx.stats.drop_packet();
                        continue;
                    }
                    Err(_) => break,
                };
                if payload.len() > ctx.limits.max_udp_payload {
                    ctx.stats.drop_packet();
                    continue;
                }
                match socket.send_to(&payload, peer).await {
                    Ok(sent) if sent == payload.len() => {
                        ctx.stats
                            .downlink
                            .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        *last_used.lock().unwrap_or_else(|error| error.into_inner()) = Instant::now();
                    }
                    _ => ctx.stats.drop_packet(),
                }
            }
        }
    }
    // 空闲由主循环按 `last_used` 回收：丢弃发送端即可让本任务退出。
}
