//! 原生Shadowsocks UDP入口：固定接收/顺序认证任务，认证后的有界关联。
use super::*;
use crate::protocol::shadowsocks::{
    Prepared,
    packet_window::{PacketWindow, SendCounter},
    replay::{Domain, Window},
};
use ::shadowsocks::{
    config::ServerType,
    context::Context as CryptoContext,
    crypto::utils::random_iv_or_salt,
    relay::{
        Address,
        udprelay::{
            crypto_io::{decrypt_client_payload, encrypt_server_payload},
            options::UdpSocketControlData,
        },
    },
};
use tokio_util::sync::CancellationToken;

const MAX_CIPHERTEXT: usize = 65507;

#[cfg(test)]
#[path = "shadowsocks_tests.rs"]
mod tests;

pub(crate) fn dual_stack_socket() -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(false)?;
    if socket.only_v6()? {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "需要双栈UDP套接字",
        ));
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into())?;
    let socket = UdpSocket::from_std(socket.into())?;
    prepare_buffers(&socket)?;
    Ok(socket)
}

// macOS默认UDP发送缓冲不足一个合法最大报文；只调整本内核持有的socket。
// 不缩小平台已有缓冲，也不把socket内核缓冲计入排队载荷预算。
pub(crate) fn prepare_buffers(socket: &UdpSocket) -> io::Result<()> {
    let socket = socket2::SockRef::from(socket);
    if socket.send_buffer_size()? < MAX_CIPHERTEXT {
        socket.set_send_buffer_size(MAX_CIPHERTEXT)?;
    }
    if socket.recv_buffer_size()? < MAX_CIPHERTEXT {
        socket.set_recv_buffer_size(MAX_CIPHERTEXT)?;
    }
    Ok(())
}

fn normalize(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(ip.into(), v6.port()))
            .unwrap_or(address),
        _ => address,
    }
}

fn mapped(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        _ => address,
    }
}

// 接收缓冲由本模块持有且已初始化；recvmsg返回的MSG_TRUNC不丢失。
async fn receive(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<(usize, bool, SocketAddr)> {
    loop {
        socket.readable().await?;
        match socket.try_io(tokio::io::Interest::READABLE, || {
            // SAFETY: u8与MaybeUninit<u8>布局一致，socket2不读取或取消初始化输入。
            let bytes =
                unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast(), buffer.len()) };
            let mut slices = [socket2::MaybeUninitSlice::new(bytes)];
            let (length, flags, source) =
                socket2::SockRef::from(socket).recv_from_vectored(&mut slices)?;
            let source = source
                .as_socket()
                .ok_or_else(|| io::Error::other("UDP来源地址无效"))?;
            Ok((length, flags.is_truncated(), source))
        }) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            result => return result,
        }
    }
}

struct EncryptedPacket {
    wire: Vec<u8>,
    source: SocketAddr,
    _budget: OwnedSemaphorePermit,
}

async fn receiver(
    socket: Arc<UdpSocket>,
    ctx: Arc<Context>,
    tx: mpsc::Sender<EncryptedPacket>,
    done: CancellationToken,
) -> io::Result<()> {
    let mut buffer = vec![0; 65536];
    loop {
        let received = tokio::select! {
            biased;
            _ = done.cancelled() => return Ok(()),
            received = receive(&socket, &mut buffer) => received,
        };
        let (length, truncated, source) = received?;
        if truncated || length > MAX_CIPHERTEXT || length == 0 {
            ctx.stats.drop_packet();
            continue;
        }
        let Ok(budget) = ctx.udp_bytes.clone().try_acquire_many_owned(length as u32) else {
            ctx.stats.drop_packet();
            continue;
        };
        let packet = EncryptedPacket {
            wire: buffer[..length].to_vec(),
            source,
            _budget: budget,
        };
        if tx.try_send(packet).is_err() {
            ctx.stats.drop_packet();
        }
    }
}

struct LegacySession {
    association: Association,
    generation: u64,
    last_used: Instant,
    _slot: OwnedSemaphorePermit,
    _gauge: crate::telemetry::Guard,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    identity: usize,
    client: u64,
}

struct ModernSocket {
    socket: Arc<UdpSocket>,
    allowed: Arc<std::sync::Mutex<HashSet<SocketAddr>>>,
    task: AbortHandle,
}

/// 单个代理目标的发件箱与读任务。
struct ProxiedTarget {
    outgoing: mpsc::Sender<crate::udp::QueuedUplink>,
    task: AbortHandle,
}

impl Drop for ProxiedTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ModernSession {
    endpoint: SocketAddr,
    /// 该关联所属用户的累计字节；单密钥模式为 None。
    traffic: Option<Arc<crate::telemetry::UserCounters>>,
    window: PacketWindow,
    server: u64,
    counter: SendCounter,
    generation: u64,
    last_used: Instant,
    key: Vec<u8>,
    transport: Option<ModernSocket>,
    _slot: OwnedSemaphorePermit,
    _gauge: crate::telemetry::Guard,
}

struct ModernReply {
    session: SessionKey,
    generation: u64,
    /// 回程地址。直连用 `recv_from` 的真实源地址；代理路径拿不到源地址，
    /// 用原目标（可能是域名），因此这里用 `Address` 而非 `SocketAddr`。
    target: Address,
    payload: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

struct Dispatcher {
    ctx: Arc<Context>,
    prepared: Arc<Prepared>,
    tag: String,
    socket: Arc<UdpSocket>,
    crypto: CryptoContext,
    legacy: HashMap<SocketAddr, LegacySession>,
    modern: HashMap<SessionKey, ModernSession>,
    legacy_tx: mpsc::Sender<Packet>,
    modern_tx: mpsc::Sender<ModernReply>,
    readers: JoinSet<()>,
    generation: u64,
    /// 走代理出站的目标。key 是**会话 + 原始目标**（与直连的 IP 集合分开：
    /// 代理路径拿不到真实源地址，回程报头用原目标）。
    ///
    /// 必须按会话隔离：只按目标做键会让两个合法用户共用一份 outlet，
    /// 后一个用户的回包被前一个用户的密钥加密并投递。
    proxied: HashMap<(SessionKey, Target), ProxiedTarget>,
}

impl Dispatcher {
    fn next_generation(&mut self) -> io::Result<u64> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("UDP代次耗尽"))?;
        Ok(self.generation)
    }

    /// 2022 模式的代理出站发送。按目标复用一份 `RoutedUdp`，回程通过
    /// `modern_tx` 汇入 `modern_reply`，由它加密并发回客户端。
    ///
    /// 2017（legacy）模式未覆盖：它的回程需要关联自己的加密上下文与
    /// `Packet` 构造，且 `Packet` 是 `udp` 模块私有。legacy 路径仍走
    /// `udp_selected` 的 fail-closed 分支（选到代理时返回 `Unsupported`，
    /// 不会悄悄直连）。
    async fn send_proxied(
        &mut self,
        target: &Target,
        payload: &[u8],
        session: (SessionKey, u64),
        traffic: Option<Arc<crate::telemetry::UserCounters>>,
    ) -> io::Result<()> {
        let proxy_key = (session.0, target.clone());
        if !self.proxied.contains_key(&proxy_key) {
            if self.proxied.len() >= self.ctx.limits.max_udp_targets {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let outlet =
                crate::udp::RoutedUdp::new(self.ctx.clone(), self.tag.clone(), target.clone())
                    .await?;
            let (outgoing, mut rx) = mpsc::channel::<crate::udp::QueuedUplink>(64);
            let ctx = self.ctx.clone();
            let modern_tx = self.modern_tx.clone();
            let reply_target = target_to_address(target);
            let (key, generation) = session;
            let tracker = ctx.children.clone();
            let handle = tokio::spawn(tracker.track_future(async move {
                let mut outlet = outlet;
                loop {
                    tokio::select! {
                        biased;
                        packet = rx.recv() => {
                            let Some(packet) = packet else { break };
                            if outlet.send(&packet.payload).await.is_err() {
                                break;
                            }
                        }
                        datagram = outlet.recv() => {
                            let Ok(datagram) = datagram else { break };
                            let len = datagram.payload.len();
                            let Some(budget) = ctx
                                .udp_bytes
                                .clone()
                                .try_acquire_many_owned(len.max(1) as u32)
                                .ok()
                            else {
                                ctx.stats.drop_packet();
                                continue;
                            };
                            let reply = ModernReply {
                                session: key,
                                generation,
                                target: reply_target.clone(),
                                payload: datagram.payload,
                                _budget: budget,
                            };
                            if modern_tx.try_send(reply).is_err() {
                                ctx.stats.drop_packet();
                            }
                        }
                    }
                }
            }));
            self.proxied.insert(
                proxy_key.clone(),
                ProxiedTarget {
                    outgoing,
                    task: handle.abort_handle(),
                },
            );
        }
        let Some(entry) = self.proxied.get(&proxy_key) else {
            return Err(io::Error::other("UDP 代理映射缺失"));
        };
        let Some(queued) = crate::udp::QueuedUplink::reserve(&self.ctx, payload.to_vec()) else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        entry
            .outgoing
            .send(queued)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        self.ctx
            .stats
            .uplink
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        if let Some(traffic) = &traffic {
            traffic.add(true, payload.len());
        }
        Ok(())
    }

    fn modern_idle(&self) -> Duration {
        Duration::from_millis(self.ctx.limits.udp_idle_timeout_ms.max(60000))
    }

    async fn expire(&mut self) {
        let legacy_idle = Duration::from_millis(self.ctx.limits.udp_idle_timeout_ms);
        let expired: Vec<_> = self
            .legacy
            .iter()
            .filter(|(_, s)| s.last_used.elapsed() >= legacy_idle)
            .map(|(&key, _)| key)
            .collect();
        for key in expired {
            if let Some(mut session) = self.legacy.remove(&key) {
                session.association.close().await;
            }
        }
        let modern_idle = self.modern_idle();
        self.modern.retain(|_, session| {
            if session.last_used.elapsed() >= modern_idle {
                if let Some(transport) = session.transport.take() {
                    transport.task.abort();
                }
                false
            } else {
                true
            }
        });
        // 会话过期/关闭后，它名下的代理出口必须一起回收，否则目标名额
        // 与上游套接字会一直挂着。
        let alive: std::collections::HashSet<SessionKey> = self.modern.keys().copied().collect();
        self.proxied.retain(|(key, _), _| alive.contains(key));
        while self.readers.try_join_next().is_some() {}
    }

    async fn process(&mut self, mut packet: EncryptedPacket, accepting: bool) -> io::Result<()> {
        let method = self.prepared.keys.method;
        let legacy_salt = if method.is_aead_2022() {
            None
        } else {
            Some(
                packet
                    .wire
                    .get(..method.salt_len())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UDP salt缺失"))?
                    .to_vec(),
            )
        };
        let (length, address, control) = decrypt_client_payload(
            &self.crypto,
            method,
            &self.prepared.keys.key,
            &mut packet.wire,
            self.prepared.keys.users.as_deref(),
        )
        // PermissionDenied 与 TCP 侧及其它协议一致，供调用方区分
        // 「认证失败」与「载荷过长 / 路由拒绝」等业务失败。
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "UDP认证失败"))?;
        let target = target(address)?;
        if length > self.ctx.limits.max_udp_payload {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP载荷过长"));
        }
        // 选路：`udp_selected` 允许代理出站，`allowed` 只允许直连。
        // 2022（modern）分支支持代理；2017（legacy）分支保持原样
        // （回程需要关联自己的加密上下文，`Packet` 又是 `udp` 模块私有）。
        let selected = self.ctx.udp_selected(&self.tag, &target).await?;
        let proxied = selected.udp_proxied()?;
        if let Some(salt) = legacy_salt {
            // 2017 不支持代理：链式部署下这一支 fail-closed，绝不静默直连。
            if proxied {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Shadowsocks 2017 模式的 UDP 不支持上游代理出站",
                ));
            }
            self.prepared.replay.admit(
                Domain {
                    inbound: self.prepared.inbound,
                    identity: 0,
                },
                &salt,
                Window::Aead2017,
            )?;
            if !self.legacy.contains_key(&packet.source) {
                if !accepting {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let slot = self
                    .ctx
                    .udp_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
                let generation = self.next_generation()?;
                let mut association = Association::with_replies(
                    self.ctx.clone(),
                    self.tag.clone(),
                    self.legacy_tx.clone(),
                    None,
                    None,
                );
                association.native = Some((packet.source, generation));
                self.legacy.insert(
                    packet.source,
                    LegacySession {
                        association,
                        generation,
                        last_used: Instant::now(),
                        _slot: slot,
                        _gauge: self.ctx.stats.enter(Gauge::Udp),
                    },
                );
            }
            let session = self.legacy.get_mut(&packet.source).expect("关联已准备");
            session
                .association
                .send(target, &packet.wire[..length])
                .await?;
            session.last_used = Instant::now();
        } else {
            let control = control.ok_or_else(|| io::Error::other("2022 control缺失"))?;
            let identity = self
                .prepared
                .identity(control.user.as_ref().map(|user| user.key()))?;
            let key = SessionKey {
                identity,
                client: control.client_session_id,
            };
            if !self.modern.contains_key(&key) {
                if !accepting {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                // 准入在申请槽与建 socket 之前：到期账户不应开新 UDP 会话。
                let name = self.prepared.user_name(key.identity);
                if !self.ctx.stats.admit_user(&self.tag, name.as_deref()) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "账户配额已用尽或已到期",
                    ));
                }
                let slot = self
                    .ctx
                    .udp_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
                let generation = self.next_generation()?;
                let transport = self.new_modern_socket(key, generation)?;
                let mut random = [0; 8];
                let mut server = key.client;
                for _ in 0..8 {
                    random_iv_or_salt(&mut random);
                    server = u64::from_be_bytes(random);
                    if server != key.client {
                        break;
                    }
                }
                if server == key.client {
                    transport.task.abort();
                    return Err(io::Error::other("UDP会话随机数冲突"));
                }
                let user_key = control
                    .user
                    .as_ref()
                    .map(|user| user.key())
                    .unwrap_or(&self.prepared.keys.key)
                    .to_vec();
                let traffic = self
                    .prepared
                    .user_name(key.identity)
                    .map(|user| self.ctx.stats.user_counter(&self.tag, &user));
                self.modern.insert(
                    key,
                    ModernSession {
                        endpoint: packet.source,
                        traffic,
                        window: PacketWindow::new(),
                        server,
                        counter: SendCounter::new(),
                        generation,
                        last_used: Instant::now(),
                        key: user_key,
                        transport: Some(transport),
                        _slot: slot,
                        _gauge: self.ctx.stats.enter(Gauge::Udp),
                    },
                );
            }
            // 重放窗口、会话存活与端点更新对直连/代理两条路径一致；
            // 此前代理分支先 return，重放包会被再次转发。
            let (generation, traffic) = {
                let session = self.modern.get_mut(&key).expect("会话已准备");
                let Some(transport) = &session.transport else {
                    return Err(io::Error::other("UDP会话已终止"));
                };
                if transport.task.is_finished() || !session.window.accept(control.packet_id) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "UDP会话已关闭或重放",
                    ));
                }
                session.endpoint = packet.source;
                session.last_used = Instant::now();
                (session.generation, session.traffic.clone())
            };
            if proxied {
                self.send_proxied(&target, &packet.wire[..length], (key, generation), traffic)
                    .await?;
                return Ok(());
            }
            let session = self.modern.get_mut(&key).expect("会话已准备");
            let Some(transport) = &session.transport else {
                return Err(io::Error::other("UDP会话已终止"));
            };
            let destination = normalize(self.ctx.direct_udp_address(&selected, &target).await?);
            {
                let allowed = transport
                    .allowed
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if !allowed.contains(&destination)
                    && allowed.len() >= self.ctx.limits.max_udp_targets
                {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
            }
            // try_send在持锁期间同步完成；reader无法在授权提交前处理该目标的回包。
            loop {
                transport.socket.writable().await?;
                let sent = {
                    let mut allowed = transport
                        .allowed
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    let sent = transport
                        .socket
                        .try_send_to(&packet.wire[..length], mapped(destination));
                    if sent.as_ref().is_ok_and(|&n| n == length) {
                        allowed.insert(destination);
                    }
                    sent
                };
                match sent {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Ok(n) if n == length => {
                        self.ctx.stats.uplink.fetch_add(n as u64, Ordering::Relaxed);
                        if let Some(traffic) = &session.traffic {
                            traffic.add(true, n);
                        }
                        break;
                    }
                    Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn new_modern_socket(
        &mut self,
        session: SessionKey,
        generation: u64,
    ) -> io::Result<ModernSocket> {
        let socket = Arc::new(dual_stack_socket()?);
        let read = socket.clone();
        let allowed = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let targets = allowed.clone();
        let ctx = self.ctx.clone();
        let tx = self.modern_tx.clone();
        let task = self
            .readers
            .spawn(ctx.children.clone().track_future(async move {
                let mut buffer = vec![0; 65536];
                while let Ok((length, truncated, source)) = receive(&read, &mut buffer).await {
                    let source = normalize(source);
                    if truncated
                        || length > ctx.limits.max_udp_payload
                        || !targets
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .contains(&source)
                    {
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
                    let reply = ModernReply {
                        session,
                        generation,
                        target: Address::SocketAddress(source),
                        payload: buffer[..length].to_vec(),
                        _budget: budget,
                    };
                    if tx.try_send(reply).is_err() {
                        ctx.stats.drop_packet();
                    }
                }
            }));
        Ok(ModernSocket {
            socket,
            allowed,
            task,
        })
    }

    async fn legacy_reply(&mut self, packet: Packet) -> io::Result<()> {
        let (source, generation) = packet
            .native
            .ok_or_else(|| io::Error::other("UDP关联归属缺失"))?;
        let session = self
            .legacy
            .get_mut(&source)
            .filter(|s| s.generation == generation)
            .ok_or_else(|| io::Error::other("UDP旧关联回包"))?;
        let address = address(&packet.target)?;
        let method = self.prepared.keys.method;
        let wire = admitted_legacy_reply(&self.prepared, || {
            let mut wire = Default::default();
            encrypt_server_payload(
                &self.crypto,
                method,
                &self.prepared.keys.key,
                &address,
                &UdpSocketControlData::default(),
                &packet.payload,
                &mut wire,
            );
            wire
        })?;
        let n = self.socket.send_to(&wire, source).await?;
        if n != wire.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.ctx
            .stats
            .downlink
            .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        session.last_used = Instant::now();
        Ok(())
    }

    async fn modern_reply(&mut self, packet: ModernReply) -> io::Result<()> {
        let session = self
            .modern
            .get_mut(&packet.session)
            .filter(|s| s.generation == packet.generation && s.transport.is_some())
            .ok_or_else(|| io::Error::other("UDP旧会话回包"))?;
        let Some(packet_id) = session.counter.next() else {
            if let Some(transport) = session.transport.take() {
                transport.task.abort();
            }
            return Err(io::Error::other("UDP发送计数耗尽"));
        };
        let mut control = UdpSocketControlData::default();
        control.client_session_id = packet.session.client;
        control.server_session_id = session.server;
        control.packet_id = packet_id;
        let mut wire = Default::default();
        encrypt_server_payload(
            &self.crypto,
            self.prepared.keys.method,
            &session.key,
            &packet.target,
            &control,
            &packet.payload,
            &mut wire,
        );
        if wire.len() > MAX_CIPHERTEXT {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP密文过长"));
        }
        let n = self.socket.send_to(&wire, session.endpoint).await?;
        if n != wire.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.ctx
            .stats
            .downlink
            .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        if let Some(traffic) = &session.traffic {
            traffic.add(false, packet.payload.len());
        }
        session.last_used = Instant::now();
        Ok(())
    }

    async fn close(&mut self) {
        for (_, mut session) in self.legacy.drain() {
            session.association.close().await;
        }
        self.readers.abort_all();
        while self.readers.join_next().await.is_some() {}
        self.modern.clear();
    }
}

// 只有带已登记salt的完整密文才可交给发送路径；编码器由调用方提供以测试碰撞。
fn admitted_legacy_reply<W: AsRef<[u8]>>(
    prepared: &Prepared,
    mut encode: impl FnMut() -> W,
) -> io::Result<W> {
    for _ in 0..8 {
        let wire = encode();
        let bytes = wire.as_ref();
        if bytes.len() > MAX_CIPHERTEXT {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP密文过长"));
        }
        let salt = bytes
            .get(..prepared.keys.method.salt_len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UDP响应salt缺失"))?;
        match prepared.replay.admit(
            Domain {
                inbound: prepared.inbound,
                identity: 0,
            },
            salt,
            Window::Aead2017,
        ) {
            Ok(()) => return Ok(wire),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("UDP salt生成冲突"))
}

/// 把会话目标转成线格式地址（回程报头用）。
fn target_to_address(target: &Target) -> Address {
    match &target.host {
        Host::Ip(ip) => Address::SocketAddress(SocketAddr::new(*ip, target.port)),
        Host::Domain(domain) => Address::DomainNameAddress(domain.clone(), target.port),
    }
}

fn target(address: Address) -> io::Result<Target> {
    let target = match address {
        Address::SocketAddress(address) => Target::from(address),
        Address::DomainNameAddress(domain, port) => Target {
            host: Host::Domain(domain),
            port,
        },
    };
    crate::protocol::address::encode(&target)?;
    if target.port == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(target)
}

fn address(target: &Target) -> io::Result<Address> {
    crate::protocol::address::encode(target)?;
    Ok(match &target.host {
        Host::Ip(ip) => Address::SocketAddress(SocketAddr::new(*ip, target.port)),
        Host::Domain(domain) => Address::DomainNameAddress(domain.clone(), target.port),
    })
}

/// UDP 失败按类型分流：认证失败计入 rejected（与 TCP 侧一致），
/// 其余（载荷过长、路由拒绝、超时）计入 dropped。
///
/// 此前一律计入 dropped，导致 SS-UDP 的口令猜测混在「队列拥塞丢包」里，
/// 运维无法区分两类事件。
fn count_udp_failure<E>(ctx: &Arc<Context>, result: &Result<io::Result<()>, E>) {
    let authentication_failed = matches!(
        result,
        Ok(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied
    );
    if authentication_failed {
        ctx.stats.reject();
    } else {
        ctx.stats.drop_packet();
    }
}

pub(crate) async fn serve(
    socket: UdpSocket,
    prepared: Arc<Prepared>,
    ctx: Arc<Context>,
    tag: String,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let (tx, mut rx) = mpsc::channel(ctx.limits.udp_queue_packets);
    let (legacy_tx, mut legacy_rx) = mpsc::channel(ctx.limits.udp_queue_packets);
    let (modern_tx, mut modern_rx) = mpsc::channel(ctx.limits.udp_queue_packets);
    let done = CancellationToken::new();
    let mut receivers = JoinSet::new();
    receivers.spawn(ctx.children.track_future(receiver(
        socket.clone(),
        ctx.clone(),
        tx,
        done.clone(),
    )));
    let mut dispatcher = Dispatcher {
        ctx: ctx.clone(),
        prepared,
        tag,
        socket,
        crypto: CryptoContext::new(ServerType::Server),
        legacy: HashMap::new(),
        modern: HashMap::new(),
        legacy_tx,
        modern_tx,
        readers: JoinSet::new(),
        generation: 0,
        proxied: HashMap::new(),
    };
    let dial = Duration::from_millis(ctx.limits.dial_timeout_ms);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let result = async {
        loop {
            tokio::select! {
                _ = force.cancelled() => return Ok(()),
                _ = stop.cancelled(), if dispatcher.legacy.is_empty() && dispatcher.modern.is_empty() => return Ok(()),
                result = receivers.join_next() => {
                    return match result { Some(Ok(Err(error))) => Err(error), _ => Err(io::Error::other("UDP接收任务提前退出")) };
                }
                _ = tick.tick() => dispatcher.expire().await,
                Some(packet) = rx.recv() => {
                    let accepting = !stop.is_cancelled();
                    let result = tokio::select! { biased; _ = force.cancelled() => return Ok(()), result = timeout(dial, dispatcher.process(packet, accepting)) => result };
                    if !matches!(result, Ok(Ok(()))) { count_udp_failure(&ctx, &result); }
                }
                Some(packet) = legacy_rx.recv() => {
                    let result = tokio::select! { biased; _ = force.cancelled() => return Ok(()), result = timeout(dial, dispatcher.legacy_reply(packet)) => result };
                    if !matches!(result, Ok(Ok(()))) { count_udp_failure(&ctx, &result); }
                }
                Some(packet) = modern_rx.recv() => {
                    let result = tokio::select! { biased; _ = force.cancelled() => return Ok(()), result = timeout(dial, dispatcher.modern_reply(packet)) => result };
                    if !matches!(result, Ok(Ok(()))) { count_udp_failure(&ctx, &result); }
                }
            }
        }
    }.await;
    done.cancel();
    while receivers.join_next().await.is_some() {}
    dispatcher.close().await;
    drop(rx);
    drop(legacy_rx);
    drop(modern_rx);
    result
}
