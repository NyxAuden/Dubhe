//! TUIC v5 服务端（sing-box 兼容）。
//!
//! 线协议以本地只读上游 `sing-quic@v0.7.2` 的 `tuic` 包为准，独立实现，不复制其代码：
//! - 传输：QUIC（TLS 1.3），默认不要求 ALPN；认证单向流携带
//!   `版本(5) + Authenticate(0) + UUID(16) + TLS exporter token(32)`；
//! - TCP：客户端打开双向流，首部为 `版本 + Connect(1) + 目标地址`，随后是字节流；
//! - UDP：数据报或单向流承载，消息为
//!   `session u16 | packet u16 | fragment_total u8 | fragment_id u8 | data_len u16 |
//!    地址 | 数据`；单向流每条消息使用一条新的单向流；
//! - 心跳：双方发送数据报 `[5, 4]`，默认 10 秒；
//! - 认证令牌：`TLS-Exporter(label = UUID 原始 16 字节, context = password)`，32 字节。
//!
//! 资源策略：连接数、握手中数、并发双向/单向流、UDP 会话数、每会话 UDP 目标数、
//! 分片重组组数/字节数、QUIC 流与连接接收窗口、数据报接收缓冲全部有界；任何线格式
//! 错误都按 fail-closed 处理。认证失败、协议错误统一以错误码 0、空原因关闭连接，
//! 不向对端泄露内部状态。
//!
//! 本模块自包含，不修改 `transport.rs` 注册；由运行器在绑定 UDP 套接字后调用
//! [`prepare`] 与 [`serve`]。

pub(crate) mod modern;
pub(crate) mod wire;

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use quinn::{
    Connection, Endpoint, RecvStream, SendStream, TransportConfig, VarInt, ZeroRttAccepted,
    crypto::rustls::QuicServerConfig,
};
use rustls::ServerConfig as RustlsServerConfig;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    forward::{self, Context},
    session::{Host, Target},
    telemetry::Gauge,
};

use modern::{CongestionControl, ZeroRtt};

/// 流首部/分片首部的读取超时；认证超时由连接级计时器额外约束。
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// 单次 QUIC 写（单向流、数据报）超时，避免被流控永久阻塞。
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// 每会话上行队列长度；队列满时丢包而不是阻塞数据报读取循环。
const UDP_QUEUE_PACKETS: usize = 32;
/// 每会话同时保留的分片重组组数。
const UDP_REASSEMBLY_GROUPS: usize = 16;
/// 每会话分片重组占用字节上限。
const UDP_REASSEMBLY_BYTES: usize = 128 * 1024;
/// 分片重组过期时间。
const UDP_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);
/// 连接关闭时等待子任务的硬上限。
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
/// 默认并发流上限（双向与单向分别应用）。
const DEFAULT_MAX_STREAMS: u32 = 512;
/// 默认每流接收窗口。
const DEFAULT_STREAM_WINDOW: u64 = 64 * 1024;
/// 默认连接接收窗口，限制一条 QUIC 连接的总缓冲。
const DEFAULT_CONNECTION_WINDOW: u64 = 4 * 1024 * 1024;
/// 默认数据报接收缓冲。
const DEFAULT_DATAGRAM_BUFFER: usize = 1024 * 1024;
/// 认证成功/失败/未决状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthState {
    Pending,
    Authenticated(usize),
    Failed,
}

/// UDP 上行/下行承载方式；由会话的首个消息决定，与上游一致。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carrier {
    Datagram,
    Stream,
}

/// 配置中的一个用户。UUID 在配置阶段解析，运行时只保留原始 16 字节。
#[derive(Clone)]
pub(crate) struct Credential {
    pub name: String,
    pub uuid: [u8; 16],
    pub password: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不输出 UUID 之外的任何凭据；password 一律脱敏。
        formatter
            .debug_struct("Credential")
            .field("name", &self.name)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl Credential {
    /// 从配置文本构造；UUID 非法时返回错误，不回显原始文本。
    pub fn parse(name: String, uuid: &str, password: String) -> io::Result<Self> {
        let uuid = wire::parse_uuid(uuid)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TUIC UUID 无效"))?;
        Ok(Self {
            name,
            uuid,
            password,
        })
    }
}

/// 服务端参数。
#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub tag: String,
    pub users: Vec<Credential>,
    /// 非空时启用 ALPN；为空表示不协商 ALPN（sing-box TUIC 默认行为）。
    pub alpn: Vec<Vec<u8>>,
    pub heartbeat: Duration,
    pub auth_timeout: Duration,
    pub idle_timeout: Duration,
    pub handshake_timeout: Duration,
    pub max_connections: usize,
    pub max_handshakes: usize,
    pub max_streams: u32,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
    pub datagram_receive_buffer: usize,
    pub max_udp_sessions: usize,
    pub max_udp_targets: usize,
    pub udp_idle_timeout: Duration,
    pub max_udp_payload: usize,
    /// quinn 拥塞控制算法；默认 Cubic，可显式选择 NewReno 或 BBR。
    pub congestion_control: CongestionControl,
    /// TLS 1.3 0-RTT 早期数据策略；默认关闭。
    ///
    /// 开启后只改变 TLS 层是否接受早期数据，不绕过 TUIC 认证、版本检查或
    /// 失败关闭。重放风险与票据消费语义见 [`modern`] 模块文档。
    pub zero_rtt: ZeroRtt,
}

impl Options {
    /// 从仓库通用限制派生，供 `runtime.rs` 直接映射。
    pub fn from_limits(
        tag: String,
        users: Vec<Credential>,
        limits: &crate::config::Limits,
    ) -> Self {
        Self {
            tag,
            users,
            alpn: Vec::new(),
            heartbeat: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_millis(limits.handshake_timeout_ms),
            max_connections: limits.max_connections,
            max_handshakes: limits.max_handshakes,
            max_streams: DEFAULT_MAX_STREAMS,
            stream_receive_window: DEFAULT_STREAM_WINDOW,
            connection_receive_window: DEFAULT_CONNECTION_WINDOW,
            datagram_receive_buffer: DEFAULT_DATAGRAM_BUFFER,
            max_udp_sessions: limits.max_udp_associations,
            max_udp_targets: limits.max_udp_targets,
            udp_idle_timeout: Duration::from_millis(limits.udp_idle_timeout_ms),
            max_udp_payload: limits.max_udp_payload,
            congestion_control: CongestionControl::default(),
            zero_rtt: ZeroRtt::default(),
        }
    }

    /// 从配置文本设置拥塞控制算法，供运行器映射 `congestion_control` 字段。
    pub fn set_congestion_control(&mut self, value: &str) -> io::Result<()> {
        self.congestion_control = CongestionControl::parse(value)?;
        Ok(())
    }

    /// 从布尔值设置 0-RTT 策略，供运行器映射 `zero_rtt_handshake` 字段。
    pub fn set_zero_rtt(&mut self, enabled: bool) {
        self.zero_rtt = if enabled {
            ZeroRtt::Enabled
        } else {
            ZeroRtt::Disabled
        };
    }

    fn validate(&self) -> io::Result<()> {
        if self.users.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC 至少需要一个用户",
            ));
        }
        if self.max_streams == 0
            || self
                .alpn
                .iter()
                .any(|value| value.is_empty() || value.len() > 255)
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUIC 参数无效"));
        }
        if self.max_udp_payload == 0 || self.max_udp_payload > wire::MAX_UDP_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC UDP 载荷上限无效",
            ));
        }
        Ok(())
    }
}

/// 预构造的 QUIC 服务配置；可在多次监听间复用。
pub(crate) struct Prepared {
    options: Options,
    server: quinn::ServerConfig,
}

/// 构造 QUIC/TLS 服务配置。
///
/// `tls` 必须来自 [`crate::tls::load`]（启用 TLS 1.3）。函数不会修改传入的
/// `Arc`，而是克隆后调整 ALPN 与 early-data 策略。
pub(crate) fn prepare(options: Options, tls: Arc<RustlsServerConfig>) -> io::Result<Prepared> {
    options.validate()?;
    let mut tls = (*tls).clone();
    if !options.alpn.is_empty() {
        tls.alpn_protocols = options.alpn.clone();
    } else {
        // 与 sing-quic 的 TUIC 服务端一致：未配置 ALPN 时完全不协商。
        tls.alpn_protocols.clear();
    }
    // QUIC 只接受 0 或 u32::MAX；默认 0（拒绝早期数据）。开启后由 rustls 的
    // 有状态票据存储（默认内存缓存）与单次 `take` 消费提供 TLS 层重放防护。
    if options.zero_rtt.is_enabled() {
        // rustls 只在“有状态会话存储 + 未启用无状态 ticketer”时接受早期数据。
        // 配置不满足时直接拒绝启动，避免表面开启 0-RTT 却永远无法生效。
        if tls.ticketer.enabled() || !tls.session_storage.can_cache() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC 0-RTT 需要 rustls 有状态会话存储且禁用 ticketer",
            ));
        }
        // 没有票据就没有 0-RTT；调用方显式关掉票据时补到至少 1 张。
        if tls.send_tls13_tickets == 0 {
            tls.send_tls13_tickets = 1;
        }
    }
    tls.max_early_data_size = options.zero_rtt.max_early_data_size();

    let crypto = QuicServerConfig::try_from(Arc::new(tls)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUIC TLS 配置不支持 QUIC（需要 TLS 1.3 与 TLS13_AES_128_GCM_SHA256）",
        )
    })?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(varint(u64::from(options.max_streams)));
    transport.max_concurrent_uni_streams(varint(u64::from(options.max_streams)));
    transport.stream_receive_window(varint(options.stream_receive_window));
    transport.receive_window(varint(options.connection_receive_window));
    transport.datagram_receive_buffer_size(Some(options.datagram_receive_buffer));
    transport.datagram_send_buffer_size(options.datagram_receive_buffer);
    // 拥塞控制由 quinn 真实实现；不支持算法在配置解析阶段失败，绝不静默回退。
    options.congestion_control.apply(&mut transport);
    // 心跳由应用层发送，不使用 QUIC PING。
    transport.keep_alive_interval(None);
    let idle = quinn::IdleTimeout::try_from(options.idle_timeout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TUIC 空闲超时超出范围"))?;
    transport.max_idle_timeout(Some(idle));
    server.transport_config(Arc::new(transport));

    Ok(Prepared { options, server })
}

fn varint(value: u64) -> VarInt {
    VarInt::from_u32(value.min(u64::from(u32::MAX)) as u32)
}

/// 运行 TUIC 监听，直到 `stop`/`force` 或端点关闭。
///
/// `socket` 必须已绑定目标地址并处于非阻塞模式（`tokio::net::UdpSocket::into_std`
/// 的结果满足要求）。
pub(crate) async fn serve(
    socket: std::net::UdpSocket,
    prepared: Prepared,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let runtime =
        quinn::default_runtime().ok_or_else(|| io::Error::other("TUIC 需要已启动的异步运行时"))?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(prepared.server.clone()),
        socket,
        runtime,
    )
    .map_err(|_| io::Error::other("TUIC QUIC 端点创建失败"))?;
    let prepared = Arc::new(prepared);
    let slots = Arc::new(Semaphore::new(prepared.options.max_connections.max(1)));
    let handshakes = Arc::new(Semaphore::new(prepared.options.max_handshakes.max(1)));
    let mut connections: JoinSet<()> = JoinSet::new();
    let mut failure: Option<io::Error> = None;

    loop {
        while let Some(result) = connections.try_join_next() {
            if result.is_err() {
                failure = Some(io::Error::other("TUIC 连接任务异常"));
            }
        }
        if failure.is_some() {
            break;
        }
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            _ = force.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    ctx.stats.reject();
                    continue;
                };
                let Ok(handshake) = handshakes.clone().try_acquire_owned() else {
                    ctx.stats.reject();
                    continue;
                };
                let prepared = prepared.clone();
                let ctx = ctx.clone();
                let stop = stop.clone();
                let force = force.clone();
                let tracker = ctx.children.clone();
                connections.spawn(tracker.track_future(async move {
                    let _slot = slot;
                    let _gauge = ctx.stats.enter(Gauge::Connection);
                    // 先取得 0.5-RTT 连接句柄，让流接收循环能在握手完成前看到
                    // 0-RTT 早期流；TUIC 认证仍要等完整握手后再用 exporter 校验。
                    // 服务端 `into_0rtt` 按 quinn 文档总是成功；若未来实现返回
                    // 错误，则回退到等待完整握手，不改变协议语义。
                    let accepted = timeout(
                        prepared.options.handshake_timeout,
                        async move { incoming.accept() },
                    )
                    .await;
                    let Ok(Ok(connecting)) = accepted else {
                        return;
                    };
                    let (connection, established) = match connecting.into_0rtt() {
                        Ok((connection, established)) => (connection, Some(established)),
                        Err(connecting) => {
                            let connected = timeout(
                                prepared.options.handshake_timeout,
                                connecting,
                            )
                            .await;
                            let Ok(Ok(connection)) = connected else {
                                return;
                            };
                            (connection, None)
                        }
                    };
                    if let Err(error) = handle_connection(
                        connection,
                        established,
                        prepared,
                        ctx,
                        stop,
                        force,
                        crate::runtime::HandshakePermits::new(handshake, None),
                    )
                    .await
                    {
                        tracing::debug!(event = "tuic_connection_closed", reason = ?error.kind());
                    }
                }));
            }
        }
    }

    endpoint.close(VarInt::from_u32(0), b"");
    let _ = timeout(Duration::from_secs(3), endpoint.wait_idle()).await;
    connections.abort_all();
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            failure = Some(io::Error::other("TUIC 连接任务异常"));
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// 单条 QUIC 连接的生命周期。
///
/// `established` 为 `Some` 表示连接已通过服务端 0.5-RTT 通道提前交付：流接收
/// 循环必须立即启动，才能在握手完成前接受并按 `RecvStream::is_0rtt()` 标记
/// 早期流。`None` 表示调用方已经等到完整握手。
async fn handle_connection(
    connection: Connection,
    established: Option<ZeroRttAccepted>,
    prepared: Arc<Prepared>,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
    handshake: crate::runtime::HandshakePermits,
) -> io::Result<()> {
    let cancel = CancellationToken::new();
    let (auth_tx, auth_rx) = watch::channel(AuthState::Pending);
    let (handshake_tx, _handshake_rx) = watch::channel(established.is_none());
    let (fatal_tx, mut fatal_rx) = mpsc::channel::<()>(1);
    let shared = Arc::new(SessionShared {
        connection: connection.clone(),
        tag: prepared.options.tag.clone(),
        ctx: ctx.clone(),
        options: prepared.options.clone(),
        auth: auth_tx,
        handshake: handshake_tx,
        auth_claimed: AtomicU8::new(0),
        reject_counted: AtomicBool::new(false),
        zero_rtt_streams: AtomicBool::new(false),
        udp: Mutex::new(HashMap::new()),
        cancel: cancel.clone(),
    });

    let mut tasks: JoinSet<()> = JoinSet::new();
    if let Some(established) = established {
        tasks.spawn(handshake_task(shared.clone(), established));
    }
    tasks.spawn(auth_timeout_task(
        shared.clone(),
        auth_rx.clone(),
        fatal_tx.clone(),
        handshake,
    ));
    tasks.spawn(heartbeat_task(shared.clone(), auth_rx.clone()));
    tasks.spawn(uni_loop(shared.clone(), auth_rx.clone(), fatal_tx.clone()));
    // 真正创建 TCP 流的是 bi_loop；连接收尾对它的集合只有有界等待，
    // 登记它本身才能让停机等到「接受流 → 登记流」这段窗口结束。
    let tracker = shared.ctx.children.clone();
    tasks.spawn(tracker.track_future(bi_loop(shared.clone(), auth_rx.clone())));
    tasks.spawn(datagram_loop(
        shared.clone(),
        auth_rx.clone(),
        fatal_tx.clone(),
    ));
    tasks.spawn(udp_sweeper(shared.clone()));
    // 保证 fatal 通道在连接生命周期内始终有发送端，避免 `recv()` 立刻返回 None。
    let _fatal_tx = fatal_tx;

    tokio::select! {
        biased;
        _ = stop.cancelled() => {},
        _ = force.cancelled() => {},
        _ = cancel.cancelled() => {},
        _ = connection.closed() => {},
        _ = fatal_rx.recv() => {},
    }

    cancel.cancel();
    connection.close(VarInt::from_u32(0), b"");
    tasks.abort_all();
    let _ = timeout(SHUTDOWN_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;

    // 会话任务不接触会话表；先中止再取出句柄。若仍有任务短暂持锁，
    // 等待有界时间后放弃，`shared.cancel` 的级联取消保证子任务最终退出。
    let sessions = match timeout(SHUTDOWN_GRACE, shared.udp.lock()).await {
        Ok(mut guard) => std::mem::take(&mut *guard),
        Err(_) => HashMap::new(),
    };
    let mut handles = Vec::with_capacity(sessions.len());
    for (_, session) in sessions {
        session.cancel.cancel();
        session.task.abort();
        handles.push(session.task);
    }
    let _ = timeout(SHUTDOWN_GRACE, async {
        for handle in handles {
            let _ = handle.await;
        }
    })
    .await;
    Ok(())
}

/// 每条连接共享的状态。
struct SessionShared {
    connection: Connection,
    tag: String,
    ctx: Arc<Context>,
    options: Options,
    auth: watch::Sender<AuthState>,
    /// 服务端握手完成通知：`true` 表示等待握手的 future 已结束（服务端的
    /// `ZeroRttAccepted` 布尔值本身无意义），`false` 表示握手看门狗超时。认证
    /// exporter 只能在该 future 结束后调用，认证超时也从这里开始计时。
    handshake: watch::Sender<bool>,
    /// 0 表示尚未收到认证帧；1 表示已接收过一次（无论成功）。
    auth_claimed: AtomicU8,
    /// 认证失败是否已计入 `stats.rejected`；多条失败路径共享同一计数，
    /// 必须去重，否则一次错误密码会按路径数量重复计数。
    reject_counted: AtomicBool,
    /// 是否在握手完成前接受过带 0-RTT 标记的流；仅在认证成功后作为 debug
    /// 事件证据输出，不参与转发决策。
    zero_rtt_streams: AtomicBool,
    udp: Mutex<HashMap<u16, UdpSession>>,
    cancel: CancellationToken,
}

impl SessionShared {
    fn fail(&self) {
        // 认证失败必须计入 rejected：运维需要区分「无人连接」与
        // 「有人在反复猜密码」。四条失败路径共享，用 swap 去重。
        if !self.reject_counted.swap(true, Ordering::Relaxed) {
            self.ctx.stats.reject();
        }
        let _ = self.auth.send(AuthState::Failed);
    }

    /// 记录一条在握手完成前被接受的流；是否真正 0-RTT 由 quinn 的
    /// `RecvStream::is_0rtt()` 决定，不在这里推断。
    fn note_early_stream(&self) {
        self.zero_rtt_streams.store(true, Ordering::Relaxed);
    }

    /// 等待完整握手；握手失败/超时或连接取消时返回 false。
    async fn wait_handshake(&self) -> bool {
        let mut receiver = self.handshake.subscribe();
        loop {
            if *receiver.borrow_and_update() {
                return true;
            }
            tokio::select! {
                _ = self.cancel.cancelled() => return false,
                changed = receiver.changed() => {
                    if changed.is_err() {
                        return false;
                    }
                }
            }
        }
    }

    async fn route_udp(&self, packet: UdpPacket, carrier: Carrier) {
        let session_id = packet.session_id;
        let mut guard = self.udp.lock().await;
        if let Some(session) = guard.get(&session_id) {
            session.touch();
            if session.sender.try_send(packet).is_err() {
                self.ctx.stats.drop_packet();
            }
            return;
        }
        if guard.len() >= self.options.max_udp_sessions {
            self.ctx.stats.drop_packet();
            return;
        }
        // 新会话准入：到期账户不应开新 UDP 关联。
        let identity = match &*self.auth.borrow() {
            AuthState::Authenticated(index) => self
                .options
                .users
                .get(*index)
                .map(|credential| credential.name.as_str()),
            _ => None,
        };
        if !self.ctx.stats.admit_user(&self.tag, identity) {
            self.ctx.stats.drop_packet();
            return;
        }
        let Ok(slot) = self.ctx.udp_slots.clone().try_acquire_owned() else {
            self.ctx.stats.drop_packet();
            return;
        };
        let (sender, receiver) = mpsc::channel(UDP_QUEUE_PACKETS);
        let session_cancel = self.cancel.child_token();
        let last_used = Arc::new(AtomicU64::new(now_ms()));
        let packet_id = Arc::new(AtomicU16::new(0));
        let user = match &*self.auth.borrow() {
            AuthState::Authenticated(index) => self
                .options
                .users
                .get(*index)
                .map(|credential| credential.name.clone()),
            _ => None,
        };
        let traffic = user.map(|name| self.ctx.stats.user_counter(&self.tag, &name));
        let info = Arc::new(UdpSessionInfo {
            shared: self.ctx.clone(),
            tag: self.tag.clone(),
            traffic,
            max_udp_targets: self.options.max_udp_targets,
            max_udp_payload: self.options.max_udp_payload,
            connection: self.connection.clone(),
            session_id,
            carrier,
            cancel: session_cancel.clone(),
            last_used: last_used.clone(),
            packet_id,
        });
        let task = tokio::spawn(udp_session_loop(receiver, info));
        guard.insert(
            session_id,
            UdpSession {
                sender: sender.clone(),
                last_used,
                cancel: session_cancel,
                task,
                _slot: slot,
            },
        );
        if sender.try_send(packet).is_err() {
            self.ctx.stats.drop_packet();
        }
    }

    async fn remove_udp_session(&self, session_id: u16) {
        let session = {
            let mut guard = self.udp.lock().await;
            guard.remove(&session_id)
        };
        if let Some(session) = session {
            session.cancel.cancel();
            session.task.abort();
        }
    }
}

struct UdpSession {
    sender: mpsc::Sender<UdpPacket>,
    last_used: Arc<AtomicU64>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    _slot: OwnedSemaphorePermit,
}

impl UdpSession {
    fn touch(&self) {
        self.last_used.store(now_ms(), Ordering::Relaxed);
    }
}

/// 等待服务端完整握手；超时则关闭连接。
///
/// 注意：服务端 `ZeroRttAccepted` 的布尔值“没有意义”（quinn 文档），它只表示
/// 握手已完成；0-RTT 是否被接受必须由每条流的 `RecvStream::is_0rtt()` 判断。
/// 因此这里把 `Ok(_)` 一律视为握手完成。
async fn handshake_task(shared: Arc<SessionShared>, established: ZeroRttAccepted) {
    let completed = timeout(shared.options.handshake_timeout, established).await;
    let ok = completed.is_ok();
    // send_replace 不要求当前已有 receiver；任务可能在握手完成后才订阅。
    shared.handshake.send_replace(ok);
    if !ok {
        shared.connection.close(VarInt::from_u32(0), b"");
    }
}

/// 认证计时器：超时或认证完成即释放握手名额。
async fn auth_timeout_task(
    shared: Arc<SessionShared>,
    mut auth: watch::Receiver<AuthState>,
    fatal: mpsc::Sender<()>,
    _permit: crate::runtime::HandshakePermits,
) {
    // 与 0.5-RTT 改造前一致：认证超时从完整握手完成后开始，不把握手耗时
    // 重复计入认证窗口；握手本身由 handshake_task 计时。
    if !shared.wait_handshake().await {
        return;
    }
    let deadline = tokio::time::sleep(shared.options.auth_timeout);
    tokio::pin!(deadline);
    loop {
        if !matches!(*auth.borrow(), AuthState::Pending) {
            return;
        }
        tokio::select! {
            _ = shared.cancel.cancelled() => return,
            _ = &mut deadline => {
                shared.fail();
                let _ = fatal.try_send(());
                return;
            }
            changed = auth.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

/// 应用层心跳；认证完成后才开始发送，避免向未认证对端暴露服务存在。
async fn heartbeat_task(shared: Arc<SessionShared>, mut auth: watch::Receiver<AuthState>) {
    if wait_auth(&mut auth).await.is_none() {
        return;
    }
    let period = shared.options.heartbeat.max(Duration::from_millis(100));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // interval 的第一次 tick 立即就绪；消耗它，使首包在 period 之后发出。
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = shared.cancel.cancelled() => return,
            _ = ticker.tick() => {
                let frame = [wire::VERSION, wire::COMMAND_HEARTBEAT];
                let sent = timeout(
                    STREAM_WRITE_TIMEOUT,
                    shared.connection.send_datagram_wait(frame.to_vec().into()),
                )
                .await;
                if !matches!(sent, Ok(Ok(()))) {
                    return;
                }
            }
        }
    }
}

/// 接收单向流。单向流上的错误会关闭整条连接（与上游一致）。
async fn uni_loop(
    shared: Arc<SessionShared>,
    auth: watch::Receiver<AuthState>,
    fatal: mpsc::Sender<()>,
) {
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                let _ = fatal.try_send(());
            }
        }
        tokio::select! {
            biased;
            _ = shared.cancel.cancelled() => break,
            accepted = shared.connection.accept_uni() => {
                let Ok(stream) = accepted else { break; };
                let shared = shared.clone();
                let auth = auth.clone();
                let fatal = fatal.clone();
                tasks.spawn(async move {
                    // quinn 在握手完成前接受流时将其标记为 0-RTT；标记必须在
                    // 读取/等待认证前采集，握手完成后该属性不再变化。
                    if stream.is_0rtt() {
                        shared.note_early_stream();
                    }
                    if handle_uni_stream(stream, shared, auth).await.is_err() {
                        let _ = fatal.try_send(());
                    }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    let _ = timeout(SHUTDOWN_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
}

async fn handle_uni_stream(
    mut stream: RecvStream,
    shared: Arc<SessionShared>,
    mut auth: watch::Receiver<AuthState>,
) -> io::Result<()> {
    let mut header = [0u8; 2];
    read_exact(&mut stream, &mut header).await?;
    let command = wire::decode_command_header(&header).map_err(wire_error)?;
    match command {
        wire::Command::Authenticate => {
            let mut body = [0u8; wire::AUTH_BODY_LEN];
            read_exact(&mut stream, &mut body).await?;
            let mut frame = [0u8; wire::AUTH_FRAME_LEN];
            frame[..2].copy_from_slice(&header);
            frame[2..].copy_from_slice(&body);
            let request = wire::decode_authenticate(&frame).map_err(wire_error)?;

            // 只允许一次认证；重复认证视为协议错误并关闭连接。
            if shared.auth_claimed.swap(1, Ordering::SeqCst) != 0 {
                shared.fail();
                return Err(protocol("TUIC 重复认证"));
            }
            // exporter 只能从完整握手的 1-RTT 密钥派生。认证帧可能是 0-RTT
            // 早期流，因此先读帧、再等握手，顺序不能反过来。
            if !shared.wait_handshake().await {
                return Err(protocol("TUIC 握手未完成"));
            }
            let Some(index) = lookup_user(&shared.options.users, &request.uuid) else {
                shared.fail();
                return Err(protocol("TUIC 认证失败"));
            };
            let user = &shared.options.users[index];
            let mut token = [0u8; 32];
            if shared
                .connection
                .export_keying_material(&mut token, &request.uuid, user.password.as_bytes())
                .is_err()
                || !wire::ct_eq(&token, &request.token)
            {
                shared.fail();
                return Err(protocol("TUIC 认证失败"));
            }
            // 只有在认证成功后才把 0-RTT 证据写入 debug 日志。事件不包含
            // UUID、password、token 或任何密钥材料；默认 INFO 过滤下不输出。
            if shared.zero_rtt_streams.load(Ordering::Relaxed) {
                tracing::debug!(
                    event = "tuic_0rtt_accepted",
                    tag = %shared.tag,
                    "TUIC 0-RTT 早期流已在认证成功前接受"
                );
            }
            let _ = shared.auth.send(AuthState::Authenticated(index));
            Ok(())
        }
        wire::Command::Packet => {
            if wait_auth(&mut auth).await.is_none() {
                return Err(protocol("TUIC 未认证"));
            }
            let packet = read_udp_stream(&mut stream, shared.options.max_udp_payload).await?;
            let Some(budget) = reserve_budget(&shared.ctx, packet.payload.len()) else {
                shared.ctx.stats.drop_packet();
                return Ok(());
            };
            let packet = packet.with_budget(budget);
            shared.route_udp(packet, Carrier::Stream).await;
            Ok(())
        }
        wire::Command::Dissociate => {
            if wait_auth(&mut auth).await.is_none() {
                return Err(protocol("TUIC 未认证"));
            }
            let mut session = [0u8; 2];
            read_exact(&mut stream, &mut session).await?;
            shared.remove_udp_session(u16::from_be_bytes(session)).await;
            Ok(())
        }
        wire::Command::Connect | wire::Command::Heartbeat => Err(protocol("TUIC 单向流命令不支持")),
    }
}

/// 接收双向流且只在该流内处理错误，不影响同连接的其他流。
async fn bi_loop(shared: Arc<SessionShared>, auth: watch::Receiver<AuthState>) {
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        tokio::select! {
            biased;
            _ = shared.cancel.cancelled() => break,
            accepted = shared.connection.accept_bi() => {
                let Ok((send, recv)) = accepted else { break; };
                let shared = shared.clone();
                let auth = auth.clone();
                let tracker = shared.ctx.children.clone();
                tasks.spawn(tracker.track_future(async move {
                    if recv.is_0rtt() {
                        shared.note_early_stream();
                    }
                    handle_bi_stream(send, recv, shared, auth).await;
                }));
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    let _ = timeout(SHUTDOWN_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
}

async fn handle_bi_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    shared: Arc<SessionShared>,
    mut auth: watch::Receiver<AuthState>,
) {
    let target = match read_connect_target(&mut recv, &mut auth).await {
        Ok(target) => target,
        Err(_) => {
            let _ = recv.stop(VarInt::from_u32(0));
            let _ = send.reset(VarInt::from_u32(0));
            return;
        }
    };
    // 准入在嗅探与拨号之前：到期账户不应触发 DNS 或上游连接。
    let user = match &*auth.borrow() {
        AuthState::Authenticated(index) => shared
            .options
            .users
            .get(*index)
            .map(|credential| credential.name.clone()),
        _ => None,
    };
    if !shared.ctx.stats.admit_user(&shared.tag, user.as_deref()) {
        let _ = recv.stop(VarInt::from_u32(0));
        let _ = send.reset(VarInt::from_u32(0));
        return;
    }
    // 首包嗅探：TUIC 客户端通常紧接 Connect 头就发首包，因此这里有机会
    // 读到 TLS SNI / HTTP Host。未配置 `sniffing` 时直接返回空前缀。
    // 用 `sniff_route_parts` 而不是包装流：失败分支还要调用
    // `recv.stop()`，包装成 `Prefixed` 后就拿不到底层句柄了。
    let (prefix, route, dial) =
        crate::transport::sniff::sniff_route_parts(&shared.ctx, &shared.tag, &mut recv, &target)
            .await;
    let upstream = match shared.ctx.connect_routed(&shared.tag, &route, &dial).await {
        Ok(upstream) => upstream,
        Err(_) => {
            let _ = recv.stop(VarInt::from_u32(0));
            let _ = send.reset(VarInt::from_u32(0));
            return;
        }
    };
    let recv = crate::transport::sniff::Prefixed::new(prefix, recv);
    let stream =
        shared
            .ctx
            .stats
            .count_user(&shared.tag, user.as_deref(), QuicStream { send, recv });
    let _ = forward::relay(stream, upstream, shared.ctx.stats.clone()).await;
}

async fn read_connect_target(
    recv: &mut RecvStream,
    auth: &mut watch::Receiver<AuthState>,
) -> io::Result<Target> {
    let mut header = [0u8; 2];
    read_exact(recv, &mut header).await?;
    if wire::decode_command_header(&header).map_err(wire_error)? != wire::Command::Connect {
        return Err(protocol("TUIC 双向流仅支持 Connect"));
    }
    let destination = read_address(recv).await?;
    if wait_auth(auth).await.is_none() {
        return Err(protocol("TUIC 未认证"));
    }
    address_to_target(&destination)
}

/// 数据报接收循环。认证前的数据报直接丢弃；认证后的非法数据报关闭连接。
async fn datagram_loop(
    shared: Arc<SessionShared>,
    mut auth: watch::Receiver<AuthState>,
    fatal: mpsc::Sender<()>,
) {
    // 与上游一致：认证完成前不消费数据报，让它们在 QUIC 接收缓冲中排队；
    // 缓冲由 transport.datagram_receive_buffer_size 严格限制。
    tokio::select! {
        biased;
        _ = shared.cancel.cancelled() => return,
        authenticated = wait_auth(&mut auth) => {
            if authenticated.is_none() {
                return;
            }
        }
    }
    loop {
        tokio::select! {
            biased;
            _ = shared.cancel.cancelled() => return,
            received = shared.connection.read_datagram() => {
                let Ok(datagram) = received else { return; };
                let command = match wire::decode_command_header(&datagram) {
                    Ok(command) => command,
                    Err(_) => {
                        let _ = fatal.try_send(());
                        return;
                    }
                };
                match command {
                    wire::Command::Heartbeat => {}
                    wire::Command::Packet => {
                        let body = match wire::decode_udp_body(&datagram[2..]) {
                            Ok(body) => body,
                            Err(_) => {
                                let _ = fatal.try_send(());
                                return;
                            }
                        };
                        if body.payload.len() > shared.options.max_udp_payload {
                            shared.ctx.stats.drop_packet();
                            continue;
                        }
                        let Some(budget) = reserve_budget(&shared.ctx, body.payload.len()) else {
                            shared.ctx.stats.drop_packet();
                            continue;
                        };
                        let packet = UdpPacket {
                            session_id: body.session_id,
                            packet_id: body.packet_id,
                            fragment_total: body.fragment_total,
                            fragment_id: body.fragment_id,
                            destination: body.destination,
                            payload: body.payload.to_vec(),
                            _budget: Some(budget),
                        };
                        shared.route_udp(packet, Carrier::Datagram).await;
                    }
                    _ => {
                        let _ = fatal.try_send(());
                        return;
                    }
                }
            }
        }
    }
}

/// 定期清理空闲或已结束的 UDP 会话。
async fn udp_sweeper(shared: Arc<SessionShared>) {
    let timeout_ms = duration_ms(shared.options.udp_idle_timeout);
    let period = shared
        .options
        .udp_idle_timeout
        .checked_div(2)
        .unwrap_or(Duration::from_secs(1))
        .max(Duration::from_millis(200));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shared.cancel.cancelled() => return,
            _ = ticker.tick() => {
                let now = now_ms();
                let stale = {
                    let mut guard = shared.udp.lock().await;
                    let ids: Vec<u16> = guard
                        .iter()
                        .filter(|(_, session)| {
                            session.task.is_finished()
                                || now.saturating_sub(session.last_used.load(Ordering::Relaxed))
                                    >= timeout_ms
                        })
                        .map(|(id, _)| *id)
                        .collect();
                    ids.into_iter()
                        .filter_map(|id| guard.remove(&id))
                        .collect::<Vec<_>>()
                };
                for session in stale {
                    session.cancel.cancel();
                    session.task.abort();
                }
            }
        }
    }
}

/// 单个 UDP 会话：解析目标、维护一个 IPv4/IPv6 无连接套接字，并把回包送回 QUIC。
async fn udp_session_loop(mut receiver: mpsc::Receiver<UdpPacket>, info: Arc<UdpSessionInfo>) {
    let _gauge = info.shared.stats.enter(Gauge::Udp);
    let mut defrag = Defrag::new();
    let mut sockets: [Option<Arc<UdpSocket>>; 2] = [None, None];
    let mut readers: Vec<JoinHandle<()>> = Vec::new();
    let mut targets: HashMap<Target, UdpTarget> = HashMap::new();

    loop {
        tokio::select! {
            biased;
            _ = info.cancel.cancelled() => break,
            packet = receiver.recv() => {
                let Some(packet) = packet else { break; };
                info.touch();
                defrag.expire();
                let Some(mut packet) = defrag.feed(packet) else {
                    continue;
                };
                if packet.payload.len() > info.max_udp_payload {
                    info.shared.stats.drop_packet();
                    continue;
                }
                if packet._budget.is_none() {
                    match reserve_budget(&info.shared, packet.payload.len()) {
                        Some(budget) => packet._budget = Some(budget),
                        None => {
                            info.shared.stats.drop_packet();
                            continue;
                        }
                    }
                }
                let target = match address_to_target(&packet.destination) {
                    Ok(target) => target,
                    Err(_) => {
                        info.shared.stats.drop_packet();
                        continue;
                    }
                };
                // 先选路：`udp_selected` 会拒绝 reject 规则、HTTP 出站与链式出站，
                // 并允许代理出站；`allowed` 只允许直连，会让 TUIC 的 UDP 在
                // 链式部署下直接失败。
                let (proxied, rule_resolved) =
                    match info.shared.udp_selected(&info.tag, &target).await {
                        Ok(selected) => match selected.udp_proxied() {
                            // 规则阶段解析过的地址要复用，见 hysteria2 同处注释。
                            Ok(proxied) => (
                                proxied,
                                selected
                                    .resolved_addresses()
                                    .map(<[SocketAddr]>::to_vec),
                            ),
                            Err(_) => continue,
                        },
                        Err(_) => {
                            // 路由拒绝已在 Context 分类并计入 rejected，这里不重复计数。
                            continue;
                        }
                    };
                // 路由变化可能改变同一目标的出站方式；旧映射不再适用。
                if targets
                    .get(&target)
                    .is_some_and(|entry| entry.is_proxied() != proxied)
                {
                    targets.remove(&target);
                }

                if proxied {
                    if !targets.contains_key(&target) {
                        if targets.len() >= info.max_udp_targets {
                            info.shared.stats.drop_packet();
                            continue;
                        }
                        let Ok(outlet) = crate::udp::RoutedUdp::new(
                            info.shared.clone(),
                            info.tag.clone(),
                            target.clone(),
                        )
                        .await
                        else {
                            info.shared.stats.drop_packet();
                            continue;
                        };
                        let (outgoing, rx) = mpsc::channel::<crate::udp::QueuedUplink>(64);
                        let task = spawn_proxied_reply_reader(target.clone(), outlet, rx, info.clone());
                        targets.insert(
                            target.clone(),
                            UdpTarget::Proxied { outgoing, task },
                        );
                    }
                    let Some(UdpTarget::Proxied { outgoing, .. }) = targets.get(&target) else {
                        info.shared.stats.drop_packet();
                        continue;
                    };
                    let Some(queued) =
                        crate::udp::QueuedUplink::reserve(&info.shared, packet.payload.clone())
                    else {
                        info.shared.stats.drop_packet();
                        continue;
                    };
                    match outgoing.send(queued).await {
                        Ok(()) => {
                            info.shared
                                .stats
                                .uplink
                                .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
                            if let Some(traffic) = &info.traffic {
                                traffic.add(true, packet.payload.len());
                            }
                            info.touch();
                        }
                        Err(_) => info.shared.stats.drop_packet(),
                    }
                    continue;
                }

                let address = if let Some(entry) = targets.get(&target) {
                    match entry {
                        UdpTarget::Direct(address) => *address,
                        // 已验证 `proxied` 为假，不会走到这里。
                        UdpTarget::Proxied { .. } => continue,
                    }
                } else {
                    if targets.len() >= info.max_udp_targets {
                        info.shared.stats.drop_packet();
                        continue;
                    }
                    let addresses = match &rule_resolved {
                        Some(addresses) => Ok(addresses.clone()),
                        None => info.shared.dns.resolve(&target).await,
                    };
                    let resolved = match addresses {
                        Ok(addresses) => match addresses.first().copied() {
                            Some(address) => address,
                            None => {
                                info.shared.stats.drop_packet();
                                continue;
                            }
                        },
                        Err(_) => {
                            info.shared.stats.drop_packet();
                            continue;
                        }
                    };
                    targets.insert(target.clone(), UdpTarget::Direct(resolved));
                    resolved
                };

                let index = if address.is_ipv6() { 1 } else { 0 };
                if sockets[index].is_none() {
                    let bind = if index == 0 {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                    } else {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                    };
                    let Ok(socket) = UdpSocket::bind(bind).await else {
                        info.shared.stats.drop_packet();
                        continue;
                    };
                    let socket = Arc::new(socket);
                    readers.push(spawn_reply_reader(socket.clone(), info.clone()));
                    sockets[index] = Some(socket);
                }
                let Some(socket) = sockets[index].as_ref() else {
                    continue;
                };
                match socket.send_to(&packet.payload, address).await {
                    Ok(sent) => {
                        info.shared
                            .stats
                            .uplink
                            .fetch_add(sent as u64, Ordering::Relaxed);
                        if let Some(traffic) = &info.traffic {
                            traffic.add(true, sent);
                        }
                        info.touch();
                    }
                    Err(_) => info.shared.stats.drop_packet(),
                }
            }
        }
    }

    for reader in &readers {
        reader.abort();
    }
    let _ = timeout(SHUTDOWN_GRACE, async {
        for reader in readers {
            let _ = reader.await;
        }
    })
    .await;
}

struct UdpSessionInfo {
    shared: Arc<Context>,
    tag: String,
    /// 该 UDP 关联所属用户的累计字节；未认证时为 None。
    traffic: Option<Arc<crate::telemetry::UserCounters>>,
    max_udp_targets: usize,
    max_udp_payload: usize,
    connection: Connection,
    session_id: u16,
    carrier: Carrier,
    cancel: CancellationToken,
    last_used: Arc<AtomicU64>,
    packet_id: Arc<AtomicU16>,
}

impl UdpSessionInfo {
    fn touch(&self) {
        self.last_used.store(now_ms(), Ordering::Relaxed);
    }
}

/// 每个套接字一个读取任务：只做 `recv_from` 与回包，不接触 UDP 会话表。
/// 把会话目标转成线格式地址。
///
/// 放在这里而不是 `tuic/wire.rs`：那个文件是纯编解码模块（会被 `tests/tuic.rs`
/// 以 `#[path]` 复用），不应依赖 `session` 类型。
fn wire_address_of(target: &Target) -> wire::WireAddress {
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => wire::WireAddress::Ipv4 {
            octets: ip.octets(),
            port: target.port,
        },
        Host::Ip(IpAddr::V6(ip)) => wire::WireAddress::Ipv6 {
            octets: ip.octets(),
            port: target.port,
        },
        Host::Domain(name) => wire::WireAddress::Domain {
            name: name.clone(),
            port: target.port,
        },
    }
}

/// 单目标的出站方式。
///
/// 直连仍按地址族共享 socket（`sockets[0]`/`sockets[1]`），只记解析后的地址；
/// 代理出站每目标一个 `RoutedUdp`（它构造时固定目标，`recv()` 不带目标）。
enum UdpTarget {
    Direct(SocketAddr),
    Proxied {
        outgoing: mpsc::Sender<crate::udp::QueuedUplink>,
        /// 会话结束时 abort，避免任务挂在 `RoutedUdp::recv` 上。
        task: JoinHandle<()>,
    },
}

impl UdpTarget {
    fn is_proxied(&self) -> bool {
        matches!(self, Self::Proxied { .. })
    }
}

impl Drop for UdpTarget {
    fn drop(&mut self) {
        if let Self::Proxied { task, .. } = self {
            task.abort();
        }
    }
}

/// 代理目标的回程：从 `RoutedUdp` 读，报头用**构造时捕获的目标**。
///
/// 直连分支的回程地址来自 `recv_from` 的真实源地址；代理分支拿不到源地址
/// （SOCKS5 只回 payload），只能用原目标。这是 UDP 中继的固有限制，
/// 与共享 `Association` 的处理一致。
fn spawn_proxied_reply_reader(
    target: Target,
    mut outlet: crate::udp::RoutedUdp,
    mut outgoing: mpsc::Receiver<crate::udp::QueuedUplink>,
    info: Arc<UdpSessionInfo>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let destination = wire_address_of(&target);
        loop {
            tokio::select! {
                biased;
                _ = info.cancel.cancelled() => return,
                packet = outgoing.recv() => {
                    let Some(packet) = packet else { return };
                    if outlet.send(&packet.payload).await.is_err() {
                        return;
                    }
                }
                datagram = outlet.recv() => {
                    let Ok(datagram) = datagram else { return };
                    let payload = datagram.payload;
                    info.touch();
                    if payload.len() > info.max_udp_payload {
                        info.shared.stats.drop_packet();
                        continue;
                    }
                    let Some(_budget) = reserve_budget(&info.shared, payload.len()) else {
                        info.shared.stats.drop_packet();
                        continue;
                    };
                    let packet_id = info.packet_id.fetch_add(1, Ordering::Relaxed);
                    match send_udp_reply(
                        &info.connection,
                        info.carrier,
                        info.session_id,
                        packet_id,
                        &destination,
                        &payload,
                    )
                    .await
                    {
                        Ok(()) => {
                            info.shared
                                .stats
                                .downlink
                                .fetch_add(payload.len() as u64, Ordering::Relaxed);
                            if let Some(traffic) = &info.traffic {
                                traffic.add(false, payload.len());
                            }
                        }
                        Err(_) => info.shared.stats.drop_packet(),
                    }
                }
            }
        }
    })
}

fn spawn_reply_reader(socket: Arc<UdpSocket>, info: Arc<UdpSessionInfo>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65536];
        loop {
            tokio::select! {
                biased;
                _ = info.cancel.cancelled() => return,
                received = socket.recv_from(&mut buffer) => {
                    let Ok((length, source)) = received else { return; };
                    info.touch();
                    if length > info.max_udp_payload {
                        info.shared.stats.drop_packet();
                        continue;
                    }
                    let payload = buffer[..length].to_vec();
                    let Some(_budget) = reserve_budget(&info.shared, payload.len()) else {
                        info.shared.stats.drop_packet();
                        continue;
                    };
                    let destination = wire::WireAddress::from_socket(source);
                    let packet_id = info.packet_id.fetch_add(1, Ordering::Relaxed);
                    match send_udp_reply(
                        &info.connection,
                        info.carrier,
                        info.session_id,
                        packet_id,
                        &destination,
                        &payload,
                    )
                    .await
                    {
                        Ok(()) => {
                            info.shared
                                .stats
                                .downlink
                                .fetch_add(payload.len() as u64, Ordering::Relaxed);
                            if let Some(traffic) = &info.traffic {
                                traffic.add(false, payload.len());
                            }
                        }
                        Err(_) => info.shared.stats.drop_packet(),
                    }
                }
            }
        }
    })
}

/// 发送一条 UDP 消息。数据报模式按协商 MTU 分片；单向流模式每条消息一条流。
async fn send_udp_reply(
    connection: &Connection,
    carrier: Carrier,
    session_id: u16,
    packet_id: u16,
    destination: &wire::WireAddress,
    payload: &[u8],
) -> io::Result<()> {
    match carrier {
        Carrier::Stream => {
            let body = wire::encode_udp_body(session_id, packet_id, 1, 0, destination, payload)
                .map_err(wire_error)?;
            let mut frame = Vec::with_capacity(2 + body.len());
            frame.push(wire::VERSION);
            frame.push(wire::COMMAND_PACKET);
            frame.extend_from_slice(&body);
            let mut stream = timeout(STREAM_WRITE_TIMEOUT, connection.open_uni())
                .await
                .map_err(|_| timed_out())?
                .map_err(|_| io::Error::other("TUIC 单向流打开失败"))?;
            timeout(STREAM_WRITE_TIMEOUT, stream.write_all(&frame))
                .await
                .map_err(|_| timed_out())?
                .map_err(|_| io::Error::other("TUIC 单向流写入失败"))?;
            let _ = stream.finish();
            Ok(())
        }
        Carrier::Datagram => {
            let maximum = connection
                .max_datagram_size()
                .ok_or_else(|| io::Error::other("TUIC 对端未协商数据报"))?;
            let header = 2 + wire::UDP_FIXED_LEN + wire::address_len(destination);
            if maximum <= header {
                return Err(io::Error::other("TUIC 数据报容量不足"));
            }
            let chunk = maximum - header;
            let total = if payload.is_empty() {
                1
            } else {
                payload.len().div_ceil(chunk)
            };
            if total > usize::from(wire::MAX_FRAGMENTS) {
                return Err(io::Error::other("TUIC 数据报分片过多"));
            }
            if total == 1 {
                let body = wire::encode_udp_body(session_id, packet_id, 1, 0, destination, payload)
                    .map_err(wire_error)?;
                let mut frame = Vec::with_capacity(2 + body.len());
                frame.push(wire::VERSION);
                frame.push(wire::COMMAND_PACKET);
                frame.extend_from_slice(&body);
                return send_datagram(connection, &frame).await;
            }
            for (index, part) in payload.chunks(chunk).enumerate() {
                let fragment = if index == 0 {
                    destination.clone()
                } else {
                    wire::WireAddress::Empty
                };
                let body = wire::encode_udp_body(
                    session_id,
                    packet_id,
                    total as u8,
                    index as u8,
                    &fragment,
                    part,
                )
                .map_err(wire_error)?;
                let mut frame = Vec::with_capacity(2 + body.len());
                frame.push(wire::VERSION);
                frame.push(wire::COMMAND_PACKET);
                frame.extend_from_slice(&body);
                send_datagram(connection, &frame).await?;
            }
            Ok(())
        }
    }
}

async fn send_datagram(connection: &Connection, frame: &[u8]) -> io::Result<()> {
    timeout(
        STREAM_WRITE_TIMEOUT,
        connection.send_datagram_wait(frame.to_vec().into()),
    )
    .await
    .map_err(|_| timed_out())?
    .map_err(|_| io::Error::other("TUIC 数据报发送失败"))
}

/// 上行 UDP 消息（已通过线格式校验）。
struct UdpPacket {
    session_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    destination: wire::WireAddress,
    payload: Vec<u8>,
    /// 队列内存预算；None 表示尚未计入（分片重组完成后的消息）。
    _budget: Option<OwnedSemaphorePermit>,
}

impl UdpPacket {
    fn with_budget(mut self, budget: OwnedSemaphorePermit) -> Self {
        self._budget = Some(budget);
        self
    }
}

/// 分片重组；只保留有限组数、有限字节，超时即丢弃。
struct Defrag {
    groups: HashMap<u16, FragGroup>,
    bytes: usize,
}

struct FragGroup {
    total: u8,
    parts: Vec<Option<Vec<u8>>>,
    received: u8,
    bytes: usize,
    destination: Option<wire::WireAddress>,
    updated: Instant,
}

impl FragGroup {
    fn new(total: u8) -> Self {
        Self {
            total,
            parts: (0..total).map(|_| None).collect(),
            received: 0,
            bytes: 0,
            destination: None,
            updated: Instant::now(),
        }
    }
}

impl Defrag {
    fn new() -> Self {
        Self {
            groups: HashMap::new(),
            bytes: 0,
        }
    }

    fn feed(&mut self, packet: UdpPacket) -> Option<UdpPacket> {
        let UdpPacket {
            session_id,
            packet_id,
            fragment_total,
            fragment_id,
            destination,
            payload,
            _budget,
        } = packet;
        if fragment_total <= 1 {
            if matches!(destination, wire::WireAddress::Empty) {
                return None;
            }
            return Some(UdpPacket {
                session_id,
                packet_id,
                fragment_total,
                fragment_id,
                destination,
                payload,
                _budget,
            });
        }

        if !self.groups.contains_key(&packet_id) {
            if self.groups.len() >= UDP_REASSEMBLY_GROUPS {
                // 组数已满时丢弃整张表，保持严格上界；攻击者无法借此无限占用内存。
                self.groups.clear();
                self.bytes = 0;
                return None;
            }
            self.groups
                .insert(packet_id, FragGroup::new(fragment_total));
        }

        let mut added = 0usize;
        let mut overflow = false;
        {
            let group = self.groups.get_mut(&packet_id)?;
            if group.total != fragment_total {
                self.bytes = self.bytes.saturating_sub(group.bytes);
                *group = FragGroup::new(fragment_total);
            }
            let index = usize::from(fragment_id);
            if index >= group.parts.len() || group.parts[index].is_some() {
                return None;
            }
            if fragment_id == 0 {
                if matches!(destination, wire::WireAddress::Empty) {
                    return None;
                }
                group.destination = Some(destination);
            }
            let length = payload.len();
            if group.bytes.saturating_add(length) > UDP_REASSEMBLY_BYTES
                || self.bytes.saturating_add(length) > UDP_REASSEMBLY_BYTES
            {
                overflow = true;
            } else {
                group.bytes += length;
                group.received += 1;
                group.updated = Instant::now();
                group.parts[index] = Some(payload);
                added = length;
            }
        }
        if overflow {
            if let Some(group) = self.groups.remove(&packet_id) {
                self.bytes = self.bytes.saturating_sub(group.bytes);
            }
            return None;
        }
        self.bytes = self.bytes.saturating_add(added);

        let complete = self
            .groups
            .get(&packet_id)
            .is_some_and(|group| group.received == group.total);
        if !complete {
            return None;
        }
        let group = self.groups.remove(&packet_id)?;
        self.bytes = self.bytes.saturating_sub(group.bytes);
        let destination = group.destination?;
        if group.bytes > wire::MAX_UDP_DATA {
            return None;
        }
        let mut payload = Vec::with_capacity(group.bytes);
        for part in group.parts {
            payload.extend_from_slice(&part?);
        }
        Some(UdpPacket {
            session_id,
            packet_id,
            fragment_total: 1,
            fragment_id: 0,
            destination,
            payload,
            _budget: None,
        })
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.groups
            .retain(|_, group| now.duration_since(group.updated) < UDP_REASSEMBLY_TIMEOUT);
        self.bytes = self.groups.values().map(|group| group.bytes).sum();
    }
}

/// 从单向流读取一条 UDP 消息；地址与数据长度都先检查上界再分配。
async fn read_udp_stream(stream: &mut RecvStream, max_payload: usize) -> io::Result<UdpPacket> {
    let mut fixed_bytes = [0u8; wire::UDP_FIXED_LEN];
    read_exact(stream, &mut fixed_bytes).await?;
    let fixed = wire::decode_udp_fixed(&fixed_bytes).map_err(wire_error)?;
    wire::validate_fragment(fixed.fragment_total, fixed.fragment_id).map_err(wire_error)?;
    let data_len = usize::from(fixed.data_len);
    if data_len > max_payload {
        return Err(protocol("TUIC UDP 载荷超限"));
    }
    let destination = read_address(stream).await?;
    let mut payload = vec![0u8; data_len];
    read_exact(stream, &mut payload).await?;
    Ok(UdpPacket {
        session_id: fixed.session_id,
        packet_id: fixed.packet_id,
        fragment_total: fixed.fragment_total,
        fragment_id: fixed.fragment_id,
        destination,
        payload,
        _budget: None,
    })
}

/// 从流中增量读取地址；先读族字节，再按族读取精确长度，最后交给统一校验。
async fn read_address(stream: &mut RecvStream) -> io::Result<wire::WireAddress> {
    let mut family = [0u8; 1];
    read_exact(stream, &mut family).await?;
    let mut bytes = Vec::with_capacity(wire::MAX_ADDRESS_LEN);
    bytes.push(family[0]);
    match family[0] {
        wire::FAMILY_EMPTY => return Ok(wire::WireAddress::Empty),
        wire::FAMILY_IPV4 | wire::FAMILY_IPV6 => {
            let length = if family[0] == wire::FAMILY_IPV4 {
                6
            } else {
                18
            };
            let start = bytes.len();
            bytes.resize(start + length, 0);
            read_exact(stream, &mut bytes[start..]).await?;
        }
        wire::FAMILY_DOMAIN => {
            let mut length = [0u8; 1];
            read_exact(stream, &mut length).await?;
            if length[0] == 0 {
                return Err(protocol("TUIC 域名为空"));
            }
            bytes.push(length[0]);
            let start = bytes.len();
            bytes.resize(start + usize::from(length[0]) + 2, 0);
            read_exact(stream, &mut bytes[start..]).await?;
        }
        _ => return Err(protocol("TUIC 地址族不支持")),
    }
    let (address, used) = wire::decode_address(&bytes).map_err(wire_error)?;
    if used != bytes.len() {
        return Err(protocol("TUIC 地址长度不匹配"));
    }
    Ok(address)
}

async fn read_exact(stream: &mut RecvStream, buffer: &mut [u8]) -> io::Result<()> {
    timeout(STREAM_READ_TIMEOUT, stream.read_exact(buffer))
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "TUIC 流读取失败"))
}

fn reserve_budget(ctx: &Context, length: usize) -> Option<OwnedSemaphorePermit> {
    let amount = length.max(1).min(u32::MAX as usize) as u32;
    ctx.udp_bytes.clone().try_acquire_many_owned(amount).ok()
}

fn address_to_target(address: &wire::WireAddress) -> io::Result<Target> {
    let (host, port) = match address {
        wire::WireAddress::Ipv4 { octets, port } => {
            (Host::Ip(IpAddr::V4(Ipv4Addr::from(*octets))), *port)
        }
        wire::WireAddress::Ipv6 { octets, port } => {
            (Host::Ip(IpAddr::V6(Ipv6Addr::from(*octets))), *port)
        }
        wire::WireAddress::Domain { name, port } => {
            (Host::Domain(name.to_ascii_lowercase()), *port)
        }
        wire::WireAddress::Empty => return Err(protocol("TUIC 目标地址为空")),
    };
    if port == 0 {
        return Err(protocol("TUIC 目标端口为 0"));
    }
    Ok(Target { host, port })
}

fn lookup_user(users: &[Credential], uuid: &[u8; 16]) -> Option<usize> {
    let mut found = None;
    for (index, user) in users.iter().enumerate() {
        if wire::ct_eq(&user.uuid, uuid) {
            found = Some(index);
        }
    }
    found
}

async fn wait_auth(auth: &mut watch::Receiver<AuthState>) -> Option<usize> {
    loop {
        match *auth.borrow_and_update() {
            AuthState::Authenticated(index) => return Some(index),
            AuthState::Failed => return None,
            AuthState::Pending => {}
        }
        if auth.changed().await.is_err() {
            return None;
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn wire_error(error: wire::WireError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn protocol(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TUIC 操作超时")
}

/// 把 quinn 的分离读写流组合成 `AsyncRead + AsyncWrite`，供 `forward::relay` 使用。
struct QuicStream<R = RecvStream> {
    send: SendStream,
    recv: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for QuicStream<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(context, buffer)
    }
}

impl<R: Unpin> AsyncWrite for QuicStream<R> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        // quinn 的同名固有方法返回 `WriteError`，这里需要 tokio 的 `AsyncWrite` 实现。
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(context)
    }
}
