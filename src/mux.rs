//! Xray Mux.Cool 服务端多路复用。
//!
//! 该模块只处理「已认证的 VLESS/VMess 字节流」之上的 Mux 帧，不负责发出
//! VLESS/VMess 应答。帧格式按 Xray `common/mux` 的线协议独立实现：
//!
//! ```text
//! 2 字节 metaLen
//! metaLen 字节元数据：
//!   2 字节 session id
//!   1 字节 status（1 New / 2 Keep / 3 End / 4 KeepAlive）
//!   1 字节 option（0x01 Data / 0x02 Error）
//!   New 时追加：1 字节 network、2 字节端口、类型化地址
//!   Keep+Data 且 network 为 UDP 时同样追加 UDP 目标
//!   可选 8 字节 GlobalID（仅 New+UDP+Data）
//! 若 option 含 Data：2 字节数据长度 + 数据
//! ```
//!
//! 数据长度不在 metaLen 内；这一点与 Xray 的 `writeMetaWithFrame` 一致。
//! 所有长度和数量都有界，畸形帧直接以错误结束整条 Mux 连接。

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::{AbortHandle, JoinSet},
    time::{Instant, sleep_until, timeout, timeout_at},
};

use crate::{
    forward::{Context, Lease, PayloadSniff},
    route::ProxyOutbound,
    session::{Host, Network, Target},
    telemetry::{Gauge, Guard},
};

/// 上游约定的 Mux 哨兵域名。
const MUX_TARGET: &str = "v1.mux.cool";
/// 元数据上限，含 session id/status/option 与地址；超出即拒绝整条连接。
const MAX_META: usize = 512;
/// 单条 Mux 连接的并发会话上限。
const MAX_SESSIONS: usize = 256;
/// 进程级 GlobalID 去重表上限。
const MAX_GLOBAL_IDS: usize = 256;
/// 最后一个 Mux 会话结束后，GlobalID 关联的保留时间。
///
/// 与 Xray `common/mux` 一致：会话进入 Expiring 后保留 1 分钟，期间新 Mux
/// 连接可以用同一 GlobalID 续接原 UDP 关联；到期后关闭套接字。
const GLOBAL_GRACE: Duration = Duration::from_secs(60);
/// 每会话上行队列容量，同时用于读/写/事件通道。
const QUEUE_PACKETS: usize = 64;
/// 单条 Mux 连接的读写队列字节预算。
const QUEUE_BYTES: usize = 256 * 1024;
/// 无会话且无数据时的整条连接空闲上限。
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// 单次 TCP 上行写入/下行读取的缓冲大小。
const BRIDGE_BUFFER: usize = 16 * 1024;
/// 清理阶段等待写任务结束的时间。
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEP_ALIVE: u8 = 0x04;

const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;

const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;

/// 判断 VLESS/VMess 请求的目标是否为 Mux 哨兵域名。
pub(crate) fn is_mux_target(target: &Target) -> bool {
    matches!(&target.host, Host::Domain(name) if name == MUX_TARGET)
}

/// 在已认证的 VLESS/VMess 流上运行 Mux 服务端。
///
/// `allow_udp` 来自入站 `xudp` 开关：命令 3 的 TCP 会话始终允许，但 Mux 内的
/// UDP New/GlobalID 仅在为 `true` 时准入。
pub(crate) async fn serve<S>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
    allow_udp: bool,
    user: Option<&str>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_scoped(stream, ctx, inbound, allow_udp, None, user).await
}

/// 与 [`serve`] 相同，并按上层 RPC 生命周期持有租约。
pub(crate) async fn serve_scoped<S>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
    allow_udp: bool,
    lease: Option<Lease>,
    user: Option<&str>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _lease = lease;
    // Mux 的子流在上层握手时已完成认证，这里只需把用户身份带给每条子流，
    // 否则客户开 mux 后该用户的流量完全不计入 `/stats/users`。
    let user_counter = user.map(|name| ctx.stats.user_counter(&inbound, name));
    let (read, write) = tokio::io::split(stream);
    let inbound_budget = Arc::new(Semaphore::new(QUEUE_BYTES));
    let out_budget = Arc::new(Semaphore::new(QUEUE_BYTES));
    let (frames_tx, mut frames_rx) = mpsc::channel::<ReadItem>(QUEUE_PACKETS);
    let (events_tx, mut events_rx) = mpsc::channel::<Event>(QUEUE_PACKETS);
    let (out_tx, out_rx) = mpsc::channel::<OutFrame>(QUEUE_PACKETS);

    let mut reader_task = AbortTask(tokio::spawn(read_loop(
        read,
        frames_tx,
        inbound_budget.clone(),
    )));
    let mut writer_task = AbortTask(tokio::spawn(write_loop(write, out_rx, ctx.clone())));
    let mut mux = Mux {
        ctx,
        inbound,
        allow_udp,
        sessions: HashMap::new(),
        tasks: JoinSet::new(),
        events: events_tx,
        out: out_tx,
        inbound_budget,
        out_budget,
        user_counter,
        user_id: user.map(str::to_owned),
    };

    let mut last_activity = Instant::now();
    let mut writer_done = false;

    let result = loop {
        tokio::select! {
            _ = sleep_until(last_activity + IDLE_TIMEOUT) => {
                if mux.sessions.is_empty() {
                    break Ok(());
                }
                // 仍有会话时不关闭连接，只推迟下一次检查。
                last_activity = Instant::now();
            }
            joined = &mut writer_task.0 => {
                writer_done = true;
                break match joined {
                    Ok(result) => result,
                    Err(error) => Err(io::Error::other(error)),
                };
            }
            item = frames_rx.recv() => {
                match item {
                    Some(ReadItem::Frame(frame)) => {
                        last_activity = Instant::now();
                        if let Err(error) = mux.handle_frame(frame).await {
                            break Err(error);
                        }
                    }
                    Some(ReadItem::Error(error)) => break Err(error),
                    // 帧边界的干净 EOF。
                    None => break Ok(()),
                }
            }
            item = events_rx.recv() => {
                if let Some(event) = item {
                    last_activity = Instant::now();
                    if let Err(error) = mux.handle_event(event).await {
                        break Err(error);
                    }
                }
            }
        }
    };

    // 先关闭会话与任务，再释放写通道，最后等待 writer 退出。
    for (_, session) in mux.sessions.drain() {
        session.close().await;
    }
    mux.tasks.abort_all();
    while mux.tasks.join_next().await.is_some() {}
    reader_task.0.abort();
    let _ = (&mut reader_task.0).await;
    drop(mux);
    if !writer_done {
        match timeout(SHUTDOWN_TIMEOUT, &mut writer_task.0).await {
            Ok(_) => {}
            Err(_) => {
                writer_task.0.abort();
                let _ = (&mut writer_task.0).await;
            }
        }
    }
    result
}

/// 帧状态；数值与 Xray `SessionStatus` 一致。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    New,
    Keep,
    End,
    KeepAlive,
}

/// 已完成边界读取的负载，持有入站字节预算直到被消费。
pub(crate) struct Chunk {
    pub(crate) payload: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

/// 一帧已完成解析的 Mux 元数据与可选负载。
pub(crate) struct Frame {
    pub(crate) id: u16,
    pub(crate) status: Status,
    pub(crate) option: u8,
    pub(crate) network: Option<Network>,
    pub(crate) target: Option<Target>,
    pub(crate) global_id: Option<[u8; 8]>,
    pub(crate) payload: Option<Chunk>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn read_length<R: AsyncRead + Unpin>(read: &mut R) -> io::Result<Option<u16>> {
    let mut first = [0u8; 1];
    if read.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let mut second = [0u8; 1];
    read.read_exact(&mut second).await?;
    Ok(Some(u16::from_be_bytes([first[0], second[0]])))
}

/// 读取一帧；仅在帧边界的干净 EOF 返回 `None`。
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    read: &mut R,
    budget: &Arc<Semaphore>,
) -> io::Result<Option<Frame>> {
    let length = match read_length(read).await? {
        Some(length) => usize::from(length),
        None => return Ok(None),
    };
    if !(4..=MAX_META).contains(&length) {
        return Err(invalid("Mux 元数据长度错误"));
    }
    let mut buffer = [0u8; MAX_META];
    read.read_exact(&mut buffer[..length]).await?;
    let meta = &buffer[..length];

    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = match meta[2] {
        STATUS_NEW => Status::New,
        STATUS_KEEP => Status::Keep,
        STATUS_END => Status::End,
        STATUS_KEEP_ALIVE => Status::KeepAlive,
        _ => return Err(invalid("Mux 状态错误")),
    };
    let option = meta[3];
    if option & !(OPTION_DATA | OPTION_ERROR) != 0 {
        return Err(invalid("Mux 选项错误"));
    }

    let mut network = None;
    let mut target = None;
    let mut global_id = None;
    match status {
        Status::New => {
            let (parsed_network, parsed_target, used) = parse_network_target(meta, 4)?;
            network = Some(parsed_network);
            target = Some(parsed_target);
            // GlobalID 只在 New+UDP+Data 时存在；全零值由上层忽略。
            if parsed_network == Network::Udp && option & OPTION_DATA != 0 {
                let rest = &meta[4 + used..];
                if rest.len() >= 8 {
                    let mut value = [0u8; 8];
                    value.copy_from_slice(&rest[..8]);
                    global_id = Some(value);
                }
            }
        }
        Status::Keep if option & OPTION_DATA != 0 && meta.len() > 4 && meta[4] == NETWORK_UDP => {
            let (parsed_network, parsed_target, _) = parse_network_target(meta, 4)?;
            if parsed_network != Network::Udp {
                return Err(invalid("Mux Keep 网络错误"));
            }
            network = Some(Network::Udp);
            target = Some(parsed_target);
        }
        _ => {}
    }

    let payload = if option & OPTION_DATA != 0 {
        let size = usize::from(read.read_u16().await?);
        let permit = budget
            .clone()
            .acquire_many_owned(size.max(1) as u32)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Mux 入站预算关闭"))?;
        let mut payload = vec![0u8; size];
        read.read_exact(&mut payload).await?;
        Some(Chunk {
            payload,
            _budget: permit,
        })
    } else {
        None
    };

    Ok(Some(Frame {
        id,
        status,
        option,
        network,
        target,
        global_id,
        payload,
    }))
}

/// 解析 network（1 TCP / 2 UDP）、端口、地址；返回消费的元数据字节数。
fn parse_network_target(meta: &[u8], offset: usize) -> io::Result<(Network, Target, usize)> {
    let network = match *meta
        .get(offset)
        .ok_or_else(|| invalid("Mux 缺少网络字段"))?
    {
        NETWORK_TCP => Network::Tcp,
        NETWORK_UDP => Network::Udp,
        _ => return Err(invalid("Mux 网络类型错误")),
    };
    let port_high = *meta
        .get(offset + 1)
        .ok_or_else(|| invalid("Mux 缺少端口"))?;
    let port_low = *meta
        .get(offset + 2)
        .ok_or_else(|| invalid("Mux 缺少端口"))?;
    let port = u16::from_be_bytes([port_high, port_low]);
    let address_type = *meta
        .get(offset + 3)
        .ok_or_else(|| invalid("Mux 缺少地址类型"))?;

    let mut cursor = offset + 4;
    let host = match address_type {
        1 => {
            let octets = meta
                .get(cursor..cursor + 4)
                .ok_or_else(|| invalid("Mux IPv4 地址被截断"))?;
            cursor += 4;
            Host::Ip(
                Ipv4Addr::from(
                    <[u8; 4]>::try_from(octets).map_err(|_| invalid("Mux IPv4 地址错误"))?,
                )
                .into(),
            )
        }
        2 => {
            let length = usize::from(
                *meta
                    .get(cursor)
                    .ok_or_else(|| invalid("Mux 缺少域名长度"))?,
            );
            cursor += 1;
            if length == 0 {
                return Err(invalid("Mux 域名长度无效"));
            }
            let domain = meta
                .get(cursor..cursor + length)
                .ok_or_else(|| invalid("Mux 域名被截断"))?;
            cursor += length;
            if !domain.iter().all(u8::is_ascii_graphic) {
                return Err(invalid("Mux 域名无效"));
            }
            let domain = std::str::from_utf8(domain).map_err(|_| invalid("Mux 域名无效"))?;
            Host::Domain(domain.to_owned())
        }
        3 => {
            let octets = meta
                .get(cursor..cursor + 16)
                .ok_or_else(|| invalid("Mux IPv6 地址被截断"))?;
            cursor += 16;
            Host::Ip(
                Ipv6Addr::from(
                    <[u8; 16]>::try_from(octets).map_err(|_| invalid("Mux IPv6 地址错误"))?,
                )
                .into(),
            )
        }
        _ => return Err(invalid("Mux 地址类型错误")),
    };

    Ok((network, Target { host, port }, cursor - offset))
}

fn encode_target(meta: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            meta.push(1);
            meta.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            meta.push(3);
            meta.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 255
                || !domain.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Mux 目标域名无效",
                ));
            }
            meta.push(2);
            meta.push(domain.len() as u8);
            meta.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

/// 编码服务端下行数据帧。上游响应始终使用 Keep（`NewResponseWriter` 的
/// `followup` 从 true 开始）；UDP 响应携带实际来源地址。
pub(crate) fn encode_data(id: u16, target: Option<&Target>, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(invalid("Mux 下行载荷过长"));
    }
    let mut meta = Vec::with_capacity(4 + 1 + 2 + 1 + 255);
    meta.extend_from_slice(&id.to_be_bytes());
    meta.push(STATUS_KEEP);
    meta.push(OPTION_DATA);
    if let Some(target) = target {
        meta.push(NETWORK_UDP);
        meta.extend_from_slice(&target.port.to_be_bytes());
        encode_target(&mut meta, target)?;
    }
    if meta.len() > MAX_META {
        return Err(invalid("Mux 下行元数据过长"));
    }
    let mut bytes = Vec::with_capacity(2 + meta.len() + 2 + payload.len());
    bytes.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&meta);
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// 编码客户端 New 帧（反向 Mux 的 portal 侧使用）。
pub(crate) fn encode_new(
    id: u16,
    network: Network,
    target: &Target,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(invalid("Mux 上行载荷过长"));
    }
    let mut meta = Vec::with_capacity(4 + 1 + 2 + 1 + 255);
    meta.extend_from_slice(&id.to_be_bytes());
    meta.push(STATUS_NEW);
    meta.push(if payload.is_empty() { 0 } else { OPTION_DATA });
    meta.push(match network {
        Network::Tcp => NETWORK_TCP,
        Network::Udp => NETWORK_UDP,
    });
    meta.extend_from_slice(&target.port.to_be_bytes());
    encode_target(&mut meta, target)?;
    if meta.len() > MAX_META {
        return Err(invalid("Mux 上行元数据过长"));
    }
    let mut bytes = Vec::with_capacity(2 + meta.len() + 2 + payload.len());
    bytes.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&meta);
    if !payload.is_empty() {
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(payload);
    }
    Ok(bytes)
}

/// 编码 End 帧；`error` 对应 OptionError。
pub(crate) fn encode_end(id: u16, error: bool) -> Vec<u8> {
    let [high, low] = id.to_be_bytes();
    vec![
        0,
        4,
        high,
        low,
        STATUS_END,
        if error { OPTION_ERROR } else { 0 },
    ]
}

/// 写入通道中的帧，持有出站字节预算直到真正写完。
struct OutFrame {
    bytes: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

/// 会话任务回报给主循环的事件。
enum Event {
    TcpData {
        id: u16,
        generation: u64,
        payload: Vec<u8>,
        _budget: OwnedSemaphorePermit,
    },
    TcpEnd {
        id: u16,
        generation: u64,
        error: bool,
    },
    UdpReply {
        key: u64,
        owner: u64,
        target: Target,
        payload: Vec<u8>,
        _budget: OwnedSemaphorePermit,
    },
    /// GlobalID 被新连接接管时，通知旧连接关闭旧会话。
    ForceEnd { key: u64, owner: u64 },
}

enum Session {
    Tcp {
        generation: u64,
        uplink: mpsc::Sender<Chunk>,
        task: AbortHandle,
        _gauge: Guard,
    },
    Udp {
        generation: u64,
        association: UdpAssociation,
        initial: Target,
        _gauge: Guard,
    },
}

impl Session {
    fn generation(&self) -> u64 {
        match self {
            Session::Tcp { generation, .. } | Session::Udp { generation, .. } => *generation,
        }
    }

    async fn close(self) {
        match self {
            Session::Tcp { task, .. } => task.abort(),
            Session::Udp {
                association,
                generation,
                ..
            } => association.detach(generation).await,
        }
    }
}

enum SessionKind {
    Tcp(mpsc::Sender<Chunk>),
    Udp(UdpAssociation, Target),
}

struct Mux {
    ctx: Arc<Context>,
    inbound: String,
    /// 入站 `xudp` 开关；只门控 Mux 内的 UDP 会话。
    allow_udp: bool,
    sessions: HashMap<u16, Session>,
    tasks: JoinSet<()>,
    events: mpsc::Sender<Event>,
    out: mpsc::Sender<OutFrame>,
    inbound_budget: Arc<Semaphore>,
    out_budget: Arc<Semaphore>,
    /// 上层握手已认证的用户；用于给每条子流归因业务字节。
    user_counter: Option<Arc<crate::telemetry::UserCounters>>,
    /// 已认证用户名；GlobalID 续接必须按账户隔离。
    user_id: Option<String>,
}

impl Mux {
    async fn enqueue(&self, bytes: Vec<u8>) -> io::Result<()> {
        let permit = self
            .out_budget
            .clone()
            .acquire_many_owned(bytes.len().max(1) as u32)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Mux 写预算关闭"))?;
        self.out
            .send(OutFrame {
                bytes,
                _budget: permit,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Mux 写端关闭"))
    }

    fn discard(&self, payload: Option<Chunk>) {
        if payload.is_some() {
            self.ctx.stats.drop_packet();
        }
    }

    fn reap_tasks(&mut self) {
        // 会话任务完成后由 JoinSet 保留句柄；每帧/事件回收一次，避免长期连接堆积。
        while self.tasks.try_join_next().is_some() {}
    }

    async fn remove_session(&mut self, id: u16) -> Option<()> {
        // 关闭需要所有权，调用方只关心“是否确实移除了该会话”。
        let session = self.sessions.remove(&id)?;
        session.close().await;
        Some(())
    }

    async fn remove_if_generation(&mut self, id: u16, generation: u64) -> Option<()> {
        if self
            .sessions
            .get(&id)
            .is_none_or(|session| session.generation() != generation)
        {
            return None;
        }
        self.remove_session(id).await
    }

    async fn close_and_end(&mut self, id: u16, error: bool) -> io::Result<()> {
        self.remove_session(id).await;
        self.enqueue(encode_end(id, error)).await
    }

    fn find_udp(&self, key: u64, owner: u64) -> Option<u16> {
        self.sessions
            .iter()
            .find_map(|(&id, session)| match session {
                Session::Udp {
                    generation,
                    association,
                    ..
                } if *generation == owner && association.key() == key => Some(id),
                _ => None,
            })
    }

    async fn handle_frame(&mut self, frame: Frame) -> io::Result<()> {
        self.reap_tasks();
        let Frame {
            id,
            status,
            option,
            network,
            target,
            global_id,
            payload,
        } = frame;

        match status {
            Status::KeepAlive => {
                // 心跳携带的负载按规范丢弃。
                self.discard(payload);
            }
            Status::End => {
                self.remove_session(id).await;
                self.discard(payload);
            }
            Status::Keep => {
                if option & OPTION_ERROR != 0 {
                    // 对端声明出错：关闭会话，负载已随帧边界消费。
                    self.remove_session(id).await;
                    self.discard(payload);
                    return Ok(());
                }
                let Some(payload) = payload else {
                    return Ok(());
                };
                let kind = match self.sessions.get(&id) {
                    Some(Session::Tcp { uplink, .. }) => Some(SessionKind::Tcp(uplink.clone())),
                    Some(Session::Udp {
                        association,
                        initial,
                        ..
                    }) => Some(SessionKind::Udp(association.clone(), initial.clone())),
                    None => None,
                };
                match kind {
                    Some(SessionKind::Tcp(uplink)) => {
                        let deadline = Duration::from_millis(self.ctx.limits.dial_timeout_ms);
                        let sent = timeout(deadline, uplink.send(payload)).await;
                        if !sent.is_ok_and(|result| result.is_ok()) {
                            self.ctx.stats.drop_packet();
                            self.close_and_end(id, true).await?;
                        }
                    }
                    Some(SessionKind::Udp(association, initial)) => {
                        let target = target.unwrap_or(initial);
                        let deadline = Duration::from_millis(self.ctx.limits.dial_timeout_ms);
                        let sent =
                            timeout(deadline, association.send(target, &payload.payload)).await;
                        if !sent.is_ok_and(|result| result.is_ok()) {
                            self.ctx.stats.drop_packet();
                            self.close_and_end(id, true).await?;
                        }
                    }
                    None => {
                        // 未知会话：回 End 并丢弃负载，不中断整条连接。
                        self.ctx.stats.drop_packet();
                        self.enqueue(encode_end(id, false)).await?;
                    }
                }
            }
            Status::New => {
                // 同 id 重新 New 时先关闭旧会话，避免旧任务泄漏。
                self.remove_session(id).await;
                let Some(target) = target else {
                    return Err(invalid("Mux New 缺少目标"));
                };
                let network = network.ok_or_else(|| invalid("Mux New 缺少网络"))?;
                if self.sessions.len() >= MAX_SESSIONS {
                    self.ctx.stats.reject();
                    self.discard(payload);
                    self.enqueue(encode_end(id, true)).await?;
                    return Ok(());
                }
                // 每条**新子流**都要准入：承载在认证时已通过一次，但到期或
                // 配额用尽的账户不能再开新子流。
                if !self
                    .ctx
                    .stats
                    .admit_user(&self.inbound, self.user_id.as_deref())
                {
                    self.ctx.stats.reject();
                    self.discard(payload);
                    self.enqueue(encode_end(id, true)).await?;
                    return Ok(());
                }
                let generation = next_token();
                match network {
                    Network::Tcp => self.create_tcp(id, generation, target, payload).await?,
                    Network::Udp => {
                        self.create_udp(id, generation, target, global_id, payload)
                            .await?
                    }
                }
            }
        }
        Ok(())
    }

    async fn create_tcp(
        &mut self,
        id: u16,
        generation: u64,
        target: Target,
        payload: Option<Chunk>,
    ) -> io::Result<()> {
        let (uplink, incoming) = mpsc::channel::<Chunk>(QUEUE_PACKETS);
        let events = self.events.clone();
        let ctx = self.ctx.clone();
        let inbound = self.inbound.clone();
        let budget = self.inbound_budget.clone();
        let user = self.user_counter.clone();
        let tracker = ctx.children.clone();
        let task = self.tasks.spawn(tracker.track_future(async move {
            tcp_session(
                id, generation, target, incoming, events, ctx, inbound, budget, user,
            )
            .await;
        }));
        let gauge = self.ctx.stats.enter(Gauge::Tcp);
        self.sessions.insert(
            id,
            Session::Tcp {
                generation,
                uplink: uplink.clone(),
                task,
                _gauge: gauge,
            },
        );
        if let Some(chunk) = payload {
            let deadline = Duration::from_millis(self.ctx.limits.dial_timeout_ms);
            let sent = timeout(deadline, uplink.send(chunk)).await;
            if !sent.is_ok_and(|result| result.is_ok()) {
                self.ctx.stats.drop_packet();
                self.close_and_end(id, true).await?;
            }
        }
        Ok(())
    }

    async fn create_udp(
        &mut self,
        id: u16,
        generation: u64,
        target: Target,
        global_id: Option<[u8; 8]>,
        payload: Option<Chunk>,
    ) -> io::Result<()> {
        // 命令 3 本身表示 Mux；UDP 会话仍由入站 xudp 开关门控。
        // 被拒绝的只是一个会话，不能拖垮整条 Mux 连接。
        if !self.allow_udp {
            self.ctx.stats.reject();
            self.discard(payload);
            self.enqueue(encode_end(id, true)).await?;
            return Ok(());
        }
        // `udp_selected` 本身不会因 reverse 报错；这里一并拒绝，
        // 让会话在建立阶段就以 End 失败关闭，而不是等到发送才失败。
        let allowed = match self.ctx.udp_selected(&self.inbound, &target).await {
            Ok(selected) => selected.udp_proxied().is_ok(),
            Err(_) => false,
        };
        if !allowed {
            self.discard(payload);
            self.enqueue(encode_end(id, true)).await?;
            return Ok(());
        }
        let slot = match self.ctx.udp_slots.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                self.ctx.stats.reject();
                self.discard(payload);
                self.enqueue(encode_end(id, true)).await?;
                return Ok(());
            }
        };
        // 没有可验证账户身份时不做跨连接续接：客户端标识不能当凭据用。
        let association = match (
            global_id.filter(|value| *value != [0u8; 8]),
            self.user_id.as_deref(),
        ) {
            (Some(global_id), Some(user)) => match acquire_global(
                global_id,
                self.ctx.clone(),
                &self.inbound,
                user,
                next_token(),
                generation,
            ) {
                Some(association) => association,
                None => {
                    self.ctx.stats.reject();
                    self.discard(payload);
                    self.enqueue(encode_end(id, true)).await?;
                    return Ok(());
                }
            },
            _ => UdpAssociation::new(self.ctx.clone(), self.inbound.clone(), next_token()),
        };
        association.set_sink(self.events.clone(), generation, self.inbound_budget.clone());
        // 槽交给关联持有：GlobalID 关联进入宽限期后仍握有 socket，
        // 必须继续计入活动上限，否则宽限期等于一次免费的配额逃逸。
        association.hold_slot(slot);
        let gauge = self.ctx.stats.enter(Gauge::Udp);
        self.sessions.insert(
            id,
            Session::Udp {
                generation,
                association: association.clone(),
                initial: target.clone(),
                _gauge: gauge,
            },
        );
        if let Some(chunk) = payload {
            let deadline = Duration::from_millis(self.ctx.limits.dial_timeout_ms);
            let sent = timeout(deadline, association.send(target, &chunk.payload)).await;
            if !sent.is_ok_and(|result| result.is_ok()) {
                self.ctx.stats.drop_packet();
                self.close_and_end(id, true).await?;
            }
        }
        Ok(())
    }

    async fn handle_event(&mut self, event: Event) -> io::Result<()> {
        self.reap_tasks();
        match event {
            Event::TcpData {
                id,
                generation,
                payload,
                _budget,
            } => {
                let current = self.sessions.get(&id).is_some_and(|session| {
                    session.generation() == generation && matches!(session, Session::Tcp { .. })
                });
                if !current {
                    self.ctx.stats.drop_packet();
                    return Ok(());
                }
                let bytes = encode_data(id, None, &payload)?;
                self.ctx
                    .stats
                    .downlink
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                // 全局计数已在这里，补一份按用户的归因（此前 mux 只计上行
                // 的用户字节，下行完全不计）。
                if let Some(counter) = &self.user_counter {
                    counter.add(false, payload.len());
                }
                self.enqueue(bytes).await?;
            }
            Event::TcpEnd {
                id,
                generation,
                error,
            } => {
                if self.remove_if_generation(id, generation).await.is_some() {
                    self.enqueue(encode_end(id, error)).await?;
                }
            }
            Event::UdpReply {
                key,
                owner,
                target,
                payload,
                _budget,
            } => {
                if let Some(id) = self.find_udp(key, owner) {
                    let bytes = encode_data(id, Some(&target), &payload)?;
                    self.ctx
                        .stats
                        .downlink
                        .fetch_add(payload.len() as u64, Ordering::Relaxed);
                    if let Some(counter) = &self.user_counter {
                        counter.add(false, payload.len());
                    }
                    self.enqueue(bytes).await?;
                } else {
                    self.ctx.stats.drop_packet();
                }
            }
            Event::ForceEnd { key, owner } => {
                if let Some(id) = self.find_udp(key, owner)
                    && self.remove_if_generation(id, owner).await.is_some()
                {
                    self.enqueue(encode_end(id, true)).await?;
                }
            }
        }
        Ok(())
    }
}

/// 读任务向主循环交付的项；错误通过通道送达，避免把截断误判为正常 EOF。
enum ReadItem {
    Frame(Frame),
    Error(io::Error),
}

/// 持有 JoinHandle，退出作用域时中止任务。
///
/// 运行层强制停机可能直接丢弃 `serve_scoped` 的 future；若只持有裸
/// `JoinHandle`，读写任务会脱管并继续占用套接字。正常清理路径仍显式
/// abort/await，此处是取消路径的兜底。
struct AbortTask<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn read_loop<R: AsyncRead + Unpin>(
    mut read: R,
    frames: mpsc::Sender<ReadItem>,
    budget: Arc<Semaphore>,
) -> io::Result<()> {
    loop {
        match read_frame(&mut read, &budget).await {
            Ok(Some(frame)) => {
                if frames.send(ReadItem::Frame(frame)).await.is_err() {
                    return Ok(());
                }
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                // 错误同时经通道送达主循环；通道需要独立所有权，故重建一份等价错误。
                let relayed = io::Error::new(error.kind(), error.to_string());
                let _ = frames.send(ReadItem::Error(relayed)).await;
                return Err(error);
            }
        }
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut write: W,
    mut frames: mpsc::Receiver<OutFrame>,
    ctx: Arc<Context>,
) -> io::Result<()> {
    let deadline = Duration::from_millis(ctx.limits.dial_timeout_ms);
    while let Some(frame) = frames.recv().await {
        timeout(deadline, async {
            write.write_all(&frame.bytes).await?;
            write.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Mux 写入超时"))??;
    }
    let _ = write.shutdown().await;
    Ok(())
}

/// 在拨号前收集子流首包；返回路由目标、拨号目标与必须回放的前缀。
///
/// 只在该入站启用嗅探时等待，期限与流式入站一致。Mux 会话数据已经按序
/// 到达，累积的字节全部来自同一子流，因此可以直接作为前缀回放。
async fn sniff_prefix(
    ctx: &Context,
    inbound: &str,
    target: &Target,
    incoming: &mut mpsc::Receiver<Chunk>,
) -> (Target, Target, Vec<u8>) {
    let Some(timeout) = ctx.sniff_timeout(inbound) else {
        return (target.clone(), target.clone(), Vec::new());
    };
    let deadline = Instant::now() + timeout;
    let mut buffer = Vec::new();
    loop {
        if !buffer.is_empty() {
            match ctx.sniff_payload(inbound, target, &buffer) {
                PayloadSniff::NeedMore => {}
                PayloadSniff::Detected { route, dial } => return (route, dial, buffer),
                PayloadSniff::Disabled | PayloadSniff::Invalid => {
                    return (target.clone(), target.clone(), buffer);
                }
            }
        }
        match timeout_at(deadline, incoming.recv()).await {
            Ok(Some(chunk)) => buffer.extend_from_slice(&chunk.payload),
            _ => break,
        }
    }
    (target.clone(), target.clone(), buffer)
}

/// 单个 TCP 会话：拨号成功后双向桥接，EOF/错误通过事件回报主循环。
// 参数是 Mux 会话的固定身份与句柄集合；合并成结构体只会把同一组值挪个位置。
#[allow(clippy::too_many_arguments)]
async fn tcp_session(
    id: u16,
    generation: u64,
    target: Target,
    mut incoming: mpsc::Receiver<Chunk>,
    events: mpsc::Sender<Event>,
    ctx: Arc<Context>,
    inbound: String,
    budget: Arc<Semaphore>,
    user: Option<Arc<crate::telemetry::UserCounters>>,
) {
    // 子流首包在拨号前嗅探；已消费的前缀必须原样写回上游。
    let (route, dial, prefix) = sniff_prefix(&ctx, &inbound, &target, &mut incoming).await;
    let upstream = match ctx.connect_routed(&inbound, &route, &dial).await {
        Ok(upstream) => upstream,
        Err(_) => {
            let _ = events
                .send(Event::TcpEnd {
                    id,
                    generation,
                    error: true,
                })
                .await;
            return;
        }
    };
    // `connect` 现在可能返回 TLS 装箱流，因此统一用可分离的通用读写半部。
    let (mut read, mut write) = tokio::io::split(upstream);
    let deadline = Duration::from_millis(ctx.limits.dial_timeout_ms);
    if !prefix.is_empty() {
        let written = timeout(deadline, write.write_all(&prefix)).await;
        if !written.is_ok_and(|result| result.is_ok()) {
            let _ = events
                .send(Event::TcpEnd {
                    id,
                    generation,
                    error: true,
                })
                .await;
            return;
        }
        ctx.stats
            .uplink
            .fetch_add(prefix.len() as u64, Ordering::Relaxed);
    }
    let mut buffer = vec![0u8; BRIDGE_BUFFER];
    let mut uplink_open = true;
    loop {
        tokio::select! {
            chunk = incoming.recv(), if uplink_open => {
                match chunk {
                    Some(chunk) => {
                        let written = timeout(deadline, write.write_all(&chunk.payload)).await;
                        if !written.is_ok_and(|result| result.is_ok()) {
                            let _ = events.send(Event::TcpEnd { id, generation, error: true }).await;
                            return;
                        }
                        ctx.stats.uplink
                            .fetch_add(chunk.payload.len() as u64, Ordering::Relaxed);
                        if let Some(counter) = &user {
                            counter.add(true, chunk.payload.len());
                        }
                    }
                    None => {
                        let _ = write.shutdown().await;
                        uplink_open = false;
                    }
                }
            }
            result = read.read(&mut buffer) => {
                match result {
                    Ok(0) => {
                        let _ = events.send(Event::TcpEnd { id, generation, error: false }).await;
                        return;
                    }
                    Ok(count) => {
                        let permit = match budget
                            .clone()
                            .acquire_many_owned(count.max(1) as u32)
                            .await
                        {
                            Ok(permit) => permit,
                            Err(_) => return,
                        };
                        let payload = buffer[..count].to_vec();
                        if events
                            .send(Event::TcpData {
                                id,
                                generation,
                                payload,
                                _budget: permit,
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = events.send(Event::TcpEnd { id, generation, error: true }).await;
                        return;
                    }
                }
            }
        }
    }
}

/// 单个 UDP 关联；内部按目标维护 connected UDP socket。
///
/// 不直接复用 `crate::udp::Association`：该类型是 `udp` 模块私有实现，未暴露
/// 可在不修改既有文件的前提下复用的 API。
#[derive(Clone)]
struct UdpAssociation {
    inner: Arc<UdpInner>,
}

impl UdpAssociation {
    fn new(ctx: Arc<Context>, inbound: String, key: u64) -> Self {
        Self {
            inner: Arc::new(UdpInner::new(ctx, inbound, key, None)),
        }
    }

    fn key(&self) -> u64 {
        self.inner.key
    }

    fn set_sink(&self, sender: mpsc::Sender<Event>, owner: u64, budget: Arc<Semaphore>) {
        self.inner.set_sink(sender, owner, budget);
    }

    /// 让关联本身持有活动槽，直到它被真正回收（含 GlobalID 宽限期）。
    fn hold_slot(&self, slot: OwnedSemaphorePermit) {
        self.inner.hold_slot(slot);
    }

    async fn detach(&self, owner: u64) {
        self.inner.detach(owner).await;
    }

    async fn send(&self, target: Target, payload: &[u8]) -> io::Result<()> {
        self.inner.send(target, payload).await
    }
}

struct UdpInner {
    ctx: Arc<Context>,
    inbound: String,
    key: u64,
    /// 由 GlobalID 建立的关联才进入宽限期登记表；键含实例、入口与账户。
    global_key: Option<GlobalKey>,
    mappings: tokio::sync::Mutex<HashMap<Target, UdpMapping>>,
    /// 单上游 SOCKS5 UDP 中继；与直连映射互斥使用。
    relay: tokio::sync::Mutex<Option<MuxRelay>>,
    tasks: StdMutex<JoinSet<()>>,
    sink: StdMutex<Option<Sink>>,
    /// 活动槽由关联本身持有，而不是由 Mux 会话持有。
    ///
    /// GlobalID 关联结束后仍会在登记表里保留 60 秒，这段时间它的映射与
    /// 上游中继仍握着 socket。若活动槽随会话释放，宽限期内的关联就不再
    /// 计入 `max_udp_associations`，等于绕过该上限。因此槽随 `UdpInner`
    /// 存活，直到关联真正被回收。
    slot: StdMutex<Option<OwnedSemaphorePermit>>,
}

struct MuxRelay {
    proxy: Arc<ProxyOutbound>,
    socket: Arc<UdpSocket>,
    // 仅用于保活；丢弃连接即通知上游释放 UDP 关联。
    _control: crate::forward::RelayControl,
    task: AbortHandle,
    last_used: Arc<StdMutex<Instant>>,
}

struct Sink {
    sender: mpsc::Sender<Event>,
    owner: u64,
    budget: Arc<Semaphore>,
}

struct UdpMapping {
    peer: SocketAddr,
    socket: Arc<UdpSocket>,
    task: AbortHandle,
    last_used: Arc<StdMutex<Instant>>,
}

impl UdpInner {
    fn new(ctx: Arc<Context>, inbound: String, key: u64, global_key: Option<GlobalKey>) -> Self {
        Self {
            ctx,
            inbound,
            key,
            global_key,
            mappings: tokio::sync::Mutex::new(HashMap::new()),
            relay: tokio::sync::Mutex::new(None),
            tasks: StdMutex::new(JoinSet::new()),
            sink: StdMutex::new(None),
            slot: StdMutex::new(None),
        }
    }

    /// 把活动槽转交给关联本身，使宽限期内仍占用配额。
    fn hold_slot(&self, slot: OwnedSemaphorePermit) {
        *self.slot.lock().unwrap_or_else(|error| error.into_inner()) = Some(slot);
    }

    /// 主动归还活动槽。代清理（停机/重载）时调用：此时关联可能仍被调用方
    /// 的 `Arc` 持有，不主动释放就会把配额留在未归还状态。
    fn release_slot(&self) {
        let _ = self
            .slot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }

    fn set_sink(&self, sender: mpsc::Sender<Event>, owner: u64, budget: Arc<Semaphore>) {
        let previous = self
            .sink
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(Sink {
                sender,
                owner,
                budget,
            });
        if let Some(previous) = previous
            && previous.owner != owner
        {
            // 旧连接若仍存活，让它尽快发出 End；失败只表示对方已退出。
            let _ = previous.sender.try_send(Event::ForceEnd {
                key: self.key,
                owner: previous.owner,
            });
        }
    }

    async fn detach(&self, owner: u64) {
        let detached = {
            let mut sink = self.sink.lock().unwrap_or_else(|error| error.into_inner());
            if sink.as_ref().is_some_and(|sink| sink.owner == owner) {
                *sink = None;
                true
            } else {
                false
            }
        };
        if !detached {
            return;
        }
        // GlobalID 关联按 Xray 语义保留映射与套接字进入宽限期，供同一
        // GlobalID 的新会话续接；非 GlobalID 关联没有登记表持有，随
        // `Session` 释放时由 `UdpInner::drop` 中止任务并关闭套接字。
        if let Some(global_key) = &self.global_key {
            release_global(global_key.clone(), owner);
        }
    }

    fn current_sink(&self) -> Option<(mpsc::Sender<Event>, u64, Arc<Semaphore>)> {
        self.sink
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map(|sink| (sink.sender.clone(), sink.owner, sink.budget.clone()))
    }

    async fn send(self: &Arc<Self>, target: Target, payload: &[u8]) -> io::Result<()> {
        // QUIC Initial SNI 只参与出站选择，实际发送目标保持不变。
        let route = self.ctx.udp_route_target(&self.inbound, &target, payload);
        let selected = self
            .ctx
            .udp_selected_routed(&self.inbound, &route, &target)
            .await?;
        // `reverse` 出站的 proxy 为空，但它是独立上游；只判断 `.proxy`
        // 会把它当直连，把反向目标当普通目标发出去。
        selected.udp_proxied()?;
        // 传 `Arc`：此前每包深拷贝一份出站配置。
        let proxy = selected.proxy.clone();
        if payload.len() > self.ctx.limits.max_udp_payload {
            return Err(invalid("Mux UDP 载荷过长"));
        }
        let deadline = Duration::from_millis(self.ctx.limits.dial_timeout_ms);
        if let Some(proxy) = proxy {
            return self.send_proxy(proxy, target, payload, deadline).await;
        }
        let mut mappings = self.mappings.lock().await;
        self.expire(&mut mappings);
        if mappings
            .get(&target)
            .is_some_and(|mapping| !selected.allows_cached_peer(mapping.peer))
            && let Some(mapping) = mappings.remove(&target)
        {
            mapping.task.abort();
        }

        if !mappings.contains_key(&target) {
            if mappings.len() >= self.ctx.limits.max_udp_targets {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Mux UDP 目标上限",
                ));
            }
            let address = self.ctx.direct_udp_address(&selected, &target).await?;
            let socket = Arc::new(UdpSocket::bind(wildcard(address.ip())).await?);
            socket.connect(address).await?;

            let read_socket = socket.clone();
            let weak = Arc::downgrade(self);
            let last_used = Arc::new(StdMutex::new(Instant::now()));
            let read_last_used = last_used.clone();
            let ctx = self.ctx.clone();
            let max_payload = ctx.limits.max_udp_payload;
            let key = self.key;
            let tracker = ctx.children.clone();
            let task = {
                let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
                tasks.spawn(tracker.track_future(async move {
                    let mut buffer = vec![0u8; 65_536];
                    loop {
                        let count = match read_socket.recv(&mut buffer).await {
                            Ok(count) => count,
                            Err(_) => break,
                        };
                        if count > max_payload {
                            ctx.stats.drop_packet();
                            continue;
                        }
                        // 只临时持有 association，避免读任务反过来延长关联生命周期。
                        let sink = match weak.upgrade() {
                            Some(inner) => inner.current_sink(),
                            None => break,
                        };
                        let Some((sender, owner, budget)) = sink else {
                            continue;
                        };
                        let permit =
                            match budget.clone().acquire_many_owned(count.max(1) as u32).await {
                                Ok(permit) => permit,
                                Err(_) => break,
                            };
                        let payload = buffer[..count].to_vec();
                        *read_last_used
                            .lock()
                            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
                        if sender
                            .send(Event::UdpReply {
                                key,
                                owner,
                                target: Target::from(address),
                                payload,
                                _budget: permit,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }))
            };
            mappings.insert(
                target.clone(),
                UdpMapping {
                    peer: address,
                    socket,
                    task,
                    last_used,
                },
            );
        }

        let mapping = mappings
            .get_mut(&target)
            .ok_or_else(|| io::Error::other("Mux UDP 映射缺失"))?;
        let count = timeout(deadline, mapping.socket.send(payload))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Mux UDP 发送超时"))??;
        if count != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Mux UDP 不完整发送",
            ));
        }
        *mapping
            .last_used
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
        self.ctx
            .stats
            .uplink
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(())
    }

    /// 经 SOCKS5 上游转发；同一关联只允许一个上游。
    async fn send_proxy(
        self: &Arc<Self>,
        proxy: Arc<ProxyOutbound>,
        target: Target,
        payload: &[u8],
        deadline: Duration,
    ) -> io::Result<()> {
        let mut relay = self.relay.lock().await;
        let ttl = Duration::from_millis(self.ctx.limits.udp_idle_timeout_ms);
        let stale = relay.as_ref().is_some_and(|relay| {
            relay.task.is_finished()
                || relay
                    .last_used
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .elapsed()
                    >= ttl
        });
        if stale && let Some(previous) = relay.take() {
            previous.task.abort();
        }
        if let Some(existing) = relay.as_ref() {
            if !Arc::ptr_eq(&existing.proxy, &proxy) && *existing.proxy != *proxy {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "同一 Mux UDP 关联只能使用同一个上游代理",
                ));
            }
        } else {
            let connection = crate::forward::dial_udp_relay(&self.ctx, &proxy).await?;
            let socket = connection.socket;
            let read_socket = socket.clone();
            let weak = Arc::downgrade(self);
            let last_used = Arc::new(StdMutex::new(Instant::now()));
            let read_last_used = last_used.clone();
            let ctx = self.ctx.clone();
            let max_payload = ctx.limits.max_udp_payload;
            let key = self.key;
            let tracker = ctx.children.clone();
            let task = {
                let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
                tasks.spawn(tracker.track_future(async move {
                    let mut buffer = vec![0u8; 65_536];
                    loop {
                        let count = match read_socket.recv(&mut buffer).await {
                            Ok(count) => count,
                            Err(_) => break,
                        };
                        let Some((reply_target, payload)) =
                            crate::outbound::socks5_udp_parse(&buffer[..count])
                        else {
                            // 分片与畸形报文直接丢弃。
                            ctx.stats.drop_packet();
                            continue;
                        };
                        if payload.len() > max_payload {
                            ctx.stats.drop_packet();
                            continue;
                        }
                        let sink = match weak.upgrade() {
                            Some(inner) => inner.current_sink(),
                            None => break,
                        };
                        let Some((sender, owner, budget)) = sink else {
                            continue;
                        };
                        let permit = match budget
                            .clone()
                            .acquire_many_owned(payload.len().max(1) as u32)
                            .await
                        {
                            Ok(permit) => permit,
                            Err(_) => break,
                        };
                        let payload = payload.to_vec();
                        *read_last_used
                            .lock()
                            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
                        if sender
                            .send(Event::UdpReply {
                                key,
                                owner,
                                target: reply_target,
                                payload,
                                _budget: permit,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }))
            };
            *relay = Some(MuxRelay {
                proxy,
                socket,
                _control: connection.control,
                task,
                last_used,
            });
        }
        let active = relay
            .as_ref()
            .ok_or_else(|| io::Error::other("Mux UDP 中继缺失"))?;
        let datagram = crate::outbound::socks5_udp_encode(&target, payload)?;
        let count = timeout(deadline, active.socket.send(&datagram))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Mux UDP 发送超时"))??;
        if count != datagram.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Mux UDP 不完整发送",
            ));
        }
        *active
            .last_used
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
        self.ctx
            .stats
            .uplink
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    fn expire(&self, mappings: &mut HashMap<Target, UdpMapping>) {
        let ttl = Duration::from_millis(self.ctx.limits.udp_idle_timeout_ms);
        mappings.retain(|_, mapping| {
            let expired = mapping.task.is_finished()
                || mapping
                    .last_used
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .elapsed()
                    >= ttl;
            if expired {
                mapping.task.abort();
            }
            !expired
        });
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        while tasks.try_join_next().is_some() {}
    }
}

impl Drop for UdpInner {
    fn drop(&mut self) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        tasks.abort_all();
    }
}

fn wildcard(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(
        if ip.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        },
        0,
    )
}

/// GlobalID 关联的登记状态。
enum GlobalState {
    /// 有会话持有该关联；登记表只保留弱引用。
    Active { inner: Weak<UdpInner>, owner: u64 },
    /// 最后一个会话已结束；登记表持有强引用直到宽限期结束。
    Expiring {
        inner: Arc<UdpInner>,
        expire: Instant,
    },
}

struct GlobalEntry {
    state: GlobalState,
}

/// GlobalID 只在创建它的服务实例（`Context`）内有效。
///
/// 同一进程可以同时运行多个服务实例；若仅按 GlobalID 登记，后来的实例会
/// 接管前一个实例的 UDP 套接字、路由与统计。地址复用安全：宽限期内的条目
/// 持有 `Arc<UdpInner>`（进而持有 `Arc<Context>`），地址不可能被复用；
/// Active 条目一旦弱引用失效，下一次登记会先清除它。
type GlobalKey = (usize, String, String, [u8; 8]);

static GLOBAL_IDS: OnceLock<StdMutex<HashMap<GlobalKey, GlobalEntry>>> = OnceLock::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

fn next_token() -> u64 {
    NEXT_TOKEN.fetch_add(1, Ordering::Relaxed)
}

fn global_ids() -> &'static StdMutex<HashMap<GlobalKey, GlobalEntry>> {
    GLOBAL_IDS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn context_instance(ctx: &Context) -> usize {
    std::ptr::from_ref(ctx) as usize
}

/// 停机时释放属于该服务实例的 GlobalID 宽限期关联。
///
/// 宽限期只应跨 Mux 连接，不应跨服务生命周期：登记表持有的映射任务会
/// 阻塞停机时的子任务等待，最长可达 [`GLOBAL_GRACE`]。
pub(crate) fn release_instance(ctx: &Context) {
    let instance = context_instance(ctx);
    let mut global = global_ids()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // 先取回被清掉条目的活动槽。仅从登记表移除不够：槽挂在 UdpInner 上，
    // 而 UdpInner 仍可能被调用方的 Arc 持有，不主动释放就会让配额停在
    // 未归还状态，代清理后新连接无槽可用。
    let dropped: Vec<Arc<UdpInner>> = global
        .iter()
        .filter(|((id, ..), _)| *id == instance)
        .filter_map(|(_, entry)| match &entry.state {
            GlobalState::Active { inner, .. } => inner.upgrade(),
            GlobalState::Expiring { inner, .. } => Some(inner.clone()),
        })
        .collect();
    global.retain(|(id, ..), _| *id != instance);
    drop(global);
    for inner in dropped {
        inner.release_slot();
    }
}

/// 清理失效条目：会话消失的 Active 条目与到期的 Expiring 条目。
fn purge_globals(global: &mut HashMap<GlobalKey, GlobalEntry>, now: Instant) {
    global.retain(|_, entry| match &entry.state {
        GlobalState::Active { inner, .. } => inner.strong_count() > 0,
        GlobalState::Expiring { expire, .. } => *expire > now,
    });
}

/// GlobalID 去重：存活或宽限期内的条目复用，死亡条目惰性清理。
///
/// 每个服务实例的上限为 256。返回 `None` 表示新 GlobalID 被拒绝。
fn acquire_global(
    global_id: [u8; 8],
    ctx: Arc<Context>,
    inbound: &str,
    user: &str,
    key: u64,
    owner: u64,
) -> Option<UdpAssociation> {
    if global_id == [0u8; 8] {
        return None;
    }
    let instance = context_instance(&ctx);
    let global_key = (instance, inbound.to_owned(), user.to_owned(), global_id);
    let now = Instant::now();
    let mut global = global_ids()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    purge_globals(&mut global, now);

    let existing = global.get_mut(&global_key).map(|entry| {
        // Active 条目由会话持有；Expiring 条目由登记表持有，二者都可复用。
        let existing = match &entry.state {
            GlobalState::Active { inner, .. } => inner.upgrade(),
            GlobalState::Expiring { inner, .. } => Some(inner.clone()),
        };
        if let Some(inner) = &existing {
            entry.state = GlobalState::Active {
                inner: Arc::downgrade(inner),
                owner,
            };
        }
        existing
    });
    match existing {
        // 未登记：下面新建。
        None => {}
        Some(Some(inner)) => return Some(UdpAssociation { inner }),
        // Active 条目的弱引用已失效，按新关联重建。
        Some(None) => {
            global.remove(&global_key);
        }
    }

    if global.keys().filter(|(id, ..)| *id == instance).count() >= MAX_GLOBAL_IDS {
        return None;
    }
    let inner = Arc::new(UdpInner::new(
        ctx,
        inbound.to_owned(),
        key,
        Some(global_key.clone()),
    ));
    global.insert(
        global_key,
        GlobalEntry {
            state: GlobalState::Active {
                inner: Arc::downgrade(&inner),
                owner,
            },
        },
    );
    Some(UdpAssociation { inner })
}

/// 最后一个会话结束后，把关联转入宽限期并安排在到期时清理。
fn release_global(global_key: GlobalKey, owner: u64) {
    let expire = Instant::now() + GLOBAL_GRACE;
    let mut global = global_ids()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    purge_globals(&mut global, Instant::now());
    let released = match global.get_mut(&global_key) {
        None => return,
        Some(entry) => {
            let released = match &entry.state {
                GlobalState::Active {
                    inner,
                    owner: current,
                } if *current == owner => Some(inner.upgrade()),
                _ => None,
            };
            if let Some(Some(inner)) = &released {
                entry.state = GlobalState::Expiring {
                    inner: inner.clone(),
                    expire,
                };
            }
            released
        }
    };
    match released {
        // 所有权已转移到别的会话，或条目已在宽限期。
        None => return,
        // 正常关闭路径下调用方仍持有 `Arc`；弱引用失效说明已被强制取消。
        Some(None) => {
            global.remove(&global_key);
            return;
        }
        Some(Some(_)) => {}
    }
    drop(global);

    // 惰性清理保证正确性；定时任务只负责按时释放本条目的套接字。
    // 只删除本条目，避免虚拟时钟推进时误清理其他运行时登记的条目。
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            sleep_until(expire).await;
            let mut global = global_ids()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let expired = global.get(&global_key).is_some_and(|entry| {
                matches!(
                    &entry.state,
                    GlobalState::Expiring { expire: current, .. } if *current <= expire
                )
            });
            if expired {
                global.remove(&global_key);
            }
        });
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod global_id_isolation_tests {
    use super::*;
    use crate::config::Config;

    /// 同一 GlobalID 只能续接**同一账户、同一入口**的关联。
    ///
    /// 此前键只有 (实例, GlobalID)：两个已认证用户碰撞同一个标识时，
    /// 后一个用户会接管前一个的 UDP 关联与回包接收方。
    #[test]
    fn continuation_is_scoped_to_account_and_inbound() {
        let config = Config::from_json(
            r#"{
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "in", "listen": "127.0.0.1:0"}],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"default": "direct"}
            }"#,
        )
        .unwrap();
        let ctx = Arc::new(Context::new(&config).unwrap());
        let id = [0x42; 8];

        let alice = acquire_global(id, ctx.clone(), "in", "alice", 1, 1).unwrap();
        let bob = acquire_global(id, ctx.clone(), "in", "bob", 2, 2).unwrap();
        assert!(
            !Arc::ptr_eq(&alice.inner, &bob.inner),
            "不同账户不能共用同一个 GlobalID 关联"
        );

        let alice_again = acquire_global(id, ctx.clone(), "in", "alice", 3, 3).unwrap();
        assert!(
            Arc::ptr_eq(&alice.inner, &alice_again.inner),
            "同一账户的续接必须复用原关联"
        );

        let other_inbound = acquire_global(id, ctx.clone(), "other", "alice", 4, 4).unwrap();
        assert!(
            !Arc::ptr_eq(&alice.inner, &other_inbound.inner),
            "不同入口不能共用同一个 GlobalID 关联"
        );

        release_instance(&ctx);
    }

    /// GlobalID 关联进入宽限期后仍握着 socket，必须继续占用活动槽。
    ///
    /// 此前槽由 Mux 会话持有：会话结束时 `OwnedSemaphorePermit` 随 `Session`
    /// 释放，而登记表还保留关联 60 秒。宽限期内的关联因此不计数，
    /// `max_udp_associations` 被绕过。修复后槽随 `UdpInner` 存活。
    #[tokio::test]
    async fn expiring_global_keeps_its_association_slot() {
        let config = Config::from_json(
            r#"{
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "in", "listen": "127.0.0.1:0"}],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"default": "direct"}
            }"#,
        )
        .unwrap();
        let ctx = Arc::new(Context::new(&config).unwrap());
        let id = [0x7e; 8];
        let before = ctx.udp_slots.available_permits();

        let association = acquire_global(id, ctx.clone(), "in", "alice", 1, 1).unwrap();
        let slot = ctx.udp_slots.clone().try_acquire_owned().unwrap();
        association.hold_slot(slot);
        assert_eq!(ctx.udp_slots.available_permits(), before - 1);

        // 会话结束：关联转入宽限期，登记表继续持有它。
        association.inner.detach(1).await;
        assert!(
            ctx.udp_slots.available_permits() == before - 1,
            "宽限期内的关联仍在占用 socket，必须继续计数活动槽"
        );

        // 关联真正释放后槽才归还。
        drop(association);
        purge_globals(
            &mut global_ids().lock().unwrap_or_else(|e| e.into_inner()),
            Instant::now(),
        );
        assert_eq!(ctx.udp_slots.available_permits(), before);

        release_instance(&ctx);
    }

    /// 停机/重载代清理必须同时归还宽限期条目占用的活动槽。
    ///
    /// `release_instance` 直接按实例清空登记表；若槽仍挂在被清掉的条目上，
    /// 第二次清理时配额就不再回到基线。
    #[tokio::test]
    async fn release_instance_reclaims_slots_held_by_expiring_entries() {
        let config = Config::from_json(
            r#"{
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "in", "listen": "127.0.0.1:0"}],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"default": "direct"}
            }"#,
        )
        .unwrap();
        let ctx = Arc::new(Context::new(&config).unwrap());
        let before = ctx.udp_slots.available_permits();

        let mut held = Vec::new();
        for index in 0..3u8 {
            let id = [0x30 + index; 8];
            let association = acquire_global(id, ctx.clone(), "in", "alice", index as u64, 1).unwrap();
            let slot = ctx.udp_slots.clone().try_acquire_owned().unwrap();
            association.hold_slot(slot);
            association.inner.detach(1).await;
            held.push(association);
        }
        assert_eq!(ctx.udp_slots.available_permits(), before - 3);

        release_instance(&ctx);
        assert_eq!(
            ctx.udp_slots.available_permits(),
            before,
            "代清理后活动槽必须回到基线"
        );
        // 仍被本测试持有的句柄不应让清理结果反弹。
        drop(held);
        assert_eq!(ctx.udp_slots.available_permits(), before);
    }

    /// 两个入口共享同一份全局配额时，一个入口不得靠宽限期超额占用。
    ///
    /// 全局上限存在不等于按入口公平；至少保证「同一实例内所有入口各自持有的
    /// 活动槽总和」不会因为 GlobalID 宽限期而超出。
    #[tokio::test]
    async fn two_inbounds_cannot_exceed_the_shared_slot_budget() {
        let config = Config::from_json(
            r#"{
                "version": 1,
                "limits": {"max_udp_associations": 2},
                "inbounds": [
                    {"type": "socks5", "tag": "a", "listen": "127.0.0.1:0"},
                    {"type": "socks5", "tag": "b", "listen": "127.0.0.1:0"}
                ],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"default": "direct"}
            }"#,
        )
        .unwrap();
        let ctx = Arc::new(Context::new(&config).unwrap());
        assert_eq!(ctx.udp_slots.available_permits(), 2);

        let a = acquire_global([0x11; 8], ctx.clone(), "a", "u", 1, 1).unwrap();
        a.hold_slot(ctx.udp_slots.clone().try_acquire_owned().unwrap());
        let b = acquire_global([0x22; 8], ctx.clone(), "b", "u", 2, 2).unwrap();
        b.hold_slot(ctx.udp_slots.clone().try_acquire_owned().unwrap());
        assert_eq!(ctx.udp_slots.available_permits(), 0);

        // 两个入口都进入宽限期，配额仍应被占满：新关联必须被拒绝。
        a.inner.detach(1).await;
        b.inner.detach(2).await;
        assert!(
            ctx.udp_slots.clone().try_acquire_owned().is_err(),
            "宽限期内不得出现可用的额外配额"
        );

        // 清理后才能恢复。
        release_instance(&ctx);
        assert_eq!(ctx.udp_slots.available_permits(), 2);
        drop((a, b));
    }
}
