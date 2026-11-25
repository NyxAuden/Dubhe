//! AnyTLS 入站：TLS 之上的密码哈希认证、会话复用与多流。
//!
//! 线协议以本地固定上游 `sing-anytls@v0.0.0-20260902142641-43bb1cbea74e` 为准：
//! 32 字节 `sha256(password)`、2 字节大端握手填充长度与填充，随后是
//! `命令(1) + 流ID(4, 大端) + 长度(2, 大端)` 的 7 字节帧头。
//! 客户端的首个流是 `SYN(长度 0)` 后紧跟 `PSH(目标地址)`；服务端只做认证、
//! 流建立/关闭与字节中继。上行（服务端→客户端）不做填充——上游
//! `newServerSession` 同样不打开 `sendPadding`，客户端读路径按帧解析，天然兼容；
//! 服务端也不主动发送心跳请求，仅在收到 `HeartRequest` 时回 `HeartResponse`。
//! 服务端按规范解析客户端 Settings 的 `padding-md5`；与本地默认方案不一致时，
//! 通过 `UpdatePaddingScheme` 帧原样下发方案字符串，供客户端后续会话使用。

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::config::{Inbound, User};
use crate::forward::{self, Context};
use crate::session::{Host, Target};

const PASSWORD_LEN: usize = 32;
const FRAME_OVERHEAD: usize = 7;
/// 每个 AnyTLS 流的排队帧上限；与本地双工缓冲共同限制单连接内存。
const STREAM_BUFFER: usize = 4;
/// 每会话并发流上限；超出后新 SYN 立即发送 FIN。
const MAX_STREAMS: usize = 64;
const BRIDGE_BUFFER: usize = 64 * 1024;
/// 上游 `settings.Bytes()` 对 `v=2` 不追加换行，此处保持逐字节一致。
const SERVER_SETTINGS: &[u8] = b"v=2";
/// 上游 `protocolVersion`；客户端 Settings 达到该版本才启用 SYNACK/ServerSettings。
const PROTOCOL_VERSION: u32 = 2;
/// 上游 `padding.defaultPaddingScheme` 的逐字节副本：UTF-8、行间 `\n`、无结尾换行。
///
/// 规范只定义 `padding-md5` 用于协商，不传输方案正文之外的结构化信息；
/// 下发时必须原样发送该字符串，不能重排 key、补行或改写尚未识别的语法。
const DEFAULT_PADDING_SCHEME: &str = super::anytls_padding::DEFAULT_SCHEME;

const COMMAND_WASTE: u8 = 0;
const COMMAND_SYN: u8 = 1;
const COMMAND_PSH: u8 = 2;
const COMMAND_FIN: u8 = 3;
const COMMAND_SETTINGS: u8 = 4;
const COMMAND_ALERT: u8 = 5;
const COMMAND_UPDATE_PADDING_SCHEME: u8 = 6;
const COMMAND_SYNACK: u8 = 7;
const COMMAND_HEART_REQUEST: u8 = 8;
const COMMAND_HEART_RESPONSE: u8 = 9;
const COMMAND_SERVER_SETTINGS: u8 = 10;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    stream: TcpStream,
    config: Arc<Inbound>,
    tls: Option<crate::tls::ServerTls>,
    ctx: Arc<Context>,
    handshake: crate::runtime::HandshakePermits,
    _stop: CancellationToken,
    _force: CancellationToken,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let acceptor = tls.ok_or_else(|| io::Error::other("AnyTLS 入口需要 TLS"))?;
    let mut accepted = timeout_at(deadline, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS TLS握手超时"))??;
    let (tag, users, raw_scheme) = match &*config {
        Inbound::AnyTls {
            tag,
            users,
            padding_scheme,
            ..
        } => (
            tag.clone(),
            users.clone(),
            padding_scheme.as_deref().unwrap_or(DEFAULT_PADDING_SCHEME),
        ),
        _ => return Err(io::Error::other("入口不是 AnyTLS")),
    };
    let password = timeout_at(deadline, read_prologue(&mut accepted))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS 认证超时"))??;
    let Some(user) = authenticate(&password, &users) else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "AnyTLS 认证失败",
        ));
    };
    let user = user.name.clone();
    let scheme = super::anytls_padding::Scheme::parse(raw_scheme)?;
    drop(handshake);
    session(accepted, &tag, &ctx, &scheme, user).await
}

/// 读取 `sha256(password)`、握手填充长度与填充；返回值是密码哈希。
async fn read_prologue<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<[u8; PASSWORD_LEN]> {
    let mut password = [0u8; PASSWORD_LEN];
    io.read_exact(&mut password).await?;
    let padding = io.read_u16().await? as usize;
    let mut buffer = [0u8; 1024];
    let mut remaining = padding;
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        io.read_exact(&mut buffer[..take]).await?;
        remaining -= take;
    }
    Ok(password)
}

/// 对所有用户执行常量时间比较，不因命中顺序提前返回。
/// 常量时间比对后返回命中的用户；找不到返回 None。
fn authenticate<'a>(received: &[u8; PASSWORD_LEN], users: &'a [User]) -> Option<&'a User> {
    let mut matched = 0u8;
    let mut index = 0usize;
    for (position, user) in users.iter().enumerate() {
        let digest: [u8; PASSWORD_LEN] = Sha256::digest(user.password.as_bytes()).into();
        let hit = digest.ct_eq(received).unwrap_u8();
        // 只在首次命中时记录，且不改变比较次数。
        index = position
            .checked_sub(position)
            .map(|_| {
                if hit == 1 && matched == 0 {
                    position
                } else {
                    index
                }
            })
            .unwrap_or(index);
        matched |= hit;
    }
    (matched == 1).then(|| &users[index])
}

async fn session<S>(
    io: S,
    tag: &str,
    ctx: &Arc<Context>,
    scheme: &super::anytls_padding::Scheme,
    user: String,
) -> io::Result<()>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut read, mut write) = tokio::io::split(io);
    let (frames, mut outgoing) = mpsc::channel::<Vec<u8>>(64);
    let writer = ctx.children.spawn(async move {
        let _ = write_frames(&mut write, &mut outgoing).await;
    });
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _writer_guard = AbortOnDrop(writer.abort_handle());
    let result = read_loop(&mut read, frames, tag, ctx, scheme, user).await;
    let _ = writer.await;
    result
}

/// 每批最多合并的帧数。
///
/// 不设上限时一个快消费者会把所有排队帧合成一次巨大的写；`MAX_BATCH` 保证
/// 公平性，并让控制帧在有限个数据帧之后就能出队。
const MAX_WRITE_BATCH: usize = 4;

/// 把排队中的帧写到下游。
///
/// 只合并**已经在队列里**的帧，绝不为凑批等待下一帧：队列空时立即写出。
/// 帧按入队顺序拼接，所以 FIN / SYNACK 等控制帧不会被它前面的数据帧越过。
async fn write_frames<W>(write: &mut W, frames: &mut mpsc::Receiver<Vec<u8>>) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;
    while let Some(first) = frames.recv().await {
        let mut batch = first;
        for _ in 1..MAX_WRITE_BATCH {
            match frames.try_recv() {
                Ok(frame) => batch.extend_from_slice(&frame),
                Err(_) => break,
            }
        }
        write.write_all(&batch).await?;
        write.flush().await?;
    }
    write.shutdown().await
}

async fn read_loop<R>(
    read: &mut R,
    frames: mpsc::Sender<Vec<u8>>,
    tag: &str,
    ctx: &Arc<Context>,
    scheme: &super::anytls_padding::Scheme,
    user: String,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut streams: HashMap<u32, StreamHandle> = HashMap::new();
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut settings_received = false;
    let mut peer_version = 0u32;
    loop {
        // 只用非阻塞方式回收流任务：帧头读取绝不能被 select 取消，否则已读出的
        // 前几个帧头字节会丢失，后续整条会话的帧边界都会错位。
        // 每个帧循环都会回收一次；空闲连接不会堆积已完成的句柄。
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                return Err(io::Error::other("AnyTLS 流任务异常"));
            }
        }
        let Some((command, id, length)) = read_header(read).await? else {
            return Ok(());
        };
        match command {
            COMMAND_SYN => {
                skip(read, length).await?;
                if !settings_received {
                    let _ = frames
                        .send(control(COMMAND_ALERT, 0, b"settings required"))
                        .await;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AnyTLS 客户端未先发送 Settings",
                    ));
                }
                if streams.contains_key(&id) {
                    continue;
                }
                streams.retain(|_, handle| !handle.data.is_closed());
                if streams.len() >= MAX_STREAMS {
                    let _ = frames.send(control(COMMAND_FIN, id, &[])).await;
                    continue;
                }
                let (data, incoming) = mpsc::channel(STREAM_BUFFER);
                let peer_closed = CancellationToken::new();
                streams.insert(
                    id,
                    StreamHandle {
                        data,
                        peer_closed: peer_closed.clone(),
                    },
                );
                let frames = frames.clone();
                let ctx = ctx.clone();
                let tag = tag.to_owned();
                let user = user.clone();
                // 上游 SYNACK 只在客户端声明了协议版本 2 及以上时发送。
                let synack = peer_version >= PROTOCOL_VERSION;
                let children = ctx.children.clone();
                tasks.spawn(children.track_future(async move {
                    serve_stream(id, incoming, frames, tag, ctx, synack, peer_closed, user).await;
                }));
            }
            COMMAND_PSH => {
                // 上游 handlePush 对零长度 PSH 直接返回；跳过可避免地址解析任务
                // 在空块上空转。
                if length == 0 {
                    continue;
                }
                let mut payload = vec![0u8; length];
                read.read_exact(&mut payload).await?;
                if let Some(sender) = streams.get(&id).map(|handle| handle.data.clone())
                    && sender.send(payload).await.is_err()
                {
                    streams.remove(&id);
                }
            }
            COMMAND_FIN => {
                skip(read, length).await?;
                // 上游 closeByPeer：FIN 关闭整条流且不再回送 FIN。取消令牌让
                // 桥接任务立即结束并释放上游连接。
                if let Some(handle) = streams.remove(&id) {
                    handle.peer_closed.cancel();
                }
            }
            COMMAND_SETTINGS => {
                let mut payload = vec![0u8; length];
                read.read_exact(&mut payload).await?;
                if payload.is_empty() {
                    continue;
                }
                settings_received = true;
                // 上游 `recvLoop` 的 cmdSettings 分支：客户端只上报当前方案的
                // `padding-md5`，不会携带方案正文。md5 与服务端不一致（含缺失
                // 该键）时，在 ServerSettings 之前原样下发服务端方案。
                // 未识别的键（例如客户端自造的 padding-scheme）一律不参与比较，
                // 更不能把其内容当作方案回显。
                if settings_field(&payload, "padding-md5") != Some(scheme.md5()) {
                    let _ = frames
                        .send(control(
                            COMMAND_UPDATE_PADDING_SCHEME,
                            0,
                            scheme.raw().as_bytes(),
                        ))
                        .await;
                }
                // 上游 `handleSettings`：解析失败或版本低于 2 时只记录，不回
                // ServerSettings；达到 2 才更新 peerVersion 并回 `v=2`。
                let version = settings_version(&payload);
                if version >= PROTOCOL_VERSION {
                    peer_version = version;
                    let _ = frames
                        .send(control(COMMAND_SERVER_SETTINGS, 0, SERVER_SETTINGS))
                        .await;
                }
            }
            COMMAND_ALERT => {
                // 上游对零长度告警直接忽略；非空告警结束整个会话。
                if length == 0 {
                    continue;
                }
                skip(read, length).await?;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "AnyTLS 对端发送告警",
                ));
            }
            // 填充帧：内容为占位零字节，直接丢弃即可。
            COMMAND_WASTE => skip(read, length).await?,
            // 上游服务端收到客户端发来的填充方案更新也只做丢弃。
            COMMAND_UPDATE_PADDING_SCHEME => skip(read, length).await?,
            COMMAND_HEART_REQUEST => {
                skip(read, length).await?;
                let _ = frames.send(control(COMMAND_HEART_RESPONSE, id, &[])).await;
            }
            _ => skip(read, length).await?,
        }
    }
}

/// 单个流：先读目标地址，拨号成功后再把剩余的上下行字节桥接到本地双工流。
// 单条流的固定句柄集合；与其它入口一致，不合并成结构体。
#[allow(clippy::too_many_arguments)]
async fn serve_stream(
    id: u32,
    incoming: mpsc::Receiver<Vec<u8>>,
    frames: mpsc::Sender<Vec<u8>>,
    tag: String,
    ctx: Arc<Context>,
    synack: bool,
    peer_closed: CancellationToken,
    user: String,
) {
    let mut incoming = Incoming::new(incoming);
    let target = match read_target(&mut incoming).await {
        Ok(target) => target,
        Err(_) => {
            // 上游 acceptStream 读取目标地址失败时走 HandshakeFailure：协议版本
            // >= 2 先回带错误文本的 SYNACK，再关闭流。
            if synack {
                let _ = frames
                    .send(control(COMMAND_SYNACK, id, b"invalid destination"))
                    .await;
            }
            // 对端已发 FIN 时不再回送 FIN（上游对已关闭的流 Close 为空操作）。
            if !peer_closed.is_cancelled() {
                let _ = frames.send(control(COMMAND_FIN, id, &[])).await;
            }
            return;
        }
    };
    // AnyTLS 没有原生 UDP 帧；协议层 UoT 目标在目标地址解析后、认证前分流。
    if let Some(version) = crate::udp::uot_version(&target) {
        if synack {
            let _ = frames.send(control(COMMAND_SYNACK, id, &[])).await;
        }
        let (relay, bridge) =
            start_bridge(id, incoming, frames, peer_closed.clone(), &ctx.children);
        tokio::select! {
            _ = peer_closed.cancelled() => {}
            _ = crate::udp::uot(relay, ctx, tag, version, None) => {}
        }
        bridge.finish().await;
        return;
    }
    // 准入在拨号之前：到期账户不应触发 DNS 或上游连接。
    if !ctx.stats.admit_user(&tag, Some(user.as_str())) {
        if synack {
            let _ = frames
                .send(control(COMMAND_SYNACK, id, b"unauthorized"))
                .await;
        }
        if !peer_closed.is_cancelled() {
            let _ = frames.send(control(COMMAND_FIN, id, &[])).await;
        }
        return;
    }
    let upstream = match ctx.connect(&tag, &target).await {
        Ok(upstream) => upstream,
        Err(_) => {
            // 上游 HandshakeFailure 在协议版本 >= 2 时把错误文本放进 SYNACK，
            // 随后关闭流（即 FIN）。
            if synack {
                let _ = frames
                    .send(control(COMMAND_SYNACK, id, b"connect failed"))
                    .await;
            }
            if !peer_closed.is_cancelled() {
                let _ = frames.send(control(COMMAND_FIN, id, &[])).await;
            }
            return;
        }
    };
    // 上游 HandshakeSuccess：协议版本 >= 2 时发送空 SYNACK。
    if synack {
        let _ = frames.send(control(COMMAND_SYNACK, id, &[])).await;
    }

    let (relay, bridge) = start_bridge(id, incoming, frames, peer_closed.clone(), &ctx.children);
    let relay = ctx.stats.count_user(&tag, Some(user.as_str()), relay);
    // 对端 FIN 关闭整条流：取消时立即丢弃中继，连带关闭上游 TCP 连接。
    tokio::select! {
        _ = peer_closed.cancelled() => {}
        _ = forward::relay(relay, upstream, ctx.stats.clone()) => {}
    }
    bridge.finish().await;
}

/// 建立 PSH 上行桥与下行读循环；TCP 与 UoT 共享同一帧生命周期。
fn start_bridge(
    id: u32,
    mut incoming: Incoming,
    frames: mpsc::Sender<Vec<u8>>,
    peer_closed: CancellationToken,
    children: &tokio_util::task::TaskTracker,
) -> (tokio::io::DuplexStream, Bridge) {
    let (relay, bridge) = tokio::io::duplex(BRIDGE_BUFFER);
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge);
    let uplink = children.spawn(async move {
        let rest = incoming.take_rest();
        if bridge_write.write_all(&rest).await.is_err() {
            return;
        }
        while let Some(chunk) = incoming.recv().await {
            if bridge_write.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = bridge_write.shutdown().await;
    });
    let downlink = children.spawn(async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = tokio::select! {
                _ = peer_closed.cancelled() => return,
                result = bridge_read.read(&mut buffer) => result,
            };
            match read {
                Ok(0) | Err(_) => {
                    if !peer_closed.is_cancelled() {
                        let _ = frames.send(control(COMMAND_FIN, id, &[])).await;
                    }
                    return;
                }
                Ok(read) => {
                    if frames
                        .send(control(COMMAND_PSH, id, &buffer[..read]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });
    (relay, Bridge { uplink, downlink })
}

struct Bridge {
    uplink: tokio::task::JoinHandle<()>,
    downlink: tokio::task::JoinHandle<()>,
}
impl Bridge {
    async fn finish(mut self) {
        // 下行任务在读到EOF时负责发送FIN；强制取消由Drop回收两端。
        let _ = (&mut self.downlink).await;
        self.uplink.abort();
        let _ = (&mut self.uplink).await;
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.uplink.abort();
        self.downlink.abort();
    }
}

/// `COMMAND_SERVER_SETTINGS` 与其它控制帧共用的 7 字节头编码。
fn control(command: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    // 上游 `writeFrame` 对超过 0xffff 的控制帧直接报错；本模块的调用点都远小于上限。
    debug_assert!(payload.len() <= usize::from(u16::MAX));
    let mut frame = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    frame.push(command);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn read_header<R: AsyncRead + Unpin>(read: &mut R) -> io::Result<Option<(u8, u32, usize)>> {
    let mut header = [0u8; FRAME_OVERHEAD];
    let mut filled = 0;
    while filled < header.len() {
        let count = read.read(&mut header[filled..]).await?;
        if count == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "AnyTLS 帧头不完整",
                ))
            };
        }
        filled += count;
    }
    let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
    Ok(Some((header[0], id, length)))
}

async fn skip<R: AsyncRead + Unpin>(read: &mut R, mut length: usize) -> io::Result<()> {
    let mut buffer = [0u8; 1024];
    while length > 0 {
        let take = length.min(buffer.len());
        read.read_exact(&mut buffer[..take]).await?;
        length -= take;
    }
    Ok(())
}

/// 读取 Settings 中最后一个 `key=value`；同键后出现的值覆盖前值（上游 StringMap）。
fn settings_field<'a>(payload: &'a [u8], key: &str) -> Option<&'a str> {
    std::str::from_utf8(payload)
        .ok()?
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| *name == key)
        .map(|(_, value)| value)
        .next_back()
}

fn settings_version(payload: &[u8]) -> u32 {
    settings_field(payload, "v")
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// 计算与客户端 Settings `padding-md5` 同格式的小写十六进制 MD5。
#[cfg(test)]
fn padding_scheme_md5(scheme: &str) -> String {
    super::anytls_padding::md5_text(scheme)
}

/// 流开头的目标地址（SOCKS5 格式：类型、地址、端口）。
async fn read_target(incoming: &mut Incoming) -> io::Result<Target> {
    let host = match incoming.read_u8().await? {
        1 => {
            let mut octets = [0u8; 4];
            incoming.read_into(&mut octets).await?;
            Host::Ip(Ipv4Addr::from(octets).into())
        }
        4 => {
            let mut octets = [0u8; 16];
            incoming.read_into(&mut octets).await?;
            Host::Ip(Ipv6Addr::from(octets).into())
        }
        3 => {
            let length = usize::from(incoming.read_u8().await?);
            if length == 0 {
                return Err(invalid_target());
            }
            let mut bytes = [0u8; 255];
            let domain = &mut bytes[..length];
            incoming.read_into(domain).await?;
            if !domain.iter().all(u8::is_ascii_graphic) {
                return Err(invalid_target());
            }
            let domain = std::str::from_utf8(domain).map_err(|_| invalid_target())?;
            Host::Domain(domain.to_ascii_lowercase())
        }
        _ => return Err(invalid_target()),
    };
    let mut port = [0u8; 2];
    incoming.read_into(&mut port).await?;
    let port = u16::from_be_bytes(port);
    // UoT 魔数目标沿用 `port=0` 的约定；普通目标仍拒绝 0。
    let uot = matches!(&host, Host::Domain(domain) if crate::udp::is_uot_domain(domain));
    if port == 0 && !uot {
        return Err(invalid_target());
    }
    Ok(Target { host, port })
}

fn invalid_target() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "AnyTLS 目标地址无效")
}

/// 活跃流句柄：数据通道与“对端已关闭该流”的取消令牌。
///
/// 上游收到对端 FIN 后走 `closeByPeer`：整条流立即关闭且不再回送 FIN。
/// 取消令牌同时用于终止桥接、释放上游连接，并避免迟到的 FIN 误关复用流 ID 的新流。
struct StreamHandle {
    data: mpsc::Sender<Vec<u8>>,
    peer_closed: CancellationToken,
}

/// 按需从 PSH 通道取字节，供目标地址解析使用；解析完成后的剩余字节交给桥接任务。
struct Incoming {
    rx: mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
    offset: usize,
}

impl Incoming {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buffer: Vec::new(),
            offset: 0,
        }
    }

    fn available(&self) -> usize {
        self.buffer.len() - self.offset
    }

    async fn fill(&mut self, count: usize) -> io::Result<()> {
        while self.available() < count {
            match self.rx.recv().await {
                Some(chunk) => self.buffer.extend_from_slice(&chunk),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "AnyTLS 流在目标地址前结束",
                    ));
                }
            }
        }
        Ok(())
    }

    async fn read_u8(&mut self) -> io::Result<u8> {
        self.fill(1).await?;
        let value = self.buffer[self.offset];
        self.offset += 1;
        Ok(value)
    }

    async fn read_into(&mut self, target: &mut [u8]) -> io::Result<()> {
        self.fill(target.len()).await?;
        let end = self.offset + target.len();
        target.copy_from_slice(&self.buffer[self.offset..end]);
        self.offset = end;
        Ok(())
    }

    fn take_rest(&mut self) -> Vec<u8> {
        let rest = self.buffer[self.offset..].to_vec();
        self.buffer.clear();
        self.offset = 0;
        rest
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_version_uses_the_last_v_key() {
        assert_eq!(settings_version(b"v=2\nclient=sing-box\n"), 2);
        assert_eq!(settings_version(b"v=1\n"), 1);
        assert_eq!(settings_version(b"v=1\nv=2\n"), 2);
        assert_eq!(settings_version(b"client=x\n"), 0);
        assert_eq!(settings_version(b""), 0);
    }

    #[test]
    fn settings_padding_md5_uses_the_last_known_key() {
        assert_eq!(
            settings_field(b"v=2\npadding-md5=0123456789abcdef\n", "padding-md5"),
            Some("0123456789abcdef")
        );
        assert_eq!(
            settings_field(b"padding-md5=old\npadding-md5=new\n", "padding-md5"),
            Some("new")
        );
        // Settings 只定义了 padding-md5；未知键不能冒充方案声明。
        assert_eq!(settings_field(b"v=2\n", "padding-md5"), None);
        assert_eq!(
            settings_field(b"padding-scheme=stop=1\n0=1-1\n", "padding-md5"),
            None
        );
        assert_eq!(settings_field(b"padding-md5\n", "padding-md5"), None);
    }

    /// 合批必须：按序输出、总字节不变、不丢帧、控制帧不被延后到后续批次。
    #[tokio::test]
    async fn write_frames_batches_in_order_without_losing_bytes() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        // 12 帧：其中夹着 FIN，验证它不会被跨批丢掉或重排。
        let frames: Vec<Vec<u8>> = (0..12u32)
            .map(|index| {
                if index == 7 {
                    control(COMMAND_FIN, index, &[])
                } else {
                    control(COMMAND_PSH, index, &[index as u8; 32])
                }
            })
            .collect();
        for frame in &frames {
            tx.send(frame.clone()).await.unwrap();
        }
        drop(tx);

        let mut sink = Vec::new();
        write_frames(&mut sink, &mut rx).await.unwrap();

        let expected: Vec<u8> = frames.concat();
        assert_eq!(sink, expected, "合批必须逐字节保持顺序与内容");
        let fin = control(COMMAND_FIN, 7, &[]);
        let position = sink
            .windows(fin.len())
            .position(|window| window == fin.as_slice())
            .expect("FIN 必须存在");
        assert_eq!(position, frames[..7].concat().len(), "FIN 顺序被改变");
    }

    #[test]
    fn default_padding_scheme_text_and_md5_match_upstream() {
        // 上游 defaultPaddingScheme 没有结尾换行；md5 按原始 UTF-8 字节计算。
        assert_eq!(DEFAULT_PADDING_SCHEME.len(), 137);
        assert!(!DEFAULT_PADDING_SCHEME.ends_with('\n'));
        assert!(!DEFAULT_PADDING_SCHEME.contains('\r'));
        assert_eq!(
            padding_scheme_md5(DEFAULT_PADDING_SCHEME),
            "75cff2ad89aadf5e257059ee571ebe11"
        );
    }

    #[test]
    fn update_padding_scheme_frame_uses_standard_header() {
        let scheme = DEFAULT_PADDING_SCHEME.as_bytes();
        let frame = control(COMMAND_UPDATE_PADDING_SCHEME, 0, scheme);
        let length = u16::try_from(scheme.len()).unwrap();

        assert_eq!(frame.len(), FRAME_OVERHEAD + scheme.len());
        assert_eq!(frame[0], COMMAND_UPDATE_PADDING_SCHEME);
        assert_eq!(&frame[1..5], &[0, 0, 0, 0], "控制帧 stream id 为 0");
        assert_eq!(&frame[5..7], &length.to_be_bytes(), "u16 大端长度");
        assert_eq!(&frame[7..], scheme, "载荷必须原样发送方案字符串");
    }

    #[test]
    fn frame_control_round_trips_header_fields() {
        let frame = control(COMMAND_PSH, 0x0102_0304, b"abc");
        assert_eq!(frame[0], COMMAND_PSH);
        assert_eq!(&frame[1..5], &[1, 2, 3, 4]);
        assert_eq!(&frame[5..7], &[0, 3]);
        assert_eq!(&frame[7..], b"abc");
    }

    #[test]
    fn server_settings_payload_matches_upstream_exactly() {
        // 上游 settings.Bytes() 对单个 v=2 不追加换行。
        assert_eq!(SERVER_SETTINGS, b"v=2");
    }

    async fn parse_target(bytes: Vec<u8>) -> io::Result<Target> {
        let (sender, receiver) = mpsc::channel(1);
        sender.send(bytes).await.unwrap();
        drop(sender);
        let mut incoming = Incoming::new(receiver);
        read_target(&mut incoming).await
    }

    #[tokio::test]
    async fn target_parser_matches_sing_socksaddr_categories() {
        // sing/common/metadata 的 SocksaddrSerializer：1=IPv4、4=IPv6、3=FQDN。
        let ipv4 = parse_target(vec![1, 192, 0, 2, 7, 0x01, 0xbb])
            .await
            .unwrap();
        assert_eq!(
            ipv4,
            Target {
                host: Host::Ip("192.0.2.7".parse().unwrap()),
                port: 443,
            }
        );

        let mut ipv6 = vec![4];
        ipv6.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ipv6.extend_from_slice(&[0x01, 0xbb]);
        assert_eq!(
            parse_target(ipv6).await.unwrap(),
            Target {
                host: Host::Ip("2001:db8::1".parse().unwrap()),
                port: 443,
            }
        );

        assert_eq!(
            parse_target(b"\x03\x0bexample.org\x01\xbb".to_vec())
                .await
                .unwrap(),
            Target {
                host: Host::Domain("example.org".into()),
                port: 443,
            }
        );

        // 未注册的类型码（含 0）、空域名与端口 0 都应拒绝。
        for invalid in [
            vec![2u8, 0, 80],
            vec![3u8, 0, 0, 80],
            vec![3u8, 1, b' ', 0, 80],
            vec![1u8, 192, 0, 2, 7, 0, 0],
        ] {
            assert!(parse_target(invalid).await.is_err());
        }
    }
}
