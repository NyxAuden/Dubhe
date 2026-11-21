//! Snell v4/v5 服务端（sing-box / Surge 兼容）。
//!
//! 本模块只实现协议行为，不依赖任何 GPL 源码；wire 规格见 `docs/snell.md`。
//! 服务端不处理 TLS/obfs，传输层由运行时负责。

pub(crate) mod client;

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use subtle::{Choice, ConstantTimeEq};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpStream, UdpSocket},
    sync::{Notify, OwnedSemaphorePermit, mpsc},
    task::{AbortHandle, JoinSet},
    time::{Instant, timeout},
};

use crate::{
    forward,
    session::{Host, Network, Target},
    telemetry::{Gauge, Stats},
};

// ---------------------------------------------------------------------------
// 常量：全部来自 sing-snell 的公开 wire 行为。
// ---------------------------------------------------------------------------

/// 记录头版本。v4 与 v5 都使用 0x04。
const HEADER_VERSION: u8 = 0x04;
/// 明文头长度：version + 2 个保留字节 + padding 长度 + payload 长度。
const HEADER_PLAIN_LEN: usize = 7;
/// AEAD 认证标签长度。
const TAG_LEN: usize = 16;
/// 加密头长度（7 + 16）。
const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + TAG_LEN;
/// 每个方向首个记录前的 salt 长度。
const SALT_LEN: usize = 16;
/// AES-GCM nonce 长度。
const NONCE_LEN: usize = 12;
/// 单个记录允许的最大 payload；超过即 fail-closed。
const MAX_PAYLOAD: usize = 0x3fff;
/// 允许的最大 padding；Surge 只会发送 0 或 0x100..=0x1ff。
const MAX_PADDING: usize = 0x3fff;
/// 单个记录在线上的最大长度：头 + padding + 载荷 + tag。
const MAX_RECORD_WIRE: usize = HEADER_CIPHER_LEN + MAX_PADDING + u16::MAX as usize + TAG_LEN;

/// 请求前缀版本。
const REQUEST_VERSION: u8 = 0x01;
/// 请求命令字。
const COMMAND_PING: u8 = 0x00;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_CONNECT_V2: u8 = 0x05;
const COMMAND_UDP: u8 = 0x06;
/// 服务端应答类型。
const REPLY_TUNNEL: u8 = 0x00;
const REPLY_PONG: u8 = 0x01;
const REPLY_ERROR: u8 = 0x02;
/// 连接目标失败时返回的通用错误码（不向上游泄露内部原因）。
const ERROR_CONNECT: u8 = 0x01;
/// UDP 记录内的转发命令。
const UDP_COMMAND_FORWARD: u8 = 0x01;
/// UDP 地址族。
const ADDRESS_TYPE_IPV4: u8 = 0x04;
const ADDRESS_TYPE_IPV6: u8 = 0x06;

/// Argon2id 参数（与 Go `argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]` 一致）。
const KDF_MEMORY_KIB: u32 = 8;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const KDF_OUTPUT_LEN: usize = 32;
const AES_KEY_LEN: usize = 16;

/// 首个记录的 padding 范围：0x100..=0x1ff。
const INITIAL_PADDING_MIN: usize = 0x100;

/// 资源上限。
const MAX_PSK_LEN: usize = 4096;
const MAX_USERS: usize = 1024;
const MAX_REPLAY_CAPACITY: usize = 1_000_000;
/// 单条隧道最多承载的逻辑请求数。
const MAX_LOGICAL_STREAMS: usize = 1024;
/// 复用隧道中等待下一个请求的空闲上限。
const REUSE_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
/// 下游已结束后，继续排空客户端记录的上限与超时。
const REUSE_DRAIN_LIMIT: usize = 0x80001;
const REUSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
/// 双向中继的读缓冲；有界且不随连接增长。
const RELAY_BUFFER: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// 配置与身份
// ---------------------------------------------------------------------------

/// Snell v6 记录模式；v4/v5 固定使用 `Shaped`（现有记录层）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// v4/v5 记录层（含首记录 padding）。
    Shaped,
    /// v6 默认 shaped 记录层（BLAKE2b profile、padding/mixing/chunk 与 salt block）。
    Default,
    /// v6：salt + AEAD 记录，禁止 padding。
    Unshaped,
    /// v6：无加密明文记录，仅用于显式测试/兼容。
    UnsafeRaw,
}

/// 配置中的 Snell 用户。`user_key` 对应 sing-box 的 `userkey` 字段。
#[derive(Clone, Debug)]
pub(crate) struct SnellUser {
    pub name: String,
    pub user_key: Vec<u8>,
}

struct PreparedUser {
    /// 仅用于将来的审计/日志；当前内核没有把用户身份传入转发表。
    #[allow(dead_code)]
    name: Option<String>,
    key: Vec<u8>,
}

/// 绑定阶段构造一次，所有连接共享。
pub(crate) struct Prepared {
    psk: Vec<u8>,
    users: Vec<PreparedUser>,
    version: u8,
    mode: Mode,
    obfs: crate::transport::snell_obfs::Mode,
    replay: SaltReplay,
}

impl Prepared {
    /// 校验配置并构造共享状态。
    ///
    /// `replay_capacity` 建议取 `Limits::max_replay_entries`；0 表示关闭 v5
    /// 首记录 salt 重放缓存。
    pub(crate) fn new(
        psk: Vec<u8>,
        users: Vec<SnellUser>,
        version: u8,
        mode: Mode,
        replay_capacity: usize,
    ) -> io::Result<Self> {
        if !matches!(version, 4..=6) {
            return Err(invalid_config("Snell 版本仅支持 4、5 或 6"));
        }
        if version == 6 {
            if !(12..=255).contains(&psk.len()) {
                return Err(invalid_config("Snell v6 psk 长度必须在 12-255 字节之间"));
            }
            if matches!(mode, Mode::Shaped) {
                return Err(invalid_config("Snell v4/v5 shaped 记录层不能用于 v6"));
            }
        } else {
            if psk.is_empty() {
                return Err(invalid_config("Snell psk 不得为空"));
            }
            if psk.len() > MAX_PSK_LEN {
                return Err(invalid_config("Snell psk 过长"));
            }
            if mode != Mode::Shaped {
                return Err(invalid_config("Snell v4/v5 仅支持 shaped 记录层"));
            }
        }
        if users.len() > MAX_USERS {
            return Err(invalid_config("Snell 用户数量超过上限"));
        }
        if replay_capacity > MAX_REPLAY_CAPACITY {
            return Err(invalid_config("Snell 重放缓存容量超过上限"));
        }
        let mut seen = HashSet::with_capacity(users.len());
        let mut prepared = Vec::with_capacity(users.len());
        for user in users {
            if user.user_key.is_empty() {
                return Err(invalid_config("Snell userkey 不得为空"));
            }
            if user.user_key.len() > 255 {
                return Err(invalid_config("Snell userkey 超过 255 字节"));
            }
            if !seen.insert(user.user_key.clone()) {
                return Err(invalid_config("Snell userkey 重复"));
            }
            prepared.push(PreparedUser {
                name: (!user.name.is_empty()).then_some(user.name),
                key: user.user_key,
            });
        }
        Ok(Self {
            psk,
            users: prepared,
            version,
            mode,
            obfs: crate::transport::snell_obfs::Mode::None,
            replay: SaltReplay::new(replay_capacity),
        })
    }

    pub(crate) fn with_obfs(mut self, name: Option<&str>) -> io::Result<Self> {
        self.obfs = crate::transport::snell_obfs::validate(self.version, name, None, None)?;
        Ok(self)
    }

    /// 常量时间校验 client id。未配置用户时接受任意（含空）id 并返回 None。
    fn authenticate(&self, client_id: &[u8]) -> io::Result<Option<&PreparedUser>> {
        if self.users.is_empty() {
            return Ok(None);
        }
        let mut found = Choice::from(0u8);
        let mut index = 0usize;
        for (position, user) in self.users.iter().enumerate() {
            let hit = user.key.as_slice().ct_eq(client_id);
            if bool::from(hit) && !bool::from(found) {
                index = position;
            }
            found |= hit;
        }
        if bool::from(found) {
            Ok(Some(&self.users[index]))
        } else {
            Err(auth_error())
        }
    }
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

/// 运行时入口，签名与 `shadowsocks::serve_tcp` 保持一致。
///
/// 调用方负责 `stream.set_nodelay(true)`、连接计数与错误日志；
/// `handshake` 只覆盖 salt/首个记录/请求解析与首次认证阶段。
pub(crate) async fn serve(
    stream: TcpStream,
    prepared: Arc<Prepared>,
    ctx: Arc<forward::Context>,
    tag: &str,
    handshake: OwnedSemaphorePermit,
) -> io::Result<()> {
    serve_stream(stream, prepared, ctx, tag, handshake).await
}

pub(crate) fn serve_stream<'a, S>(
    stream: S,
    prepared: Arc<Prepared>,
    ctx: Arc<forward::Context>,
    tag: &'a str,
    handshake: OwnedSemaphorePermit,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'a,
{
    let obfs = prepared.obfs;
    // 在承载选择边界类型擦除，避免把两套记录状态机内联进所有入口。
    if obfs == crate::transport::snell_obfs::Mode::None {
        Box::pin(serve_stream_impl(stream, prepared, ctx, tag, handshake))
    } else {
        Box::pin(serve_stream_impl(
            crate::transport::snell_obfs::Stream::server(stream, obfs),
            prepared,
            ctx,
            tag,
            handshake,
        ))
    }
}

async fn serve_stream_impl<S>(
    stream: S,
    prepared: Arc<Prepared>,
    ctx: Arc<forward::Context>,
    tag: &str,
    handshake: OwnedSemaphorePermit,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);

    let (mut reader, first_record) = timeout(deadline, async {
        let mut reader = match prepared.mode {
            Mode::Shaped | Mode::Unshaped => Reader::Aead(
                RecordReader::new(read_half, &prepared.psk, prepared.mode == Mode::Shaped).await?,
            ),
            Mode::Default => Reader::ShapedV6(ShapedV6Reader::new(read_half, &prepared.psk)),
            Mode::UnsafeRaw => Reader::Raw(RawReader::new(read_half)),
        };
        let record = reader.read_record().await?;
        Ok::<_, io::Error>((reader, record))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Snell 握手超时"))??;

    let first_record = first_record.ok_or_else(|| invalid("Snell 首个记录为零块"))?;

    // v5 对首个记录 salt 做跨连接重放检查；v6 unshaped 不做该检查。
    if prepared.version == 5
        && prepared.mode == Mode::Shaped
        && prepared
            .replay
            .check_and_add(reader.salt().expect("shaped 读取器带 salt"))
    {
        return Err(auth_error());
    }

    let (request, early) = parse_request(&first_record, prepared.version)?;
    serve_tunnel(
        &prepared,
        &ctx,
        tag,
        &mut reader,
        write_half,
        prepared.mode,
        request,
        early,
        handshake,
    )
    .await
}

/// 在同一条加密隧道上处理一个或多个逻辑请求。
// 参数分别来自配置、连接与首个请求，生命周期不同，合并会引入不必要的绑定。
#[allow(clippy::too_many_arguments)]
async fn serve_tunnel<S>(
    prepared: &Prepared,
    ctx: &Arc<forward::Context>,
    tag: &str,
    reader: &mut Reader<ReadHalf<S>>,
    write_half: WriteHalf<S>,
    mode: Mode,
    first: Request,
    first_early: Vec<u8>,
    handshake: OwnedSemaphorePermit,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut io = TunnelIo::new(write_half, mode);
    let mut handshake = Some(handshake);
    let mut request = first;
    let mut early = first_early;
    let mut streams = 0usize;

    loop {
        streams += 1;
        if streams > MAX_LOGICAL_STREAMS {
            return Err(invalid("Snell 逻辑请求数超过上限"));
        }

        match request.command {
            COMMAND_PING => {
                drop(handshake.take());
                let writer = io.writer(&prepared.psk).await?;
                writer.write_record(&[REPLY_PONG]).await?;
                return Ok(());
            }
            COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
                let user = prepared.authenticate(&request.client_id)?;
                let traffic = user
                    .and_then(|user| user.name.as_deref())
                    .map(|name| ctx.stats.user_counter(tag, name));
                drop(handshake.take());

                let target = request
                    .target
                    .ok_or_else(|| invalid("Snell CONNECT 缺少目标地址"))?;
                let target_stream = ctx.connect(tag, &target).await;

                let writer = io.writer(&prepared.psk).await?;
                let target_stream = match target_stream {
                    Ok(stream) => stream,
                    Err(error) => {
                        // 认证已成功，可以返回通用错误；不回显内部原因。
                        let _ = send_error(writer, ERROR_CONNECT, "connect failed").await;
                        return Err(error);
                    }
                };

                writer.write_record(&[REPLY_TUNNEL]).await?;
                let reuse = request.command == COMMAND_CONNECT_V2;
                relay_tcp(
                    reader,
                    writer,
                    target_stream,
                    ctx.stats.clone(),
                    reuse,
                    early,
                    traffic,
                )
                .await?;

                if !reuse {
                    return Ok(());
                }

                match read_next_request(reader, prepared.version).await {
                    Ok((next, next_early)) => {
                        request = next;
                        early = next_early;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof | io::ErrorKind::TimedOut
                        ) =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            COMMAND_UDP => {
                let user = prepared.authenticate(&request.client_id)?;
                let traffic = user
                    .and_then(|user| user.name.as_deref())
                    .map(|name| ctx.stats.user_counter(tag, name));
                drop(handshake.take());
                if !early.is_empty() {
                    return Err(invalid("Snell UDP 请求携带多余数据"));
                }

                let writer = io.writer(&prepared.psk).await?;
                writer.write_record(&[REPLY_TUNNEL]).await?;
                serve_udp(reader, writer, ctx, tag, traffic).await?;
                // 与上游一致：UDP 关联结束即结束整条隧道。
                return Ok(());
            }
            _ => return Err(invalid("不支持的 Snell 命令")),
        }
    }
}

async fn read_next_request<R: AsyncRead + Unpin>(
    reader: &mut Reader<R>,
    version: u8,
) -> io::Result<(Request, Vec<u8>)> {
    let record = timeout(REUSE_IDLE_TIMEOUT, reader.read_record())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Snell 复用空闲超时"))?;
    match record {
        Ok(Some(payload)) => parse_request(&payload, version),
        Ok(None) => Err(invalid("Snell 请求位置出现零块")),
        Err(error) => Err(error),
    }
}

// ---------------------------------------------------------------------------
// 请求与应答
// ---------------------------------------------------------------------------

struct Request {
    command: u8,
    client_id: Vec<u8>,
    target: Option<Target>,
}

/// 解析请求并返回记录中剩余的 early data。
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_request(bytes: &[u8], version: u8) {
    let _ = parse_request(bytes, version);
}

fn parse_request(bytes: &[u8], version: u8) -> io::Result<(Request, Vec<u8>)> {
    let mut cursor = Cursor::new(bytes);

    if cursor.u8()? != REQUEST_VERSION {
        return Err(invalid("Snell 请求版本无效"));
    }
    let command = cursor.u8()?;
    let client_id_len = usize::from(cursor.u8()?);

    // v5 的 PING 在读取 3 字节前缀后立即返回，不消费 client id。
    let client_id = if command == COMMAND_PING && version >= 5 {
        Vec::new()
    } else {
        cursor.bytes(client_id_len)?.to_vec()
    };

    let target = match command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => Some(read_connect_address(&mut cursor)?),
        COMMAND_PING | COMMAND_UDP => None,
        _ => return Err(invalid("不支持的 Snell 命令")),
    };

    Ok((
        Request {
            command,
            client_id,
            target,
        },
        cursor.remaining().to_vec(),
    ))
}

/// CONNECT 目标：1 字节长度 + 主机字符串 + 2 字节大端端口。
fn read_connect_address(cursor: &mut Cursor<'_>) -> io::Result<Target> {
    let host_len = usize::from(cursor.u8()?);
    if host_len == 0 {
        return Err(invalid("Snell 目标主机为空"));
    }
    let host = parse_host(cursor.bytes(host_len)?)?;
    let port = cursor.u16_be()?;
    Ok(Target { host, port })
}

fn parse_host(bytes: &[u8]) -> io::Result<Host> {
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(invalid("Snell 主机长度无效"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("Snell 主机不是 UTF-8"))?;
    if !text.as_bytes().iter().all(u8::is_ascii_graphic) {
        return Err(invalid("Snell 主机含非可见字符"));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        Ok(Host::Ip(ip))
    } else {
        Ok(Host::Domain(text.to_owned()))
    }
}

fn encode_error(code: u8, message: &str) -> io::Result<Vec<u8>> {
    let message = message.as_bytes();
    if message.len() > 255 {
        return Err(invalid("Snell 错误消息过长"));
    }
    let mut reply = Vec::with_capacity(3 + message.len());
    reply.push(REPLY_ERROR);
    reply.push(code);
    reply.push(message.len() as u8);
    reply.extend_from_slice(message);
    Ok(reply)
}

async fn send_error<W: AsyncWrite + Unpin>(
    writer: &mut Writer<W>,
    code: u8,
    message: &str,
) -> io::Result<()> {
    let reply = encode_error(code, message)?;
    writer.write_record(&reply).await
}

// ---------------------------------------------------------------------------
// TCP 中继
// ---------------------------------------------------------------------------

/// 在一个逻辑流内双向中继，保持记录边界。
///
/// * 上游（客户端 -> 目标）读到零块时关闭目标写端。
/// * 下游（目标 -> 客户端）读到 EOF 时，复用模式写零块，否则直接返回。
/// * 下游先结束时，复用模式继续排空客户端记录（有字节上限与超时）。
async fn relay_tcp<R, W, T>(
    reader: &mut Reader<R>,
    writer: &mut Writer<W>,
    target: T,
    stats: Arc<Stats>,
    reuse: bool,
    early: Vec<u8>,
    traffic: Option<Arc<crate::telemetry::UserCounters>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let _flow = stats.enter(Gauge::Tcp);
    let (mut target_r, mut target_w) = tokio::io::split(target);
    let downstream_done = Notify::new();
    let abort = Notify::new();

    let up_stats = stats.clone();
    let down_stats = stats.clone();
    let up_traffic = traffic.clone();
    let down_traffic = traffic;
    let done_up = &downstream_done;
    let abort_up = &abort;
    let upstream = async move {
        let result: io::Result<()> = async {
            if !early.is_empty() {
                target_w.write_all(&early).await?;
                up_stats
                    .uplink
                    .fetch_add(early.len() as u64, Ordering::Relaxed);
                if let Some(traffic) = &up_traffic {
                    traffic.add(true, early.len());
                }
            }

            let mut downstream_finished = false;
            let mut discarded = 0usize;
            loop {
                let record = if downstream_finished {
                    if !reuse {
                        return Ok(());
                    }
                    tokio::select! {
                        biased;
                        _ = abort_up.notified() => return Ok(()),
                        result = timeout(REUSE_DRAIN_TIMEOUT, reader.read_record()) => {
                            match result {
                                Ok(result) => result,
                                Err(_) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        "Snell 复用排空超时",
                                    ));
                                }
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        biased;
                        _ = abort_up.notified() => return Ok(()),
                        _ = done_up.notified() => {
                            downstream_finished = true;
                            continue;
                        }
                        result = reader.read_record() => result,
                    }
                };

                match record {
                    Ok(Some(payload)) => {
                        if downstream_finished {
                            discarded = discarded.saturating_add(payload.len());
                            if discarded > REUSE_DRAIN_LIMIT {
                                return Err(invalid("Snell 复用排空超过上限"));
                            }
                        } else {
                            target_w.write_all(&payload).await?;
                            up_stats
                                .uplink
                                .fetch_add(payload.len() as u64, Ordering::Relaxed);
                            if let Some(traffic) = &up_traffic {
                                traffic.add(true, payload.len());
                            }
                        }
                    }
                    Ok(None) => {
                        if !downstream_finished {
                            let _ = target_w.shutdown().await;
                        }
                        return Ok(());
                    }
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        if !downstream_finished {
                            let _ = target_w.shutdown().await;
                        }
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        .await;
        if result.is_err() {
            abort_up.notify_one();
        }
        result
    };

    let done_down = &downstream_done;
    let abort_down = &abort;
    let downstream = async move {
        let result: io::Result<()> = async {
            let mut buffer = vec![0u8; RELAY_BUFFER];
            loop {
                let count = tokio::select! {
                    biased;
                    _ = abort_down.notified() => return Ok(()),
                    result = target_r.read(&mut buffer) => result?,
                };
                if count == 0 {
                    if reuse {
                        writer.write_zero().await?;
                    }
                    return Ok(());
                }
                writer.write_data(&buffer[..count]).await?;
                down_stats
                    .downlink
                    .fetch_add(count as u64, Ordering::Relaxed);
                if let Some(traffic) = &down_traffic {
                    traffic.add(false, count);
                }
            }
        }
        .await;
        done_down.notify_one();
        if result.is_err() {
            abort_down.notify_one();
        }
        result
    };

    let (upstream_result, downstream_result) = tokio::join!(upstream, downstream);
    upstream_result?;
    downstream_result?;
    Ok(())
}

// ---------------------------------------------------------------------------
// UDP over stream
// ---------------------------------------------------------------------------

struct UdpReply {
    address: SocketAddr,
    payload: Vec<u8>,
    /// 与关联共享的队列字节额度；drop 时归还。
    _budget: tokio::sync::OwnedSemaphorePermit,
}

struct Mapping {
    socket: Arc<UdpSocket>,
    task: AbortHandle,
    last_used: Arc<Mutex<Instant>>,
}

struct UdpAssociation {
    mappings: HashMap<Target, Mapping>,
    tasks: JoinSet<()>,
}

impl UdpAssociation {
    fn new() -> Self {
        Self {
            mappings: HashMap::new(),
            tasks: JoinSet::new(),
        }
    }

    fn expire(&mut self, ctx: &forward::Context) {
        let ttl = Duration::from_millis(ctx.limits.udp_idle_timeout_ms);
        let now = Instant::now();
        self.mappings.retain(|_, mapping| {
            let expired = mapping.task.is_finished()
                || mapping
                    .last_used
                    .lock()
                    .map(|last| now.checked_duration_since(*last).unwrap_or_default() >= ttl)
                    .unwrap_or(true);
            if expired {
                mapping.task.abort();
                false
            } else {
                true
            }
        });
        while self.tasks.try_join_next().is_some() {}
    }

    async fn send(
        &mut self,
        target: Target,
        payload: &[u8],
        ctx: &Arc<forward::Context>,
        inbound: &str,
        replies: &mpsc::Sender<UdpReply>,
    ) -> io::Result<()> {
        ctx.allowed(inbound, Network::Udp, &target).await?;
        if payload.len() > ctx.limits.max_udp_payload {
            return Err(invalid("Snell UDP 载荷超过上限"));
        }
        self.expire(ctx);

        if !self.mappings.contains_key(&target) {
            if self.mappings.len() >= ctx.limits.max_udp_targets {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Snell UDP 目标数量超过上限",
                ));
            }
            let addresses = ctx.dns.resolve(&target).await?;
            let address = *addresses
                .first()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Snell UDP 无可用地址"))?;
            let bind = if address.is_ipv4() {
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
            };
            let socket = Arc::new(UdpSocket::bind(bind).await?);
            crate::udp::shadowsocks::prepare_buffers(&socket)?;
            socket.connect(address).await?;

            let read_socket = socket.clone();
            let tx = replies.clone();
            let task_ctx = ctx.clone();
            let tracker = ctx.children.clone();
            let last_used = Arc::new(Mutex::new(Instant::now()));
            let last_received = last_used.clone();
            let task = self.tasks.spawn(tracker.track_future(async move {
                let mut buffer = vec![0u8; 65536];
                loop {
                    let count = match read_socket.recv(&mut buffer).await {
                        Ok(count) => count,
                        Err(_) => break,
                    };
                    if count > task_ctx.limits.max_udp_payload {
                        task_ctx.stats.drop_packet();
                        continue;
                    }
                    let Some(budget) = task_ctx
                        .udp_bytes
                        .clone()
                        .try_acquire_many_owned(count.max(1) as u32)
                        .ok()
                    else {
                        task_ctx.stats.drop_packet();
                        continue;
                    };
                    let reply = UdpReply {
                        address,
                        payload: buffer[..count].to_vec(),
                        _budget: budget,
                    };
                    match tx.try_send(reply) {
                        Ok(()) => {
                            if let Ok(mut last) = last_received.lock() {
                                *last = Instant::now();
                            }
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            task_ctx.stats.drop_packet();
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    }
                }
            }));

            self.mappings.insert(
                target.clone(),
                Mapping {
                    socket,
                    task,
                    last_used,
                },
            );
        }

        let mapping = self
            .mappings
            .get_mut(&target)
            .ok_or_else(|| io::Error::other("Snell UDP 映射缺失"))?;
        let sent = mapping.socket.send(payload).await?;
        if sent != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Snell UDP 发送不完整",
            ));
        }
        if let Ok(mut last) = mapping.last_used.lock() {
            *last = Instant::now();
        }
        ctx.stats.uplink.fetch_add(sent as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn close(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.mappings.clear();
    }
}

async fn serve_udp<R, W>(
    reader: &mut Reader<R>,
    writer: &mut Writer<W>,
    ctx: &Arc<forward::Context>,
    tag: &str,
    traffic: Option<Arc<crate::telemetry::UserCounters>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let _slot = ctx
        .udp_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Snell UDP 关联上限"))?;
    let _gauge = ctx.stats.enter(Gauge::Udp);

    let (replies, mut incoming) = mpsc::channel(ctx.limits.udp_queue_packets.max(1));
    let mut association = UdpAssociation::new();
    let idle = Duration::from_millis(ctx.limits.udp_idle_timeout_ms);
    let mut deadline = Instant::now() + idle;

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            record = reader.read_record() => {
                match record {
                    Ok(Some(payload)) => {
                        let (target, data) = decode_udp_request(&payload)?;
                        if data.len() > ctx.limits.max_udp_payload {
                            ctx.stats.drop_packet();
                            continue;
                        }
                        match association.send(target, &data, ctx, tag, &replies).await {
                            Ok(()) => deadline = Instant::now() + idle,
                            Err(_) => {
                                // 路由拒绝、目标上限、解析失败等只丢弃该数据报，
                                // 不静默改变隧道语义；协议错误已在上方返回。
                                ctx.stats.drop_packet();
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(error),
                }
            }
            reply = incoming.recv() => {
                let Some(reply) = reply else { break; };
                let mut frame = Vec::with_capacity(19 + reply.payload.len());
                encode_udp_response_address(reply.address, &mut frame);
                if frame.len() + reply.payload.len() > writer.max_payload() {
                    ctx.stats.drop_packet();
                    continue;
                }
                frame.extend_from_slice(&reply.payload);
                writer.write_packet(&frame).await?;
                ctx.stats
                    .downlink
                    .fetch_add(reply.payload.len() as u64, Ordering::Relaxed);
                if let Some(traffic) = &traffic {
                    traffic.add(false, reply.payload.len());
                }
                deadline = Instant::now() + idle;
            }
        }
    }

    association.close().await;
    Ok(())
}

/// 客户端 UDP 记录：[0x01][目标地址][载荷]。
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode_udp_request(bytes: &[u8]) {
    let _ = decode_udp_request(bytes);
}

fn decode_udp_request(bytes: &[u8]) -> io::Result<(Target, Vec<u8>)> {
    let mut cursor = Cursor::new(bytes);
    if cursor.u8()? != UDP_COMMAND_FORWARD {
        return Err(invalid("不支持的 Snell UDP 命令"));
    }
    let target = read_udp_request_address(&mut cursor)?;
    Ok((target, cursor.remaining().to_vec()))
}

/// UDP 目标地址：
/// * 首字节 0x00：随后是地址族 0x04/0x06、IP 字节、端口。
/// * 首字节非 0：视为域名长度，随后是域名字符串、端口。
fn read_udp_request_address(cursor: &mut Cursor<'_>) -> io::Result<Target> {
    let first = cursor.u8()?;
    if first != 0x00 {
        let host = parse_host(cursor.bytes(usize::from(first))?)?;
        let port = cursor.u16_be()?;
        return Ok(Target { host, port });
    }

    let family = cursor.u8()?;
    let host = match family {
        ADDRESS_TYPE_IPV4 => {
            let octets: [u8; 4] = cursor
                .bytes(4)?
                .try_into()
                .map_err(|_| invalid("Snell IPv4 地址被截断"))?;
            Host::Ip(Ipv4Addr::from(octets).into())
        }
        ADDRESS_TYPE_IPV6 => {
            let octets: [u8; 16] = cursor
                .bytes(16)?
                .try_into()
                .map_err(|_| invalid("Snell IPv6 地址被截断"))?;
            Host::Ip(Ipv6Addr::from(octets).into())
        }
        // 上游 v5 对未知地址族会“吞掉两字节并继续”，这里改为 fail-closed。
        _ => return Err(invalid("不支持的 Snell UDP 地址族")),
    };
    let port = cursor.u16_be()?;
    Ok(Target { host, port })
}

/// 服务端 UDP 应答地址只使用字面 IP（客户端不接受域名来源）。
fn encode_udp_response_address(address: SocketAddr, out: &mut Vec<u8>) {
    match address {
        SocketAddr::V4(v4) => {
            out.push(ADDRESS_TYPE_IPV4);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(ADDRESS_TYPE_IPV6);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
}

// ---------------------------------------------------------------------------
// 记录层
// ---------------------------------------------------------------------------

/// 一条记录在解析完头部后、载荷尚未到齐时的中间状态。
#[derive(Clone, Copy)]
struct PendingRecord {
    padding_len: usize,
    payload_len: usize,
}

struct RecordReader<R> {
    inner: R,
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    /// v4/v5 允许首记录 padding；v6 unshaped 要求为零。
    allow_padding: bool,
    /// 已从底层读出、尚未消费的字节；最多一条记录。
    buffer: Vec<u8>,
    pending: Option<PendingRecord>,
}

impl<R: AsyncRead + Unpin> RecordReader<R> {
    async fn new(mut inner: R, psk: &[u8], allow_padding: bool) -> io::Result<Self> {
        // salt 是固定 16 字节且不参与取消安全状态机；握手阶段整体受超时约束。
        let mut salt = [0u8; SALT_LEN];
        let mut filled = 0;
        while filled < SALT_LEN {
            let count = inner.read(&mut salt[filled..]).await?;
            if count == 0 {
                return Err(truncated_error());
            }
            filled += count;
        }
        let key = derive_key(psk, &salt)?;
        let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| internal_error())?;
        Ok(Self {
            inner,
            cipher,
            nonce: [0u8; NONCE_LEN],
            salt,
            allow_padding,
            buffer: Vec::new(),
            pending: None,
        })
    }

    fn salt(&self) -> [u8; SALT_LEN] {
        self.salt
    }

    /// 读取一个记录。`Ok(None)` 表示零块（逻辑流 EOF）。
    ///
    /// 该 future 是取消安全的：所有已读字节先进入 `buffer`，头部解析结果
    /// 保存在 `pending`，被 `select!` 取消后再次调用可从断点继续。
    async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(pending) = self.pending {
                let total = pending
                    .padding_len
                    .checked_add(pending.payload_len)
                    .and_then(|value| value.checked_add(TAG_LEN))
                    .ok_or_else(|| invalid("Snell 记录长度溢出"))?;
                if total > MAX_RECORD_WIRE {
                    return Err(invalid("Snell 记录超过上限"));
                }
                self.fill(total).await?;

                let record = self.buffer.get(..total).ok_or_else(truncated_error)?;
                let (padding_bytes, payload_bytes) = record.split_at(pending.padding_len);
                let mut padding = padding_bytes.to_vec();
                let mut payload_cipher = payload_bytes.to_vec();

                // 与写入端相同的奇数字节交换，先还原再解密。
                interleave(&mut padding, &mut payload_cipher);

                let payload = self
                    .cipher
                    .decrypt(
                        (&self.nonce).into(),
                        Payload {
                            msg: &payload_cipher,
                            aad: &[],
                        },
                    )
                    .map_err(|_| auth_error())?;
                increment_nonce(&mut self.nonce)?;
                if payload.len() != pending.payload_len {
                    return Err(auth_error());
                }
                self.buffer.drain(..total);
                self.pending = None;
                return Ok(Some(payload));
            }

            self.fill(HEADER_CIPHER_LEN).await?;
            let header_cipher = self
                .buffer
                .get(..HEADER_CIPHER_LEN)
                .ok_or_else(truncated_error)?;
            let header = self
                .cipher
                .decrypt(
                    (&self.nonce).into(),
                    Payload {
                        msg: header_cipher,
                        aad: &[],
                    },
                )
                .map_err(|_| auth_error())?;
            increment_nonce(&mut self.nonce)?;

            let header: [u8; HEADER_PLAIN_LEN] =
                header.as_slice().try_into().map_err(|_| auth_error())?;
            if header[0] != HEADER_VERSION || header[1] != 0 || header[2] != 0 {
                return Err(invalid("Snell 记录头无效"));
            }
            let padding_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let payload_len = usize::from(u16::from_be_bytes([header[5], header[6]]));

            let maximum = if self.allow_padding {
                MAX_PAYLOAD
            } else {
                u16::MAX as usize
            };
            if payload_len > maximum {
                return Err(invalid("Snell 记录载荷超过上限"));
            }
            if padding_len > MAX_PADDING {
                return Err(invalid("Snell 记录 padding 超过上限"));
            }
            if padding_len > 0 && !self.allow_padding {
                return Err(invalid("Snell v6 unshaped 记录不得携带 padding"));
            }

            self.buffer.drain(..HEADER_CIPHER_LEN);
            if payload_len == 0 {
                if padding_len != 0 {
                    return Err(invalid("Snell 零块携带 padding"));
                }
                return Ok(None);
            }
            // 头部已消费且 nonce 已前进；下一轮只等待载荷。
            self.pending = Some(PendingRecord {
                padding_len,
                payload_len,
            });
        }
    }

    /// 确保 `buffer` 至少有 `needed` 字节。读取量严格不超过缺口，
    /// 因此缓冲区不会超过当前记录大小。
    async fn fill(&mut self, needed: usize) -> io::Result<()> {
        if needed > MAX_RECORD_WIRE {
            return Err(invalid("Snell 记录超过上限"));
        }
        let mut chunk = [0u8; 4096];
        while self.buffer.len() < needed {
            let want = (needed - self.buffer.len()).min(chunk.len());
            let count = self.inner.read(&mut chunk[..want]).await?;
            if count == 0 {
                return Err(truncated_error());
            }
            self.buffer.extend_from_slice(&chunk[..count]);
        }
        Ok(())
    }
}

struct RecordWriter<W> {
    inner: W,
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_LEN],
    first: bool,
    /// v4/v5 首记录 padding；v6 unshaped 固定为零。
    pad: bool,
}

impl<W: AsyncWrite + Unpin> RecordWriter<W> {
    async fn new(mut inner: W, psk: &[u8], pad: bool) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        secure_random(&mut salt)?;
        // 先完成 KDF 再写出 salt，避免内部错误时泄漏半个握手。
        let key = derive_key(psk, &salt)?;
        let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| internal_error())?;
        inner.write_all(&salt).await?;
        Ok(Self {
            inner,
            cipher,
            nonce: [0u8; NONCE_LEN],
            first: true,
            pad,
        })
    }

    async fn write_data(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let maximum = if self.pad {
                MAX_PAYLOAD
            } else {
                u16::MAX as usize
            };
            let count = data.len().min(maximum);
            self.write_record(&data[..count]).await?;
            data = &data[count..];
        }
        Ok(())
    }

    /// 零块只包含一个加密头：payload 与 tag 都不写出，nonce 仅前进一次。
    /// 这与 v4 `writeSliceRecordLocked(nil, 0)` 和 v5 `WriteZeroChunk` 一致。
    async fn write_zero(&mut self) -> io::Result<()> {
        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        let header_cipher = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &header,
                    aad: &[],
                },
            )
            .map_err(|_| internal_error())?;
        increment_nonce(&mut self.nonce)?;
        self.first = false;
        self.inner.write_all(&header_cipher).await
    }

    async fn write_record(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return self.write_zero().await;
        }
        let maximum = if self.pad {
            MAX_PAYLOAD
        } else {
            u16::MAX as usize
        };
        if payload.len() > maximum {
            return Err(invalid("Snell 写出载荷超过上限"));
        }

        // 每个方向的首个非空记录带 0x100..=0x1ff 随机 padding。
        let padding_len = if self.first && self.pad && !payload.is_empty() {
            let mut random = [0u8; 1];
            secure_random(&mut random)?;
            INITIAL_PADDING_MIN + usize::from(random[0])
        } else {
            0
        };

        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[1] = 0;
        header[2] = 0;
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());

        let header_cipher = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &header,
                    aad: &[],
                },
            )
            .map_err(|_| internal_error())?;
        increment_nonce(&mut self.nonce)?;

        let mut padding = vec![0u8; padding_len];
        if padding_len > 0 {
            secure_random(&mut padding)?;
        }
        let mut payload_cipher = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: payload,
                    aad: &[],
                },
            )
            .map_err(|_| internal_error())?;
        increment_nonce(&mut self.nonce)?;

        interleave(&mut padding, &mut payload_cipher);

        let mut record = Vec::with_capacity(HEADER_CIPHER_LEN + padding_len + payload_cipher.len());
        record.extend_from_slice(&header_cipher);
        record.extend_from_slice(&padding);
        record.extend_from_slice(&payload_cipher);
        self.inner.write_all(&record).await?;
        self.first = false;
        Ok(())
    }
}

/// v6 `unsafe-raw` 读取器：明文头 + 明文载荷。
struct RawReader<R> {
    inner: R,
    buffer: Vec<u8>,
}

impl<R: AsyncRead + Unpin> RawReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
        }
    }

    async fn fill(&mut self, needed: usize) -> io::Result<()> {
        while self.buffer.len() < needed {
            let mut data = [0u8; 4096];
            let count = (needed - self.buffer.len()).min(data.len());
            let received = self.inner.read(&mut data[..count]).await?;
            if received == 0 {
                return Err(truncated_error());
            }
            self.buffer.extend_from_slice(&data[..received]);
        }
        Ok(())
    }

    async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.fill(HEADER_PLAIN_LEN).await?;
        let header = &self.buffer[..HEADER_PLAIN_LEN];
        if header[0] != HEADER_VERSION || header[1] != 0 || header[2] != 0 {
            return Err(invalid("Snell 记录头无效"));
        }
        let padding_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let payload_len = usize::from(u16::from_be_bytes([header[5], header[6]]));
        if padding_len != 0 {
            return Err(invalid("Snell unsafe-raw 记录无效"));
        }
        if payload_len == 0 {
            self.buffer.clear();
            return Ok(None);
        }
        // header与payload均在实例中保留，select!取消后不会丢半帧。
        self.fill(HEADER_PLAIN_LEN + payload_len).await?;
        let payload = self.buffer[HEADER_PLAIN_LEN..].to_vec();
        self.buffer.clear();
        Ok(Some(payload))
    }
}

/// v6 `unsafe-raw` 写入器：不加密、不 padding。
struct RawWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> RawWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner }
    }

    async fn write_record(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(invalid("Snell raw记录过长"));
        }
        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        self.inner.write_all(&header).await?;
        self.inner.write_all(payload).await
    }

    async fn write_data(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let count = data.len().min(u16::MAX as usize);
            self.write_record(&data[..count]).await?;
            data = &data[count..];
        }
        Ok(())
    }

    async fn write_zero(&mut self) -> io::Result<()> {
        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        self.inner.write_all(&header).await
    }
}

/// v6 `default` shaped 读取器：把异步字节流喂给增量解码器。
struct ShapedV6Reader<R> {
    inner: R,
    reader: crate::protocol::snell_v6::ShapedReader,
}

impl<R: AsyncRead + Unpin> ShapedV6Reader<R> {
    fn new(inner: R, psk: &[u8]) -> Self {
        Self {
            inner,
            reader: crate::protocol::snell_v6::ShapedReader::new(psk),
        }
    }

    async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            match self.reader.next_record()? {
                Some(crate::protocol::snell_v6::DecodedRecord::Data(data)) => {
                    return Ok(Some(data));
                }
                Some(crate::protocol::snell_v6::DecodedRecord::Zero) => return Ok(None),
                None => {
                    let mut buffer = [0u8; 8192];
                    let count = self.inner.read(&mut buffer).await?;
                    if count == 0 {
                        return Err(truncated_error());
                    }
                    self.reader.push(&buffer[..count]);
                }
            }
        }
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

/// 记录读取器：按实例模式选择 AEAD 或明文记录层。
#[allow(clippy::large_enum_variant)] // 连接期构造一次，热路径只匹配。
enum Reader<R> {
    Aead(RecordReader<R>),
    ShapedV6(ShapedV6Reader<R>),
    Raw(RawReader<R>),
}

impl<R: AsyncRead + Unpin> Reader<R> {
    async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self {
            Self::Aead(reader) => reader.read_record().await,
            Self::ShapedV6(reader) => reader.read_record().await,
            Self::Raw(reader) => reader.read_record().await,
        }
    }

    fn salt(&self) -> Option<[u8; SALT_LEN]> {
        match self {
            Self::Aead(reader) => Some(reader.salt()),
            Self::ShapedV6(_) | Self::Raw(_) => None,
        }
    }
}

/// 记录写入器：按实例模式选择 AEAD 或明文记录层。
#[allow(clippy::large_enum_variant)] // 连接期构造一次，热路径只匹配。
enum Writer<W> {
    Aead(RecordWriter<W>),
    ShapedV6 {
        inner: W,
        writer: crate::protocol::snell_v6::ShapedWriter,
    },
    Raw(RawWriter<W>),
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    fn max_payload(&self) -> usize {
        match self {
            Self::Aead(writer) if writer.pad => MAX_PAYLOAD,
            _ => u16::MAX as usize,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Aead(writer) => writer.inner.flush().await,
            Self::ShapedV6 { inner, .. } => inner.flush().await,
            Self::Raw(writer) => writer.inner.flush().await,
        }
    }

    async fn write_record(&mut self, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Aead(writer) => writer.write_record(payload).await,
            Self::ShapedV6 { inner, writer } => {
                let encoded = writer.write_data_at(payload, unix_now())?;
                inner.write_all(&encoded).await
            }
            Self::Raw(writer) => writer.write_record(payload).await,
        }?;
        // obfs承载可能已缓冲首头/末块，记录写完成不能留下等待下一业务写的尾部。
        self.flush().await
    }

    async fn write_data(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Aead(writer) => writer.write_data(data).await,
            Self::ShapedV6 { inner, writer } => {
                let encoded = writer.write_data_at(data, unix_now())?;
                inner.write_all(&encoded).await
            }
            Self::Raw(writer) => writer.write_data(data).await,
        }?;
        self.flush().await
    }

    /// UDP 数据报必须保持单记录边界；v6 default 使用 packet 模式。
    async fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Aead(writer) => writer.write_record(payload).await,
            Self::ShapedV6 { inner, writer } => {
                let encoded = writer.write_packet_at(payload, unix_now())?;
                inner.write_all(&encoded).await
            }
            Self::Raw(writer) => writer.write_record(payload).await,
        }?;
        self.flush().await
    }

    async fn write_zero(&mut self) -> io::Result<()> {
        match self {
            Self::Aead(writer) => writer.write_zero().await,
            Self::ShapedV6 { inner, writer } => {
                let encoded = writer.write_zero_chunk_at(unix_now())?;
                inner.write_all(&encoded).await
            }
            Self::Raw(writer) => writer.write_zero().await,
        }?;
        self.flush().await
    }
}

/// 隧道写方向：首次需要写数据时才生成 salt，认证失败时不会产生任何输出。
struct TunnelIo<W> {
    writer: Option<Writer<W>>,
    half: Option<W>,
    mode: Mode,
}

impl<W: AsyncWrite + Unpin> TunnelIo<W> {
    fn new(half: W, mode: Mode) -> Self {
        Self {
            writer: None,
            half: Some(half),
            mode,
        }
    }

    async fn writer(&mut self, psk: &[u8]) -> io::Result<&mut Writer<W>> {
        if self.writer.is_none() {
            let half = self
                .half
                .take()
                .ok_or_else(|| io::Error::other("Snell 写方向已初始化"))?;
            let writer = match self.mode {
                Mode::Shaped | Mode::Unshaped => {
                    Writer::Aead(RecordWriter::new(half, psk, self.mode == Mode::Shaped).await?)
                }
                Mode::Default => Writer::ShapedV6 {
                    inner: half,
                    writer: crate::protocol::snell_v6::ShapedWriter::new_random(psk)?,
                },
                Mode::UnsafeRaw => Writer::Raw(RawWriter::new(half)),
            };
            self.writer = Some(writer);
        }
        self.writer
            .as_mut()
            .ok_or_else(|| io::Error::other("Snell 写方向未初始化"))
    }
}

fn interleave(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    let mut index = 0;
    while index < limit {
        std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
        index += 2;
    }
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) -> io::Result<()> {
    for byte in nonce.iter_mut() {
        *byte = (*byte).wrapping_add(1);
        if *byte != 0 {
            return Ok(());
        }
    }
    Err(io::Error::other("Snell nonce 溢出"))
}

fn derive_key(psk: &[u8], salt: &[u8; SALT_LEN]) -> io::Result<[u8; AES_KEY_LEN]> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KDF_OUTPUT_LEN),
    )
    .map_err(|_| internal_error())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; KDF_OUTPUT_LEN];
    argon
        .hash_password_into(psk, salt, &mut output)
        .map_err(|_| internal_error())?;
    let mut key = [0u8; AES_KEY_LEN];
    key.copy_from_slice(&output[..AES_KEY_LEN]);
    Ok(key)
}

fn secure_random(bytes: &mut [u8]) -> io::Result<()> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(bytes)
        .map_err(|_| io::Error::other("Snell 安全随机源失败"))
}

// ---------------------------------------------------------------------------
// v5 首记录 salt 重放缓存
// ---------------------------------------------------------------------------

/// 两代精确集合，容量严格有界；比 Bloom 更简单且无假阳性。
struct SaltReplay {
    capacity: usize,
    state: Mutex<ReplayState>,
}

struct ReplayState {
    current: usize,
    counts: [usize; 2],
    sets: [HashSet<[u8; SALT_LEN]>; 2],
}

impl SaltReplay {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(ReplayState {
                current: 0,
                counts: [0; 2],
                sets: [HashSet::new(), HashSet::new()],
            }),
        }
    }

    /// 返回 true 表示 salt 已出现过；锁中毒时按重复处理（fail-closed）。
    fn check_and_add(&self, salt: [u8; SALT_LEN]) -> bool {
        if self.capacity == 0 {
            return false;
        }
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return true,
        };
        if state.sets[0].contains(&salt) || state.sets[1].contains(&salt) {
            return true;
        }
        let current = state.current;
        state.sets[current].insert(salt);
        state.counts[current] += 1;
        if state.counts[current] >= self.capacity {
            state.counts[current] = 0;
            state.current ^= 1;
            let next = state.current;
            state.sets[next].clear();
            state.counts[next] = 0;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

/// 有界游标；所有读取都检查剩余长度。
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u8(&mut self) -> io::Result<u8> {
        let byte = *self.bytes.get(self.offset).ok_or_else(truncated_error)?;
        self.offset += 1;
        Ok(byte)
    }

    fn u16_be(&mut self) -> io::Result<u16> {
        let bytes: [u8; 2] = self.bytes(2)?.try_into().map_err(|_| truncated_error())?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn bytes(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(truncated_error)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(truncated_error)?;
        self.offset = end;
        Ok(slice)
    }

    fn remaining(&self) -> &'a [u8] {
        self.bytes.get(self.offset..).unwrap_or(&[])
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_config(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn truncated_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "Snell 记录被截断")
}

/// 认证/解密失败统一使用 PermissionDenied，且不携带内部细节。
fn auth_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Snell 认证失败")
}

fn internal_error() -> io::Error {
    io::Error::other("Snell 内部错误")
}
