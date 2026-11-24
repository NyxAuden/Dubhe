//! Hysteria2 服务端：QUIC + HTTP/3 认证 + TCP 流 / UDP DATAGRAM 中继。
//!
//! 兼容范围与协议行为见 `docs/hysteria2.md`。本模块独立实现 wire 行为，
//! 不复制 GPL 上游代码。整体结构：
//!
//! - `wire`：与 crate 无关的编解码；
//! - `obfs`：salamander XOR 层；
//! - `socket`：quinn 抽象 UDP 套接字（可选 obfs）；
//! - 本文件：端点生命周期、认证、TCP 流中继、UDP 会话与资源上限。
//!
//! 认证使用 HTTP/3（ALPN `h3`）。Hysteria2 客户端在一次 QUIC 连接上只发送
//! 一次认证请求；认证完成后本实现交出连接，改用 quinn 的原始 `accept_bi`
//! 接收代理流。上游 sing-box 用 quic-go 的 StreamDispatcher 做同样的事，
//! 但 `h3` crate 没有公开派发钩子，因此这里采用“认证后交接”的方式。

mod brutal;
mod client;
mod client_udp;
mod gecko;
mod obfs;
mod socket;
mod wire;

pub(crate) use brutal::{Bandwidth, BrutalControl, BrutalFactory};
pub(crate) use client::{ClientPrepared, UdpKeepalive, UdpParts};
pub(crate) use client_udp::{UdpSessionReceiver, UdpSessionSender};

/// 把出站配置映射为 obfs 层；非法参数失败关闭。
pub(crate) fn client_obfs(
    obfs: Option<&crate::config::Hysteria2Obfs>,
) -> io::Result<Option<ObfsMode>> {
    let Some(obfs) = obfs else {
        return Ok(None);
    };
    let password = obfs.password.0.as_bytes().to_vec();
    if password.is_empty() || password.len() > wire::MAX_PASSWORD_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria2 obfs 密码长度无效",
        ));
    }
    match obfs.kind {
        crate::config::Hysteria2ObfsType::Salamander => Ok(Some(ObfsMode::Salamander(password))),
        crate::config::Hysteria2ObfsType::Gecko => {
            let min = obfs
                .min_packet_size
                .unwrap_or(gecko::DEFAULT_MIN_PACKET_SIZE as u64);
            let max = obfs
                .max_packet_size
                .unwrap_or(gecko::DEFAULT_MAX_PACKET_SIZE as u64);
            if min == 0 || max < min || max > gecko::MAX_FRAME as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Hysteria2 gecko 分片长度无效",
                ));
            }
            Ok(Some(ObfsMode::Gecko {
                password,
                min_packet_size: usize::try_from(min).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Hysteria2 gecko 分片长度无效")
                })?,
                max_packet_size: usize::try_from(max).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Hysteria2 gecko 分片长度无效")
                })?,
            }))
        }
    }
}

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use quinn::{Connection, Endpoint, IdleTimeout, TransportConfig, VarInt};

pub(crate) use socket::ObfsMode;

/// 预构造的 masquerade 响应；路径与内容在启动时固定。
#[derive(Clone, Debug)]
pub(crate) enum Masquerade {
    String { status: u16, content: Vec<u8> },
    File { directory: std::path::PathBuf },
}
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::User,
    forward::{self, Context},
    session::{Host, Target},
    telemetry::Gauge,
};

use self::socket::ObfsUdpSocket;

/// 单连接并发双向流上限；同时写入 QUIC `max_concurrent_bidi_streams`。
const MAX_STREAMS: usize = 512;
/// 单连接活跃 UDP 会话上限（全局额度仍由 `limits.max_udp_associations` 限制）。
const MAX_UDP_SESSIONS: usize = 64;
/// QUIC 每连接 DATAGRAM 接收/发送缓冲上限。
const MAX_DATAGRAM_BUFFER: usize = 1024 * 1024;
/// UDP 分片重组条目上限（每项最多 4 KiB，故总内存上界为 256 KiB）。
const MAX_REASSEMBLY_ENTRIES: usize = 64;
const REASSEMBLY_TTL: Duration = Duration::from_secs(8);
/// QUIC keep-alive；与上游默认值一致。
const KEEP_ALIVE: Duration = Duration::from_secs(10);

/// 运行时构造的服务端参数。
///
/// 该结构体不直接依赖 `config::Inbound`，便于配置层按需映射；`users` 在构造
/// 时即转换为 SHA-256 摘要，认证路径不再接触明文密码。
pub(crate) struct Options {
    pub tag: String,
    password_digests: Arc<Vec<[u8; 32]>>,
    /// 与 `password_digests` 同序的用户名，仅用于统计归因。
    user_names: Arc<Vec<String>>,
    pub obfs: Option<ObfsMode>,
    /// 未认证 HTTP/3 请求的伪装响应；缺省返回 404。
    pub masquerade: Option<Masquerade>,
    pub udp: bool,
    /// 服务端上行/下行带宽，方向与上游 `bandwidth.up/down` 一致。
    pub bandwidth: Bandwidth,
    /// 是否忽略客户端带宽声明。为真时使用常规拥塞控制，并在认证响应中
    /// 返回 `Hysteria-CC-RX: auto`（上游 `IgnoreClientBandwidth`）。
    pub ignore_client_bandwidth: bool,
    pub idle_timeout: Duration,
    pub max_streams: usize,
}

impl Options {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_bandwidth(
        tag: String,
        users: &[User],
        obfs: Option<ObfsMode>,
        masquerade: Option<Masquerade>,
        udp: bool,
        bandwidth: Bandwidth,
        ignore_client_bandwidth: bool,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        if tag.is_empty() {
            return Err(invalid("Hysteria2 入口 tag 为空"));
        }
        if users.is_empty() {
            return Err(invalid("Hysteria2 至少需要一个用户"));
        }
        let mut password_digests = Vec::with_capacity(users.len());
        let mut user_names = Vec::with_capacity(users.len());
        for user in users {
            if user.password.is_empty() {
                return Err(invalid("Hysteria2 用户密码不得为空"));
            }
            password_digests.push(wire::digest_password(user.password.as_bytes()));
            user_names.push(user.name.clone());
        }
        if let Some(obfs) = &obfs {
            let password = obfs.password();
            if password.is_empty() || password.len() > wire::MAX_PASSWORD_LENGTH {
                return Err(invalid("Hysteria2 obfs 密码长度无效"));
            }
            if let ObfsMode::Gecko {
                min_packet_size,
                max_packet_size,
                ..
            } = obfs
                && (*min_packet_size == 0
                    || *max_packet_size < *min_packet_size
                    || *max_packet_size > gecko::MAX_FRAME)
            {
                return Err(invalid("Hysteria2 gecko 分片长度无效"));
            }
        }
        if idle_timeout.is_zero() || idle_timeout > Duration::from_secs(86_400) {
            return Err(invalid("Hysteria2 空闲超时无效"));
        }
        Ok(Self {
            tag,
            password_digests: Arc::new(password_digests),
            user_names: Arc::new(user_names),
            obfs,
            masquerade,
            udp,
            bandwidth,
            ignore_client_bandwidth,
            idle_timeout,
            max_streams: MAX_STREAMS,
        })
    }

    /// 认证成功响应头。
    ///
    /// `Hysteria-CC-RX` 通告的是**服务端接收**带宽（上游 MaxRx），单位
    /// byte/s；`ignore_client_bandwidth` 为真时使用上游的 `auto` 哨兵。
    fn auth_headers(&self) -> io::Result<http::HeaderMap> {
        let rx = self.bandwidth.rx_bytes_per_sec();
        if self.ignore_client_bandwidth {
            wire::auth_ok_headers_auto(self.udp, rx, true)
        } else {
            wire::auth_ok_headers(self.udp, rx)
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "Hysteria2 超时")
}

/// 启动 Hysteria2 服务端；套接字必须已绑定到入口监听地址。
///
/// 调用方需要：
/// 1. 用 `tls::load` 加载证书，并把 `ServerConfig::alpn_protocols` 设为 `["h3"]`；
/// 2. 以 UDP 方式绑定 `listen`（不是 TCP）；
/// 3. 在停机时取消 `stop`，强制停机取消 `force`。
pub(crate) async fn serve(
    socket: UdpSocket,
    tls: Arc<rustls::ServerConfig>,
    options: Options,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    if !tls
        .alpn_protocols
        .iter()
        .any(|protocol| protocol.as_slice() == b"h3")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria2 TLS 必须提供 ALPN h3",
        ));
    }
    let transport = transport_config(&options)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TLS 配置无法用于 QUIC"))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport));
    let abstract_socket = ObfsUdpSocket::new(socket, options.obfs.clone())?;
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server.clone()),
        abstract_socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let server = Arc::new(server);

    let options = Arc::new(options);
    let permits = Arc::new(Semaphore::new(ctx.limits.max_connections));
    let mut connections = JoinSet::new();
    loop {
        while let Some(result) = connections.try_join_next() {
            if result.is_err() {
                tracing::debug!(event = "hysteria2_task_failed");
            }
        }
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    incoming.ignore();
                    ctx.stats.reject();
                    continue;
                };
                // 每条连接一个控制句柄：认证请求里的 Hysteria-CC-RX 是
                // 连接级参数，认证完成后写入实际 Brutal 速率。
                let control = BrutalControl::new();
                let server_config = if options.ignore_client_bandwidth {
                    // 与上游一致：忽略客户端带宽时完全不启用 Brutal，
                    // 保持 quinn 默认 Cubic 行为。
                    Arc::new((*server).clone())
                } else {
                    match brutal_server_config(&server, &options, &control) {
                        Ok(config) => config,
                        Err(error) => {
                            tracing::debug!(
                                event = "hysteria2_brutal_config_failed",
                                reason = ?error.kind()
                            );
                            incoming.ignore();
                            ctx.stats.reject();
                            continue;
                        }
                    }
                };
                let connection_options = options.clone();
                let connection_ctx = ctx.clone();
                let connection_stop = stop.clone();
                let connection_force = force.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_connection(
                        incoming,
                        server_config,
                        control,
                        connection_options,
                        connection_ctx,
                        connection_stop,
                        connection_force,
                    )
                    .await
                    {
                        // 日志只记录错误类别，绝不包含认证材料。
                        tracing::debug!(
                            event = "hysteria2_connection_closed",
                            reason = ?error.kind()
                        );
                    }
                });
            }
        }
    }

    endpoint.close(VarInt::from_u32(0), b"shutdown");
    if force.is_cancelled() {
        connections.abort_all();
    }
    let shutdown = Duration::from_millis(ctx.limits.shutdown_timeout_ms);
    let _ = timeout(shutdown, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

fn transport_config(options: &Options) -> io::Result<TransportConfig> {
    let mut transport = TransportConfig::default();
    let streams =
        u32::try_from(options.max_streams.min(MAX_STREAMS)).map_err(|_| invalid("流上限无效"))?;
    transport.max_concurrent_bidi_streams(VarInt::from_u32(streams));
    // h3 需要客户端/服务端控制流与 QPACK 流；认证完成后不再使用，
    // 但仍给出有界额度避免对端无限开单向流。
    transport.max_concurrent_uni_streams(VarInt::from_u32(16));
    transport.datagram_receive_buffer_size(Some(MAX_DATAGRAM_BUFFER));
    transport.datagram_send_buffer_size(MAX_DATAGRAM_BUFFER);
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(options.idle_timeout)
            .map_err(|_| invalid("Hysteria2 空闲超时超出 QUIC 范围"))?,
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    // Hysteria2 以 1200 字节起步；obfs salt 再增加 8 字节，仍低于 IPv6
    // 最小 MTU 1280。启用 obfs 时关闭路径 MTU 发现，避免 quinn 把报文
    // 增长到 1450 字节后叠加 8 字节 salt 触发黑洞。
    transport.initial_mtu(1200);
    if options.obfs.is_some() {
        transport.mtu_discovery_config(None);
    }
    Ok(transport)
}

/// 构造带 Brutal 控制器的单连接 `ServerConfig`。
///
/// quinn 的拥塞控制器只能在连接建立时由工厂构造，而客户端带宽声明要等
/// HTTP/3 认证后才拿到；因此工厂绑定一个共享的 [`BrutalControl`]，认证
/// 前速率保持 0（回退常规拥塞控制），认证后写入实际速率。
fn brutal_server_config(
    base: &quinn::ServerConfig,
    options: &Options,
    control: &Arc<BrutalControl>,
) -> io::Result<Arc<quinn::ServerConfig>> {
    let mut transport = transport_config(options)?;
    transport.congestion_controller_factory(BrutalFactory::new(control.clone()));
    let mut config = base.clone();
    config.transport_config(Arc::new(transport));
    Ok(Arc::new(config))
}

/// HTTP/3 认证后连接的去向。
enum AuthOutcome {
    /// 认证成功；h3 控点必须保留到代理会话结束。
    Authenticated(H3Connection, usize),
    /// 未认证但配置了 masquerade；继续用同一连接响应 GET/HEAD 等请求。
    Masquerade(H3Connection),
    /// 未认证且没有 masquerade；立即关闭。
    Rejected,
}

type H3Connection = h3::server::Connection<h3_quinn::Connection, prost::bytes::Bytes>;
type H3RequestStream =
    h3::server::RequestStream<h3_quinn::BidiStream<prost::bytes::Bytes>, prost::bytes::Bytes>;

async fn handle_connection(
    incoming: quinn::Incoming,
    server_config: Arc<quinn::ServerConfig>,
    control: Arc<BrutalControl>,
    options: Arc<Options>,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let _gauge = ctx.stats.enter(Gauge::Connection);
    let handshake_timeout = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let deadline = Instant::now()
        .checked_add(handshake_timeout)
        .unwrap_or_else(Instant::now);
    let connecting = incoming
        .accept_with(server_config)
        .map_err(|_| invalid("QUIC 握手失败"))?;
    let connection = timeout_at(deadline, connecting)
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| invalid("QUIC 握手失败"))?;

    let masquerade = options.masquerade.clone();
    match timeout_at(deadline, authenticate(&connection, &options, &control)).await {
        Ok(Ok(AuthOutcome::Authenticated(h3, user_index))) => {
            let user = options.user_names.get(user_index).cloned();
            let result = run_connection(&connection, options, ctx, stop, force, user).await;
            // `h3::server::Connection` 在 Drop 时关闭整个 QUIC 连接，因此必须
            // 保留到代理会话结束；提前丢弃会让认证成功的连接立即被关闭。
            drop(h3);
            connection.close(VarInt::from_u32(0), b"");
            result
        }
        Ok(Ok(AuthOutcome::Masquerade(h3))) => {
            let Some(handler) = masquerade else {
                connection.close(VarInt::from_u32(0), b"");
                return Ok(());
            };
            let result = serve_masquerade_connection(h3, handler, stop, force).await;
            connection.close(VarInt::from_u32(0), b"");
            result
        }
        _ => {
            // 认证失败必须计入 rejected，否则运维无法从指标区分
            // 「无人连接」与「有人在反复猜密码」。
            ctx.stats.reject();
            connection.close(VarInt::from_u32(0), b"auth failed");
            Ok(())
        }
    }
}

/// HTTP/3 认证。
///
/// 兼容上游的判定：`POST https://hysteria/auth`，密码取自 `Hysteria-Auth`，
/// 成功状态码 233。未认证请求在配置 masquerade 时返回伪装内容并继续服务同一
/// 连接；否则返回 404 并关闭。
async fn authenticate(
    connection: &Connection,
    options: &Options,
    control: &BrutalControl,
) -> io::Result<AuthOutcome> {
    let mut h3_connection: H3Connection =
        h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|_| invalid("HTTP/3 初始化失败"))?;
    let accepted = h3_connection
        .accept()
        .await
        .map_err(|_| invalid("HTTP/3 请求无效"))?;
    let Some(resolver) = accepted else {
        return Ok(AuthOutcome::Rejected);
    };
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|_| invalid("HTTP/3 请求无效"))?;

    if !wire::is_auth_request(request.method(), request.uri()) {
        return reject_request(&mut stream, &request, options, h3_connection).await;
    }
    let request_auth = match wire::parse_auth_request(request.headers()) {
        Ok(value) => value,
        Err(_) => return reject_request(&mut stream, &request, options, h3_connection).await,
    };
    let Some(user_index) =
        wire::match_password_index(&request_auth.password, &options.password_digests)
    else {
        return reject_request(&mut stream, &request, options, h3_connection).await;
    };

    // 上游：实际发送速率 = min(客户端声明的接收带宽, 服务端 MaxTx)；
    // ignoreClientBandwidth 为真时速率置 0，回退常规拥塞控制。
    let tx_bytes_per_sec = brutal::negotiate_tx_bytes(
        request_auth.rx,
        options.bandwidth,
        options.ignore_client_bandwidth,
    );
    control.set_rate(tx_bytes_per_sec);
    let headers = options.auth_headers()?;
    let response = response(wire::STATUS_AUTH_OK, headers)?;
    stream
        .send_response(response)
        .await
        .map_err(|_| invalid("HTTP/3 响应发送失败"))?;
    stream
        .finish()
        .await
        .map_err(|_| invalid("HTTP/3 响应结束失败"))?;
    Ok(AuthOutcome::Authenticated(h3_connection, user_index))
}

async fn reject_request(
    stream: &mut H3RequestStream,
    request: &http::Request<()>,
    options: &Options,
    h3_connection: H3Connection,
) -> io::Result<AuthOutcome> {
    match &options.masquerade {
        None => {
            let response = response(http::StatusCode::NOT_FOUND.as_u16(), http::HeaderMap::new())?;
            let _ = stream.send_response(response).await;
            let _ = stream.finish().await;
            Ok(AuthOutcome::Rejected)
        }
        Some(masquerade) => {
            respond_masquerade(stream, request, masquerade).await?;
            Ok(AuthOutcome::Masquerade(h3_connection))
        }
    }
}

async fn serve_masquerade_connection(
    mut connection: H3Connection,
    masquerade: Masquerade,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    loop {
        tokio::select! {
            biased;
            _ = force.cancelled() => return Ok(()),
            _ = stop.cancelled() => return Ok(()),
            accepted = connection.accept() => {
                let Some(resolver) = accepted.map_err(|_| invalid("HTTP/3 请求无效"))? else {
                    return Ok(());
                };
                let (request, mut stream) = resolver
                    .resolve_request()
                    .await
                    .map_err(|_| invalid("HTTP/3 请求无效"))?;
                // 单个请求的读写不得无限占用连接。
                let _ = timeout(
                    Duration::from_secs(10),
                    respond_masquerade(&mut stream, &request, &masquerade),
                )
                .await;
            }
        }
    }
}

const MAX_MASQUERADE_FILE: u64 = 4 * 1024 * 1024;

async fn respond_masquerade(
    stream: &mut H3RequestStream,
    request: &http::Request<()>,
    masquerade: &Masquerade,
) -> io::Result<()> {
    let (status, content_type, body) = match masquerade {
        Masquerade::String { status, content } => {
            (*status, "text/plain; charset=utf-8", content.clone())
        }
        Masquerade::File { directory } => {
            match read_masquerade_file(directory, request.uri().path()).await {
                Ok((content_type, body)) => (200u16, content_type, body),
                Err(_) => (404u16, "text/plain; charset=utf-8", b"not found".to_vec()),
            }
        }
    };
    let response = http::Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("content-length", body.len().to_string())
        .body(())
        .map_err(|_| invalid("HTTP/3 响应头无效"))?;
    stream
        .send_response(response)
        .await
        .map_err(|_| invalid("HTTP/3 响应发送失败"))?;
    if *request.method() != http::Method::HEAD && !body.is_empty() {
        stream
            .send_data(prost::bytes::Bytes::from(body))
            .await
            .map_err(|_| invalid("HTTP/3 响应发送失败"))?;
    }
    stream
        .finish()
        .await
        .map_err(|_| invalid("HTTP/3 响应结束失败"))
}

async fn read_masquerade_file(directory: &Path, path: &str) -> io::Result<(&'static str, Vec<u8>)> {
    let directory = directory.to_path_buf();
    let path = path.to_owned();
    let (file, body) =
        tokio::task::spawn_blocking(move || -> io::Result<(std::path::PathBuf, Vec<u8>)> {
            let decoded = percent_decode(&path);
            let relative = decoded.trim_start_matches('/');
            if relative.contains('\0') || relative.split('/').any(|segment| segment == "..") {
                return Err(invalid("masquerade 路径无效"));
            }
            let mut file = directory.join(relative);
            if relative.is_empty() || path.ends_with('/') {
                file.push("index.html");
            }
            if std::fs::metadata(&file)?.is_dir() {
                file.push("index.html");
            }
            let metadata = std::fs::metadata(&file)?;
            if !metadata.is_file() || metadata.len() > MAX_MASQUERADE_FILE {
                return Err(invalid("masquerade 文件无效"));
            }
            let body = std::fs::read(&file)?;
            Ok((file, body))
        })
        .await
        .map_err(|_| io::Error::other("masquerade 读取任务失败"))??;
    Ok((masquerade_content_type(&file), body))
}

fn masquerade_content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16)
        {
            output.push(byte);
            index += 3;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn response(status: u16, headers: http::HeaderMap) -> io::Result<http::Response<()>> {
    let status = http::StatusCode::from_u16(status).map_err(|_| invalid("HTTP 状态码无效"))?;
    let mut response = http::Response::new(());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

async fn run_connection(
    connection: &Connection,
    options: Arc<Options>,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
    user: Option<String>,
) -> io::Result<()> {
    // Brutal 的 RTT 由控制器在 `on_ack` 回调中直接读取，不再轮询连接。
    let mut tasks: JoinSet<()> = JoinSet::new();
    if options.udp {
        let udp_connection = connection.clone();
        let udp_options = options.clone();
        let udp_ctx = ctx.clone();
        let udp_traffic = user
            .as_ref()
            .map(|name| ctx.stats.user_counter(&options.tag, name));
        tasks.spawn(async move {
            udp_loop(udp_connection, udp_options, udp_ctx, udp_traffic).await;
        });
    }
    let streams = Arc::new(Semaphore::new(options.max_streams));
    loop {
        // 回收已结束的流任务，避免长连接在高 churn 下累积 JoinSet 句柄。
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                tracing::debug!(event = "hysteria2_task_failed");
            }
        }
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            _ = connection.closed() => break,
            accepted = connection.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let Ok(permit) = streams.clone().try_acquire_owned() else {
                    let mut send = send;
                    let _ = send.reset(VarInt::from_u32(0));
                    ctx.stats.reject();
                    continue;
                };
                let tag = options.tag.clone();
                let stream_ctx = ctx.clone();
                let stream_user = user.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) =
                        handle_stream(send, recv, &tag, &stream_ctx, stream_user.as_deref()).await
                    {
                        tracing::debug!(
                            event = "hysteria2_stream_closed",
                            reason = ?error.kind()
                        );
                    }
                });
            }
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// 单个 TCP 代理流。
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    tag: &str,
    ctx: &Arc<Context>,
    user: Option<&str>,
) -> io::Result<()> {
    let handshake = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let frame = timeout(handshake, wire::read_varint(&mut recv))
        .await
        .map_err(|_| timed_out())??;
    if frame != wire::FRAME_TYPE_TCP_REQUEST {
        return Err(invalid("未知的 Hysteria2 帧类型"));
    }
    let destination = timeout(handshake, wire::read_tcp_request(&mut recv))
        .await
        .map_err(|_| timed_out())??;
    // 规范：服务端 MUST 对每个 TCP 请求回 TCPResponse。地址解析失败也要回
    // Error，否则客户端只会看到流被重置而没有原因。
    let target = match wire::parse_host_port(&destination)
        .and_then(|(host, port)| target_from_wire(&host, port))
    {
        Ok(target) => target,
        Err(_) => {
            let response = wire::encode_tcp_response(false, "invalid address", &[])?;
            let _ = timeout(handshake, send.write_all(&response)).await;
            let _ = send.finish();
            return Ok(());
        }
    };

    // 首包嗅探：Hysteria2 的客户端通常把首包与 TCPRequest 一起发出，所以
    // 这里有机会读到 TLS SNI / HTTP Host。未为该入口配置 `sniffing` 时
    // `sniff_route_read` 直接返回原样，零开销。
    //
    // 只用读侧：写侧还要在失败分支 `finish()`，不能与读侧合成一个对象。
    let (recv, route, dial) =
        crate::transport::sniff::sniff_route_read(ctx, tag, recv, &target).await;
    match ctx.connect_routed(tag, &route, &dial).await {
        Ok(upstream) => {
            let response = wire::encode_tcp_response(true, "", &[])?;
            timeout(handshake, send.write_all(&response))
                .await
                .map_err(|_| timed_out())??;
            // 后续字节直接双向中继；已读首包由 `Prefixed` 原样回放。
            let stream = ctx.stats.count_user(tag, user, tokio::io::join(recv, send));
            forward::relay(stream, upstream, ctx.stats.clone()).await?;
        }
        Err(_) => {
            // 不回显内部错误细节；上游把 err.Error() 写回客户端。
            let response = wire::encode_tcp_response(false, "connect failed", &[])?;
            let _ = timeout(handshake, send.write_all(&response)).await;
            let _ = send.finish();
        }
    }
    Ok(())
}

fn target_from_wire(host: &str, port: u16) -> io::Result<Target> {
    if port == 0 {
        return Err(invalid("Hysteria2 目标端口为 0"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Target {
            host: Host::Ip(ip),
            port,
        });
    }
    if host.is_empty() || host.len() > 255 || !host.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid("Hysteria2 目标域名无效"));
    }
    Ok(Target {
        host: Host::Domain(host.to_ascii_lowercase()),
        port,
    })
}

/// UDP DATAGRAM 总循环。
async fn udp_loop(
    connection: Connection,
    options: Arc<Options>,
    ctx: Arc<Context>,
    traffic: Option<Arc<crate::telemetry::UserCounters>>,
) {
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut reassembler = Reassembler::default();
    loop {
        // 回收已结束的会话任务句柄。
        while tasks.try_join_next().is_some() {}
        let datagram = match connection.read_datagram().await {
            Ok(datagram) => datagram,
            Err(_) => break,
        };
        let message = match wire::decode_udp_message(&datagram) {
            Ok(message) => message,
            Err(_) => {
                ctx.stats.drop_packet();
                continue;
            }
        };
        let Some(payload) = reassembler.feed(&message) else {
            continue;
        };
        let (host, port) = match wire::parse_host_port(message.destination) {
            Ok(value) => value,
            Err(_) => {
                ctx.stats.drop_packet();
                continue;
            }
        };
        let target = match target_from_wire(&host, port) {
            Ok(target) => target,
            Err(_) => {
                ctx.stats.drop_packet();
                continue;
            }
        };
        dispatch_packet(
            &sessions,
            &mut tasks,
            &connection,
            &ctx,
            &options,
            &traffic,
            message.session_id,
            target,
            payload,
        );
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

type SessionMap = Arc<Mutex<HashMap<u32, mpsc::Sender<QueuedPacket>>>>;
type Activity = Arc<Mutex<Instant>>;

#[allow(clippy::too_many_arguments)]
fn dispatch_packet(
    sessions: &SessionMap,
    tasks: &mut JoinSet<()>,
    connection: &Connection,
    ctx: &Arc<Context>,
    options: &Arc<Options>,
    traffic: &Option<Arc<crate::telemetry::UserCounters>>,
    session_id: u32,
    target: Target,
    payload: Vec<u8>,
) {
    let existing = lock(sessions).get(&session_id).cloned();
    let sender = match existing {
        Some(sender) => sender,
        None => {
            let Ok(slot) = ctx.udp_slots.clone().try_acquire_owned() else {
                ctx.stats.reject();
                return;
            };
            let mut guard = lock(sessions);
            if guard.len() >= MAX_UDP_SESSIONS {
                ctx.stats.reject();
                return;
            }
            let (sender, receiver) = mpsc::channel(ctx.limits.udp_queue_packets);
            guard.insert(session_id, sender.clone());
            drop(guard);
            let udp_connection = connection.clone();
            let udp_ctx = ctx.clone();
            let udp_options = options.clone();
            let udp_sessions = sessions.clone();
            let _ = tasks.spawn(udp_session(
                session_id,
                receiver,
                slot,
                udp_connection,
                udp_ctx,
                udp_options,
                udp_sessions,
                traffic.clone(),
            ));
            sender
        }
    };

    let Some(packet) = QueuedPacket::reserve(ctx, target, payload) else {
        ctx.stats.drop_packet();
        return;
    };
    if sender.try_send(packet).is_err() {
        ctx.stats.drop_packet();
    }
}

struct QueuedPacket {
    target: Target,
    payload: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

impl QueuedPacket {
    fn reserve(ctx: &Context, target: Target, payload: Vec<u8>) -> Option<Self> {
        let bytes = u32::try_from(payload.len().max(1)).ok()?;
        let permit = ctx.udp_bytes.clone().try_acquire_many_owned(bytes).ok()?;
        Some(Self {
            target,
            payload,
            _budget: permit,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn udp_session(
    session_id: u32,
    mut receiver: mpsc::Receiver<QueuedPacket>,
    _slot: OwnedSemaphorePermit,
    connection: Connection,
    ctx: Arc<Context>,
    options: Arc<Options>,
    sessions: SessionMap,
    traffic: Option<Arc<crate::telemetry::UserCounters>>,
) {
    let _gauge = ctx.stats.enter(Gauge::Udp);
    let activity: Activity = Arc::new(Mutex::new(Instant::now()));
    let packet_id = Arc::new(AtomicU16::new(0));
    let mut mappings: HashMap<Target, UdpMapping> = HashMap::new();
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        // 映射读取任务通常随会话结束；这里回收异常退出的句柄。
        while tasks.try_join_next().is_some() {}
        let deadline = lock(&activity)
            .checked_add(options.idle_timeout)
            .unwrap_or_else(Instant::now);
        tokio::select! {
            _ = sleep_until(deadline) => {
                let expired = lock(&activity)
                    .checked_add(options.idle_timeout)
                    .is_none_or(|next| Instant::now() >= next);
                if expired {
                    break;
                }
            }
            packet = receiver.recv() => {
                let Some(packet) = packet else {
                    break;
                };
                if forward_to(
                    &mut mappings,
                    &mut tasks,
                    &connection,
                    &ctx,
                    &options.tag,
                    &traffic,
                    session_id,
                    packet_id.clone(),
                    &activity,
                    packet,
                )
                .await
                .is_err()
                {
                    ctx.stats.drop_packet();
                }
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    lock(&sessions).remove(&session_id);
}

/// 单目标的 UDP 出站方式。
///
/// 直连保持原有快路径（每目标一个 connected socket + 读任务）；代理出站
/// 共用一个 `RoutedUdp`，由它负责上游关联与回程。
enum UdpMapping {
    Direct(Arc<UdpSocket>),
    Proxied { outgoing: mpsc::Sender<Vec<u8>> },
}

impl UdpMapping {
    fn is_proxied(&self) -> bool {
        matches!(self, Self::Proxied { .. })
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_to(
    mappings: &mut HashMap<Target, UdpMapping>,
    tasks: &mut JoinSet<()>,
    connection: &Connection,
    ctx: &Arc<Context>,
    tag: &str,
    traffic: &Option<Arc<crate::telemetry::UserCounters>>,
    session_id: u32,
    packet_id: Arc<AtomicU16>,
    activity: &Activity,
    packet: QueuedPacket,
) -> io::Result<()> {
    // 先选路。`udp_selected` 会拒绝 reject 规则、HTTP 出站与链式出站；
    // 选到代理时走共享 UDP 关联（与 SOCKS5/VLESS 等路径同一套实现），
    // 否则保持原有的直连快路径。
    let proxied = ctx.udp_selected(tag, &packet.target).await?.proxy.is_some();
    let payload_limit = ctx.limits.max_udp_payload.min(wire::MAX_UDP_PAYLOAD);
    if packet.payload.len() > payload_limit {
        return Err(invalid("Hysteria2 UDP 载荷过长"));
    }

    // 路由变化可能把同一目标从直连改为代理（或反之）；旧映射不再适用。
    if mappings
        .get(&packet.target)
        .is_some_and(|mapping| mapping.is_proxied() != proxied)
    {
        mappings.remove(&packet.target);
    }

    if proxied {
        if !mappings.contains_key(&packet.target) {
            if mappings.len() >= ctx.limits.max_udp_targets {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "UDP 目标上限"));
            }
            // 回程要把目标地址写回 QUIC 报头，因此提前取出。
            let target_host = match &packet.target.host {
                crate::session::Host::Ip(ip) => ip.to_string(),
                crate::session::Host::Domain(domain) => domain.clone(),
            };
            let target_port = packet.target.port;
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
            let outlet =
                crate::udp::RoutedUdp::new(ctx.clone(), tag.to_owned(), packet.target.clone())
                    .await?;
            let reader_connection = connection.clone();
            let reader_traffic = traffic.clone();
            let reader_activity = activity.clone();
            let reader_packet_id = packet_id.clone();
            let reader_ctx = ctx.clone();
            let tracker = ctx.children.clone();
            let _ = tasks.spawn(tracker.track_future(async move {
                // `RoutedUdp` 的 send 与 recv 必须由同一处持有，因此整个
                // 移进任务：发送走 channel，回程在这里写回 QUIC。
                let mut outlet = outlet;
                loop {
                    tokio::select! {
                        biased;
                        outgoing = rx.recv() => {
                            let Some(payload) = outgoing else { break };
                            if outlet.send(&payload).await.is_err() {
                                break;
                            }
                        }
                        datagram = outlet.recv() => {
                            let Ok(datagram) = datagram else { break };
                            let length = datagram.payload.len();
                            let id = reader_packet_id.fetch_add(1, Ordering::Relaxed);
                            let destination = wire::format_host_port(
                                &target_host,
                                target_port,
                            );
                            let fragments = match wire::fragment_udp_message(
                                session_id,
                                id,
                                &destination,
                                &datagram.payload,
                                wire::UDP_MTU,
                            ) {
                                Ok(fragments) => fragments,
                                Err(_) => {
                                    reader_ctx.stats.drop_packet();
                                    continue;
                                }
                            };
                            let mut failed = false;
                            for fragment in fragments {
                                if reader_connection.send_datagram(fragment.into()).is_err() {
                                    reader_ctx.stats.drop_packet();
                                    failed = true;
                                    break;
                                }
                            }
                            if failed {
                                break;
                            }
                            *lock(&reader_activity) = Instant::now();
                            reader_ctx
                                .stats
                                .downlink
                                .fetch_add(length as u64, Ordering::Relaxed);
                            if let Some(counter) = &reader_traffic {
                                counter.add(false, length);
                            }
                        }
                    }
                }
            }));
            mappings.insert(packet.target.clone(), UdpMapping::Proxied { outgoing: tx });
        }
        let Some(UdpMapping::Proxied { outgoing }) = mappings.get(&packet.target) else {
            return Err(io::Error::other("UDP 映射类型不一致"));
        };
        outgoing
            .send(packet.payload.clone())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "UDP 代理映射已失效"))?;
        *lock(activity) = Instant::now();
        ctx.stats
            .uplink
            .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        if let Some(counter) = traffic {
            counter.add(true, packet.payload.len());
        }
        return Ok(());
    }

    if !mappings.contains_key(&packet.target) {
        if mappings.len() >= ctx.limits.max_udp_targets {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "UDP 目标上限"));
        }
        let address = ctx
            .dns
            .resolve(&packet.target)
            .await?
            .first()
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "无可用地址"))?;
        let bind = if address.is_ipv4() {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        };
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        // connected UDP 套接字由内核过滤非目标来源。
        socket.connect(address).await?;
        let reader_socket = socket.clone();
        let reader_connection = connection.clone();
        let reader_ctx = ctx.clone();
        let reader_traffic = traffic.clone();
        let reader_activity = activity.clone();
        let reader_packet_id = packet_id.clone();
        let tracker = ctx.children.clone();
        let _ = tasks.spawn(tracker.track_future(async move {
            let mut buffer = vec![0u8; wire::MAX_UDP_PAYLOAD];
            loop {
                let length = match reader_socket.recv(&mut buffer).await {
                    Ok(0) => continue,
                    Ok(length) => length,
                    Err(_) => break,
                };
                if length > wire::MAX_UDP_PAYLOAD {
                    reader_ctx.stats.drop_packet();
                    continue;
                }
                let destination = wire::format_host_port(&address.ip().to_string(), address.port());
                let id = reader_packet_id.fetch_add(1, Ordering::Relaxed);
                let fragments = match wire::fragment_udp_message(
                    session_id,
                    id,
                    &destination,
                    &buffer[..length],
                    wire::UDP_MTU,
                ) {
                    Ok(fragments) => fragments,
                    Err(_) => {
                        reader_ctx.stats.drop_packet();
                        continue;
                    }
                };
                for fragment in fragments {
                    if reader_connection.send_datagram(fragment.into()).is_err() {
                        reader_ctx.stats.drop_packet();
                        break;
                    }
                }
                *lock(&reader_activity) = Instant::now();
                reader_ctx
                    .stats
                    .downlink
                    .fetch_add(length as u64, Ordering::Relaxed);
                if let Some(counter) = &reader_traffic {
                    counter.add(false, length);
                }
            }
        }));
        mappings.insert(packet.target.clone(), UdpMapping::Direct(socket.clone()));
    }

    let Some(UdpMapping::Direct(socket)) = mappings.get(&packet.target) else {
        return Err(io::Error::other("UDP 映射丢失"));
    };
    let written = socket.send(&packet.payload).await?;
    if written != packet.payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "UDP 报文未完整发送",
        ));
    }
    *lock(activity) = Instant::now();
    ctx.stats
        .uplink
        .fetch_add(written as u64, Ordering::Relaxed);
    if let Some(counter) = traffic {
        counter.add(true, written);
    }
    Ok(())
}

/// UDP 分片重组。键为 `(sessionID, packetID)`，所有维度都有硬上限。
///
/// 每个条目最多 4 KiB、最多 64 个条目，因此总内存上界为 256 KiB，
/// 无需额外维护全局字节计数。
#[derive(Default)]
struct Reassembler {
    entries: HashMap<(u32, u16), FragmentEntry>,
    last_sweep: Option<Instant>,
}

struct FragmentEntry {
    total: u8,
    received: u8,
    chunks: Vec<Option<Vec<u8>>>,
    bytes: usize,
    created: Instant,
}

impl Reassembler {
    fn feed(&mut self, message: &wire::UdpMessage<'_>) -> Option<Vec<u8>> {
        if message.fragment_total <= 1 {
            return Some(message.payload.to_vec());
        }
        if message.fragment_total > wire::MAX_FRAGMENTS {
            return None;
        }
        let now = Instant::now();
        if self
            .last_sweep
            .is_none_or(|last| now.saturating_duration_since(last) >= REASSEMBLY_TTL / 2)
        {
            self.sweep(now);
        }
        let key = (message.session_id, message.packet_id);
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= MAX_REASSEMBLY_ENTRIES {
                self.evict_oldest();
            }
            self.entries.insert(
                key,
                FragmentEntry {
                    total: message.fragment_total,
                    received: 0,
                    chunks: vec![None; usize::from(message.fragment_total)],
                    bytes: 0,
                    created: now,
                },
            );
        }

        let invalid_entry = {
            let entry = self.entries.get_mut(&key)?;
            if entry.total != message.fragment_total {
                true
            } else {
                let index = usize::from(message.fragment_id);
                // 先取出“槽位是否存在/已占用”的纯值，避免同时持有不可变与
                // 可变借用。
                match entry.chunks.get(index).map(|slot| slot.is_some()) {
                    None | Some(true) => true,
                    Some(false) => {
                        if entry.bytes.saturating_add(message.payload.len()) > wire::MAX_UDP_PAYLOAD
                        {
                            true
                        } else {
                            if let Some(slot) = entry.chunks.get_mut(index) {
                                *slot = Some(message.payload.to_vec());
                            }
                            entry.bytes = entry.bytes.saturating_add(message.payload.len());
                            entry.received = entry.received.saturating_add(1);
                            false
                        }
                    }
                }
            }
        };
        if invalid_entry {
            self.entries.remove(&key);
            return None;
        }
        let complete = self
            .entries
            .get(&key)
            .is_some_and(|entry| entry.received >= entry.total);
        if !complete {
            return None;
        }
        let entry = self.entries.remove(&key)?;
        if entry.bytes > wire::MAX_UDP_PAYLOAD {
            return None;
        }
        let mut output = Vec::with_capacity(entry.bytes);
        for chunk in entry.chunks.into_iter().flatten() {
            output.extend_from_slice(&chunk);
        }
        if output.len() != entry.bytes || output.len() > wire::MAX_UDP_PAYLOAD {
            return None;
        }
        Some(output)
    }

    fn sweep(&mut self, now: Instant) {
        self.entries
            .retain(|_, entry| now.saturating_duration_since(entry.created) < REASSEMBLY_TTL);
        self.last_sweep = Some(now);
    }

    fn evict_oldest(&mut self) {
        let mut oldest: Option<((u32, u16), Instant)> = None;
        for (key, entry) in &self.entries {
            if oldest.is_none_or(|(_, created)| entry.created < created) {
                oldest = Some((*key, entry.created));
            }
        }
        if let Some((key, _)) = oldest {
            self.entries.remove(&key);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
