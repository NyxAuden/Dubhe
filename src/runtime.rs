use std::{
    collections::HashMap, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

use anyhow::Result;
use ipnet::IpNet;
use tokio::{
    io::AsyncReadExt as _,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Config, Inbound},
    forward::{self, Context, Lease},
    protocol::{http, shadowsocks, snell, socks5, trojan, vless, vmess},
    session::{Command, Host, Network, Target},
    telemetry::{Gauge, Stats},
    tls, transport, udp,
};

mod accept;

/// 该 NW3 入口是否应改走内部 relay，返回其地址字符串。
///
/// 只有 `out=direct` 才改写：`egress` 与用户显式配置的 SOCKS 上游必须保持
/// 原样，否则同进程里的 Egress Portal 会被指向回环，出口语义被改。
fn nw3_relay_for(
    out: &crate::config::Nw3Out,
    tag: &str,
    addresses: &HashMap<String, SocketAddr>,
) -> Option<String> {
    if !matches!(out, crate::config::Nw3Out::Direct) {
        return None;
    }
    addresses
        .get(&format!("{NW3_RELAY_PREFIX}{tag}"))
        .map(|address| address.to_string())
}

/// 为 NW3 注入的内部入口 tag。它不会出现在配置、导出或热重载指纹里。
/// 内部 relay 的监听地址表键前缀。真实 tag 沿用它所属 NW3 入口的 tag，
/// 否则 `route.rules[].inbounds: ["nw3-in"]` 匹配不到经 relay 的流量。
pub(crate) const NW3_RELAY_PREFIX: &str = "__nw3_relay:";

/// 握手期的两个名额（全局并发 + 单 IP 在途）。协议实现只需按原样持有并在
/// 握手完成时 `drop`，两者的释放时机因此自动对齐。
pub(crate) use accept::HandshakePermits;
pub(crate) use accept::{ACCEPT_BACKOFF, recoverable_accept_error};
mod listener;
mod reload;
mod serve;
mod wireguard;
use accept::*;
use listener::*;
pub use reload::HotReloadHandle;
pub(crate) use serve::*;
use wireguard::*;

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_reality_tests.rs"]
mod reality_tests;

#[cfg(test)]
#[path = "runtime_websocket_tests.rs"]
mod websocket_tests;

/// 构造 VMess 协议状态；非 VMess 入站返回 `None`。
fn prepare_vmess(
    inbound: &Inbound,
    replay: Arc<vmess::replay::ReplayPool>,
) -> Result<Option<Arc<vmess::Prepared>>> {
    // QUIC 传输总是有 TLS，不存在明文正文；其余字段与 VMess 入口一致。
    if let Inbound::VmessQuic {
        users,
        xudp,
        packetaddr,
        allow_authenticated_length,
        ..
    } = inbound
    {
        return Ok(Some(Arc::new(vmess::Prepared::new(
            users,
            replay,
            vmess::Policy {
                xudp: *xudp,
                packetaddr: *packetaddr,
                allow_insecure_body: false,
                allow_authenticated_length: *allow_authenticated_length,
            },
        )?)));
    }
    let (Inbound::Vmess {
        users,
        xudp,
        packetaddr,
        allow_insecure_body,
        allow_authenticated_length,
        ..
    }
    | Inbound::VmessHttp {
        users,
        xudp,
        packetaddr,
        allow_insecure_body,
        allow_authenticated_length,
        ..
    }
    | Inbound::VmessReality {
        users,
        xudp,
        packetaddr,
        allow_insecure_body,
        allow_authenticated_length,
        ..
    }
    | Inbound::VmessWs {
        users,
        xudp,
        packetaddr,
        allow_insecure_body,
        allow_authenticated_length,
        ..
    }
    | Inbound::VmessGrpc {
        users,
        xudp,
        packetaddr,
        allow_insecure_body,
        allow_authenticated_length,
        ..
    }
    | Inbound::VmessXhttp {
        users,
        xudp,
        packetaddr,
        allow_insecure_body,
        allow_authenticated_length,
        ..
    }
    | Inbound::VmessHttpUpgrade {
        users,
        xudp,
        packetaddr,
        allow_insecure_body,
        allow_authenticated_length,
        ..
    }
    | Inbound::VmessKcp {
        users,
        xudp,
        packetaddr,
        allow_insecure_body,
        allow_authenticated_length,
        ..
    }) = inbound
    else {
        return Ok(None);
    };
    Ok(Some(Arc::new(vmess::Prepared::new(
        users,
        replay,
        vmess::Policy {
            xudp: *xudp,
            packetaddr: *packetaddr,
            allow_insecure_body: *allow_insecure_body,
            allow_authenticated_length: *allow_authenticated_length,
        },
    )?)))
}

pub struct Server {
    listeners: Vec<Listener>,
    udp: Vec<UdpListener>,
    /// NW3 Portal 自行绑定同端口的 TCP 与 UDP，因此不进入通用监听路径。
    portals: Vec<(String, nowhere::Portal)>,
    /// NW3 Egress 出口服务：无本地监听，主动连接远端 Portal。
    nw3_egress: Option<(String, nowhere::Egress)>,
    /// 管理/统计 API 监听；与代理业务监听分开计量。
    api: Option<(TcpListener, crate::config::ApiConfig)>,
    api_address: Option<SocketAddr>,
    context: Arc<Context>,
    shared: Arc<crate::forward::SharedContext>,
    probe_stop: Arc<std::sync::Mutex<CancellationToken>>,
    /// 探测任务的实例级根令牌：每一代用 `child_token()`，停机取消根。
    probe_root: CancellationToken,
    addresses: HashMap<String, SocketAddr>,
    cert_reloads: tls::ReloadHandle,
    reload_fingerprint: Option<serde_json::Value>,
    has_udp_listeners: bool,
}

/// 仅影响监听器生命周期的配置子集；用于判断能否热替换 `Context`。
fn reload_fingerprint(config: &Config) -> Option<serde_json::Value> {
    serde_json::to_value((
        &config.inbounds,
        &config.limits,
        &config.api,
        &config.nw3_egress,
        &config.reverse_bridges,
    ))
    .ok()
}

impl Server {
    pub fn check(config: &Config) -> Result<()> {
        config.validate()?;
        if let Some(api) = &config.api {
            // 在绑定管理端口前读取并校验 token 文件，避免带错误权限启动。
            api.load_token()?;
        }
        crate::route::check_outbounds(config)?;
        // 地理数据集引用（`geosite:` 等）在路由编译期展开；`check` 必须
        // 走到这里，否则配置写错要等到真正启动才暴露。
        crate::route::Router::new(config)?;
        for inbound in &config.inbounds {
            if let Some((certificate, private_key)) = inbound.tls_paths() {
                tls::load(certificate, private_key)?;
            }
            if let Some(reality) = inbound.reality() {
                tls::reality::check(reality)?;
            }
        }
        if config.nw3_egress.is_some() {
            // 端点、密钥与 TLS 选项由 Nowhere 的解析器一次性校验。
            drop(crate::transport::nw3::prepare_egress(config)?);
        }
        Ok(())
    }
    pub async fn bind(config: Config) -> Result<Self> {
        Self::bind_with_udp_probe(config, udp::shadowsocks::dual_stack_socket).await
    }

    async fn bind_with_udp_probe(
        config: Config,
        probe: fn() -> io::Result<UdpSocket>,
    ) -> Result<Self> {
        Self::check(&config)?;
        let context = Arc::new(Context::new(&config)?);
        // 共享槽在 run 启动时初始化；bind 到 run 之间库调用方仍可通过
        // `Arc::get_mut` 注入 DNS 等测试依赖。
        let shared = crate::forward::SharedContext::new();
        let probe_root = CancellationToken::new();
        let probe_stop = Arc::new(std::sync::Mutex::new(probe_root.child_token()));
        let replay = Arc::new(shadowsocks::replay::ReplayPool::new(
            config.limits.max_replay_entries,
        ));
        let vmess_replay = Arc::new(vmess::replay::ReplayPool::new(
            config.limits.max_vmess_replay_entries,
        ));
        let reality_replay = Arc::new(tls::reality::replay::ReplayPool::new(
            config.limits.max_reality_replay_entries,
        )?);
        let mut reality_pending = Vec::new();
        let mut reality_windows = HashMap::<[u8; 32], u64>::new();
        let mut listeners = Vec::new();
        let mut cert_reloads = Vec::new();
        let mut udp_listeners = Vec::new();
        let mut portals = Vec::new();
        let mut addresses = HashMap::new();
        // 所有监听准备成功后才会进入 run；失败时局部对象析构关闭套接字。
        // NW3 的 `out` 为 `direct`（默认）时，注入一个**仅供本进程使用**的
        // loopback SOCKS5 入口，并把 Portal 的 `out` 指向它。这样 NW3 流量
        // 走本内核的 route/limits/stats，而不是让 vendored Portal 自己直连。
        //
        // 不用「改 vendor 注入 dialer」的理由：`Outlet`/`OutboundDialer` 都是
        // `pub(crate)`，注入要在 GPL 代码里维护分叉；而 `out=` 是 Nowhere 的
        // 公开契约。代价是多一次回环往返（实测 SOCKS5 转发延迟 +0.235ms）。
        let mut inbounds = config.inbounds.clone();
        // 每个 `out=direct` 的 NW3 入口各配一个内部 SOCKS5，tag 为
        // `__nw3_relay:<原 tag>`。逐一配而不是共用一个，是因为共用会让所有
        // Portal 的出站指向同一地址（`out=egress` 也被改写），且丢失入口身份。
        let relays: Vec<(String, String)> = inbounds
            .iter()
            .filter_map(|inbound| match inbound {
                Inbound::Nw3 {
                    tag,
                    out: crate::config::Nw3Out::Direct,
                    ..
                } => Some((tag.clone(), format!("{NW3_RELAY_PREFIX}{tag}"))),
                _ => None,
            })
            .collect();
        for (_, relay_tag) in relays.iter().rev() {
            // 放在最前：NW3 分支要能查到它实际绑定的端口（listen 端口为 0）。
            inbounds.insert(
                0,
                Inbound::Socks5 {
                    tag: relay_tag.clone(),
                    listen: "127.0.0.1:0".parse().expect("静态回环地址"),
                    users: Vec::new(),
                    allow_insecure: false,
                },
            );
        }
        for (index, inbound) in inbounds.iter().enumerate() {
            // WireGuard 只监听 UDP，握手与会话由 boringtun 驱动；隧道内 TCP/UDP
            // 经 route/direct 拨号，不创建 TUN。
            if let Inbound::Wireguard {
                tag,
                listen,
                private_key,
                address,
                peers,
                mtu,
                max_peers,
                max_tcp_connections,
                max_udp_associations,
                max_queued_datagrams,
                max_handshake_inits_per_sec,
                peer_idle_timeout_secs,
            } = inbound
            {
                // 将新增入口的准备状态放到堆上，不扩大所有入口共用的 bind future。
                let (bound, server) = Box::pin(async {
                    let prepared = wireguard_server_config(
                        index,
                        private_key,
                        address,
                        peers,
                        *mtu,
                        *max_peers,
                        *max_tcp_connections,
                        *max_udp_associations,
                        *max_queued_datagrams,
                        *max_handshake_inits_per_sec,
                        *peer_idle_timeout_secs,
                    )?;
                    let socket = UdpSocket::bind(*listen).await.map_err(|error| {
                        anyhow::anyhow!("入口 {} UDP绑定失败: {:?}", inbound.tag(), error.kind())
                    })?;
                    let bound = socket.local_addr()?;
                    let server = Arc::new(
                        crate::transport::wireguard_server::WireguardServer::new(
                            Arc::new(socket),
                            prepared,
                            Arc::new(WireguardRouteDialer {
                                context: context.clone(),
                                inbound: tag.clone(),
                            }),
                        )
                        .map_err(|error| {
                            anyhow::anyhow!("入口 {} WireGuard 初始化失败: {error}", inbound.tag())
                        })?,
                    );
                    Ok::<_, anyhow::Error>((bound, server))
                })
                .await?;
                addresses.insert(tag.clone(), bound);
                udp_listeners.push(UdpListener::Wireguard {
                    tag: tag.clone(),
                    server,
                });
                continue;
            }
            // Hysteria2/TUIC 只监听 UDP，不能通过通用 TCP 监听路径。
            if let Inbound::Hysteria2 {
                tag,
                listen,
                users,
                certificate,
                private_key,
                obfs,
                udp: udp_enabled,
                up_mbps,
                down_mbps,
                ignore_client_bandwidth,
                idle_timeout_ms,
                masquerade,
                ..
            } = inbound
            {
                let mut loaded = tls::load(certificate, private_key)?;
                Arc::make_mut(&mut loaded).alpn_protocols = vec![b"h3".to_vec()];
                let obfs_mode = obfs.as_ref().map(|obfs| {
                    let password = obfs.password.0.clone().into_bytes();
                    match obfs.kind {
                        crate::config::Hysteria2ObfsType::Salamander => {
                            crate::transport::hysteria2::ObfsMode::Salamander(password)
                        }
                        crate::config::Hysteria2ObfsType::Gecko => {
                            crate::transport::hysteria2::ObfsMode::Gecko {
                                password,
                                min_packet_size: obfs.min_packet_size.unwrap_or(512) as usize,
                                max_packet_size: obfs.max_packet_size.unwrap_or(1200) as usize,
                            }
                        }
                    }
                });
                let masquerade = masquerade.as_ref().map(|masquerade| match masquerade.kind {
                    crate::config::Hysteria2MasqueradeType::String => {
                        crate::transport::hysteria2::Masquerade::String {
                            status: masquerade.status_code.unwrap_or(200),
                            content: masquerade.content.clone().unwrap_or_default().into_bytes(),
                        }
                    }
                    crate::config::Hysteria2MasqueradeType::File => {
                        crate::transport::hysteria2::Masquerade::File {
                            directory: std::path::PathBuf::from(
                                masquerade.directory.clone().unwrap_or_default(),
                            ),
                        }
                    }
                });
                let bandwidth =
                    crate::transport::hysteria2::Bandwidth::from_mbps(*up_mbps, *down_mbps)
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "入口 {} Hysteria2 带宽配置无效: {error}",
                                inbound.tag()
                            )
                        })?;
                let options = crate::transport::hysteria2::Options::with_bandwidth(
                    tag.clone(),
                    users,
                    obfs_mode,
                    masquerade,
                    *udp_enabled,
                    bandwidth,
                    *ignore_client_bandwidth,
                    Duration::from_millis(idle_timeout_ms.unwrap_or(30_000)),
                )
                .map_err(|error| {
                    anyhow::anyhow!("入口 {} Hysteria2 配置无效: {error}", inbound.tag())
                })?;
                let socket = UdpSocket::bind(*listen).await.map_err(|error| {
                    anyhow::anyhow!("入口 {} UDP绑定失败: {:?}", inbound.tag(), error.kind())
                })?;
                let address = socket.local_addr()?;
                addresses.insert(tag.clone(), address);
                udp_listeners.push(UdpListener::Hysteria2 {
                    socket,
                    tls: loaded,
                    options,
                });
                continue;
            }
            if let Inbound::Tuic {
                tag,
                listen,
                users,
                certificate,
                private_key,
                alpn,
                auth_timeout_ms,
                heartbeat_ms,
                idle_timeout_ms,
                max_streams,
                congestion_control,
                zero_rtt_handshake,
                ..
            } = inbound
            {
                let credentials = users
                    .iter()
                    .map(|user| {
                        crate::transport::tuic::Credential::parse(
                            user.name.clone(),
                            &user.uuid,
                            user.password.0.clone(),
                        )
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                let mut options = crate::transport::tuic::Options::from_limits(
                    tag.clone(),
                    credentials,
                    &config.limits,
                );
                if let Some(ms) = auth_timeout_ms {
                    options.auth_timeout = Duration::from_millis(*ms);
                }
                if let Some(ms) = heartbeat_ms {
                    options.heartbeat = Duration::from_millis(*ms);
                }
                if let Some(ms) = idle_timeout_ms {
                    options.idle_timeout = Duration::from_millis(*ms);
                }
                if let Some(value) = max_streams {
                    options.max_streams = *value;
                }
                if let Some(value) = congestion_control {
                    options.set_congestion_control(value).map_err(|error| {
                        anyhow::anyhow!("入口 {} TUIC 拥塞控制配置无效: {error}", inbound.tag())
                    })?;
                }
                options.set_zero_rtt(zero_rtt_handshake.unwrap_or(false));
                options.alpn = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
                let prepared =
                    crate::transport::tuic::prepare(options, tls::load(certificate, private_key)?)?;
                let socket = UdpSocket::bind(*listen).await.map_err(|error| {
                    anyhow::anyhow!("入口 {} UDP绑定失败: {:?}", inbound.tag(), error.kind())
                })?;
                let address = socket.local_addr()?;
                let socket = socket.into_std()?;
                addresses.insert(tag.clone(), address);
                udp_listeners.push(UdpListener::Tuic { socket, prepared });
                continue;
            }
            // NW3 由 Nowhere Portal 在 run 阶段自行绑定同端口的 TCP（TLS 1.3）与 QUIC。
            if let Inbound::Nw3 {
                tag, listen, out, ..
            } = inbound
            {
                // 只有 `out=direct` 的 Portal 才走内部 relay。`egress` 与用户
                // 显式配置的 SOCKS 上游必须保持原样——早期实现无条件覆盖，
                // 导致同进程里的 Egress Portal 也被指向回环，出口语义被改。
                let relay = nw3_relay_for(out, tag, &addresses);
                let portal = transport::nw3::prepare_with_out(inbound, relay.as_deref())?;
                addresses.insert(tag.clone(), *listen);
                portals.push((tag.clone(), portal));
                continue;
            }
            // XHTTP/3 只监听 UDP；QUIC 端点取代 TCP 监听路径。
            if let Some(xhttp) = match inbound {
                Inbound::VlessXhttp { xhttp, .. }
                | Inbound::VmessXhttp { xhttp, .. }
                | Inbound::TrojanXhttp { xhttp, .. } => Some(xhttp),
                _ => None,
            } && xhttp.h3
            {
                let (certificate, private_key) = inbound.tls_paths().ok_or_else(|| {
                    anyhow::anyhow!("入口 {} XHTTP/3 缺少 TLS 证书", inbound.tag())
                })?;
                let mut loaded = tls::load(certificate, private_key)?;
                Arc::make_mut(&mut loaded).alpn_protocols = vec![b"h3".to_vec()];
                let vmess = prepare_vmess(inbound, vmess_replay.clone())?;
                let pool =
                    transport::xhttp::Pool::new(xhttp, &config.limits, context.stats.clone());
                let socket = UdpSocket::bind(inbound.listen()).await.map_err(|error| {
                    anyhow::anyhow!("入口 {} UDP绑定失败: {:?}", inbound.tag(), error.kind())
                })?;
                let address = socket.local_addr()?;
                addresses.insert(inbound.tag().to_owned(), address);
                udp_listeners.push(UdpListener::XhttpH3 {
                    socket,
                    tls: loaded,
                    config: inbound.clone(),
                    vmess,
                    pool,
                });
                continue;
            }
            // 纯 UDP 的 dokodemo-door 直接绑定 UDP；tcp,udp 在 TCP 绑定后复用同一端口。
            if let Inbound::DokodemoDoor {
                tag,
                listen,
                network,
                ..
            } = inbound
                && crate::config::dokodemo_networks(network).is_some_and(|(tcp, udp)| udp && !tcp)
            {
                let socket = UdpSocket::bind(*listen).await.map_err(|error| {
                    anyhow::anyhow!("入口 {tag} UDP绑定失败: {:?}", error.kind())
                })?;
                let address = socket.local_addr()?;
                addresses.insert(tag.clone(), address);
                udp_listeners.push(UdpListener::Dokodemo {
                    socket,
                    config: inbound.clone(),
                });
                continue;
            }
            // V2Ray QUIC 只占用 UDP；TLS 1.3 与 h3 ALPN 由 QUIC 端点强制。
            if matches!(
                inbound,
                Inbound::VlessQuic { .. } | Inbound::VmessQuic { .. } | Inbound::TrojanQuic { .. }
            ) {
                let (certificate, private_key) = inbound.tls_paths().ok_or_else(|| {
                    anyhow::anyhow!("入口 {} V2Ray QUIC 缺少 TLS 证书", inbound.tag())
                })?;
                let mut loaded = tls::load(certificate, private_key)?;
                Arc::make_mut(&mut loaded).alpn_protocols = vec![b"h3".to_vec()];
                let vmess = prepare_vmess(inbound, vmess_replay.clone())?;
                let socket = UdpSocket::bind(inbound.listen()).await.map_err(|error| {
                    anyhow::anyhow!("入口 {} UDP绑定失败: {:?}", inbound.tag(), error.kind())
                })?;
                let address = socket.local_addr()?;
                addresses.insert(inbound.tag().to_owned(), address);
                udp_listeners.push(UdpListener::V2rayQuic {
                    socket,
                    tls: loaded,
                    config: inbound.clone(),
                    vmess,
                });
                continue;
            }
            // mKCP 只占用 UDP：KCP 会话之上再按需套 TLS，随后复用协议入站处理。
            if let Some(kcp) = match inbound {
                Inbound::VlessKcp { kcp, .. }
                | Inbound::VmessKcp { kcp, .. }
                | Inbound::TrojanKcp { kcp, .. } => Some(kcp),
                _ => None,
            } {
                let prepared = transport::kcp::prepare(kcp)?;
                let tls = match inbound.tls_paths() {
                    Some((certificate, private_key)) => {
                        Some(TlsAcceptor::from(tls::load(certificate, private_key)?))
                    }
                    None => None,
                };
                let vmess = prepare_vmess(inbound, vmess_replay.clone())?;
                let socket = UdpSocket::bind(inbound.listen()).await.map_err(|error| {
                    anyhow::anyhow!("入口 {} UDP绑定失败: {:?}", inbound.tag(), error.kind())
                })?;
                let address = socket.local_addr()?;
                addresses.insert(inbound.tag().to_owned(), address);
                udp_listeners.push(UdpListener::Kcp {
                    socket,
                    prepared,
                    tls,
                    config: inbound.clone(),
                    vmess,
                });
                continue;
            }
            let tls = if let Some((certificate, private_key)) = inbound.tls_paths() {
                let alpn = if matches!(
                    inbound,
                    Inbound::VlessWs { .. } | Inbound::VmessWs { .. } | Inbound::TrojanWs { .. }
                ) {
                    // 此入口只提供 HTTP/1.1 Upgrade，不借 ALPN 声称 HTTP/2 WebSocket。
                    vec![b"http/1.1".to_vec()]
                } else if matches!(
                    inbound,
                    Inbound::VlessGrpc { .. }
                        | Inbound::VmessGrpc { .. }
                        | Inbound::TrojanGrpc { .. }
                ) {
                    // gRPC 承载的 TLS 只提供 h2；运行时仍要求实际协商到 h2。
                    vec![b"h2".to_vec()]
                } else if matches!(
                    inbound,
                    Inbound::VlessHttpUpgrade { .. }
                        | Inbound::VmessHttpUpgrade { .. }
                        | Inbound::TrojanHttpUpgrade { .. }
                ) {
                    // HTTPUpgrade 只使用 HTTP/1.1 Upgrade。
                    vec![b"http/1.1".to_vec()]
                } else if matches!(
                    inbound,
                    Inbound::VlessXhttp { .. }
                        | Inbound::VmessXhttp { .. }
                        | Inbound::TrojanXhttp { .. }
                        | Inbound::VlessHttp { .. }
                        | Inbound::VmessHttp { .. }
                        | Inbound::TrojanHttp { .. }
                        | Inbound::Http { .. }
                        | Inbound::Naive { .. }
                ) {
                    // XHTTP 与 V2Ray HTTP 传输同时接受 HTTP/2 与 HTTP/1.1；h2 优先。
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                } else {
                    Vec::new()
                };
                let server_tls = tls::ServerTls::new(tls::load(certificate, private_key)?, alpn);
                cert_reloads.push((
                    certificate.to_path_buf(),
                    private_key.to_path_buf(),
                    server_tls.clone(),
                ));
                Some(server_tls)
            } else {
                None
            };
            let paired_udp = matches!(
                inbound,
                Inbound::Shadowsocks { .. } | Inbound::Naive { h3: true, .. }
            ) || matches!(inbound, Inbound::DokodemoDoor { network, .. }
                    if crate::config::dokodemo_networks(network).is_some_and(|(_, udp)| udp));
            let (socket, mut bound_udp) = if paired_udp {
                let (tcp, udp) = bind_tcp_udp(inbound.listen()).await.map_err(|error| {
                    anyhow::anyhow!(
                        "入口 {} TCP/UDP联合绑定失败: {:?}",
                        inbound.tag(),
                        error.kind()
                    )
                })?;
                (tcp, Some(udp))
            } else {
                (
                    TcpListener::bind(inbound.listen()).await.map_err(|error| {
                        anyhow::anyhow!("入口 {} 绑定失败: {:?}", inbound.tag(), error.kind())
                    })?,
                    None,
                )
            };
            let address = socket.local_addr()?;
            // 同一 Naive 入口的 TCP/TLS 与 QUIC 共用握手预算。
            let handshakes = Arc::new(Semaphore::new(config.limits.max_handshakes));
            if let Inbound::Naive {
                h3: true,
                certificate,
                private_key,
                ..
            } = inbound
            {
                let udp = bound_udp
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Naive H3 UDP未联合准备"))?;
                udp_listeners.push(UdpListener::NaiveH3 {
                    socket: udp,
                    tls: tls::load(certificate, private_key)?,
                    config: inbound.clone(),
                    handshakes: handshakes.clone(),
                });
            }
            let shadowsocks = if let Inbound::Shadowsocks {
                method,
                password,
                users,
                ..
            } = inbound
            {
                let keys =
                    crate::config::prepare_shadowsocks(*method, password, users.as_deref(), index)?;
                if method.is_2022() {
                    let probe = probe().map_err(|error| {
                        anyhow::anyhow!(
                            "入口 {} 双栈UDP能力不可用: {:?}",
                            inbound.tag(),
                            error.kind()
                        )
                    })?;
                    drop(probe);
                }
                let udp = bound_udp
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Shadowsocks UDP未联合准备"))?;
                udp::shadowsocks::prepare_buffers(&udp).map_err(|error| {
                    anyhow::anyhow!("入口 {} UDP缓冲准备失败: {:?}", inbound.tag(), error.kind())
                })?;
                Some(ShadowsocksListener {
                    prepared: Arc::new(shadowsocks::Prepared {
                        keys,
                        inbound: index,
                        replay: replay.clone(),
                    }),
                    udp,
                })
            } else {
                None
            };
            let vmess = prepare_vmess(inbound, vmess_replay.clone())?;
            if let Some(reality) = inbound.reality() {
                let imported = reality.prepare()?;
                reality_windows
                    .entry(imported.public_key)
                    .and_modify(|window| *window = (*window).max(reality.max_time_diff_ms))
                    .or_insert(reality.max_time_diff_ms);
                // 记录的是**即将 push 进 `listeners` 的下标**，不是入口枚举的
                // 下标。NW3/WireGuard 等入口在到达这里之前就 `continue` 了，
                // 用全入口下标会在稍后索引 `listeners` 时越界（实测
                // `NW3 + REALITY` 的合法配置 `check` 通过、`run` panic）。
                reality_pending.push((listeners.len(), reality.clone(), imported));
            }
            let xhttp = match inbound {
                Inbound::VlessXhttp { xhttp, .. }
                | Inbound::VmessXhttp { xhttp, .. }
                | Inbound::TrojanXhttp { xhttp, .. } => Some(crate::transport::xhttp::Pool::new(
                    xhttp,
                    &config.limits,
                    context.stats.clone(),
                )),
                _ => None,
            };
            let snell = if let Inbound::Snell {
                psk,
                version,
                users,
                mode,
                obfs_mode,
                ..
            } = inbound
            {
                let snell_mode = if *version == 6 {
                    match mode.as_deref() {
                        None | Some("default") => crate::protocol::snell::Mode::Default,
                        Some("unshaped") => crate::protocol::snell::Mode::Unshaped,
                        Some("unsafe-raw") => crate::protocol::snell::Mode::UnsafeRaw,
                        _ => return Err(anyhow::anyhow!("Snell v6 mode 无效")),
                    }
                } else {
                    crate::protocol::snell::Mode::Shaped
                };
                Some(Arc::new(
                    crate::protocol::snell::Prepared::new(
                        psk.0.clone().into_bytes(),
                        users
                            .iter()
                            .map(|user| crate::protocol::snell::SnellUser {
                                name: user.name.clone(),
                                user_key: user.userkey.0.clone().into_bytes(),
                            })
                            .collect(),
                        *version,
                        snell_mode,
                        config.limits.max_replay_entries,
                    )
                    .and_then(|prepared| prepared.with_obfs(obfs_mode.as_deref()))
                    .map_err(|error| {
                        anyhow::anyhow!("入口 {} Snell 配置无效: {error}", inbound.tag())
                    })?,
                ))
            } else {
                None
            };
            let shadowtls = if let Inbound::ShadowTls {
                tag,
                users,
                handshake,
                handshake_for_server_name,
                strict_mode,
                wildcard_sni,
                ..
            } = inbound
            {
                let mut server_targets = Vec::with_capacity(handshake_for_server_name.len());
                for (name, target) in handshake_for_server_name {
                    server_targets.push((name.clone(), target.target()?));
                }
                let wildcard = match wildcard_sni {
                    None => crate::transport::shadowtls::WildcardSni::Off,
                    Some(crate::config::ShadowTlsWildcardSni::Authed) => {
                        crate::transport::shadowtls::WildcardSni::Authed
                    }
                    Some(crate::config::ShadowTlsWildcardSni::All) => {
                        crate::transport::shadowtls::WildcardSni::All
                    }
                };
                Some(Arc::new(
                    crate::transport::shadowtls::Prepared::new(
                        tag.clone(),
                        users,
                        handshake.target()?,
                        server_targets,
                        *strict_mode,
                        wildcard,
                    )
                    .map_err(|error| {
                        anyhow::anyhow!("入口 {} ShadowTLS 配置无效: {error}", inbound.tag())
                    })?,
                ))
            } else {
                None
            };
            let vless_encryption = if let Some(value) = inbound.decryption() {
                match crate::config::vless_encryption::parse(value)? {
                    Some(decryption) => Some(Arc::new(
                        crate::transport::vless_encryption::Prepared::new(
                            &decryption,
                            config.limits.max_replay_entries,
                        )
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "入口 {} VLESS Encryption 配置无效: {error}",
                                inbound.tag()
                            )
                        })?,
                    )),
                    None => None,
                }
            } else {
                None
            };
            if let Inbound::DokodemoDoor { network, .. } = inbound
                && crate::config::dokodemo_networks(network).is_some_and(|(_, udp)| udp)
            {
                // 与 TCP 复用同一监听端口（包括 :0 解析出的实际端口）。
                let socket = bound_udp
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Dokodemo UDP未联合准备"))?;
                udp_listeners.push(UdpListener::Dokodemo {
                    socket,
                    config: inbound.clone(),
                });
            }
            addresses.insert(inbound.tag().to_owned(), address);
            listeners.push(Listener {
                socket,
                config: Arc::new(inbound.clone()),
                tls: tls.clone(),
                security: tls
                    .as_ref()
                    .filter(|_| uses_security(inbound))
                    .map(|tls| tls::InboundSecurity::Tls(tls.clone())),
                handshakes,
                per_ip_handshakes: config.limits.per_ip_handshakes,
                max_handshakes: config.limits.max_handshakes,
                shadowsocks,
                prepared: None,
                snell,
                vmess,
                reality: None,
                xhttp,
                shadowtls,
                vless_encryption,
                detour: None,
            });
        }
        let bound: Arc<[SocketAddr]> = addresses.values().copied().collect::<Vec<_>>().into();
        for (index, reality, imported) in reality_pending {
            let window = reality_windows[&imported.public_key];
            let prepared = Arc::new(tls::reality::Prepared::new(
                reality.clone(),
                imported,
                reality_replay.clone(),
                Duration::from_millis(2 * window + 1000),
                bound.clone(),
                reality_alpn(&listeners[index].config),
            )?);
            listeners[index].reality = Some(prepared.clone());
            if uses_security(&listeners[index].config) {
                listeners[index].security = Some(tls::InboundSecurity::Reality(prepared));
            }
        }
        // ShadowTLS 的 detour 目标在同一次绑定完成后解析，避免入口顺序依赖。
        let shadowtls_detours: Vec<usize> = listeners
            .iter()
            .enumerate()
            .filter(|(_, listener)| matches!(&*listener.config, Inbound::ShadowTls { .. }))
            .map(|(index, _)| index)
            .collect();
        for index in shadowtls_detours {
            let detour_tag = match &*listeners[index].config {
                Inbound::ShadowTls { detour, .. } => detour.clone(),
                _ => unreachable!("仅处理 ShadowTLS 入口"),
            };
            let resolved = {
                let target = listeners
                    .iter()
                    .find(|listener| listener.config.tag() == detour_tag)
                    .ok_or_else(|| anyhow::anyhow!("ShadowTLS detour 目标未绑定"))?;
                Detour::from_listener(target).ok_or_else(|| {
                    anyhow::anyhow!("ShadowTLS detour 目标 {detour_tag} 不是受支持的明文入站")
                })?
            };
            listeners[index].detour = Some(resolved);
        }
        let nw3_egress = if config.nw3_egress.is_some() {
            Some(transport::nw3::prepare_egress(&config)?)
        } else {
            None
        };
        let (api, api_address) = match &config.api {
            Some(api) => {
                let listener = TcpListener::bind(api.listen)
                    .await
                    .map_err(|error| anyhow::anyhow!("API 绑定失败: {:?}", error.kind()))?;
                let address = listener.local_addr()?;
                (Some((listener, api.clone())), Some(address))
            }
            None => (None, None),
        };
        // Shadowsocks 入口始终额外绑定 UDP；其长期任务持有启动时 Context，
        // 因此必须与其它 UDP 入口一样阻止原地热替换。
        // NW3 Egress 不读取该 Context，未变化时可由 reload_fingerprint 判定并热替换。
        let has_udp_listeners = !udp_listeners.is_empty()
            || !portals.is_empty()
            || listeners
                .iter()
                .any(|listener| listener.shadowsocks.is_some());
        Ok(Self {
            listeners,
            udp: udp_listeners,
            portals,
            nw3_egress,
            api,
            api_address,
            context,
            shared,
            probe_stop,
            probe_root,
            addresses,
            cert_reloads: tls::ReloadHandle::new(cert_reloads),
            reload_fingerprint: reload_fingerprint(&config),
            has_udp_listeners,
        })
    }
    /// 证书轮换句柄；`run` 会消费 `Server`，因此必须在启动前取得。
    ///
    /// 仅覆盖 TCP/TLS 入口；QUIC、mKCP、REALITY 与 ShadowTLS 的证书仍需
    /// 通过完整重启更新。
    pub fn reload_handle(&self) -> tls::ReloadHandle {
        self.cert_reloads.clone()
    }

    /// 零停机热重载句柄；仅在入口、limits、API 与 NW3 Egress 未变化且没有
    /// UDP 监听器时生效，否则返回 `false` 由调用方走完整重启。
    pub fn hot_reload_handle(&self) -> HotReloadHandle {
        HotReloadHandle {
            shared: self.shared.clone(),
            probe_stop: self.probe_stop.clone(),
            probe_root: self.probe_root.clone(),
            fingerprint: self.reload_fingerprint.clone(),
            has_udp_listeners: self.has_udp_listeners,
        }
    }
    pub fn local_addr(&self, tag: &str) -> Option<SocketAddr> {
        self.addresses.get(tag).copied()
    }
    /// 管理/统计 API 的实际监听地址；未配置时为 `None`。
    pub fn api_addr(&self) -> Option<SocketAddr> {
        self.api_address
    }
    pub fn stats(&self) -> Arc<Stats> {
        self.context.stats.clone()
    }
    pub async fn run(self, stop: CancellationToken) -> Result<()> {
        // 不让新增监听器 driver 扩大调用方（例如 join!）的内联状态机。
        Box::pin(self.run_with_tasks(stop, JoinSet::new())).await
    }

    async fn run_with_tasks(
        self,
        stop: CancellationToken,
        mut tasks: JoinSet<io::Result<()>>,
    ) -> Result<()> {
        self.shared.replace(self.context.clone());
        let slots = Arc::new(Semaphore::new(self.context.limits.max_connections));
        let grpc_slots = Arc::new(Semaphore::new(self.context.limits.max_grpc_streams));
        let force = CancellationToken::new();
        let probe_token = crate::sync::locked(&self.probe_stop).clone();
        self.context.spawn_urltest_probes(probe_token.clone());
        for (tag, proxy, reconnect) in self.context.reverse_bridges().iter().cloned() {
            let context = self.context.clone();
            let stop = stop.clone();
            let force = force.clone();
            tasks.spawn(async move {
                crate::reverse::bridge_loop(context, tag, proxy, reconnect, stop, force).await;
                Ok(())
            });
        }
        if let Some((listener, api)) = self.api {
            tasks.spawn(crate::admin::serve(
                listener,
                api,
                self.context.stats.clone(),
                self.context.connections.clone(),
                stop.clone(),
                force.clone(),
            ));
        }
        for udp in self.udp {
            match udp {
                UdpListener::Hysteria2 {
                    socket,
                    tls,
                    options,
                } => {
                    tasks.spawn(crate::transport::hysteria2::serve(
                        socket,
                        tls,
                        options,
                        self.context.clone(),
                        stop.clone(),
                        force.clone(),
                    ));
                }
                UdpListener::Tuic { socket, prepared } => {
                    tasks.spawn(crate::transport::tuic::serve(
                        socket,
                        prepared,
                        self.context.clone(),
                        stop.clone(),
                        force.clone(),
                    ));
                }
                UdpListener::XhttpH3 {
                    socket,
                    tls,
                    config,
                    vmess,
                    pool,
                } => {
                    tasks.spawn(crate::transport::xhttp::serve_quic(
                        socket,
                        tls,
                        Arc::new(config),
                        vmess,
                        self.context.clone(),
                        pool,
                        stop.clone(),
                        force.clone(),
                    ));
                }
                UdpListener::Kcp {
                    socket,
                    prepared,
                    tls,
                    config,
                    vmess,
                } => {
                    tasks.spawn(crate::transport::kcp::serve(
                        socket,
                        prepared,
                        tls,
                        Arc::new(config),
                        vmess,
                        self.context.clone(),
                        stop.clone(),
                        force.clone(),
                    ));
                }
                UdpListener::V2rayQuic {
                    socket,
                    tls,
                    config,
                    vmess,
                } => {
                    tasks.spawn(crate::transport::v2ray_quic::serve(
                        socket,
                        tls,
                        Arc::new(config),
                        vmess,
                        self.context.clone(),
                        stop.clone(),
                        force.clone(),
                    ));
                }
                UdpListener::Dokodemo { socket, config } => {
                    tasks.spawn(crate::transport::dokodemo::serve_udp(
                        socket,
                        Arc::new(config),
                        self.context.clone(),
                        stop.clone(),
                        force.clone(),
                    ));
                }
                UdpListener::NaiveH3 {
                    socket,
                    tls,
                    config,
                    handshakes,
                } => {
                    tasks.spawn(crate::transport::naive_h3::serve(
                        socket,
                        tls,
                        Arc::new(config),
                        self.context.clone(),
                        slots.clone(),
                        handshakes,
                        grpc_slots.clone(),
                        stop.clone(),
                        force.clone(),
                    ));
                }
                UdpListener::Wireguard { tag, server } => {
                    let initial = server.stats();
                    tracing::info!(
                        event = "inbound_ready",
                        inbound = tag,
                        rx = initial.received_datagrams,
                        tx = initial.sent_datagrams,
                        queued = initial.queued_datagrams
                    );
                    let stop = stop.clone();
                    let force = force.clone();
                    // WireGuard 的认证失败要能出现在 /metrics 上。
                    // 它在 bind 阶段就构造完毕，那时全局 Stats 还没创建，
                    // 所以在这里周期采样两个认证计数的增量并入全局 rejected。
                    // 细分（invalid_packets / unknown_peers）仍保留在
                    // WireguardServerStats 里。
                    let sampler = server.clone();
                    let global = self.context.stats.clone();
                    let interval = Duration::from_millis(self.context.limits.stats_interval_ms);
                    let sampler_stop = stop.clone();
                    tasks.spawn(async move {
                        let mut last = sampler.stats();
                        loop {
                            tokio::select! {
                                biased;
                                _ = sampler_stop.cancelled() => return Ok(()),
                                _ = tokio::time::sleep(interval) => {}
                            }
                            let now = sampler.stats();
                            let auth = (now.invalid_packets + now.unknown_peers)
                                .saturating_sub(last.invalid_packets + last.unknown_peers);
                            global.reject_many(auth);
                            last = now;
                        }
                    });
                    tasks.spawn(async move {
                        let driver = server.clone().run();
                        tokio::pin!(driver);
                        tokio::select! {
                            biased;
                            result = &mut driver => result,
                            _ = stop.cancelled() => {
                                server.shutdown();
                                driver.await
                            }
                            _ = force.cancelled() => {
                                server.shutdown();
                                driver.await
                            }
                        }
                    });
                }
            }
        }
        for (tag, portal) in self.portals {
            tracing::info!(event = "inbound_ready", inbound = tag);
            let stop = stop.clone();
            let force = force.clone();
            tasks.spawn(async move {
                // 强制关闭阶段直接丢弃 Portal future，其内部 JoinSet 随之中止子任务。
                tokio::select! {
                    result = transport::nw3::serve(portal, stop) => result,
                    _ = force.cancelled() => Ok(()),
                }
            });
        }
        if let Some((tag, egress)) = self.nw3_egress {
            tracing::info!(event = "nw3_egress_ready", service = tag);
            let stop = stop.clone();
            let force = force.clone();
            tasks.spawn(async move {
                tokio::select! {
                    result = transport::nw3::serve_egress(egress, stop) => result,
                    _ = force.cancelled() => Ok(()),
                }
            });
        }
        for mut listener in self.listeners {
            if let Some(native) = listener.shadowsocks.take() {
                let prepared = native.prepared;
                tasks.spawn(udp::shadowsocks::serve(
                    native.udp,
                    prepared.clone(),
                    self.context.clone(),
                    listener.config.tag().to_owned(),
                    stop.clone(),
                    force.clone(),
                ));
                // UDP所有权已经移到受同一屏障管理的任务，TCP仅保留共享协议状态。
                listener.prepared = Some(prepared);
            }
            tracing::info!(event = "inbound_ready", inbound = listener.config.tag());
            tasks.spawn(accept_loop(
                listener,
                self.shared.clone(),
                slots.clone(),
                grpc_slots.clone(),
                stop.clone(),
                force.clone(),
            ));
        }
        tracing::info!(event = "ready", listeners = self.addresses.len());
        let mut tick =
            tokio::time::interval(Duration::from_millis(self.context.limits.stats_interval_ms));
        let mut failure = None;
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Some(Ok(Ok(()))) => {},
                        Some(Ok(Err(error))) => failure = Some(anyhow::anyhow!("监听任务失败: {:?}", error.kind())),
                        Some(Err(_)) => failure = Some(anyhow::anyhow!("监听任务异常退出")),
                        None => {},
                    }
                    stop.cancel();
                    break;
                }
                _ = tick.tick() => {
                    let snapshot = self.context.stats.snapshot();
                    tracing::info!(event="stats", connections=snapshot.connections,tcp_flows=snapshot.tcp_flows,udp_associations=snapshot.udp_associations,grpc_streams=snapshot.grpc_streams,xhttp_sessions=snapshot.xhttp_sessions,uplink=snapshot.uplink,downlink=snapshot.downlink,dropped=snapshot.dropped,rejected=snapshot.rejected);
                }
            }
        }
        stop.cancel();
        let drained = timeout(
            Duration::from_millis(self.context.limits.shutdown_timeout_ms),
            async {
                while let Some(result) = tasks.join_next().await {
                    if !matches!(result, Ok(Ok(()))) {
                        // 只在没有更早的错误时记录：否则真正的根因（例如
                        // `accept()` 的 EMFILE）会被这条笼统信息覆盖掉。
                        failure.get_or_insert_with(|| anyhow::anyhow!("停止监听任务失败"));
                    }
                }
            },
        )
        .await
        .is_ok();
        let forced = if drained {
            0
        } else {
            self.context.stats.snapshot().connections
        };
        force.cancel();
        // 取消根令牌：热重载可能已经换过几代，启动时那份不是当前任务。
        self.probe_root.cancel();
        while let Some(result) = tasks.join_next().await {
            if !matches!(result, Ok(Ok(()))) {
                failure.get_or_insert_with(|| anyhow::anyhow!("停止监听任务失败"));
            }
        }
        // GlobalID 宽限期关联属于本实例，停机时必须主动释放，否则其映射
        // 任务会阻塞下面的子任务等待，最长可达宽限期。
        crate::mux::release_instance(&self.context);
        // 关闭出站池的等待/空闲资源，不能让children屏障等到协议空闲期限。
        self.context.outbound_stop.cancel();
        // 反向 Portal 的载体任务不依赖出站池：单独唤醒它们，否则 Bridge
        // 仍在线时读任务会一直等下一帧，停机挂在这里。
        self.context.shutdown.cancel();
        // 父任务取消会触发 UDP JoinSet 析构；等待追踪器确认子任务真正释放资源。
        self.context.children.close();
        self.context.children.wait().await;
        tracing::info!(event = "stopped", forced_connections = forced);
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod nw3_relay_tests {
    use super::*;
    use crate::config::Nw3Out;

    fn addresses(tag: &str) -> HashMap<String, SocketAddr> {
        let mut map = HashMap::new();
        map.insert(
            format!("{NW3_RELAY_PREFIX}{tag}"),
            "127.0.0.1:12345".parse().unwrap(),
        );
        map
    }

    /// `out=direct` 必须改走内部 relay：否则 NW3 流量绕过 route/limits/stats。
    #[test]
    fn direct_uses_the_internal_relay() {
        let relay = nw3_relay_for(&Nw3Out::Direct, "nw3-in", &addresses("nw3-in"));
        assert_eq!(relay.as_deref(), Some("127.0.0.1:12345"));
    }

    /// `out=egress` 与显式 SOCKS 上游**不得**被改写。
    ///
    /// 早期实现无条件覆盖，同进程里两种 Portal 并存时，`egress` 那个也会被
    /// 指向回环 SOCKS——出口语义被改，且所有 Portal 共用同一地址。
    #[test]
    fn egress_and_explicit_socks_keep_their_out() {
        let all = addresses("nw3-in");
        assert!(nw3_relay_for(&Nw3Out::Egress, "nw3-in", &all).is_none());
        assert!(nw3_relay_for(&Nw3Out::Socks("10.0.0.1:1080".into()), "nw3-in", &all).is_none());
    }

    /// relay 只按自己的 tag 取地址：两个 direct Portal 不互相串用。
    #[test]
    fn relays_are_per_inbound_tag() {
        let mut all = addresses("first");
        all.insert(
            format!("{NW3_RELAY_PREFIX}second"),
            "127.0.0.1:23456".parse().unwrap(),
        );
        assert_eq!(
            nw3_relay_for(&Nw3Out::Direct, "first", &all).as_deref(),
            Some("127.0.0.1:12345")
        );
        assert_eq!(
            nw3_relay_for(&Nw3Out::Direct, "second", &all).as_deref(),
            Some("127.0.0.1:23456")
        );
        // 没有对应 relay 的 tag 返回 None，而不是借用别人的地址。
        assert!(nw3_relay_for(&Nw3Out::Direct, "third", &all).is_none());
    }
}
