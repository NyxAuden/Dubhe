//! 监听器结构与绑定辅助。

use super::*;

/// TCP的临时端口分配不检查UDP命名空间；只对 :0 的该类冲突做有限重选。
/// 显式端口及其他错误原样失败，不能静默改写用户配置。
pub(super) async fn bind_tcp_udp(address: SocketAddr) -> io::Result<(TcpListener, UdpSocket)> {
    bind_tcp_udp_with(address, UdpSocket::bind).await
}

pub(super) async fn bind_tcp_udp_with<F, Fut>(
    address: SocketAddr,
    mut bind_udp: F,
) -> io::Result<(TcpListener, UdpSocket)>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<UdpSocket>>,
{
    for attempt in 0..32 {
        let tcp = TcpListener::bind(address).await?;
        match bind_udp(tcp.local_addr()?).await {
            Ok(udp) => return Ok((tcp, udp)),
            Err(error)
                if address.port() == 0
                    && error.kind() == io::ErrorKind::AddrInUse
                    && attempt < 31 =>
            {
                drop(tcp);
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("有限循环的最后一次错误必返回")
}

pub(super) struct ShadowsocksListener {
    pub(super) prepared: Arc<shadowsocks::Prepared>,
    pub(super) udp: UdpSocket,
}

pub(super) struct Listener {
    pub(super) socket: TcpListener,
    pub(super) config: Inbound,
    pub(super) tls: Option<tls::ServerTls>,
    /// WS/gRPC/XHTTP/HTTPUpgrade 的安全层；TLS 或 REALITY。
    pub(super) security: Option<tls::InboundSecurity>,
    pub(super) handshakes: Arc<Semaphore>,
    pub(super) shadowsocks: Option<ShadowsocksListener>,
    pub(super) prepared: Option<Arc<shadowsocks::Prepared>>,
    pub(super) snell: Option<Arc<crate::protocol::snell::Prepared>>,
    pub(super) vmess: Option<Arc<vmess::Prepared>>,
    pub(super) reality: Option<Arc<tls::reality::Prepared>>,
    pub(super) xhttp: Option<Arc<crate::transport::xhttp::Pool>>,
    pub(super) shadowtls: Option<Arc<crate::transport::shadowtls::Prepared>>,
    /// VLESS Encryption 的认证密钥与 0-RTT 票据会话。
    pub(super) vless_encryption: Option<Arc<crate::transport::vless_encryption::Prepared>>,
    pub(super) detour: Option<Detour>,
}

/// 这些入口由 `Listener::security` 提供 TLS/REALITY，而不是各自读取 `tls`。
pub(super) fn uses_security(config: &Inbound) -> bool {
    matches!(
        config,
        Inbound::VlessWs { .. }
            | Inbound::VmessWs { .. }
            | Inbound::TrojanWs { .. }
            | Inbound::VlessGrpc { .. }
            | Inbound::VmessGrpc { .. }
            | Inbound::TrojanGrpc { .. }
            | Inbound::VlessXhttp { .. }
            | Inbound::VmessXhttp { .. }
            | Inbound::TrojanXhttp { .. }
            | Inbound::VlessHttpUpgrade { .. }
            | Inbound::VmessHttpUpgrade { .. }
            | Inbound::TrojanHttpUpgrade { .. }
    )
}

/// REALITY 只在 EncryptedExtensions 中表达 ALPN，模板 ServerHello 不含 ALPN。
/// 这里按内层承载设置本端 TLS 允许的 ALPN，否则 gRPC/XHTTP 客户端看不到 h2。
pub(super) fn reality_alpn(config: &Inbound) -> Vec<Vec<u8>> {
    match config {
        Inbound::VlessGrpc { .. } | Inbound::VmessGrpc { .. } | Inbound::TrojanGrpc { .. } => {
            vec![b"h2".to_vec()]
        }
        Inbound::VlessXhttp { .. } | Inbound::VmessXhttp { .. } | Inbound::TrojanXhttp { .. } => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        _ => Vec::new(),
    }
}

/// 仅使用 UDP 的 QUIC 入口；与 TCP 监听分开保存，不绑定假 TCP 套接字。
pub(super) enum UdpListener {
    Hysteria2 {
        socket: UdpSocket,
        tls: Arc<rustls::ServerConfig>,
        options: crate::transport::hysteria2::Options,
    },
    Tuic {
        socket: std::net::UdpSocket,
        prepared: crate::transport::tuic::Prepared,
    },
    XhttpH3 {
        socket: UdpSocket,
        tls: Arc<rustls::ServerConfig>,
        config: Inbound,
        vmess: Option<Arc<vmess::Prepared>>,
        pool: Arc<crate::transport::xhttp::Pool>,
    },
    Kcp {
        socket: UdpSocket,
        prepared: Arc<crate::transport::kcp::Prepared>,
        tls: Option<TlsAcceptor>,
        config: Inbound,
        vmess: Option<Arc<vmess::Prepared>>,
    },
    V2rayQuic {
        socket: UdpSocket,
        tls: Arc<rustls::ServerConfig>,
        config: Inbound,
        vmess: Option<Arc<vmess::Prepared>>,
    },
    Dokodemo {
        socket: UdpSocket,
        config: Inbound,
    },
    Wireguard {
        tag: String,
        server: Arc<crate::transport::wireguard_server::WireguardServer>,
    },
    NaiveH3 {
        socket: UdpSocket,
        tls: Arc<rustls::ServerConfig>,
        config: Inbound,
        handshakes: Arc<Semaphore>,
    },
}

/// ShadowTLS 认证后的内层协议分派；只保存同一配置内明文入站的共享状态。
#[derive(Clone)]
pub(super) enum Detour {
    Shadowsocks {
        tag: String,
        prepared: Arc<shadowsocks::Prepared>,
    },
    Snell {
        tag: String,
        prepared: Arc<snell::Prepared>,
    },
    Socks5 {
        tag: String,
        users: Vec<crate::config::User>,
    },
    Http {
        tag: String,
        users: Vec<crate::config::User>,
    },
    Mixed {
        tag: String,
        users: Vec<crate::config::User>,
    },
    Vmess {
        tag: String,
        prepared: Arc<vmess::Prepared>,
    },
}

impl Detour {
    pub(super) fn from_listener(listener: &Listener) -> Option<Self> {
        match &listener.config {
            Inbound::Shadowsocks { tag, .. } => Some(Self::Shadowsocks {
                tag: tag.clone(),
                prepared: listener.shadowsocks.as_ref()?.prepared.clone(),
            }),
            Inbound::Snell { tag, .. } => Some(Self::Snell {
                tag: tag.clone(),
                prepared: listener.snell.clone()?,
            }),
            Inbound::Socks5 { tag, users, .. } => Some(Self::Socks5 {
                tag: tag.clone(),
                users: users.clone(),
            }),
            Inbound::Http { tag, users, .. } => Some(Self::Http {
                tag: tag.clone(),
                users: users.clone(),
            }),
            Inbound::Mixed { tag, users, .. } => Some(Self::Mixed {
                tag: tag.clone(),
                users: users.clone(),
            }),
            Inbound::Vmess { tag, .. } if listener.tls.is_none() => Some(Self::Vmess {
                tag: tag.clone(),
                prepared: listener.vmess.clone()?,
            }),
            _ => None,
        }
    }

    pub(super) async fn serve<S>(
        self,
        mut stream: S,
        ctx: Arc<Context>,
        handshake: tokio::sync::OwnedSemaphorePermit,
    ) -> io::Result<()>
    where
        S: transport::DetourStream + 'static,
    {
        let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
        match self {
            Self::Shadowsocks { tag, prepared } => {
                shadowsocks::serve_generic(stream, prepared, ctx, &tag, handshake).await
            }
            Self::Snell { tag, prepared } => {
                snell::serve_stream(stream, prepared, ctx, &tag, handshake).await
            }
            Self::Socks5 { tag, users } => {
                serve_socks5_detoured(stream, &tag, &users, ctx, deadline, handshake).await
            }
            Self::Http { tag, users } => {
                serve_http(stream, &tag, &users, None, ctx, deadline, handshake).await
            }
            Self::Mixed { tag, users } => {
                use tokio::io::AsyncReadExt;
                let mut first = [0u8; 1];
                stream.read_exact(&mut first).await?;
                let stream = crate::transport::xhttp::PrefixReader::new(first.to_vec(), stream);
                if first[0] == 5 {
                    serve_socks5_detoured(stream, &tag, &users, ctx, deadline, handshake).await
                } else {
                    serve_http(stream, &tag, &users, None, ctx, deadline, handshake).await
                }
            }
            Self::Vmess { tag, prepared } => {
                let (stream, accepted) = timeout(deadline, async {
                    let mut stream = stream;
                    let accepted = prepared.handshake(&mut stream, false).await?;
                    Ok::<_, io::Error>((stream, accepted))
                })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VMess 认证超时"))??;
                let allow_udp = prepared.allow_udp();
                drop(handshake);
                serve_vmess(stream, accepted, &tag, ctx, deadline, allow_udp).await
            }
        }
    }
}
