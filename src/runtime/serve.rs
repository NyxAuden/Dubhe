//! 已认证入站连接的协议分派与转发。
//!
//! `runtime` 负责监听、握手与资源许可；这里只处理认证成功后的业务流。

use super::*;

// 普通 TLS Vision 与 REALITY 复用同一 VLESS 业务分派，不复制认证或 UDP codec。
/// 反向 Mux portal 隧道的固定路由目标（与 Xray 命令 4 一致）。
pub(super) const REVERSE_TARGET: &str = "v1.rvs.cool";

/// 把已认证的反向连接交给对应的 `reverse` 出站 portal。
pub(super) fn serve_reverse<S>(
    stream: S,
    inbound: &str,
    user: Option<&str>,
    declared: Option<&str>,
    ctx: Arc<Context>,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 反向载体也是「新业务」：到期或配额用尽的账户不能再注册隧道，
    // 否则它仍能把 Portal 的流量引到自己这里。
    if !ctx.stats.admit_user(inbound, user) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "账户配额已用尽或已到期",
        ));
    }
    // 优先用 `users[].reverse.tag` 声明的归属（Xray 写法）。
    // 未声明时默认拒绝：否则任何已认证账户只要命中 reverse 路由就能成为
    // Portal 载体。旧行为需显式打开 `reverse_route_fallback`。
    let tag = match declared {
        Some(tag) => std::sync::Arc::<str>::from(tag),
        None if !ctx.reverse_route_fallback => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "该账户未声明 reverse.tag，不能建立反向隧道",
            ));
        }
        None => {
            let target = Target {
                host: Host::Domain(REVERSE_TARGET.to_owned()),
                port: 0,
            };
            let selected = ctx.router.select_outbound(inbound, Network::Tcp, &target);
            let Some(tag) = selected.reverse else {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "反向 Mux 连接未命中 reverse 出站",
                ));
            };
            tag
        }
    };
    ctx.reverse.attach(&tag, stream, &ctx)
}

pub(super) async fn serve_controlled_vless<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    mut stream: tls::controlled::Controlled<S>,
    accepted: vless::FlowAccepted,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    allow_udp: bool,
) -> io::Result<()> {
    // 认证已完成：把之后的客户端字节归到该用户；Vision/Mux 共用同一承载。
    let user = match &accepted.accepted {
        vless::Accepted::Single(request) => request.user.clone(),
        vless::Accepted::Mux { user } | vless::Accepted::Reverse { user, .. } => Some(user.clone()),
    };
    if let vless::Accepted::Reverse { tag: declared, .. } = &accepted.accepted {
        let declared = declared.clone();
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        return match accepted.vision {
            Some(uuid) => {
                let stream = tls::vision::Vision::new(stream, uuid);
                serve_reverse(stream, tag, user.as_deref(), declared.as_deref(), ctx)
            }
            None => serve_reverse(stream, tag, user.as_deref(), declared.as_deref(), ctx),
        };
    }
    // 命令 3 与「命令 1 + v1.mux.cool」都进入复用层；Vision 包装保持不变。
    let mux = match &accepted.accepted {
        vless::Accepted::Mux { .. } => true,
        vless::Accepted::Reverse { .. } => false,
        vless::Accepted::Single(request) => {
            request.command == Command::Connect && crate::mux::is_mux_target(&request.target)
        }
    };
    if mux {
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        return match accepted.vision {
            Some(uuid) => {
                let stream = tls::vision::Vision::new(stream, uuid);
                crate::mux::serve(stream, ctx, tag.to_owned(), allow_udp, user.as_deref()).await
            }
            None => {
                crate::mux::serve(stream, ctx, tag.to_owned(), allow_udp, user.as_deref()).await
            }
        };
    }
    if let vless::Accepted::Single(request) = &accepted.accepted
        && request.command == Command::Connect
        && let Some(version) = udp::uot_version(&request.target)
    {
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        return match accepted.vision {
            Some(uuid) => {
                let stream = tls::vision::Vision::new(stream, uuid);
                udp::uot(
                    stream,
                    ctx,
                    tag.to_owned(),
                    version,
                    request.user.as_deref(),
                )
                .await
            }
            None => {
                udp::uot(
                    stream,
                    ctx,
                    tag.to_owned(),
                    version,
                    request.user.as_deref(),
                )
                .await
            }
        };
    }
    if let Some(uuid) = accepted.vision {
        let target = match &accepted.accepted {
            vless::Accepted::Single(request) if request.command == Command::Connect => {
                Some(request.target.clone())
            }
            // Mux/UoT 已在上面提前分派；此处只可能来自非法 flow/命令组合。
            _ => None,
        };
        // VLESS 应答必须先于 Vision 记录层建立；随后在 Vision 解包后的内层
        // 字节流上嗅探首包，与明文路径语义一致。
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        let stream = tls::vision::Vision::new(stream, uuid);
        let Some(target) = target else {
            return Err(io::Error::other("Vision 会话缺少目标"));
        };
        // 准入必须在嗅探/拨号之前：否则到期账户仍能触发 DNS 与上游连接，
        // 并从握手结果区分目标是否可达。
        if !ctx.stats.admit_user(tag, user.as_deref()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "账户配额已用尽或已到期",
            ));
        }
        let (stream, route, dial) =
            crate::transport::sniff::sniff_route(&ctx, tag, stream, &target).await;
        let upstream = ctx.connect_routed(tag, &route, &dial).await?;
        let stream = ctx.stats.count_user(tag, user.as_deref(), stream);
        return forward::relay(stream, upstream, ctx.stats.clone()).await;
    }
    match accepted.accepted {
        vless::Accepted::Mux { .. } => Err(io::Error::other("Mux 已提前分派")),
        vless::Accepted::Reverse { .. } => unreachable!("反向 Mux 已提前分派"),
        vless::Accepted::Single(request) if request.command == Command::Connect => {
            // 准入在嗅探/拨号之前，理由同 Vision 分支。
            if !ctx.stats.admit_user(tag, user.as_deref()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "账户配额已用尽或已到期",
                ));
            }
            let (stream, route, dial) =
                crate::transport::sniff::sniff_route(&ctx, tag, stream, &request.target).await;
            let target = ctx.connect_routed(tag, &route, &dial).await?;
            let mut stream = stream;
            timeout(deadline, vless::reply(&mut stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
            let stream = ctx.stats.count_user(tag, user.as_deref(), stream);
            forward::relay(stream, target, ctx.stats.clone()).await
        }
        vless::Accepted::Single(request) => {
            udp::vless(
                stream,
                request.target,
                ctx,
                tag.to_owned(),
                request.user.as_deref(),
            )
            .await
        }
    }
}

pub(super) async fn serve_plain_vision_vless_impl<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    mut stream: S,
    accepted: vless::FlowAccepted,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    allow_udp: bool,
) -> io::Result<()> {
    // 认证已完成：把之后的客户端字节归到该用户；Vision/Mux 共用同一承载。
    let user = match &accepted.accepted {
        vless::Accepted::Single(request) => request.user.clone(),
        vless::Accepted::Mux { user } | vless::Accepted::Reverse { user, .. } => Some(user.clone()),
    };
    if let vless::Accepted::Reverse { tag: declared, .. } = &accepted.accepted {
        let declared = declared.clone();
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        return match accepted.vision {
            Some(uuid) => {
                let stream = tls::vision::Vision::new_plain(stream, uuid);
                serve_reverse(stream, tag, user.as_deref(), declared.as_deref(), ctx)
            }
            None => serve_reverse(stream, tag, user.as_deref(), declared.as_deref(), ctx),
        };
    }
    // 命令 3 与「命令 1 + v1.mux.cool」都进入复用层；Vision 包装保持不变。
    let mux = match &accepted.accepted {
        vless::Accepted::Mux { .. } => true,
        vless::Accepted::Reverse { .. } => false,
        vless::Accepted::Single(request) => {
            request.command == Command::Connect && crate::mux::is_mux_target(&request.target)
        }
    };
    if mux {
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        return match accepted.vision {
            Some(uuid) => {
                let stream = tls::vision::Vision::new_plain(stream, uuid);
                crate::mux::serve(stream, ctx, tag.to_owned(), allow_udp, user.as_deref()).await
            }
            None => {
                crate::mux::serve(stream, ctx, tag.to_owned(), allow_udp, user.as_deref()).await
            }
        };
    }
    if let vless::Accepted::Single(request) = &accepted.accepted
        && request.command == Command::Connect
        && let Some(version) = udp::uot_version(&request.target)
    {
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        return match accepted.vision {
            Some(uuid) => {
                let stream = tls::vision::Vision::new_plain(stream, uuid);
                udp::uot(
                    stream,
                    ctx,
                    tag.to_owned(),
                    version,
                    request.user.as_deref(),
                )
                .await
            }
            None => {
                udp::uot(
                    stream,
                    ctx,
                    tag.to_owned(),
                    version,
                    request.user.as_deref(),
                )
                .await
            }
        };
    }
    if let Some(uuid) = accepted.vision {
        let target = match &accepted.accepted {
            vless::Accepted::Single(request) if request.command == Command::Connect => {
                Some(request.target.clone())
            }
            // Mux/UoT 已在上面提前分派；此处只可能来自非法 flow/命令组合。
            _ => None,
        };
        // VLESS 应答必须先于 Vision 记录层建立；随后在 Vision 解包后的内层
        // 字节流上嗅探首包，与明文路径语义一致。
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        let stream = tls::vision::Vision::new_plain(stream, uuid);
        let Some(target) = target else {
            return Err(io::Error::other("Vision 会话缺少目标"));
        };
        // 准入必须在嗅探/拨号之前：否则到期账户仍能触发 DNS 与上游连接，
        // 并从握手结果区分目标是否可达。
        if !ctx.stats.admit_user(tag, user.as_deref()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "账户配额已用尽或已到期",
            ));
        }
        let (stream, route, dial) =
            crate::transport::sniff::sniff_route(&ctx, tag, stream, &target).await;
        let upstream = ctx.connect_routed(tag, &route, &dial).await?;
        let stream = ctx.stats.count_user(tag, user.as_deref(), stream);
        return forward::relay(stream, upstream, ctx.stats.clone()).await;
    }
    match accepted.accepted {
        vless::Accepted::Mux { .. } => Err(io::Error::other("Mux 已提前分派")),
        vless::Accepted::Reverse { .. } => unreachable!("反向 Mux 已提前分派"),
        vless::Accepted::Single(request) if request.command == Command::Connect => {
            // 准入在嗅探/拨号之前，理由同 Vision 分支。
            if !ctx.stats.admit_user(tag, user.as_deref()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "账户配额已用尽或已到期",
                ));
            }
            let (stream, route, dial) =
                crate::transport::sniff::sniff_route(&ctx, tag, stream, &request.target).await;
            let target = ctx.connect_routed(tag, &route, &dial).await?;
            let mut stream = stream;
            timeout(deadline, vless::reply(&mut stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
            let stream = ctx.stats.count_user(tag, user.as_deref(), stream);
            forward::relay(stream, target, ctx.stats.clone()).await
        }
        vless::Accepted::Single(request) => {
            udp::vless(
                stream,
                request.target,
                ctx,
                tag.to_owned(),
                request.user.as_deref(),
            )
            .await
        }
    }
}

pub(super) fn serve_plain_vision_vless<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
    accepted: vless::FlowAccepted,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    allow_udp: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'static>> {
    let tag = tag.to_owned();
    Box::pin(async move {
        serve_plain_vision_vless_impl(stream, accepted, &tag, ctx, deadline, allow_udp).await
    })
}

pub(super) async fn serve_trojan_reality(
    stream: TcpStream,
    tag: &str,
    users: &[crate::config::User],
    prepared: Arc<tls::reality::Prepared>,
    ctx: Arc<Context>,
    handshake: super::HandshakePermits,
    deadline: Duration,
) -> io::Result<()> {
    let absolute = tokio::time::Instant::now() + deadline;
    let mut stream = match prepared.accept(stream, &ctx, absolute).await? {
        tls::reality::Accepted::Fallback { client, target } => {
            drop(handshake);
            return prepared.fallback(client, target).await;
        }
        tls::reality::Accepted::Local(stream) => *stream,
    };
    let request = tokio::time::timeout_at(absolute, trojan::handshake(&mut stream, users))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY/Trojan 认证超时"))??;
    drop(handshake);
    match request.command {
        Command::Connect => serve_trojan_connect(stream, tag, ctx, &request).await,
        Command::UdpAssociate => {
            udp::trojan(stream, ctx, tag.to_owned(), request.user.as_deref()).await
        }
        Command::Bind => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "该协议不支持 BIND",
        )),
    }
}

pub(super) async fn handle_vmess_reality(
    stream: TcpStream,
    tag: &str,
    prepared: Arc<vmess::Prepared>,
    reality: Arc<tls::reality::Prepared>,
    ctx: Arc<Context>,
    handshake: super::HandshakePermits,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let absolute = tokio::time::Instant::now() + deadline;
    let mut stream = match reality.accept(stream, &ctx, absolute).await? {
        tls::reality::Accepted::Fallback { client, target } => {
            drop(handshake);
            return reality.fallback(client, target).await;
        }
        tls::reality::Accepted::Local(stream) => *stream,
    };
    let accepted = tokio::time::timeout_at(absolute, prepared.handshake(&mut stream, true))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY/VMess 认证超时"))??;
    let allow_udp = prepared.allow_udp();
    drop(handshake);
    serve_vmess(stream, accepted, tag, ctx, deadline, allow_udp).await
}

pub(super) async fn handle_vmess(
    stream: TcpStream,
    tag: &str,
    tls: Option<tls::ServerTls>,
    prepared: Arc<vmess::Prepared>,
    ctx: Arc<Context>,
    handshake: super::HandshakePermits,
) -> io::Result<()> {
    use tokio::io::{AsyncRead, AsyncWrite};
    // 一次有限分派抹除仅用于直承载/标准TLS两种类型，不引入永久worker。
    trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
    stream.set_nodelay(true)?;
    let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let (stream, accepted) = timeout(deadline, async {
        let tls_enabled = tls.is_some();
        let mut stream: Box<dyn Io> = match tls {
            Some(tls) => Box::new(tls.accept(stream).await?),
            None => Box::new(stream),
        };
        let accepted = prepared.handshake(&mut stream, tls_enabled).await?;
        Ok::<_, io::Error>((stream, accepted))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VMess TLS/认证超时"))??;
    let allow_udp = prepared.allow_udp();
    drop(handshake);
    serve_vmess(stream, accepted, tag, ctx, deadline, allow_udp).await
}

pub(crate) async fn serve_vmess<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
    accepted: vmess::Accepted,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    allow_udp: bool,
) -> io::Result<()> {
    serve_vmess_scoped(stream, accepted, tag, ctx, deadline, allow_udp, None).await
}

pub(crate) async fn serve_vmess_scoped<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
    mut accepted: vmess::Accepted,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    allow_udp: bool,
    lease: Option<Lease>,
) -> io::Result<()> {
    // VMess 认证已完成：之后所有客户端字节归到该用户，Mux 子流共用承载。
    let user = accepted.user.clone();
    let mut stream = ctx.stats.admit_counter(tag, Some(user.as_str()), stream)?;
    // 命令 3 与「命令 1 + v1.mux.cool」都进入复用层。
    let mux = matches!(&accepted.mode, vmess::Mode::Mux)
        || matches!(
            &accepted.mode,
            vmess::Mode::Tcp(target) if crate::mux::is_mux_target(target)
        );
    if mux {
        timeout(deadline, accepted.reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VMess 应答超时"))??;
        let stream = vmess::body::Stream::new(
            stream,
            accepted.security,
            accepted.options,
            accepted.key,
            accepted.iv,
        )?;
        return crate::mux::serve_scoped(
            stream,
            ctx,
            tag.to_owned(),
            allow_udp,
            lease,
            Some(user.as_str()),
        )
        .await;
    }
    // 克隆模式以避免 `reply(&mut accepted)` 与目标借用冲突；Target 很小。
    match accepted.mode.clone() {
        vmess::Mode::Tcp(target) => {
            let uot = udp::uot_version(&target);
            // 响应头必须写原始流（独立密钥的明文帧），因此在构造加密正文流
            // 之前写出；正文流建立后才能读取并回放业务首包做嗅探。
            timeout(deadline, accepted.reply(&mut stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VMess 应答超时"))??;
            let stream = vmess::body::Stream::new(
                stream,
                accepted.security,
                accepted.options,
                accepted.key,
                accepted.iv,
            )?;
            match uot {
                Some(version) => {
                    udp::uot(stream, ctx, tag.to_owned(), version, Some(user.as_str())).await
                }
                None => {
                    let (stream, route, dial) =
                        crate::transport::sniff::sniff_route(&ctx, tag, stream, &target).await;
                    let upstream = ctx.connect_routed(tag, &route, &dial).await?;
                    forward::relay(stream, upstream, ctx.stats.clone()).await
                }
            }
        }
        // Mux 已在上面提前分派；此分支仅防御性返回错误，不 panic。
        vmess::Mode::Mux => Err(io::Error::other("VMess Mux 已提前分派")),
        vmess::Mode::Udp(_) | vmess::Mode::PacketAddr => {
            udp::vmess::serve(stream, accepted, ctx, tag.to_owned(), lease).await
        }
    }
}

pub(super) async fn handle_websocket(
    stream: TcpStream,
    config: &Inbound,
    security: Option<tls::InboundSecurity>,
    prepared: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    handshake: super::HandshakePermits,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let websocket = match config {
        Inbound::VlessWs { websocket, .. }
        | Inbound::VmessWs { websocket, .. }
        | Inbound::TrojanWs { websocket, .. } => websocket,
        _ => return Err(io::Error::other("入口不是 WebSocket")),
    };
    let duration = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let absolute = tokio::time::Instant::now() + duration;
    // TLS/REALITY 都提供加密承载；REALITY 视为真实安全层。
    let tls_enabled = security.is_some();
    let stream = tokio::time::timeout_at(absolute, async {
        let io: Box<dyn tls::Io> = match security {
            Some(security) => match security.accept(stream, &ctx, absolute).await? {
                tls::AcceptedInbound::Fallback => return Ok(None),
                tls::AcceptedInbound::Stream { io, alpn } => {
                    if alpn.as_deref().is_some_and(|alpn| alpn != b"http/1.1") {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "WebSocket ALPN 必须为 HTTP/1.1",
                        ));
                    }
                    io
                }
            },
            None => Box::new(stream),
        };
        Ok(Some(
            crate::transport::websocket::accept(io, websocket).await?,
        ))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS/WebSocket 握手超时"))??;
    let Some(stream) = stream else {
        return Ok(());
    };
    let mut stream: Box<dyn tls::Io> = match ctx.vless_encryption(config.tag()) {
        Some(prepared) => Box::new(
            tokio::time::timeout_at(absolute, prepared.accept(stream))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "VLESS Encryption 握手超时")
                })??,
        ),
        None => Box::new(stream),
    };
    match config {
        Inbound::VlessWs {
            tag, users, xudp, ..
        } => {
            let accepted = tokio::time::timeout_at(
                absolute,
                vless::read_plain_request(&mut stream, users, *xudp),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket/VLESS 认证超时"))??;
            drop(handshake);
            serve_plain_vless(stream, accepted, tag, ctx, duration, *xudp).await
        }
        Inbound::TrojanWs { tag, users, .. } => {
            let request =
                tokio::time::timeout_at(absolute, trojan::read_request(&mut stream, users))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "WebSocket/Trojan 认证超时")
                    })??;
            drop(handshake);
            match request.command {
                Command::Connect => serve_trojan_connect(stream, tag, ctx, &request).await,
                Command::UdpAssociate => {
                    udp::trojan(stream, ctx, tag.clone(), request.user.as_deref()).await
                }
                Command::Bind => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "该协议不支持 BIND",
                )),
            }
        }
        Inbound::VmessWs { tag, .. } => {
            let prepared = prepared.ok_or_else(|| io::Error::other("VMess 未准备"))?;
            let accepted =
                tokio::time::timeout_at(absolute, prepared.handshake(&mut stream, tls_enabled))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "WebSocket/VMess 认证超时")
                    })??;
            let allow_udp = prepared.allow_udp();
            drop(handshake);
            serve_vmess(stream, accepted, tag, ctx, duration, allow_udp).await
        }
        _ => unreachable!("已验证 WebSocket 入口类型"),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_reality_encrypted(
    prepared: Arc<crate::transport::vless_encryption::Prepared>,
    stream: tls::reality::Stream,
    users: &[crate::config::VlessUser],
    xudp: bool,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    absolute: tokio::time::Instant,
    handshake: super::HandshakePermits,
) -> io::Result<()> {
    let mut stream = tokio::time::timeout_at(absolute, prepared.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY/VLESS Encryption 超时"))??;
    let accepted = tokio::time::timeout_at(
        absolute,
        vless::handshake_with_xudp(&mut stream, users, xudp),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY/VLESS 认证超时"))??;
    drop(handshake);
    serve_plain_vless_scoped(stream, accepted, tag, ctx, deadline, xudp, None).await
}

pub(crate) async fn serve_plain_vless<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
    accepted: vless::Accepted,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    allow_udp: bool,
) -> io::Result<()> {
    serve_plain_vless_scoped(stream, accepted, tag, ctx, deadline, allow_udp, None).await
}

pub(crate) async fn serve_plain_vless_scoped<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
    accepted: vless::Accepted,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    allow_udp: bool,
    lease: Option<Lease>,
) -> io::Result<()> {
    // 认证已完成：之后所有客户端字节都归到该用户；Mux 子流共用同一承载。
    let user = match &accepted {
        vless::Accepted::Single(request) => request.user.clone(),
        vless::Accepted::Mux { user } | vless::Accepted::Reverse { user, .. } => Some(user.clone()),
    };
    // Mux / 反向 Mux 的字节由**子流**按用户归因（`mux::serve` 内部对每条子流
    // 计数）。若在这里也包装一层 `UserCounted`，同一个字节会被算两次——
    // 实测 5 字节业务配 Mux 后 `/stats/users` 记成 26/20（多出的是 Mux 帧头）。
    // 因此只有非 Mux 的单流路径才包装外层。
    let is_mux = matches!(
        accepted,
        vless::Accepted::Mux { .. } | vless::Accepted::Reverse { .. }
    );
    let mut stream = if is_mux {
        // Mux 子流按账户准入：外层只统计承载帧。
        ctx.stats.count_user(tag, None, stream)
    } else {
        ctx.stats.admit_counter(tag, user.as_deref(), stream)?
    };
    if let vless::Accepted::Reverse { tag: declared, .. } = &accepted {
        let declared = declared.clone();
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        return serve_reverse(stream, tag, user.as_deref(), declared.as_deref(), ctx);
    }
    let request = match accepted {
        vless::Accepted::Single(request) => request,
        vless::Accepted::Reverse { .. } => unreachable!("反向 Mux 已提前分派"),
        vless::Accepted::Mux { .. } => {
            timeout(deadline, vless::reply(&mut stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
            return crate::mux::serve_scoped(
                stream,
                ctx,
                tag.to_owned(),
                allow_udp,
                lease,
                user.as_deref(),
            )
            .await;
        }
    };
    // 命令 1 + v1.mux.cool 也进入 Mux；先于 UoT 判断，避免与发现目标混淆。
    if request.command == Command::Connect && crate::mux::is_mux_target(&request.target) {
        timeout(deadline, vless::reply(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
        return crate::mux::serve_scoped(
            stream,
            ctx,
            tag.to_owned(),
            allow_udp,
            lease,
            user.as_deref(),
        )
        .await;
    }
    match request.command {
        Command::Connect if udp::uot_version(&request.target).is_some() => {
            let version = udp::uot_version(&request.target).expect("已判定 UoT 目标");
            timeout(deadline, vless::reply(&mut stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
            udp::uot(
                stream,
                ctx,
                tag.to_owned(),
                version,
                request.user.as_deref(),
            )
            .await
        }
        Command::Connect => {
            // 嗅探在应答前完成：客户端可能随请求夹带业务首包。
            let (stream, route, dial) =
                crate::transport::sniff::sniff_route(&ctx, tag, stream, &request.target).await;
            let target = ctx.connect_routed(tag, &route, &dial).await?;
            let mut stream = stream;
            timeout(deadline, vless::reply(&mut stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
            forward::relay(stream, target, ctx.stats.clone()).await
        }
        Command::UdpAssociate => {
            udp::vless_scoped(
                stream,
                request.target,
                ctx,
                tag.to_owned(),
                lease,
                request.user.as_deref(),
            )
            .await
        }
        Command::Bind => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VLESS 不支持 BIND",
        )),
    }
}

/// Trojan CONNECT 统一入口：先按策略嗅探首包，再建立上游连接并转发。
///
/// 嗅探失败或未启用时目标保持不变；`dest_override` 决定是否用域名拨号。
pub(crate) async fn serve_trojan_connect<S>(
    stream: S,
    tag: &str,
    ctx: Arc<Context>,
    request: &crate::session::Request,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let target = &request.target;
    let stream = ctx
        .stats
        .admit_counter(tag, request.user.as_deref(), stream)?;
    let (stream, route, dial) =
        crate::transport::sniff::sniff_route(&ctx, tag, stream, target).await;
    let target = ctx.connect_routed(tag, &route, &dial).await?;
    forward::relay(stream, target, ctx.stats.clone()).await
}

pub(super) async fn serve_socks5_stream<S>(
    mut stream: S,
    tag: &str,
    users: &[crate::config::User],
    ctx: Arc<Context>,
    deadline: Duration,
    handshake: super::HandshakePermits,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = timeout(deadline, socks5::handshake(&mut stream, users))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "握手超时"))??;
    drop(handshake);
    // 准入必须在拨号/建监听之前：`serve_socks5_stream` 没有便宜的身份传递
    // 路径，所以在这里查一次。
    if !ctx.stats.admit_user(tag, request.user.as_deref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "账户配额已用尽或已到期",
        ));
    }
    match request.command {
        Command::Connect => serve_socks5_connect(stream, tag, ctx, deadline, request.target).await,
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TLS Mixed 的 SOCKS 仅支持 CONNECT",
        )),
    }
}

pub(super) async fn serve_socks5(
    mut stream: TcpStream,
    tag: &str,
    users: &[crate::config::User],
    ctx: Arc<Context>,
    deadline: Duration,
    handshake: super::HandshakePermits,
) -> io::Result<()> {
    let request = timeout(deadline, socks5::handshake(&mut stream, users))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "握手超时"))??;
    drop(handshake);
    // UDP ASSOCIATE 的业务载荷不走这条 TCP 流，因此只归因 CONNECT/BIND。
    let user = request.user.clone();
    match request.command {
        Command::Connect => {
            let stream = ctx.stats.admit_counter(tag, user.as_deref(), stream)?;
            serve_socks5_connect(stream, tag, ctx, deadline, request.target).await
        }
        Command::UdpAssociate => {
            udp::socks(
                stream,
                request.target,
                ctx,
                tag.to_owned(),
                request.user.as_deref(),
            )
            .await
        }
        Command::Bind => {
            if !ctx.stats.admit_user(tag, user.as_deref()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "账户配额已用尽或已到期",
                ));
            }
            serve_socks5_bind(stream, tag, ctx, deadline, request.target).await
        }
    }
}

/// ShadowTLS 内层 SOCKS5 没有独立 UDP 套接字，只接受 CONNECT。
pub(super) async fn serve_socks5_detoured<S>(
    mut stream: S,
    tag: &str,
    users: &[crate::config::User],
    ctx: Arc<Context>,
    deadline: Duration,
    handshake: super::HandshakePermits,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = timeout(deadline, socks5::handshake(&mut stream, users))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "握手超时"))??;
    drop(handshake);
    if !ctx.stats.admit_user(tag, request.user.as_deref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "账户配额已用尽或已到期",
        ));
    }
    match request.command {
        Command::Connect => serve_socks5_connect(stream, tag, ctx, deadline, request.target).await,
        Command::UdpAssociate | Command::Bind => {
            let _ = timeout(
                deadline,
                socks5::reply(
                    &mut stream,
                    7,
                    udp::wildcard(std::net::Ipv4Addr::UNSPECIFIED.into()),
                ),
            )
            .await;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ShadowTLS 内层 SOCKS5 只支持 CONNECT",
            ))
        }
    }
}

/// SOCKS5 BIND：在控制连接的本机地址上监听并接受一个入站连接。
///
/// 出于安全边界，监听地址始终取控制连接的本地 IP，而不是客户端请求的
/// 任意地址；请求中的 IP 只作为期望对端过滤（未指定表示任意），端口 0 表示
/// 内核选择。只接受一个入站连接，随后在控制连接与入站连接之间转发。
pub(super) async fn serve_socks5_bind(
    mut stream: TcpStream,
    _tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    expected: crate::session::Target,
) -> io::Result<()> {
    let local = stream.local_addr()?;
    let expected_ip = match expected.host {
        crate::session::Host::Ip(ip) => ip,
        crate::session::Host::Domain(_) => {
            let _ = timeout(
                deadline,
                socks5::reply(&mut stream, 8, udp::wildcard(local.ip())),
            )
            .await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 BIND 目标必须是 IP 地址",
            ));
        }
    };
    if !expected_ip.is_unspecified() && expected_ip != local.ip() {
        let _ = timeout(
            deadline,
            socks5::reply(&mut stream, 2, udp::wildcard(local.ip())),
        )
        .await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 BIND 目标地址与本机监听地址不符",
        ));
    }
    let listener =
        match TcpListener::bind(std::net::SocketAddr::new(local.ip(), expected.port)).await {
            Ok(listener) => listener,
            Err(error) => {
                let _ = timeout(
                    deadline,
                    socks5::reply(&mut stream, 1, udp::wildcard(local.ip())),
                )
                .await;
                return Err(error);
            }
        };
    let bound = listener.local_addr()?;
    timeout(deadline, socks5::reply(&mut stream, 0, bound))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 BIND 应答超时"))??;

    let accepted = timeout(deadline, async {
        loop {
            let (incoming, peer) = listener.accept().await?;
            let ip_matches = expected_ip.is_unspecified() || peer.ip() == expected_ip;
            let port_matches = expected.port == 0 || peer.port() == expected.port;
            if ip_matches && port_matches {
                return Ok::<_, io::Error>((incoming, peer));
            }
            drop(incoming);
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 BIND 等待入站连接超时"))??;
    let (incoming, peer) = accepted;
    drop(listener);
    timeout(deadline, socks5::reply(&mut stream, 0, peer))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 BIND 应答超时"))??;
    forward::relay(stream, incoming, ctx.stats.clone()).await
}

pub(super) async fn serve_socks5_connect<S>(
    stream: S,
    tag: &str,
    ctx: Arc<Context>,
    deadline: Duration,
    request: crate::session::Target,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (stream, route, dial) =
        crate::transport::sniff::sniff_route(&ctx, tag, stream, &request).await;
    let mut stream = stream;
    let target = match ctx.connect_routed(tag, &route, &dial).await {
        Ok(target) => target,
        Err(error) => {
            let code = match error.kind() {
                io::ErrorKind::PermissionDenied => 2,
                io::ErrorKind::ConnectionRefused => 5,
                io::ErrorKind::NotFound => 4,
                _ => 1,
            };
            let _ = timeout(
                deadline,
                socks5::reply(
                    &mut stream,
                    code,
                    udp::wildcard(std::net::Ipv4Addr::UNSPECIFIED.into()),
                ),
            )
            .await;
            return Err(error);
        }
    };
    let bound = target
        .local_addr()
        .ok()
        .unwrap_or_else(|| udp::wildcard(std::net::Ipv4Addr::UNSPECIFIED.into()));
    timeout(deadline, socks5::reply(&mut stream, 0, bound))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "应答超时"))??;
    forward::relay(stream, target, ctx.stats.clone()).await
}

pub(crate) async fn serve_http<S>(
    stream: S,
    tag: &str,
    users: &[crate::config::User],
    tls: Option<tls::ServerTls>,
    ctx: Arc<Context>,
    deadline: Duration,
    handshake: super::HandshakePermits,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match tls {
        Some(tls) => {
            let accepted = timeout(deadline, tls.accept(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTPS 握手超时"))??;
            let alpn = accepted.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            if alpn.as_deref() == Some(b"h2") {
                return serve_http_h2(accepted, tag, users, ctx, deadline, handshake).await;
            }
            serve_http_h1(accepted, tag, users, ctx, deadline, handshake).await
        }
        None => serve_http_h1(stream, tag, users, ctx, deadline, handshake).await,
    }
}

pub(super) async fn serve_http_h1<S>(
    mut stream: S,
    tag: &str,
    users: &[crate::config::User],
    ctx: Arc<Context>,
    deadline: Duration,
    handshake: super::HandshakePermits,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let accepted = timeout(deadline, http::handshake(&mut stream, users))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP 代理握手超时"))??;
    drop(handshake);
    let user = accepted.request.user.clone();
    let mut stream = ctx.stats.admit_counter(tag, user.as_deref(), stream)?;
    let target = match ctx.connect(tag, &accepted.request.target).await {
        Ok(target) => target,
        Err(error) => {
            let _ = timeout(deadline, http::status_reply(&mut stream, 502)).await;
            return Err(error);
        }
    };
    match accepted.rewritten {
        Some(head) => {
            let mut target = target;
            tokio::io::AsyncWriteExt::write_all(&mut target, &head).await?;
            if !accepted.early.is_empty() {
                tokio::io::AsyncWriteExt::write_all(&mut target, &accepted.early).await?;
            }
            forward::relay(stream, target, ctx.stats.clone()).await
        }
        None => {
            timeout(deadline, http::status_reply(&mut stream, 200))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP 代理应答超时"))??;
            let app = crate::transport::xhttp::PrefixReader::new(accepted.early, stream);
            forward::relay(app, target, ctx.stats.clone()).await
        }
    }
}

pub(super) async fn serve_http_h2<S>(
    io: S,
    tag: &str,
    users: &[crate::config::User],
    ctx: Arc<Context>,
    deadline: Duration,
    handshake: super::HandshakePermits,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use ::http::{Method, Response, StatusCode};
    let mut builder = h2::server::Builder::new();
    builder.max_concurrent_streams(64);
    let mut connection = timeout(deadline, builder.handshake(io))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP/2 代理握手超时"))?
        .map_err(io::Error::other)?;
    // 首次认证成功前的绝对期限：H2 握手完成后客户端可以一直不发 CONNECT，
    // 若此时释放握手许可，一条无需凭据的连接就能长期占住连接槽。
    let mut handshake = Some(handshake);
    let mut streams = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = connection.accept() => {
                let Some(accepted) = accepted else { break };
                let (request, mut respond) = accepted.map_err(io::Error::other)?;
                if request.method() != Method::CONNECT {
                    let _ = respond.send_response(
                        Response::builder().status(StatusCode::METHOD_NOT_ALLOWED).body(()).unwrap(),
                        true,
                    );
                    continue;
                }
                let auth = request
                    .headers()
                    .get("proxy-authorization")
                    .and_then(|value| value.to_str().ok());
                let user = match http::authenticate_header(auth, users) {
                    Ok(user) => {
                        // 首次认证成功后才归还握手名额：此后按已认证连接处理。
                        handshake.take();
                        user
                    }
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        // 与 H1 的 accept.rs 兜底保持一致：认证失败计入 rejected。
                        // 此前 H2 只回 407 就 continue，同一入口 H1 能看见爆破、
                        // H2 看不见；而 TLS 下 ALPN 优先 h2。
                        ctx.stats.reject();
                        let _ = respond.send_response(
                            Response::builder().status(StatusCode::PROXY_AUTHENTICATION_REQUIRED).body(()).unwrap(),
                            true,
                        );
                        continue;
                    }
                    Err(_) => {
                        let _ = respond.send_response(
                            Response::builder().status(StatusCode::BAD_REQUEST).body(()).unwrap(),
                            true,
                        );
                        continue;
                    }
                };
                let authority = request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str().to_owned())
                    .or_else(|| {
                        request.headers().get("host").and_then(|value| value.to_str().ok()).map(str::to_owned)
                    });
                let target = match authority.as_deref().map(http::authority_target) {
                    Some(Ok(target)) => target,
                    _ => {
                        let _ = respond.send_response(
                            Response::builder().status(StatusCode::BAD_REQUEST).body(()).unwrap(),
                            true,
                        );
                        continue;
                    }
                };
                let send = match respond.send_response(
                    Response::builder().status(StatusCode::OK).body(()).unwrap(),
                    false,
                ) {
                    Ok(send) => send,
                    Err(_) => break,
                };
                // 准入必须在回 200 与拨号之前：否则到期账户仍能触发 DNS/
                // 上游连接，并从状态码区分目标是否可达。
                if !ctx.stats.admit_user(tag, user.as_deref()) {
                    let _ = respond.send_response(
                        Response::builder().status(StatusCode::FORBIDDEN).body(()).unwrap(),
                        true,
                    );
                    continue;
                }
                let tunnel = crate::transport::xhttp::Tunnel::new(
                    crate::transport::xhttp::H2Reader::new(request.into_body()),
                    crate::transport::xhttp::H2Writer::new(send),
                );
                let tag = tag.to_owned();
                let ctx = ctx.clone();
                let tunnel = ctx.stats.count_user(&tag, user.as_deref(), tunnel);
                let tracker = ctx.children.clone();
                streams.spawn(tracker.track_future(async move {
                    if let Ok(upstream) = ctx.connect(&tag, &target).await {
                        let _ = forward::relay(tunnel, upstream, ctx.stats.clone()).await;
                    }
                }));
            }
            Some(_) = streams.join_next() => {}
        }
    }
    // abort 只是请求取消：任务要等运行时下一次调度才被 drop。流任务持有
    // `Gauge::Tcp`，这里不 drain 就会让停机快照看到已断开的「幽灵连接」。
    streams.abort_all();
    while streams.join_next().await.is_some() {}
    Ok(())
}
