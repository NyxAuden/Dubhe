//! 监听循环与入站协议分派。

use super::*;

pub(super) async fn accept_loop(
    listener: Listener,
    shared: Arc<crate::forward::SharedContext>,
    slots: Arc<Semaphore>,
    grpc_slots: Arc<Semaphore>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let Listener {
        socket,
        config,
        tls,
        security,
        handshakes,
        shadowsocks: _,
        prepared,
        snell,
        vmess,
        reality,
        xhttp,
        shadowtls,
        vless_encryption,
        detour,
    } = listener;
    let mut connections = JoinSet::new();
    let mut failure = None;
    let last_error_log = Arc::new(std::sync::Mutex::new(None::<std::time::Instant>));
    loop {
        // 持续 accept 就绪时也要回收完成任务，避免偏置 select 饿死 join 分支。
        while let Some(result) = connections.try_join_next() {
            if result.is_err() {
                failure = Some(io::Error::other("连接任务异常"));
            }
        }
        if failure.is_some() {
            break;
        }
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            accepted = socket.accept() => {
                let (stream, _) = match accepted { Ok(value) => value, Err(error) => { failure = Some(error); break; } };
                let Some(ctx) = shared.current() else { failure = Some(io::Error::other("共享 Context 未初始化")); break; };
                let Ok(connection_permit) = slots.clone().try_acquire_owned() else { ctx.stats.reject(); continue; };
                let Ok(handshake_permit) = handshakes.clone().try_acquire_owned() else { ctx.stats.reject(); continue; };
                let config = config.clone(); let tls = tls.clone(); let security = security.clone(); let ctx = ctx.clone(); let force = force.clone();
                let stop = stop.clone(); let grpc_slots = grpc_slots.clone(); let xhttp = xhttp.clone();
                let last_error_log = last_error_log.clone();
                let prepared = prepared.clone();
                let snell = snell.clone();
                let vmess = vmess.clone();
                let reality = reality.clone();
                let shadowtls = shadowtls.clone();
                let vless_encryption = vless_encryption.clone();
                let detour = detour.clone();
                connections.spawn(async move {
                    let _connection_permit = connection_permit;
                    let _gauge = ctx.stats.enter(Gauge::Connection);
                    tokio::select! {
                        biased;
                        _ = force.cancelled() => {},
                        result = async {
                            if matches!(config, Inbound::VlessGrpc { .. } | Inbound::VmessGrpc { .. } | Inbound::TrojanGrpc { .. }) {
                                crate::transport::grpc::serve(stream, config.clone(), security, vmess, ctx.clone(), handshake_permit, grpc_slots, stop, force.clone()).await
                            } else if matches!(config, Inbound::Naive { .. }) {
                                crate::transport::naive::serve(stream, config.clone(), tls, ctx.clone(), handshake_permit, grpc_slots.clone(), stop, force.clone()).await
                            } else if matches!(config, Inbound::AnyTls { .. }) {
                                crate::transport::anytls::serve(stream, config.clone(), tls, ctx.clone(), handshake_permit, stop, force.clone()).await
                            } else if matches!(config, Inbound::VlessHttpUpgrade { .. } | Inbound::VmessHttpUpgrade { .. } | Inbound::TrojanHttpUpgrade { .. }) {
                                crate::transport::httpupgrade::serve(stream, config.clone(), security, vmess, ctx.clone(), handshake_permit, stop, force.clone()).await
                            } else if matches!(config, Inbound::DokodemoDoor { .. }) {
                                let deadline = tokio::time::Instant::now()
                                    + Duration::from_millis(ctx.limits.handshake_timeout_ms);
                                crate::transport::dokodemo::serve(
                                    stream,
                                    config.clone(),
                                    ctx.clone(),
                                    handshake_permit,
                                    deadline,
                                )
                                .await
                            } else if matches!(config, Inbound::VlessHttp { .. } | Inbound::VmessHttp { .. } | Inbound::TrojanHttp { .. }) {
                                crate::transport::v2ray_http::serve(stream, config.clone(), tls, vmess, ctx.clone(), handshake_permit, stop, force.clone()).await
                            } else if matches!(config, Inbound::VlessXhttp { .. } | Inbound::VmessXhttp { .. } | Inbound::TrojanXhttp { .. }) {
                                let pool = xhttp.ok_or_else(|| io::Error::other("XHTTP会话表未准备"))?;
                                crate::transport::xhttp::serve(stream, config.clone(), security, vmess, ctx.clone(), pool, handshake_permit, stop, force.clone()).await
                            } else if matches!(config, Inbound::VlessWs { .. } | Inbound::VmessWs { .. } | Inbound::TrojanWs { .. }) {
                                handle_websocket(stream, &config, security, vmess, ctx.clone(), handshake_permit).await
                            } else if matches!(config, Inbound::Snell { .. }) {
                                let prepared = snell.clone().ok_or_else(|| io::Error::other("Snell 状态未准备"))?;
                                stream.set_nodelay(true)?;
                                Box::pin(snell::serve(stream, prepared, ctx.clone(), config.tag(), handshake_permit)).await
                            } else if matches!(config, Inbound::ShadowTls { .. }) {
                                let prepared = shadowtls.clone().ok_or_else(|| io::Error::other("ShadowTLS 状态未准备"))?;
                                let detour = detour.clone().ok_or_else(|| io::Error::other("ShadowTLS detour 未解析"))?;
                                stream.set_nodelay(true)?;
                                match crate::transport::shadowtls::accept(
                                    stream,
                                    prepared,
                                    ctx.clone(),
                                    handshake_permit,
                                )
                                .await?
                                {
                                    crate::transport::shadowtls::AuthOutcome::Authenticated {
                                        stream,
                                        permit,
                                    } => detour.serve(stream, ctx.clone(), permit).await,
                                    // 未认证流量已按真实 TLS 回落到伪装服务器。
                                    crate::transport::shadowtls::AuthOutcome::Fallback => Ok(()),
                                }
                            } else if matches!(config, Inbound::VmessReality { .. }) {
                                let vmess = vmess.clone().ok_or_else(|| io::Error::other("VMess 状态未准备"))?;
                                let reality = reality.clone().ok_or_else(|| io::Error::other("REALITY 未准备"))?;
                                Box::pin(handle_vmess_reality(stream, config.tag(), vmess, reality, ctx.clone(), handshake_permit)).await
                            } else if let Some(vmess) = vmess {
                                handle_vmess(stream, config.tag(), tls, vmess, ctx.clone(), handshake_permit).await
                            } else {
                                Box::pin(handle(
                                    stream,
                                    &config,
                                    tls,
                                    prepared,
                                    reality,
                                    vless_encryption,
                                    ctx.clone(),
                                    handshake_permit,
                                ))
                                .await
                            }
                        } => {
                            if let Err(error) = result {
                                // 新入口的路由拒绝已在 Context 分类；其余旧入口统计语义保持不变。
                                if !matches!(config, Inbound::VlessReality { .. } | Inbound::VmessReality { .. } | Inbound::TrojanReality { .. } | Inbound::VlessWs { .. } | Inbound::VmessWs { .. } | Inbound::TrojanWs { .. } | Inbound::VlessGrpc { .. } | Inbound::VmessGrpc { .. } | Inbound::TrojanGrpc { .. } | Inbound::VlessHttpUpgrade { .. } | Inbound::VmessHttpUpgrade { .. } | Inbound::TrojanHttpUpgrade { .. } | Inbound::VlessXhttp { .. } | Inbound::VmessXhttp { .. } | Inbound::TrojanXhttp { .. } | Inbound::Naive { .. } | Inbound::AnyTls { .. } | Inbound::Snell { .. } | Inbound::ShadowTls { .. }) || !forward::is_route_rejection(&error) {
                                    ctx.stats.reject();
                                }
                                let mut last = crate::sync::locked(&last_error_log);
                                if last.is_none_or(|time| time.elapsed() >= Duration::from_secs(1)) {
                                    tracing::warn!(event="connection_closed", inbound=config.tag(), reason=?error.kind());
                                    *last = Some(std::time::Instant::now());
                                }
                            }
                        }
                    }
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if result.is_some_and(|r| r.is_err()) { failure = Some(io::Error::other("连接任务异常")); break; }
            }
        }
    }
    drop(socket);
    if failure.is_some() {
        stop.cancel();
    }
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            failure = Some(io::Error::other("连接任务异常"));
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

// 入站分派的固定上下文：共享资源用 Arc，协议专用状态用 Option。
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle(
    stream: TcpStream,
    config: &Inbound,
    tls: Option<tls::ServerTls>,
    prepared: Option<Arc<shadowsocks::Prepared>>,
    reality: Option<Arc<tls::reality::Prepared>>,
    vless_encryption: Option<Arc<crate::transport::vless_encryption::Prepared>>,
    ctx: Arc<Context>,
    handshake: tokio::sync::OwnedSemaphorePermit,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    match config {
        Inbound::Socks5 { tag, users, .. } => {
            serve_socks5(stream, tag, users, ctx, deadline, handshake).await
        }
        Inbound::Http { tag, users, .. } => {
            serve_http(stream, tag, users, tls, ctx, deadline, handshake).await
        }
        Inbound::Mixed { tag, users, .. } => {
            Box::pin(async move {
                if let Some(tls) = tls {
                    let mut stream: Box<dyn tls::Io> = Box::new(tls.accept(stream).await?);
                    let mut first = [0u8; 1];
                    stream.read_exact(&mut first).await?;
                    let stream = crate::transport::xhttp::PrefixReader::new(first.to_vec(), stream);
                    if first[0] == 5 {
                        serve_socks5_stream(stream, tag, users, ctx, deadline, handshake).await
                    } else {
                        serve_http(stream, tag, users, None, ctx, deadline, handshake).await
                    }
                } else {
                    let mut first = [0u8; 1];
                    stream.peek(&mut first).await?;
                    if first[0] == 5 {
                        serve_socks5(stream, tag, users, ctx, deadline, handshake).await
                    } else {
                        serve_http(stream, tag, users, None, ctx, deadline, handshake).await
                    }
                }
            })
            .await
        }
        Inbound::Trojan {
            tag,
            users,
            fallbacks,
            ..
        } => {
            let acceptor = tls.ok_or_else(|| io::Error::other("TLS 未配置"))?;
            let peer = stream.peer_addr()?;
            let local = stream.local_addr()?;
            let tls_stream = timeout(deadline, acceptor.accept(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS超时"))??;
            let sni = tls_stream.get_ref().1.server_name().map(str::to_owned);
            let alpn = tls_stream
                .get_ref()
                .1
                .alpn_protocol()
                .map(<[u8]>::to_vec)
                .and_then(|value| String::from_utf8(value).ok());
            let mut stream = crate::fallback::Recording::new(tls_stream);
            // fallback 需要保留连接原状，认证失败时不能发送 TLS 半关闭。
            let attempt = timeout(deadline, async {
                if fallbacks.is_empty() {
                    trojan::handshake(&mut stream, users).await
                } else {
                    trojan::read_request(&mut stream, users).await
                }
            })
            .await;
            match attempt {
                Ok(Ok(request)) => {
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
                Ok(Err(error)) if fallbacks.is_empty() => Err(error),
                Err(_) if fallbacks.is_empty() => {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "认证超时"))
                }
                _ => {
                    drop(handshake);
                    match crate::fallback::relay(
                        stream,
                        fallbacks,
                        peer,
                        local,
                        &ctx,
                        sni.as_deref(),
                        alpn.as_deref(),
                    )
                    .await
                    {
                        Ok(()) => Ok(()),
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Trojan 认证失败",
                        )),
                    }
                }
            }
        }
        Inbound::TrojanReality { tag, users, .. } => {
            let prepared = reality.ok_or_else(|| io::Error::other("REALITY 未准备"))?;
            Box::pin(serve_trojan_reality(
                stream, tag, users, prepared, ctx, handshake, deadline,
            ))
            .await
        }
        Inbound::VmessReality { .. } => Err(io::Error::other("VMess REALITY 未准备")),
        Inbound::Vless {
            tag,
            users,
            xudp,
            fallbacks,
            ..
        } => {
            let Some(acceptor) = tls else {
                // 无 TLS：Xray 明文 VLESS；VLESS Encryption 可作为协议层加密，
                // Vision/fallback 仍由配置校验拒绝。
                let mut stream: Box<dyn tls::Io> = match vless_encryption {
                    Some(decryption) => Box::new(
                        timeout(deadline, decryption.accept(stream))
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::TimedOut, "VLESS Encryption 握手超时")
                            })??,
                    ),
                    None => Box::new(stream),
                };
                let accepted = timeout(
                    deadline,
                    vless::handshake_with_xudp(&mut stream, users, *xudp),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "认证超时"))??;
                drop(handshake);
                return serve_plain_vless(stream, accepted, tag, ctx, deadline, *xudp).await;
            };
            if users
                .iter()
                .any(|user| user.flow == crate::config::VlessFlow::Vision)
            {
                if let Some(decryption) = vless_encryption.clone() {
                    let tls_config = acceptor.config().clone();
                    let users = users.to_vec();
                    let xudp = *xudp;
                    return Box::pin(async move {
                        let (stream, accepted) = timeout(deadline, async {
                            let controlled =
                                tls::controlled::Controlled::accept(stream, tls_config).await?;
                            let tls13 = controlled.protocol_version()
                                == Some(rustls::ProtocolVersion::TLSv1_3);
                            let mut encrypted = decryption.accept(controlled).await?;
                            let accepted =
                                vless::handshake_with_flow(&mut encrypted, &users, xudp, tls13)
                                    .await?;
                            Ok::<_, io::Error>((encrypted, accepted))
                        })
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS/认证超时"))??;
                        drop(handshake);
                        serve_plain_vision_vless(stream, accepted, tag, ctx, deadline, xudp).await
                    })
                    .await;
                }
                let (stream, accepted) = timeout(deadline, async {
                    let mut stream =
                        tls::controlled::Controlled::accept(stream, acceptor.config().clone())
                            .await?;
                    let tls13 = stream.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
                    let accepted =
                        vless::handshake_with_flow(&mut stream, users, *xudp, tls13).await?;
                    Ok::<_, io::Error>((stream, accepted))
                })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS/认证超时"))??;
                drop(handshake);
                return serve_controlled_vless(stream, accepted, tag, ctx, deadline, *xudp).await;
            }
            let peer = stream.peer_addr()?;
            let local = stream.local_addr()?;
            let tls_stream = timeout(deadline, acceptor.accept(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS超时"))??;
            // VLESS Encryption 在 TLS 之内、VLESS 之前；配置校验已禁止它与 fallbacks/Vision 并存。
            if let Some(decryption) = vless_encryption {
                let mut stream = timeout(deadline, decryption.accept(tls_stream))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "VLESS Encryption 握手超时")
                    })??;
                let request = timeout(
                    deadline,
                    vless::handshake_with_xudp(&mut stream, users, *xudp),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "认证超时"))??;
                drop(handshake);
                return serve_plain_vless(stream, request, tag, ctx, deadline, *xudp).await;
            }
            let sni = tls_stream.get_ref().1.server_name().map(str::to_owned);
            let alpn = tls_stream
                .get_ref()
                .1
                .alpn_protocol()
                .map(<[u8]>::to_vec)
                .and_then(|value| String::from_utf8(value).ok());
            let mut stream = crate::fallback::Recording::new(tls_stream);
            // fallback 需要保留连接原状，不能在认证失败时发送 TLS 半关闭。
            let attempt = timeout(deadline, async {
                if fallbacks.is_empty() {
                    vless::handshake_with_xudp(&mut stream, users, *xudp).await
                } else {
                    vless::read_plain_request(&mut stream, users, *xudp).await
                }
            })
            .await;
            match attempt {
                Ok(Ok(request)) => {
                    drop(handshake);
                    serve_plain_vless(stream, request, tag, ctx, deadline, *xudp).await
                }
                Ok(Err(error)) if fallbacks.is_empty() => Err(error),
                Err(_) if fallbacks.is_empty() => {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "认证超时"))
                }
                _ => {
                    drop(handshake);
                    match crate::fallback::relay(
                        stream,
                        fallbacks,
                        peer,
                        local,
                        &ctx,
                        sni.as_deref(),
                        alpn.as_deref(),
                    )
                    .await
                    {
                        Ok(()) => Ok(()),
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "VLESS 认证失败",
                        )),
                    }
                }
            }
        }
        Inbound::VlessReality {
            tag, users, xudp, ..
        } => {
            Box::pin(async move {
                let prepared = reality.ok_or_else(|| io::Error::other("REALITY 未准备"))?;
                let absolute = tokio::time::Instant::now() + deadline;
                let has_vision = users
                    .iter()
                    .any(|user| user.flow == crate::config::VlessFlow::Vision);
                let outer = Box::pin(prepared.accept(stream, &ctx, absolute)).await?;
                let (stream, accepted) = match outer {
                    tls::reality::Accepted::Fallback { client, target } => {
                        drop(handshake);
                        return prepared.fallback(client, target).await;
                    }
                    tls::reality::Accepted::Local(stream) => {
                        let stream = *stream;
                        if has_vision && let Some(decryption) = ctx.vless_encryption(tag) {
                            let mut encrypted =
                                tokio::time::timeout_at(absolute, decryption.accept(stream))
                                    .await
                                    .map_err(|_| {
                                        io::Error::new(
                                            io::ErrorKind::TimedOut,
                                            "REALITY/VLESS Encryption 超时",
                                        )
                                    })??;
                            let accepted = tokio::time::timeout_at(
                                absolute,
                                vless::handshake_with_flow(&mut encrypted, users, *xudp, true),
                            )
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::TimedOut, "REALITY/VLESS 认证超时")
                            })??;
                            drop(handshake);
                            return serve_plain_vision_vless(
                                encrypted, accepted, tag, ctx, deadline, *xudp,
                            )
                            .await;
                        }
                        if let Some(prepared) = ctx.vless_encryption(tag) {
                            return Box::pin(serve_reality_encrypted(
                                prepared, stream, users, *xudp, tag, ctx, deadline, absolute,
                                handshake,
                            ))
                            .await;
                        }
                        let mut stream = stream;
                        let accepted = tokio::time::timeout_at(
                            absolute,
                            vless::handshake_with_flow(&mut stream, users, *xudp, true),
                        )
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "REALITY/VLESS 认证超时")
                        })??;
                        (stream, accepted)
                    }
                };
                drop(handshake);
                serve_controlled_vless(stream, accepted, tag, ctx, deadline, *xudp).await
            })
            .await
        }
        Inbound::VlessWs { .. } | Inbound::VmessWs { .. } | Inbound::TrojanWs { .. } => {
            handle_websocket(
                stream,
                config,
                tls.map(tls::InboundSecurity::Tls),
                None,
                ctx,
                handshake,
            )
            .await
        }
        Inbound::VlessGrpc { .. } | Inbound::VmessGrpc { .. } | Inbound::TrojanGrpc { .. } => {
            Err(io::Error::other("gRPC 入口必须由连接driver处理"))
        }
        Inbound::VlessXhttp { .. } | Inbound::VmessXhttp { .. } | Inbound::TrojanXhttp { .. } => {
            Err(io::Error::other("XHTTP 入口必须由连接driver处理"))
        }
        Inbound::VlessHttpUpgrade { .. }
        | Inbound::VmessHttpUpgrade { .. }
        | Inbound::TrojanHttpUpgrade { .. } => {
            Err(io::Error::other("HTTPUpgrade 入口必须由连接driver处理"))
        }
        Inbound::Naive { .. } => Err(io::Error::other("Naive 入口必须由连接driver处理")),
        Inbound::AnyTls { .. } => Err(io::Error::other("AnyTLS 入口必须由连接driver处理")),
        Inbound::Snell { .. } => Err(io::Error::other("Snell 入口必须由连接driver处理")),
        Inbound::ShadowTls { .. } => {
            Err(io::Error::other("ShadowTLS 入口必须由 detour driver 处理"))
        }
        Inbound::VlessKcp { .. } | Inbound::VmessKcp { .. } | Inbound::TrojanKcp { .. } => {
            Err(io::Error::other("mKCP 入口必须由 UDP driver 处理"))
        }
        Inbound::VlessHttp { .. } | Inbound::VmessHttp { .. } | Inbound::TrojanHttp { .. } => {
            Err(io::Error::other("V2Ray HTTP 入口必须由连接driver处理"))
        }
        Inbound::DokodemoDoor { .. } => {
            Err(io::Error::other("dokodemo-door 入口必须由连接driver处理"))
        }
        Inbound::VlessQuic { .. } | Inbound::VmessQuic { .. } | Inbound::TrojanQuic { .. } => Err(
            io::Error::other("V2Ray QUIC 入口必须由 UDP/QUIC driver 处理"),
        ),
        Inbound::Hysteria2 { .. } => Err(io::Error::other(
            "Hysteria2 入口必须由 UDP/QUIC driver 处理",
        )),
        Inbound::Tuic { .. } => Err(io::Error::other("TUIC 入口必须由 UDP/QUIC driver 处理")),
        Inbound::Nw3 { .. } => Err(io::Error::other("NW3 入口必须由 Portal driver 处理")),
        Inbound::Wireguard { .. } => Err(io::Error::other("WireGuard 入口必须由 UDP driver 处理")),
        Inbound::Vmess { .. } => Err(io::Error::other("VMess 未准备")),
        Inbound::Shadowsocks { tag, .. } => {
            let prepared = prepared.ok_or_else(|| io::Error::other("Shadowsocks未准备"))?;
            shadowsocks::serve_tcp(stream, prepared, ctx, tag, handshake).await
        }
    }
}
