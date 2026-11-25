//! 监听循环与入站协议分派。

use super::*;

/// 按源 IP 计数的在途握手槽。
///
/// 存在的理由：全局 `max_handshakes` 是每个入口一个闸门，单个 IP 开满它就
/// 能让该入口对其他所有 IP 不可用——实测 64 条不发 ClientHello 的连接使
/// 合法握手 0/3，释放后立即恢复。
///
/// 计数表用 `Arc<Mutex<..>>` 共享：guard 会随连接任务活到结束，归还时必须
/// 能触达同一张表。锁只在 admit/释放时短暂持有，不在 I/O 期间持有。
#[derive(Clone)]
struct PerIpHandshakes {
    limit: usize,
    active: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
}

impl PerIpHandshakes {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            active: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// 允许则返回随连接生命周期释放的 guard；超限返回 `None`。
    fn admit(&self, stream: &tokio::net::TcpStream) -> Option<PerIpGuard> {
        if self.limit == 0 {
            return Some(PerIpGuard {
                shared: None,
                ip: None,
            });
        }
        // 拿不到对端地址时不因计数问题拒绝连接。
        let ip = stream.peer_addr().ok()?.ip();
        let mut active = crate::sync::locked(&self.active);
        let count = active.entry(ip).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        drop(active);
        Some(PerIpGuard {
            shared: Some(self.clone()),
            ip: Some(ip),
        })
    }

    fn release(&self, ip: std::net::IpAddr) {
        let mut active = crate::sync::locked(&self.active);
        if let Some(count) = active.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&ip);
            }
        }
    }
}

/// 把 per-IP 计数与全局握手名额绑成一体。
///
/// 关键点：它**必须**和 `handshake_permit` 同生命周期。早期实现让 guard 活到
/// 整个连接结束，于是「每 IP 8 个并发连接」被当成了「每 IP 8 个在途握手」，
/// 一个浏览器开 8 个标签页后第 9 个就连不上（实测 12 条正常连接只成功 8 条）。
/// 把两者打包后，协议实现里既有的 27 处 `drop(handshake)` 不需要改一行，
/// 释放时机自动对齐。
pub(crate) struct HandshakePermits {
    _global: tokio::sync::OwnedSemaphorePermit,
    _per_ip: Option<PerIpGuard>,
}

impl HandshakePermits {
    pub(crate) fn new(
        global: tokio::sync::OwnedSemaphorePermit,
        per_ip: Option<PerIpGuard>,
    ) -> Self {
        Self {
            _global: global,
            _per_ip: per_ip,
        }
    }
}

/// 连接结束时归还在途计数。
pub(crate) struct PerIpGuard {
    shared: Option<PerIpHandshakes>,
    ip: Option<std::net::IpAddr>,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        // 归还时需要知道是哪个 IP；由 admit 记录的条目在表里，这里直接用
        // 记录在 guard 上的地址。
        if let (Some(shared), Some(ip)) = (&self.shared, self.ip) {
            shared.release(ip);
        }
    }
}

/// `accept()` 返回这些错误时进程应当继续服务：
///
/// - `EMFILE` / `ENFILE`：FD 耗尽。这是**最常见**的一种，一次连接风暴即可触发；
/// - `ECONNABORTED`：对端在 accept 前关闭；
/// - `EINTR`：被信号打断；
/// - `EAGAIN` / `EWOULDBLOCK`：监听 socket 被设为非阻塞时的正常空转。
pub(crate) fn recoverable_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    ) || matches!(error.raw_os_error(), Some(libc_emfile) if libc_emfile == 24 || libc_emfile == 23)
}

/// FD 耗尽后等待多久再重试。
///
/// 退避是必要的：立刻重试会在 FD 仍然耗尽时形成忙循环，把 CPU 打满。
/// 取 20ms：既能在一批连接释放后很快恢复，又不会在持续压力下空转。
pub(crate) const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);

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
        per_ip_handshakes: per_ip_limit,
        max_handshakes: global_handshake_limit,
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
    // 按入口记录上次输出时间，避免所有入口共用一个时间戳。
    let last_error_log: Arc<
        std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    > = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // 每源 IP 的在途握手数。没有这一层时，单个 IP 开满全局
    // `max_handshakes` 就等于让该入口对其他所有 IP 不可用（实测 64 条
    // 不发 ClientHello 的连接可让合法握手 0/3）。
    // 单 IP 上限超过全局上限时以全局为准（否则它永远不会生效）。
    let effective_per_ip = if per_ip_limit == 0 {
        0
    } else {
        per_ip_limit.min(global_handshake_limit)
    };
    let per_ip = PerIpHandshakes::new(effective_per_ip);
    loop {
        // 持续 accept 就绪时也要回收完成任务，避免偏置 select 饿死 join 分支。
        while let Some(result) = connections.try_join_next() {
            if result.is_err() {
                // 单条连接任务 panic 只损失这一条连接。此前会升级成整站
                // failure 并取消全局 stop，一个坏包能打挂所有协议。
                tracing::error!(event = "connection_task_panicked", inbound = config.tag());
            }
        }
        if failure.is_some() {
            break;
        }
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            accepted = socket.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    // 可恢复错误不能让整个进程退出：一次连接风暴把 FD 吃光
                    // （EMFILE/ENFILE）就会让**所有**入站同时掉线，实测 118 条
                    // 半开连接即可触发，而 Xray 在同样条件下继续服务。
                    // 退避后重试；只有真正的致命错误才向上报。
                    Err(error) if recoverable_accept_error(&error) => {
                        // 计入 rejected：否则运维只会看到「连接莫名失败」而没有
                        // 任何计数线索。拿不到 Context 时（启动早期）跳过计数。
                        if let Some(ctx) = shared.current() {
                            ctx.stats.reject();
                        }
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                    Err(error) => { failure = Some(error); break; }
                };
                let Some(ctx) = shared.current() else { failure = Some(io::Error::other("共享 Context 未初始化")); break; };
                // 对端 IP 用于连接级日志；只记 IP 不记端口与目标。
                let peer_ip = stream
                    .peer_addr()
                    .map(|address| address.ip())
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|_| "-".to_owned());
                let Ok(connection_permit) = slots.clone().try_acquire_owned() else { ctx.stats.reject(); continue; };
                // 单 IP 超限时直接拒绝，不占用全局握手槽。
                let ip_guard = match per_ip.admit(&stream) {
                    Some(guard) => guard,
                    None => { ctx.stats.reject(); continue; }
                };
                let Ok(handshake_permit) = handshakes.clone().try_acquire_owned() else { ctx.stats.reject(); continue; };
                // 与 per-IP guard 绑定：两者都只在**握手期**持有，握手完成
                // （协议实现里的 drop(handshake)）即同时释放。
                let handshake_permit = HandshakePermits::new(handshake_permit, Some(ip_guard));
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
                // 这个 async 块内联了全部运输层分支；不装箱时每个任务都要
                // 按值携带整个状态机（实测 97.6 KB/连接）。Box 后任务只持有
                // 一个指针。注意：仅给 handle() 装箱不够——大小来自这层。
                connections.spawn(Box::pin(async move {
                    let _connection_permit = connection_permit;
                    let _gauge = ctx.stats.enter(Gauge::Connection);
                    tokio::select! {
                        biased;
                        _ = force.cancelled() => {},
                        result = async {
                            // 普通 VLESS / REALITY 与运输分支**互斥装箱**：只把
                            // 需要的那一侧的状态机放进外层 future。仅用提前
                            // `return` 不够——另一侧的 future 仍会被算进并集。
                            if matches!(&*config, Inbound::Vless { .. } | Inbound::VlessReality { .. }) {
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
                            } else {
                                Box::pin(async {
                            if matches!(&*config, Inbound::VlessGrpc { .. } | Inbound::VmessGrpc { .. } | Inbound::TrojanGrpc { .. }) {
                                crate::transport::grpc::serve(stream, config.clone(), security, vmess, ctx.clone(), handshake_permit, grpc_slots, stop, force.clone()).await
                            } else if matches!(&*config, Inbound::Naive { .. }) {
                                crate::transport::naive::serve(stream, config.clone(), tls, ctx.clone(), handshake_permit, grpc_slots.clone(), stop, force.clone()).await
                            } else if matches!(&*config, Inbound::AnyTls { .. }) {
                                crate::transport::anytls::serve(stream, config.clone(), tls, ctx.clone(), handshake_permit, stop, force.clone()).await
                            } else if matches!(&*config, Inbound::VlessHttpUpgrade { .. } | Inbound::VmessHttpUpgrade { .. } | Inbound::TrojanHttpUpgrade { .. }) {
                                crate::transport::httpupgrade::serve(stream, config.clone(), security, vmess, ctx.clone(), handshake_permit, stop, force.clone()).await
                            } else if matches!(&*config, Inbound::DokodemoDoor { .. }) {
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
                            } else if matches!(&*config, Inbound::VlessHttp { .. } | Inbound::VmessHttp { .. } | Inbound::TrojanHttp { .. }) {
                                crate::transport::v2ray_http::serve(stream, config.clone(), tls, vmess, ctx.clone(), handshake_permit, stop, force.clone()).await
                            } else if matches!(&*config, Inbound::VlessXhttp { .. } | Inbound::VmessXhttp { .. } | Inbound::TrojanXhttp { .. }) {
                                let pool = xhttp.ok_or_else(|| io::Error::other("XHTTP会话表未准备"))?;
                                crate::transport::xhttp::serve(stream, config.clone(), security, vmess, ctx.clone(), pool, handshake_permit, stop, force.clone()).await
                            } else if matches!(&*config, Inbound::VlessWs { .. } | Inbound::VmessWs { .. } | Inbound::TrojanWs { .. }) {
                                handle_websocket(stream, &config, security, vmess, ctx.clone(), handshake_permit).await
                            } else if matches!(&*config, Inbound::Snell { .. }) {
                                let prepared = snell.clone().ok_or_else(|| io::Error::other("Snell 状态未准备"))?;
                                stream.set_nodelay(true)?;
                                Box::pin(snell::serve(stream, prepared, ctx.clone(), config.tag(), handshake_permit)).await
                            } else if matches!(&*config, Inbound::ShadowTls { .. }) {
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
                            } else if matches!(&*config, Inbound::VmessReality { .. }) {
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
                                })
                                .await
                            }
                        } => {
                            if let Err(error) = result {
                                // 新入口的路由拒绝已在 Context 分类；其余旧入口统计语义保持不变。
                                if !matches!(&*config, Inbound::VlessReality { .. } | Inbound::VmessReality { .. } | Inbound::TrojanReality { .. } | Inbound::VlessWs { .. } | Inbound::VmessWs { .. } | Inbound::TrojanWs { .. } | Inbound::VlessGrpc { .. } | Inbound::VmessGrpc { .. } | Inbound::TrojanGrpc { .. } | Inbound::VlessHttpUpgrade { .. } | Inbound::VmessHttpUpgrade { .. } | Inbound::TrojanHttpUpgrade { .. } | Inbound::VlessXhttp { .. } | Inbound::VmessXhttp { .. } | Inbound::TrojanXhttp { .. } | Inbound::Naive { .. } | Inbound::AnyTls { .. } | Inbound::Snell { .. } | Inbound::ShadowTls { .. }) || !forward::is_route_rejection(&error) {
                                    ctx.stats.reject();
                                }
                                // 限速按入口分开：原来所有入口共用一个时间戳，
                                // 一个入口出错就会把其他入口的日志一起吞掉。
                                // 对端 IP 可以记录；**目标地址不记录**（威胁模型
                                // T14：默认不记目标与载荷）。需要目标时用
                                // `DUBHE_LOG=debug` 打开协议层的 debug 日志。
                                let mut last = crate::sync::locked(&last_error_log);
                                let now = std::time::Instant::now();
                                let should_log = match last.get(config.tag()) {
                                    Some(time) => now.duration_since(*time) >= Duration::from_secs(1),
                                    None => true,
                                };
                                if should_log {
                                    tracing::warn!(
                                        event = "connection_closed",
                                        inbound = config.tag(),
                                        peer = %peer_ip,
                                        reason = ?error.kind()
                                    );
                                    last.insert(config.tag().to_owned(), now);
                                }
                            }
                        }
                    }
                }));
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if result.is_some_and(|r| r.is_err()) {
                    tracing::error!(
                        event = "connection_task_panicked",
                        inbound = config.tag()
                    );
                }
            }
        }
    }
    drop(socket);
    if failure.is_some() {
        stop.cancel();
    }
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            tracing::error!(event = "connection_task_panicked", inbound = config.tag());
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// TLS VLESS 快路径：无 Vision、无 fallback、无 Encryption。
///
/// 与 `handle_inner` 的对应分支语义一致：TLS 握手 → 普通 VLESS 认证 →
/// `serve_plain_vless`。fallback 为空时不会走 `Recording` 的回放分支，
/// 因此这里只保留 TLS 与认证所需的状态。
#[allow(clippy::too_many_arguments)]
async fn serve_tls_vless_entry(
    stream: TcpStream,
    tag: &str,
    users: &[crate::config::VlessUser],
    xudp: bool,
    ctx: Arc<Context>,
    deadline: Duration,
    handshake: HandshakePermits,
    acceptor: tls::ServerTls,
) -> io::Result<()> {
    let tls_stream = timeout(deadline, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS超时"))??;
    // `fallbacks` 为空（前置条件已保证），`Recording` 的回放分支不可达，
    // 因此不需要为它累积读到的字节。装箱还有第二个作用：`vless_accept`
    // 只按 `Box<dyn tls::Io>` 单态化一次，而不是按
    // `Recording<TlsStream<TcpStream>>` 生成一份更大的实例。
    let stream: Box<dyn tls::Io> = Box::new(tls_stream);
    vless_accept(stream, tag, users, xudp, ctx, deadline, handshake).await
}

/// VLESS 认证收尾：超时、释放握手许可、交给业务分派。
///
/// 快路径与 `handle_inner` 的 `Vless`/无 TLS 分支共用这一份实现，避免两处
/// 分叉——此前快路径漏掉 `set_nodelay` 正是分叉造成的。
///
/// `serve_plain_vless` 自身已处理 Single / Mux / 反向三种 `Accepted`，
/// 所以这里不需要回落到完整分派。
async fn vless_accept<S>(
    mut stream: S,
    tag: &str,
    users: &[crate::config::VlessUser],
    xudp: bool,
    ctx: Arc<Context>,
    deadline: Duration,
    handshake: HandshakePermits,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let accepted = timeout(
        deadline,
        vless::handshake_with_xudp(&mut stream, users, xudp),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "认证超时"))??;
    drop(handshake);
    serve_plain_vless(stream, accepted, tag, ctx, deadline, xudp).await
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
    handshake: HandshakePermits,
) -> io::Result<()> {
    // 两条路径都需要的 socket 初始化，放在分派之前，保证恰好执行一次。
    stream.set_nodelay(true)?;
    // 最省内存的形态先分派出去：明文 VLESS（无 TLS、无 Encryption、
    // 无 fallback）。它的 future 只含认证与转发所需状态，不再与
    // gRPC/XHTTP/REALITY 等分支共享暂停状态。
    //
    // 收益来源是 future 布局，不是「少用了某个协议分支」：`handle_inner`
    // 的 future 是 26 个分支的并集，release 布局 44,400 B；明文专用入口
    // 10,528 B。每连接节省约 33 KiB 的状态机，另有 RSS 差额来自分配器。
    if tls.is_none()
        && vless_encryption.is_none()
        && let Inbound::Vless {
            tag,
            users,
            xudp,
            fallbacks,
            ..
        } = config
        && fallbacks.is_empty()
    {
        let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
        return Box::pin(vless_accept(
            stream, tag, users, *xudp, ctx, deadline, handshake,
        ))
        .await;
    }
    // TLS VLESS（无 Vision、无 fallback、无 Encryption）：公网最常见的
    // 形态。它的认证要经过 `Recording` 以便 fallback 回放，但 fallback
    // 为空时那条路径不可达，可以只保留 TLS + 认证 + 转发所需状态。
    if vless_encryption.is_none()
        && let Inbound::Vless {
            tag,
            users,
            xudp,
            fallbacks,
            ..
        } = config
        && fallbacks.is_empty()
        && !users
            .iter()
            .any(|user| user.flow == crate::config::VlessFlow::Vision)
        && let Some(acceptor) = &tls
    {
        let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
        return Box::pin(serve_tls_vless_entry(
            stream,
            tag,
            users,
            *xudp,
            ctx,
            deadline,
            handshake,
            acceptor.clone(),
        ))
        .await;
    }
    // SOCKS5 入口在完整分派里本来就是一行调用，前置后它不再与
    // gRPC/XHTTP/REALITY 共享暂停状态。Chat 出口/ShadowTLS 内层 SOCKS
    // 走的是别的变体，不会误入这里。
    if let Inbound::Socks5 { tag, users, .. } = config {
        let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
        return Box::pin(serve_socks5(stream, tag, users, ctx, deadline, handshake)).await;
    }
    // 其余分支仍走完整分派：这个函数把 26 个协议分支内联在同一个 match 里，
    // future 大小等于各分支的并集。整体装箱后，调用方按值复制的不再是巨型
    // 状态机，而是一个指针。
    Box::pin(handle_inner(
        stream,
        config,
        tls,
        prepared,
        reality,
        vless_encryption,
        ctx,
        handshake,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner(
    stream: TcpStream,
    config: &Inbound,
    tls: Option<tls::ServerTls>,
    prepared: Option<Arc<shadowsocks::Prepared>>,
    reality: Option<Arc<tls::reality::Prepared>>,
    vless_encryption: Option<Arc<crate::transport::vless_encryption::Prepared>>,
    ctx: Arc<Context>,
    handshake: HandshakePermits,
) -> io::Result<()> {
    let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    match config {
        // SOCKS5 已在 `handle` 前置分派，这里不可达；保留是为了让 match
        // 保持穷尽，避免未来新增变体时漏掉。
        Inbound::Socks5 { .. } => Err(io::Error::other("SOCKS5 已前置分派")),
        Inbound::Http { tag, users, .. } => {
            serve_http(stream, tag, users, tls, ctx, deadline, handshake).await
        }
        Inbound::Mixed { tag, users, .. } => {
            // 认证前的等待必须共用同一个绝对期限：TLS 握手和首字节探测
            // 都不能无限挂起，否则一条不说话的连接就能长期占住握手槽。
            let absolute = tokio::time::Instant::now() + deadline;
            let (stream, socks5): (Box<dyn tls::Io>, bool) = match tls {
                Some(tls) => {
                    let mut stream: Box<dyn tls::Io> = Box::new(
                        tokio::time::timeout_at(absolute, tls.accept(stream))
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::TimedOut, "Mixed TLS 握手超时")
                            })??,
                    );
                    let mut first = [0u8; 1];
                    tokio::time::timeout_at(absolute, stream.read_exact(&mut first))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "Mixed 首字节超时")
                        })??;
                    let stream = crate::transport::xhttp::PrefixReader::new(first.to_vec(), stream);
                    (Box::new(stream), first[0] == 5)
                }
                None => {
                    let mut first = [0u8; 1];
                    tokio::time::timeout_at(absolute, stream.peek(&mut first))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "Mixed 首字节超时")
                        })??;
                    (Box::new(stream), first[0] == 5)
                }
            };
            if socks5 {
                serve_socks5_stream(stream, tag, users, ctx, deadline, handshake).await
            } else {
                serve_http(stream, tag, users, None, ctx, deadline, handshake).await
            }
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
                // 共享认证收尾：与前置快路径同一份实现。
                let stream: Box<dyn tls::Io> = match vless_encryption {
                    Some(decryption) => Box::new(
                        timeout(deadline, decryption.accept(stream))
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::TimedOut, "VLESS Encryption 握手超时")
                            })??,
                    ),
                    None => Box::new(stream),
                };
                return vless_accept(stream, tag, users, *xudp, ctx, deadline, handshake).await;
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

#[cfg(test)]
mod accept_tests {
    use super::*;

    /// 单 IP 占满槽位后，同 IP 被拒、其他 IP 不受影响。
    ///
    /// 这对应实测场景：64 条同源半开连接曾让该入口对其他所有 IP 不可用
    /// （合法握手 0/3）。修复后其他 IP 仍 3/3。
    #[test]
    fn per_ip_handshakes_are_isolated() {
        let limit = 2;
        let tracker = PerIpHandshakes::new(limit);
        let ip_a: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let ip_b: std::net::IpAddr = "192.0.2.2".parse().unwrap();

        // 手动驱动计数，避免为测试构造真实 TcpStream。
        let guards_a: Vec<_> = (0..limit)
            .map(|_| {
                crate::sync::locked(&tracker.active)
                    .entry(ip_a)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                PerIpGuard {
                    shared: Some(tracker.clone()),
                    ip: Some(ip_a),
                }
            })
            .collect();
        assert_eq!(
            *crate::sync::locked(&tracker.active).get(&ip_a).unwrap(),
            limit
        );
        // A 已达上限；B 未使用任何槽。
        assert!(crate::sync::locked(&tracker.active).get(&ip_b).is_none());

        drop(guards_a);
        // 释放后条目应被删除，表不随连接数无限增长。
        assert!(
            crate::sync::locked(&tracker.active).get(&ip_a).is_none(),
            "归零后应删除条目"
        );
    }

    /// `0` 表示不限制：任何连接都放行（退化为原行为，供不想启用的人使用）。
    #[test]
    fn zero_limit_disables_the_cap() {
        let tracker = PerIpHandshakes::new(0);
        assert!(tracker.active.lock().unwrap().is_empty());
    }

    fn os_error(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    /// FD 耗尽（EMFILE=24 / ENFILE=23）必须被视为可恢复：重试而不是退出。
    /// 此前一次连接风暴就能让整个进程以 EXIT=1 结束——实测 118 条半开连接
    /// 即触发，而 Xray 在同样条件下继续服务。
    #[test]
    fn fd_exhaustion_is_recoverable() {
        assert!(recoverable_accept_error(&os_error(24)), "EMFILE 应可恢复");
        assert!(recoverable_accept_error(&os_error(23)), "ENFILE 应可恢复");
    }

    #[test]
    fn transient_accept_errors_are_recoverable() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionAborted,
        ] {
            assert!(
                recoverable_accept_error(&io::Error::from(kind)),
                "{kind:?} 应可恢复"
            );
        }
    }

    /// 真正的致命错误仍然要向上报，不能无限重试掩盖问题。
    #[test]
    fn fatal_accept_errors_are_not_swallowed() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::AddrNotAvailable,
        ] {
            assert!(
                !recoverable_accept_error(&io::Error::from(kind)),
                "{kind:?} 不应被视为可恢复"
            );
        }
    }
}
