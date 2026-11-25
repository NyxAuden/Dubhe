use std::{io, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Config, DomainStrategy, Limits, OutboundKind, SniffKind, SniffingPolicy},
    connections::{Connection, Registry},
    dns::Dns,
    route::{ProxyOutbound, Router, Selected, UrltestGroup},
    session::{Host, Network, Target},
    telemetry::{Counted, Gauge, Stats},
};

#[derive(Debug)]
struct RouteRejected;
impl std::fmt::Display for RouteRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("路由拒绝")
    }
}
impl std::error::Error for RouteRejected {}

/// 是否为协议层认证失败。
///
/// VLESS / VMess / Trojan 的认证失败统一用 `PermissionDenied`
/// （见 `src/protocol/vless.rs:123`、`vmess/header.rs:97`、`trojan.rs:49`）。
/// 用于在多路复用入口（gRPC、V2Ray HTTP H2、V2Ray QUIC）里补计数，
/// 这些路径此前用 `let _` 吞掉 dispatch 错误，认证失败完全不可见。
pub(crate) fn is_authentication_failure(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

pub(crate) fn is_route_rejection(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<RouteRejected>())
}

/// 允许连接处理器按需读取当前 `Context` 的共享槽。
///
/// 只有不改变监听器的配置才会热替换该槽；已建立的连接继续持有其握手时的
/// `Arc<Context>` 快照。
#[derive(Default)]
pub(crate) struct SharedContext(std::sync::RwLock<Option<Arc<Context>>>);

impl SharedContext {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn current(&self) -> Option<Arc<Context>> {
        self.0
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    pub(crate) fn replace(&self, context: Arc<Context>) {
        *self.0.write().unwrap_or_else(|error| error.into_inner()) = Some(context);
    }
}

pub struct Context {
    pub limits: Limits,
    pub router: Router,
    pub dns: Dns,
    pub stats: Arc<Stats>,
    pub udp_slots: Arc<Semaphore>,
    pub udp_bytes: Arc<Semaphore>,
    pub children: tokio_util::task::TaskTracker,
    /// 跨热重载共享的出站后台资源停机信号，先取消再等children。
    pub(crate) outbound_stop: CancellationToken,
    /// 本实例的停机信号：反向 Portal 的载体任务必须能在这里被唤醒，
    /// 不能只依赖对端断开。
    pub(crate) shutdown: CancellationToken,
    pub(crate) sniff: Option<SniffPolicy>,
    pub(crate) connections: Arc<Registry>,
    /// `reverse` 出站的 portal 隧道注册表。
    pub(crate) reverse: Arc<crate::reverse::Registry>,
    /// 各 VLESS 入口的 Encryption 服务端状态（按 tag 共享）。
    pub(crate) vless_encryption:
        std::collections::HashMap<String, Arc<crate::transport::vless_encryption::Prepared>>,
    /// 反向 Bridge：本地 tag、到 Portal 的已编译 VLESS 出站与重连间隔。
    pub(crate) reverse_bridges: Vec<(String, Arc<ProxyOutbound>, Duration)>,
    /// 未声明 `reverse.tag` 的账户是否可按路由匹配建立反向隧道。
    pub(crate) reverse_route_fallback: bool,
}

/// 流式入站首包嗅探策略的运行期副本。
///
/// 配置期已校验范围与入口引用；这里只保留判定所需的最小状态。
#[derive(Clone)]
pub(crate) struct SniffPolicy {
    inbounds: Vec<String>,
    dest_override: Vec<SniffKind>,
    route_only: bool,
    timeout: Duration,
}

impl SniffPolicy {
    fn new(policy: &SniffingPolicy) -> Option<Self> {
        policy.enabled.then(|| Self {
            inbounds: policy.inbounds.clone(),
            dest_override: policy.dest_override.clone(),
            route_only: policy.route_only,
            timeout: Duration::from_millis(policy.timeout_ms),
        })
    }

    fn applies(&self, inbound: &str) -> bool {
        self.inbounds.is_empty() || self.inbounds.iter().any(|tag| tag == inbound)
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 该协议是否允许把嗅探域名作为拨号目标。
    pub(crate) fn overrides(&self, kind: SniffKind) -> bool {
        !self.route_only && self.dest_override.contains(&kind)
    }
}

/// 对已读入的 Mux.Cool 子流首包做嗅探的结果。
///
/// 与流式入站的 `sniff_route` 语义一致；区别只在
/// 子流首包来自 Mux 数据帧，调用方需要自行累积并在拨号后回放这些字节。
#[derive(Debug, PartialEq, Eq)]
pub enum PayloadSniff {
    /// 该入站未启用嗅探。
    Disabled,
    /// 当前缓冲区不足以判定，调用方可以继续累积。
    NeedMore,
    /// 不是可识别的 TLS ClientHello / HTTP/1.1 请求，或超过观察上限。
    Invalid,
    /// 已识别域名；`route` 用于选路，`dial` 仅在 `dest_override` 允许时改写。
    Detected { route: Target, dial: Target },
}

/// 与子任务共享的内部额度租约。RPC/关联创建它并在每个spawn出的reader/mapping
/// 中持有克隆；最后一个持有者释放时才归还许可与计量，避免子任务仍活时提前
/// 收回RPC额度。全局`children`跟踪器仍独立负责停机时等待任务。
#[derive(Clone, Default)]
pub struct Lease(
    // 字段只为持有共享所有权，不读取内容。
    #[allow(dead_code)] Option<Arc<dyn std::any::Any + Send + Sync>>,
);
impl Lease {
    pub fn new<T: Send + Sync + 'static>(value: T) -> Self {
        Self(Some(Arc::new(value)))
    }
}

fn prepare_vless_encryption(
    config: &Config,
) -> anyhow::Result<
    std::collections::HashMap<String, Arc<crate::transport::vless_encryption::Prepared>>,
> {
    let mut prepared = std::collections::HashMap::new();
    for inbound in &config.inbounds {
        let Some(value) = inbound.decryption() else {
            continue;
        };
        let Some(decryption) = crate::config::vless_encryption::parse(value)? else {
            continue;
        };
        let state = crate::transport::vless_encryption::Prepared::new(
            &decryption,
            config.limits.max_replay_entries,
        )
        .map_err(|error| {
            anyhow::anyhow!("入口 {} VLESS Encryption 配置无效: {error}", inbound.tag())
        })?;
        prepared.insert(inbound.tag().to_owned(), Arc::new(state));
    }
    Ok(prepared)
}

fn compile_reverse_bridges(
    config: &Config,
    router: &Router,
) -> anyhow::Result<Vec<(String, Arc<ProxyOutbound>, Duration)>> {
    config
        .reverse_bridges
        .iter()
        .map(|bridge| {
            let proxy = router
                .proxy_by_tag(&bridge.outbound)
                .ok_or_else(|| anyhow::anyhow!("反向 Bridge 引用的出站未编译"))?;
            Ok((
                bridge.tag.clone(),
                proxy,
                Duration::from_millis(bridge.reconnect_ms),
            ))
        })
        .collect()
}

impl Context {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let router = Router::new(config)?;
        let reverse_bridges = compile_reverse_bridges(config, &router)?;
        Ok(Self {
            limits: config.limits.clone(),
            router,
            dns: Dns::from_config(
                config.dns.as_ref(),
                config.limits.max_dns_queries,
                Duration::from_millis(config.limits.dns_timeout_ms),
            )?,
            stats: Arc::new(Stats::with_idle_timeout(config.limits.idle_timeout_ms)),
            udp_slots: Arc::new(Semaphore::new(config.limits.max_udp_associations)),
            udp_bytes: Arc::new(Semaphore::new(config.limits.udp_queue_bytes)),
            children: tokio_util::task::TaskTracker::new(),
            outbound_stop: CancellationToken::new(),
            shutdown: CancellationToken::new(),
            sniff: config.sniffing.as_ref().and_then(SniffPolicy::new),
            connections: Arc::new(Registry::default()),
            reverse: Arc::new(crate::reverse::Registry::new(config)?),
            vless_encryption: prepare_vless_encryption(config)?,
            reverse_bridges,
            reverse_route_fallback: config.reverse_route_fallback,
        })
    }

    /// 基于旧实例的共享基础设施构造热重载后的 `Context`。
    ///
    /// 统计、活动连接、子任务跟踪与 UDP 预算保持同一实例；仅替换路由、DNS、
    /// 嗅探与反向 portal 配置。
    pub(crate) fn reloaded(config: &Config, previous: &Context) -> anyhow::Result<Self> {
        let router = Router::new(config)?;
        let reverse_bridges = compile_reverse_bridges(config, &router)?;
        Ok(Self {
            limits: config.limits.clone(),
            router,
            dns: Dns::from_config(
                config.dns.as_ref(),
                config.limits.max_dns_queries,
                Duration::from_millis(config.limits.dns_timeout_ms),
            )?,
            stats: previous.stats.clone(),
            udp_slots: previous.udp_slots.clone(),
            udp_bytes: previous.udp_bytes.clone(),
            children: previous.children.clone(),
            outbound_stop: previous.outbound_stop.clone(),
            shutdown: CancellationToken::new(),
            sniff: config.sniffing.as_ref().and_then(SniffPolicy::new),
            connections: previous.connections.clone(),
            reverse: Arc::new(crate::reverse::Registry::new(config)?),
            vless_encryption: prepare_vless_encryption(config)?,
            reverse_bridges,
            reverse_route_fallback: config.reverse_route_fallback,
        })
    }

    pub(crate) fn reverse_bridges(&self) -> &[(String, Arc<ProxyOutbound>, Duration)] {
        &self.reverse_bridges
    }

    pub(crate) fn has_reverse_bridges(&self) -> bool {
        !self.reverse_bridges.is_empty()
    }

    /// 当前实例是否配置了 reverse portal；有活动反向隧道时禁用热重载。
    pub(crate) fn has_reverse(&self) -> bool {
        !self.reverse.is_empty()
    }

    /// 该入口的 VLESS Encryption 服务端状态。
    pub(crate) fn vless_encryption(
        &self,
        tag: &str,
    ) -> Option<Arc<crate::transport::vless_encryption::Prepared>> {
        self.vless_encryption.get(tag).cloned()
    }

    /// 该入口生效的嗅探策略；未启用或入口不在列表内时返回 `None`。
    pub(crate) fn sniff_policy(&self, inbound: &str) -> Option<&SniffPolicy> {
        self.sniff.as_ref().filter(|policy| policy.applies(inbound))
    }

    /// 该入口等待首包做嗅探的最长期限；未启用嗅探时返回 `None`。
    ///
    /// 供 Mux.Cool 子流使用：子流首包不能直接按流读取，需要由调用方限时累积。
    pub fn sniff_timeout(&self, inbound: &str) -> Option<Duration> {
        self.sniff_policy(inbound).map(SniffPolicy::timeout)
    }

    /// 对已累积的子流首包判定嗅探结果。
    ///
    /// 与流式嗅探一致：识别出的域名默认只用于选路，仅当入口配置允许
    /// `dest_override` 时才同时作为拨号目标。
    pub fn sniff_payload(&self, inbound: &str, target: &Target, payload: &[u8]) -> PayloadSniff {
        let Some(policy) = self.sniff_policy(inbound) else {
            return PayloadSniff::Disabled;
        };
        if payload.len() >= crate::transport::sniff::MAX_SNIFF {
            return PayloadSniff::Invalid;
        }
        let domain = match crate::transport::sniff::detect(payload) {
            crate::transport::sniff::Sniffed::NeedMore => return PayloadSniff::NeedMore,
            crate::transport::sniff::Sniffed::Invalid => return PayloadSniff::Invalid,
            crate::transport::sniff::Sniffed::Domain(domain) => domain,
        };
        let kind = if payload.first() == Some(&0x16) {
            SniffKind::Tls
        } else {
            SniffKind::Http
        };
        let route = Target {
            host: Host::Domain(domain),
            port: target.port,
        };
        let dial = if policy.overrides(kind) {
            route.clone()
        } else {
            target.clone()
        };
        PayloadSniff::Detected { route, dial }
    }

    /// UDP 首包嗅探：QUIC Initial 的 SNI 只用于选路，不改变发送目标。
    ///
    /// 供 UDP 关联之外的 UDP 承载（Mux.Cool 的 xudp 会话）复用。
    pub fn udp_route_target(&self, inbound: &str, target: &Target, payload: &[u8]) -> Target {
        crate::transport::sniff::udp_route_target(self, inbound, target, payload)
    }
    /// 路由选择；`ip-if-non-match` 在没有任何规则命中时解析域名并重试。
    ///
    /// 解析失败按未命中处理并回落到默认出站，不因 DNS 故障拒绝连接；实际
    /// 拨号仍会再次解析域名，缓存由解析器自身负责。
    async fn selected(
        &self,
        inbound: &str,
        network: Network,
        target: &Target,
        allow_udp_proxy: bool,
    ) -> io::Result<Selected> {
        let mut selected = self.router.select_outbound(inbound, network, target);
        if !selected.matched
            && self.router.domain_strategy() == DomainStrategy::IpIfNonMatch
            && matches!(target.host, Host::Domain(_))
            && self.router.has_ip_candidates(inbound, network, target)
            && let Ok(addresses) = self.dns.resolve(target).await
        {
            let ips: Vec<IpAddr> = addresses.iter().map(|address| address.ip()).collect();
            if !ips.is_empty() {
                selected = self
                    .router
                    .select_with(inbound, network, target, Some(&ips));
            }
        }
        if selected.kind == OutboundKind::Reject {
            self.stats.reject();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                RouteRejected,
            ));
        }
        if target.port == 0 && selected.kind != OutboundKind::Reverse {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "无效目标端口"));
        }
        if network == Network::Udp && selected.proxy.is_some() {
            if !allow_udp_proxy {
                // 只有共享 UDP 关联实现了代理中继；其余 UDP 路径必须失败关闭，
                // 绝不能静默改走直连。
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "该 UDP 路径尚不支持上游代理出站",
                ));
            }
            if !matches!(
                selected.kind,
                OutboundKind::Socks5
                    | OutboundKind::Shadowsocks
                    | OutboundKind::Trojan
                    | OutboundKind::Vless
                    | OutboundKind::Vmess
                    | OutboundKind::Anytls
                    | OutboundKind::Hysteria2
                    | OutboundKind::Tuic
                    | OutboundKind::Wireguard
                    | OutboundKind::Nw3Vector
                    | OutboundKind::Snell
                    | OutboundKind::Naive
            ) {
                // 普通 HTTP CONNECT 不承载 UDP，不能私自变为 CONNECT-UDP 或改走直连。
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "该上游出站不支持 UDP",
                ));
            }
            if selected
                .proxy
                .as_ref()
                .is_some_and(|proxy| proxy.via.is_some())
            {
                // 链式出站只实现 TCP；嵌套 UDP ASSOCIATE 不在当前范围。
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "链式出站不支持 UDP",
                ));
            }
        }
        Ok(selected)
    }

    pub async fn allowed(
        &self,
        inbound: &str,
        network: Network,
        target: &Target,
    ) -> io::Result<()> {
        self.selected(inbound, network, target, false)
            .await
            .map(|_| ())
    }

    /// 共享 UDP 关联使用的选路：允许 SOCKS5 上游，HTTP 仍失败关闭。
    pub async fn udp_selected(&self, inbound: &str, target: &Target) -> io::Result<Selected> {
        self.selected(inbound, Network::Udp, target, true).await
    }

    /// 建立到目标（或上游代理）的 TCP/TLS 流。
    ///
    /// 直连使用明文 TCP；配置了 `tls` 的上游代理在握手前先完成 TLS。两者
    /// 统一包装为 `Upstream`，便于上层继续按字节转发。
    pub async fn connect(&self, inbound: &str, target: &Target) -> io::Result<Upstream> {
        self.connect_routed(inbound, target, target).await
    }

    /// 路由目标与拨号目标分离的连接：嗅探域名参与规则匹配，实际拨号仍可
    /// 使用原始目标（未启用 `dest_override` 时）。
    /// 按独立的选路目标与拨号目标建立 TCP 上游。
    ///
    /// 通常两者相同；首包嗅探只改写路由目标而保留原始拨号目标时，二者会不同。
    pub async fn connect_routed(
        &self,
        inbound: &str,
        route: &Target,
        dial: &Target,
    ) -> io::Result<Upstream> {
        let selected = self.selected(inbound, Network::Tcp, route, false).await?;
        let mut upstream = match &selected.reverse {
            Some(tag) => self.reverse.open(tag, dial).await?,
            None => {
                self.connect_selected(selected.proxy.as_deref(), dial)
                    .await?
            }
        };
        upstream.track(
            self.connections
                .register(inbound, selected.kind.name(), route),
        );
        Ok(upstream)
    }

    /// 按已选中的出站建立连接。
    ///
    /// `urltest` 探测复用该函数，因此不经过路由选择，也不改变选择结果。
    pub(crate) async fn connect_selected(
        &self,
        proxy: Option<&ProxyOutbound>,
        target: &Target,
    ) -> io::Result<Upstream> {
        timeout(Duration::from_millis(self.limits.dial_timeout_ms), async {
            let attempt = Duration::from_millis(self.limits.dial_attempt_timeout_ms);
            // ShadowTLS 没有目标，只能作为其他出站的 via detour；不能终端直连。
            if proxy.is_some_and(|proxy| proxy.shadowtls.is_some()) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "ShadowTLS 只能作为 via detour",
                ));
            }
            match proxy {
                None => {
                    let addresses = self.dns.resolve(target).await?;
                    let stream = dial_addresses(&addresses, attempt).await?;
                    let local = stream.local_addr().ok();
                    Ok(Upstream::new(Box::new(stream), local))
                }
                Some(proxy) if proxy.wireguard.is_some() => {
                    let wireguard = proxy.wireguard.as_ref().expect("已检查");
                    wireguard.connect(self, target).await
                }
                Some(proxy) if proxy.hysteria2.is_some() => {
                    let hysteria2 = proxy.hysteria2.as_ref().expect("已检查");
                    hysteria2.connect(self, target).await
                }
                Some(proxy) if proxy.tuic.is_some() => {
                    let tuic = proxy.tuic.as_ref().expect("已检查");
                    tuic.connect(self, target).await
                }
                Some(proxy) if proxy.nw3.is_some() => {
                    let nw3 = proxy.nw3.as_ref().expect("已检查");
                    let host = match &target.host {
                        crate::session::Host::Ip(ip) => ip.to_string(),
                        crate::session::Host::Domain(domain) => domain.clone(),
                    };
                    let stream = nw3.connect_tcp(&host, target.port).await.map_err(|error| {
                        io::Error::other(format!("NW3 Vector 连接失败: {error}"))
                    })?;
                    Ok(Upstream::new(
                        Box::new(SyncStream(std::sync::Mutex::new(stream))),
                        None,
                    ))
                }
                Some(proxy) if proxy.kind == OutboundKind::Naive => {
                    crate::transport::naive_client::connect(self, proxy, target).await
                }
                Some(proxy) if proxy.anytls_pool.is_some() => {
                    let pool = proxy.anytls_pool.as_ref().expect("已检查");
                    let password = proxy
                        .secret
                        .as_deref()
                        .ok_or_else(|| io::Error::other("AnyTLS缺少密码"))?;
                    pool.connect(
                        password,
                        target,
                        self.children.clone(),
                        self.outbound_stop.clone(),
                        Duration::from_millis(self.limits.dial_timeout_ms),
                        || self.dial_proxy_transport(proxy, false),
                    )
                    .await
                }
                Some(proxy) if proxy.snell_pool.is_some() => {
                    let pool = proxy.snell_pool.as_ref().expect("已检查");
                    let options = proxy
                        .snell
                        .as_deref()
                        .ok_or_else(|| io::Error::other("Snell出站参数缺失"))?;
                    pool.connect(
                        options,
                        target,
                        self.children.clone(),
                        self.outbound_stop.clone(),
                        || self.dial_proxy_transport(proxy, false),
                    )
                    .await
                }
                Some(proxy) => {
                    let stream = self.dial_proxy_transport(proxy, false).await?;
                    crate::outbound::connect_prepared(stream, proxy, target).await
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "拨号超时"))?
    }

    /// 建立到代理端点的裸 TCP/TLS 流，不做代理协议握手。
    ///
    /// 供 UDP 中继建立协议专用的长连接；不登记管理接口连接表。
    pub(crate) async fn dial_proxy_endpoint(&self, proxy: &ProxyOutbound) -> io::Result<Upstream> {
        if proxy.kind == OutboundKind::ShadowTls {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ShadowTLS 没有可用的裸端点或 UDP 用法",
            ));
        }
        let attempt = Duration::from_millis(self.limits.dial_attempt_timeout_ms);
        let addresses = self.dns.resolve(&proxy.endpoint).await?;
        let stream = dial_addresses(&addresses, attempt).await?;
        let local = stream.local_addr().ok();
        match (&proxy.tls, &proxy.reality) {
            (_, Some(reality)) => {
                reality
                    .connect(Upstream::new(Box::new(stream), local), None)
                    .await
            }
            (None, None) => Ok(Upstream::new(Box::new(stream), local)),
            (Some(tls), None) => {
                let connector = upstream_tls_connector(tls, proxy);
                let wrapped = connector.connect(tls.server_name.clone(), stream).await?;
                Ok(Upstream::new(Box::new(wrapped), local))
            }
        }
    }

    /// 启动所有被路由引用的 `urltest` 组周期探测任务。
    ///
    /// 探测经成员出站拨号配置的 `probe` 目标，只测量 TCP 建连延迟；失败
    /// 成员不参与选择，全部失败时保持当前成员。
    pub fn spawn_urltest_probes(self: &Arc<Self>, stop: CancellationToken) {
        for group in self.router.urltest_groups() {
            let context = Arc::clone(self);
            let group = Arc::clone(group);
            let stop = stop.clone();
            self.children.spawn(async move {
                urltest_loop(context, group, stop).await;
            });
        }
    }

    /// 为代理协议建立完整承载。UDP 命令 2 使用普通 TLS，不套 Vision body。
    /// H1 分离模式的连接工厂也会逐跳穿过同一 via 链，绝不绕过代理直连。
    pub(crate) async fn dial_proxy_transport(
        &self,
        proxy: &ProxyOutbound,
        udp: bool,
    ) -> io::Result<Upstream> {
        let attempt = Duration::from_millis(self.limits.dial_attempt_timeout_ms);
        let handshake = Duration::from_millis(self.limits.handshake_timeout_ms);
        let mut hops = Vec::new();
        let mut current = Some(proxy);
        while let Some(hop) = current {
            hops.push(hop.clone());
            current = hop.via.as_deref();
        }
        hops.reverse();
        let first = hops.first().ok_or_else(|| io::Error::other("出站链为空"))?;
        // 构造工厂不能先查询链首DNS：中间跳的健康池命中时根本无需新拨号。
        let mut factory = base_transport_factory(
            first,
            self.dns.clone(),
            attempt,
            handshake,
            self.children.clone(),
        );
        let last = hops.len() - 1;
        let mut previous: Option<Arc<ProxyOutbound>> = None;
        for (index, hop) in hops.into_iter().enumerate() {
            if let Some(previous) = previous {
                factory = tunnel_factory(
                    factory,
                    previous,
                    hop.endpoint.clone(),
                    handshake,
                    self.children.clone(),
                    self.outbound_stop.clone(),
                );
            }
            let hop = Arc::new(hop);
            factory = proxy_transport_factory(
                factory,
                hop.clone(),
                udp && index == last,
                handshake,
                self.children.clone(),
            );
            previous = Some(hop);
        }
        factory().await
    }
}

/// 底层连接工厂不借用 Context；多请求 HTTP/1.1 可以安全地重开同一条链。
type OpenStream = crate::transport::xhttp_client::OpenStream;

fn base_transport_factory(
    proxy: &ProxyOutbound,
    dns: Dns,
    attempt: Duration,
    handshake: Duration,
    tracker: tokio_util::task::TaskTracker,
) -> OpenStream {
    let proxy = proxy.clone();
    Arc::new(move || {
        let proxy = proxy.clone();
        let dns = dns.clone();
        let tracker = tracker.clone();
        Box::pin(async move {
            let addresses = dns.resolve(&proxy.endpoint).await?;
            if let Some(quic) = &proxy.quic {
                let peer = addresses.first().copied().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "QUIC 端点无可用地址")
                })?;
                if is_xhttp3(&proxy) {
                    let lease = quic.open_dedicated_at(peer, handshake).await?;
                    let options = xhttp_client_options(&proxy)?;
                    let stream = crate::transport::xhttp_client::connect_h3_tracked(
                        lease.connection(),
                        &options,
                        &tracker,
                    )
                    .await?;
                    return Ok(lease.wrap(stream));
                }
                return quic.connect_at(peer, handshake).await;
            }
            if let Some(kcp) = &proxy.kcp {
                let peer = addresses.first().copied().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "mKCP 端点无可用地址")
                })?;
                let stream = kcp.connect_tracked(peer, tracker).await?;
                return Ok(Upstream::new_send(stream, None));
            }
            let stream = dial_addresses(&addresses, attempt).await?;
            let local = stream.local_addr().ok();
            Ok(Upstream::new(Box::new(stream), local))
        })
    })
}

fn tunnel_factory(
    previous: OpenStream,
    hop: Arc<ProxyOutbound>,
    target: Target,
    handshake: Duration,
    tracker: tokio_util::task::TaskTracker,
    stop: CancellationToken,
) -> OpenStream {
    Arc::new(move || {
        let previous = previous.clone();
        let hop = hop.clone();
        let target = target.clone();
        let tracker = tracker.clone();
        let stop = stop.clone();
        Box::pin(async move {
            timeout(handshake, async {
                if hop.kind == OutboundKind::ShadowTls {
                    // 配置阶段已要求两端 endpoint 相同；运行期再次失败关闭，
                    // 防止直接构造的配置绕过该约束。
                    if hop.endpoint != target {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "ShadowTLS detour 目标与上游端点不一致",
                        ));
                    }
                    let client = hop
                        .shadowtls
                        .as_ref()
                        .ok_or_else(|| io::Error::other("ShadowTLS 客户端未初始化"))?;
                    let stream = previous().await?;
                    return client.connect(stream).await;
                }
                if let Some(pool) = &hop.anytls_pool {
                    let password = hop
                        .secret
                        .as_deref()
                        .ok_or_else(|| io::Error::other("AnyTLS缺少密码"))?;
                    return pool
                        .connect(password, &target, tracker, stop, handshake, || previous())
                        .await;
                }
                if let Some(pool) = &hop.snell_pool {
                    let options = hop
                        .snell
                        .as_deref()
                        .ok_or_else(|| io::Error::other("Snell出站参数缺失"))?;
                    return pool
                        .connect(options, &target, tracker, stop, || previous())
                        .await;
                }
                let stream = previous().await?;
                if hop.kind == OutboundKind::Naive {
                    return crate::transport::naive_client::connect_tcp(
                        stream, &hop, &target, tracker, stop, handshake,
                    )
                    .await;
                }
                crate::outbound::connect_prepared(stream, &hop, &target).await
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "出站链握手超时"))?
        })
    })
}

fn proxy_transport_factory(
    raw: OpenStream,
    proxy: Arc<ProxyOutbound>,
    udp: bool,
    handshake: Duration,
    tracker: tokio_util::task::TaskTracker,
) -> OpenStream {
    // ShadowTLS 客户端自行完成外层真实 TLS；这里返回裸流，避免重复套 TLS。
    if proxy.kind == OutboundKind::ShadowTls {
        return raw;
    }
    // QUIC 的 TLS 已在底层完成，HTTP/3 也已由专用连接工厂接管。
    if is_xhttp3(&proxy) {
        return raw;
    }
    let tls_proxy = proxy.clone();
    let secured: OpenStream = Arc::new(move || {
        let raw = raw.clone();
        let proxy = tls_proxy.clone();
        Box::pin(async move {
            timeout(handshake, async {
                let stream = raw().await?;
                if proxy.quic.is_some() || !udp && uses_controlled_tls(&proxy) {
                    return Ok(stream);
                }
                if let Some(reality) = &proxy.reality {
                    return reality.connect(stream, transport_alpn(&proxy)).await;
                }
                let Some(tls) = &proxy.tls else {
                    return Ok(stream);
                };
                let local = stream.local_addr().ok();
                let connector = upstream_tls_connector(tls, &proxy);
                let wrapped = connector.connect(tls.server_name.clone(), stream).await?;
                if let Some(expected) = transport_alpn(&proxy) {
                    let negotiated = wrapped.get_ref().1.alpn_protocol();
                    if negotiated.is_some_and(|protocol| protocol != expected)
                        || expected == b"h2" && negotiated != Some(expected)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "上游 ALPN 与配置的传输不一致",
                        ));
                    }
                }
                Ok(Upstream::new(Box::new(wrapped), local))
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "出站安全层握手超时"))?
        })
    });
    Arc::new(move || {
        let secured = secured.clone();
        let proxy = proxy.clone();
        let tracker = tracker.clone();
        Box::pin(async move {
            timeout(handshake, async {
                let stream = secured().await?;
                if proxy.transport.as_ref().is_some_and(|transport| {
                    transport.kind == crate::config::OutboundTransportType::Xhttp
                }) {
                    let options = xhttp_client_options(&proxy)?;
                    let local = stream.local_addr().ok();
                    let transport = proxy.transport.as_ref().expect("传输已检查");
                    let wrapped = match transport.http_version() {
                        crate::config::OutboundHttpVersion::Http1 => {
                            crate::transport::xhttp_client::connect_h1_with_opener_tracked(
                                stream,
                                &options,
                                secured.clone(),
                                &tracker,
                            )
                            .await?
                        }
                        crate::config::OutboundHttpVersion::Http2 => {
                            crate::transport::xhttp_client::connect_h2_tracked(
                                stream, &options, &tracker,
                            )
                            .await?
                        }
                        crate::config::OutboundHttpVersion::Http3 => {
                            return Err(io::Error::other("HTTP/3 承载未由 QUIC 工厂接管"));
                        }
                    };
                    return Ok(Upstream::new_send(wrapped, local));
                }
                crate::outbound::wrap_transport(stream, &proxy).await
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "出站传输握手超时"))?
        })
    })
}

fn is_xhttp3(proxy: &ProxyOutbound) -> bool {
    proxy.transport.as_ref().is_some_and(|transport| {
        transport.kind == crate::config::OutboundTransportType::Xhttp
            && transport.http_version() == crate::config::OutboundHttpVersion::Http3
    })
}

fn xhttp_client_options(
    proxy: &ProxyOutbound,
) -> io::Result<crate::transport::xhttp_client::ClientOptions> {
    let transport = proxy
        .transport
        .as_ref()
        .ok_or_else(|| io::Error::other("缺少 XHTTP 参数"))?;
    Ok(crate::transport::xhttp_client::ClientOptions {
        path: transport.path.clone().unwrap_or_else(|| "/".into()),
        host: Some(
            transport
                .host
                .clone()
                .unwrap_or_else(|| match &proxy.endpoint.host {
                    Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", proxy.endpoint.port),
                    Host::Ip(ip) => format!("{ip}:{}", proxy.endpoint.port),
                    Host::Domain(domain) => format!("{domain}:{}", proxy.endpoint.port),
                }),
        ),
        mode: transport.mode.unwrap_or_default(),
        h3: transport.http_version() == crate::config::OutboundHttpVersion::Http3,
        headers: transport.headers.clone(),
        x_padding: transport.x_padding,
        max_post_bytes: transport.max_post_bytes.unwrap_or(64 * 1024),
    })
}

pub(crate) fn transport_alpn(proxy: &ProxyOutbound) -> Option<&'static [u8]> {
    if let Some(options) = &proxy.naive {
        return Some(match options.http_version {
            crate::config::NaiveHttpVersion::H1 => b"http/1.1",
            crate::config::NaiveHttpVersion::H2 => b"h2",
            crate::config::NaiveHttpVersion::H3 => b"h3",
        });
    }
    let transport = proxy.transport.as_ref()?;
    match transport.kind {
        crate::config::OutboundTransportType::Grpc => Some(b"h2"),
        crate::config::OutboundTransportType::Ws
        | crate::config::OutboundTransportType::HttpUpgrade => Some(b"http/1.1"),
        crate::config::OutboundTransportType::Xhttp => match transport.http_version() {
            crate::config::OutboundHttpVersion::Http1 => Some(b"http/1.1"),
            crate::config::OutboundHttpVersion::Http2 => Some(b"h2"),
            crate::config::OutboundHttpVersion::Http3 => Some(b"h3"),
        },
        _ => None,
    }
}

/// Vision 需要受控 TLS 记录层，不能由普通 `tokio-rustls` 提前包装。
fn uses_controlled_tls(proxy: &ProxyOutbound) -> bool {
    proxy.kind == crate::config::OutboundKind::Vless
        && proxy.flow == crate::config::VlessFlow::Vision
}

/// 到上游的 TLS 连接器；仅提供配置所需的 ALPN，不猜测已丢失的协商结果。
fn upstream_tls_connector(
    tls: &crate::tls::ClientTls,
    proxy: &ProxyOutbound,
) -> tokio_rustls::TlsConnector {
    match transport_alpn(proxy) {
        Some(alpn) => {
            let mut config = (*tls.config).clone();
            config.alpn_protocols = vec![alpn.to_vec()];
            tokio_rustls::TlsConnector::from(Arc::new(config))
        }
        None => tokio_rustls::TlsConnector::from(tls.config.clone()),
    }
}

async fn urltest_loop(context: Arc<Context>, group: Arc<UrltestGroup>, stop: CancellationToken) {
    loop {
        if stop.is_cancelled() {
            return;
        }
        probe_round(&context, &group, &stop).await;
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(group.interval()) => {}
        }
    }
}

/// 并发探测组内全部成员；只在探测成功者中选择最低延迟，且位于容差内
/// 不切换当前成员。
async fn probe_round(context: &Arc<Context>, group: &Arc<UrltestGroup>, stop: &CancellationToken) {
    let current = group.selected_index();
    let mut tasks = JoinSet::new();
    for (index, member) in group.members().iter().enumerate() {
        let context = Arc::clone(context);
        let stop = stop.clone();
        let member = member.clone();
        let target = group.probe_target().clone();
        let limit = group.timeout();
        tasks.spawn(async move {
            if !member.dialable() {
                // `reject`/`reverse` 不能被探测成「健康」：不拨号、无样本。
                return (index, None);
            }
            let started = Instant::now();
            let result = tokio::select! {
                biased;
                _ = stop.cancelled() => return (index, None),
                result = timeout(limit, context.connect_selected(member.proxy(), &target)) => result,
            };
            (
                index,
                result.ok().and_then(std::result::Result::ok).map(|stream| {
                    drop(stream);
                    started.elapsed()
                }),
            )
        });
    }
    let mut best: Option<(usize, Duration)> = None;
    let mut current_latency = None;
    while let Some(joined) = tasks.join_next().await {
        let Ok((index, latency)) = joined else {
            continue;
        };
        let Some(latency) = latency else {
            continue;
        };
        if index == current {
            current_latency = Some(latency);
        }
        if best.is_none_or(|(_, best)| latency < best) {
            best = Some((index, latency));
        }
    }
    let Some((_, best_latency)) = best else {
        return;
    };
    if let Some(index) = choose_member(current, current_latency, best, group.tolerance()) {
        group.update(index);
        tracing::info!(
            event = "urltest",
            group = %group.tag(),
            outbound = %group.members()[index].tag,
            latency_ms = %best_latency.as_millis(),
            "出站组切换"
        );
    }
}

/// 决定是否切换成员：当前成功且与最优延迟之差在容差内时保持不动；
/// 当前失败或明显更慢时切换到最优成员。
fn choose_member(
    current: usize,
    current_latency: Option<Duration>,
    best: Option<(usize, Duration)>,
    tolerance: Duration,
) -> Option<usize> {
    let (best_index, best_latency) = best?;
    if best_index == current {
        return None;
    }
    if current_latency.is_some_and(|latency| latency <= best_latency.saturating_add(tolerance)) {
        return None;
    }
    Some(best_index)
}

/// 同时具备读写、`Unpin` 与 `Send` 的装箱流。
///
/// trait object 只能附加 auto trait，因此用一个 supertrait 组合出装箱类型。
#[doc(hidden)]
/// 把非 `Sync` 的字节流包装成可共享类型；短临界区加锁，不跨 await。
struct SyncStream<S>(std::sync::Mutex<S>);

impl<S: AsyncRead + Unpin> AsyncRead for SyncStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut stream = self.0.lock().unwrap_or_else(|error| error.into_inner());
        std::pin::Pin::new(&mut *stream).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SyncStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let mut stream = self.0.lock().unwrap_or_else(|error| error.into_inner());
        std::pin::Pin::new(&mut *stream).poll_write(cx, buffer)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut stream = self.0.lock().unwrap_or_else(|error| error.into_inner());
        std::pin::Pin::new(&mut *stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut stream = self.0.lock().unwrap_or_else(|error| error.into_inner());
        std::pin::Pin::new(&mut *stream).poll_shutdown(cx)
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + ?Sized> AsyncStream for T {}

pub(crate) type UpstreamStream = Box<dyn AsyncStream>;

/// 统一出站流：直连 TCP，或到上游代理的 TLS。
///
/// 保留 TCP 层本地地址供 SOCKS5 应答使用；TLS 不改变该地址。
pub struct Upstream {
    inner: UpstreamStream,
    local_addr: Option<std::net::SocketAddr>,
    /// 管理接口的连接句柄；丢弃时自动从注册表注销。
    session: Option<Arc<Connection>>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl Upstream {
    pub(crate) fn new(inner: UpstreamStream, local_addr: Option<std::net::SocketAddr>) -> Self {
        Self {
            inner,
            local_addr,
            session: None,
        }
    }

    /// 适配只要求 `Send` 的承载；锁只覆盖一次 poll，不跨 await 持有。
    pub(crate) fn new_send<S>(inner: S, local_addr: Option<std::net::SocketAddr>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new(
            Box::new(SyncStream(std::sync::Mutex::new(inner))),
            local_addr,
        )
    }

    fn track(&mut self, session: Arc<Connection>) {
        self.session = Some(session);
    }

    /// 拆出底层流、本地地址与连接句柄，供上游协议包装（Shadowsocks）。
    pub(crate) fn into_parts(
        self,
    ) -> (
        UpstreamStream,
        Option<std::net::SocketAddr>,
        Option<Arc<Connection>>,
    ) {
        (self.inner, self.local_addr, self.session)
    }

    /// 用包装后的流重建 `Upstream`，保留本地地址与管理接口句柄。
    pub(crate) fn from_parts(
        inner: UpstreamStream,
        local_addr: Option<std::net::SocketAddr>,
        session: Option<Arc<Connection>>,
    ) -> Self {
        Self {
            inner,
            local_addr,
            session,
        }
    }

    /// 用只要求 `Send` 的包装流重建 `Upstream`，保留本地地址与管理句柄。
    ///
    /// 记录层等类型可能包含非 `Sync` 的密码上下文；锁只覆盖单次 poll，不跨
    /// await，也不会把同一流并发暴露给多个任务。
    pub(crate) fn from_parts_send<S>(
        inner: S,
        local_addr: Option<std::net::SocketAddr>,
        session: Option<Arc<Connection>>,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::from_parts(
            Box::new(SyncStream(std::sync::Mutex::new(inner))),
            local_addr,
            session,
        )
    }

    /// 管理接口是否已请求关闭。**只做一次原子读**，不登记 waker。
    ///
    /// 转发路径每次 poll 都调用它；此前这里每次都拿一把互斥锁登记 waker，
    /// 即使绝大多数字节都由 `Ready(Ok(_))` 直接返回。
    fn close_error(&self) -> Option<io::Error> {
        let session = self.session.as_ref()?;
        session
            .is_closed()
            .then(|| io::Error::new(io::ErrorKind::ConnectionAborted, "连接已被管理接口关闭"))
    }

    /// 底层返回 `Pending` 时登记 waker，并复查一次关闭状态，避免「登记前
    /// 刚被取消」导致漏唤醒。
    fn park(&self, cx: &mut std::task::Context<'_>) -> Option<io::Error> {
        let session = self.session.as_ref()?;
        session.register_waker(cx.waker());
        session
            .is_closed()
            .then(|| io::Error::new(io::ErrorKind::ConnectionAborted, "连接已被管理接口关闭"))
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.local_addr
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "出站连接没有本地地址"))
    }
}

impl AsyncRead for Upstream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if let Some(error) = self.close_error() {
            return std::task::Poll::Ready(Err(error));
        }
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        match &result {
            std::task::Poll::Ready(Ok(())) => {
                if let Some(session) = &self.session {
                    session.add_download((buf.filled().len() - before) as u64);
                }
            }
            std::task::Poll::Pending => {
                if let Some(error) = self.park(cx) {
                    return std::task::Poll::Ready(Err(error));
                }
            }
            std::task::Poll::Ready(Err(_)) => {}
        }
        result
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if let Some(error) = self.close_error() {
            return std::task::Poll::Ready(Err(error));
        }
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        match &result {
            std::task::Poll::Ready(Ok(written)) => {
                if let Some(session) = &self.session {
                    session.add_upload(*written as u64);
                }
            }
            std::task::Poll::Pending => {
                if let Some(error) = self.park(cx) {
                    return std::task::Poll::Ready(Err(error));
                }
            }
            std::task::Poll::Ready(Err(_)) => {}
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if let Some(error) = self.close_error() {
            return std::task::Poll::Ready(Err(error));
        }
        let result = std::pin::Pin::new(&mut self.inner).poll_flush(cx);
        if let std::task::Poll::Pending = &result
            && let Some(error) = self.park(cx)
        {
            return std::task::Poll::Ready(Err(error));
        }
        result
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        if let Some(error) = self.close_error() {
            return std::task::Poll::Ready(Err(error));
        }
        let result = std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        match &result {
            std::task::Poll::Ready(Ok(written)) => {
                if let Some(session) = &self.session {
                    session.add_upload(*written as u64);
                }
            }
            std::task::Poll::Pending => {
                if let Some(error) = self.park(cx) {
                    return std::task::Poll::Ready(Err(error));
                }
            }
            std::task::Poll::Ready(Err(_)) => {}
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

pub async fn dial_addresses(
    addresses: &[std::net::SocketAddr],
    attempt: Duration,
) -> io::Result<TcpStream> {
    let mut error = io::Error::new(io::ErrorKind::NotFound, "无可用地址");
    for address in addresses {
        match timeout(attempt, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Ok(Err(err)) => error = err,
            Err(_) => error = io::Error::new(io::ErrorKind::TimedOut, "地址拨号超时"),
        }
    }
    Err(error)
}

/// 已建立的 SOCKS5 UDP 中继。
///
/// `control` 只是保活句柄：丢弃它即通知上游释放关联，因此必须与 `socket`
/// 一同存活。
pub struct UdpRelay {
    pub socket: Arc<tokio::net::UdpSocket>,
    /// 只用于保活；可能是明文 TCP，也可能是到上游的 TLS 流。
    #[allow(dead_code)]
    pub control: RelayControl,
}

#[doc(hidden)]
pub type RelayControl = Box<dyn AsyncStream>;

/// 连接上游并建立 UDP ASSOCIATE，返回已连接到中继地址的 UDP 套接字。
pub async fn dial_udp_relay(ctx: &Context, proxy: &ProxyOutbound) -> io::Result<UdpRelay> {
    let attempt = Duration::from_millis(ctx.limits.dial_attempt_timeout_ms);
    let addresses = ctx.dns.resolve(&proxy.endpoint).await?;
    let control = dial_addresses(&addresses, attempt).await?;
    let peer_ip = control.peer_addr()?.ip();
    let mut control: RelayControl = Box::new(control);
    if let Some(tls) = &proxy.tls {
        let connector = tokio_rustls::TlsConnector::from(tls.config.clone());
        control = Box::new(connector.connect(tls.server_name.clone(), control).await?);
    }
    let relay = crate::outbound::socks5_udp_associate(&mut control, proxy, peer_ip).await?;
    let socket = tokio::net::UdpSocket::bind(crate::udp::wildcard(relay.ip())).await?;
    crate::udp::shadowsocks::prepare_buffers(&socket)?;
    socket.connect(relay).await?;
    Ok(UdpRelay {
        socket: Arc::new(socket),
        control,
    })
}

pub async fn relay<S, T>(client: S, target: T, stats: Arc<Stats>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (uplink, downlink) = relay_blocks();
    relay_sized(client, target, stats, uplink, downlink).await
}

/// 默认中继块；与 Tokio 的 `DEFAULT_BUF_SIZE` 一致。
pub(crate) const COPY_BLOCK: usize = 8 * 1024;

/// 实验用块大小覆盖：`DUBHE_RELAY_UP_KIB` / `DUBHE_RELAY_DOWN_KIB`。
///
/// 只为基准测试存在，**不是**配置项：生产部署不应依赖它。读完一次后缓存，
/// 热路径上只是一次原子读。
///
/// 已测结论（同机回环、VLESS、四流、同轮配对）：
///
/// | 上行/下行 | 下载 | 上传 | 每连接增量 |
/// |---|---:|---:|---:|
/// | 8/8 KiB（默认） | 18.2–18.5 | 22.3–22.5 | 47.8–48.9 KiB |
/// | 1/12 KiB | 23.9–24.1 | **4.7–4.85** | 46.0–46.5 KiB |
/// | 16/32 KiB | 28.0–28.5 | 24.0 | **81.5–81.9 KiB** |
///
/// 也就是说：`1/12` 用**上传掉 79%** 换来下载 +32%，绝不能当默认值；
/// `16/32` 能到 28 Gbit/s，但每连接多占约 33 KiB，会输掉内存优势。
/// 默认保持 8/8，除非将来能证明业务是纯下行。
fn relay_block_override(side: RelaySide) -> usize {
    use std::sync::OnceLock;
    static UP: OnceLock<usize> = OnceLock::new();
    static DOWN: OnceLock<usize> = OnceLock::new();
    let cell = match side {
        RelaySide::Uplink => &UP,
        RelaySide::Downlink => &DOWN,
    };
    *cell.get_or_init(|| {
        let name = match side {
            RelaySide::Uplink => "DUBHE_RELAY_UP_KIB",
            RelaySide::Downlink => "DUBHE_RELAY_DOWN_KIB",
        };
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|kib| (1..=1024).contains(kib))
            .map_or(COPY_BLOCK, |kib| kib * 1024)
    })
}

enum RelaySide {
    Uplink,
    Downlink,
}

/// 当前生效的（上行, 下行）中继块大小。
fn relay_blocks() -> (usize, usize) {
    (
        relay_block_override(RelaySide::Uplink),
        relay_block_override(RelaySide::Downlink),
    )
}

/// 双向块大小不对称的中继：`uplink` 是 client→target，`downlink` 是 target→client。
///
/// 只给确有证据的协议使用。块越大，每条连接多占 `uplink + downlink - 16 KiB`
/// 的常驻缓冲；不要全局放大。
pub(crate) async fn relay_sized<S, T>(
    client: S,
    target: T,
    stats: Arc<Stats>,
    uplink: usize,
    downlink: usize,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let _flow = stats.enter(Gauge::Tcp);
    let idle = stats.idle_timeout();
    let client = Counted {
        inner: client,
        stats: stats.clone(),
        uplink: false,
    };
    let target = Counted {
        inner: target,
        stats,
        uplink: true,
    };
    // Tokio 的双向复制在单向 EOF 后关闭对应写端，继续排空另一方向。
    copy_with_idle_sizes(client, target, idle, uplink, downlink).await
}

/// 带空闲超时的双向复制；供不经 `relay` 的中继路径复用同一语义。
pub async fn copy_with_idle<S, T>(client: S, target: T, idle: Option<Duration>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    copy_with_idle_sizes(client, target, idle, COPY_BLOCK, COPY_BLOCK).await
}

/// 同 [`copy_with_idle`]，但两个方向可以各自指定块大小。
async fn copy_with_idle_sizes<S, T>(
    client: S,
    target: T,
    idle: Option<Duration>,
    uplink: usize,
    downlink: usize,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let Some(idle) = idle else {
        let mut client = client;
        let mut target = target;
        tokio::io::copy_bidirectional_with_sizes(&mut client, &mut target, uplink, downlink)
            .await?;
        return Ok(());
    };
    let activity = Arc::new(std::sync::atomic::AtomicU64::new(now_millis()));
    let mut client = Activity {
        inner: client,
        activity: activity.clone(),
    };
    let mut target = Activity {
        inner: target,
        activity: activity.clone(),
    };
    tokio::select! {
        result = tokio::io::copy_bidirectional_with_sizes(&mut client, &mut target, uplink, downlink) => {
            result?;
        }
        () = idle_watchdog(activity, idle) => {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "中继空闲超时"));
        }
    }
    Ok(())
}

/// 进程内单调毫秒，避免系统时钟回拨影响空闲判定。
fn now_millis() -> u64 {
    use std::sync::OnceLock;
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// 每次读写成功都刷新时间戳；任一层未就绪不会误判为空闲。
struct Activity<T> {
    inner: T,
    activity: Arc<std::sync::atomic::AtomicU64>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Activity<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &result
            && buf.filled().len() > before
        {
            self.activity
                .store(now_millis(), std::sync::atomic::Ordering::Relaxed);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Activity<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &result
            && *n > 0
        {
            self.activity
                .store(now_millis(), std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    // 必须转发：默认实现会退化为非 vectored 写入，改变底层分块与时序，
    // 在 H2 流控窗口边界上会放大竞态。
    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let std::task::Poll::Ready(Ok(written)) = &result
            && *written > 0
        {
            self.activity
                .store(now_millis(), std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

async fn idle_watchdog(activity: Arc<std::sync::atomic::AtomicU64>, idle: Duration) {
    let idle_ms: u64 = idle.as_millis().try_into().unwrap_or(u64::MAX);
    // 检查间隔取空闲上限的四分之一，兼顾及时性与定时器开销。
    let tick = Duration::from_millis((idle_ms / 4).max(1));
    loop {
        tokio::time::sleep(tick).await;
        let last = activity.load(std::sync::atomic::Ordering::Relaxed);
        if now_millis().saturating_sub(last) >= idle_ms {
            return;
        }
    }
}

#[cfg(test)]
mod lease_tests {
    use super::{Lease, relay};
    use crate::telemetry::Stats;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::{io, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Counted(Arc<AtomicUsize>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn urltest_choice_respects_tolerance_and_failures() {
        use super::choose_member;
        use std::time::Duration;

        let best = Some((1, Duration::from_millis(100)));
        let tolerance = Duration::from_millis(50);
        // 当前成员就是最优成员。
        assert_eq!(
            choose_member(1, Some(Duration::from_millis(100)), best, tolerance),
            None
        );
        // 在容差内保持当前成员，避免抖动。
        assert_eq!(
            choose_member(0, Some(Duration::from_millis(140)), best, tolerance),
            None
        );
        assert_eq!(
            choose_member(0, Some(Duration::from_millis(150)), best, tolerance),
            None
        );
        // 超出容差或当前探测失败时切换。
        assert_eq!(
            choose_member(0, Some(Duration::from_millis(151)), best, tolerance),
            Some(1)
        );
        assert_eq!(choose_member(0, None, best, tolerance), Some(1));
        // 全部探测失败时保持当前成员。
        assert_eq!(choose_member(0, None, None, tolerance), None);
    }

    #[test]
    fn lease_is_released_only_after_last_holder_drops() {
        let drops = Arc::new(AtomicUsize::new(0));
        let lease = Lease::new(Counted(drops.clone()));
        let child = lease.clone();
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 0, "子任务仍持有lease");
        drop(child);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "最后一个持有者释放");
    }

    #[tokio::test(start_paused = true)]
    async fn relay_drops_idle_connection_like_xray_conn_idle() {
        // 两端都不发数据：中继必须在空闲上限后自行结束，不能永久占用连接名额。
        let stats = Arc::new(Stats::with_idle_timeout(1000));
        let (client, _client_peer) = tokio::io::duplex(64);
        let (target, _target_peer) = tokio::io::duplex(64);
        // start_paused 下只有虚拟时钟会推进，用 tokio 的 Instant 判断。
        let started = tokio::time::Instant::now();
        let error = relay(client, target, stats)
            .await
            .expect_err("空闲连接必须超时");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_secs(1), "不能提前断开");
    }

    #[tokio::test(start_paused = true)]
    async fn relay_keeps_connection_alive_while_data_flows() {
        let stats = Arc::new(Stats::with_idle_timeout(200));
        let (client, mut client_peer) = tokio::io::duplex(64);
        let (target, mut target_peer) = tokio::io::duplex(64);
        let relay = tokio::spawn(relay(client, target, stats));
        // 持续 1 秒（远超 200ms 上限），每 50ms 双向各发一次。
        for _ in 0..20 {
            client_peer.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            target_peer.read_exact(&mut buf).await.unwrap();
            target_peer.write_all(b"pong").await.unwrap();
            client_peer.read_exact(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // 关闭一端后中继应正常收尾，而不是因空闲被杀。
        drop(client_peer);
        drop(target_peer);
        let result = relay.await.expect("中继任务不应panic");
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn zero_idle_timeout_disables_the_limit() {
        let stats = Stats::with_idle_timeout(0);
        assert!(stats.idle_timeout().is_none());
    }
}
