use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, mpsc},
    task::{AbortHandle, JoinSet},
    time::{Instant, timeout},
};

use crate::{
    forward::{Context, Lease},
    protocol::{socks5, trojan, vless, vmess as vmess_wire},
    route::{ProxyOutbound, Selected},
    session::{Host, Network, Target},
    telemetry::Gauge,
};

pub(crate) mod shadowsocks;
pub(crate) mod vmess;
use tokio_util::sync::{CancellationToken, DropGuard};
// 命令 3 现已由完整 Mux 承载；保留 XUDP wire codec 供 `tests/xudp.rs` 与
// 历史资产验证，不再作为运行层入口。
#[allow(dead_code)]
mod xudp;
pub use xudp::serve as xudp;

fn shadowsocks_uot_target() -> Target {
    Target {
        host: Host::Domain("sp.v2.udp-over-tcp.arpa".to_owned()),
        port: 0,
    }
}

fn to_shadowsocks_address(target: &Target) -> ::shadowsocks::relay::Address {
    match &target.host {
        Host::Ip(ip) => {
            ::shadowsocks::relay::Address::SocketAddress(SocketAddr::new(*ip, target.port))
        }
        Host::Domain(domain) => {
            ::shadowsocks::relay::Address::DomainNameAddress(domain.clone(), target.port)
        }
    }
}

fn from_shadowsocks_address(address: ::shadowsocks::relay::Address) -> Target {
    match address {
        ::shadowsocks::relay::Address::SocketAddress(address) => Target::from(address),
        ::shadowsocks::relay::Address::DomainNameAddress(domain, port) => Target {
            host: Host::Domain(domain),
            port,
        },
    }
}

/// 读取任务所需的句柄集合：发送端、UDP 会话标识、原生来源、共享上下文。
type ReaderParams = (
    mpsc::Sender<Packet>,
    Option<(u16, u64)>,
    Option<(SocketAddr, u64)>,
    Arc<Context>,
);

struct Packet {
    target: Target,
    payload: Vec<u8>,
    _budget: OwnedSemaphorePermit,
    session: Option<(u16, u64)>,
    native: Option<(SocketAddr, u64)>,
}
impl Packet {
    fn reserve(ctx: &Context, target: Target, payload: Vec<u8>) -> Option<Self> {
        let permit = ctx
            .udp_bytes
            .clone()
            .try_acquire_many_owned(payload.len().max(1) as u32)
            .ok()?;
        Some(Self {
            target,
            payload,
            _budget: permit,
            session: None,
            native: None,
        })
    }
}
/// 二级队列（SS / Snell / TUIC / Hysteria2 的按目标上行）的排队载荷。
///
/// 这些队列只按包数限长，而单包可达 `limits.max_udp_payload`；不随包持有
/// 字节额度时，一个关联就能囤积「包数 × 最大载荷」的内存，绕过
/// `limits.udp_queue_bytes`。额度在出队并写完上游后才归还。
pub(crate) struct QueuedUplink {
    pub payload: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

impl QueuedUplink {
    /// 额度不足就丢弃该包，与其它 UDP 路径的失败关闭一致。
    pub(crate) fn reserve(ctx: &Context, payload: Vec<u8>) -> Option<Self> {
        let budget = ctx
            .udp_bytes
            .clone()
            .try_acquire_many_owned(u32::try_from(payload.len().max(1)).ok()?)
            .ok()?;
        Some(Self {
            payload,
            _budget: budget,
        })
    }
}

/// 单目标 UDP 代理适配；复用现有 Association 的路由、字节预算与上游中继。
/// 用于 WireGuard 等并非 VLESS/Trojan 帧的入口，不另建直连旁路。
pub(crate) struct RoutedDatagram {
    pub payload: Vec<u8>,
    _packet: Packet,
}

pub(crate) struct RoutedUdp {
    association: Association,
    replies: mpsc::Receiver<Packet>,
    target: Target,
    _slot: OwnedSemaphorePermit,
    _gauge: crate::telemetry::Guard,
}

impl RoutedUdp {
    pub(crate) async fn new(
        ctx: Arc<Context>,
        inbound: String,
        target: Target,
    ) -> io::Result<Self> {
        ctx.udp_selected(&inbound, &target).await?;
        let slot = ctx
            .udp_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "UDP 关联上限"))?;
        let gauge = ctx.stats.enter(Gauge::Udp);
        let (association, replies) = Association::new(ctx, inbound);
        Ok(Self {
            association,
            replies,
            target,
            _slot: slot,
            _gauge: gauge,
        })
    }

    /// 固定HTTP请求：原域名先选路，成功应答前解析/准备，不发送探测空包。
    ///
    /// DNS 返回多个地址时按顺序尝试准备，保留各出站已有的地址族选择能力
    /// （例如只有 IPv4 内层地址的 WireGuard 可在 IPv6 候选失败后换用
    /// IPv4）；成功的候选固定为请求目标，后续发送不再解析。
    #[cfg(test)]
    pub(crate) fn prepared(
        ctx: Arc<Context>,
        inbound: String,
        target: Target,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Self>> + Send>> {
        Box::pin(async move {
            let selected = ctx.udp_selected(&inbound, &target).await?;
            let slot = ctx
                .udp_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "UDP 关联上限"))?;
            let gauge = ctx.stats.enter(Gauge::Udp);
            let addresses = ctx.dns.resolve(&target).await?;
            if addresses.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "UDP目标无可用地址"));
            }
            let deadline = Instant::now() + Duration::from_millis(ctx.limits.dial_timeout_ms);
            let mut last_error = None;
            for address in addresses {
                let target = Target::from(address);
                let (mut association, replies) = Association::new(ctx.clone(), inbound.clone());
                association.fixed = Some(Fixed {
                    selected: selected.clone(),
                    target: target.clone(),
                    failed: CancellationToken::new(),
                });
                let prepared = tokio::time::timeout_at(
                    deadline,
                    association.prepare_selected(selected.clone(), &target),
                )
                .await;
                match prepared {
                    Ok(Ok(())) => {
                        return Ok(Self {
                            association,
                            replies,
                            target,
                            _slot: slot,
                            _gauge: gauge,
                        });
                    }
                    Ok(Err(error)) => last_error = Some(error),
                    Err(_) => {
                        last_error =
                            Some(io::Error::new(io::ErrorKind::TimedOut, "UDP资源准备超时"));
                    }
                }
            }
            Err(last_error
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "UDP目标无可用地址")))
        })
    }

    pub(crate) async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > self.association.ctx.limits.max_udp_payload {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP 载荷过长"));
        }
        let packet = Packet::reserve(&self.association.ctx, self.target.clone(), payload.to_vec())
            .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "UDP 字节预算耗尽"))?;
        let result = timeout(
            Duration::from_millis(self.association.ctx.limits.dial_timeout_ms),
            self.association.send(packet.target, &packet.payload),
        )
        .await
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "UDP 出站拨号超时")));
        if result.as_ref().is_err_and(|error| {
            !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::InvalidInput
            )
        }) && let Some(fixed) = &self.association.fixed
        {
            fixed.failed.cancel();
        }
        result
    }

    pub(crate) async fn recv(&mut self) -> io::Result<RoutedDatagram> {
        let mut filtered = 0usize;
        loop {
            let mut packet = if let Some(fixed) = &self.association.fixed {
                tokio::select! { biased;
                    _ = fixed.failed.cancelled() => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "固定UDP请求资源已失效")),
                    packet = self.replies.recv() => packet,
                }
            } else { self.replies.recv().await }
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "UDP 关联已关闭"))?;
            // 固定请求只接受已准备目标；SOCKS/UoT 等上游携带的来源地址不能
            // 把其它目标的回程注入该请求。非固定关联保持原有逐目标语义。
            if self
                .association
                .fixed
                .as_ref()
                .is_some_and(|fixed| packet.target != fixed.target)
            {
                self.association.ctx.stats.drop_packet();
                filtered += 1;
                if filtered.is_multiple_of(32) {
                    tokio::task::yield_now().await;
                }
                continue;
            }
            return Ok(RoutedDatagram {
                payload: std::mem::take(&mut packet.payload),
                _packet: packet,
            });
        }
    }

    pub(crate) fn received(&self, count: usize) {
        self.association
            .ctx
            .stats
            .downlink
            .fetch_add(count as u64, Ordering::Relaxed);
    }
}

impl Drop for RoutedUdp {
    fn drop(&mut self) {
        self.association.tasks.abort_all();
        for mapping in self.association.mappings.values() {
            mapping.task.abort();
        }
        if let Some(relay) = &mut self.association.relay {
            relay.tasks.abort_all();
        }
    }
}

struct Mapping {
    socket: Arc<UdpSocket>,
    task: AbortHandle,
    last_used: Arc<std::sync::Mutex<Instant>>,
}
/// 上游 UDP 中继；具体承载由出站协议决定。
struct Relay {
    proxy: ProxyOutbound,
    uplink: Uplink,
    tasks: JoinSet<()>,
    last_used: Arc<std::sync::Mutex<Instant>>,
}

enum Uplink {
    /// SOCKS5 UDP ASSOCIATE；控制连接保活信息随变体持有。
    Socks5 {
        socket: Arc<UdpSocket>,
        _control: Option<crate::forward::RelayControl>,
    },
    Shadowsocks {
        socket: Arc<::shadowsocks::relay::udprelay::ProxySocket<::shadowsocks::net::UdpSocket>>,
        /// AEAD-2022 的发送控制状态：服务端按 (client_session_id, packet_id)
        /// 做重放窗口，固定 0 会让第一包之后的每个包都被判重放。
        session: u64,
        packet: u64,
    },
    /// Trojan UDP：单条 TCP 隧道，逐包携带目标。
    Trojan(tokio::io::WriteHalf<crate::forward::Upstream>),
    /// VLESS UDP：每个目标一条固定目标隧道。
    Vless(HashMap<Target, tokio::io::WriteHalf<crate::forward::Upstream>>),
    /// VMess UDP：每个目标一条命令 2 隧道，正文块即数据报边界。
    Vmess(
        HashMap<Target, vmess_wire::body::Writer<tokio::io::WriteHalf<crate::forward::Upstream>>>,
    ),
    /// Shadowsocks UoT：单条 TCP 隧道承载逐包目标。
    ShadowsocksUot(tokio::io::WriteHalf<crate::forward::Upstream>),
    /// AnyTLS 无原生 UDP；同样以协议层 UoT v2 承载。
    AnytlsUot(tokio::io::WriteHalf<crate::forward::Upstream>),
    /// Hysteria2 UDP：专用 QUIC 连接上的 DATAGRAM 会话。
    Hysteria2 {
        sender: crate::transport::hysteria2::UdpSessionSender,
        _keepalive: crate::transport::hysteria2::UdpKeepalive,
    },
    /// IP 隧道/NW3：每目标独立 UDP socket/Flow，回包来源不混用。
    Datagrams(HashMap<Target, TargetDatagram>),
    /// TUIC v5 UDP：专用 QUIC 连接上的 DATAGRAM 会话。
    Tuic {
        sender: crate::transport::tuic_client::UdpSender,
        _keepalive: crate::transport::tuic_client::UdpKeepalive,
    },
}
struct DatagramRequest {
    payload: Vec<u8>,
    _budget: OwnedSemaphorePermit,
    completion: tokio::sync::oneshot::Sender<io::Result<()>>,
}

struct TargetDatagram {
    sender: mpsc::Sender<DatagramRequest>,
    task: AbortHandle,
    last_used: Arc<std::sync::Mutex<Instant>>,
}

/// 两种 QUIC 出站的 UDP 接收端；共用同一回包投递路径。
enum UdpReader {
    Hysteria2(crate::transport::hysteria2::UdpSessionReceiver),
    Tuic(crate::transport::tuic_client::UdpReceiver),
}

impl UdpReader {
    async fn recv(&mut self) -> io::Result<(Target, Vec<u8>)> {
        match self {
            Self::Hysteria2(receiver) => receiver.recv().await,
            Self::Tuic(receiver) => receiver.recv().await,
        }
    }
}

struct Fixed {
    selected: Selected,
    target: Target,
    failed: CancellationToken,
}

struct Association {
    ctx: Arc<Context>,
    inbound: String,
    mappings: HashMap<Target, Mapping>,
    relay: Option<Relay>,
    /// 反向 Mux Portal 的 UDP 隧道；与普通 relay 互斥。
    reverse: Option<(Arc<str>, crate::reverse::UdpSender)>,
    tasks: JoinSet<()>,
    tx: mpsc::Sender<Packet>,
    session: Option<(u16, u64)>,
    native: Option<(SocketAddr, u64)>,
    lease: Option<Lease>,
    fixed: Option<Fixed>,
    /// 已认证用户的累计字节；未认证路径为 None。
    traffic: Option<Arc<crate::telemetry::UserCounters>>,
}
/// AEAD-2022 UDP 的客户端会话标识：非零随机值，服务端按它隔离关联。
fn random_session_id() -> u64 {
    loop {
        let mut bytes = [0u8; 8];
        aws_lc_rs::rand::fill(&mut bytes).expect("系统随机源不可用");
        let value = u64::from_be_bytes(bytes);
        if value != 0 {
            return value;
        }
    }
}

impl Association {
    fn new(ctx: Arc<Context>, inbound: String) -> (Self, mpsc::Receiver<Packet>) {
        let (tx, rx) = mpsc::channel(ctx.limits.udp_queue_packets);
        (Self::with_replies(ctx, inbound, tx, None, None), rx)
    }
    fn with_lease(
        ctx: Arc<Context>,
        inbound: String,
        lease: Option<Lease>,
    ) -> (Self, mpsc::Receiver<Packet>) {
        let (tx, rx) = mpsc::channel(ctx.limits.udp_queue_packets);
        (Self::with_replies(ctx, inbound, tx, None, lease), rx)
    }
    fn with_replies(
        ctx: Arc<Context>,
        inbound: String,
        tx: mpsc::Sender<Packet>,
        session: Option<(u16, u64)>,
        lease: Option<Lease>,
    ) -> Self {
        Self {
            ctx,
            inbound,
            mappings: HashMap::new(),
            relay: None,
            reverse: None,
            tasks: JoinSet::new(),
            tx,
            session,
            native: None,
            lease,
            fixed: None,
            traffic: None,
        }
    }
    fn failure_guard(&self) -> Option<DropGuard> {
        self.fixed
            .as_ref()
            .map(|fixed| fixed.failed.clone().drop_guard())
    }
    fn expire(&mut self) {
        if self.fixed.is_some() {
            return;
        } // 固定请求只能随HTTP结束，不单独空闲回收后重建。
        let ttl = Duration::from_millis(self.ctx.limits.udp_idle_timeout_ms);
        self.mappings.retain(|_, mapping| {
            if mapping.task.is_finished()
                || mapping
                    .last_used
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .elapsed()
                    >= ttl
            {
                mapping.task.abort();
                false
            } else {
                true
            }
        });
        if let Some(Relay {
            uplink: Uplink::Datagrams(targets),
            ..
        }) = &mut self.relay
        {
            targets.retain(|_, target| {
                if target.task.is_finished()
                    || target
                        .last_used
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .elapsed()
                        >= ttl
                {
                    target.task.abort();
                    false
                } else {
                    true
                }
            });
        }
        let relay_expired = self.relay.as_ref().is_some_and(|relay| {
            relay
                .last_used
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .elapsed()
                >= ttl
        });
        if relay_expired && let Some(mut relay) = self.relay.take() {
            relay.tasks.abort_all();
        }
        while self.tasks.try_join_next().is_some() {}
    }
    async fn send(&mut self, target: Target, payload: &[u8]) -> io::Result<()> {
        if payload.len() > self.ctx.limits.max_udp_payload {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP 载荷过长"));
        }
        // QUIC Initial 的 SNI 只参与选路；UDP 发送目标保持不变，避免同一
        // 关联的后续包在域名与 IP 之间切换。
        let selected = if let Some(fixed) = &self.fixed {
            if fixed.failed.is_cancelled() || target != fixed.target {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "固定UDP请求资源已失效",
                ));
            }
            fixed.selected.clone()
        } else {
            let route = crate::transport::sniff::udp_route_target(
                &self.ctx,
                &self.inbound,
                &target,
                payload,
            );
            // 非固定入口保持首包嗅探/按报文选路，不因预备接口改变。
            self.ctx.udp_selected(&self.inbound, &route).await?
        };
        self.expire();
        if let Some(tag) = selected.reverse {
            return self.send_reverse(tag, &target, payload).await;
        }
        if self.reverse.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "同一 UDP 关联不能混用反向 Portal 与其它上游",
            ));
        }
        let proxy = selected.proxy.map(|proxy| (*proxy).clone());
        if let Some(proxy) = proxy {
            return self.send_proxy(proxy, &target, payload).await;
        }
        self.prepare_direct(&target).await?;
        let mapping = self
            .mappings
            .get_mut(&target)
            .ok_or_else(|| io::Error::other("UDP 直接映射缺失"))?;
        let n = mapping.socket.send(payload).await?;
        if n != payload.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "UDP 不完整发送"));
        }
        *mapping
            .last_used
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
        self.count_uplink(n);
        Ok(())
    }

    #[cfg(test)]
    async fn prepare_selected(&mut self, selected: Selected, target: &Target) -> io::Result<()> {
        if let Some(tag) = selected.reverse {
            return self.prepare_reverse(tag, target).await;
        }
        if let Some(proxy) = selected.proxy {
            return self.prepare_proxy((*proxy).clone(), target).await;
        }
        self.prepare_direct(target).await
    }

    async fn prepare_direct(&mut self, target: &Target) -> io::Result<()> {
        if !self.mappings.contains_key(target) {
            self.ensure_target_capacity(target)?;
            let address = self
                .ctx
                .dns
                .resolve(target)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "UDP目标无可用地址"))?;
            let bind = if address.is_ipv4() {
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
            };
            let socket = Arc::new(UdpSocket::bind(bind).await?);
            // 公共关联同样可发送配置允许的最大UDP包；macOS默认发送缓冲
            // 只有9216字节。复用逐socket准备，不修改系统参数或缩小已有缓冲。
            shadowsocks::prepare_buffers(&socket)?;
            // connected UDP 套接字由内核过滤非目标来源。
            socket.connect(address).await?;
            let read = socket.clone();
            let tx = self.tx.clone();
            let session = self.session;
            let native = self.native;
            let ctx = self.ctx.clone();
            let last_used = Arc::new(std::sync::Mutex::new(Instant::now()));
            let last_received = last_used.clone();
            let tracker = ctx.children.clone();
            // mapping reader与RPC/关联共享租约：任务真正结束前不归还上层额度。
            let lease = self.lease.clone();
            let failure = self.failure_guard();
            let task = self.tasks.spawn(tracker.track_future(async move {
                let _lease = lease;
                let _failure = failure;
                let mut buffer = vec![0; 65536];
                while let Ok(n) = read.recv(&mut buffer).await {
                    if n > ctx.limits.max_udp_payload {
                        ctx.stats.drop_packet();
                        continue;
                    }
                    let Some(mut packet) =
                        Packet::reserve(&ctx, address.into(), buffer[..n].to_vec())
                    else {
                        ctx.stats.drop_packet();
                        continue;
                    };
                    packet.session = session;
                    packet.native = native;
                    if tx.try_send(packet).is_err() {
                        ctx.stats.drop_packet();
                    } else {
                        *last_received
                            .lock()
                            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
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
        Ok(())
    }
    /// 经 SOCKS5 上游转发一个 UDP 载荷。
    ///
    /// 一个关联只允许一个上游：不同代理的出站需要各自的 UDP 中继与控制连接，
    /// 混用会让回程地址无法归属，因此直接失败关闭。
    async fn send_reverse(
        &mut self,
        tag: Arc<str>,
        target: &Target,
        payload: &[u8],
    ) -> io::Result<()> {
        self.prepare_reverse(tag, target).await?;
        let sender = &self.reverse.as_ref().expect("反向会话已建立").1;
        sender.send(target, payload).await?;
        self.count_uplink(payload.len());
        Ok(())
    }

    async fn prepare_reverse(&mut self, tag: Arc<str>, target: &Target) -> io::Result<()> {
        if self.relay.is_some() || !self.mappings.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "同一 UDP 关联不能混用反向 Portal 与其它上游",
            ));
        }
        if let Some((existing, _)) = &self.reverse {
            if existing.as_ref() != tag.as_ref() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "同一 UDP 关联只能使用一个反向 Portal",
                ));
            }
        } else {
            let (sender, mut receiver) = self.ctx.reverse.open_udp(&tag, target)?;
            let (tx, session, native, ctx) = self.reader_params();
            let tracker = ctx.children.clone();
            let lease = self.lease.clone();
            let failure = self.failure_guard();
            self.tasks.spawn(tracker.track_future(async move {
                let _lease = lease;
                let _failure = failure;
                while let Some((target, payload)) = receiver.recv().await {
                    if payload.len() > ctx.limits.max_udp_payload {
                        ctx.stats.drop_packet();
                        continue;
                    }
                    let Some(mut packet) = Packet::reserve(&ctx, target, payload) else {
                        ctx.stats.drop_packet();
                        continue;
                    };
                    packet.session = session;
                    packet.native = native;
                    if tx.try_send(packet).is_err() {
                        ctx.stats.drop_packet();
                    }
                }
            }));
            self.reverse = Some((tag.clone(), sender));
        }
        Ok(())
    }

    /// 本关联已占用的逐目标资源数：直连映射 + 逐目标代理隧道。
    ///
    /// 文档承诺 `max_udp_targets` 是「每关联，直连与代理目标合计」；两条
    /// 路径各数各的会让混合路由突破上限。
    fn target_count(&self) -> usize {
        let tunnels = match self.relay.as_ref().map(|relay| &relay.uplink) {
            Some(Uplink::Vless(tunnels)) => tunnels.len(),
            Some(Uplink::Vmess(tunnels)) => tunnels.len(),
            _ => 0,
        };
        self.mappings.len() + tunnels
    }

    /// 新目标拨号前统一检查容量；已存在的目标复用，不重复占名额。
    fn ensure_target_capacity(&self, target: &Target) -> io::Result<()> {
        if self.mappings.contains_key(target) || self.has_proxy_tunnel(target) {
            return Ok(());
        }
        if self.target_count() >= self.ctx.limits.max_udp_targets {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "UDP 目标上限"));
        }
        Ok(())
    }

    fn has_proxy_tunnel(&self, target: &Target) -> bool {
        match self.relay.as_ref().map(|relay| &relay.uplink) {
            Some(Uplink::Vless(tunnels)) => tunnels.contains_key(target),
            Some(Uplink::Vmess(tunnels)) => tunnels.contains_key(target),
            Some(Uplink::Datagrams(targets)) => targets.contains_key(target),
            _ => false,
        }
    }

    async fn prepare_proxy(&mut self, proxy: ProxyOutbound, target: &Target) -> io::Result<()> {
        if let Some(relay) = &self.relay {
            if relay.proxy != proxy {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "同一 UDP 关联只能使用同一个上游代理",
                ));
            }
        } else {
            self.establish_relay(proxy).await?;
        }
        if matches!(
            self.relay.as_ref().map(|relay| &relay.uplink),
            Some(Uplink::Vless(tunnels)) if !tunnels.contains_key(target)
        ) {
            self.ensure_target_capacity(target)?;
            self.open_vless_tunnel(target).await?;
        }
        if matches!(
            self.relay.as_ref().map(|relay| &relay.uplink),
            Some(Uplink::Vmess(tunnels)) if !tunnels.contains_key(target)
        ) {
            self.ensure_target_capacity(target)?;
            self.open_vmess_tunnel(target).await?;
        }
        if matches!(self.relay.as_ref().map(|relay| &relay.uplink),
            Some(Uplink::Datagrams(targets)) if !targets.contains_key(target))
        {
            self.open_datagram_target(target).await?;
        }
        Ok(())
    }

    /// 记录一次成功的业务上行：全局计数 + 已认证用户的归因。
    ///
    /// 直连、代理、反向三条成功路径必须用同一处记账；只在直连里补用户计数
    /// 会让代理出站的上行在 `/stats/users` 里恒为 0。
    fn count_uplink(&self, bytes: usize) {
        self.ctx
            .stats
            .uplink
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if let Some(traffic) = &self.traffic {
            traffic.add(true, bytes);
        }
    }

    async fn send_proxy(
        &mut self,
        proxy: ProxyOutbound,
        target: &Target,
        payload: &[u8],
    ) -> io::Result<()> {
        self.prepare_proxy(proxy, target).await?;
        let relay = self
            .relay
            .as_mut()
            .ok_or_else(|| io::Error::other("UDP 中继未建立"))?;
        match &mut relay.uplink {
            Uplink::Socks5 { socket, .. } => {
                let datagram = crate::outbound::socks5_udp_encode(target, payload)?;
                let sent = socket.send(&datagram).await?;
                if sent != datagram.len() {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "UDP 不完整发送"));
                }
            }
            Uplink::Shadowsocks {
                socket,
                session,
                packet,
            } => {
                let address = to_shadowsocks_address(target);
                *packet = packet.wrapping_add(1);
                // 结构是 non_exhaustive：先 default 再改字段。
                let mut control =
                    ::shadowsocks::relay::udprelay::options::UdpSocketControlData::default();
                control.client_session_id = *session;
                control.packet_id = *packet;
                socket
                    .send_with_ctrl(&address, &control, payload)
                    .await
                    .map_err(|error| {
                        io::Error::other(format!("Shadowsocks UDP 发送失败: {error}"))
                    })?;
            }
            Uplink::Trojan(write) => {
                let datagram = crate::protocol::trojan::encode_datagram(target, payload)?;
                write.write_all(&datagram).await?;
                write.flush().await?;
            }
            Uplink::Vless(tunnels) => {
                let write = tunnels
                    .get_mut(target)
                    .ok_or_else(|| io::Error::other("VLESS UDP 隧道缺失"))?;
                let length = u16::try_from(payload.len())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UDP 载荷过长"))?;
                write.write_all(&length.to_be_bytes()).await?;
                write.write_all(payload).await?;
                write.flush().await?;
            }
            Uplink::Vmess(tunnels) => {
                let write = tunnels
                    .get_mut(target)
                    .ok_or_else(|| io::Error::other("VMess UDP 隧道缺失"))?;
                write.packet(payload).await?;
                write.flush().await?;
            }
            Uplink::ShadowsocksUot(write) | Uplink::AnytlsUot(write) => {
                let framing = Framing::Uot {
                    is_connect: false,
                    destination: shadowsocks_uot_target(),
                };
                let frame = framing.encode(target, payload)?;
                write.write_all(&frame).await?;
                write.flush().await?;
            }
            Uplink::Hysteria2 { sender, .. } => sender.send(target, payload).await?,
            Uplink::Tuic { sender, .. } => sender.send(target, payload).await?,
            Uplink::Datagrams(targets) => {
                let mapping = targets
                    .get(target)
                    .ok_or_else(|| io::Error::other("UDP 目标会话缺失"))?;
                let (completion, result) = tokio::sync::oneshot::channel();
                // worker 拥有的副本也占预算，调用方取消后队列不能留下无额度的载荷。
                let budget = self
                    .ctx
                    .udp_bytes
                    .clone()
                    .try_acquire_many_owned(payload.len().max(1) as u32)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::WouldBlock, "UDP 发送队列字节预算耗尽")
                    })?;
                mapping
                    .sender
                    .send(DatagramRequest {
                        payload: payload.to_vec(),
                        _budget: budget,
                        completion,
                    })
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "UDP 目标会话已关闭"))?;
                result
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "UDP 发送任务退出"))??;
                *mapping
                    .last_used
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Instant::now();
            }
        }
        *relay
            .last_used
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
        self.count_uplink(payload.len());
        Ok(())
    }

    fn establish_relay(
        &mut self,
        proxy: ProxyOutbound,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>> {
        // 多协议拨号状态机只在建立关联时分配，避免嵌入每个 UDP 数据面的 future。
        Box::pin(self.establish_relay_impl(proxy))
    }

    async fn establish_relay_impl(&mut self, proxy: ProxyOutbound) -> io::Result<()> {
        let uplink = match proxy.kind {
            crate::config::OutboundKind::Socks5 => {
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式出站不支持 UDP",
                    ));
                }
                let connection = crate::forward::dial_udp_relay(&self.ctx, &proxy).await?;
                let socket = connection.socket;
                let read = socket.clone();
                let (tx, session, native, ctx) = self.reader_params();
                let mut tasks = JoinSet::new();
                let last_used = Arc::new(std::sync::Mutex::new(Instant::now()));
                let last_received = last_used.clone();
                let tracker = ctx.children.clone();
                let lease = self.lease.clone();
                let failure = self.failure_guard();
                tasks.spawn(tracker.track_future(async move {
                    let _lease = lease;
                    let _failure = failure;
                    let mut buffer = vec![0; 65536];
                    while let Ok(n) = read.recv(&mut buffer).await {
                        let Some((target, payload)) =
                            crate::outbound::socks5_udp_parse(&buffer[..n])
                        else {
                            ctx.stats.drop_packet();
                            continue;
                        };
                        if payload.len() > ctx.limits.max_udp_payload {
                            ctx.stats.drop_packet();
                            continue;
                        }
                        let Some(mut packet) = Packet::reserve(&ctx, target, payload.to_vec())
                        else {
                            ctx.stats.drop_packet();
                            continue;
                        };
                        packet.session = session;
                        packet.native = native;
                        if tx.try_send(packet).is_err() {
                            ctx.stats.drop_packet();
                        } else {
                            *last_received
                                .lock()
                                .unwrap_or_else(|error| error.into_inner()) = Instant::now();
                        }
                    }
                }));
                let control = if self.fixed.is_some() {
                    let mut control = connection.control;
                    let guard = self.failure_guard();
                    tasks.spawn(tracker.track_future(async move {
                        let _failure = guard;
                        let mut byte = [0];
                        let _ = control.read(&mut byte).await; // EOF/错误都使固定请求结束。
                    }));
                    None
                } else {
                    Some(connection.control)
                };
                self.relay = Some(Relay {
                    proxy,
                    uplink: Uplink::Socks5 {
                        socket,
                        _control: control,
                    },
                    tasks,
                    last_used,
                });
                return Ok(());
            }
            crate::config::OutboundKind::Shadowsocks => {
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式出站不支持 UDP",
                    ));
                }
                if proxy.udp_over_tcp {
                    let mut stream = self.ctx.dial_proxy_endpoint(&proxy).await?;
                    stream = crate::outbound::shadowsocks_connect(
                        stream,
                        &proxy,
                        &shadowsocks_uot_target(),
                    )?;
                    // UoT v2 请求：isConnect=false + 占位地址；逐包目标在帧内。
                    stream.write_all(&[0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    stream.flush().await?;
                    let (mut read, write) = tokio::io::split(stream);
                    let (tx, session, native, ctx) = self.reader_params();
                    let mut tasks = JoinSet::new();
                    let tracker = ctx.children.clone();
                    let lease = self.lease.clone();
                    let failure = self.failure_guard();
                    tasks.spawn(tracker.track_future(async move {
                        let _lease = lease;
                        let _failure = failure;
                        let framing = Framing::Uot {
                            is_connect: false,
                            destination: shadowsocks_uot_target(),
                        };
                        loop {
                            let (target, payload) =
                                match framing.read(&mut read, ctx.limits.max_udp_payload).await {
                                    Ok(Some(packet)) => packet,
                                    Ok(None) | Err(_) => break,
                                };
                            let Some(mut packet) = Packet::reserve(&ctx, target, payload) else {
                                ctx.stats.drop_packet();
                                continue;
                            };
                            packet.session = session;
                            packet.native = native;
                            if tx.try_send(packet).is_err() {
                                ctx.stats.drop_packet();
                            }
                        }
                    }));
                    let last_used = Arc::new(std::sync::Mutex::new(Instant::now()));
                    self.relay = Some(Relay {
                        proxy,
                        uplink: Uplink::ShadowsocksUot(write),
                        tasks,
                        last_used,
                    });
                    return Ok(());
                }
                let (context, config) = crate::outbound::shadowsocks_udp_config(&proxy)?;
                let socket = Arc::new(
                    ::shadowsocks::relay::udprelay::ProxySocket::connect(context, &config)
                        .await
                        .map_err(|error| {
                            io::Error::other(format!("Shadowsocks UDP 连接失败: {error}"))
                        })?,
                );
                let client_session = random_session_id();
                let read = socket.clone();
                let (tx, session, native, ctx) = self.reader_params();
                let mut tasks = JoinSet::new();
                let tracker = ctx.children.clone();
                let lease = self.lease.clone();
                let failure = self.failure_guard();
                tasks.spawn(tracker.track_future(async move {
                    let _lease = lease;
                    let _failure = failure;
                    let expected_session = client_session;
                    let mut buffer = vec![0; 65536];
                    loop {
                        let (length, address, _, control) =
                            match read.recv_with_ctrl(&mut buffer).await {
                                Ok(value) => value,
                                Err(_) => break,
                            };
                        // 服务端回包必须属于本关联的客户端会话，避免错投。
                        if control
                            .is_some_and(|control| control.client_session_id != expected_session)
                        {
                            ctx.stats.drop_packet();
                            continue;
                        }
                        if length > ctx.limits.max_udp_payload {
                            ctx.stats.drop_packet();
                            continue;
                        }
                        let target = from_shadowsocks_address(address);
                        let Some(mut packet) =
                            Packet::reserve(&ctx, target, buffer[..length].to_vec())
                        else {
                            ctx.stats.drop_packet();
                            continue;
                        };
                        packet.session = session;
                        packet.native = native;
                        if tx.try_send(packet).is_err() {
                            ctx.stats.drop_packet();
                        }
                    }
                }));
                self.relay = Some(Relay {
                    proxy,
                    uplink: Uplink::Shadowsocks {
                        socket,
                        session: client_session,
                        packet: 0,
                    },
                    tasks,
                    last_used: Arc::new(std::sync::Mutex::new(Instant::now())),
                });
                return Ok(());
            }
            crate::config::OutboundKind::Trojan => {
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式出站不支持 UDP",
                    ));
                }
                let mut stream = self.ctx.dial_proxy_transport(&proxy, true).await?;
                crate::outbound::trojan_udp_connect(&mut stream, &proxy).await?;
                let (mut read, write) = tokio::io::split(stream);
                let (tx, session, native, ctx) = self.reader_params();
                let mut tasks = JoinSet::new();
                let tracker = ctx.children.clone();
                let lease = self.lease.clone();
                let failure = self.failure_guard();
                let max = ctx.limits.max_udp_payload;
                tasks.spawn(tracker.track_future(async move {
                    let _lease = lease;
                    let _failure = failure;
                    loop {
                        let Ok((target, payload)) =
                            crate::protocol::trojan::read_datagram(&mut read, max).await
                        else {
                            break;
                        };
                        let Some(mut packet) = Packet::reserve(&ctx, target, payload) else {
                            ctx.stats.drop_packet();
                            continue;
                        };
                        packet.session = session;
                        packet.native = native;
                        if tx.try_send(packet).is_err() {
                            ctx.stats.drop_packet();
                        }
                    }
                }));
                self.relay = Some(Relay {
                    proxy,
                    uplink: Uplink::Trojan(write),
                    tasks,
                    last_used: Arc::new(std::sync::Mutex::new(Instant::now())),
                });
                return Ok(());
            }
            crate::config::OutboundKind::Anytls => {
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式出站不支持 UDP",
                    ));
                }
                // 与TCP共用同一出站池/方案；先取空闲会话，池空才经原工厂拨号。
                let mut stream = self
                    .ctx
                    .connect_selected(Some(&proxy), &shadowsocks_uot_target())
                    .await?;
                stream.write_all(&[0, 1, 0, 0, 0, 0, 0, 0]).await?;
                stream.flush().await?;
                let (mut read, write) = tokio::io::split(stream);
                let (tx, session, native, ctx) = self.reader_params();
                let mut tasks = JoinSet::new();
                let tracker = ctx.children.clone();
                let lease = self.lease.clone();
                let failure = self.failure_guard();
                tasks.spawn(tracker.track_future(async move {
                    let _lease = lease;
                    let _failure = failure;
                    let framing = Framing::Uot {
                        is_connect: false,
                        destination: shadowsocks_uot_target(),
                    };
                    loop {
                        let (target, payload) =
                            match framing.read(&mut read, ctx.limits.max_udp_payload).await {
                                Ok(Some(packet)) => packet,
                                Ok(None) | Err(_) => break,
                            };
                        let Some(mut packet) = Packet::reserve(&ctx, target, payload) else {
                            ctx.stats.drop_packet();
                            continue;
                        };
                        packet.session = session;
                        packet.native = native;
                        if tx.try_send(packet).is_err() {
                            ctx.stats.drop_packet();
                        }
                    }
                }));
                self.relay = Some(Relay {
                    proxy,
                    uplink: Uplink::AnytlsUot(write),
                    tasks,
                    last_used: Arc::new(std::sync::Mutex::new(Instant::now())),
                });
                return Ok(());
            }
            crate::config::OutboundKind::Hysteria2 => {
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式出站不支持 UDP",
                    ));
                }
                let prepared = proxy
                    .hysteria2
                    .clone()
                    .ok_or_else(|| io::Error::other("Hysteria2 出站未初始化"))?;
                let parts = prepared.open_udp(&self.ctx).await?;
                let keepalive = parts.keepalive();
                let crate::transport::hysteria2::UdpParts {
                    sender, receiver, ..
                } = parts;
                self.relay = Some(Relay {
                    proxy,
                    uplink: Uplink::Hysteria2 {
                        sender,
                        _keepalive: keepalive,
                    },
                    tasks: self.spawn_udp_reader(UdpReader::Hysteria2(receiver)),
                    last_used: Arc::new(std::sync::Mutex::new(Instant::now())),
                });
                return Ok(());
            }
            crate::config::OutboundKind::Tuic => {
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式出站不支持 UDP",
                    ));
                }
                let prepared = proxy
                    .tuic
                    .clone()
                    .ok_or_else(|| io::Error::other("TUIC 出站未初始化"))?;
                let parts = prepared.open_udp(&self.ctx, proxy.tuic_udp_mode).await?;
                let keepalive = parts.keepalive();
                let crate::transport::tuic_client::UdpParts {
                    sender, receiver, ..
                } = parts;
                self.relay = Some(Relay {
                    proxy,
                    uplink: Uplink::Tuic {
                        sender,
                        _keepalive: keepalive,
                    },
                    tasks: self.spawn_udp_reader(UdpReader::Tuic(receiver)),
                    last_used: Arc::new(std::sync::Mutex::new(Instant::now())),
                });
                return Ok(());
            }
            crate::config::OutboundKind::Wireguard
            | crate::config::OutboundKind::Nw3Vector
            | crate::config::OutboundKind::Snell
            | crate::config::OutboundKind::Naive => {
                if proxy.kind == crate::config::OutboundKind::Naive
                    && !proxy
                        .naive
                        .as_ref()
                        .is_some_and(|options| options.udp_over_tcp)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Naive出站UDP未启用UoT",
                    ));
                }
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式 UDP 出站未实现",
                    ));
                }
                Uplink::Datagrams(HashMap::new())
            }
            crate::config::OutboundKind::Vless => {
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式出站不支持 UDP",
                    ));
                }
                Uplink::Vless(HashMap::new())
            }
            crate::config::OutboundKind::Vmess => {
                if proxy.via.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "链式出站不支持 UDP",
                    ));
                }
                Uplink::Vmess(HashMap::new())
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "该上游出站不支持 UDP",
                ));
            }
        };
        self.relay = Some(Relay {
            proxy,
            uplink,
            tasks: JoinSet::new(),
            last_used: Arc::new(std::sync::Mutex::new(Instant::now())),
        });
        Ok(())
    }

    /// 为 IP 隧道/NW3 建立一个固定目标 UDP 会话。任务拥有会话和有界发送队列，
    /// 不共享可串目标的读游标；取消发送后结束该 Flow，不能继续使用部分帧。
    fn open_datagram_target<'a>(
        &'a mut self,
        target: &'a Target,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(self.open_datagram_target_impl(target))
    }

    async fn open_datagram_target_impl(&mut self, target: &Target) -> io::Result<()> {
        let proxy = self
            .relay
            .as_ref()
            .ok_or_else(|| io::Error::other("UDP 中继缺失"))?
            .proxy
            .clone();
        let count = match &self.relay.as_ref().expect("已检查").uplink {
            Uplink::Datagrams(targets) => targets.len(),
            _ => return Err(io::Error::other("不是逐目标 UDP 中继")),
        };
        if count >= self.ctx.limits.max_udp_targets {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP 目标会话上限",
            ));
        }
        let mut session: Box<dyn crate::transport::tunnel_udp::DatagramSession> = match proxy.kind {
            crate::config::OutboundKind::Naive => timeout(
                Duration::from_millis(self.ctx.limits.dial_timeout_ms),
                crate::transport::naive_client::open_udp(&self.ctx, &proxy, target),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive UoT握手超时"))??,
            crate::config::OutboundKind::Snell => {
                let options = proxy
                    .snell
                    .as_deref()
                    .ok_or_else(|| io::Error::other("Snell出站未初始化"))?;
                let flow = timeout(
                    Duration::from_millis(self.ctx.limits.dial_timeout_ms),
                    async {
                        let stream = self.ctx.dial_proxy_endpoint(&proxy).await?;
                        crate::protocol::snell::client::open_udp(stream, options, target).await
                    },
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Snell UDP握手超时"))??;
                Box::new(flow)
            }
            crate::config::OutboundKind::Wireguard => {
                proxy
                    .wireguard
                    .as_ref()
                    .ok_or_else(|| io::Error::other("WireGuard 出站未初始化"))?
                    .open_udp(&self.ctx, target)
                    .await?
            }
            crate::config::OutboundKind::Nw3Vector => {
                let client = proxy
                    .nw3
                    .as_ref()
                    .ok_or_else(|| io::Error::other("NW3 出站未初始化"))?;
                let host = match &target.host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Domain(name) => name.clone(),
                };
                let flow = client
                    .connect_udp(&host, target.port)
                    .await
                    .map_err(|error| io::Error::other(format!("NW3 UDP Flow 打开失败: {error}")))?;
                Box::new(flow)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "不支持的 UDP 中继",
                ));
            }
        };
        let (sender, mut requests) =
            mpsc::channel::<DatagramRequest>(self.ctx.limits.udp_queue_packets);
        let (tx, session_id, native, ctx) = self.reader_params();
        let origin = target.clone();
        let idle = Duration::from_millis(ctx.limits.udp_idle_timeout_ms);
        let write_timeout = Duration::from_millis(ctx.limits.dial_timeout_ms);
        let last_used = Arc::new(std::sync::Mutex::new(Instant::now()));
        let activity = last_used.clone();
        let tracker = ctx.children.clone();
        let lease = self.lease.clone();
        let failure = self.failure_guard();
        let fixed = self.fixed.is_some();
        let relay = self.relay.as_mut().expect("会话建立中中继仍存在");
        while relay.tasks.try_join_next().is_some() {}
        let task = relay.tasks.spawn(tracker.track_future(async move {
            let _lease = lease;
            let _failure = failure;
            let mut deadline = Instant::now() + idle;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline), if !fixed => break,
                    request = requests.recv() => {
                        let Some(mut request) = request else { break };
                        if request.completion.is_closed() { continue; }
                        let result = tokio::select! {
                            biased;
                            _ = request.completion.closed() => break,
                            result = timeout(write_timeout, session.send(&request.payload)) =>
                                result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "隧道 UDP 发送超时"))),
                        };
                        let fatal = result.as_ref().is_err_and(|error| !matches!(error.kind(),
                            io::ErrorKind::InvalidInput | io::ErrorKind::WouldBlock));
                        if result.is_ok() {
                            deadline = Instant::now() + idle;
                            *activity.lock().unwrap_or_else(|error| error.into_inner()) = Instant::now();
                        }
                        let _ = request.completion.send(result);
                        if fatal { break; }
                    }
                    response = session.recv() => {
                        let payload = match response { Ok(payload) => payload, Err(_) => break };
                        if payload.len() > ctx.limits.max_udp_payload { ctx.stats.drop_packet(); continue; }
                        let Some(mut packet) = Packet::reserve(&ctx, origin.clone(), payload) else {
                            ctx.stats.drop_packet(); continue;
                        };
                        packet.session = session_id;
                        packet.native = native;
                        if tx.try_send(packet).is_err() { ctx.stats.drop_packet(); }
                        deadline = Instant::now() + idle;
                        *activity.lock().unwrap_or_else(|error| error.into_inner()) = Instant::now();
                    }
                }
            }
            let _ = timeout(Duration::from_millis(500), session.close()).await;
        }));
        if let Uplink::Datagrams(targets) = &mut relay.uplink {
            targets.insert(
                target.clone(),
                TargetDatagram {
                    sender,
                    task,
                    last_used,
                },
            );
        }
        Ok(())
    }

    /// 启动 QUIC UDP 回包循环；接收端与连接保活随任务存活。
    fn spawn_udp_reader(&self, mut receiver: UdpReader) -> JoinSet<()> {
        let (tx, session, native, ctx) = self.reader_params();
        let mut tasks = JoinSet::new();
        let tracker = ctx.children.clone();
        let lease = self.lease.clone();
        let failure = self.failure_guard();
        tasks.spawn(tracker.track_future(async move {
            let _lease = lease;
            let _failure = failure;
            loop {
                let (target, payload) = match receiver.recv().await {
                    Ok(packet) => packet,
                    Err(_) => break,
                };
                if payload.len() > ctx.limits.max_udp_payload {
                    ctx.stats.drop_packet();
                    continue;
                }
                let Some(mut packet) = Packet::reserve(&ctx, target, payload) else {
                    ctx.stats.drop_packet();
                    continue;
                };
                packet.session = session;
                packet.native = native;
                if tx.try_send(packet).is_err() {
                    ctx.stats.drop_packet();
                }
            }
        }));
        tasks
    }

    fn reader_params(&self) -> ReaderParams {
        (self.tx.clone(), self.session, self.native, self.ctx.clone())
    }

    /// 为 VLESS UDP 建立某个目标专用的隧道并启动读取任务。
    async fn open_vless_tunnel(&mut self, target: &Target) -> io::Result<()> {
        let Some(relay) = self.relay.as_ref() else {
            return Err(io::Error::other("UDP 中继未建立"));
        };
        if relay.proxy.via.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "链式出站不支持 UDP",
            ));
        }
        let proxy = relay.proxy.clone();
        let mut stream = self.ctx.dial_proxy_transport(&proxy, true).await?;
        stream = crate::outbound::wrap_vless_encryption(stream, &proxy).await?;
        if let Err(error) = crate::outbound::vless_udp_connect(&mut stream, &proxy, target).await {
            if let Some(encryption) = &proxy.encryption {
                encryption.invalidate();
            }
            return Err(error);
        }
        let (mut read, write) = tokio::io::split(stream);
        let expected = target.clone();
        let (tx, session, native, ctx) = self.reader_params();
        let tracker = ctx.children.clone();
        let lease = self.lease.clone();
        let failure = self.failure_guard();
        let relay = self
            .relay
            .as_mut()
            .ok_or_else(|| io::Error::other("UDP 中继未建立"))?;
        relay.tasks.spawn(tracker.track_future(async move {
            let _lease = lease;
            let _failure = failure;
            loop {
                let mut length = [0u8; 2];
                if read.read_exact(&mut length).await.is_err() {
                    break;
                }
                let length = usize::from(u16::from_be_bytes(length));
                if length > ctx.limits.max_udp_payload {
                    ctx.stats.drop_packet();
                    break;
                }
                let mut payload = vec![0u8; length];
                if read.read_exact(&mut payload).await.is_err() {
                    break;
                }
                let Some(mut packet) = Packet::reserve(&ctx, expected.clone(), payload) else {
                    ctx.stats.drop_packet();
                    continue;
                };
                packet.session = session;
                packet.native = native;
                if tx.try_send(packet).is_err() {
                    ctx.stats.drop_packet();
                }
            }
        }));
        if let Uplink::Vless(tunnels) = &mut relay.uplink {
            tunnels.insert(target.clone(), write);
        }
        *relay
            .last_used
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
        Ok(())
    }

    /// 为 VMess UDP 建立某个目标专用的命令 2 隧道并启动读取任务。
    async fn open_vmess_tunnel(&mut self, target: &Target) -> io::Result<()> {
        let Some(relay) = self.relay.as_ref() else {
            return Err(io::Error::other("UDP 中继未建立"));
        };
        if relay.proxy.via.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "链式出站不支持 UDP",
            ));
        }
        let proxy = relay.proxy.clone();
        let uuid = proxy
            .uuid
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "VMess 出站缺少 uuid"))?;
        let mut stream = self.ctx.dial_proxy_transport(&proxy, true).await?;
        let state = vmess_wire::client::handshake(
            &mut stream,
            &uuid,
            target,
            proxy.security.unwrap_or(3),
            2,
        )
        .await?;
        let (mut read, write) = vmess_wire::body::split_client(
            stream,
            state.security,
            state.options,
            state.key,
            state.iv,
        )?;
        let expected = target.clone();
        let (tx, session, native, ctx) = self.reader_params();
        let tracker = ctx.children.clone();
        let lease = self.lease.clone();
        let failure = self.failure_guard();
        let relay = self
            .relay
            .as_mut()
            .ok_or_else(|| io::Error::other("UDP 中继未建立"))?;
        relay.tasks.spawn(tracker.track_future(async move {
            let _lease = lease;
            let _failure = failure;
            loop {
                let payload = match read.packet().await {
                    Ok(Some(payload)) => payload,
                    Ok(None) => break,
                    Err(_) => break,
                };
                if payload.len() > ctx.limits.max_udp_payload {
                    ctx.stats.drop_packet();
                    continue;
                }
                let Some(mut packet) = Packet::reserve(&ctx, expected.clone(), payload) else {
                    ctx.stats.drop_packet();
                    continue;
                };
                packet.session = session;
                packet.native = native;
                if tx.try_send(packet).is_err() {
                    ctx.stats.drop_packet();
                }
            }
        }));
        if let Uplink::Vmess(tunnels) = &mut relay.uplink {
            tunnels.insert(target.clone(), write);
        }
        *relay
            .last_used
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
        Ok(())
    }

    async fn close(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        // relay 任务（读取/逐目标worker/控制观察）不属于 tasks；关闭必须
        // 等待这些任务真实析构后再归还上层额度与socket。
        if let Some(mut relay) = self.relay.take() {
            relay.tasks.abort_all();
            while relay.tasks.join_next().await.is_some() {}
        }
        self.mappings.clear();
        self.reverse = None;
    }
}

pub async fn socks(
    mut control: TcpStream,
    target: Target,
    ctx: Arc<Context>,
    inbound: String,
    user: Option<&str>,
) -> io::Result<()> {
    let traffic = user.map(|user| ctx.stats.user_counter(&inbound, user));
    let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let prepared = async {
        let slot = ctx
            .udp_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "UDP 关联上限"))?;
        let peer = control.peer_addr()?;
        match &target.host {
            Host::Ip(ip) if ip.is_unspecified() || *ip == peer.ip() => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "UDP 客户端地址不匹配",
                ));
            }
        }
        let socket = UdpSocket::bind(SocketAddr::new(control.local_addr()?.ip(), 0)).await?;
        // 回程也需容纳配置允许的大包；只调整当前持有的 socket，不改系统参数。
        shadowsocks::prepare_buffers(&socket)?;
        Ok::<_, io::Error>((slot, peer.ip(), socket))
    }
    .await;
    let (_slot, requested_ip, socket) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let code = if error.kind() == io::ErrorKind::PermissionDenied {
                2
            } else {
                1
            };
            let _ = timeout(
                deadline,
                socks5::reply(&mut control, code, "0.0.0.0:0".parse().expect("固定地址")),
            )
            .await;
            return Err(error);
        }
    };
    let _gauge = ctx.stats.enter(Gauge::Udp);
    timeout(
        deadline,
        socks5::reply(&mut control, 0, socket.local_addr()?),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP 应答超时"))??;
    let mut expected = (target.port != 0).then_some(SocketAddr::new(requested_ip, target.port));
    let (mut assoc, mut replies) = Association::new(ctx.clone(), inbound);
    assoc.traffic = traffic.clone();
    let idle = Duration::from_millis(ctx.limits.udp_idle_timeout_ms);
    let mut deadline = Instant::now() + idle;
    let mut buffer = vec![0; 65536];
    let mut control_buffer = [0; 1];
    let result = async {
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                _ = control.read(&mut control_buffer) => break,
                received = socket.recv_from(&mut buffer) => {
                    let (n, source) = received?;
                    if source.ip() != requested_ip || expected.is_some_and(|p| p != source) {
                        ctx.stats.drop_packet(); continue;
                    }
                    let (target, payload) = match socks5::decode_datagram(&buffer[..n]) {
                        Ok(packet) => packet, Err(_) => { ctx.stats.drop_packet(); continue; }
                    };
                    expected = Some(source);
                    let Some(packet) = Packet::reserve(&ctx, target, payload) else { ctx.stats.drop_packet(); continue; };
                    if timeout(Duration::from_millis(ctx.limits.dial_timeout_ms), assoc.send(packet.target, &packet.payload)).await.is_ok_and(|r| r.is_ok()) {
                        deadline = Instant::now() + idle;
                    } else { ctx.stats.drop_packet(); }
                }
                Some(packet) = replies.recv() => {
                    if let Some(peer) = expected {
                        let encoded = socks5::encode_datagram(&packet.target, &packet.payload)?;
                        timeout(idle, socket.send_to(&encoded, peer)).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP 写入超时"))??;
                        ctx.stats.downlink.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
                        if let Some(traffic) = &traffic {
                            traffic.add(false, packet.payload.len());
                        }
                        deadline = Instant::now() + idle;
                    }
                }
            }
        }
        Ok(())
    }.await;
    assoc.close().await;
    result
}

pub async fn trojan<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
    user: Option<&str>,
) -> io::Result<()> {
    trojan_scoped(stream, ctx, inbound, None, user).await
}

/// gRPC等按RPC回收的上层使用；`lease`由reader/mapping共享到任务结束。
pub(crate) async fn trojan_scoped<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    ctx: Arc<Context>,
    inbound: String,
    lease: Option<Lease>,
    user: Option<&str>,
) -> io::Result<()> {
    framed(stream, ctx, inbound, Framing::Trojan, lease, user).await
}

pub async fn vless<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    target: Target,
    ctx: Arc<Context>,
    inbound: String,
    user: Option<&str>,
) -> io::Result<()> {
    vless_scoped(stream, target, ctx, inbound, None, user).await
}

pub(crate) async fn vless_scoped<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    target: Target,
    ctx: Arc<Context>,
    inbound: String,
    lease: Option<Lease>,
    user: Option<&str>,
) -> io::Result<()> {
    // 固定目标 UDP 也走共享关联，因此与 `Association::send` 使用同一套
    // 选路规则：SOCKS5 上游可用，HTTP 上游仍失败关闭。
    ctx.udp_selected(&inbound, &target).await?;
    framed(stream, ctx, inbound, Framing::Vless(target), lease, user).await
}

/// UoT（UDP over TCP）：sing-box 在 VLESS/VMess 内的 UDP 承载。
pub(crate) const UOT_V2_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_LEGACY_MAGIC: &str = "sp.udp-over-tcp.arpa";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UotVersion {
    V2,
    Legacy,
}

/// 识别 VLESS/VMess 目标是否为 UoT 魔数地址（与 sing-box 一致，精确匹配）。
pub(crate) fn is_uot_domain(name: &str) -> bool {
    name == UOT_V2_MAGIC || name == UOT_LEGACY_MAGIC
}

pub(crate) fn uot_version(target: &Target) -> Option<UotVersion> {
    let Host::Domain(name) = &target.host else {
        return None;
    };
    if name == UOT_V2_MAGIC {
        Some(UotVersion::V2)
    } else if name == UOT_LEGACY_MAGIC {
        Some(UotVersion::Legacy)
    } else {
        None
    }
}

/// 在已认证的 VLESS/VMess 字节流上承载 UoT；调用方负责先发送协议应答。
pub(crate) async fn uot<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    ctx: Arc<Context>,
    inbound: String,
    version: UotVersion,
    user: Option<&str>,
) -> io::Result<()> {
    let framing = match version {
        UotVersion::V2 => {
            let request = timeout(
                Duration::from_millis(ctx.limits.handshake_timeout_ms),
                read_uot_request(&mut stream),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UoT 请求超时"))??;
            framing_uot(request)
        }
        UotVersion::Legacy => framing_uot(UotRequest {
            is_connect: false,
            destination: Target {
                host: Host::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                port: 0,
            },
        }),
    };
    framed(stream, ctx, inbound, framing, None, user).await
}

struct UotRequest {
    is_connect: bool,
    destination: Target,
}

fn framing_uot(request: UotRequest) -> Framing {
    Framing::Uot {
        is_connect: request.is_connect,
        destination: request.destination,
    }
}

/// 版本 2 的初始请求：1 字节 isConnect + SOCKS5 地址。
/// sing-box 以 Go `binary.Read` 读取 bool，仅接受 0/1；其他值不是合法请求。
async fn read_uot_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<UotRequest> {
    let is_connect = match reader.read_u8().await? {
        0 => false,
        1 => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UoT isConnect 无效",
            ));
        }
    };
    let destination = read_socks_target(reader).await?;
    Ok(UotRequest {
        is_connect,
        destination,
    })
}

async fn read_socks_target<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Target> {
    let host = match reader.read_u8().await? {
        1 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            Host::Ip(Ipv4Addr::from(octets).into())
        }
        4 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            Host::Ip(Ipv6Addr::from(octets).into())
        }
        3 => {
            let length = usize::from(reader.read_u8().await?);
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UoT 目标域名无效",
                ));
            }
            let mut bytes = [0u8; 255];
            let domain = &mut bytes[..length];
            reader.read_exact(domain).await?;
            if !domain.iter().all(u8::is_ascii_graphic) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UoT 目标域名无效",
                ));
            }
            let domain = std::str::from_utf8(domain)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "UoT 目标域名无效"))?;
            Host::Domain(domain.to_ascii_lowercase())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UoT 目标地址类型无效",
            ));
        }
    };
    let port = reader.read_u16().await?;
    // 与 sing-box/SOCKS 地址语义一致：端口 0 是合法占位值。非 connect 模式的
    // 初始目标仅用于元数据，实际逐包目标在后续帧中给出。
    Ok(Target { host, port })
}

/// 逐包地址使用 UoT 自己的类型码：0x00 IPv4、0x01 IPv6、0x02 域名。
async fn read_uot_address<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Target> {
    let host = match reader.read_u8().await? {
        0x00 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            Host::Ip(Ipv4Addr::from(octets).into())
        }
        0x01 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            Host::Ip(Ipv6Addr::from(octets).into())
        }
        0x02 => {
            let length = usize::from(reader.read_u8().await?);
            if length == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "UoT 域名无效"));
            }
            let mut bytes = [0u8; 255];
            let domain = &mut bytes[..length];
            reader.read_exact(domain).await?;
            if !domain.iter().all(u8::is_ascii_graphic) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "UoT 域名无效"));
            }
            let domain = std::str::from_utf8(domain)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "UoT 域名无效"))?;
            Host::Domain(domain.to_ascii_lowercase())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UoT 地址类型无效",
            ));
        }
    };
    let port = reader.read_u16().await?;
    Ok(Target { host, port })
}

fn encode_uot_address(target: &Target) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(3 + 255 + 2);
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            out.push(0x00);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(name) => {
            // 与读取侧及既有 VLESS/Trojan 地址规则一致：非空、至多 255 字节的 ASCII。
            if name.is_empty()
                || name.len() > 255
                || !name.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "UoT 域名无效"));
            }
            out.push(0x02);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

#[derive(Clone)]
enum Framing {
    Trojan,
    Vless(Target),
    Uot {
        is_connect: bool,
        destination: Target,
    },
}
impl Framing {
    async fn read<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        max: usize,
    ) -> io::Result<Option<(Target, Vec<u8>)>> {
        // 只将帧边界干净EOF映射会话结束；原始WS截断已由承载返回错误。
        // 首字节仅回放给原codec一次，半地址/长度/载荷仍由原codec拒绝。
        let mut first = [0];
        if reader.read(&mut first).await? == 0 {
            return Ok(None);
        }
        let mut prefixed = first.as_slice().chain(reader);
        match self {
            Self::Trojan => trojan::read_datagram(&mut prefixed, max).await.map(Some),
            Self::Vless(target) => Ok(Some((
                target.clone(),
                vless::read_datagram(&mut prefixed, max).await?,
            ))),
            Self::Uot {
                is_connect,
                destination,
            } => {
                let (target, length) = if *is_connect {
                    (destination.clone(), usize::from(prefixed.read_u16().await?))
                } else {
                    let target = read_uot_address(&mut prefixed).await?;
                    (target, usize::from(prefixed.read_u16().await?))
                };
                if length > max {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "UoT 载荷过长"));
                }
                let mut payload = vec![0u8; length];
                prefixed.read_exact(&mut payload).await?;
                Ok(Some((target, payload)))
            }
        }
    }

    fn encode(&self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Trojan => trojan::encode_datagram(target, payload),
            Self::Vless(_) => vless::encode_datagram(payload),
            Self::Uot { is_connect, .. } => {
                if payload.len() > u16::MAX as usize {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "UoT 载荷过长"));
                }
                let mut out = if *is_connect {
                    Vec::with_capacity(2 + payload.len())
                } else {
                    encode_uot_address(target)?
                };
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
                Ok(out)
            }
        }
    }

    fn discards_empty(&self) -> bool {
        matches!(self, Self::Vless(_))
    }
}

async fn framed<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    ctx: Arc<Context>,
    inbound: String,
    framing: Framing,
    lease: Option<Lease>,
    user: Option<&str>,
) -> io::Result<()> {
    let traffic = user.map(|user| ctx.stats.user_counter(&inbound, user));
    let _slot = ctx
        .udp_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "UDP 关联上限"))?;
    let _gauge = ctx.stats.enter(Gauge::Udp);
    if matches!(&framing, Framing::Vless(_)) {
        timeout(
            Duration::from_millis(ctx.limits.handshake_timeout_ms),
            vless::reply(&mut stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP 应答超时"))??;
    }
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel(ctx.limits.udp_queue_packets);
    let mut reader_tasks = JoinSet::new();
    let reader_ctx = ctx.clone();
    let reader_framing = framing.clone();
    let reader_lease = lease.clone();
    // 帧读取在独立任务中完成；select 取消其它分支时不丢失已消费的半帧。
    reader_tasks.spawn(ctx.children.track_future(async move {
        let _lease = reader_lease;
        loop {
            match reader_framing
                .read(&mut reader, reader_ctx.limits.max_udp_payload)
                .await
            {
                Ok(None) => break,
                Ok(Some((target, payload))) => {
                    if payload.is_empty() && reader_framing.discards_empty() {
                        reader_ctx.stats.drop_packet();
                        // 连续空帧不应占满一个执行线程；空帧也不延长空闲期限。
                        tokio::task::yield_now().await;
                        continue;
                    }
                    let Some(packet) = Packet::reserve(&reader_ctx, target, payload) else {
                        reader_ctx.stats.drop_packet();
                        continue;
                    };
                    if let Err(error) = tx.try_send(Ok(packet)) {
                        if matches!(error, mpsc::error::TrySendError::Closed(_)) {
                            break;
                        }
                        reader_ctx.stats.drop_packet();
                    }
                }
                Err(error) => {
                    let _ = tx.send(Err(error)).await;
                    break;
                }
            }
        }
    }));
    let (mut assoc, mut replies) = Association::with_lease(ctx.clone(), inbound, lease);
    assoc.traffic = traffic.clone();
    let idle = Duration::from_millis(ctx.limits.udp_idle_timeout_ms);
    let mut deadline = Instant::now() + idle;
    let result = async {
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                item = rx.recv() => {
                    let Some(item) = item else { break; };
                    let packet = item?;
                    if timeout(Duration::from_millis(ctx.limits.dial_timeout_ms), assoc.send(packet.target, &packet.payload)).await.is_ok_and(|r| r.is_ok()) {
                        deadline = Instant::now() + idle;
                    } else { ctx.stats.drop_packet(); }
                }
                Some(packet) = replies.recv() => {
                    if packet.payload.is_empty() && framing.discards_empty() {
                        ctx.stats.drop_packet();
                        continue;
                    }
                    let frame = framing.encode(&packet.target, &packet.payload)?;
                    timeout(idle, async {
                        writer.write_all(&frame).await?;
                        writer.flush().await
                    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP 写入超时"))??;
                    ctx.stats.downlink.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
                    if let Some(traffic) = &traffic {
                        traffic.add(false, packet.payload.len());
                    }
                    deadline = Instant::now() + idle;
                }
            }
        }
        Ok(())
    }.await;
    reader_tasks.abort_all();
    while reader_tasks.join_next().await.is_some() {}
    assoc.close().await;
    result
}

pub fn wildcard(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(
        if ip.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    fn context(bytes: usize, packets: usize) -> Arc<Context> {
        let value = serde_json::json!({"version":1,"inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"udp_queue_bytes":bytes,"udp_queue_packets":packets}});
        Arc::new(Context::new(&Config::from_json(&value.to_string()).unwrap()).unwrap())
    }
    /// 二级队列必须随包持有字节额度：包数上限乘最大载荷可以远超
    /// `udp_queue_bytes`，否则一条关联就能囤积几十 MiB。
    #[tokio::test]
    async fn secondary_queue_payloads_hold_byte_budget_until_sent() {
        let ctx = context(8, 64);
        let (tx, mut rx) = mpsc::channel::<QueuedUplink>(64);
        let first = QueuedUplink::reserve(&ctx, vec![1; 4]).unwrap();
        assert_eq!(ctx.udp_bytes.available_permits(), 4);
        tx.try_send(first).unwrap();
        assert_eq!(ctx.udp_bytes.available_permits(), 4, "排队期间额度不得归还");
        // 剩余额度不足 8 字节：更大的包必须被拒绝，而不是无限堆积。
        assert!(QueuedUplink::reserve(&ctx, vec![2; 8]).is_none());
        assert!(QueuedUplink::reserve(&ctx, vec![2; 5]).is_none());
        drop(rx.recv().await.unwrap());
        assert_eq!(
            ctx.udp_bytes.available_permits(),
            8,
            "出队并释放后才归还额度"
        );
    }
    #[tokio::test]
    async fn byte_budget_empty_packets_and_full_queue_release_permits() {
        let ctx = context(4, 1);
        let target = Target::from("127.0.0.1:9".parse::<SocketAddr>().unwrap());
        let held = Packet::reserve(&ctx, target.clone(), vec![1; 4]).unwrap();
        assert_eq!(ctx.udp_bytes.available_permits(), 0);
        assert!(Packet::reserve(&ctx, target.clone(), vec![]).is_none());
        drop(held);
        assert_eq!(ctx.udp_bytes.available_permits(), 4);
        let empty = Packet::reserve(&ctx, target.clone(), vec![]).unwrap();
        assert_eq!(ctx.udp_bytes.available_permits(), 3);
        drop(empty);
        let (mut assoc, mut replies) = Association::new(ctx.clone(), "socks".into());
        assert!(
            assoc
                .tx
                .try_send(Packet::reserve(&ctx, target.clone(), vec![1]).unwrap())
                .is_ok()
        );
        assert!(
            assoc
                .tx
                .try_send(Packet::reserve(&ctx, target, vec![2]).unwrap())
                .is_err()
        );
        assert_eq!(ctx.udp_bytes.available_permits(), 3);
        drop(replies.recv().await.unwrap());
        assert_eq!(ctx.udp_bytes.available_permits(), 4);
        assoc.close().await;
    }
    #[tokio::test(start_paused = true)]
    async fn downstream_activity_preserves_mapping_and_cancel_waits_for_socket_drop() {
        let ctx = context(128, 4);
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (mut assoc, mut replies) = Association::new(ctx.clone(), "socks".into());
        assoc.send(address.into(), b"start").await.unwrap();
        let mut b = [0; 32];
        let (_, peer) = target.recv_from(&mut b).await.unwrap();
        tokio::time::advance(Duration::from_secs(50)).await;
        target.send_to(b"push", peer).await.unwrap();
        let packet = replies.recv().await.unwrap();
        assert_eq!(packet.payload, b"push");
        drop(packet);
        tokio::time::advance(Duration::from_secs(20)).await;
        assoc.expire();
        assert_eq!(assoc.mappings.len(), 1);
        // 模拟父 future 被取消，析构请求 abort；追踪器必须等待真实析构。
        drop(assoc);
        ctx.children.close();
        ctx.children.wait().await;
        assert_eq!(ctx.udp_bytes.available_permits(), 128);
        let _rebound = UdpSocket::bind(peer).await.unwrap();
    }
    #[tokio::test]
    async fn prepared_fixes_target_without_probing_and_releases_owner_resources() {
        let value = serde_json::json!({"version":1,
            "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"default":"direct"},
            "limits":{"udp_queue_bytes":64,"udp_queue_packets":4,"max_udp_associations":1}
        });
        let ctx = Arc::new(Context::new(&Config::from_json(&value.to_string()).unwrap()).unwrap());
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let mut prepared = RoutedUdp::prepared(ctx.clone(), "socks".into(), Target::from(address))
            .await
            .unwrap();
        assert_eq!(
            ctx.stats.snapshot().udp_associations,
            1,
            "准备完成即占关联额度"
        );
        assert_eq!(ctx.stats.snapshot().uplink, 0);
        assert_eq!(ctx.stats.snapshot().downlink, 0);
        let mut buffer = [0; 32];
        assert!(
            timeout(Duration::from_millis(100), target.recv_from(&mut buffer))
                .await
                .is_err(),
            "准备阶段不得发送业务包或空包"
        );
        // 同一关联额度被占用时，第二个固定请求必须在准备阶段失败。
        let blocked = RoutedUdp::prepared(ctx.clone(), "socks".into(), Target::from(address)).await;
        assert_eq!(
            blocked.err().expect("第二个关联必须失败").kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(ctx.stats.snapshot().udp_associations, 1);
        prepared.send(b"hello").await.unwrap();
        let (length, peer) = timeout(Duration::from_secs(1), target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"hello");
        target.send_to(b"reply", peer).await.unwrap();
        assert_eq!(prepared.recv().await.unwrap().payload, b"reply");
        prepared.send(b"").await.unwrap();
        let (length, _) = timeout(Duration::from_secs(1), target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(length, 0, "空 UDP 数据报保持独立边界");
        assert_eq!(ctx.stats.snapshot().uplink, b"hello".len() as u64);
        // 资源失效通知必须让挂起读和后续发送失败，不重建映射。
        let failed = prepared
            .association
            .fixed
            .as_ref()
            .expect("固定请求")
            .failed
            .clone();
        failed.cancel();
        assert_eq!(
            prepared
                .recv()
                .await
                .err()
                .expect("资源失效后不能继续读")
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            prepared.send(b"after-failure").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(ctx.stats.snapshot().uplink, b"hello".len() as u64);
        drop(prepared);
        ctx.children.close();
        ctx.children.wait().await;
        assert_eq!(ctx.stats.snapshot().udp_associations, 0);
        assert_eq!(ctx.udp_slots.available_permits(), 1);
        assert_eq!(ctx.udp_bytes.available_permits(), 64);
        let _rebound = UdpSocket::bind(peer).await.unwrap();
    }

    #[tokio::test]
    async fn prepared_rejection_uses_route_error_before_any_socket() {
        let value = serde_json::json!({"version":1,
            "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
            "outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],
            "route":{"default":"reject"}
        });
        let ctx = Arc::new(Context::new(&Config::from_json(&value.to_string()).unwrap()).unwrap());
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let error = RoutedUdp::prepared(
            ctx.clone(),
            "socks".into(),
            Target::from(target.local_addr().unwrap()),
        )
        .await
        .err()
        .expect("reject 路由必须在准备阶段失败");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(ctx.stats.snapshot().udp_associations, 0);
        assert_eq!(ctx.stats.snapshot().uplink, 0);
        assert_eq!(
            ctx.udp_slots.available_permits(),
            ctx.limits.max_udp_associations
        );
    }

    #[tokio::test]
    async fn slow_consumer_queue_is_bounded_and_close_joins_tasks() {
        let ctx = context(16, 1);
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (mut assoc, replies) = Association::new(ctx.clone(), "socks".into());
        assoc.send(address.into(), b"start").await.unwrap();
        let mut b = [0; 32];
        let (_, peer) = target.recv_from(&mut b).await.unwrap();
        for _ in 0..8 {
            target.send_to(b"12345678", peer).await.unwrap();
        }
        timeout(Duration::from_secs(1), async {
            while ctx.stats.snapshot().dropped < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(replies.len(), 1);
        assert!(ctx.udp_bytes.available_permits() >= 8);
        assoc.close().await;
        assert!(assoc.tasks.is_empty());
        drop(assoc);
        // 回程队列现在由调用者持有，释放队列后归还尚未消费报文的预算。
        drop(replies);
        assert_eq!(ctx.udp_bytes.available_permits(), 16);
        // 任务已回收后，原目标映射端口立即可重新绑定。
        let _rebound = UdpSocket::bind(peer).await.unwrap();
    }

    fn proxy_context(address: SocketAddr, kind: &str) -> Arc<Context> {
        let value = serde_json::json!({
            "version": 1,
            "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
            "outbounds": [
                {"type": kind, "tag": "up", "endpoint": address.to_string()},
                {"type": "direct", "tag": "direct"}
            ],
            "route": {"default": "direct", "rules": [{"outbound": "up"}]}
        });
        Arc::new(Context::new(&Config::from_json(&value.to_string()).unwrap()).unwrap())
    }

    #[tokio::test]
    async fn snell_worker_budget_queue_and_drop_are_bounded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stopped, finished) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0; 7];
            stream.read_exact(&mut header).await.unwrap();
            let mut request = vec![0; usize::from(u16::from_be_bytes([header[5], header[6]]))];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [1, 6, 0]);
            stream.write_all(&[4, 0, 0, 0, 0, 0, 1, 0]).await.unwrap();
            let mut header = [0; 7];
            stream.read_exact(&mut header).await.unwrap();
            let mut frame = vec![0; usize::from(u16::from_be_bytes([header[5], header[6]]))];
            stream.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame[..9], &[1, 0, 4, 127, 0, 0, 1, 0, 9]);
            assert_eq!(&frame[9..], b"ok");
            // 重复推送由容量1队列与4字节预算约束；保留未消费报文到析构。
            let reply = [4, 0, 0, 0, 0, 0, 9, 4, 127, 0, 0, 1, 0, 9, b'o', b'k'];
            for _ in 0..4 {
                stream.write_all(&reply).await.unwrap();
            }
            let mut bytes = [0; 64];
            loop {
                match stream.read(&mut bytes).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = stopped.send(());
        });
        let config = Config::from_json(
            &serde_json::json!({"version":1,
                "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
                "outbounds":[{"type":"snell","tag":"up","endpoint":address.to_string(),
                    "snell":{"psk":"valid-snell-test-psk","version":6,"mode":"unsafe-raw"}}],
                "route":{"default":"up"},"limits":{"udp_queue_bytes":4,"udp_queue_packets":1}
            })
            .to_string(),
        )
        .unwrap();
        let ctx = Arc::new(Context::new(&config).unwrap());
        let (mut assoc, mut replies) = Association::new(ctx.clone(), "socks".into());
        let target: Target = "127.0.0.1:9".parse::<SocketAddr>().unwrap().into();
        // 调用方已占3字节，worker额外副本必须失败，不能留下无预算排队载荷。
        let held = Packet::reserve(&ctx, target.clone(), vec![0; 3]).unwrap();
        assert_eq!(
            assoc.send(target.clone(), b"no").await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(ctx.stats.snapshot().uplink, 0);
        drop(held);
        assoc.send(target, b"ok").await.unwrap();
        timeout(Duration::from_secs(2), async {
            while ctx.stats.snapshot().dropped == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(replies.len(), 1);
        // 确认worker已处理最后一帧再核额度，避免与暂时持有预算的入队尝试竞态。
        timeout(Duration::from_secs(2), async {
            while ctx.stats.snapshot().dropped < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(ctx.udp_bytes.available_permits(), 2);
        assert_eq!(replies.recv().await.unwrap().payload, b"ok");
        assert_eq!(ctx.udp_bytes.available_permits(), 4);
        drop(assoc);
        ctx.children.close();
        timeout(Duration::from_secs(2), ctx.children.wait())
            .await
            .unwrap();
        drop(replies);
        assert_eq!(ctx.udp_bytes.available_permits(), 4);
        timeout(Duration::from_secs(2), finished)
            .await
            .unwrap()
            .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_udp_relay_uses_control_associate_and_header_source() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_address = listener.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = udp.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0u8; 10];
            control.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            let mut reply = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
            reply.extend_from_slice(&relay_address.port().to_be_bytes());
            control.write_all(&reply).await.unwrap();

            let mut buffer = vec![0u8; 2048];
            let (n, peer) = udp.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..4], &[0x00, 0x00, 0x00, 0x03]);
            let length = buffer[4] as usize;
            assert_eq!(&buffer[5..5 + length], b"example.test");
            let port = u16::from_be_bytes([buffer[5 + length], buffer[6 + length]]);
            assert_eq!(port, 53);
            assert_eq!(&buffer[7 + length..n], b"ping");

            let mut reply = vec![0x00, 0x00, 0x00, 0x01, 192, 0, 2, 9];
            reply.extend_from_slice(&9999u16.to_be_bytes());
            reply.extend_from_slice(b"pong");
            udp.send_to(&reply, peer).await.unwrap();

            // 控制连接必须保持到关联结束；客户端回收后这里读到 EOF。
            let mut end = [0u8; 1];
            assert_eq!(control.read(&mut end).await.unwrap(), 0);
        });

        let ctx = proxy_context(control_address, "socks5");
        let (mut assoc, mut replies) = Association::new(ctx, "socks".into());
        assoc
            .send(
                Target {
                    host: Host::Domain("example.test".into()),
                    port: 53,
                },
                b"ping",
            )
            .await
            .unwrap();
        let packet = timeout(Duration::from_secs(5), replies.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.payload, b"pong");
        assert_eq!(
            packet.target,
            Target {
                host: Host::Ip("192.0.2.9".parse().unwrap()),
                port: 9999,
            }
        );
        assoc.close().await;
        drop(assoc);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_proxy_udp_route_fails_closed() {
        let ctx = proxy_context("127.0.0.1:1".parse().unwrap(), "http");
        let (mut assoc, _replies) = Association::new(ctx, "socks".into());
        let error = assoc
            .send(
                Target::from("192.0.2.1:53".parse::<SocketAddr>().unwrap()),
                b"x",
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn generic_udp_paths_reject_proxy_without_direct_fallback() {
        let ctx = proxy_context("127.0.0.1:1080".parse().unwrap(), "socks5");
        let target = Target::from("192.0.2.1:53".parse::<SocketAddr>().unwrap());
        // Mux、Shadowsocks 2022 等路径只用 `allowed` 预检；必须失败关闭。
        let error = ctx
            .allowed("socks", crate::session::Network::Udp, &target)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            ctx.allowed("socks", crate::session::Network::Tcp, &target)
                .await
                .is_ok()
        );
    }
}
