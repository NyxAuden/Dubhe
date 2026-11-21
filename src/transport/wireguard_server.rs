//! WireGuard **服务端**核心（用户态，无 TUN）。
//!
//! 设计目标与边界：
//!
//! * Noise_IK 握手完全交给 `boringtun`（作为 responder），本模块只做：
//!   - 用 `parse_handshake_anon` 从 init 中识别 peer 静态公钥；
//!   - 会话索引分片：每个 peer 的 `Tunn` 使用固定的 24 位 slot，数据包按
//!     `receiver_index >> 8` 直接路由到对应 peer 的 `Tunn`；
//!   - 由 `boringtun` 完成密钥轮换、TAI64N 重放检查和数据计数器校验。
//! * 隧道内 IPv4/IPv6 的 TCP/UDP 不经过内核 TUN，而是：
//!   - 把目的地址按 NAT 方式改写到本机隧道地址 + 临时端口；
//!   - 由 `smoltcp` 终止 TCP（Listener），并转发到调用方注入的出站拨号器；
//!   - UDP 也使用 `smoltcp` socket 承接每个五元组，再经拨号器转发。
//! * 所有资源都有上限：peer 数、TCP 连接、UDP 关联、待发送队列、隧道内
//!   RX 队列、握手速率。任何解析/校验失败都丢弃报文（fail-closed），不会
//!   放行未认证数据。
//! * 不记录私钥或预共享密钥；`Debug` 实现会脱敏。
//!
//! 配置接入点见文件末尾 `CONFIG INTEGRATION` 注释与最终报告；本文件刻意
//! 不引用 `crate::config` / `crate::route` / `crate::runtime`，以便通过
//! `OutboundDialer` 由运行时注入真正的 route/direct 拨号逻辑。

use crate::sync::poisoned;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::{Duration, Instant};

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{HandshakeInit, Packet, Tunn, TunnResult};
use boringtun::x25519;
use ipnet::IpNet;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// 单个 UDP 数据报的缓冲上限（最大 IP 包 + WireGuard 封装余量）。
const DATAGRAM: usize = 65_535 + 64;
/// TCP 终止 socket 的收发缓冲。
const TCP_BUFFER: usize = 64 * 1024;
/// UDP 关联的收发缓冲。
const UDP_BUFFER: usize = 64 * 1024;
/// NAT 临时端口范围。
const NAT_PORT_START: u16 = 49_152;
const NAT_PORT_END: u16 = 61_000;
/// 驱动循环的最小节拍：定时器、重传、keepalive 与协议栈推进。
const TICK: Duration = Duration::from_millis(20);
/// 定期清理空闲 NAT 关联 / 过期 peer 的周期。
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const TCP_IDLE: Duration = Duration::from_secs(120);
const UDP_IDLE: Duration = Duration::from_secs(60);

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// 解析标准 base64（带 `=` 填充）形式的 32 字节 WireGuard 密钥。
pub fn parse_base64_key(value: &str) -> io::Result<[u8; 32]> {
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| invalid_input("WireGuard 密钥不是合法 base64"))?;
    let length = decoded.len();
    decoded
        .try_into()
        .map_err(|_| invalid_input(format!("WireGuard 密钥必须是 32 字节，实际 {length} 字节")))
}

/// 单个 peer 的服务端配置。
///
/// `allowed_ips` 同时用于源地址过滤：只有源 IP 落在其中一条网段的、已通过
/// Noise 认证的隧道内报文才会被转发。它不会自动参与出站路由；出站目标由
/// 报文原始目的地址决定，交给 `OutboundDialer` 做策略判断。
#[derive(Clone)]
pub struct WireguardPeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<IpNet>,
    /// `None` / `Some(0)` 表示不启用 persistent keepalive。
    pub keepalive_secs: Option<u16>,
}

impl std::fmt::Debug for WireguardPeerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireguardPeerConfig")
            .field("public_key", &self.public_key)
            .field("preshared_key", &self.preshared_key.map(|_| "[REDACTED]"))
            .field("allowed_ips", &self.allowed_ips)
            .field("keepalive_secs", &self.keepalive_secs)
            .finish()
    }
}

impl WireguardPeerConfig {
    pub fn new(public_key: [u8; 32], allowed_ips: Vec<IpNet>) -> Self {
        Self {
            public_key,
            preshared_key: None,
            allowed_ips,
            keepalive_secs: None,
        }
    }

    pub fn with_preshared_key(mut self, preshared_key: Option<[u8; 32]>) -> Self {
        self.preshared_key = preshared_key;
        self
    }

    pub fn with_keepalive_secs(mut self, keepalive_secs: Option<u16>) -> Self {
        self.keepalive_secs = keepalive_secs;
        self
    }

    #[allow(dead_code)] // 与 WireguardServerConfig::from_base64 成对的库构造入口。
    pub fn from_base64(
        public_key: &str,
        preshared_key: Option<&str>,
        allowed_ips: &[&str],
        keepalive_secs: Option<u16>,
    ) -> io::Result<Self> {
        let preshared_key = match preshared_key {
            Some(value) => Some(parse_base64_key(value)?),
            None => None,
        };
        let mut parsed = Vec::with_capacity(allowed_ips.len());
        for value in allowed_ips {
            parsed.push(
                value.parse::<IpNet>().map_err(|_| {
                    invalid_input(format!("allowed_ips 条目不是有效 CIDR: {value}"))
                })?,
            );
        }
        Ok(Self {
            public_key: parse_base64_key(public_key)?,
            preshared_key,
            allowed_ips: parsed,
            keepalive_secs,
        })
    }
}

/// 服务端运行期配置。
///
/// 注意：WireGuard 私钥只应来自受控配置；本结构体不派生/序列化。
#[derive(Clone)]
pub struct WireguardServerConfig {
    pub private_key: [u8; 32],
    /// 本机在隧道网络中的地址（IPv4/IPv6 均可）。至少一条。
    pub local_addresses: Vec<IpNet>,
    pub peers: Vec<WireguardPeerConfig>,
    pub mtu: usize,
    /// 配置中允许的 peer 总数上限；超出直接拒绝启动。
    pub max_peers: usize,
    pub max_tcp_connections: usize,
    pub max_udp_associations: usize,
    /// 待发送 UDP 数据报队列与隧道内 RX 队列的共用上限。
    pub max_queued_datagrams: usize,
    /// 每秒接受的 handshake initiation 总数（含未知 peer）。
    pub max_handshake_inits_per_sec: u32,
    /// peer 在该时间内没有任何已认证报文时清空其会话与 NAT 关联。
    pub peer_idle_timeout: Duration,
}

impl std::fmt::Debug for WireguardServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireguardServerConfig")
            .field("private_key", &"[REDACTED]")
            .field("local_addresses", &self.local_addresses)
            .field("peers", &self.peers)
            .field("mtu", &self.mtu)
            .field("max_peers", &self.max_peers)
            .field("max_tcp_connections", &self.max_tcp_connections)
            .field("max_udp_associations", &self.max_udp_associations)
            .field("max_queued_datagrams", &self.max_queued_datagrams)
            .field(
                "max_handshake_inits_per_sec",
                &self.max_handshake_inits_per_sec,
            )
            .field("peer_idle_timeout", &self.peer_idle_timeout)
            .finish()
    }
}

impl WireguardServerConfig {
    pub fn new(private_key: [u8; 32], local_addresses: Vec<IpNet>) -> Self {
        Self {
            private_key,
            local_addresses,
            peers: Vec::new(),
            mtu: 1420,
            max_peers: 256,
            max_tcp_connections: 256,
            max_udp_associations: 256,
            max_queued_datagrams: 1024,
            max_handshake_inits_per_sec: 50,
            peer_idle_timeout: Duration::from_secs(300),
        }
    }

    #[cfg(test)]
    pub fn with_peer(mut self, peer: WireguardPeerConfig) -> Self {
        self.peers.push(peer);
        self
    }

    #[allow(dead_code)] // 供库调用方直接构造配置；runtime 已按 inbound 字段解析。
    pub fn from_base64(private_key: &str, local_addresses: &[&str]) -> io::Result<Self> {
        let mut parsed = Vec::with_capacity(local_addresses.len());
        for value in local_addresses {
            parsed.push(value.parse::<IpNet>().map_err(|_| {
                invalid_input(format!("local_addresses 条目不是有效 CIDR: {value}"))
            })?);
        }
        Ok(Self::new(parse_base64_key(private_key)?, parsed))
    }

    fn validate(&self) -> io::Result<()> {
        if self.private_key.iter().all(|byte| *byte == 0) {
            return Err(invalid_input("WireGuard 服务端私钥不能全为 0"));
        }
        if self.local_addresses.is_empty()
            || self.local_addresses.len() > smoltcp::config::IFACE_MAX_ADDR_COUNT
        {
            return Err(invalid_input(format!(
                "WireGuard 隧道内地址数量必须在 1..={} 内",
                smoltcp::config::IFACE_MAX_ADDR_COUNT
            )));
        }
        if !(576..=1500).contains(&self.mtu) {
            return Err(invalid_input("WireGuard 服务端 mtu 必须在 576..=1500"));
        }
        if self.max_peers == 0 || self.max_peers > 0x00FF_FFFF {
            return Err(invalid_input("max_peers 必须在 1..=0x00FF_FFFF"));
        }
        if self.peers.len() > self.max_peers {
            return Err(invalid_input("peer 数量超过 max_peers"));
        }
        if self.max_tcp_connections == 0
            || self.max_udp_associations == 0
            || self.max_queued_datagrams == 0
            || self.max_handshake_inits_per_sec == 0
        {
            return Err(invalid_input("WireGuard 服务端资源上限不能为 0"));
        }
        if self.peer_idle_timeout.is_zero() {
            return Err(invalid_input("peer_idle_timeout 不能为 0"));
        }
        let mut seen = std::collections::HashSet::with_capacity(self.peers.len());
        for peer in &self.peers {
            if peer.public_key.iter().all(|byte| *byte == 0) {
                return Err(invalid_input("peer 公钥不能全为 0"));
            }
            if !seen.insert(peer.public_key) {
                return Err(invalid_input("peer 公钥重复"));
            }
            if peer.allowed_ips.is_empty() {
                return Err(invalid_input("每个 peer 必须配置至少一条 allowed_ips"));
            }
            // 0.0.0.0/0 是显式全量授权；出站访问控制由 dialer 负责。
        }
        Ok(())
    }
}

/// 出站 TCP 流的最小抽象。任何 `tokio`/自定义流只要满足该约束都可注入。
pub trait RelayTcp: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> RelayTcp for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// 出站 UDP 关联的最小抽象。
///
/// `send` / `recv` 返回的 future 在 `select!` 中可能被取消；实现应保证取消
/// 不会丢包或破坏后续调用（`tokio::net::UdpSocket` 满足此约束）。
pub trait RelayUdp: Send + 'static {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;
}

/// 拨号返回的 TCP 中继流 future；`'_` 绑定拨号器自身的生命周期。
type BoxDialTcp<'a> = Pin<Box<dyn Future<Output = io::Result<Box<dyn RelayTcp>>> + Send + 'a>>;
/// 拨号返回的 UDP 中继关联 future。
type BoxDialUdp<'a> = Pin<Box<dyn Future<Output = io::Result<Box<dyn RelayUdp>>> + Send + 'a>>;

/// 由运行时注入的出站拨号器（对应 route/direct 接口）。
///
/// 实现方必须执行访问控制与 DNS 解析策略；本模块只传入隧道内报文的原始
/// 目的 `SocketAddr`，不会自行放行任何目标。
pub trait OutboundDialer: Send + Sync + 'static {
    fn relay_tcp(
        &self,
        stream: Box<dyn RelayTcp>,
        mut target: Box<dyn RelayTcp>,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>> {
        Box::pin(async move {
            let mut stream = stream;
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
            Ok(())
        })
    }

    fn dial_tcp(&self, target: SocketAddr) -> BoxDialTcp<'_>;

    fn dial_udp(&self, target: SocketAddr) -> BoxDialUdp<'_>;
}

/// 已 `connect` 到固定目标的 UDP 关联；供测试的 loopback 拨号使用。
#[cfg(test)]
pub struct ConnectedUdpSocket(pub tokio::net::UdpSocket);

#[cfg(test)]
impl RelayUdp for ConnectedUdpSocket {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { self.0.send(payload).await.map(|_| ()) })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { self.0.recv(buffer).await })
    }
}

/// 服务端统计快照。计数器均为单调递增。
///
/// 运行层目前只导出 `received_datagrams`/`sent_datagrams`/`queued_datagrams`；
/// 其余诊断计数由测试断言使用，保留在快照中以维持统计面的完整性。
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct WireguardServerStats {
    pub received_datagrams: u64,
    pub sent_datagrams: u64,
    pub dropped_datagrams: u64,
    pub invalid_packets: u64,
    pub unknown_peers: u64,
    pub completed_handshakes: u64,
    pub expired_peers: u64,
    pub tcp_connections: usize,
    pub udp_associations: usize,
    pub queued_datagrams: usize,
}

#[derive(Default)]
struct Stats {
    received: AtomicU64,
    sent: AtomicU64,
    dropped: AtomicU64,
    invalid: AtomicU64,
    unknown_peers: AtomicU64,
    handshakes: AtomicU64,
    expired_peers: AtomicU64,
}

/// smoltcp 的 IP 报文队列；`Medium::Ip` 不需要链路层寻址。
struct DeviceState {
    mtu: usize,
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct RxTokenState(Vec<u8>);

impl RxToken for RxTokenState {
    fn consume<R, F: FnOnce(&[u8]) -> R>(mut self, f: F) -> R {
        let result = f(&self.0);
        self.0.clear();
        result
    }
}

struct TxTokenState<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for TxTokenState<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.0.push_back(buffer);
        result
    }
}

impl Device for DeviceState {
    type RxToken<'a> = RxTokenState;
    type TxToken<'a> = TxTokenState<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.rx.pop_front()?;
        Some((RxTokenState(buffer), TxTokenState(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenState(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

/// 隧道内一条 NAT 五元组。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    /// 配置中 peer 的下标。
    peer: usize,
    protocol: u8,
    /// 隧道内客户端地址（TCP/UDP 源）。
    source: SocketAddr,
    /// 客户端看到的原始目的地址。
    destination: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatKind {
    Tcp,
    Udp,
}

struct NatEntry {
    kind: NatKind,
    local_port: u16,
    handle: SocketHandle,
    /// TCP 已在 smoltcp 中完成握手并派生 relay 任务；UDP 创建即派生。
    spawned: bool,
    last_activity: Instant,
    cancel: CancellationToken,
}

struct PeerRuntime {
    tunn: Tunn,
    endpoint: Option<SocketAddr>,
    last_activity: Instant,
}

struct Inner {
    interface: Interface,
    device: DeviceState,
    sockets: SocketSet<'static>,
    peers: Vec<PeerRuntime>,
    flows: HashMap<FlowKey, NatEntry>,
    /// 本地 NAT 端口 -> flow；保证同一端口只服务一条关联。
    ports: HashMap<u16, FlowKey>,
    next_port: u16,
    tcp_flows: usize,
    udp_flows: usize,
    wakers: Vec<Waker>,
    closed: bool,
    last_cleanup: Instant,
}

struct Outgoing {
    endpoint: SocketAddr,
    datagram: Vec<u8>,
}

struct HandshakeWindow {
    started: Instant,
    count: u32,
}

/// 已绑定 UdpSocket 上的 WireGuard 服务端。
///
/// 用法：
/// ```ignore
/// let socket = Arc::new(UdpSocket::bind("0.0.0.0:51820").await?);
/// let server = Arc::new(WireguardServer::new(socket, config, Arc::new(dialer))?);
/// let task = server.spawn();       // 或 async move { server.run().await }
/// server.shutdown();
/// ```
/// WireGuard 的认证/协议层拒绝类型；两者都计入全局 rejected。
#[derive(Clone, Copy)]
enum RejectKind {
    /// 无效握手 / MAC1 失败 / 解密失败 / 报文校验失败。
    Invalid,
    /// 未知静态公钥。
    UnknownPeer,
}

pub struct WireguardServer {
    socket: Arc<UdpSocket>,
    config: Arc<WireguardServerConfig>,
    dialer: Arc<dyn OutboundDialer>,
    private: x25519::StaticSecret,
    public: x25519::PublicKey,
    rate_limiter: Arc<RateLimiter>,
    /// 静态公钥 -> peer 下标。
    peer_slots: HashMap<[u8; 32], usize>,
    inner: Mutex<Inner>,
    outgoing: Mutex<VecDeque<Outgoing>>,
    notify: Notify,
    shutdown: Notify,
    handshake_window: Mutex<HandshakeWindow>,
    relays: Mutex<JoinSet<()>>,
    stats: Stats,
}

impl std::fmt::Debug for WireguardServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireguardServer")
            .field("config", &self.config)
            .field("stats", &self.stats())
            .finish()
    }
}

impl WireguardServer {
    /// 在**调用方已绑定**的 UDP socket 上创建服务端；本方法不绑定端口。
    pub fn new(
        socket: Arc<UdpSocket>,
        config: WireguardServerConfig,
        dialer: Arc<dyn OutboundDialer>,
    ) -> io::Result<Self> {
        config.validate()?;
        let private = x25519::StaticSecret::from(config.private_key);
        let public = x25519::PublicKey::from(&private);
        let rate_limiter = Arc::new(RateLimiter::new(
            &public,
            u64::from(config.max_handshake_inits_per_sec),
        ));

        let mut peers = Vec::with_capacity(config.peers.len());
        let mut peer_slots = HashMap::with_capacity(config.peers.len());
        for (index, peer) in config.peers.iter().enumerate() {
            // slot 从 1 开始，避免 receiver_index 高位全 0 与非法索引混淆。
            let slot = (index + 1) as u32;
            peer_slots.insert(peer.public_key, index);
            peers.push(PeerRuntime {
                tunn: new_tunn(&config, peer, slot, Arc::clone(&rate_limiter)),
                endpoint: None,
                last_activity: Instant::now(),
            });
        }

        let mut device = DeviceState {
            mtu: config.mtu,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        };
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::now(),
        );
        interface.update_ip_addrs(|addresses| {
            for network in &config.local_addresses {
                addresses
                    .push(IpCidr::new(
                        to_smoltcp_ip(network.addr()),
                        network.prefix_len(),
                    ))
                    .expect("接口地址数量受配置约束");
            }
        });
        if let Some(address) = config
            .local_addresses
            .iter()
            .find_map(|network| match network {
                IpNet::V4(network) => Some(Ipv4Address::from(network.addr().octets())),
                IpNet::V6(_) => None,
            })
        {
            let _ = interface.routes_mut().add_default_ipv4_route(address);
        }
        if let Some(address) = config
            .local_addresses
            .iter()
            .find_map(|network| match network {
                IpNet::V6(network) => Some(Ipv6Address::from(network.addr().octets())),
                IpNet::V4(_) => None,
            })
        {
            let _ = interface.routes_mut().add_default_ipv6_route(address);
        }

        Ok(Self {
            socket,
            config: Arc::new(config),
            dialer,
            private,
            public,
            rate_limiter,
            peer_slots,
            inner: Mutex::new(Inner {
                interface,
                device,
                sockets: SocketSet::new(Vec::new()),
                peers,
                flows: HashMap::new(),
                ports: HashMap::new(),
                next_port: NAT_PORT_START,
                tcp_flows: 0,
                udp_flows: 0,
                wakers: Vec::new(),
                closed: false,
                last_cleanup: Instant::now(),
            }),
            outgoing: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            shutdown: Notify::new(),
            handshake_window: Mutex::new(HandshakeWindow {
                started: Instant::now(),
                count: 0,
            }),
            relays: Mutex::new(JoinSet::new()),
            stats: Stats::default(),
        })
    }

    /// 已绑定 socket 的本地地址。
    #[cfg(test)]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 派生驱动任务。
    #[cfg(test)]
    pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<io::Result<()>> {
        let server = Arc::clone(self);
        tokio::spawn(async move { server.run().await })
    }

    /// 运行驱动循环。UDP 接收/发送失败会以 `Err` 返回，不会被静默忽略。
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        struct StopOnDrop(Arc<WireguardServer>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.shutdown();
            }
        }
        let _stop = StopOnDrop(self.clone());
        let result = self.drive().await;
        self.shutdown();
        // 不留下持有 socket/Context 的 detached relay；所有退出路径都等待回收。
        let mut relays = {
            let mut active = self.relays.lock().unwrap_or_else(poisoned);
            std::mem::replace(&mut *active, JoinSet::new())
        };
        relays.abort_all();
        while relays.join_next().await.is_some() {}
        result
    }

    async fn drive(self: &Arc<Self>) -> io::Result<()> {
        let mut buffer = vec![0u8; DATAGRAM];
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if self.is_closed() {
                return Ok(());
            }
            self.flush_outgoing().await?;
            tokio::select! {
                biased;
                _ = self.shutdown.notified() => return Ok(()),
                _ = self.notify.notified() => {}
                result = self.socket.recv_from(&mut buffer) => {
                    let (length, sender) = result.map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("WireGuard 服务端 UDP 接收失败: {error}"),
                        )
                    })?;
                    self.handle_datagram(&buffer[..length], sender);
                }
                _ = ticker.tick() => {
                    self.tick();
                }
            }
        }
    }

    /// 请求驱动循环退出。
    pub fn shutdown(&self) {
        let wakers = {
            let mut inner = self.inner.lock().unwrap_or_else(poisoned);
            inner.closed = true;
            let keys: Vec<_> = inner.flows.keys().cloned().collect();
            for key in keys {
                remove_flow(&mut inner, &key);
            }
            inner.device.rx.clear();
            inner.device.tx.clear();
            std::mem::take(&mut inner.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
        self.outgoing.lock().unwrap_or_else(poisoned).clear();
        self.relays.lock().unwrap_or_else(poisoned).abort_all();
        // `notify_one` 会保留 permit，避免 shutdown 与 select! 建 future 之间的竞态。
        self.shutdown.notify_one();
        self.notify.notify_one();
    }

    /// 记录一次认证/协议层拒绝的本地细分计数。
    ///
    /// 全局 `rejected` 由 `runtime` 周期采样 `invalid_packets` +
    /// `unknown_peers` 的增量合并（见 WireGuard 的 sampler 任务），
    /// 因为本类型在 bind 阶段就构造完毕，那时全局 Stats 还不存在。
    fn reject(&self, kind: RejectKind) {
        match kind {
            RejectKind::Invalid => self.stats.invalid.fetch_add(1, Ordering::Relaxed),
            RejectKind::UnknownPeer => self.stats.unknown_peers.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn stats(&self) -> WireguardServerStats {
        let (tcp, udp, queued) = {
            let inner = self.inner.lock().unwrap_or_else(poisoned);
            (
                inner.tcp_flows,
                inner.udp_flows,
                self.outgoing.lock().unwrap_or_else(poisoned).len(),
            )
        };
        WireguardServerStats {
            received_datagrams: self.stats.received.load(Ordering::Relaxed),
            sent_datagrams: self.stats.sent.load(Ordering::Relaxed),
            dropped_datagrams: self.stats.dropped.load(Ordering::Relaxed),
            invalid_packets: self.stats.invalid.load(Ordering::Relaxed),
            unknown_peers: self.stats.unknown_peers.load(Ordering::Relaxed),
            completed_handshakes: self.stats.handshakes.load(Ordering::Relaxed),
            expired_peers: self.stats.expired_peers.load(Ordering::Relaxed),
            tcp_connections: tcp,
            udp_associations: udp,
            queued_datagrams: queued,
        }
    }

    fn is_closed(&self) -> bool {
        self.inner.lock().unwrap_or_else(poisoned).closed
    }

    async fn flush_outgoing(&self) -> io::Result<()> {
        loop {
            let next = self.outgoing.lock().unwrap_or_else(poisoned).pop_front();
            let Some(item) = next else {
                return Ok(());
            };
            self.socket
                .send_to(&item.datagram, item.endpoint)
                .await
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("WireGuard 服务端 UDP 发送失败: {error}"),
                    )
                })?;
            self.stats.sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn allow_handshake(&self) -> bool {
        let mut window = self.handshake_window.lock().unwrap_or_else(poisoned);
        let now = Instant::now();
        if now.duration_since(window.started) >= Duration::from_secs(1) {
            window.started = now;
            window.count = 0;
        }
        if window.count >= self.config.max_handshake_inits_per_sec {
            return false;
        }
        window.count += 1;
        true
    }

    fn handle_datagram(self: &Arc<Self>, datagram: &[u8], sender: SocketAddr) {
        self.stats.received.fetch_add(1, Ordering::Relaxed);
        match Tunn::parse_incoming_packet(datagram) {
            Ok(Packet::HandshakeInit(init)) => self.handle_handshake(&init, datagram, sender),
            Ok(Packet::PacketData(packet)) => {
                self.handle_data(packet.receiver_idx, datagram, sender)
            }
            // 服务端通常只作为 responder；但 boringtun 在无会话时可能由
            // `encapsulate` 主动发起握手，此路径用于接收对应 response。
            Ok(Packet::HandshakeResponse(packet)) => {
                self.handle_data(packet.receiver_idx, datagram, sender)
            }
            // 仅当服务端因无会话而主动发起握手时才会收到 cookie reply；
            // 其 receiver_index 同样落在本端 slot 空间内，交给 Tunn 校验。
            Ok(Packet::PacketCookieReply(packet)) => {
                self.handle_data(packet.receiver_idx, datagram, sender)
            }
            Err(error) => {
                tracing::debug!(?error, "WireGuard 服务端丢弃无法解析的报文");
                self.reject(RejectKind::Invalid);
            }
        }
    }

    fn handle_handshake(
        self: &Arc<Self>,
        init: &HandshakeInit<'_>,
        datagram: &[u8],
        sender: SocketAddr,
    ) {
        if !self.allow_handshake() {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // 只解析静态公钥，不做任何信任决定；真正的 MAC1/时间戳重放校验在
        // `Tunn::decapsulate` 中完成。
        let half = match parse_handshake_anon(&self.private, &self.public, init) {
            Ok(half) => half,
            Err(error) => {
                tracing::debug!(?error, "WireGuard 服务端拒绝无效握手初始化");
                self.reject(RejectKind::Invalid);
                return;
            }
        };
        let Some(index) = self.peer_slots.get(&half.peer_static_public).copied() else {
            self.reject(RejectKind::UnknownPeer);
            return;
        };

        let (sends, spawns, new_udp) = {
            let mut inner = self.inner.lock().unwrap_or_else(poisoned);
            if inner.closed {
                return;
            }
            let mut scratch = vec![0u8; DATAGRAM];
            let mut sends = Vec::new();
            let mut plain = Vec::new();
            let mut new_udp = Vec::new();
            let mut accepted = false;
            let mut failed = false;
            {
                let peer = &mut inner.peers[index];
                let mut result = peer
                    .tunn
                    .decapsulate(Some(sender.ip()), datagram, &mut scratch);
                loop {
                    match result {
                        TunnResult::Done => break,
                        TunnResult::Err(error) => {
                            tracing::debug!(?error, "WireGuard 服务端拒绝握手/重放报文");
                            failed = true;
                            break;
                        }
                        TunnResult::WriteToNetwork(data) => {
                            if matches!(
                                Tunn::parse_incoming_packet(data),
                                Ok(Packet::HandshakeResponse(_))
                            ) {
                                accepted = true;
                            }
                            sends.push(data.to_vec());
                            result = peer.tunn.decapsulate(Some(sender.ip()), &[], &mut scratch);
                        }
                        TunnResult::WriteToTunnelV4(data, _)
                        | TunnResult::WriteToTunnelV6(data, _) => {
                            plain.push(data.to_vec());
                            result = peer.tunn.decapsulate(Some(sender.ip()), &[], &mut scratch);
                        }
                    }
                }
            }
            if failed {
                self.reject(RejectKind::Invalid);
            } else if accepted {
                // 只有完整通过 MAC1、静态密钥、TAI64N 校验后才学习漫游地址。
                let peer = &mut inner.peers[index];
                peer.endpoint = Some(sender);
                peer.last_activity = Instant::now();
                self.stats.handshakes.fetch_add(1, Ordering::Relaxed);
            }
            for packet in plain {
                if let Some(key) = self.feed_ip(&mut inner, index, packet) {
                    new_udp.push(key);
                }
            }
            let spawns = self.pump_stack(&mut inner);
            (sends, spawns, new_udp)
        };
        for datagram in sends {
            self.queue_datagram(sender, &datagram);
        }
        for key in spawns {
            self.spawn_tcp_relay(key);
        }
        for key in new_udp {
            self.spawn_udp_relay(key);
        }
    }

    fn handle_data(self: &Arc<Self>, receiver_index: u32, datagram: &[u8], sender: SocketAddr) {
        // slot = 24 位 peer 分片，低 8 位是 boringtun 的会话计数器。
        let slot = (receiver_index >> 8) as usize;
        if slot == 0 || slot > self.config.peers.len() {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let index = slot - 1;

        let (sends, spawns, new_udp) = {
            let mut inner = self.inner.lock().unwrap_or_else(poisoned);
            if inner.closed {
                return;
            }
            let mut scratch = vec![0u8; DATAGRAM];
            let mut sends = Vec::new();
            let mut plain = Vec::new();
            let mut new_udp = Vec::new();
            let mut failed = false;
            let mut accepted = false;
            let mut first = true;
            {
                let peer = &mut inner.peers[index];
                let mut result = peer
                    .tunn
                    .decapsulate(Some(sender.ip()), datagram, &mut scratch);
                loop {
                    match result {
                        TunnResult::Done => {
                            // 空载荷 keepalive 也经过完整认证；刷新 endpoint 与活跃时间。
                            if first {
                                accepted = true;
                            }
                            break;
                        }
                        TunnResult::Err(error) => {
                            tracing::debug!(?error, "WireGuard 服务端丢弃无效数据报文");
                            failed = true;
                            break;
                        }
                        TunnResult::WriteToNetwork(data) => {
                            sends.push(data.to_vec());
                            accepted = true;
                            result = peer.tunn.decapsulate(Some(sender.ip()), &[], &mut scratch);
                        }
                        TunnResult::WriteToTunnelV4(data, _)
                        | TunnResult::WriteToTunnelV6(data, _) => {
                            plain.push(data.to_vec());
                            accepted = true;
                            result = peer.tunn.decapsulate(Some(sender.ip()), &[], &mut scratch);
                        }
                    }
                    first = false;
                }
            }
            if failed {
                self.reject(RejectKind::Invalid);
            } else if accepted {
                let peer = &mut inner.peers[index];
                peer.endpoint = Some(sender);
                peer.last_activity = Instant::now();
            }
            for packet in plain {
                if let Some(key) = self.feed_ip(&mut inner, index, packet) {
                    new_udp.push(key);
                }
            }
            let spawns = self.pump_stack(&mut inner);
            (sends, spawns, new_udp)
        };
        let endpoint = self
            .inner
            .lock()
            .unwrap_or_else(poisoned)
            .peers
            .get(index)
            .and_then(|peer| peer.endpoint)
            .unwrap_or(sender);
        for datagram in sends {
            self.queue_datagram(endpoint, &datagram);
        }
        for key in spawns {
            self.spawn_tcp_relay(key);
        }
        for key in new_udp {
            self.spawn_udp_relay(key);
        }
    }

    /// 处理一条已解密并通过 allowed_ips 检查的隧道内 IP 报文。
    fn feed_ip(
        self: &Arc<Self>,
        inner: &mut Inner,
        peer_index: usize,
        mut packet: Vec<u8>,
    ) -> Option<FlowKey> {
        if !valid_packet_checksums(&packet) {
            self.reject(RejectKind::Invalid);
            return None;
        }
        let Some(info) = inspect_packet(&packet) else {
            self.reject(RejectKind::Invalid);
            return None;
        };
        if info.destination.ip().is_unspecified()
            || info.destination.ip().is_multicast()
            || info.destination.ip() == IpAddr::V4(Ipv4Addr::BROADCAST)
            || info.destination.port() == 0
            || info.source.port() == 0
        {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let allowed = self.config.peers[peer_index]
            .allowed_ips
            .iter()
            .any(|network| network.contains(&info.source.ip()));
        if !allowed {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let key = FlowKey {
            peer: peer_index,
            protocol: info.protocol,
            source: info.source,
            destination: info.destination,
        };
        let Some(local_ip) = self.local_ip(info.destination.ip()) else {
            // 没有与报文地址族匹配的本机隧道地址，失败关闭。
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        let (local_port, kind, created) = if let Some(entry) = inner.flows.get(&key) {
            (entry.local_port, entry.kind, false)
        } else {
            match info.protocol {
                6 if info.tcp_syn => {
                    if inner.tcp_flows >= self.config.max_tcp_connections
                        || inner.flows.len()
                            >= self.config.max_tcp_connections + self.config.max_udp_associations
                    {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    let port = allocate_port(inner)?;
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
                        tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
                    );
                    let timeout = smoltcp::time::Duration::from_secs(TCP_IDLE.as_secs());
                    socket.set_timeout(Some(timeout));
                    socket.set_keep_alive(Some(timeout));
                    if socket.listen(port).is_err() {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    let handle = inner.sockets.add(socket);
                    inner.tcp_flows += 1;
                    inner.ports.insert(port, key.clone());
                    inner.flows.insert(
                        key.clone(),
                        NatEntry {
                            kind: NatKind::Tcp,
                            local_port: port,
                            handle,
                            spawned: false,
                            last_activity: Instant::now(),
                            cancel: CancellationToken::new(),
                        },
                    );
                    (port, NatKind::Tcp, false)
                }
                17 => {
                    if inner.udp_flows >= self.config.max_udp_associations
                        || inner.flows.len()
                            >= self.config.max_tcp_connections + self.config.max_udp_associations
                    {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    let port = allocate_port(inner)?;
                    let mut socket = udp::Socket::new(
                        udp::PacketBuffer::new(
                            vec![udp::PacketMetadata::EMPTY; 16],
                            vec![0u8; UDP_BUFFER],
                        ),
                        udp::PacketBuffer::new(
                            vec![udp::PacketMetadata::EMPTY; 16],
                            vec![0u8; UDP_BUFFER],
                        ),
                    );
                    if socket
                        .bind(IpListenEndpoint {
                            addr: Some(to_smoltcp_ip(local_ip)),
                            port,
                        })
                        .is_err()
                    {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    let handle = inner.sockets.add(socket);
                    inner.udp_flows += 1;
                    inner.ports.insert(port, key.clone());
                    inner.flows.insert(
                        key.clone(),
                        NatEntry {
                            kind: NatKind::Udp,
                            local_port: port,
                            handle,
                            spawned: true,
                            last_activity: Instant::now(),
                            cancel: CancellationToken::new(),
                        },
                    );
                    (port, NatKind::Udp, true)
                }
                _ => {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        };

        // 将目的地址 DNAT 到本机隧道地址 + 临时端口，便于 smoltcp 终止。
        if !rewrite_destination(&mut packet, local_ip, local_port) {
            self.reject(RejectKind::Invalid);
            return None;
        }
        if inner.device.rx.len() >= self.config.max_queued_datagrams {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        inner.device.rx.push_back(packet);
        if let Some(entry) = inner.flows.get_mut(&key) {
            entry.last_activity = Instant::now();
        }
        if kind == NatKind::Udp && created {
            Some(key)
        } else {
            None
        }
    }

    /// 推进 smoltcp；返回刚刚完成握手、需要派生 relay 任务的 TCP flow。
    fn pump_stack(&self, inner: &mut Inner) -> Vec<FlowKey> {
        if inner.closed {
            return Vec::new();
        }
        let now = SmolInstant::now();
        inner
            .interface
            .poll(now, &mut inner.device, &mut inner.sockets);

        while let Some(packet) = inner.device.tx.pop_front() {
            self.encapsulate_tx(inner, packet);
        }

        let mut spawns = Vec::new();
        {
            let Inner { flows, sockets, .. } = inner;
            for (key, entry) in flows.iter_mut() {
                if entry.kind != NatKind::Tcp || entry.spawned {
                    continue;
                }
                if matches!(
                    sockets.get::<tcp::Socket>(entry.handle).state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    entry.spawned = true;
                    spawns.push(key.clone());
                }
            }
        }

        let wakers = std::mem::take(&mut inner.wakers);
        for waker in wakers {
            waker.wake();
        }
        spawns
    }

    /// 将 smoltcp 产生的 IP 报文还原为原始源地址并封装进对应 peer 的隧道。
    fn encapsulate_tx(&self, inner: &mut Inner, mut packet: Vec<u8>) {
        let Some(info) = inspect_packet(&packet) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(key) = inner.ports.get(&info.source.port()).cloned() else {
            // 任何没有 NAT 归属的出站报文都丢弃，避免跨 peer 泄漏。
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if info.destination != key.source {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let target = key.destination;
        if !rewrite_source(&mut packet, target.ip(), target.port()) {
            self.reject(RejectKind::Invalid);
            return;
        }
        let peer = &mut inner.peers[key.peer];
        let Some(endpoint) = peer.endpoint else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut scratch = vec![0u8; DATAGRAM];
        if let TunnResult::WriteToNetwork(data) = peer.tunn.encapsulate(&packet, &mut scratch) {
            let datagram = data.to_vec();
            self.queue_datagram(endpoint, &datagram);
        } else {
            // 无会话时 boringtun 会把报文放入其有界队列；队列满则静默丢弃，
            // 这里只把本轮未能发送计入统计。
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn queue_datagram(&self, endpoint: SocketAddr, datagram: &[u8]) {
        let mut queue = self.outgoing.lock().unwrap_or_else(poisoned);
        if queue.len() >= self.config.max_queued_datagrams {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        queue.push_back(Outgoing {
            endpoint,
            datagram: datagram.to_vec(),
        });
        drop(queue);
        self.notify.notify_one();
    }

    fn tick(self: &Arc<Self>) {
        // boringtun 的共享限速器需要外部周期性重置计数。
        self.rate_limiter.reset_count();
        let spawns;
        {
            let mut inner = self.inner.lock().unwrap_or_else(poisoned);
            if inner.closed {
                return;
            }

            let mut reset = Vec::new();
            for index in 0..inner.peers.len() {
                let endpoint = inner.peers[index].endpoint;
                if endpoint.is_none() {
                    continue;
                }
                let mut scratch = vec![0u8; DATAGRAM];
                match inner.peers[index].tunn.update_timers(&mut scratch) {
                    TunnResult::WriteToNetwork(data) => {
                        if let Some(endpoint) = endpoint {
                            let datagram = data.to_vec();
                            self.queue_datagram(endpoint, &datagram);
                        }
                    }
                    TunnResult::Err(error) => {
                        tracing::debug!(?error, "WireGuard 服务端 peer 会话过期");
                        reset.push(index);
                    }
                    TunnResult::Done
                    | TunnResult::WriteToTunnelV4(_, _)
                    | TunnResult::WriteToTunnelV6(_, _) => {}
                }
            }
            for index in reset {
                self.stats.expired_peers.fetch_add(1, Ordering::Relaxed);
                self.reset_peer(&mut inner, index);
            }

            let now = Instant::now();
            if now.duration_since(inner.last_cleanup) >= CLEANUP_INTERVAL {
                inner.last_cleanup = now;
                let stale: Vec<FlowKey> = inner
                    .flows
                    .iter()
                    .filter(|(key, entry)| {
                        let idle = match entry.kind {
                            NatKind::Tcp => TCP_IDLE,
                            NatKind::Udp => UDP_IDLE,
                        };
                        now.duration_since(entry.last_activity) >= idle
                            || now.duration_since(inner.peers[key.peer].last_activity)
                                >= self.config.peer_idle_timeout
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in stale {
                    remove_flow(&mut inner, &key);
                }
                let idle_peers: Vec<usize> = inner
                    .peers
                    .iter()
                    .enumerate()
                    .filter(|(_, peer)| {
                        peer.endpoint.is_some()
                            && now.duration_since(peer.last_activity)
                                >= self.config.peer_idle_timeout
                    })
                    .map(|(index, _)| index)
                    .collect();
                for index in idle_peers {
                    self.stats.expired_peers.fetch_add(1, Ordering::Relaxed);
                    self.reset_peer(&mut inner, index);
                }
            }

            spawns = self.pump_stack(&mut inner);
        }
        for key in spawns {
            self.spawn_tcp_relay(key);
        }
    }

    fn reset_peer(&self, inner: &mut Inner, index: usize) {
        // 保留同一 Handshake 的 TAI64N 高水位，不能通过重建 Tunn 重新接受旧 init。
        // 该公开 API 清除会话密钥，但不重置已认证握手时间戳/会话索引。
        inner.peers[index].tunn.set_static_private(
            x25519::StaticSecret::from(self.config.private_key),
            self.public,
            Some(Arc::clone(&self.rate_limiter)),
        );
        inner.peers[index].endpoint = None;
        inner.peers[index].last_activity = Instant::now();
        let keys: Vec<FlowKey> = inner
            .flows
            .keys()
            .filter(|key| key.peer == index)
            .cloned()
            .collect();
        for key in keys {
            remove_flow(inner, &key);
        }
    }

    fn local_ip(&self, remote: IpAddr) -> Option<IpAddr> {
        self.config
            .local_addresses
            .iter()
            .find_map(|network| match (network, remote) {
                (IpNet::V4(network), IpAddr::V4(_)) => Some(IpAddr::V4(network.addr())),
                (IpNet::V6(network), IpAddr::V6(_)) => Some(IpAddr::V6(network.addr())),
                _ => None,
            })
    }

    fn spawn_tcp_relay(self: &Arc<Self>, key: FlowKey) {
        let inner = self.inner.lock().unwrap_or_else(poisoned);
        let Some(entry) = inner.flows.get(&key).filter(|_| !inner.closed) else {
            return;
        };
        let cancel = entry.cancel.clone();
        let server = Arc::clone(self);
        let mut tasks = self.relays.lock().unwrap_or_else(poisoned);
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = run_tcp_relay(server, key, cancel.clone()) => {}
            }
        });
    }

    fn spawn_udp_relay(self: &Arc<Self>, key: FlowKey) {
        let inner = self.inner.lock().unwrap_or_else(poisoned);
        let Some(entry) = inner.flows.get(&key).filter(|_| !inner.closed) else {
            return;
        };
        let handle = entry.handle;
        let cancel = entry.cancel.clone();
        let server = Arc::clone(self);
        let mut tasks = self.relays.lock().unwrap_or_else(poisoned);
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = run_udp_relay(server, key, handle) => {}
            }
        });
    }

    fn take_udp(&self, key: &FlowKey, handle: SocketHandle) -> Result<Option<Vec<u8>>, ()> {
        let mut inner = self.inner.lock().unwrap_or_else(poisoned);
        if !inner.flows.contains_key(key) {
            return Err(());
        }
        let socket = inner.sockets.get_mut::<udp::Socket>(handle);
        let mut buffer = vec![0u8; UDP_BUFFER];
        match socket.recv_slice(&mut buffer) {
            Ok((length, _metadata)) => {
                buffer.truncate(length);
                if let Some(entry) = inner.flows.get_mut(key) {
                    entry.last_activity = Instant::now();
                }
                Ok(Some(buffer))
            }
            Err(_) => Ok(None),
        }
    }

    fn udp_reply(self: &Arc<Self>, key: &FlowKey, payload: &[u8]) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(poisoned);
        let handle = match inner.flows.get(key) {
            Some(entry) if entry.kind == NatKind::Udp => entry.handle,
            _ => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "UDP 关联已关闭")),
        };
        let client = key.source;
        {
            let socket = inner.sockets.get_mut::<udp::Socket>(handle);
            socket
                .send_slice(
                    payload,
                    IpEndpoint::new(to_smoltcp_ip(client.ip()), client.port()),
                )
                .map_err(|error| {
                    io::Error::other(format!("WireGuard UDP 回包入队失败: {error:?}"))
                })?;
        }
        if let Some(entry) = inner.flows.get_mut(key) {
            entry.last_activity = Instant::now();
        }
        let spawns = self.pump_stack(&mut inner);
        drop(inner);
        for key in spawns {
            self.spawn_tcp_relay(key);
        }
        Ok(())
    }

    fn release_flow(&self, key: &FlowKey) {
        let mut inner = self.inner.lock().unwrap_or_else(poisoned);
        remove_flow(&mut inner, key);
    }
}

fn new_tunn(
    config: &WireguardServerConfig,
    peer: &WireguardPeerConfig,
    slot: u32,
    rate_limiter: Arc<RateLimiter>,
) -> Tunn {
    Tunn::new(
        x25519::StaticSecret::from(config.private_key),
        x25519::PublicKey::from(peer.public_key),
        peer.preshared_key,
        peer.keepalive_secs.filter(|seconds| *seconds != 0),
        slot,
        Some(rate_limiter),
    )
}

fn allocate_port(inner: &mut Inner) -> Option<u16> {
    let span = u32::from(NAT_PORT_END) - u32::from(NAT_PORT_START) + 1;
    for _ in 0..span {
        let port = inner.next_port;
        inner.next_port = if port >= NAT_PORT_END {
            NAT_PORT_START
        } else {
            port + 1
        };
        if !inner.ports.contains_key(&port) {
            return Some(port);
        }
    }
    None
}

fn remove_flow(inner: &mut Inner, key: &FlowKey) {
    let Some(entry) = inner.flows.remove(key) else {
        return;
    };
    entry.cancel.cancel();
    inner.ports.remove(&entry.local_port);
    match entry.kind {
        NatKind::Tcp => inner.tcp_flows = inner.tcp_flows.saturating_sub(1),
        NatKind::Udp => inner.udp_flows = inner.udp_flows.saturating_sub(1),
    }
    // SocketSet::remove 不关心具体类型。
    let _ = inner.sockets.remove(entry.handle);
}

async fn run_tcp_relay(server: Arc<WireguardServer>, key: FlowKey, cancel: CancellationToken) {
    let target = key.destination;
    let outbound = match server.dialer.dial_tcp(target).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::debug!(?error, %target, "WireGuard 服务端 TCP 出站拨号失败");
            server.release_flow(&key);
            return;
        }
    };
    let tunnel = TunnelTcpStream {
        server: Arc::clone(&server),
        key: key.clone(),
        cancel,
        read_closed: false,
        write_closed: false,
    };
    if let Err(error) = server.dialer.relay_tcp(Box::new(tunnel), outbound).await {
        tracing::debug!(?error, %target, "WireGuard TCP relay 结束");
    }
}

async fn run_udp_relay(server: Arc<WireguardServer>, key: FlowKey, handle: SocketHandle) {
    let target = key.destination;
    let relay = match server.dialer.dial_udp(target).await {
        Ok(relay) => relay,
        Err(error) => {
            tracing::debug!(?error, %target, "WireGuard 服务端 UDP 出站拨号失败");
            server.release_flow(&key);
            return;
        }
    };
    let mut buffer = vec![0u8; UDP_BUFFER];
    loop {
        if server.is_closed() {
            break;
        }
        loop {
            match server.take_udp(&key, handle) {
                Ok(Some(payload)) => {
                    if relay.send(&payload).await.is_err() {
                        server.release_flow(&key);
                        return;
                    }
                }
                Ok(None) => break,
                Err(()) => return,
            }
        }
        match tokio::time::timeout(Duration::from_millis(5), relay.recv(&mut buffer)).await {
            Ok(Ok(length)) => {
                if server.udp_reply(&key, &buffer[..length]).is_err() {
                    break;
                }
            }
            Ok(Err(error)) => {
                tracing::debug!(?error, %target, "WireGuard UDP relay 接收失败");
                break;
            }
            Err(_) => {}
        }
    }
    server.release_flow(&key);
}

/// 以 smoltcp TCP socket 为底座的隧道内流。
struct TunnelTcpStream {
    server: Arc<WireguardServer>,
    key: FlowKey,
    cancel: CancellationToken,
    read_closed: bool,
    write_closed: bool,
}

impl TunnelTcpStream {
    fn wait(&self, context: &mut TaskContext<'_>, write: bool) -> Poll<io::Result<()>> {
        {
            let mut inner = self.server.inner.lock().unwrap_or_else(poisoned);
            if inner.closed || self.cancel.is_cancelled() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "WireGuard 服务端已关闭",
                )));
            }
            let Some(entry) = inner.flows.get(&self.key) else {
                return Poll::Ready(Ok(()));
            };
            let handle = entry.handle;
            let socket = inner.sockets.get_mut::<tcp::Socket>(handle);
            let ready = if write {
                socket.can_send() || !socket.may_send()
            } else {
                socket.can_recv() || !socket.may_recv()
            };
            if ready {
                drop(inner);
                let mut inner = self.server.inner.lock().unwrap_or_else(poisoned);
                let _ = self.server.pump_stack(&mut inner);
                return Poll::Ready(Ok(()));
            }
            inner.wakers.push(context.waker().clone());
        }
        // 驱动 tick/收包会唤醒等待者；不能在 Pending 路径自唤醒造成忙轮询。
        Poll::Pending
    }
}

impl AsyncRead for TunnelTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_closed || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match this.wait(context, false) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let mut inner = this.server.inner.lock().unwrap_or_else(poisoned);
                let Some(entry) = inner.flows.get(&this.key) else {
                    this.read_closed = true;
                    return Poll::Ready(Ok(()));
                };
                let handle = entry.handle;
                let socket = inner.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_recv() {
                    let length =
                        socket
                            .recv_slice(buffer.initialize_unfilled())
                            .map_err(|error| {
                                io::Error::other(format!("WireGuard 服务端读取失败: {error:?}"))
                            })?;
                    buffer.advance(length);
                    if let Some(entry) = inner.flows.get_mut(&this.key) {
                        entry.last_activity = Instant::now();
                    }
                } else {
                    this.read_closed = true;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for TunnelTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WireGuard 服务端 TCP 已关闭",
            )));
        }
        match this.wait(context, true) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let mut inner = this.server.inner.lock().unwrap_or_else(poisoned);
                let Some(entry) = inner.flows.get(&this.key) else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "WireGuard 服务端 TCP 已移除",
                    )));
                };
                let handle = entry.handle;
                let socket = inner.sockets.get_mut::<tcp::Socket>(handle);
                if !socket.may_send() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "WireGuard 隧道 TCP 写方向已关闭",
                    )));
                }
                match socket.send_slice(buffer) {
                    Ok(length) => {
                        if let Some(entry) = inner.flows.get_mut(&this.key) {
                            entry.last_activity = Instant::now();
                        }
                        let _ = this.server.pump_stack(&mut inner);
                        if length == 0 && !buffer.is_empty() {
                            inner.wakers.push(context.waker().clone());
                            Poll::Pending
                        } else {
                            Poll::Ready(Ok(length))
                        }
                    }
                    Err(_) => {
                        // 缓冲区满：注册 waker 后返回 Pending，由驱动重试。
                        inner.wakers.push(context.waker().clone());
                        drop(inner);
                        this.server.pump();
                        Poll::Pending
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.server.pump();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            this.write_closed = true;
            let mut inner = this.server.inner.lock().unwrap_or_else(poisoned);
            if !this.cancel.is_cancelled()
                && let Some(entry) = inner.flows.get(&this.key)
            {
                let handle = entry.handle;
                inner.sockets.get_mut::<tcp::Socket>(handle).close();
            }
            let _ = this.server.pump_stack(&mut inner);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for TunnelTcpStream {
    fn drop(&mut self) {
        // 同五元组可能已被重新分配；旧任务析构不能关闭新的关联。
        if !self.cancel.is_cancelled() {
            self.server.release_flow(&self.key);
        }
    }
}

impl WireguardServer {
    /// 推动一次协议栈（重传定时器、smoltcp、加密）。测试与 relay 内部使用。
    fn pump(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(poisoned);
        let _ = self.pump_stack(&mut inner);
    }
}

// ---------------------------------------------------------------------------
// IP / TCP / UDP 解析与 NAT 重写（非密码学；仅做地址与校验和计算）。
// ---------------------------------------------------------------------------

struct PacketInfo {
    protocol: u8,
    source: SocketAddr,
    destination: SocketAddr,
    tcp_syn: bool,
}

fn inspect_packet(packet: &[u8]) -> Option<PacketInfo> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20 || packet.len() < header {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total < header || total > packet.len() {
                return None;
            }
            // 拒绝分片：用户态终止无法安全重组。
            let fragment = u16::from_be_bytes([packet[6], packet[7]]);
            if fragment & 0x3fff != 0 {
                return None;
            }
            let protocol = packet[9];
            let source = IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            ));
            let destination = IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            ));
            ports(packet, header, protocol, source, destination)
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let protocol = packet[6];
            // 扩展头（含分片）一律拒绝，保持行为可预测。
            if !matches!(protocol, 6 | 17) {
                return None;
            }
            if 40 + payload > packet.len() {
                return None;
            }
            let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
            let destination =
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
            ports(packet, 40, protocol, source, destination)
        }
        _ => None,
    }
}

fn ports(
    packet: &[u8],
    offset: usize,
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
) -> Option<PacketInfo> {
    let (source_port, destination_port, tcp_syn) = match protocol {
        6 => {
            if packet.len() < offset + 20 {
                return None;
            }
            let flags = packet[offset + 13];
            (
                u16::from_be_bytes([packet[offset], packet[offset + 1]]),
                u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]),
                flags & 0x02 != 0 && flags & 0x10 == 0,
            )
        }
        17 => {
            if packet.len() < offset + 8 {
                return None;
            }
            (
                u16::from_be_bytes([packet[offset], packet[offset + 1]]),
                u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]),
                false,
            )
        }
        _ => return None,
    };
    Some(PacketInfo {
        protocol,
        source: SocketAddr::new(source, source_port),
        destination: SocketAddr::new(destination, destination_port),
        tcp_syn,
    })
}

fn rewrite_destination(packet: &mut [u8], new_ip: IpAddr, new_port: u16) -> bool {
    let Some(info) = inspect_packet(packet) else {
        return false;
    };
    let (offset, protocol) = match info.protocol {
        6 | 17 => match l4_offset(packet) {
            Some(value) => value,
            None => return false,
        },
        _ => return false,
    };
    match (packet[0] >> 4, new_ip) {
        (4, IpAddr::V4(address)) => {
            packet[16..20].copy_from_slice(&address.octets());
        }
        (6, IpAddr::V6(address)) => {
            packet[24..40].copy_from_slice(&address.octets());
        }
        _ => return false,
    }
    let port_offset = match protocol {
        6 => offset + 2,
        17 => offset + 2,
        _ => return false,
    };
    packet[port_offset..port_offset + 2].copy_from_slice(&new_port.to_be_bytes());
    recompute_checksums(packet)
}

fn rewrite_source(packet: &mut [u8], new_ip: IpAddr, new_port: u16) -> bool {
    let Some(info) = inspect_packet(packet) else {
        return false;
    };
    let (offset, protocol) = match info.protocol {
        6 | 17 => match l4_offset(packet) {
            Some(value) => value,
            None => return false,
        },
        _ => return false,
    };
    match (packet[0] >> 4, new_ip) {
        (4, IpAddr::V4(address)) => {
            packet[12..16].copy_from_slice(&address.octets());
        }
        (6, IpAddr::V6(address)) => {
            packet[8..24].copy_from_slice(&address.octets());
        }
        _ => return false,
    }
    let port_offset = match protocol {
        6 => offset,
        17 => offset,
        _ => return false,
    };
    packet[port_offset..port_offset + 2].copy_from_slice(&new_port.to_be_bytes());
    recompute_checksums(packet)
}

fn l4_offset(packet: &[u8]) -> Option<(usize, u8)> {
    match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            (header >= 20 && packet.len() >= header).then_some((header, packet[9]))
        }
        6 => (packet.len() >= 40).then_some((40, packet[6])),
        _ => None,
    }
}

/// NAT 改写前先校验原始报文，不能替客户端“修复”畸形 IP/L4 校验和。
pub(super) fn valid_packet_checksums(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let Some((offset, protocol)) = l4_offset(packet) else {
        return false;
    };
    let end = match packet[0] >> 4 {
        4 => {
            if fold_checksum(checksum_bytes(&packet[..offset])) != 0 {
                return false;
            }
            usize::from(u16::from_be_bytes([packet[2], packet[3]]))
        }
        6 => 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])),
        _ => return false,
    };
    if end > packet.len() || end < offset {
        return false;
    }
    match protocol {
        6 => {
            if end < offset + 20 {
                return false;
            }
            let header = usize::from(packet[offset + 12] >> 4) * 4;
            header >= 20
                && offset + header <= end
                && l4_checksum(packet, protocol, offset, end) == 0
        }
        17 => {
            if end < offset + 8 {
                return false;
            }
            let length = usize::from(u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]));
            if length < 8 || offset + length != end {
                return false;
            }
            let omitted = packet[offset + 6..offset + 8] == [0, 0];
            if omitted {
                packet[0] >> 4 == 4
            } else {
                l4_checksum(packet, protocol, offset, end) == 0
            }
        }
        _ => false,
    }
}

fn recompute_checksums(packet: &mut [u8]) -> bool {
    let Some((offset, protocol)) = l4_offset(packet) else {
        return false;
    };
    let end = match packet[0] >> 4 {
        4 => usize::from(u16::from_be_bytes([packet[2], packet[3]])),
        6 => 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])),
        _ => return false,
    };
    if end < offset || end > packet.len() {
        return false;
    }
    if packet[0] >> 4 == 4 {
        packet[10] = 0;
        packet[11] = 0;
        let header = checksum_bytes(&packet[..offset]);
        let value = fold_checksum(header);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
    }
    let checksum_offset = match protocol {
        6 => offset + 16,
        17 => offset + 6,
        _ => return false,
    };
    if packet.len() < checksum_offset + 2 {
        return false;
    }
    packet[checksum_offset] = 0;
    packet[checksum_offset + 1] = 0;
    let value = l4_checksum(packet, protocol, offset, end);
    let value = if protocol == 17 && value == 0 {
        0xffff
    } else {
        value
    };
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&value.to_be_bytes());
    true
}

fn l4_checksum(packet: &[u8], protocol: u8, offset: usize, end: usize) -> u16 {
    let length = end - offset;
    let mut sum = 0u32;
    if packet[0] >> 4 == 4 {
        sum += checksum_bytes(&packet[12..20]);
        sum += u32::from(protocol);
        sum += length as u32;
    } else {
        sum += checksum_bytes(&packet[8..40]);
        sum += length as u32;
        sum += u32::from(protocol);
    }
    sum += checksum_bytes(&packet[offset..end]);
    fold_checksum(sum)
}

fn checksum_bytes(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn to_smoltcp_ip(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => IpAddress::Ipv4(Ipv4Address::from(address.octets())),
        IpAddr::V6(address) => IpAddress::Ipv6(Ipv6Address::from(address.octets())),
    }
}

// ---------------------------------------------------------------------------
// CONFIG INTEGRATION（需要 `src/config.rs` / `src/runtime.rs` / `src/transport.rs`
// 的改动，本文件不修改这些公共模块）：
//
// 1. `src/transport.rs` 增加 `pub(crate) mod wireguard_server;`。
// 2. `src/config.rs` 新增服务端配置结构（建议命名 `WireguardServerOptions` /
//    `WireguardServerPeerOptions`），字段映射：
//      - private_key        -> WireguardServerConfig::private_key（base64 -> 32B）
//      - address            -> local_addresses（CIDR）
//      - peers[].public_key -> WireguardPeerConfig::public_key
//      - peers[].preshared_key -> preshared_key
//      - peers[].allowed_ips   -> allowed_ips（同时作为源地址 ACL）
//      - peers[].keepalive_secs-> keepalive_secs
//      - mtu / max_peers / max_tcp_connections / max_udp_associations /
//        max_queued_datagrams / max_handshake_inits_per_sec / peer_idle_timeout
//    校验应在 `Config::validate` 中做与 `WireguardServerConfig::validate` 等价的
//    失败关闭检查；密钥必须从配置解码后直接传入，不要写入日志。
// 3. `src/runtime.rs` 在服务端 inbound 启动路径中：
//      let socket = Arc::new(UdpSocket::bind(listen).await?);
//      let dialer: Arc<dyn OutboundDialer> = Arc::new(RouteDialer { ... });
//      let server = Arc::new(WireguardServer::new(socket, config, dialer)?);
//      server.spawn();
//    其中 `RouteDialer` 必须实现 `OutboundDialer`，把 `dial_tcp` / `dial_udp`
//    接入现有 route/outbound 逻辑（并执行路由策略、DNS、拒绝直连私网等）。
//    服务端生命周期/热重载由 runtime 持有 `Arc<WireguardServer>`，替换配置时
//    调用 `shutdown()` 并等待 join handle。
// 4. 出站方向（现有 `src/transport/wireguard.rs`）不受影响；本文件只提供
//    inbound 服务端核心。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener as TokioTcpListener, TcpStream, UdpSocket as TokioUdpSocket};

    const SERVER_SECRET: [u8; 32] = [7u8; 32];
    const CLIENT_SECRET: [u8; 32] = [9u8; 32];
    const OTHER_SECRET: [u8; 32] = [13u8; 32];

    fn public_of(secret: &[u8; 32]) -> [u8; 32] {
        x25519::PublicKey::from(&x25519::StaticSecret::from(*secret)).to_bytes()
    }

    fn base64_key(key: &[u8; 32]) -> String {
        base64::engine::general_purpose::STANDARD.encode(key)
    }

    struct LoopbackDialer {
        tcp: SocketAddr,
        udp: SocketAddr,
    }

    impl OutboundDialer for LoopbackDialer {
        fn dial_tcp(
            &self,
            _target: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn RelayTcp>>> + Send + '_>> {
            Box::pin(async move {
                let stream = TcpStream::connect(self.tcp).await?;
                Ok(Box::new(stream) as Box<dyn RelayTcp>)
            })
        }

        fn dial_udp(
            &self,
            _target: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn RelayUdp>>> + Send + '_>> {
            Box::pin(async move {
                let socket = TokioUdpSocket::bind("127.0.0.1:0").await?;
                socket.connect(self.udp).await?;
                Ok(Box::new(ConnectedUdpSocket(socket)) as Box<dyn RelayUdp>)
            })
        }
    }

    async fn spawn_tcp_echo() -> SocketAddr {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(length) => {
                                if stream.write_all(&buffer[..length]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        address
    }

    async fn spawn_udp_echo() -> SocketAddr {
        let socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                if socket.send_to(&buffer[..length], peer).await.is_err() {
                    return;
                }
            }
        });
        address
    }

    fn server_config(
        local: &str,
        peer_allowed: &str,
        peer_public: [u8; 32],
    ) -> WireguardServerConfig {
        let peer =
            WireguardPeerConfig::new(peer_public, vec![peer_allowed.parse::<IpNet>().unwrap()])
                .with_keepalive_secs(Some(2));
        let mut config =
            WireguardServerConfig::new(SERVER_SECRET, vec![local.parse::<IpNet>().unwrap()])
                .with_peer(peer);
        config.max_queued_datagrams = 128;
        config.peer_idle_timeout = Duration::from_secs(30);
        config
    }

    async fn start_server(
        config: WireguardServerConfig,
        tcp_echo: SocketAddr,
        udp_echo: SocketAddr,
    ) -> (
        Arc<WireguardServer>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dialer = Arc::new(LoopbackDialer {
            tcp: tcp_echo,
            udp: udp_echo,
        });
        let server = Arc::new(WireguardServer::new(socket, config, dialer).unwrap());
        let task = server.spawn();
        (server, task)
    }

    // ---- 测试用的最小 WireGuard 客户端（boringtun + smoltcp） ----

    struct TestClient {
        udp: TokioUdpSocket,
        server: SocketAddr,
        tunn: Tunn,
        interface: Interface,
        device: DeviceState,
        sockets: SocketSet<'static>,
        pending: VecDeque<Vec<u8>>,
        local_ip: IpAddress,
        next_port: u16,
    }

    impl TestClient {
        async fn new(secret: [u8; 32], local_cidr: &str, server: SocketAddr) -> Self {
            let network = local_cidr.parse::<IpNet>().unwrap();
            let local_ip = to_smoltcp_ip(network.addr());
            let mut device = DeviceState {
                mtu: 1420,
                rx: VecDeque::new(),
                tx: VecDeque::new(),
            };
            let mut interface = Interface::new(
                InterfaceConfig::new(HardwareAddress::Ip),
                &mut device,
                SmolInstant::now(),
            );
            interface.update_ip_addrs(|addresses| {
                addresses
                    .push(IpCidr::new(local_ip, network.prefix_len()))
                    .unwrap();
            });
            match network {
                IpNet::V4(network) => {
                    interface
                        .routes_mut()
                        .add_default_ipv4_route(Ipv4Address::from(network.addr().octets()))
                        .unwrap();
                }
                IpNet::V6(network) => {
                    interface
                        .routes_mut()
                        .add_default_ipv6_route(Ipv6Address::from(network.addr().octets()))
                        .unwrap();
                }
            }
            let tunn = Tunn::new(
                x25519::StaticSecret::from(secret),
                x25519::PublicKey::from(public_of(&SERVER_SECRET)),
                None,
                Some(2),
                0x42,
                None,
            );
            let udp = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
            Self {
                udp,
                server,
                tunn,
                interface,
                device,
                sockets: SocketSet::new(Vec::new()),
                pending: VecDeque::new(),
                local_ip,
                next_port: 40_000,
            }
        }

        fn pump(&mut self) -> io::Result<()> {
            let mut buffer = [0u8; DATAGRAM];
            loop {
                match self.udp.try_recv_from(&mut buffer) {
                    Ok((length, _)) => {
                        let mut scratch = [0u8; DATAGRAM];
                        let mut result =
                            self.tunn.decapsulate(None, &buffer[..length], &mut scratch);
                        loop {
                            match result {
                                TunnResult::Done | TunnResult::Err(_) => break,
                                TunnResult::WriteToNetwork(data) => {
                                    self.pending.push_back(data.to_vec());
                                    result = self.tunn.decapsulate(None, &[], &mut scratch);
                                }
                                TunnResult::WriteToTunnelV4(data, _)
                                | TunnResult::WriteToTunnelV6(data, _) => {
                                    self.device.rx.push_back(data.to_vec());
                                    result = self.tunn.decapsulate(None, &[], &mut scratch);
                                }
                            }
                        }
                    }
                    Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }

            let mut scratch = [0u8; DATAGRAM];
            if let TunnResult::WriteToNetwork(data) = self.tunn.update_timers(&mut scratch) {
                self.pending.push_back(data.to_vec());
            }

            let now = SmolInstant::now();
            self.interface
                .poll(now, &mut self.device, &mut self.sockets);

            while let Some(packet) = self.device.tx.pop_front() {
                let mut scratch = [0u8; DATAGRAM];
                if let TunnResult::WriteToNetwork(data) =
                    self.tunn.encapsulate(&packet, &mut scratch)
                {
                    self.pending.push_back(data.to_vec());
                }
            }

            while let Some(datagram) = self.pending.front() {
                match self.udp.try_send_to(datagram, self.server) {
                    Ok(_) => {
                        self.pending.pop_front();
                    }
                    Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }

        async fn spin<F>(&mut self, mut condition: F) -> io::Result<()>
        where
            F: FnMut(&Self) -> bool,
        {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                self.pump()?;
                if condition(self) {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "测试客户端等待超时",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        fn allocate_port(&mut self) -> u16 {
            let port = self.next_port;
            self.next_port = if self.next_port >= 60_000 {
                40_000
            } else {
                self.next_port + 1
            };
            port
        }

        async fn connect_tcp(&mut self, destination: SocketAddr) -> io::Result<SocketHandle> {
            let port = self.allocate_port();
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            );
            socket.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));
            socket
                .connect(
                    self.interface.context(),
                    IpEndpoint::new(to_smoltcp_ip(destination.ip()), destination.port()),
                    IpListenEndpoint {
                        addr: Some(self.local_ip),
                        port,
                    },
                )
                .map_err(|error| io::Error::other(format!("测试客户端 connect 失败: {error:?}")))?;
            let handle = self.sockets.add(socket);
            self.spin(|client| {
                matches!(
                    client.sockets.get::<tcp::Socket>(handle).state(),
                    tcp::State::Established
                )
            })
            .await?;
            Ok(handle)
        }

        async fn tcp_write_all(&mut self, handle: SocketHandle, mut data: &[u8]) -> io::Result<()> {
            while !data.is_empty() {
                self.pump()?;
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                if socket.may_send() {
                    match socket.send_slice(data) {
                        Ok(length) => data = &data[length..],
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
            // 推进协议栈，确保数据进入隧道并完成 UDP 发送。
            for _ in 0..3 {
                self.pump()?;
            }
            Ok(())
        }

        async fn tcp_read_exact(
            &mut self,
            handle: SocketHandle,
            output: &mut [u8],
        ) -> io::Result<()> {
            let mut filled = 0;
            let deadline = Instant::now() + Duration::from_secs(5);
            while filled < output.len() {
                self.pump()?;
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_recv() {
                    let length = socket.recv_slice(&mut output[filled..]).map_err(|error| {
                        io::Error::other(format!("测试客户端读取失败: {error:?}"))
                    })?;
                    filled += length;
                } else if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "测试客户端读取超时",
                    ));
                } else {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
            Ok(())
        }

        fn bind_udp(&mut self, port: u16) -> io::Result<SocketHandle> {
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; UDP_BUFFER]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; UDP_BUFFER]),
            );
            socket
                .bind(IpListenEndpoint {
                    addr: Some(self.local_ip),
                    port,
                })
                .map_err(|error| {
                    io::Error::other(format!("测试客户端 UDP bind 失败: {error:?}"))
                })?;
            Ok(self.sockets.add(socket))
        }

        fn send_udp(
            &mut self,
            handle: SocketHandle,
            destination: SocketAddr,
            payload: &[u8],
        ) -> io::Result<()> {
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            socket
                .send_slice(
                    payload,
                    IpEndpoint::new(to_smoltcp_ip(destination.ip()), destination.port()),
                )
                .map_err(|error| io::Error::other(format!("测试客户端 UDP 发送失败: {error:?}")))?;
            Ok(())
        }

        async fn recv_udp(&mut self, handle: SocketHandle) -> io::Result<Vec<u8>> {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                self.pump()?;
                let socket = self.sockets.get_mut::<udp::Socket>(handle);
                if socket.can_recv() {
                    let mut buffer = vec![0u8; 4096];
                    let (length, _) = socket.recv_slice(&mut buffer).map_err(|error| {
                        io::Error::other(format!("测试客户端 UDP 读取失败: {error:?}"))
                    })?;
                    buffer.truncate(length);
                    return Ok(buffer);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "测试客户端 UDP 读取超时",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        fn force_handshake(&mut self) {
            let mut scratch = [0u8; DATAGRAM];
            if let TunnResult::WriteToNetwork(data) =
                self.tunn.format_handshake_initiation(&mut scratch, true)
            {
                self.pending.push_back(data.to_vec());
            }
        }
    }

    async fn wait_for_stats<F>(server: &Arc<WireguardServer>, mut predicate: F)
    where
        F: FnMut(&WireguardServerStats) -> bool,
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if predicate(&server.stats()) {
                return;
            }
            if Instant::now() >= deadline {
                panic!("等待服务端统计超时: {:?}", server.stats());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn tcp_echo_over_ipv4_tunnel() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let (server, task) = start_server(
            server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
            tcp_echo,
            udp_echo,
        )
        .await;
        let server_addr = server.local_addr().unwrap();

        let mut client = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let handle = client
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        client
            .tcp_write_all(handle, b"hello wireguard")
            .await
            .unwrap();
        let mut reply = [0u8; 15];
        client.tcp_read_exact(handle, &mut reply).await.unwrap();
        assert_eq!(&reply, b"hello wireguard");

        wait_for_stats(&server, |stats| stats.completed_handshakes >= 1).await;
        assert!(server.stats().tcp_connections >= 1);
        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn udp_echo_over_ipv4_tunnel() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let (server, task) = start_server(
            server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
            tcp_echo,
            udp_echo,
        )
        .await;
        let server_addr = server.local_addr().unwrap();

        let mut client = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let handle = client.bind_udp(55_555).unwrap();
        client
            .send_udp(handle, "10.66.0.1:9999".parse().unwrap(), b"ping")
            .unwrap();
        let reply = client.recv_udp(handle).await.unwrap();
        assert_eq!(&reply, b"ping");
        assert!(server.stats().udp_associations >= 1);

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn tcp_echo_over_ipv6_tunnel() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let (server, task) = start_server(
            server_config("fd00::1/64", "fd00::2/128", public_of(&CLIENT_SECRET)),
            tcp_echo,
            udp_echo,
        )
        .await;
        let server_addr = server.local_addr().unwrap();

        let mut client = TestClient::new(CLIENT_SECRET, "fd00::2/64", server_addr).await;
        let handle = client
            .connect_tcp("[fd00::1]:8080".parse().unwrap())
            .await
            .unwrap();
        client.tcp_write_all(handle, b"ipv6 hello").await.unwrap();
        let mut reply = [0u8; 10];
        client.tcp_read_exact(handle, &mut reply).await.unwrap();
        assert_eq!(&reply, b"ipv6 hello");

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn udp_associations_are_bounded_and_reused() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let mut config = server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET));
        config.max_udp_associations = 1;
        let (server, task) = start_server(config, tcp_echo, udp_echo).await;
        let server_addr = server.local_addr().unwrap();

        let mut client = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let handle = client.bind_udp(55_555).unwrap();
        for _ in 0..3 {
            client
                .send_udp(handle, "10.66.0.1:9999".parse().unwrap(), b"ping")
                .unwrap();
            assert_eq!(client.recv_udp(handle).await.unwrap(), b"ping");
        }
        assert_eq!(server.stats().udp_associations, 1);

        // 第二条关联超过上限，必须失败关闭且不影响已有流。
        client
            .send_udp(handle, "10.66.0.1:9998".parse().unwrap(), b"other")
            .unwrap();
        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline {
            client.pump().unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(server.stats().udp_associations, 1);
        assert!(server.stats().dropped_datagrams >= 1);

        client
            .send_udp(handle, "10.66.0.1:9999".parse().unwrap(), b"again")
            .unwrap();
        assert_eq!(client.recv_udp(handle).await.unwrap(), b"again");

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn malformed_datagrams_fail_closed() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let (server, task) = start_server(
            server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
            tcp_echo,
            udp_echo,
        )
        .await;
        let server_addr = server.local_addr().unwrap();

        let sender = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(&[0u8; 3], server_addr).await.unwrap();
        sender.send_to(&[1u8, 0, 0, 0], server_addr).await.unwrap();
        sender.send_to(&[4u8; 31], server_addr).await.unwrap();
        wait_for_stats(&server, |stats| stats.invalid_packets >= 3).await;
        assert_eq!(server.stats().completed_handshakes, 0);

        // 服务端仍可服务合法客户端。
        let mut client = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let tcp = client
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        client.tcp_write_all(tcp, b"ok").await.unwrap();
        let mut reply = [0u8; 2];
        client.tcp_read_exact(tcp, &mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn idle_peer_is_expired_and_can_rehandshake() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let mut config = server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET));
        config.peer_idle_timeout = Duration::from_secs(1);
        let (server, task) = start_server(config, tcp_echo, udp_echo).await;
        let server_addr = server.local_addr().unwrap();

        let mut client = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let tcp = client
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        client.tcp_write_all(tcp, b"one").await.unwrap();
        let mut reply = [0u8; 3];
        client.tcp_read_exact(tcp, &mut reply).await.unwrap();
        wait_for_stats(&server, |stats| stats.completed_handshakes >= 1).await;

        // 停止客户端活动，等待 peer idle 清理。
        wait_for_stats(&server, |stats| stats.expired_peers >= 1).await;

        // 新客户端重新握手后仍可建立 TCP。
        let mut fresh = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let tcp = fresh
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        fresh.tcp_write_all(tcp, b"two").await.unwrap();
        let mut reply = [0u8; 3];
        fresh.tcp_read_exact(tcp, &mut reply).await.unwrap();

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn multiple_peers_use_independent_sessions() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let mut config =
            WireguardServerConfig::new(SERVER_SECRET, vec!["10.66.0.1/24".parse().unwrap()])
                .with_peer(WireguardPeerConfig::new(
                    public_of(&CLIENT_SECRET),
                    vec!["10.66.0.2/32".parse().unwrap()],
                ))
                .with_peer(WireguardPeerConfig::new(
                    public_of(&OTHER_SECRET),
                    vec!["10.66.0.3/32".parse().unwrap()],
                ));
        config.peer_idle_timeout = Duration::from_secs(30);
        let (server, task) = start_server(config, tcp_echo, udp_echo).await;
        let server_addr = server.local_addr().unwrap();

        let mut first = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let mut second = TestClient::new(OTHER_SECRET, "10.66.0.3/24", server_addr).await;
        let first_tcp = first
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        let second_tcp = second
            .connect_tcp("10.66.0.1:8081".parse().unwrap())
            .await
            .unwrap();

        first.tcp_write_all(first_tcp, b"peer-a").await.unwrap();
        second.tcp_write_all(second_tcp, b"peer-b").await.unwrap();
        let mut reply = [0u8; 6];
        first.tcp_read_exact(first_tcp, &mut reply).await.unwrap();
        assert_eq!(&reply, b"peer-a");
        second.tcp_read_exact(second_tcp, &mut reply).await.unwrap();
        assert_eq!(&reply, b"peer-b");

        wait_for_stats(&server, |stats| stats.completed_handshakes >= 2).await;
        assert!(server.stats().tcp_connections >= 2);

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn unknown_peer_handshake_is_dropped() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let (server, task) = start_server(
            server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
            tcp_echo,
            udp_echo,
        )
        .await;
        let server_addr = server.local_addr().unwrap();

        let attacker_udp = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut attacker = Tunn::new(
            x25519::StaticSecret::from(OTHER_SECRET),
            x25519::PublicKey::from(public_of(&SERVER_SECRET)),
            None,
            None,
            0x99,
            None,
        );
        let mut scratch = [0u8; DATAGRAM];
        let TunnResult::WriteToNetwork(init) =
            attacker.format_handshake_initiation(&mut scratch, false)
        else {
            panic!("未生成握手初始化");
        };
        attacker_udp.send_to(init, server_addr).await.unwrap();

        wait_for_stats(&server, |stats| stats.unknown_peers >= 1).await;
        assert_eq!(server.stats().completed_handshakes, 0);

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn replayed_handshake_is_rejected_and_traffic_continues() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let (server, task) = start_server(
            server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
            tcp_echo,
            udp_echo,
        )
        .await;
        let server_addr = server.local_addr().unwrap();

        // 用同一身份通过独立 socket 发送一次 init，并保存字节用于重放。
        let replay_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut replay_tun = Tunn::new(
            x25519::StaticSecret::from(CLIENT_SECRET),
            x25519::PublicKey::from(public_of(&SERVER_SECRET)),
            None,
            None,
            0x77,
            None,
        );
        let mut scratch = [0u8; DATAGRAM];
        let TunnResult::WriteToNetwork(init) =
            replay_tun.format_handshake_initiation(&mut scratch, false)
        else {
            panic!("未生成握手初始化");
        };
        let init = init.to_vec();
        replay_socket.send_to(&init, server_addr).await.unwrap();
        wait_for_stats(&server, |stats| stats.completed_handshakes >= 1).await;

        let before = server.stats().invalid_packets;
        replay_socket.send_to(&init, server_addr).await.unwrap();
        wait_for_stats(&server, |stats| stats.invalid_packets > before).await;

        // 正常客户端仍能建立连接与收发。
        let mut client = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let handle = client
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        client.tcp_write_all(handle, b"still alive").await.unwrap();
        let mut reply = [0u8; 11];
        client.tcp_read_exact(handle, &mut reply).await.unwrap();
        assert_eq!(&reply, b"still alive");

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[tokio::test]
    async fn idle_cleanup_keeps_handshake_replay_high_water_mark() {
        let echo = spawn_tcp_echo().await;
        let (server, task) = start_server(
            server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
            echo,
            spawn_udp_echo().await,
        )
        .await;
        let socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut initiator = Tunn::new(
            x25519::StaticSecret::from(CLIENT_SECRET),
            x25519::PublicKey::from(public_of(&SERVER_SECRET)),
            None,
            None,
            0x77,
            None,
        );
        let mut scratch = vec![0u8; DATAGRAM];
        let TunnResult::WriteToNetwork(init) =
            initiator.format_handshake_initiation(&mut scratch, false)
        else {
            panic!("缺少握手初始化")
        };
        let init = init.to_vec();
        socket
            .send_to(&init, server.local_addr().unwrap())
            .await
            .unwrap();
        wait_for_stats(&server, |stats| stats.completed_handshakes == 1).await;
        {
            let mut inner = server.inner.lock().unwrap_or_else(poisoned);
            server.reset_peer(&mut inner, 0);
        }
        let invalid = server.stats().invalid_packets;
        socket
            .send_to(&init, server.local_addr().unwrap())
            .await
            .unwrap();
        wait_for_stats(&server, |stats| stats.invalid_packets > invalid).await;
        assert_eq!(
            server.stats().completed_handshakes,
            1,
            "空闲清理不能重新接受旧 init"
        );
        server.shutdown();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn tcp_client_half_close_still_receives_response() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request-until-fin");
            stream.write_all(b"response-after-fin").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let (server, task) = start_server(
            server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
            target,
            spawn_udp_echo().await,
        )
        .await;
        let mut client =
            TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server.local_addr().unwrap()).await;
        let stream = client
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        client
            .tcp_write_all(stream, b"request-until-fin")
            .await
            .unwrap();
        client.sockets.get_mut::<tcp::Socket>(stream).close();
        let mut response = [0u8; 18];
        client.tcp_read_exact(stream, &mut response).await.unwrap();
        assert_eq!(&response, b"response-after-fin");
        responder.await.unwrap();
        server.shutdown();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_cancels_pending_dials_and_joins_children() {
        struct PendingDialer(Arc<std::sync::atomic::AtomicUsize>);
        struct Active(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        impl OutboundDialer for PendingDialer {
            fn dial_tcp(
                &self,
                _: SocketAddr,
            ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn RelayTcp>>> + Send + '_>>
            {
                Box::pin(async {
                    self.0.fetch_add(1, Ordering::SeqCst);
                    let _active = Active(self.0.clone());
                    std::future::pending().await
                })
            }
            fn dial_udp(
                &self,
                _: SocketAddr,
            ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn RelayUdp>>> + Send + '_>>
            {
                Box::pin(async {
                    self.0.fetch_add(1, Ordering::SeqCst);
                    let _active = Active(self.0.clone());
                    std::future::pending().await
                })
            }
        }
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server = Arc::new(
            WireguardServer::new(
                socket,
                server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
                Arc::new(PendingDialer(active.clone())),
            )
            .unwrap(),
        );
        let task = server.spawn();
        let address = server.local_addr().unwrap();
        let mut client = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", address).await;
        let _tcp = client
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        let udp = client.bind_udp(40_100).unwrap();
        client
            .send_udp(udp, "10.66.0.1:8081".parse().unwrap(), b"pending")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while active.load(Ordering::SeqCst) != 2 {
                client.pump().unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        server.shutdown();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(server.relays.lock().unwrap_or_else(poisoned).is_empty());
        assert_eq!(server.stats().tcp_connections, 0);
        assert_eq!(server.stats().udp_associations, 0);
        drop(server);
        UdpSocket::bind(address)
            .await
            .expect("停机后应释放监听端口");
    }

    #[test]
    fn packet_validation_rejects_corruption_before_nat() {
        let good = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(10, 66, 0, 1),
            40_000,
            80,
            0x02,
        );
        assert!(valid_packet_checksums(&good));
        let mut bad = good.clone();
        bad[8] ^= 1;
        assert!(!valid_packet_checksums(&bad), "错误 IPv4 头校验和");
        let mut bad = good;
        bad[24] ^= 1;
        assert!(!valid_packet_checksums(&bad), "错误 TCP 校验和");
        let mut bad = build_ipv6_udp_packet(
            "fd00::2".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            40_000,
            53,
        );
        assert!(valid_packet_checksums(&bad));
        bad[46..48].fill(0);
        assert!(!valid_packet_checksums(&bad), "IPv6 UDP 不能省略校验和");
    }

    #[tokio::test]
    async fn session_rekey_keeps_tcp_connection_working() {
        let tcp_echo = spawn_tcp_echo().await;
        let udp_echo = spawn_udp_echo().await;
        let (server, task) = start_server(
            server_config("10.66.0.1/24", "10.66.0.2/32", public_of(&CLIENT_SECRET)),
            tcp_echo,
            udp_echo,
        )
        .await;
        let server_addr = server.local_addr().unwrap();

        let mut client = TestClient::new(CLIENT_SECRET, "10.66.0.2/24", server_addr).await;
        let handle = client
            .connect_tcp("10.66.0.1:8080".parse().unwrap())
            .await
            .unwrap();
        client.tcp_write_all(handle, b"first").await.unwrap();
        let mut reply = [0u8; 5];
        client.tcp_read_exact(handle, &mut reply).await.unwrap();
        assert_eq!(&reply, b"first");
        wait_for_stats(&server, |stats| stats.completed_handshakes >= 1).await;

        // 强制一轮新的握手，boringtun 会分配新的接收索引并轮换密钥。
        client.force_handshake();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            client.pump().unwrap();
            if server.stats().completed_handshakes >= 2 {
                break;
            }
            if Instant::now() >= deadline {
                panic!("等待重新握手超时: {:?}", server.stats());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        client.tcp_write_all(handle, b"second").await.unwrap();
        let mut reply = [0u8; 6];
        client.tcp_read_exact(handle, &mut reply).await.unwrap();
        assert_eq!(&reply, b"second");

        server.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    #[test]
    fn config_rejects_unbounded_or_invalid_values() {
        let public = public_of(&CLIENT_SECRET);
        let peer = WireguardPeerConfig::new(public, vec!["10.0.0.2/32".parse().unwrap()]);
        let duplicate = peer.clone();
        let config =
            WireguardServerConfig::new(SERVER_SECRET, vec!["10.0.0.1/24".parse().unwrap()])
                .with_peer(peer)
                .with_peer(duplicate);
        assert_eq!(
            WireguardServerConfig::validate(&config).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let mut empty = WireguardServerConfig::new(SERVER_SECRET, Vec::new());
        assert!(empty.validate().is_err());
        empty.local_addresses.push("10.0.0.1/24".parse().unwrap());

        let mut too_many = empty.clone();
        too_many.max_peers = 1;
        too_many.peers.push(WireguardPeerConfig::new(
            public_of(&CLIENT_SECRET),
            vec!["10.0.0.2/32".parse().unwrap()],
        ));
        too_many.peers.push(WireguardPeerConfig::new(
            public_of(&OTHER_SECRET),
            vec!["10.0.0.3/32".parse().unwrap()],
        ));
        assert!(too_many.validate().is_err());

        let mut zero_queue = empty;
        zero_queue.max_queued_datagrams = 0;
        assert!(zero_queue.validate().is_err());
    }

    #[test]
    fn base64_key_parser_matches_boringtun_shape() {
        let encoded = base64_key(&CLIENT_SECRET);
        assert_eq!(parse_base64_key(&encoded).unwrap(), CLIENT_SECRET);
        assert!(parse_base64_key("not base64").is_err());
        assert!(
            parse_base64_key(&base64::engine::general_purpose::STANDARD.encode([0u8; 3])).is_err()
        );
    }

    #[test]
    fn ip_rewrites_recompute_checksums() {
        // 手工构造一个 IPv4/TCP SYN 报文并做双向重写。
        let mut packet = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 66, 0, 2),
            Ipv4Addr::new(93, 184, 216, 34),
            40_000,
            80,
            0x02,
        );
        assert!(rewrite_destination(
            &mut packet,
            "10.66.0.1".parse().unwrap(),
            49_152
        ));
        let info = inspect_packet(&packet).unwrap();
        assert_eq!(info.destination, "10.66.0.1:49152".parse().unwrap());
        let checksum = u16::from_be_bytes([packet[36], packet[37]]);
        assert_ne!(checksum, 0);
        assert!(rewrite_source(
            &mut packet,
            "93.184.216.34".parse().unwrap(),
            80
        ));
        let info = inspect_packet(&packet).unwrap();
        assert_eq!(info.source, "93.184.216.34:80".parse().unwrap());

        // IPv6/UDP 版本。
        let mut packet = build_ipv6_udp_packet(
            "fd00::2".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            50_000,
            443,
        );
        assert!(rewrite_destination(
            &mut packet,
            "fd00::1".parse().unwrap(),
            49_153
        ));
        assert!(rewrite_source(&mut packet, "fd00::1".parse().unwrap(), 443));
        let checksum = u16::from_be_bytes([packet[46], packet[47]]);
        assert_ne!(checksum, 0);
    }

    fn build_ipv4_tcp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        let _ = recompute_checksums(&mut packet);
        packet
    }

    fn build_ipv6_udp_packet(
        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        let IpAddr::V6(source) = source else {
            panic!("需要 IPv6 源");
        };
        let IpAddr::V6(destination) = destination else {
            panic!("需要 IPv6 目的");
        };
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&8u16.to_be_bytes());
        let _ = recompute_checksums(&mut packet);
        packet
    }
}
