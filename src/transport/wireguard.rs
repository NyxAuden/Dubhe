//! WireGuard 出站：boringtun 负责 Noise 握手与数据封装，smoltcp 提供
//! 用户态 IPv4/IPv6 与 TCP 栈。
//!
//! 本模块只作为**出站**：内核 TCP 连接映射为一条经隧道传输的 smoltcp TCP
//! 连接；UDP 使用同一用户态栈中的独立固定目标 socket，保持数据报边界。

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::config::WireguardOptions;
use crate::forward::{Context, Upstream};
use crate::session::Target;

/// 单个隧道内 TCP 连接的收发缓冲。
const TCP_BUFFER: usize = 64 * 1024;
/// boringtun 明文/密文缓冲上限：最大 UDP 载荷加封装开销。
const DATAGRAM: usize = 65_535 + 64;
/// 隧道内 TCP socket 的空闲/重传上限。
const TCP_TIMEOUT_MS: u64 = 60_000;
const MAX_TUNNEL_QUEUE: usize = 256;

/// WireGuard 出站的已校验运行期配置。
#[derive(Clone)]
pub(crate) struct WireguardConfig {
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    addresses: Vec<IpCidr>,
    mtu: usize,
    keepalive: Option<u16>,
}

impl std::fmt::Debug for WireguardConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireguardConfig")
            .field("addresses", &self.addresses)
            .field("mtu", &self.mtu)
            .field("keepalive", &self.keepalive)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl WireguardConfig {
    /// 解析并校验配置；密钥、地址与 MTU 的格式检查已在 `Config::validate`
    /// 完成，这里仍失败关闭，避免库调用方绕过校验。
    pub(crate) fn parse(options: &WireguardOptions) -> Result<Self> {
        let private_key = crate::config::parse_wireguard_key(&options.private_key)
            .ok_or_else(|| anyhow!("wireguard private_key 必须是 32 字节 base64"))?;
        let peer_public_key = crate::config::parse_wireguard_key(&options.peer_public_key)
            .ok_or_else(|| anyhow!("wireguard peer_public_key 必须是 32 字节 base64"))?;
        let preshared_key = match &options.preshared_key {
            Some(key) => Some(
                crate::config::parse_wireguard_key(key)
                    .ok_or_else(|| anyhow!("wireguard preshared_key 必须是 32 字节 base64"))?,
            ),
            None => None,
        };
        let mut addresses = Vec::with_capacity(options.address.len());
        for value in &options.address {
            let network: ipnet::IpNet = value
                .parse()
                .map_err(|_| anyhow!("wireguard address {value} 不是有效 CIDR"))?;
            addresses.push(IpCidr::new(
                to_smoltcp_ip(network.addr()),
                network.prefix_len(),
            ));
        }
        ensure!(
            !addresses.is_empty() && addresses.len() <= smoltcp::config::IFACE_MAX_ADDR_COUNT,
            "wireguard address 数量超过当前用户态接口容量"
        );
        let mtu = options.mtu.unwrap_or(1420) as usize;
        ensure!((576..=1500).contains(&mtu), "wireguard mtu 超出范围");
        let keepalive = options.keepalive_secs.filter(|seconds| *seconds != 0);
        Ok(Self {
            private_key,
            peer_public_key,
            preshared_key,
            addresses,
            mtu,
            keepalive,
        })
    }
}

/// 一个 `wireguard` 出站的共享运行期状态。
pub(crate) struct WireguardOutbound {
    config: Arc<WireguardConfig>,
    peer: Target,
    stack: tokio::sync::OnceCell<Arc<Stack>>,
}

impl WireguardOutbound {
    pub(crate) fn new(config: WireguardConfig, peer: Target) -> Self {
        Self {
            config: Arc::new(config),
            peer,
            stack: tokio::sync::OnceCell::new(),
        }
    }

    /// 建立到目标的一条隧道内 TCP 连接。
    pub(crate) async fn connect(&self, context: &Context, target: &Target) -> io::Result<Upstream> {
        let stack = self.stack(context).await?;
        let remote = context.dns.resolve(target).await?;
        let address = remote
            .iter()
            .copied()
            .find(|address| stack.supports(address.ip()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "目标地址与隧道地址族不匹配",
                )
            })?;
        let stream = stack.connect(address).await?;
        Ok(Upstream::new(Box::new(stream), None))
    }

    pub(crate) async fn open_udp(
        &self,
        context: &Context,
        target: &Target,
    ) -> io::Result<Box<dyn super::tunnel_udp::DatagramSession>> {
        let stack = self.stack(context).await?;
        stack
            .wait_handshake(Duration::from_millis(context.limits.dial_timeout_ms))
            .await?;
        let remote = context
            .dns
            .resolve(target)
            .await?
            .into_iter()
            .find(|address| stack.supports(address.ip()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "WireGuard UDP 地址族不匹配",
                )
            })?;
        let local = stack.local_ip(remote.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "WireGuard UDP 缺少本地地址",
            )
        })?;
        Ok(Box::new(super::tunnel_udp::Session::open(
            stack,
            local,
            remote,
            self.config.mtu,
        )?))
    }

    /// 首次使用时解析对端并建立 UDP/隧道驱动；失败可从 `OnceCell` 重试。
    async fn stack(&self, context: &Context) -> io::Result<Arc<Stack>> {
        self.stack
            .get_or_try_init(|| async {
                let peer = context.dns.resolve(&self.peer).await?;
                // 外层 UDP 的 IP 族与隧道内 IP 族相互独立。
                let address = peer.iter().copied().next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "wireguard 对端地址族无匹配的本地地址",
                    )
                })?;
                Stack::start(self.config.clone(), Some(address), None).await
            })
            .await
            .cloned()
    }
}

impl std::fmt::Debug for WireguardOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireguardOutbound")
            .field("peer", &self.peer)
            .field("config", &self.config)
            .finish()
    }
}

/// smoltcp 的 IP 报文收发队列。`Medium::Ip` 不涉及链路层地址。
struct DeviceState {
    mtu: usize,
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl DeviceState {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
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
        if self.tx.len() >= MAX_TUNNEL_QUEUE {
            return None;
        }
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

/// smoltcp 接口与所有隧道内 socket 的共享状态。
struct Inner {
    tunn: Tunn,
    interface: Interface,
    device: DeviceState,
    sockets: SocketSet<'static>,
    wakers: Vec<Waker>,
    closed: bool,
}

/// 一条 WireGuard UDP 隧道及其用户态 TCP 栈。
struct Stack {
    config: Arc<WireguardConfig>,
    /// UDP 对端；服务端测试模式在收到首个报文时学习。
    peer: Mutex<Option<SocketAddr>>,
    udp: Arc<UdpSocket>,
    inner: Mutex<Inner>,
    pending: Mutex<VecDeque<Vec<u8>>>,
    notify: Notify,
    next_port: AtomicU16,
}

impl super::tunnel_udp::UdpStack for Stack {
    fn with_sockets<R>(&self, action: impl FnOnce(&mut SocketSet<'static>) -> R) -> io::Result<R> {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if inner.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WireGuard 隧道已关闭",
            ));
        }
        Ok(action(&mut inner.sockets))
    }
    fn pump_udp(&self) {
        self.pump();
    }
}

impl Stack {
    async fn start(
        config: Arc<WireguardConfig>,
        peer: Option<SocketAddr>,
        bind: Option<SocketAddr>,
    ) -> io::Result<Arc<Self>> {
        let bind = bind.unwrap_or_else(|| match peer {
            Some(peer) if peer.is_ipv6() => "[::]:0".parse().expect("IPv6 通配地址"),
            _ => "0.0.0.0:0".parse().expect("IPv4 通配地址"),
        });
        let udp = Arc::new(UdpSocket::bind(bind).await?);
        let tunn = Tunn::new(
            x25519::StaticSecret::from(config.private_key),
            x25519::PublicKey::from(config.peer_public_key),
            config.preshared_key,
            config.keepalive,
            random_index(),
            None,
        );
        let mut device = DeviceState::new(config.mtu);
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::now(),
        );
        interface.update_ip_addrs(|addresses| {
            for address in &config.addresses {
                addresses.push(*address).expect("接口地址上限");
            }
        });
        // `Medium::Ip` 不使用网关做链路层解析；默认路由只为让非本地目标
        // 不因缺少路由而被丢弃。
        if let Some(address) = config.addresses.iter().find_map(|address| match address {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            IpCidr::Ipv6(_) => None,
        }) {
            let _ = interface.routes_mut().add_default_ipv4_route(address);
        }
        if let Some(address) = config.addresses.iter().find_map(|address| match address {
            IpCidr::Ipv6(cidr) => Some(cidr.address()),
            IpCidr::Ipv4(_) => None,
        }) {
            let _ = interface.routes_mut().add_default_ipv6_route(address);
        }
        let stack = Arc::new(Self {
            config,
            peer: Mutex::new(peer),
            udp,
            inner: Mutex::new(Inner {
                tunn,
                interface,
                device,
                sockets: SocketSet::new(Vec::new()),
                wakers: Vec::new(),
                closed: false,
            }),
            pending: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            next_port: AtomicU16::new(49_152),
        });
        let weak = Arc::downgrade(&stack);
        let shared = Arc::clone(&stack);
        tokio::spawn(async move { shared.drive(weak).await });
        Ok(stack)
    }

    async fn wait_handshake(&self, duration: Duration) -> io::Result<()> {
        let deadline = Instant::now() + duration;
        loop {
            let initiation = {
                let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
                if inner.closed {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "WireGuard 隧道关闭",
                    ));
                }
                if inner.tunn.stats().0.is_some() {
                    return Ok(());
                }
                let mut scratch = vec![0u8; DATAGRAM];
                match inner.tunn.format_handshake_initiation(&mut scratch, false) {
                    TunnResult::WriteToNetwork(data) => Some(data.to_vec()),
                    _ => None,
                }
            };
            if let Some(initiation) = initiation {
                self.pending
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push_back(initiation);
                self.notify.notify_one();
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "WireGuard UDP 握手超时",
                ));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[cfg(test)]
    fn local_udp_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    fn supports(&self, address: IpAddr) -> bool {
        self.config
            .addresses
            .iter()
            .any(|cidr| same_family(address, cidr))
    }

    /// 隧道内本地地址（同地址族的第一条）。
    fn local_ip(&self, remote: IpAddr) -> Option<IpAddr> {
        self.config
            .addresses
            .iter()
            .find_map(|cidr| match (remote, cidr) {
                (IpAddr::V4(_), IpCidr::Ipv4(network)) => {
                    Some(IpAddr::V4(network.address().octets().into()))
                }
                (IpAddr::V6(_), IpCidr::Ipv6(network)) => {
                    Some(IpAddr::V6(network.address().octets().into()))
                }
                _ => None,
            })
    }

    async fn connect(self: &Arc<Self>, remote: SocketAddr) -> io::Result<WireguardStream> {
        let local_ip = self.local_ip(remote.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "隧道没有匹配地址族的 address",
            )
        })?;
        let port = self.allocate_port();
        let handle = {
            let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            );
            let timeout = smoltcp::time::Duration::from_millis(TCP_TIMEOUT_MS);
            socket.set_timeout(Some(timeout));
            socket.set_keep_alive(Some(timeout));
            socket
                .connect(
                    inner.interface.context(),
                    smoltcp::wire::IpEndpoint::new(to_smoltcp_ip(remote.ip()), remote.port()),
                    smoltcp::wire::IpListenEndpoint {
                        addr: Some(to_smoltcp_ip(local_ip)),
                        port,
                    },
                )
                .map_err(|error| io::Error::other(format!("wireguard TCP 连接失败: {error:?}")))?;
            inner.sockets.add(socket)
        };
        self.pump();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            {
                let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
                let socket = inner.sockets.get_mut::<tcp::Socket>(handle);
                match socket.state() {
                    tcp::State::Established => break,
                    tcp::State::Closed => {
                        inner.sockets.remove(handle);
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "wireguard 目标拒绝连接",
                        ));
                    }
                    _ => {}
                }
            }
            if Instant::now() >= deadline {
                let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
                inner.sockets.remove(handle);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "wireguard TCP 握手超时",
                ));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            self.pump();
        }
        Ok(WireguardStream {
            stack: Arc::clone(self),
            handle,
            closed: false,
        })
    }

    fn allocate_port(&self) -> u16 {
        let mut port = self.next_port.fetch_add(1, Ordering::Relaxed);
        if port < 1024 {
            self.next_port.store(49_152, Ordering::Relaxed);
            port = 49_152;
        }
        port
    }

    /// 推进一次协议栈：处理定时器、收发隧道报文、轮询 TCP。
    fn pump(&self) {
        let (sends, wakers) = {
            let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
            if inner.closed {
                return;
            }
            let Inner {
                tunn,
                interface,
                device,
                sockets,
                wakers,
                ..
            } = &mut *inner;
            let mut sends = Vec::new();
            // 先让 boringtun 处理排队报文/重传定时器。
            drain_tunn(tunn, device, &mut sends);
            let now = SmolInstant::now();
            interface.poll(now, device, sockets);
            // 加密 smoltcp 产生的 IP 报文。
            let mut scratch = [0u8; DATAGRAM];
            while let Some(packet) = device.tx.pop_front() {
                if let TunnResult::WriteToNetwork(data) = tunn.encapsulate(&packet, &mut scratch) {
                    sends.push(data.to_vec());
                }
                drain_tunn(tunn, device, &mut sends);
            }
            if let TunnResult::WriteToNetwork(data) = tunn.update_timers(&mut scratch) {
                sends.push(data.to_vec());
            }
            drain_tunn(tunn, device, &mut sends);
            // 解密得到的 IP 报文再喂给协议栈。
            interface.poll(now, device, sockets);
            (sends, std::mem::take(wakers))
        };
        let sent = !sends.is_empty();
        {
            let mut queue = self
                .pending
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let remaining = MAX_TUNNEL_QUEUE.saturating_sub(queue.len());
            queue.extend(sends.into_iter().take(remaining));
        }
        for waker in wakers {
            waker.wake();
        }
        if sent {
            self.notify.notify_one();
        }
    }

    /// 把隧道收到的 UDP 载荷交给 boringtun，再推进协议栈。
    fn receive_datagram(&self, datagram: &[u8], sender: SocketAddr) {
        let (sends, wakers) = {
            let mut peer = self.peer.lock().unwrap_or_else(|error| error.into_inner());
            if peer.is_none() {
                *peer = Some(sender);
            }
            let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
            if inner.closed {
                return;
            }
            let Inner {
                tunn,
                interface,
                device,
                sockets,
                wakers,
                ..
            } = &mut *inner;
            let mut sends = Vec::new();
            let mut scratch = [0u8; DATAGRAM];
            let mut result = tunn.decapsulate(None, datagram, &mut scratch);
            loop {
                match result {
                    TunnResult::Done => break,
                    TunnResult::Err(error) => {
                        tracing::debug!(?error, "wireguard 丢弃无效报文");
                        break;
                    }
                    TunnResult::WriteToNetwork(data) => {
                        sends.push(data.to_vec());
                        result = tunn.decapsulate(None, &[], &mut scratch);
                    }
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        if device.rx.len() < MAX_TUNNEL_QUEUE {
                            device.rx.push_back(data.to_vec());
                        }
                        result = tunn.decapsulate(None, &[], &mut scratch);
                    }
                }
            }
            interface.poll(SmolInstant::now(), device, sockets);
            (sends, std::mem::take(wakers))
        };
        let sent = !sends.is_empty();
        {
            let mut queue = self
                .pending
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let remaining = MAX_TUNNEL_QUEUE.saturating_sub(queue.len());
            queue.extend(sends.into_iter().take(remaining));
        }
        for waker in wakers {
            waker.wake();
        }
        if sent {
            self.notify.notify_one();
        }
    }

    /// 驱动循环：持有弱引用，出站被丢弃后自动退出。
    async fn drive(self: Arc<Self>, weak: Weak<Self>) {
        let mut buffer = vec![0u8; DATAGRAM];
        'driver: loop {
            // 优先清空待发送队列。
            let pending: Vec<Vec<u8>> = {
                let mut queue = self
                    .pending
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                queue.drain(..).collect()
            };
            let peer = *self.peer.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(peer) = peer {
                for datagram in pending {
                    if self.udp.send_to(&datagram, peer).await.is_err() {
                        break 'driver;
                    }
                }
            }
            if weak.strong_count() <= 1 {
                break;
            }
            tokio::select! {
                biased;
                result = self.udp.recv_from(&mut buffer) => {
                    match result {
                        Ok((length, sender)) => {
                            let expected = *self.peer.lock().unwrap_or_else(|error| error.into_inner());
                            if expected.is_none_or(|peer| peer == sender) {
                                self.receive_datagram(&buffer[..length], sender);
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
            self.pump();
            if weak.strong_count() <= 1 {
                break;
            }
        }
        let wakers = {
            let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
            inner.closed = true;
            std::mem::take(&mut inner.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

fn random_index() -> u32 {
    // boringtun 只要求进程内区分多个隧道实例；用时间低位即可。
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(1))
        | 1
}

fn same_family(address: IpAddr, cidr: &IpCidr) -> bool {
    matches!(
        (address, cidr),
        (IpAddr::V4(_), IpCidr::Ipv4(_)) | (IpAddr::V6(_), IpCidr::Ipv6(_))
    )
}

fn to_smoltcp_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(ip) => IpAddress::Ipv4(Ipv4Address::from(ip.octets())),
        IpAddr::V6(ip) => IpAddress::Ipv6(Ipv6Address::from(ip.octets())),
    }
}

/// 反复调用 `decapsulate` 处理 boringtun 的排队输出，直到完成。
fn drain_tunn(tunn: &mut Tunn, device: &mut DeviceState, sends: &mut Vec<Vec<u8>>) {
    let mut scratch = [0u8; DATAGRAM];
    let mut result = tunn.decapsulate(None, &[], &mut scratch);
    loop {
        match result {
            TunnResult::Done | TunnResult::Err(_) => break,
            TunnResult::WriteToNetwork(data) => {
                sends.push(data.to_vec());
                result = tunn.decapsulate(None, &[], &mut scratch);
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                if device.rx.len() < MAX_TUNNEL_QUEUE {
                    device.rx.push_back(data.to_vec());
                }
                result = tunn.decapsulate(None, &[], &mut scratch);
            }
        }
    }
}

/// 一条经 WireGuard 隧道承载的 TCP 流。
struct WireguardStream {
    stack: Arc<Stack>,
    handle: SocketHandle,
    closed: bool,
}

impl WireguardStream {
    fn poll_stack(&self, context: &mut TaskContext<'_>, write: bool) -> Poll<io::Result<()>> {
        {
            let mut inner = self.inner();
            let socket = inner.sockets.get_mut::<tcp::Socket>(self.handle);
            let ready = if write {
                socket.may_send()
            } else {
                socket.can_recv()
                    || matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
            };
            if ready {
                drop(inner);
                self.stack.pump();
                return Poll::Ready(Ok(()));
            }
            inner.wakers.push(context.waker().clone());
        }
        self.stack.pump();
        Poll::Pending
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.stack
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl AsyncRead for WireguardStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        match this.poll_stack(context, false) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let ended =
                    {
                        let mut inner = this.inner();
                        let socket = inner.sockets.get_mut::<tcp::Socket>(this.handle);
                        if socket.can_recv() {
                            let length = socket.recv_slice(buffer.initialize_unfilled()).map_err(
                                |error| io::Error::other(format!("wireguard 读取失败: {error:?}")),
                            )?;
                            buffer.advance(length);
                            false
                        } else {
                            matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
                        }
                    };
                if ended {
                    this.closed = true;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for WireguardStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wireguard TCP 已关闭",
            )));
        }
        match this.poll_stack(context, true) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let length = {
                    let mut inner = this.inner();
                    let socket = inner.sockets.get_mut::<tcp::Socket>(this.handle);
                    match socket.send_slice(buffer) {
                        Ok(length) => length,
                        Err(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "wireguard 发送缓冲已满",
                            )));
                        }
                    }
                };
                this.stack.pump();
                Poll::Ready(Ok(length))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.stack.pump();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.closed = true;
            {
                let mut inner = this.inner();
                inner.sockets.get_mut::<tcp::Socket>(this.handle).close();
            }
            this.stack.pump();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for WireguardStream {
    fn drop(&mut self) {
        let mut inner = self.inner();
        // 直接移除会中止连接（RST 语义）；FIN 由显式 `close` 承担。
        inner.sockets.remove(self.handle);
    }
}

#[cfg(test)]
impl Stack {
    fn listen_tcp(&self, port: u16) -> io::Result<SocketHandle> {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        );
        socket
            .listen(port)
            .map_err(|error| io::Error::other(format!("wireguard 监听失败: {error:?}")))?;
        Ok(inner.sockets.add(socket))
    }

    async fn accept_tcp(self: &Arc<Self>, handle: SocketHandle) -> io::Result<WireguardStream> {
        loop {
            {
                let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
                let socket = inner.sockets.get_mut::<tcp::Socket>(handle);
                if socket.is_active() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            self.pump();
        }
        Ok(WireguardStream {
            stack: Arc::clone(self),
            handle,
            closed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn options(private: &[u8; 32], public: &[u8; 32], address: &str) -> WireguardOptions {
        WireguardOptions {
            private_key: base64::engine::general_purpose::STANDARD.encode(private),
            peer_public_key: base64::engine::general_purpose::STANDARD.encode(public),
            preshared_key: None,
            address: vec![address.to_owned()],
            mtu: Some(1420),
            keepalive_secs: Some(5),
        }
    }

    fn public_of(secret: &[u8; 32]) -> [u8; 32] {
        x25519::PublicKey::from(&x25519::StaticSecret::from(*secret)).to_bytes()
    }

    #[tokio::test]
    async fn udp_owner_drop_exits_driver_and_releases_outer_socket() {
        let config =
            WireguardConfig::parse(&options(&[9; 32], &public_of(&[7; 32]), "10.66.0.1/24"))
                .unwrap();
        let stack = Stack::start(Arc::new(config), Some("127.0.0.1:9".parse().unwrap()), None)
            .await
            .unwrap();
        let address = stack.local_udp_addr().unwrap();
        let weak = Arc::downgrade(&stack);
        let session = super::super::tunnel_udp::Session::open(
            stack.clone(),
            "10.66.0.1".parse().unwrap(),
            "10.66.0.2:53".parse().unwrap(),
            1420,
        )
        .unwrap();
        drop(session);
        drop(stack);
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        UdpSocket::bind(address)
            .await
            .expect("最后所有者丢弃后必须释放外层 UDP 端口");
    }

    #[tokio::test]
    async fn wireguard_tcp_round_trip_over_loopback() {
        let peer_secret = [7u8; 32];
        let local_secret = [9u8; 32];
        let peer_public = public_of(&peer_secret);
        let local_public = public_of(&local_secret);
        let server_config =
            WireguardConfig::parse(&options(&peer_secret, &local_public, "10.66.0.2/24")).unwrap();
        let client_config =
            WireguardConfig::parse(&options(&local_secret, &peer_public, "10.66.0.1/24")).unwrap();
        let server = Stack::start(
            Arc::new(server_config),
            None,
            Some("127.0.0.1:0".parse().unwrap()),
        )
        .await
        .unwrap();
        let listener = server.listen_tcp(8080).unwrap();
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let mut stream = server.accept_tcp(listener).await.unwrap();
                let mut buffer = [0u8; 5];
                stream.read_exact(&mut buffer).await.unwrap();
                assert_eq!(&buffer, b"hello");
                stream.write_all(b"world").await.unwrap();
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
            })
        };
        let client = Stack::start(
            Arc::new(client_config),
            Some(server.local_udp_addr().unwrap()),
            None,
        )
        .await
        .unwrap();
        let mut stream = client
            .connect(SocketAddr::new("10.66.0.2".parse().unwrap(), 8080))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world");
        let _ = tokio::time::timeout(Duration::from_secs(3), server_task).await;
        drop(stream);
        drop(client);
        drop(server);
    }
}
