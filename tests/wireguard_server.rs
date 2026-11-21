mod common;

use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use base64::Engine as _;
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519,
};
use common::{Echo, Running};
use dubhe::Config;
use serde_json::{Value, json};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::Instant as SmolInstant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
    },
};
use tokio::net::UdpSocket;

const DATAGRAM: usize = 65_535 + 64;
const TCP_BUFFER: usize = 64 * 1024;
const UDP_BUFFER: usize = 64 * 1024;
const SERVER_SECRET: [u8; 32] = [7u8; 32];
const CLIENT_SECRET: [u8; 32] = [9u8; 32];

fn base64_key(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    x25519::PublicKey::from(&x25519::StaticSecret::from(*secret)).to_bytes()
}

fn config() -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "wireguard",
            "tag": "wg",
            "listen": "127.0.0.1:0",
            "private_key": base64_key(&SERVER_SECRET),
            "address": ["10.88.0.1/24"],
            "peers": [{
                "public_key": base64_key(&public_of(&CLIENT_SECRET)),
                "allowed_ips": ["10.88.0.2/32"],
                "keepalive": 2
            }],
            "mtu": 1420,
            "max_peers": 8,
            "max_tcp_connections": 8,
            "max_udp_associations": 8,
            "max_queued_datagrams": 128,
            "max_handshake_inits_per_sec": 50,
            "peer_idle_timeout_secs": 30
        }],
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 1000}
    })
}

// ---- 测试用最小 WireGuard 客户端（boringtun + smoltcp，回环 UDP） ----

struct DeviceState {
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
        capabilities.max_transmission_unit = 1420;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

fn to_ip(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => IpAddress::Ipv4(Ipv4Address::from(address.octets())),
        IpAddr::V6(address) => IpAddress::Ipv6(Ipv6Address::from(address.octets())),
    }
}

struct Client {
    udp: UdpSocket,
    server: SocketAddr,
    tunn: Tunn,
    interface: Interface,
    device: DeviceState,
    sockets: SocketSet<'static>,
    pending: VecDeque<Vec<u8>>,
    local_ip: IpAddress,
    next_port: u16,
}

impl Client {
    async fn new(server: SocketAddr) -> Self {
        let mut device = DeviceState {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        };
        let local_ip = to_ip("10.88.0.2".parse().unwrap());
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::now(),
        );
        interface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(local_ip, 24)).unwrap();
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 88, 0, 1))
            .unwrap();
        let tunn = Tunn::new(
            x25519::StaticSecret::from(CLIENT_SECRET),
            x25519::PublicKey::from(public_of(&SERVER_SECRET)),
            None,
            Some(2),
            0x42,
            None,
        );
        Self {
            udp: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
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
                    let mut result = self.tunn.decapsulate(None, &buffer[..length], &mut scratch);
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
            if let TunnResult::WriteToNetwork(data) = self.tunn.encapsulate(&packet, &mut scratch) {
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

    async fn connect(&mut self, destination: SocketAddr) -> io::Result<SocketHandle> {
        let port = self.allocate_port();
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        );
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));
        socket
            .connect(
                self.interface.context(),
                IpEndpoint::new(to_ip(destination.ip()), destination.port()),
                IpListenEndpoint {
                    addr: Some(self.local_ip),
                    port,
                },
            )
            .map_err(|error| io::Error::other(format!("客户端 connect 失败: {error:?}")))?;
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

    async fn write_all(&mut self, handle: SocketHandle, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            self.pump()?;
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if socket.may_send() {
                match socket.send_slice(data) {
                    Ok(length) => data = &data[length..],
                    Err(_) => tokio::time::sleep(Duration::from_millis(2)).await,
                }
            } else {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        for _ in 0..3 {
            self.pump()?;
        }
        Ok(())
    }

    async fn read_exact(&mut self, handle: SocketHandle, output: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while filled < output.len() {
            self.pump()?;
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_recv() {
                let length = socket
                    .recv_slice(&mut output[filled..])
                    .map_err(|error| io::Error::other(format!("客户端读取失败: {error:?}")))?;
                filled += length;
            } else if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "客户端读取超时"));
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
            .map_err(|error| io::Error::other(format!("客户端 UDP bind 失败: {error:?}")))?;
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
                IpEndpoint::new(to_ip(destination.ip()), destination.port()),
            )
            .map_err(|error| io::Error::other(format!("客户端 UDP 发送失败: {error:?}")))
    }

    async fn recv_udp(&mut self, handle: SocketHandle) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.pump()?;
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            if socket.can_recv() {
                let mut buffer = vec![0u8; 4096];
                let (length, _) = socket
                    .recv_slice(&mut buffer)
                    .map_err(|error| io::Error::other(format!("客户端 UDP 读取失败: {error:?}")))?;
                buffer.truncate(length);
                return Ok(buffer);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "客户端 UDP 读取超时",
                ));
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

#[tokio::test]
async fn tunnel_relays_tcp_and_udp_echo() {
    let tcp_echo = Echo::tcp("127.0.0.1", false).await;
    let udp_echo = Echo::udp("127.0.0.1").await;
    let running = Running::start(config()).await;
    let server = running.address;

    let mut client = Client::new(server).await;
    let tcp = client.connect(tcp_echo.address).await.unwrap();
    client.write_all(tcp, b"wireguard tcp").await.unwrap();
    let mut reply = [0u8; 13];
    client.read_exact(tcp, &mut reply).await.unwrap();
    assert_eq!(&reply, b"wireguard tcp");
    assert_eq!(running.stats.snapshot().uplink, 13);
    assert_eq!(running.stats.snapshot().downlink, 13);

    let udp = client.bind_udp(40_000).unwrap();
    for payload in [b"wg-udp-1".as_slice(), b"wg-udp-2".as_slice()] {
        client.send_udp(udp, udp_echo.address, payload).unwrap();
        let echoed = client.recv_udp(udp).await.unwrap();
        assert_eq!(echoed, payload);
    }

    running.shutdown().await;
}

#[tokio::test]
async fn udp_follows_socks5_upstream_and_counts_business_bytes() {
    let echo = Echo::udp("127.0.0.1").await;
    let upstream = Running::start(json!({
        "version":1,
        "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":1000}
    }))
    .await;
    let mut value = config();
    value["outbounds"] =
        json!([{"type":"socks5","tag":"proxy","endpoint":upstream.address.to_string()}]);
    value["route"]["default"] = json!("proxy");
    let running = Running::start(value).await;
    let mut client = Client::new(running.address).await;
    let socket = client.bind_udp(40_001).unwrap();
    client
        .send_udp(socket, echo.address, b"wg-via-proxy")
        .unwrap();
    assert_eq!(client.recv_udp(socket).await.unwrap(), b"wg-via-proxy");
    assert!(upstream.stats.snapshot().uplink >= b"wg-via-proxy".len() as u64);
    assert_eq!(
        running.stats.snapshot().uplink,
        b"wg-via-proxy".len() as u64
    );
    running.shutdown().await;
    upstream.shutdown().await;
}

#[test]
fn wireguard_inbound_config_is_validated() {
    let valid = config();
    Config::from_json(&valid.to_string()).expect("有效配置应通过校验");

    let mut bad_key = valid.clone();
    bad_key["inbounds"][0]["private_key"] = json!("not-base64");
    assert!(Config::from_json(&bad_key.to_string()).is_err());

    let mut no_peers = valid.clone();
    no_peers["inbounds"][0]["peers"] = json!([]);
    assert!(Config::from_json(&no_peers.to_string()).is_err());

    let mut bad_address = valid.clone();
    bad_address["inbounds"][0]["address"] = json!(["not-a-cidr"]);
    assert!(Config::from_json(&bad_address.to_string()).is_err());

    let mut bad_allowed = valid.clone();
    bad_allowed["inbounds"][0]["peers"][0]["allowed_ips"] = json!(["10.88.0.2/33"]);
    assert!(Config::from_json(&bad_allowed.to_string()).is_err());

    let mut too_many_addresses = valid.clone();
    too_many_addresses["inbounds"][0]["address"] = json!(
        (0..=smoltcp::config::IFACE_MAX_ADDR_COUNT)
            .map(|index| format!("10.88.{}.1/24", index))
            .collect::<Vec<_>>()
    );
    assert!(Config::from_json(&too_many_addresses.to_string()).is_err());

    let mut overlapping = valid;
    overlapping["inbounds"][0]["peers"] = json!([
        {
            "public_key": base64_key(&public_of(&CLIENT_SECRET)),
            "allowed_ips": ["10.88.0.0/24"]
        },
        {
            "public_key": base64_key(&public_of(&[13u8; 32])),
            "allowed_ips": ["10.88.0.2/32"]
        }
    ]);
    assert!(Config::from_json(&overlapping.to_string()).is_err());
}

/// WireGuard 的认证失败必须能出现在 `/metrics` 的 `dubhe_rejected_total` 上。
///
/// 回归背景：`WireguardServer` 有独立的 `WireguardServerStats`
/// （区分 `invalid_packets` 与 `unknown_peers`，比全局 `rejected` 更细），
/// 但此前完全不进 `/metrics`——运维看不到未知公钥 / MAC1 错误 / 报文
/// 校验失败。由于该类型在 bind 阶段就构造完毕（那时全局 Stats 还没创建），
/// `runtime` 用周期采样把两个计数的增量并入全局 rejected。
#[tokio::test]
async fn invalid_handshakes_are_merged_into_global_rejected() {
    let mut value = config();
    // 采样周期缩到最小，测试才不必等 30 秒。
    value["limits"]["stats_interval_ms"] = json!(1);
    let running = Running::start(value).await;

    let before = running.stats.snapshot().rejected;
    // 发一个不可能通过 MAC1 校验的握手初始化：随机字节。
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut garbage = [0u8; 148];
    for (index, byte) in garbage.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    socket.send_to(&garbage, running.address).await.unwrap();

    let merged = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if running.stats.snapshot().rejected > before {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;

    running.shutdown().await;
    assert!(
        merged.unwrap_or(false),
        "WireGuard 无效握手没有并入全局 rejected（修复前恒为 0）"
    );
}
