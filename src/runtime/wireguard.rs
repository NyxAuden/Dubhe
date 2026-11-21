//! WireGuard 服务端与内核路由/出站之间的适配层。

use super::*;

/// WireGuard 服务端的出站拨号适配器。
///
/// TCP 复用完整 `Context::connect`；UDP 复用共享 `RoutedUdp` 的路由、预算与
/// 上游中继，不在 WireGuard 入口创建绕过路由的直连旁路。
pub(super) struct WireguardRouteDialer {
    pub(super) context: Arc<Context>,
    pub(super) inbound: String,
}

impl crate::transport::wireguard_server::OutboundDialer for WireguardRouteDialer {
    fn relay_tcp(
        &self,
        stream: Box<dyn crate::transport::wireguard_server::RelayTcp>,
        target: Box<dyn crate::transport::wireguard_server::RelayTcp>,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>> {
        let stats = self.context.stats.clone();
        Box::pin(async move { forward::relay(stream, target, stats).await })
    }

    fn dial_tcp(
        &self,
        target: SocketAddr,
    ) -> Pin<
        Box<
            dyn Future<Output = io::Result<Box<dyn crate::transport::wireguard_server::RelayTcp>>>
                + Send
                + '_,
        >,
    > {
        let context = self.context.clone();
        let inbound = self.inbound.clone();
        Box::pin(async move {
            let upstream = context.connect(&inbound, &Target::from(target)).await?;
            Ok(Box::new(upstream) as Box<dyn crate::transport::wireguard_server::RelayTcp>)
        })
    }

    fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> Pin<
        Box<
            dyn Future<Output = io::Result<Box<dyn crate::transport::wireguard_server::RelayUdp>>>
                + Send
                + '_,
        >,
    > {
        let context = self.context.clone();
        let inbound = self.inbound.clone();
        Box::pin(async move {
            let relay = crate::udp::RoutedUdp::new(context, inbound, Target::from(target)).await?;
            Ok(Box::new(WireguardRoutedUdp(tokio::sync::Mutex::new(relay)))
                as Box<dyn crate::transport::wireguard_server::RelayUdp>)
        })
    }
}

pub(super) struct WireguardRoutedUdp(tokio::sync::Mutex<crate::udp::RoutedUdp>);

impl crate::transport::wireguard_server::RelayUdp for WireguardRoutedUdp {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { self.0.lock().await.send(payload).await })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut relay = self.0.lock().await;
            let packet = relay.recv().await?;
            if packet.payload.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WireGuard UDP 接收缓冲不足",
                ));
            }
            let length = packet.payload.len();
            buffer[..length].copy_from_slice(&packet.payload);
            relay.received(length);
            Ok(length)
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn wireguard_server_config(
    index: usize,
    private_key: &str,
    addresses: &[String],
    peers: &[crate::config::WireguardServerPeerOptions],
    mtu: Option<u16>,
    max_peers: Option<usize>,
    max_tcp_connections: Option<usize>,
    max_udp_associations: Option<usize>,
    max_queued_datagrams: Option<usize>,
    max_handshake_inits_per_sec: Option<u32>,
    peer_idle_timeout_secs: Option<u64>,
) -> Result<crate::transport::wireguard_server::WireguardServerConfig> {
    use crate::transport::wireguard_server::{WireguardPeerConfig, WireguardServerConfig};

    let private_key = crate::config::parse_wireguard_key(private_key)
        .ok_or_else(|| anyhow::anyhow!("入口 {index} WireGuard private_key 无效"))?;
    let mut local_addresses = Vec::with_capacity(addresses.len());
    for value in addresses {
        local_addresses.push(value.parse::<IpNet>().map_err(|_| {
            anyhow::anyhow!("入口 {index} WireGuard address 不是有效 CIDR: {value}")
        })?);
    }
    let mut parsed_peers = Vec::with_capacity(peers.len());
    for (peer_index, peer) in peers.iter().enumerate() {
        let public_key = crate::config::parse_wireguard_key(&peer.public_key)
            .ok_or_else(|| anyhow::anyhow!("入口 {index} peers[{peer_index}] public_key 无效"))?;
        let preshared_key = match &peer.preshared_key {
            Some(value) => Some(crate::config::parse_wireguard_key(value).ok_or_else(|| {
                anyhow::anyhow!("入口 {index} peers[{peer_index}] preshared_key 无效")
            })?),
            None => None,
        };
        let mut allowed_ips = Vec::with_capacity(peer.allowed_ips.len());
        for value in &peer.allowed_ips {
            allowed_ips.push(value.parse::<IpNet>().map_err(|_| {
                anyhow::anyhow!(
                    "入口 {index} peers[{peer_index}] allowed_ips 不是有效 CIDR: {value}"
                )
            })?);
        }
        parsed_peers.push(
            WireguardPeerConfig::new(public_key, allowed_ips)
                .with_preshared_key(preshared_key)
                .with_keepalive_secs(peer.keepalive),
        );
    }
    let mut config = WireguardServerConfig::new(private_key, local_addresses);
    config.peers = parsed_peers;
    config.mtu = mtu.map(usize::from).unwrap_or(1420);
    config.max_peers = max_peers.unwrap_or(256);
    config.max_tcp_connections = max_tcp_connections.unwrap_or(256);
    config.max_udp_associations = max_udp_associations.unwrap_or(256);
    config.max_queued_datagrams = max_queued_datagrams.unwrap_or(1024);
    config.max_handshake_inits_per_sec = max_handshake_inits_per_sec.unwrap_or(50);
    config.peer_idle_timeout = Duration::from_secs(peer_idle_timeout_secs.unwrap_or(300));
    Ok(config)
}
