//! TUIC v5 出站（TCP 与 native/quic UDP），可选真实CC与早期握手策略。
//!
//! 每个出站共享一条 QUIC 连接；连接建立后以单向流发送
//! `版本(5)+Authenticate(0)+UUID+TLS exporter token`，随后每个目标打开一条
//! 双向流发送 `版本(5)+Connect(1)+地址`。UDP 的 native/quic 承载分别
//! 使用专用连接，避免同一条连接上多个关联争抢数据报或单向流。
//! 0-RTT默认关闭，只提前Connect元数据/Heartbeat；业务不自动重放，标准exporter
//! 仍在完整握手后使用。端点按地址族有界复用票据，活流持有最后所有权。

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use quinn::{Endpoint, RecvStream, SendStream};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::config::TuicClientOptions;
use crate::forward::{Context, Upstream};
use crate::session::{Host, Target};

use super::tuic::{
    modern::CongestionControl,
    wire::{self, WireAddress},
};

const KEEP_ALIVE: Duration = Duration::from_secs(10);
const DATAGRAM_BUFFER: usize = 1 << 20;

#[cfg(test)]
mod tests;

pub(crate) struct ClientPrepared {
    endpoint: Target,
    quic: quinn::ClientConfig,
    server_name: String,
    uuid: [u8; 16],
    password: String,
    zero_rtt: bool,
    endpoints: Mutex<Endpoints>,
    state: Mutex<Option<Arc<State>>>,
}

#[derive(Default)]
struct Endpoints {
    v4: Option<Arc<CachedEndpoint>>,
    v6: Option<Arc<CachedEndpoint>>,
}
struct CachedEndpoint(Endpoint);
impl Drop for CachedEndpoint {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"last endpoint owner dropped");
    }
}

struct State {
    connection: quinn::Connection,
    _endpoint: Arc<CachedEndpoint>,
    #[cfg(test)]
    attempted_early: bool,
    #[cfg(test)]
    accepted_early: bool,
}

/// 调用取消/失败时关闭尚未交付的连接，不能留下仅endpoint持有的半认证会话。
struct PendingConnection {
    connection: quinn::Connection,
    armed: bool,
}
impl Drop for PendingConnection {
    fn drop(&mut self) {
        if self.armed {
            self.connection.close(0u32.into(), b"connect cancelled");
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.connection.close(quinn::VarInt::from_u32(0), b"");
    }
}

/// 每个 UDP 关联使用独立 QUIC 连接，保证只有一个 DATAGRAM 接收循环。
#[derive(Clone)]
pub(crate) struct UdpKeepalive(#[allow(dead_code)] Arc<State>);

/// TUIC UDP 发送端；按 `udp_relay_mode` 选择 DATAGRAM 或单向流。
pub(crate) enum UdpSender {
    Native(crate::transport::tuic_udp::UdpSessionSender),
    Stream(crate::transport::tuic_udp_stream::StreamSender),
}

impl UdpSender {
    pub(crate) async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Native(sender) => sender.send(target, payload).await,
            Self::Stream(sender) => sender.send(target, payload).await,
        }
    }
}

/// TUIC UDP 接收端；与发送端模式保持一致。
pub(crate) enum UdpReceiver {
    Native(crate::transport::tuic_udp::UdpSessionReceiver),
    Stream(crate::transport::tuic_udp_stream::StreamReceiver),
}

impl UdpReceiver {
    pub(crate) async fn recv(&mut self) -> io::Result<(Target, Vec<u8>)> {
        match self {
            Self::Native(receiver) => receiver.recv().await,
            Self::Stream(receiver) => receiver.recv().await,
        }
    }
}

/// 专用 UDP 连接的发送端、接收端与连接保活句柄。
pub(crate) struct UdpParts {
    pub(crate) sender: UdpSender,
    pub(crate) receiver: UdpReceiver,
    keepalive: UdpKeepalive,
}

impl UdpParts {
    pub(crate) fn keepalive(&self) -> UdpKeepalive {
        self.keepalive.clone()
    }
}

impl ClientPrepared {
    pub(crate) fn new(
        endpoint: Target,
        tls: Arc<ClientConfig>,
        server_name: String,
        uuid: [u8; 16],
        password: String,
        options: TuicClientOptions,
    ) -> io::Result<Self> {
        let algorithm =
            CongestionControl::parse(options.congestion_control.as_deref().unwrap_or("cubic"))?;
        let mut tls = (*tls).clone();
        tls.enable_early_data = options.zero_rtt_handshake;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TUIC TLS配置无效"))?;
        let mut quic = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        algorithm.apply(&mut transport);
        transport.keep_alive_interval(Some(KEEP_ALIVE));
        transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
        transport.datagram_send_buffer_size(DATAGRAM_BUFFER);
        quic.transport_config(Arc::new(transport));
        Ok(Self {
            endpoint,
            quic,
            server_name,
            uuid,
            password,
            zero_rtt: options.zero_rtt_handshake,
            endpoints: Mutex::new(Endpoints::default()),
            state: Mutex::new(None),
        })
    }

    pub(crate) async fn connect(&self, context: &Context, target: &Target) -> io::Result<Upstream> {
        let mut outbound = Vec::with_capacity(2 + wire::MAX_ADDRESS_LEN);
        outbound.push(wire::VERSION);
        outbound.push(wire::COMMAND_CONNECT);
        wire::encode_address(&address(target)?, &mut outbound)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TUIC 目标地址无效"))?;
        let mut guard = self.state.lock().await;
        let mut early = None;
        let state = match guard
            .as_ref()
            .filter(|state| state.connection.close_reason().is_none())
        {
            Some(state) => state.clone(),
            None => {
                let (state, stream) = self.start(context, Some(&outbound)).await?;
                early = stream;
                let state = Arc::new(state);
                *guard = Some(state.clone());
                state
            }
        };
        drop(guard);
        let (send, recv) = match early {
            Some(stream) => stream,
            None => open_connect(&state.connection, &outbound).await?,
        };
        Ok(Upstream::new(
            Box::new(TuicStream {
                send,
                recv,
                _state: state,
            }),
            None,
        ))
    }

    /// 为一条 UDP 关联建立专用 QUIC 连接并拆分数据报会话。
    pub(crate) async fn open_udp(
        &self,
        context: &Context,
        mode: crate::config::TuicUdpRelayMode,
    ) -> io::Result<UdpParts> {
        let (state, _) = self.start(context, None).await?;
        let state = Arc::new(state);
        let (sender, receiver) = match mode {
            crate::config::TuicUdpRelayMode::Native => {
                // 对端是否协商QUIC数据报在握手后即可确定；固定目标准备在
                // 成功应答前失败关闭，不能等到首个业务包才发现不支持。
                if state.connection.max_datagram_size().is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "TUIC 对端未协商QUIC数据报",
                    ));
                }
                let (sender, receiver) =
                    crate::transport::tuic_udp::split(state.connection.clone())?;
                (UdpSender::Native(sender), UdpReceiver::Native(receiver))
            }
            crate::config::TuicUdpRelayMode::Quic => {
                let (sender, receiver) =
                    crate::transport::tuic_udp_stream::split(state.connection.clone())?;
                (UdpSender::Stream(sender), UdpReceiver::Stream(receiver))
            }
        };
        Ok(UdpParts {
            sender,
            receiver,
            keepalive: UdpKeepalive(state),
        })
    }

    async fn endpoint_for(&self, ipv4: bool) -> io::Result<Arc<CachedEndpoint>> {
        let mut endpoints = self.endpoints.lock().await;
        let slot = if ipv4 {
            &mut endpoints.v4
        } else {
            &mut endpoints.v6
        };
        if let Some(endpoint) = slot {
            return Ok(endpoint.clone());
        }
        let bind = if ipv4 { "0.0.0.0:0" } else { "[::]:0" };
        let mut endpoint = Endpoint::client(bind.parse().expect("固定通配地址"))?;
        endpoint.set_default_client_config(self.quic.clone());
        let endpoint = Arc::new(CachedEndpoint(endpoint));
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }

    async fn start(
        &self,
        context: &Context,
        request: Option<&[u8]>,
    ) -> io::Result<(State, Option<(SendStream, RecvStream)>)> {
        tokio::time::timeout(
            Duration::from_millis(context.limits.dial_timeout_ms),
            self.start_inner(context, request),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TUIC连接/认证超时"))?
    }

    async fn start_inner(
        &self,
        context: &Context,
        request: Option<&[u8]>,
    ) -> io::Result<(State, Option<(SendStream, RecvStream)>)> {
        let addresses = context.dns.resolve(&self.endpoint).await?;
        let peer = addresses.first().copied().ok_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "TUIC 服务端无可用地址")
        })?;
        let endpoint = self.endpoint_for(peer.is_ipv4()).await?;
        let connecting = endpoint
            .0
            .connect(peer, &self.server_name)
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionRefused, "TUIC连接建立失败"))?;
        let (connection, early) = if self.zero_rtt {
            match connecting.into_0rtt() {
                Ok((connection, accepted)) => (connection, Some(accepted)),
                Err(connecting) => (connecting.await.map_err(quic_error)?, None),
            }
        } else {
            (connecting.await.map_err(quic_error)?, None)
        };
        let mut pending = PendingConnection {
            connection: connection.clone(),
            armed: true,
        };
        let mut stream = None;
        #[cfg(test)]
        let attempted_early = early.is_some();
        #[cfg(test)]
        let mut accepted_early = false;
        if let Some(accepted) = early {
            // 只提前发送Connect元数据，不交付业务流，拒绝时可无业务重放地重建。
            let mut early_error = None;
            if let Some(request) = request {
                match open_connect(&connection, request).await {
                    Ok(value) => stream = Some(value),
                    Err(error) => early_error = Some(error),
                }
            } else {
                // Heartbeat无目标和载荷，早期DATAGRAM被拒绝/延后均无副作用。
                let _ = connection.send_datagram(bytes::Bytes::from_static(&[
                    wire::VERSION,
                    wire::COMMAND_HEARTBEAT,
                ]));
            }
            let was_accepted = accepted.await;
            #[cfg(test)]
            {
                accepted_early = was_accepted;
            }
            if let Some(error) = connection.close_reason() {
                return Err(quic_error(error));
            }
            if let Some(error) = early_error {
                let rejected = error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<quinn::WriteError>())
                    .is_some_and(|error| matches!(error, quinn::WriteError::ZeroRttRejected));
                if was_accepted || !rejected {
                    return Err(error);
                }
            }
            if !was_accepted {
                stream = None;
            }
        }
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &self.uuid, self.password.as_bytes())
            .map_err(|error| io::Error::other(format!("TUIC exporter 失败: {error:?}")))?;
        let mut auth = connection
            .open_uni()
            .await
            .map_err(|error| io::Error::other(format!("TUIC 认证流失败: {error}")))?;
        auth.write_all(&wire::encode_authenticate(&self.uuid, &token))
            .await
            .map_err(|error| io::Error::other(format!("TUIC 认证写入失败: {error}")))?;
        auth.finish()
            .map_err(|error| io::Error::other(format!("TUIC 认证流结束失败: {error}")))?;
        if stream.is_none()
            && let Some(request) = request
        {
            stream = Some(open_connect(&connection, request).await?);
        }
        pending.armed = false;
        Ok((
            State {
                connection,
                _endpoint: endpoint,
                #[cfg(test)]
                attempted_early,
                #[cfg(test)]
                accepted_early,
            },
            stream,
        ))
    }
}

fn quic_error(_: quinn::ConnectionError) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "TUIC QUIC握手或连接失败")
}

async fn open_connect(
    connection: &quinn::Connection,
    request: &[u8],
) -> io::Result<(SendStream, RecvStream)> {
    let (mut send, recv) = connection.open_bi().await.map_err(quic_error)?;
    send.write_all(request)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))?;
    Ok((send, recv))
}

fn address(target: &Target) -> io::Result<WireAddress> {
    Ok(match &target.host {
        Host::Ip(std::net::IpAddr::V4(ip)) => WireAddress::Ipv4 {
            octets: ip.octets(),
            port: target.port,
        },
        Host::Ip(std::net::IpAddr::V6(ip)) => WireAddress::Ipv6 {
            octets: ip.octets(),
            port: target.port,
        },
        Host::Domain(domain) => WireAddress::Domain {
            name: domain.clone(),
            port: target.port,
        },
    })
}

pub(crate) struct TuicStream {
    send: SendStream,
    recv: RecvStream,
    _state: Arc<State>,
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
