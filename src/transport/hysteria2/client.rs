//! Hysteria2 出站（TCP）。
//!
//! 每个出站共享一条 QUIC 连接；先用 HTTP/3 `POST https://hysteria/auth`
//! 完成密码认证，之后每个目标打开一条 QUIC 双向流，按 0x401 TCP 请求帧
//! 携带目标地址。UDP DATAGRAM 使用专用连接，按关联独立认证与回收。

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use prost::bytes::Bytes;
use quinn::{Endpoint, RecvStream, SendStream};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::forward::{Context, Upstream};
use crate::session::Target;

use super::brutal::{Bandwidth, BrutalControl, BrutalFactory};
use super::socket::{ObfsMode, ObfsUdpSocket};
use super::wire;

const AUTH_STATUS: u16 = 233;
const KEEP_ALIVE: Duration = Duration::from_secs(10);
const DATAGRAM_BUFFER: usize = 1 << 20;

pub(crate) struct ClientPrepared {
    endpoint: Target,
    tls: Arc<ClientConfig>,
    server_name: String,
    password: String,
    obfs: Option<ObfsMode>,
    bandwidth: Bandwidth,
    state: Mutex<Option<Arc<State>>>,
}

struct State {
    connection: quinn::Connection,
    /// h3 控制连接必须存活；Drop 会关闭整个 QUIC 连接。
    _h3: Mutex<h3::client::Connection<h3_quinn::Connection, Bytes>>,
    _endpoint: Endpoint,
    udp: bool,
    /// 客户端上行为 Brutal 控制器；`None` 表示未配置 `up_mbps`。
    _brutal: Option<Arc<BrutalControl>>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.connection.close(quinn::VarInt::from_u32(0), b"");
    }
}

/// 每个 UDP 关联使用独立 QUIC 连接，保证只有一个 DATAGRAM 接收循环。
#[derive(Clone)]
pub(crate) struct UdpKeepalive(#[allow(dead_code)] Arc<State>);

/// 专用 UDP 连接的发送端、接收端与连接保活句柄。
pub(crate) struct UdpParts {
    pub(crate) sender: super::client_udp::UdpSessionSender,
    pub(crate) receiver: super::client_udp::UdpSessionReceiver,
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
        password: String,
        obfs: Option<ObfsMode>,
        bandwidth: Bandwidth,
    ) -> Self {
        Self {
            endpoint,
            tls,
            server_name,
            password,
            obfs,
            bandwidth,
            state: Mutex::new(None),
        }
    }

    pub(crate) async fn connect(&self, context: &Context, target: &Target) -> io::Result<Upstream> {
        let state = self.state(context).await?;
        let (send, recv) = state
            .connection
            .open_bi()
            .await
            .map_err(|error| io::Error::other(format!("Hysteria2 打开流失败: {error}")))?;
        let mut stream = Hysteria2Stream {
            send,
            recv,
            _state: state,
        };
        let destination = destination(target);
        stream
            .send
            .write_all(&wire::encode_tcp_request(&destination, &[])?)
            .await?;
        stream.send.flush().await?;
        read_tcp_reply(&mut stream.recv).await?;
        Ok(Upstream::new(Box::new(stream), None))
    }

    /// 为一条 UDP 关联建立专用 QUIC 连接并拆分数据报会话。
    pub(crate) async fn open_udp(&self, context: &Context) -> io::Result<UdpParts> {
        let state = Arc::new(self.start(context).await?);
        if !state.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Hysteria2 服务端未启用 UDP",
            ));
        }
        let (sender, receiver) =
            super::client_udp::split(state.connection.clone()).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Hysteria2 UDP 会话初始化失败: {error}"),
                )
            })?;
        Ok(UdpParts {
            sender,
            receiver,
            keepalive: UdpKeepalive(state),
        })
    }

    async fn state(&self, context: &Context) -> io::Result<Arc<State>> {
        let mut guard = self.state.lock().await;
        if let Some(state) = guard.as_ref()
            && state.connection.close_reason().is_none()
        {
            return Ok(state.clone());
        }
        let state = Arc::new(self.start(context).await?);
        *guard = Some(state.clone());
        Ok(state)
    }

    async fn start(&self, context: &Context) -> io::Result<State> {
        let addresses = context.dns.resolve(&self.endpoint).await?;
        let peer = addresses.first().copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Hysteria2 服务端无可用地址",
            )
        })?;
        let bind: std::net::SocketAddr = if peer.is_ipv4() {
            "0.0.0.0:0".parse().expect("IPv4 通配地址")
        } else {
            "[::]:0".parse().expect("IPv6 通配地址")
        };
        let socket = UdpSocket::bind(bind).await?;
        let abstract_socket = ObfsUdpSocket::new(socket, self.obfs.clone())?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(self.tls.clone())
            .map_err(|error| io::Error::other(format!("Hysteria2 TLS 配置无效: {error}")))?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE));
        transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
        transport.datagram_send_buffer_size(DATAGRAM_BUFFER);
        // 客户端上行为 Brutal 仅在显式 up_mbps 时启用；认证响应可下调速率。
        // Quinn 没有独立 pacer，控制器仍沿用模块内已记录的窗口近似边界。
        let brutal = (self.bandwidth.tx_bytes_per_sec() > 0).then(BrutalControl::new);
        if let Some(control) = &brutal {
            transport.congestion_controller_factory(BrutalFactory::new(control.clone()));
        }
        client.transport_config(Arc::new(transport));
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            abstract_socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client);
        let connection = endpoint
            .connect(peer, &self.server_name)
            .map_err(|error| io::Error::other(format!("Hysteria2 连接失败: {error}")))?
            .await
            .map_err(|error| io::Error::other(format!("Hysteria2 QUIC 握手失败: {error}")))?;

        let (h3, mut send_request) = h3::client::builder()
            .enable_datagram(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|error| io::Error::other(format!("Hysteria2 HTTP/3 初始化失败: {error}")))?;
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://hysteria/auth")
            .header(wire::HEADER_AUTH, &self.password)
            .header(
                wire::HEADER_CC_RX,
                self.bandwidth.rx_bytes_per_sec().to_string(),
            )
            .body(())
            .map_err(|error| io::Error::other(format!("Hysteria2 认证请求失败: {error}")))?;
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| io::Error::other(format!("Hysteria2 认证请求失败: {error}")))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|error| io::Error::other(format!("Hysteria2 认证应答失败: {error}")))?;
        if response.status().as_u16() != AUTH_STATUS {
            connection.close(quinn::VarInt::from_u32(0), b"auth failed");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Hysteria2 认证失败: {}", response.status()),
            ));
        }
        let udp = response
            .headers()
            .get(wire::HEADER_UDP)
            .and_then(|value| value.to_str().ok())
            == Some("true");
        let (server_rx, rx_auto) = response
            .headers()
            .get(wire::HEADER_CC_RX)
            .and_then(|value| value.to_str().ok())
            .map_or((0, false), |value| {
                if value == "auto" {
                    (0, true)
                } else {
                    (value.parse::<u64>().unwrap_or(0), false)
                }
            });
        let send_bps = self.bandwidth.tx_bytes_per_sec();
        let actual_tx = if server_rx == 0 || server_rx > send_bps {
            send_bps
        } else {
            server_rx
        };
        if let (Some(control), false, true) = (&brutal, rx_auto, actual_tx > 0) {
            control.set_rate(actual_tx);
        }
        Ok(State {
            connection,
            _h3: Mutex::new(h3),
            _endpoint: endpoint,
            udp,
            _brutal: brutal,
        })
    }
}

/// 先验证对端声明长度，再分配有界缓冲；绝不直接按 QUIC varint 分配。
async fn read_tcp_reply<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<()> {
    let status = stream.read_u8().await?;
    let message_len = wire::read_varint(stream).await?;
    if message_len > wire::MAX_MESSAGE_LENGTH as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria2 响应消息超出上限",
        ));
    }
    let mut message = vec![0; message_len as usize];
    stream.read_exact(&mut message).await?;
    let padding_len = wire::read_varint(stream).await?;
    if padding_len > wire::MAX_PADDING_LENGTH as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria2 响应 padding 超出上限",
        ));
    }
    let mut padding = vec![0; padding_len as usize];
    stream.read_exact(&mut padding).await?;
    std::str::from_utf8(&message)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Hysteria2 响应消息不是 UTF-8"))?;
    if status != 0 {
        // 不把对端可控消息插入日志/终端，也不把业务字节误当响应。
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "Hysteria2 目标连接被拒绝",
        ));
    }
    Ok(())
}

fn destination(target: &Target) -> String {
    match &target.host {
        crate::session::Host::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]:{}", target.port),
        crate::session::Host::Ip(ip) => format!("{ip}:{}", target.port),
        crate::session::Host::Domain(domain) => format!("{domain}:{}", target.port),
    }
}

/// 一条 Hysteria2 TCP 流：QUIC 双向流加响应头已消费后的正文。
pub(crate) struct Hysteria2Stream {
    send: SendStream,
    recv: RecvStream,
    _state: Arc<State>,
}

impl AsyncRead for Hysteria2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2Stream {
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

#[cfg(test)]
mod reply_tests {
    use super::*;

    #[tokio::test]
    async fn oversized_response_lengths_fail_before_reading_the_declared_body() {
        for (message_len, padding_len) in [
            (wire::MAX_MESSAGE_LENGTH as u64 + 1, None),
            (0, Some(wire::MAX_PADDING_LENGTH as u64 + 1)),
            (wire::MAX_VARINT, None),
        ] {
            let mut bytes = vec![0];
            wire::encode_varint(message_len, &mut bytes).unwrap();
            if let Some(padding) = padding_len {
                wire::encode_varint(padding, &mut bytes).unwrap();
            }
            let error = read_tcp_reply(&mut bytes.as_slice()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn bounded_response_preserves_business_tail_and_rejects_truncation() {
        let mut bytes = wire::encode_tcp_response(true, "", b"tail").unwrap();
        let mut reader = bytes.as_slice();
        read_tcp_reply(&mut reader).await.unwrap();
        assert_eq!(reader, b"tail");
        bytes.truncate(1);
        assert_eq!(
            read_tcp_reply(&mut bytes.as_slice())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
