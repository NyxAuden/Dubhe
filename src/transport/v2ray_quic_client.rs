//! V2Ray QUIC 传输出站（sing-box `v2ray-quic` 语义）。
//!
//! 服务端 [`crate::transport::v2ray_quic`] 把每条 QUIC 双向流直接交给
//! VLESS/VMess/Trojan 认证层：传输本身没有额外的首包、目标地址或 Xray
//! `quicSettings` 加密/混淆层。因此客户端只需共享一条 QUIC 连接，并为每条
//! 代理连接打开一条双向流，随后由上层协议在流上写入各自的请求头。
//!
//! 与 Hysteria2/TUIC 出站一致：端点与连接在首次使用时建立并缓存，连接
//! 关闭后下一次调用自动重建。上层协议的 UDP 帧仍走可靠双向流，
//! 不把它解释为原生 QUIC DATAGRAM；XHTTP/3 使用专用连接，避免抢占 HTTP 控制流。

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use quinn::{Endpoint, RecvStream, SendStream};
use rustls::ClientConfig;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{config::V2rayQuic, forward::Upstream};

/// 服务端固定协商的 QUIC ALPN。
const ALPN: &[u8] = b"h3";
/// 等待并发流额度或打开流的最长期限。
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// 已准备好的 V2Ray QUIC 出站。
///
/// 同一出站的所有连接共享一条 QUIC 连接；连接失效时由下一次 `connect`
/// 重建。`tls` 只提供信任锚与证书校验名，ALPN 在建立连接时统一覆盖为
/// `h3`。
pub(crate) struct ClientPrepared {
    tls: Arc<ClientConfig>,
    server_name: String,
    idle_timeout: Duration,
    keep_alive: Option<Duration>,
    max_bidi_streams: u32,
    state: Mutex<Option<Arc<State>>>,
}

struct State {
    connection: quinn::Connection,
    /// 本地出站流额度，与服务端 `max_bidi_streams` 的口径一致。
    streams: Arc<Semaphore>,
    /// 客户端端点必须随连接一起存活，Drop 会关闭整条 QUIC 连接。
    _endpoint: Endpoint,
}

impl Drop for State {
    fn drop(&mut self) {
        // 主动关闭，保证 HTTP/3 后台任务持有的 Connection 克隆也能退出。
        self.connection.close(quinn::VarInt::from_u32(0), b"");
    }
}

/// 专用连接的所有权租约；最后一条业务流丢弃时关闭 QUIC。
pub(crate) struct DedicatedConnection {
    state: Arc<State>,
}

impl DedicatedConnection {
    pub(crate) fn connection(&self) -> quinn::Connection {
        self.state.connection.clone()
    }

    pub(crate) fn wrap<S>(self, stream: S) -> Upstream
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Upstream::new_send(
            LeasedStream {
                inner: stream,
                _lease: self,
            },
            None,
        )
    }
}

struct LeasedStream<S> {
    inner: S,
    _lease: DedicatedConnection,
}

impl<S: AsyncRead + Unpin> AsyncRead for LeasedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LeasedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl ClientPrepared {
    /// 按与入站同形状的 `V2rayQuic` 参数约束出站资源。
    ///
    /// `V2rayQuic` 描述的是服务端视角；出站复用同一组字段限制空闲超时、
    /// 保活间隔与单连接并发双向流数量。
    pub(crate) fn with_quic(tls: Arc<ClientConfig>, server_name: String, quic: &V2rayQuic) -> Self {
        let keep_alive =
            (quic.keep_alive_ms > 0).then(|| Duration::from_millis(quic.keep_alive_ms));
        Self::with_options(
            tls,
            server_name,
            Duration::from_millis(quic.idle_timeout_ms.max(1)),
            keep_alive,
            quic.max_bidi_streams.max(1),
        )
    }

    fn with_options(
        tls: Arc<ClientConfig>,
        server_name: String,
        idle_timeout: Duration,
        keep_alive: Option<Duration>,
        max_bidi_streams: u32,
    ) -> Self {
        Self {
            tls,
            server_name,
            idle_timeout,
            keep_alive,
            max_bidi_streams,
            state: Mutex::new(None),
        }
    }

    /// 地址已经过内核 DNS 策略解析；可由可克隆的连接工厂调用。
    pub(crate) async fn connect_at(
        &self,
        peer: SocketAddr,
        wait: Duration,
    ) -> io::Result<Upstream> {
        let state = self.state(peer, wait).await?;
        let permit = timeout(OPEN_STREAM_TIMEOUT, state.streams.clone().acquire_owned())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray QUIC 等待流额度超时"))?
            .map_err(|_| io::Error::other("V2Ray QUIC 流额度已关闭"))?;
        let (send, recv) = timeout(OPEN_STREAM_TIMEOUT, state.connection.open_bi())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray QUIC 打开流超时"))?
            .map_err(|error| io::Error::other(format!("V2Ray QUIC 打开流失败: {error}")))?;
        Ok(Upstream::new(
            Box::new(QuicStream {
                send,
                recv,
                _permit: permit,
                _state: state,
            }),
            None,
        ))
    }

    /// HTTP/3 会接管连接的控制流；每个 XHTTP 隧道使用专用连接。
    pub(crate) async fn open_dedicated_at(
        &self,
        peer: SocketAddr,
        wait: Duration,
    ) -> io::Result<DedicatedConnection> {
        Ok(DedicatedConnection {
            state: Arc::new(self.start(peer, wait, true).await?),
        })
    }

    async fn state(&self, peer: SocketAddr, wait: Duration) -> io::Result<Arc<State>> {
        let mut guard = self.state.lock().await;
        if let Some(state) = guard.as_ref()
            && state.connection.close_reason().is_none()
        {
            return Ok(state.clone());
        }
        let state = Arc::new(self.start(peer, wait, false).await?);
        *guard = Some(state.clone());
        Ok(state)
    }

    async fn start(&self, peer: SocketAddr, wait: Duration, http3: bool) -> io::Result<State> {
        let bind = if peer.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };

        // 出站 TLS 配置只负责信任锚与证书校验名；ALPN 必须与服务端一致。
        let mut tls = (*self.tls).clone();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        // 不使用 0-RTT：避免重放与半开连接的语义。
        tls.enable_early_data = false;
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "V2Ray QUIC TLS 配置不支持 QUIC",
                )
            })?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(self.max_bidi_streams));
        // HTTP/3 需要对端控制流和 QPACK 流；原始 V2Ray QUIC 不接受单向流。
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(if http3 { 16 } else { 0 }));
        let idle = quinn::IdleTimeout::try_from(self.idle_timeout)
            .map_err(|_| io::Error::other("V2Ray QUIC 空闲超时超出范围"))?;
        transport.max_idle_timeout(Some(idle));
        transport.keep_alive_interval(self.keep_alive);
        client.transport_config(Arc::new(transport));

        let mut endpoint = Endpoint::client(bind)?;
        endpoint.set_default_client_config(client);
        let connecting = endpoint
            .connect(peer, &self.server_name)
            .map_err(|error| io::Error::other(format!("V2Ray QUIC 连接失败: {error}")))?;
        let connection = timeout(wait, connecting)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray QUIC 握手超时"))?
            .map_err(|error| io::Error::other(format!("V2Ray QUIC 握手失败: {error}")))?;
        Ok(State {
            connection,
            streams: Arc::new(Semaphore::new(self.max_bidi_streams as usize)),
            _endpoint: endpoint,
        })
    }
}

/// 一条 V2Ray QUIC 双向流：业务字节原样承载，流关闭时归还并发额度。
struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    _permit: OwnedSemaphorePermit,
    /// 热重载丢弃旧出站时，已有流仍保持端点与连接存活。
    _state: Arc<State>,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), context)
    }
}
