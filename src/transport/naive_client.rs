//! Naive原生H1/H2/H3普通CONNECT客户端，不是Chromium/Cronet指纹模拟。
//! H1裸流或显式首8块padding，H2/H3按响应协商；派生任务由实例取消和TaskTracker管理。
use super::{
    h2_progress::{FlushIo, H2Data, H2Progress, flush as h2_flush, send as h2_send},
    naive_padding::{self, PaddedStream},
    xhttp::H2Reader,
};
use crate::{
    config::{NaiveClientOptions, NaiveHttpVersion},
    forward::{Context, Upstream},
    route::ProxyOutbound,
    session::{Host, Target},
    tls::ClientTls,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use http::{HeaderValue, Request, StatusCode};
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_util::{
    sync::{CancellationToken, PollSender},
    task::TaskTracker,
};

mod connect_h1;
mod connect_h3;
mod runtime;
mod udp;
pub(crate) use udp::open as open_udp;

const MAX_HEAD: usize = 8192;
const MAX_BLOCK: usize = 16 * 1024;
const WRITE_QUEUE: usize = 8;
const STREAM_WINDOW: u32 = 64 * 1024;
pub(super) const UOT_HOST: &str = crate::udp::UOT_V2_MAGIC;

type H3Send = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3Recv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Naive连接或发送任务已结束")
}
fn options(proxy: &ProxyOutbound) -> io::Result<&NaiveClientOptions> {
    proxy
        .naive
        .as_deref()
        .ok_or_else(|| invalid("Naive出站未初始化"))
}
fn authority(target: &Target) -> io::Result<String> {
    let host = match &target.host {
        Host::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        Host::Ip(ip) => ip.to_string(),
        Host::Domain(name)
            if !name.is_empty()
                && name.len() <= 255
                && name.bytes().all(|b| {
                    b.is_ascii_graphic() && !matches!(b, b'@' | b':' | b'/' | b'\\' | b'?' | b'#')
                }) =>
        {
            name.clone()
        }
        _ => return Err(invalid("Naive目标主机无效")),
    };
    if target.port == 0 && !matches!(&target.host, Host::Domain(name) if name == UOT_HOST) {
        return Err(invalid("Naive目标端口无效"));
    }
    Ok(format!("{host}:{}", target.port))
}
fn request(proxy: &ProxyOutbound, target: &Target) -> io::Result<Request<()>> {
    let options = options(proxy)?;
    options
        .validate()
        .map_err(|_| invalid("Naive出站参数无效"))?;
    let (username, password) = proxy
        .credentials
        .as_ref()
        .ok_or_else(|| invalid("Naive缺少Basic身份"))?;
    let mut authorization = HeaderValue::from_str(&format!(
        "Basic {}",
        STANDARD.encode(format!("{username}:{password}"))
    ))
    .map_err(|_| invalid("Naive Basic身份无效"))?;
    authorization.set_sensitive(true);
    let mut request = Request::builder()
        .method(http::Method::CONNECT)
        .uri(authority(target)?)
        .header("proxy-authorization", authorization)
        .header(
            "padding",
            HeaderValue::from_bytes(&naive_padding::request_header_value()?).map_err(error)?,
        );
    for (name, value) in &options.extra_headers {
        request = request.header(name, value);
    }
    let request = request.body(()).map_err(error)?;
    let size = request
        .headers()
        .iter()
        .map(|(n, v)| n.as_str().len() + v.len() + 32)
        .sum::<usize>()
        + request.uri().authority().map_or(0, |a| a.as_str().len())
        + 128;
    if size > MAX_HEAD {
        return Err(invalid("Naive CONNECT头过大"));
    }
    Ok(request)
}
fn response_padding(response: &http::Response<()>) -> io::Result<bool> {
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Naive上游拒绝CONNECT",
        ));
    }
    let mut padding = response.headers().get_all("padding").iter();
    let enabled = padding.next().is_some_and(|value| !value.is_empty());
    if padding.next().is_some() {
        return Err(invalid("Naive响应重复Padding头"));
    }
    Ok(enabled)
}

/// 生产根路径；H1/H2保留原TCP/via工厂，H3只使用独立QUIC。
pub(crate) fn connect<'a>(
    ctx: &'a Context,
    proxy: &'a ProxyOutbound,
    target: &'a Target,
) -> Pin<Box<dyn Future<Output = io::Result<Upstream>> + Send + 'a>> {
    Box::pin(async move {
        match options(proxy)?.http_version {
            NaiveHttpVersion::H1 | NaiveHttpVersion::H2 => {
                let wire = ctx.dial_proxy_transport(proxy, false).await?;
                connect_tcp(
                    wire,
                    proxy,
                    target,
                    ctx.children.clone(),
                    ctx.outbound_stop.clone(),
                    Duration::from_millis(ctx.limits.dial_timeout_ms),
                )
                .await
            }
            NaiveHttpVersion::H3 => connect_h3(ctx, proxy, target).await,
        }
    })
}

#[derive(Clone)]
struct Failure {
    kind: io::ErrorKind,
    message: String,
}
struct Shared {
    cancel: CancellationToken,
    failure: Mutex<Option<Failure>>,
    reader: AtomicWaker,
    writer: AtomicWaker,
}
impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancel: CancellationToken::new(),
            failure: Mutex::new(None),
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
        })
    }
    fn error(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|f| io::Error::new(f.kind, f.message.clone()))
    }
    fn fail(&self, error: io::Error) {
        let mut slot = self.failure.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(Failure {
                kind: error.kind(),
                message: error.to_string(),
            });
        }
        drop(slot);
        self.cancel.cancel();
        self.reader.wake();
        self.writer.wake();
    }
}
struct Lifetime {
    cancel: CancellationToken,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
}
impl Lifetime {
    fn new(shared: &Shared) -> Self {
        Self {
            cancel: shared.cancel.clone(),
            endpoint: None,
            connection: None,
        }
    }
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(connection) = &self.connection {
            connection.close(0u32.into(), b"naive session dropped");
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"naive session dropped");
        }
    }
}
fn spawn_io(
    tracker: &TaskTracker,
    shared: &Arc<Shared>,
    stop: CancellationToken,
    task: impl Future<Output = io::Result<()>> + Send + 'static,
) {
    let shared = shared.clone();
    tracker.spawn(async move {
        tokio::select! {
            biased;
            _ = shared.cancel.cancelled() => {},
            _ = stop.cancelled() => shared.fail(io::Error::new(io::ErrorKind::ConnectionAborted,"Naive实例已停止")),
            result = task => if let Err(error) = result { shared.fail(error); },
        }
    });
}

/// 根与链中间跳共享TCP版本分派；调用方已按所选版本完成真实TLS/ALPN校验。
pub(crate) fn connect_tcp<'a>(
    wire: Upstream,
    proxy: &'a ProxyOutbound,
    target: &'a Target,
    tracker: TaskTracker,
    stop: CancellationToken,
    wait: Duration,
) -> Pin<Box<dyn Future<Output = io::Result<Upstream>> + Send + 'a>> {
    // 固定建连边界类型擦除，不把H2 driver握手future逐层内联到TCP链。
    Box::pin(async move {
        match options(proxy)?.http_version {
            NaiveHttpVersion::H1 => {
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "Naive实例已停止")),
                    result = timeout(wait, connect_h1::connect(wire, proxy, target)) => {
                        result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive H1握手超时"))?
                    }
                }
            }
            NaiveHttpVersion::H2 => connect_h2(wire, proxy, target, tracker, stop, wait).await,
            NaiveHttpVersion::H3 => Err(invalid("Naive H3不能使用TCP承载")),
        }
    })
}

/// H2调用方必须已完成真实TLS并核ALPN h2。
pub(crate) async fn connect_h2(
    wire: Upstream,
    proxy: &ProxyOutbound,
    target: &Target,
    tracker: TaskTracker,
    stop: CancellationToken,
    wait: Duration,
) -> io::Result<Upstream> {
    let request = request(proxy, target)?;
    let local = wire.local_addr().ok();
    let shared = Shared::new();
    let lifetime = Lifetime::new(&shared); // 首个派生任务之前创建，握手取消同样回收。
    let progress = Arc::new(H2Progress::default());
    let io = FlushIo {
        inner: wire,
        progress: progress.clone(),
    };
    let (mut sender, driver) = h2::client::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(256 * 1024)
        .max_header_list_size(MAX_HEAD as u32)
        .max_frame_size(MAX_BLOCK as u32)
        .max_concurrent_streams(1)
        .handshake::<_, H2Data>(io)
        .await
        .map_err(error)?;
    let driver_progress = progress.clone();
    spawn_io(&tracker, &shared, stop.clone(), async move {
        tokio::pin!(driver);
        poll_fn(|cx| {
            driver_progress.driver_waker.register(cx.waker());
            driver.as_mut().poll(cx)
        })
        .await
        .map_err(error)
    });
    poll_fn(|cx| sender.poll_ready(cx)).await.map_err(error)?;
    let (response, send) = sender.send_request(request, false).map_err(error)?;
    let response = response.await.map_err(error)?;
    let (parts, body) = response.into_parts();
    let padded = response_padding(&http::Response::from_parts(parts, ()))?;
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    spawn_io(&tracker, &shared, stop, h2_pump(send, rx, progress, wait));
    let stream = Stream {
        reader: Reader::H2(H2Reader::new(body)),
        writer: Writer::new(tx, shared.clone()),
        shared,
        read_eof: false,
        _keepalive: Keepalive::H2(sender),
        _lifetime: lifetime,
    };
    Ok(Upstream::new_send(PaddedStream::new(stream, padded), local))
}
async fn h2_pump(
    mut send: h2::SendStream<H2Data>,
    mut rx: mpsc::Receiver<Write>,
    progress: Arc<H2Progress>,
    wait: Duration,
) -> io::Result<()> {
    while let Some(item) = rx.recv().await {
        let finishing = matches!(&item, Write::Finish(_));
        timeout(wait, async {
            match item {
                Write::Data(bytes) => h2_send(&mut send, bytes, &progress).await,
                Write::Flush(ack) => {
                    h2_flush(&progress).await?;
                    let _ = ack.send(());
                    Ok(())
                }
                Write::Finish(ack) => {
                    send.send_data(H2Data::new(Bytes::new(), &progress), true)
                        .map_err(error)?;
                    h2_flush(&progress).await?;
                    let _ = ack.send(());
                    Ok(())
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive H2写超时"))??;
        if finishing {
            return Ok(());
        }
    }
    Ok(())
}

async fn connect_h3(ctx: &Context, proxy: &ProxyOutbound, target: &Target) -> io::Result<Upstream> {
    if proxy.via.is_some() {
        return Err(invalid("Naive H3不能嵌入TCP链"));
    }
    let request = request(proxy, target)?;
    let tls = proxy.tls.as_ref().ok_or_else(|| invalid("Naive缺少TLS"))?;
    let addresses = ctx.dns.resolve(&proxy.endpoint).await?;
    if addresses.is_empty() {
        return Err(invalid("Naive上游无地址"));
    }
    // 逐个地址尝试：只试第一个会让「首个地址不可达、第二个健康」的上游整体不可用。
    let attempt = Duration::from_millis(ctx.limits.dial_attempt_timeout_ms);
    let deadline = Instant::now() + Duration::from_millis(ctx.limits.dial_timeout_ms);
    let mut last_error = None;
    let mut established = None;
    for peer in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match connect_h3_peer(ctx, tls, peer, attempt.min(remaining)).await {
            Ok(value) => {
                established = Some(value);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some((endpoint, connection, shared, lifetime)) = established else {
        return Err(last_error.unwrap_or_else(|| invalid("Naive H3连接失败")));
    };
    let negotiated = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok());
    if negotiated
        .as_ref()
        .and_then(|data| data.protocol.as_deref())
        != Some(b"h3".as_slice())
    {
        return Err(invalid("Naive H3 ALPN不匹配"));
    }
    let local = endpoint.local_addr().ok();
    let backend = connect_h3::Connect::new(connection.clone(), &request)?;
    let (mut driver, mut sender) = h3::client::builder()
        .max_field_section_size(MAX_HEAD as u64)
        .build::<_, _, Bytes>(backend)
        .await
        .map_err(error)?;
    let cancel = shared.cancel.clone();
    let stop = ctx.outbound_stop.clone();
    let status = shared.clone();
    ctx.children.spawn(async move {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {},
            _ = stop.cancelled() => status.fail(io::Error::new(io::ErrorKind::ConnectionAborted,"Naive实例已停止")),
            _ = poll_fn(|cx| driver.poll_close(cx)) => status.fail(closed()),
        }
        connection.close(0u32.into(), b"naive driver stopped");
        endpoint.close(0u32.into(), b"naive driver stopped");
    });
    let mut request_stream = sender.send_request(request).await.map_err(error)?;
    let response = request_stream.recv_response().await.map_err(error)?;
    let padded = response_padding(&response)?;
    let (send, recv) = request_stream.split();
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    spawn_io(
        &ctx.children,
        &shared,
        ctx.outbound_stop.clone(),
        h3_pump(send, rx, Duration::from_millis(ctx.limits.dial_timeout_ms)),
    );
    let stream = Stream {
        reader: Reader::H3(H3Reader {
            recv,
            current: Bytes::new(),
        }),
        writer: Writer::new(tx, shared.clone()),
        shared,
        read_eof: false,
        _keepalive: Keepalive::H3(sender),
        _lifetime: lifetime,
    };
    Ok(Upstream::new_send(PaddedStream::new(stream, padded), local))
}

/// 建立到单个地址的 H3 承载；失败时 `lifetime` 析构会取消端点清理任务。
async fn connect_h3_peer(
    ctx: &Context,
    tls: &ClientTls,
    peer: SocketAddr,
    budget: Duration,
) -> io::Result<(quinn::Endpoint, quinn::Connection, Arc<Shared>, Lifetime)> {
    let shared = Shared::new();
    let mut lifetime = Lifetime::new(&shared);
    let socket = std::net::UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    let runtime = runtime::Runtime::new(ctx.children.clone());
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime.clone(),
    )?;
    lifetime.endpoint = Some(endpoint.clone());
    // QUIC握手之前即登记端点/驱动回收；错误CA与半握手取消同样被children覆盖。
    let cleanup_endpoint = endpoint.clone();
    let cleanup_cancel = shared.cancel.clone();
    let cleanup_stop = ctx.outbound_stop.clone();
    ctx.children.spawn(async move {
        tokio::select! { biased;
            _ = cleanup_cancel.cancelled() => {},
            _ = cleanup_stop.cancelled() => {},
        }
        cleanup_endpoint.close(0u32.into(), b"naive endpoint cleanup");
        let _ = timeout(Duration::from_secs(2), cleanup_endpoint.wait_idle()).await;
        drop(cleanup_endpoint);
        runtime.shutdown().await; // 期限后也等全部Quinn驱动真正析构，不留下仍占端口的任务。
    });
    let mut config = (*tls.config).clone();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config).map_err(error)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(0u32.into());
    transport.max_concurrent_uni_streams(3u32.into());
    transport.stream_receive_window(STREAM_WINDOW.into());
    transport.receive_window((256u32 * 1024).into());
    transport.send_window(256 * 1024);
    transport.datagram_receive_buffer_size(None);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_millis(ctx.limits.udp_idle_timeout_ms))
            .map_err(error)?,
    ));
    config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(config);
    let connecting = endpoint
        .connect(peer, &tls.server_name.to_str())
        .map_err(error)?;
    let connection = match timeout(budget, connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(cause)) => return Err(error(cause)),
        Err(_) => {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Naive H3 握手超时"));
        }
    };
    lifetime.connection = Some(connection.clone());
    Ok((endpoint, connection, shared, lifetime))
}

async fn h3_pump(
    mut send: H3Send,
    mut rx: mpsc::Receiver<Write>,
    wait: Duration,
) -> io::Result<()> {
    while let Some(item) = rx.recv().await {
        let finishing = matches!(&item, Write::Finish(_));
        timeout(wait, async {
            match item {
                Write::Data(bytes) => send.send_data(bytes).await.map_err(error),
                Write::Flush(ack) => {
                    let _ = ack.send(());
                    Ok(())
                }
                Write::Finish(ack) => {
                    send.finish().await.map_err(error)?;
                    let _ = ack.send(());
                    Ok(())
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive H3写超时"))??;
        if finishing {
            return Ok(());
        }
    }
    Ok(())
}

#[allow(dead_code)]
enum Keepalive {
    H2(h2::client::SendRequest<H2Data>),
    H3(h3::client::SendRequest<connect_h3::Opener, Bytes>),
}
struct Stream {
    reader: Reader,
    writer: Writer,
    shared: Arc<Shared>,
    read_eof: bool,
    _keepalive: Keepalive,
    _lifetime: Lifetime,
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 || self.read_eof {
            return Poll::Ready(Ok(()));
        }
        self.shared.reader.register(cx.waker());
        let before = out.filled().len();
        let result = Pin::new(&mut self.reader).poll_read(cx, out);
        if matches!(&result, Poll::Ready(Ok(()))) {
            // 成熟流已明确给出END_STREAM/FIN，独立读方向的EOF不可被随后连接关闭改写。
            // 没有流FIN的连接关闭由Reader返回Err，或Pending时检查共享错误，不伪装EOF。
            if out.filled().len() == before {
                self.read_eof = true;
            }
            return result;
        }
        if let Some(error) = self.shared.error() {
            return Poll::Ready(Err(error));
        }
        result
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
enum Reader {
    H2(H2Reader),
    H3(H3Reader),
}
impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::H2(reader) => Pin::new(reader).poll_read(cx, out),
            Self::H3(reader) => Pin::new(reader).poll_read(cx, out),
        }
    }
}
struct H3Reader {
    recv: H3Recv,
    current: Bytes,
}
impl AsyncRead for H3Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.current.has_remaining() {
                let take = self.current.remaining().min(out.remaining());
                out.put_slice(&self.current[..take]);
                self.current.advance(take);
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.recv.poll_recv_data(cx)) {
                Ok(Some(mut data)) => {
                    let size = data.remaining();
                    self.current = data.copy_to_bytes(size);
                }
                Ok(None) => return Poll::Ready(Ok(())),
                Err(e) => return Poll::Ready(Err(error(e))),
            }
        }
    }
}
enum Write {
    Data(Bytes),
    Flush(oneshot::Sender<()>),
    Finish(oneshot::Sender<()>),
}
struct Writer {
    tx: PollSender<Write>,
    pending: Option<oneshot::Receiver<()>>,
    finishing: bool,
    closed: bool,
    shared: Arc<Shared>,
}
impl Writer {
    fn new(tx: mpsc::Sender<Write>, shared: Arc<Shared>) -> Self {
        Self {
            tx: PollSender::new(tx),
            pending: None,
            finishing: false,
            closed: false,
            shared,
        }
    }
    fn barrier(&mut self, cx: &mut TaskContext<'_>, finish: bool) -> Poll<io::Result<()>> {
        self.shared.writer.register(cx.waker());
        if let Some(e) = self.shared.error() {
            return Poll::Ready(Err(e));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_none() {
            std::task::ready!(self.tx.poll_reserve(cx)).map_err(|_| closed())?;
            let (tx, rx) = oneshot::channel();
            self.tx
                .send_item(if finish {
                    Write::Finish(tx)
                } else {
                    Write::Flush(tx)
                })
                .map_err(|_| closed())?;
            self.finishing = finish;
            self.pending = Some(rx);
        }
        let result =
            std::task::ready!(Pin::new(self.pending.as_mut().expect("已设置屏障")).poll(cx));
        self.pending = None;
        result.map_err(|_| self.shared.error().unwrap_or_else(closed))?;
        if self.finishing {
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.shared.writer.register(cx.waker());
        if let Some(e) = self.shared.error() {
            return Poll::Ready(Err(e));
        }
        if self.pending.is_some() {
            std::task::ready!(self.barrier(cx, false))?;
        }
        if self.closed {
            return Poll::Ready(Err(closed()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.tx.poll_reserve(cx)).map_err(|_| closed())?;
        let take = bytes.len().min(MAX_BLOCK);
        self.tx
            .send_item(Write::Data(Bytes::copy_from_slice(&bytes[..take])))
            .map_err(|_| closed())?;
        Poll::Ready(Ok(take))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.barrier(cx, false)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if self.pending.is_some() {
            std::task::ready!(self.barrier(cx, false))?;
        }
        self.barrier(cx, true)
    }
}

#[cfg(test)]
mod tests;
