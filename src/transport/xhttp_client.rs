//! XHTTP 出站：在既有 TCP（明文或 TLS）或 QUIC 连接上承载业务字节。
//!
//! 本模块只负责 HTTP 语义与字节桥接，不处理 VLESS/VMess/Trojan 认证与路由。
//! 服务端行为见 `transport::xhttp`；客户端必须生成与之完全一致的请求形状：
//!
//! - stream-one：`POST {path}`，请求体与响应体都是长连接字节流；
//! - stream-up：`POST {path}/{session}` 持续上行，`GET {path}/{session}` 单独下行；
//! - packet-up：`POST {path}/{session}/{seq}` 逐块上行，`GET {path}/{session}` 下行；
//! - auto 由客户端选择 stream-one（服务端接受任一合法形状）。
//!
//! HTTP/1.1 的分离模式必须由调用方提供独立连接工厂，不能把同一连接当成多路复用。
//! 本模块不推测 ALPN；调用方负责选择与实际协商结果一致的入口。

use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::task::AtomicWaker;
use h3::client::RequestStream;
use h3_quinn::{OpenStreams, RecvStream as H3RecvStream, SendStream as H3SendStream};
use http::{Method, Request, StatusCode};
use prost::bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::{CancellationToken, PollSender};
use tokio_util::task::TaskTracker;

use crate::config::{Mode, XhttpPadding};
use crate::forward::Upstream;

/// 请求/响应头与 chunk 行的统一上限；服务端允许最多 16 个 1KiB 自定义响应头。
const MAX_HEAD: usize = 16 * 1024;
/// 单次写入/单块上行的上限，与服务端 `CHUNK_LIMIT` 一致。
const MAX_BLOCK: usize = 64 * 1024;
/// 解析 chunked 下行时允许的最大单块声明长度；仅用于拒绝明显异常的帧。
const MAX_DOWNLINK_CHUNK: usize = 16 * 1024 * 1024;
/// HTTP/2 单帧与流控窗口，与服务端配置保持一致，避免对端缓冲过大。
const STREAM_CHUNK: usize = 16 * 1024;
const H2_INITIAL_WINDOW: u32 = 65_535;
const H2_MAX_FRAME: u32 = 16_384;
const H2_MAX_CONCURRENT: u32 = 64;
/// 上行待写队列长度：队列 × 单块上限 = 有界内存。
const WRITE_QUEUE: usize = 16;
/// 下行待读队列长度。
const READ_QUEUE: usize = 16;
/// 响应头、拨号、单块传输与 flush 屏障分别有界；空闲隧道不受此限制。
const OP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_POST_RESPONSE: usize = 16 * 1024;
const MAX_REQUEST_HEAD: usize = 8_192;

/// H1 分离模式需要新的端点流；工厂必须保留调用方的 TLS、via 与路由语义。
pub(crate) type OpenStream =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<Upstream>> + Send>> + Send + Sync>;

#[derive(Clone, Debug)]
pub(crate) struct ClientOptions {
    pub path: String,
    pub host: Option<String>,
    pub mode: Mode,
    pub h3: bool,
    pub headers: BTreeMap<String, String>,
    pub x_padding: Option<XhttpPadding>,
    pub max_post_bytes: usize,
}

#[derive(Clone)]
struct Failure {
    kind: io::ErrorKind,
    message: String,
}

impl Failure {
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

/// 错误保存在通道之外，队列堵塞或任务被取消时也不能把失败变成 EOF。
struct Shared {
    cancel: CancellationToken,
    error: Mutex<Option<Failure>>,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancel: CancellationToken::new(),
            error: Mutex::new(None),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        })
    }

    fn error(&self) -> Option<io::Error> {
        self.error
            .lock()
            .expect("XHTTP错误锁未中毒")
            .as_ref()
            .map(Failure::error)
    }

    fn fail(&self, error: io::Error) {
        let mut slot = self.error.lock().unwrap_or_else(|error| error.into_inner());
        if slot.is_none() {
            *slot = Some(Failure {
                kind: error.kind(),
                message: error.to_string(),
            });
        }
        drop(slot);
        self.cancel.cancel();
        self.read_waker.wake();
        self.write_waker.wake();
    }
}

/// 在第一次 await 之前创建；握手 future 被丢弃时也会终止已经派生的任务。
struct Lifetime {
    cancel: CancellationToken,
    quic: Option<quinn::Connection>,
}

impl Lifetime {
    fn new(shared: &Shared) -> Self {
        Self {
            cancel: shared.cancel.clone(),
            quic: None,
        }
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(connection) = &self.quic {
            connection.close(0u32.into(), b"XHTTP client dropped");
        }
    }
}

fn spawn_io<F>(tracker: &TaskTracker, shared: &Arc<Shared>, future: F)
where
    F: Future<Output = io::Result<()>> + Send + 'static,
{
    let shared = shared.clone();
    tracker.spawn(async move {
        tokio::select! {
            biased;
            _ = shared.cancel.cancelled() => {}
            result = future => if let Err(error) = result { shared.fail(error); },
        }
    });
}

async fn bounded<T>(future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    timeout(OP_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP请求或写入超时"))?
}

/// XHTTP 字节流：读方向还原下行字节，写方向按所选模式发送上行。
///
/// `S` 只用于类型归属（HTTP/1.1 的底层流已被拆成后台任务），
/// 因此 HTTP/2 与 HTTP/3 也可以复用同一个类型。
pub(crate) struct XhttpStream<S> {
    reader: ChannelReader,
    writer: ChannelWriter,
    _keepalive: KeepAlive,
    shared: Arc<Shared>,
    _lifetime: Lifetime,
    _marker: PhantomData<fn() -> S>,
}

impl<S> XhttpStream<S> {
    fn new(
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Upload>,
        keepalive: KeepAlive,
        shared: Arc<Shared>,
        lifetime: Lifetime,
        max_block: usize,
    ) -> Self {
        Self {
            reader: ChannelReader::new(rx),
            writer: ChannelWriter::new(tx, shared.clone(), max_block),
            _keepalive: keepalive,
            shared,
            _lifetime: lifetime,
            _marker: PhantomData,
        }
    }
}

impl<S> Drop for XhttpStream<S> {
    fn drop(&mut self) {
        self.shared.cancel.cancel();
    }
}

/// 没有工厂时，H1 只能承载 stream-one（含 auto）。
pub(crate) async fn connect_h1<S>(stream: S, options: &ClientOptions) -> io::Result<XhttpStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_h1_tracked(stream, options, &TaskTracker::new()).await
}

pub(crate) async fn connect_h1_tracked<S>(
    stream: S,
    options: &ClientOptions,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    validate_options(options)?;
    if effective_mode(options.mode) != Mode::StreamOne {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "XHTTP/1.1分离模式需要独立连接工厂",
        ));
    }
    let shared = Shared::new();
    let lifetime = Lifetime::new(&shared);
    let (mut read, mut write) = tokio::io::split(stream);
    let head = h1_request(Method::POST, options, None, None, None)?;
    bounded(async {
        write.write_all(head.as_bytes()).await?;
        write.flush().await
    })
    .await?;
    // 必须允许调用方先写认证字节；不能等服务器响应头才返回隧道。
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (out, out_rx) = mpsc::channel(READ_QUEUE);
    spawn_io(tracker, &shared, h1_upload_pump(write, rx, None));
    spawn_io(tracker, &shared, async move {
        let response = bounded(read_h1_response_head(&mut read)).await?;
        ensure_ok("XHTTP/1.1", response.status)?;
        require_chunked(&response)?;
        h1_downlink_pump(H1BodyReader::new(read), out).await
    });
    Ok(XhttpStream::new(
        out_rx,
        tx,
        KeepAlive::None,
        shared,
        lifetime,
        options.max_post_bytes,
    ))
}

pub(crate) async fn connect_h1_with_opener_tracked(
    initial: Upstream,
    options: &ClientOptions,
    opener: OpenStream,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<Upstream>> {
    if effective_mode(options.mode) == Mode::StreamOne {
        return connect_h1_tracked(initial, options, tracker).await;
    }
    validate_options(options)?;
    let shared = Shared::new();
    let lifetime = Lifetime::new(&shared);
    let session = unique_session_id()?;
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (out, out_rx) = mpsc::channel(READ_QUEUE);
    let (started, wait_started) = oneshot::channel();
    let get_options = options.clone();
    let get_session = session.clone();
    let get_opener = opener.clone();
    spawn_io(tracker, &shared, async move {
        wait_started.await.map_err(|_| closed())?;
        h1_downlink_get(get_opener, &get_options, &get_session, out).await
    });
    match effective_mode(options.mode) {
        Mode::StreamUp => {
            spawn_io(
                tracker,
                &shared,
                h1_stream_up_manager(
                    initial,
                    opener,
                    options.clone(),
                    session,
                    rx,
                    started,
                    tracker.clone(),
                    shared.clone(),
                ),
            );
        }
        Mode::PacketUp => {
            spawn_io(
                tracker,
                &shared,
                h1_packet_up_manager(initial, opener, options.clone(), session, rx, started),
            );
        }
        _ => unreachable!("分离模式已归一化"),
    }
    Ok(XhttpStream::new(
        out_rx,
        tx,
        KeepAlive::None,
        shared,
        lifetime,
        options.max_post_bytes,
    ))
}

/// 调用方必须已经确认 ALPN 为 h2，或明确选择明文 h2c prior-knowledge。
pub(crate) async fn connect_h2<S>(stream: S, options: &ClientOptions) -> io::Result<XhttpStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_h2_tracked(stream, options, &TaskTracker::new()).await
}

pub(crate) async fn connect_h2_tracked<S>(
    stream: S,
    options: &ClientOptions,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    validate_options(options)?;
    let shared = Shared::new();
    let lifetime = Lifetime::new(&shared);
    let progress = Arc::new(H2Progress::default());
    let stream = FlushIo {
        inner: stream,
        progress: progress.clone(),
    };
    let (send_request, connection) = bounded(async {
        h2::client::Builder::new()
            .initial_window_size(H2_INITIAL_WINDOW)
            .initial_connection_window_size(H2_INITIAL_WINDOW)
            .max_frame_size(H2_MAX_FRAME)
            .max_header_list_size(MAX_HEAD as u32)
            .max_concurrent_streams(H2_MAX_CONCURRENT)
            .handshake::<_, H2Data>(stream)
            .await
            .map_err(h2_error)
    })
    .await?;
    let driver_progress = progress.clone();
    spawn_io(tracker, &shared, async move {
        tokio::pin!(connection);
        poll_fn(|cx| {
            driver_progress.driver_waker.register(cx.waker());
            connection.as_mut().poll(cx)
        })
        .await
        .map_err(h2_error)?;
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "XHTTP/2连接已结束",
        ))
    });
    match effective_mode(options.mode) {
        Mode::StreamOne => {
            h2_stream_one(send_request, options, shared, lifetime, progress, tracker).await
        }
        Mode::StreamUp => {
            h2_stream_up(send_request, options, shared, lifetime, progress, tracker).await
        }
        Mode::PacketUp => h2_packet_up(send_request, options, shared, lifetime, progress, tracker),
        Mode::Auto => unreachable!("auto已归一化"),
    }
}

pub(crate) async fn connect_h3_tracked(
    connection: quinn::Connection,
    options: &ClientOptions,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<quinn::Connection>> {
    let shared = Shared::new();
    let mut lifetime = Lifetime::new(&shared);
    lifetime.quic = Some(connection.clone());
    validate_options(options)?;
    let handshake = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XHTTP/3缺少真实TLS握手信息"))?;
    if handshake.protocol.as_deref() != Some(b"h3".as_slice()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XHTTP/3协商ALPN不是h3",
        ));
    }
    let mut builder = h3::client::builder();
    builder.max_field_section_size(MAX_HEAD as u64);
    let (mut driver, send_request) = bounded(async {
        builder
            .build::<_, OpenStreams, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .map_err(h3_error)
    })
    .await?;
    spawn_io(tracker, &shared, async move {
        // 此vendor的poll_close/wait_idle返回ConnectionError，而非Result。
        Err(h3_error(driver.wait_idle().await))
    });
    match effective_mode(options.mode) {
        Mode::StreamOne => h3_stream_one(send_request, options, shared, lifetime, tracker).await,
        Mode::StreamUp => h3_stream_up(send_request, options, shared, lifetime, tracker).await,
        Mode::PacketUp => h3_packet_up(send_request, options, shared, lifetime, tracker),
        Mode::Auto => unreachable!("auto已归一化"),
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1
// ---------------------------------------------------------------------------

struct H1ResponseHead {
    status: StatusCode,
    chunked: bool,
    length: Option<usize>,
}

/// 逐字节读取响应头，避免越过 `\r\n\r\n` 吞掉后续业务字节。
async fn read_h1_response_head<R: AsyncRead + Unpin>(read: &mut R) -> io::Result<H1ResponseHead> {
    // 允许少量 1xx 临时响应；其余状态原样返回给调用方判断。
    for _ in 0..4 {
        let mut raw = Vec::new();
        loop {
            let byte = read.read_u8().await.map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "XHTTP 响应头被截断")
                } else {
                    error
                }
            })?;
            raw.push(byte);
            if raw.len() > MAX_HEAD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XHTTP 响应头过长",
                ));
            }
            if raw.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = std::str::from_utf8(&raw)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XHTTP 响应头非 UTF8"))?;
        let mut lines = text.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let mut parts = status_line.split_whitespace();
        let version = parts.next().unwrap_or("");
        if !version.starts_with("HTTP/1.") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XHTTP 响应状态行非法",
            ));
        }
        let status = parts
            .next()
            .and_then(|text| text.parse::<u16>().ok())
            .and_then(|code| StatusCode::from_u16(code).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XHTTP 响应状态码非法"))?;

        let mut chunked = false;
        let mut length = None;
        let mut count = 0usize;
        for line in lines {
            if line.is_empty() {
                break;
            }
            count += 1;
            if count > 64 {
                return Err(invalid("XHTTP响应头数量超限"));
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("XHTTP响应头非法"))?;
            http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| invalid("响应头名称非法"))?;
            http::header::HeaderValue::from_str(value.trim())
                .map_err(|_| invalid("响应头值非法"))?;
            if name.eq_ignore_ascii_case("transfer-encoding") {
                if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                    return Err(invalid("XHTTP响应Transfer-Encoding非法"));
                }
                chunked = true;
            }
            if name.eq_ignore_ascii_case("content-length") {
                let parsed = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| invalid("响应长度非法"))?;
                if length.is_some() {
                    return Err(invalid("重复响应Content-Length"));
                }
                length = Some(parsed);
            }
        }
        if chunked && length.is_some() {
            return Err(invalid("响应同时声明长度和chunked"));
        }
        if status.is_informational() {
            if status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(invalid("XHTTP不接受协议升级"));
            }
            continue;
        }
        return Ok(H1ResponseHead {
            status,
            chunked,
            length,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "XHTTP 临时响应过多",
    ))
}

fn require_chunked(response: &H1ResponseHead) -> io::Result<()> {
    if response.chunked {
        Ok(())
    } else {
        Err(invalid("XHTTP/1.1下行响应不是chunked编码"))
    }
}

async fn drain_h1_response<R: AsyncRead + Unpin>(
    read: R,
    response: H1ResponseHead,
) -> io::Result<()> {
    bounded(async move {
        // 不需要装箱，分别复用同一个有界排空器。
        if response.chunked {
            drain_small(H1BodyReader::new(read)).await
        } else if let Some(length) = response.length {
            if length > MAX_POST_RESPONSE {
                return Err(invalid("XHTTP上行响应体过大"));
            }
            let mut body = read.take(length as u64);
            let mut bytes = Vec::new();
            body.read_to_end(&mut bytes).await?;
            if bytes.len() != length {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "POST响应体截断",
                ));
            }
            Ok(())
        } else {
            drain_small(read).await
        }
    })
    .await
}

async fn drain_small<R: AsyncRead + Unpin>(mut read: R) -> io::Result<()> {
    let mut total = 0;
    let mut bytes = [0u8; 4096];
    loop {
        let n = read.read(&mut bytes).await?;
        if n == 0 {
            return Ok(());
        }
        total += n;
        if total > MAX_POST_RESPONSE {
            return Err(invalid("XHTTP上行响应体过大"));
        }
    }
}

/// 上行命令按序执行；Flush确认必须等到底层flush，不能只检查本地队列。
async fn h1_upload_pump<W: AsyncWrite + Unpin>(
    mut write: W,
    mut rx: mpsc::Receiver<Upload>,
    mut started: Option<oneshot::Sender<()>>,
) -> io::Result<()> {
    while let Some(command) = rx.recv().await {
        match command {
            Upload::Data(chunk) => {
                bounded(async {
                    write
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await?;
                    write.write_all(&chunk).await?;
                    write.write_all(b"\r\n").await?;
                    write.flush().await
                })
                .await?;
                if let Some(started) = started.take() {
                    let _ = started.send(());
                }
            }
            Upload::Flush(ack) => {
                bounded(write.flush()).await?;
                let _ = ack.send(());
            }
            Upload::Shutdown(ack) => {
                bounded(async {
                    write.write_all(b"0\r\n\r\n").await?;
                    write.flush().await?;
                    write.shutdown().await
                })
                .await?;
                let _ = ack.send(());
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn h1_downlink_pump<R: AsyncRead + Unpin>(
    mut body: H1BodyReader<R>,
    out: mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let mut buffer = vec![0u8; MAX_BLOCK];
    loop {
        let n = body.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        out.send(buffer[..n].to_vec()).await.map_err(|_| closed())?;
    }
}

async fn h1_downlink_get(
    opener: OpenStream,
    options: &ClientOptions,
    session: &str,
    out: mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let mut stream = bounded(opener()).await?;
    let head = h1_request(Method::GET, options, Some(session), None, Some(0))?;
    bounded(async {
        stream.write_all(head.as_bytes()).await?;
        stream.flush().await
    })
    .await?;
    let response = bounded(read_h1_response_head(&mut stream)).await?;
    ensure_ok("XHTTP/1.1下行", response.status)?;
    require_chunked(&response)?;
    h1_downlink_pump(H1BodyReader::new(stream), out).await
}

/// 上传响应单独驱动；同一隧道最多一个POST响应任务，错误进入共享状态。
fn spawn_response<F>(
    tracker: &TaskTracker,
    shared: &Arc<Shared>,
    future: F,
) -> tokio::task::JoinHandle<io::Result<()>>
where
    F: Future<Output = io::Result<()>> + Send + 'static,
{
    let shared = shared.clone();
    tracker.spawn(async move {
        tokio::select! {
            biased;
            _ = shared.cancel.cancelled() => Err(closed()),
            result = future => {
                if let Err(error) = &result {
                    shared.fail(io::Error::new(error.kind(), error.to_string()));
                }
                result
            }
        }
    })
}

async fn join_response(task: tokio::task::JoinHandle<io::Result<()>>) -> io::Result<()> {
    bounded(async { task.await.map_err(io::Error::other)? }).await
}

async fn h1_start_upload(
    mut stream: Upstream,
    options: &ClientOptions,
    session: &str,
    tracker: &TaskTracker,
    shared: &Arc<Shared>,
) -> io::Result<(
    tokio::io::WriteHalf<Upstream>,
    tokio::task::JoinHandle<io::Result<()>>,
    CancellationToken,
)> {
    let head = h1_request(Method::POST, options, Some(session), None, None)?;
    bounded(async {
        stream.write_all(head.as_bytes()).await?;
        stream.flush().await
    })
    .await?;
    let (mut read, write) = tokio::io::split(stream);
    let finished = CancellationToken::new();
    let response_finished = finished.clone();
    let response = spawn_response(tracker, shared, async move {
        let response = {
            let response = read_h1_response_head(&mut read);
            tokio::pin!(response);
            tokio::select! {
                result = &mut response => result?,
                _ = response_finished.cancelled() => bounded(response).await?,
            }
        };
        ensure_ok("XHTTP/1.1上行", response.status)?;
        drain_h1_response(read, response).await
    });
    Ok((write, response, finished))
}

// 上行管理器的固定句柄集合；拆分只会让生命周期更难表达。
#[allow(clippy::too_many_arguments)]
async fn h1_stream_up_manager(
    initial: Upstream,
    _opener: OpenStream,
    options: ClientOptions,
    session: String,
    rx: mpsc::Receiver<Upload>,
    started: oneshot::Sender<()>,
    tracker: TaskTracker,
    shared: Arc<Shared>,
) -> io::Result<()> {
    let (write, response, finished) =
        h1_start_upload(initial, &options, &session, &tracker, &shared).await?;
    h1_upload_pump(write, rx, Some(started)).await?;
    finished.cancel();
    join_response(response).await
}

/// 每个POST独占连接；仅有一个顺序上传任务及一个GET任务，不按块派生任务。
async fn h1_packet_up_manager(
    initial: Upstream,
    opener: OpenStream,
    options: ClientOptions,
    session: String,
    mut rx: mpsc::Receiver<Upload>,
    started: oneshot::Sender<()>,
) -> io::Result<()> {
    let mut initial = Some(initial);
    let mut started = Some(started);
    let mut seq = 0u64;
    while let Some(command) = rx.recv().await {
        match command {
            Upload::Data(payload) => {
                let mut stream = match initial.take() {
                    Some(stream) => stream,
                    None => bounded(opener()).await?,
                };
                let head = h1_request(
                    Method::POST,
                    &options,
                    Some(&session),
                    Some(seq),
                    Some(payload.len()),
                )?;
                bounded(async {
                    stream.write_all(head.as_bytes()).await?;
                    stream.write_all(&payload).await?;
                    stream.flush().await
                })
                .await?;
                let response = bounded(read_h1_response_head(&mut stream)).await?;
                ensure_ok("XHTTP/1.1上行", response.status)?;
                drain_h1_response(stream, response).await?;
                seq = seq.checked_add(1).ok_or_else(|| invalid("XHTTP序号溢出"))?;
                if let Some(started) = started.take() {
                    let _ = started.send(());
                }
            }
            Upload::Flush(ack) => {
                let _ = ack.send(());
            }
            Upload::Shutdown(ack) => {
                // packet-up线上没有结束上传的保留帧；不能伪造空POST当作FIN。
                let _ = ack.send(());
                return Ok(());
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ChunkState {
    Size,
    Data,
    DataCrlf,
    Trailer,
    Done,
}

/// chunked 请求体的流式解码器；只缓冲元数据，块内容直接交给调用方。
struct H1BodyReader<R> {
    inner: R,
    buffer: Vec<u8>,
    offset: usize,
    remaining: usize,
    state: ChunkState,
    eof: bool,
    trailer_bytes: usize,
}

impl<R> H1BodyReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            offset: 0,
            remaining: 0,
            state: ChunkState::Size,
            eof: false,
            trailer_bytes: 0,
        }
    }

    fn compact(&mut self) {
        if self.offset == self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        }
    }
}

impl<R: AsyncRead + Unpin> H1BodyReader<R> {
    fn read_more(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut chunk = [0u8; 4096];
        let mut read = ReadBuf::new(&mut chunk);
        std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
        let filled = read.filled();
        if filled.is_empty() {
            self.eof = true;
        } else {
            self.buffer.extend_from_slice(filled);
        }
        Poll::Ready(Ok(()))
    }

    fn take_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Some(end) = self.buffer[self.offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| self.offset + index)
        else {
            return Ok(None);
        };
        if end - self.offset > MAX_HEAD {
            return Err(invalid("XHTTP chunk元数据行过长"));
        }
        let line = self.buffer[self.offset..end].to_vec();
        self.offset = end + 2;
        self.compact();
        Ok(Some(line))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for H1BodyReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let this = &mut *self;
            match this.state {
                ChunkState::Size => {
                    if let Some(line) = this.take_line()? {
                        let text = std::str::from_utf8(&line).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "chunk 长度非 ASCII")
                        })?;
                        let size =
                            usize::from_str_radix(text.split(';').next().unwrap_or("").trim(), 16)
                                .map_err(|_| {
                                    io::Error::new(io::ErrorKind::InvalidData, "非法 chunk 长度")
                                })?;
                        if size > MAX_DOWNLINK_CHUNK {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "XHTTP 下行块过大",
                            )));
                        }
                        if size == 0 {
                            this.state = ChunkState::Trailer;
                        } else {
                            this.remaining = size;
                            this.state = ChunkState::Data;
                        }
                        continue;
                    }
                    if this.eof {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "chunk 长度被截断",
                        )));
                    }
                    if this.buffer.len() - this.offset > MAX_HEAD {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk 长度行过长",
                        )));
                    }
                    std::task::ready!(this.read_more(cx))?;
                }
                ChunkState::Data => {
                    if this.remaining == 0 {
                        this.state = ChunkState::DataCrlf;
                        continue;
                    }
                    let available = this.buffer.len() - this.offset;
                    if available > 0 {
                        let take = available.min(this.remaining).min(buf.remaining());
                        buf.put_slice(&this.buffer[this.offset..this.offset + take]);
                        this.offset += take;
                        this.remaining -= take;
                        this.compact();
                        return Poll::Ready(Ok(()));
                    }
                    if this.eof {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "chunk 正文被截断",
                        )));
                    }
                    std::task::ready!(this.read_more(cx))?;
                }
                ChunkState::DataCrlf => {
                    if this.buffer.len() - this.offset < 2 {
                        if this.eof {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "chunk 结尾被截断",
                            )));
                        }
                        std::task::ready!(this.read_more(cx))?;
                        continue;
                    }
                    if &this.buffer[this.offset..this.offset + 2] != b"\r\n" {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk 结尾非法",
                        )));
                    }
                    this.offset += 2;
                    this.compact();
                    this.state = ChunkState::Size;
                }
                ChunkState::Trailer => {
                    if let Some(line) = this.take_line()? {
                        this.trailer_bytes += line.len() + 2;
                        if this.trailer_bytes > MAX_HEAD {
                            return Poll::Ready(Err(invalid("XHTTP trailer总量超限")));
                        }
                        if line.is_empty() {
                            this.state = ChunkState::Done;
                        } else if !line.contains(&b':') {
                            return Poll::Ready(Err(invalid("XHTTP trailer格式非法")));
                        }
                        continue;
                    }
                    if this.eof {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "chunk trailer 被截断",
                        )));
                    }
                    if this.buffer.len() - this.offset > MAX_HEAD {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk trailer 过长",
                        )));
                    }
                    std::task::ready!(this.read_more(cx))?;
                }
                ChunkState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP/2
// ---------------------------------------------------------------------------

use super::h2_progress::{FlushIo, H2Data, H2Progress};

type H2Sender = h2::client::SendRequest<H2Data>;

async fn h2_flush(progress: &H2Progress) -> io::Result<()> {
    let target = progress.submitted.load(Ordering::SeqCst);
    bounded(poll_fn(|cx| {
        progress.waker.register(cx.waker());
        if progress.flushed.load(Ordering::SeqCst) >= target {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }))
    .await
}

async fn h2_open(
    sender: &mut H2Sender,
    request: Request<()>,
    end: bool,
) -> io::Result<(h2::client::ResponseFuture, h2::SendStream<H2Data>)> {
    bounded(async {
        poll_fn(|cx| sender.poll_ready(cx))
            .await
            .map_err(h2_error)?;
        sender.send_request(request, end).map_err(h2_error)
    })
    .await
}

async fn h2_stream_one<S>(
    mut sender: H2Sender,
    options: &ClientOptions,
    shared: Arc<Shared>,
    lifetime: Lifetime,
    progress: Arc<H2Progress>,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<S>> {
    let (response, upload) = h2_open(
        &mut sender,
        h2_request(Method::POST, options, None, None)?,
        false,
    )
    .await?;
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (out, out_rx) = mpsc::channel(READ_QUEUE);
    spawn_io(
        tracker,
        &shared,
        h2_upload_pump(upload, rx, progress, None, None),
    );
    spawn_io(tracker, &shared, async move {
        let response = bounded(async { response.await.map_err(h2_error) }).await?;
        ensure_ok("XHTTP/2", response.status())?;
        h2_download(response.into_body(), out).await
    });
    Ok(XhttpStream::new(
        out_rx,
        tx,
        KeepAlive::H2(sender),
        shared,
        lifetime,
        options.max_post_bytes,
    ))
}

async fn h2_stream_up<S>(
    mut sender: H2Sender,
    options: &ClientOptions,
    shared: Arc<Shared>,
    lifetime: Lifetime,
    progress: Arc<H2Progress>,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<S>> {
    let session = unique_session_id()?;
    let ready = CancellationToken::new();
    let upload = h2_start_upload(&mut sender, options, &session, tracker, &shared, &ready).await?;
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (out, out_rx) = mpsc::channel(READ_QUEUE);
    spawn_io(
        tracker,
        &shared,
        h2_stream_up_manager(upload, rx, progress, ready.clone()),
    );
    let get_options = options.clone();
    let get_sender = sender.clone();
    spawn_io(tracker, &shared, async move {
        ready.cancelled().await;
        h2_downlink_get(get_sender, &get_options, &session, out, true).await
    });
    Ok(XhttpStream::new(
        out_rx,
        tx,
        KeepAlive::H2(sender),
        shared,
        lifetime,
        options.max_post_bytes,
    ))
}

type H2Upload = (
    h2::SendStream<H2Data>,
    tokio::task::JoinHandle<io::Result<()>>,
    CancellationToken,
);

async fn h2_start_upload(
    sender: &mut H2Sender,
    options: &ClientOptions,
    session: &str,
    tracker: &TaskTracker,
    shared: &Arc<Shared>,
    ready: &CancellationToken,
) -> io::Result<H2Upload> {
    let (response, send) = h2_open(
        sender,
        h2_request(Method::POST, options, Some(session), None)?,
        false,
    )
    .await?;
    let finished = CancellationToken::new();
    let response_finished = finished.clone();
    let ready = ready.clone();
    let task = spawn_response(tracker, shared, async move {
        tokio::pin!(response);
        let response = tokio::select! {
            result = &mut response => result.map_err(h2_error)?,
            _ = response_finished.cancelled() => bounded(async { response.await.map_err(h2_error) }).await?,
        };
        ensure_ok("XHTTP/2上行", response.status())?;
        ready.cancel();
        let mut body = response.into_body();
        {
            let drain = h2_drain_post(&mut body);
            tokio::pin!(drain);
            tokio::select! {
                result = &mut drain => result,
                _ = response_finished.cancelled() => bounded(drain).await,
            }
        }
    });
    Ok((send, task, finished))
}

async fn h2_finish_upload(
    send: &mut h2::SendStream<H2Data>,
    progress: &Arc<H2Progress>,
    finished: &CancellationToken,
) -> io::Result<()> {
    send.send_data(H2Data::new(Bytes::new(), progress), true)
        .map_err(h2_error)?;
    h2_flush(progress).await?;
    finished.cancel();
    Ok(())
}

async fn h2_stream_up_manager(
    upload: H2Upload,
    mut rx: mpsc::Receiver<Upload>,
    progress: Arc<H2Progress>,
    ready: CancellationToken,
) -> io::Result<()> {
    let (mut send, response, finished) = upload;
    while let Some(command) = rx.recv().await {
        match command {
            Upload::Data(chunk) => {
                bounded(h2_send_all(&mut send, &chunk, &progress)).await?;
                // stream-up 与独立 GET 下行共享同一条 H2 连接；逐块 flush 会在
                // 下行窗口被读端暂时填满时把上行阻塞在 flush 屏障上。数据已
                // 交给 h2 连接驱动，显式 Flush 命令仍会等待完整屏障。
                ready.cancel();
            }
            Upload::Flush(ack) => {
                h2_flush(&progress).await?;
                let _ = ack.send(());
            }
            Upload::Shutdown(ack) => {
                h2_finish_upload(&mut send, &progress, &finished).await?;
                join_response(response).await?;
                let _ = ack.send(());
                return Ok(());
            }
        }
    }
    Ok(())
}

fn h2_packet_up<S>(
    sender: H2Sender,
    options: &ClientOptions,
    shared: Arc<Shared>,
    lifetime: Lifetime,
    progress: Arc<H2Progress>,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<S>> {
    let session = unique_session_id()?;
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (out, out_rx) = mpsc::channel(READ_QUEUE);
    let (started, wait_started) = oneshot::channel();
    let get_sender = sender.clone();
    let get_options = options.clone();
    let get_session = session.clone();
    spawn_io(tracker, &shared, async move {
        wait_started.await.map_err(|_| closed())?;
        h2_downlink_get(get_sender, &get_options, &get_session, out, false).await
    });
    spawn_io(
        tracker,
        &shared,
        h2_packet_up_manager(
            sender.clone(),
            options.clone(),
            session,
            rx,
            started,
            progress,
        ),
    );
    Ok(XhttpStream::new(
        out_rx,
        tx,
        KeepAlive::H2(sender),
        shared,
        lifetime,
        options.max_post_bytes,
    ))
}

async fn h2_packet_up_manager(
    mut sender: H2Sender,
    options: ClientOptions,
    session: String,
    mut rx: mpsc::Receiver<Upload>,
    started: oneshot::Sender<()>,
    progress: Arc<H2Progress>,
) -> io::Result<()> {
    let mut seq = 0u64;
    let mut started = Some(started);
    while let Some(command) = rx.recv().await {
        match command {
            Upload::Data(payload) => {
                bounded(h2_post_block(
                    &mut sender,
                    &options,
                    &session,
                    seq,
                    payload,
                    &progress,
                ))
                .await?;
                seq = seq.checked_add(1).ok_or_else(|| invalid("XHTTP序号溢出"))?;
                if let Some(started) = started.take() {
                    let _ = started.send(());
                }
            }
            Upload::Flush(ack) => {
                h2_flush(&progress).await?;
                let _ = ack.send(());
            }
            Upload::Shutdown(ack) => {
                h2_flush(&progress).await?;
                let _ = ack.send(());
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn h2_post_block(
    sender: &mut H2Sender,
    options: &ClientOptions,
    session: &str,
    seq: u64,
    payload: Vec<u8>,
    progress: &Arc<H2Progress>,
) -> io::Result<()> {
    let request = h2_request(Method::POST, options, Some(session), Some(seq))?;
    let (response, mut upload) = h2_open(sender, request, false).await?;
    h2_send_all(&mut upload, &payload, progress).await?;
    upload
        .send_data(H2Data::new(Bytes::new(), progress), true)
        .map_err(h2_error)?;
    let response = response.await.map_err(h2_error)?;
    ensure_ok("XHTTP/2上行", response.status())?;
    h2_drain_post(&mut response.into_body()).await
}

async fn h2_drain_post(body: &mut h2::RecvStream) -> io::Result<()> {
    let mut total = 0usize;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_error)?;
        total += chunk.len();
        if total > MAX_POST_RESPONSE {
            return Err(invalid("XHTTP上行响应体过大"));
        }
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(h2_error)?;
    }
    body.trailers().await.map_err(h2_error)?;
    Ok(())
}

async fn h2_downlink_get(
    mut sender: H2Sender,
    options: &ClientOptions,
    session: &str,
    out: mpsc::Sender<Vec<u8>>,
    retry: bool,
) -> io::Result<()> {
    for attempt in 0..8 {
        let (response, send) = h2_open(
            &mut sender,
            h2_request(Method::GET, options, Some(session), None)?,
            true,
        )
        .await?;
        drop(send);
        let response = bounded(async { response.await.map_err(h2_error) }).await?;
        if retry && response.status() == StatusCode::NOT_FOUND && attempt < 7 {
            bounded(h2_drain_post(&mut response.into_body())).await?;
            tokio::time::sleep(Duration::from_millis(5 << attempt.min(5))).await;
            continue;
        }
        ensure_ok("XHTTP/2下行", response.status())?;
        return h2_download(response.into_body(), out).await;
    }
    Err(invalid("XHTTP下行重试耗尽"))
}

async fn h2_download(body: h2::RecvStream, out: mpsc::Sender<Vec<u8>>) -> io::Result<()> {
    let mut body = H2BodyReader::new(body);
    let mut bytes = vec![0u8; MAX_BLOCK];
    loop {
        let n = body.read(&mut bytes).await?;
        if n == 0 {
            return Ok(());
        }
        out.send(bytes[..n].to_vec()).await.map_err(|_| closed())?;
    }
}

async fn h2_upload_pump(
    mut send: h2::SendStream<H2Data>,
    mut rx: mpsc::Receiver<Upload>,
    progress: Arc<H2Progress>,
    ready: Option<CancellationToken>,
    finished: Option<CancellationToken>,
) -> io::Result<()> {
    while let Some(command) = rx.recv().await {
        match command {
            Upload::Data(chunk) => {
                bounded(h2_send_all(&mut send, &chunk, &progress)).await?;
                h2_flush(&progress).await?;
                if let Some(ready) = &ready {
                    ready.cancel();
                }
            }
            Upload::Flush(ack) => {
                h2_flush(&progress).await?;
                let _ = ack.send(());
            }
            Upload::Shutdown(ack) => {
                send.send_data(H2Data::new(Bytes::new(), &progress), true)
                    .map_err(h2_error)?;
                h2_flush(&progress).await?;
                if let Some(finished) = &finished {
                    finished.cancel();
                }
                let _ = ack.send(());
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn h2_send_all(
    send: &mut h2::SendStream<H2Data>,
    data: &[u8],
    progress: &Arc<H2Progress>,
) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        if send.capacity() == 0 {
            send.reserve_capacity(remaining);
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(0)) => continue,
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(h2_error(error)),
                None => return Err(closed()),
            }
        }
        let take = send.capacity().min(remaining).min(STREAM_CHUNK);
        if take == 0 {
            continue;
        }
        send.send_data(
            H2Data::new(
                Bytes::copy_from_slice(&data[offset..offset + take]),
                progress,
            ),
            false,
        )
        .map_err(h2_error)?;
        offset += take;
    }
    Ok(())
}

struct H2BodyReader {
    body: h2::RecvStream,
    current: Bytes,
    offset: usize,
}

impl H2BodyReader {
    fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            current: Bytes::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for H2BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.offset < this.current.len() {
                let take = buf.remaining().min(this.current.len() - this.offset);
                buf.put_slice(&this.current[this.offset..this.offset + take]);
                this.offset += take;
                // 归还窗口，否则长连接会在初始 64KiB 后停滞。
                this.body
                    .flow_control()
                    .release_capacity(take)
                    .map_err(h2_error)?;
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(this.body.poll_data(cx)) {
                Some(Ok(next)) => {
                    this.current = next;
                    this.offset = 0;
                }
                Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP/3
// ---------------------------------------------------------------------------

type H3Sender = h3::client::SendRequest<OpenStreams, Bytes>;

async fn h3_stream_one<S>(
    mut sender: H3Sender,
    options: &ClientOptions,
    shared: Arc<Shared>,
    lifetime: Lifetime,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<S>> {
    let request = h3_request(Method::POST, options, None, None)?;
    let stream = bounded(async { sender.send_request(request).await.map_err(h3_error) }).await?;
    let (send, mut recv) = stream.split();
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (out, out_rx) = mpsc::channel(READ_QUEUE);
    spawn_io(tracker, &shared, h3_upload_pump(send, rx, None, None));
    spawn_io(tracker, &shared, async move {
        let response = bounded(async { recv.recv_response().await.map_err(h3_error) }).await?;
        ensure_ok("XHTTP/3", response.status())?;
        h3_download(recv, out).await
    });
    Ok(XhttpStream::new(
        out_rx,
        tx,
        KeepAlive::H3(sender),
        shared,
        lifetime,
        options.max_post_bytes,
    ))
}

async fn h3_stream_up<S>(
    mut sender: H3Sender,
    options: &ClientOptions,
    shared: Arc<Shared>,
    lifetime: Lifetime,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<S>> {
    let session = unique_session_id()?;
    let ready = CancellationToken::new();
    let upload = h3_start_upload(&mut sender, options, &session, tracker, &shared, &ready).await?;
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (out, out_rx) = mpsc::channel(READ_QUEUE);
    spawn_io(
        tracker,
        &shared,
        h3_stream_up_manager(upload, rx, ready.clone()),
    );
    let get_options = options.clone();
    let get_sender = sender.clone();
    spawn_io(tracker, &shared, async move {
        ready.cancelled().await;
        h3_downlink_get(get_sender, &get_options, &session, out, true).await
    });
    Ok(XhttpStream::new(
        out_rx,
        tx,
        KeepAlive::H3(sender),
        shared,
        lifetime,
        options.max_post_bytes,
    ))
}

type H3Upload = (
    RequestStream<H3SendStream<Bytes>, Bytes>,
    tokio::task::JoinHandle<io::Result<()>>,
    CancellationToken,
);

async fn h3_start_upload(
    sender: &mut H3Sender,
    options: &ClientOptions,
    session: &str,
    tracker: &TaskTracker,
    shared: &Arc<Shared>,
    ready: &CancellationToken,
) -> io::Result<H3Upload> {
    let request = h3_request(Method::POST, options, Some(session), None)?;
    let stream = bounded(async { sender.send_request(request).await.map_err(h3_error) }).await?;
    let (send, mut recv) = stream.split();
    let finished = CancellationToken::new();
    let response_finished = finished.clone();
    let ready = ready.clone();
    let task = spawn_response(tracker, shared, async move {
        let response = {
            let response = recv.recv_response();
            tokio::pin!(response);
            tokio::select! {
                result = &mut response => result.map_err(h3_error)?,
                _ = response_finished.cancelled() => bounded(async { response.await.map_err(h3_error) }).await?,
            }
        };
        ensure_ok("XHTTP/3上行", response.status())?;
        ready.cancel();
        let drain = h3_drain_post(&mut recv);
        tokio::pin!(drain);
        tokio::select! {
            result = &mut drain => result,
            _ = response_finished.cancelled() => bounded(drain).await,
        }
    });
    Ok((send, task, finished))
}

async fn h3_finish_upload(
    send: &mut RequestStream<H3SendStream<Bytes>, Bytes>,
    finished: &CancellationToken,
) -> io::Result<()> {
    bounded(async { send.finish().await.map_err(h3_error) }).await?;
    finished.cancel();
    Ok(())
}

async fn h3_stream_up_manager(
    upload: H3Upload,
    mut rx: mpsc::Receiver<Upload>,
    ready: CancellationToken,
) -> io::Result<()> {
    let (mut send, response, finished) = upload;
    while let Some(command) = rx.recv().await {
        match command {
            Upload::Data(chunk) => {
                bounded(async { send.send_data(Bytes::from(chunk)).await.map_err(h3_error) })
                    .await?;
                ready.cancel();
            }
            Upload::Flush(ack) => {
                let _ = ack.send(());
            }
            Upload::Shutdown(ack) => {
                h3_finish_upload(&mut send, &finished).await?;
                join_response(response).await?;
                let _ = ack.send(());
                return Ok(());
            }
        }
    }
    Ok(())
}

fn h3_packet_up<S>(
    sender: H3Sender,
    options: &ClientOptions,
    shared: Arc<Shared>,
    lifetime: Lifetime,
    tracker: &TaskTracker,
) -> io::Result<XhttpStream<S>> {
    let session = unique_session_id()?;
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (out, out_rx) = mpsc::channel(READ_QUEUE);
    let (started, wait_started) = oneshot::channel();
    let get_sender = sender.clone();
    let get_options = options.clone();
    let get_session = session.clone();
    spawn_io(tracker, &shared, async move {
        wait_started.await.map_err(|_| closed())?;
        h3_downlink_get(get_sender, &get_options, &get_session, out, false).await
    });
    spawn_io(
        tracker,
        &shared,
        h3_packet_up_manager(sender.clone(), options.clone(), session, rx, started),
    );
    Ok(XhttpStream::new(
        out_rx,
        tx,
        KeepAlive::H3(sender),
        shared,
        lifetime,
        options.max_post_bytes,
    ))
}

async fn h3_packet_up_manager(
    mut sender: H3Sender,
    options: ClientOptions,
    session: String,
    mut rx: mpsc::Receiver<Upload>,
    started: oneshot::Sender<()>,
) -> io::Result<()> {
    let mut seq = 0u64;
    let mut started = Some(started);
    while let Some(command) = rx.recv().await {
        match command {
            Upload::Data(payload) => {
                bounded(h3_post_block(&mut sender, &options, &session, seq, payload)).await?;
                seq = seq.checked_add(1).ok_or_else(|| invalid("XHTTP序号溢出"))?;
                if let Some(started) = started.take() {
                    let _ = started.send(());
                }
            }
            Upload::Flush(ack) => {
                let _ = ack.send(());
            }
            Upload::Shutdown(ack) => {
                let _ = ack.send(());
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn h3_post_block(
    sender: &mut H3Sender,
    options: &ClientOptions,
    session: &str,
    seq: u64,
    payload: Vec<u8>,
) -> io::Result<()> {
    let request = h3_request(Method::POST, options, Some(session), Some(seq))?;
    let mut stream = sender.send_request(request).await.map_err(h3_error)?;
    stream
        .send_data(Bytes::from(payload))
        .await
        .map_err(h3_error)?;
    stream.finish().await.map_err(h3_error)?;
    let response = stream.recv_response().await.map_err(h3_error)?;
    ensure_ok("XHTTP/3上行", response.status())?;
    h3_drain_post(&mut stream).await
}

async fn h3_drain_post<S: h3::quic::RecvStream>(
    stream: &mut RequestStream<S, Bytes>,
) -> io::Result<()> {
    let mut total = 0usize;
    while let Some(chunk) = stream.recv_data().await.map_err(h3_error)? {
        total += chunk.remaining();
        if total > MAX_POST_RESPONSE {
            return Err(invalid("XHTTP上行响应体过大"));
        }
    }
    stream.recv_trailers().await.map_err(h3_error)?;
    Ok(())
}

async fn h3_downlink_get(
    mut sender: H3Sender,
    options: &ClientOptions,
    session: &str,
    out: mpsc::Sender<Vec<u8>>,
    retry: bool,
) -> io::Result<()> {
    for attempt in 0..8 {
        let request = h3_request(Method::GET, options, Some(session), None)?;
        let mut stream =
            bounded(async { sender.send_request(request).await.map_err(h3_error) }).await?;
        bounded(async { stream.finish().await.map_err(h3_error) }).await?;
        let response = bounded(async { stream.recv_response().await.map_err(h3_error) }).await?;
        if retry && response.status() == StatusCode::NOT_FOUND && attempt < 7 {
            bounded(h3_drain_post(&mut stream)).await?;
            tokio::time::sleep(Duration::from_millis(5 << attempt.min(5))).await;
            continue;
        }
        ensure_ok("XHTTP/3下行", response.status())?;
        let (_send, recv) = stream.split();
        return h3_download(recv, out).await;
    }
    Err(invalid("XHTTP下行重试耗尽"))
}

async fn h3_download(
    recv: RequestStream<H3RecvStream, Bytes>,
    out: mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let mut body = H3BodyReader::new(recv);
    let mut bytes = vec![0u8; MAX_BLOCK];
    loop {
        let n = body.read(&mut bytes).await?;
        if n == 0 {
            return Ok(());
        }
        out.send(bytes[..n].to_vec()).await.map_err(|_| closed())?;
    }
}

async fn h3_upload_pump(
    mut send: RequestStream<H3SendStream<Bytes>, Bytes>,
    mut rx: mpsc::Receiver<Upload>,
    ready: Option<CancellationToken>,
    finished: Option<CancellationToken>,
) -> io::Result<()> {
    while let Some(command) = rx.recv().await {
        match command {
            Upload::Data(chunk) => {
                // vendor的send_data会poll_ready到整个帧已写入Quinn，非仅本地排队。
                bounded(async { send.send_data(Bytes::from(chunk)).await.map_err(h3_error) })
                    .await?;
                if let Some(ready) = &ready {
                    ready.cancel();
                }
            }
            Upload::Flush(ack) => {
                let _ = ack.send(());
            }
            Upload::Shutdown(ack) => {
                bounded(async { send.finish().await.map_err(h3_error) }).await?;
                if let Some(finished) = &finished {
                    finished.cancel();
                }
                let _ = ack.send(());
                return Ok(());
            }
        }
    }
    Ok(())
}

struct H3BodyReader {
    recv: RequestStream<H3RecvStream, Bytes>,
    current: Bytes,
    offset: usize,
}

impl H3BodyReader {
    fn new(recv: RequestStream<H3RecvStream, Bytes>) -> Self {
        Self {
            recv,
            current: Bytes::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for H3BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.offset < this.current.len() {
                let take = buf.remaining().min(this.current.len() - this.offset);
                buf.put_slice(&this.current[this.offset..this.offset + take]);
                this.offset += take;
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(this.recv.poll_recv_data(cx)) {
                Ok(Some(mut next)) => {
                    let size = next.remaining();
                    if size > MAX_BLOCK {
                        return Poll::Ready(Err(invalid("XHTTP/3下行块超过64KiB")));
                    }
                    this.current = next.copy_to_bytes(size);
                    this.offset = 0;
                }
                Ok(None) => return Poll::Ready(Ok(())),
                Err(error) => return Poll::Ready(Err(h3_error(error))),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 公共字节流适配
// ---------------------------------------------------------------------------

/// 只有业务下行任务拥有sender；上传响应完成不能关闭业务下行。
struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            current: Vec::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.offset < self.current.len() {
                let take = buf.remaining().min(self.current.len() - self.offset);
                buf.put_slice(&self.current[self.offset..self.offset + take]);
                self.offset += take;
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.rx.poll_recv(cx)) {
                Some(next) => {
                    self.current = next;
                    self.offset = 0;
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

enum Upload {
    Data(Vec<u8>),
    Flush(oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

struct ChannelWriter {
    tx: Option<PollSender<Upload>>,
    shared: Arc<Shared>,
    max_block: usize,
    pending: Option<oneshot::Receiver<()>>,
    closing: bool,
    shutdown_done: bool,
}

impl ChannelWriter {
    fn new(tx: mpsc::Sender<Upload>, shared: Arc<Shared>, max_block: usize) -> Self {
        Self {
            tx: Some(PollSender::new(tx)),
            shared,
            max_block,
            pending: None,
            closing: false,
            shutdown_done: false,
        }
    }

    fn check(&self, cx: &mut TaskContext<'_>) -> io::Result<()> {
        self.shared.write_waker.register(cx.waker());
        if let Some(error) = self.shared.error() {
            return Err(error);
        }
        Ok(())
    }

    fn poll_ack(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        if let Some(pending) = &mut self.pending {
            let result = std::task::ready!(Pin::new(pending).poll(cx));
            self.pending = None;
            result.map_err(|_| self.shared.error().unwrap_or_else(closed))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_barrier(&mut self, cx: &mut TaskContext<'_>, shutdown: bool) -> Poll<io::Result<()>> {
        self.check(cx)?;
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_some() {
            std::task::ready!(self.poll_ack(cx))?;
            if self.closing {
                self.shutdown_done = true;
                self.tx = None;
                return Poll::Ready(Ok(()));
            }
            if !shutdown {
                return Poll::Ready(Ok(()));
            }
        }
        let tx = self.tx.as_mut().ok_or_else(closed)?;
        std::task::ready!(tx.poll_reserve(cx))
            .map_err(|_| self.shared.error().unwrap_or_else(closed))?;
        let (ack, pending) = oneshot::channel();
        let command = if shutdown {
            Upload::Shutdown(ack)
        } else {
            Upload::Flush(ack)
        };
        tx.send_item(command)
            .map_err(|_| self.shared.error().unwrap_or_else(closed))?;
        self.pending = Some(pending);
        self.closing = shutdown;
        std::task::ready!(self.poll_ack(cx))?;
        if shutdown {
            self.shutdown_done = true;
            self.tx = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check(cx)?;
        if self.closing || self.shutdown_done {
            return Poll::Ready(Err(closed()));
        }
        std::task::ready!(self.poll_ack(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(self.max_block);
        let this = &mut *self;
        let tx = this.tx.as_mut().ok_or_else(closed)?;
        std::task::ready!(tx.poll_reserve(cx))
            .map_err(|_| this.shared.error().unwrap_or_else(closed))?;
        tx.send_item(Upload::Data(buf[..take].to_vec()))
            .map_err(|_| this.shared.error().unwrap_or_else(closed))?;
        Poll::Ready(Ok(take))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.poll_barrier(cx, false)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.poll_barrier(cx, true)
    }
}

impl<S: Unpin> AsyncRead for XhttpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.shared.read_waker.register(cx.waker());
        if let Some(error) = self.shared.error() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<S: Unpin> AsyncWrite for XhttpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// 保持协议连接存活；HTTP/3 的最后一个 `SendRequest` 被丢弃会关闭连接。
/// 变体字段只持有连接，不读取；删除字段会让 sender 提前 drop。
#[allow(dead_code)]
enum KeepAlive {
    None,
    H2(H2Sender),
    H3(h3::client::SendRequest<OpenStreams, Bytes>),
}

// ---------------------------------------------------------------------------
// 请求构造与错误
// ---------------------------------------------------------------------------

fn effective_mode(mode: Mode) -> Mode {
    match mode {
        Mode::Auto => Mode::StreamOne,
        other => other,
    }
}

/// 在基础路径后追加会话与序号，并保留基础路径中的查询串。
fn target_path(
    options: &ClientOptions,
    session: Option<&str>,
    seq: Option<u64>,
) -> io::Result<String> {
    let (path, query) = match options.path.split_once('?') {
        Some((path, query)) => (path, query),
        None => (options.path.as_str(), ""),
    };
    let base = path.trim_end_matches('/');
    let mut out = String::with_capacity(base.len() + 96);
    out.push_str(base);
    if let Some(session) = session {
        out.push('/');
        out.push_str(session);
    } else if seq.is_none() {
        // Xray 的 XHTTP 服务端按 `path/` 规范化；stream-one 也使用尾斜杠。
        out.push('/');
    }
    if let Some(seq) = seq {
        out.push('/');
        out.push_str(&seq.to_string());
    }
    if out.is_empty() {
        out.push('/');
    }
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    if let Some(padding) = options.x_padding {
        let mut selector = [0u8; 4];
        aws_lc_rs::rand::fill(&mut selector).map_err(|_| io::Error::other("随机数生成失败"))?;
        let length =
            padding.from + u32::from_be_bytes(selector) as usize % (padding.to - padding.from + 1);
        // Xray 以原文长度校验 x_padding，不发 base64；使用固定可见字符。
        out.push(if query.is_empty() { '?' } else { '&' });
        out.push_str("x_padding=");
        out.push_str(&"X".repeat(length));
    }
    Ok(out)
}

fn h1_request(
    method: Method,
    options: &ClientOptions,
    session: Option<&str>,
    seq: Option<u64>,
    length: Option<usize>,
) -> io::Result<String> {
    let target = target_path(options, session, seq)?;
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\n",
        options.host.as_deref().unwrap_or("localhost")
    );
    if method == Method::POST {
        if let Some(length) = length {
            head.push_str(&format!("Content-Length: {length}\r\n"));
        } else {
            head.push_str("Transfer-Encoding: chunked\r\n");
        }
    }
    for (name, value) in &options.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    if head.len() > MAX_REQUEST_HEAD {
        return Err(invalid("XHTTP请求头超限"));
    }
    Ok(head)
}

fn h2_request(
    method: Method,
    options: &ClientOptions,
    session: Option<&str>,
    seq: Option<u64>,
) -> io::Result<Request<()>> {
    let path = target_path(options, session, seq)?;
    let host = options.host.as_deref().unwrap_or("localhost");
    let uri = format!(
        "{}://{host}{path}",
        if options.h3 { "https" } else { "http" }
    );
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in &options.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(()).map_err(|_| invalid("XHTTP请求头非法"))
}

fn h3_request(
    method: Method,
    options: &ClientOptions,
    session: Option<&str>,
    seq: Option<u64>,
) -> io::Result<Request<()>> {
    let mut request = h2_request(method, options, session, seq)?;
    let host = options.host.as_deref().unwrap_or("localhost");
    let path = request
        .uri()
        .path_and_query()
        .ok_or_else(|| invalid("XHTTP路径非法"))?
        .as_str()
        .to_owned();
    *request.uri_mut() = format!("https://{host}{path}")
        .parse()
        .map_err(|_| invalid("XHTTP/3 URI非法"))?;
    Ok(request)
}

fn validate_options(options: &ClientOptions) -> io::Result<()> {
    let path = options.path.split('?').next().unwrap_or("");
    if path.is_empty()
        || path.len() > 1024
        || !path.starts_with('/')
        || options.path.len() > 2048
        || !options
            .path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
    {
        return Err(invalid("XHTTP路径必须是有界ASCII绝对路径"));
    }
    if !(64..=MAX_BLOCK).contains(&options.max_post_bytes) {
        return Err(invalid("XHTTP max_post_bytes必须为64..=65536"));
    }
    if let Some(host) = &options.host
        && (host.is_empty()
            || host.len() > 255
            || host.parse::<http::uri::Authority>().is_err()
            || host.contains('@'))
    {
        return Err(invalid("XHTTP host不是合法authority"));
    }
    let mut budget = 256 + options.path.len() + options.host.as_ref().map_or(9, String::len);
    if options.headers.len() > 16 {
        return Err(invalid("XHTTP自定义头超过16项"));
    }
    for (name, value) in &options.headers {
        let parsed = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("XHTTP头名称非法"))?;
        let protected = [
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "proxy-connection",
            "upgrade",
            "te",
            "trailer",
        ];
        if name.len() > 64
            || protected.contains(&parsed.as_str())
            || value.len() > 1024
            || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(invalid("XHTTP自定义头非法或受保护"));
        }
        http::header::HeaderValue::from_str(value).map_err(|_| invalid("XHTTP头值非法"))?;
        budget += name.len() + value.len() + 4 + 32;
    }
    if let Some(padding) = options.x_padding {
        if padding.from > padding.to || padding.to > 16_384 {
            return Err(invalid("XHTTP padding范围非法"));
        }
        if options.path.split('?').nth(1).is_some_and(|query| {
            query
                .split('&')
                .any(|item| item.split('=').next() == Some("x_padding"))
        }) {
            return Err(invalid("XHTTP padding不能重复配置"));
        }
        budget += 12 + padding.to.div_ceil(3) * 4;
    }
    if budget > MAX_REQUEST_HEAD {
        return Err(invalid("XHTTP请求头最坏预算超过8192字节"));
    }
    Ok(())
}

fn ensure_ok(protocol: &str, status: StatusCode) -> io::Result<()> {
    if status == StatusCode::OK {
        Ok(())
    } else {
        Err(status_error(protocol, status))
    }
}

fn status_error(protocol: &str, status: StatusCode) -> io::Error {
    io::Error::other(format!("{protocol} 上游返回状态 {status}"))
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP 会话已关闭")
}

fn h2_error(error: h2::Error) -> io::Error {
    io::Error::other(format!("XHTTP/2 传输失败: {error}"))
}

fn h3_error(error: impl fmt::Display) -> io::Error {
    io::Error::other(format!("XHTTP/3 传输失败: {error}"))
}

/// 服务端会校验会话标识为 1..=64 字节的 `[A-Za-z0-9_-]`。
fn unique_session_id() -> io::Result<String> {
    let mut random = [0u8; 24];
    aws_lc_rs::rand::fill(&mut random).map_err(|_| io::Error::other("XHTTP会话随机数生成失败"))?;
    Ok(URL_SAFE_NO_PAD.encode(random))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
