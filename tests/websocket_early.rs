//! 三协议真实 early-data 回环业务；HTTP/WS 与协议 wire 均使用独立测试端。
//! 不依赖目标等待 EOF 后才回包；Close 只结束已经完成业务交换的会话。
#[path = "common/vmess.rs"]
mod client;
mod common;
#[path = "common/websocket.rs"]
mod ws;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use client::{Client, Request};
use common::{Certificate, Echo, PASSWORD, Running, read_exact, socks_config};
use serde_json::{Value, json};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, ready},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(3);
const EARLY_LIMIT: usize = 8192;
const FIRST: &[u8] = b"early-first\x00\xff\x80";
const SECOND: &[u8] = b"after-upgrade\x00\xfe";
const VLESS_UUID: &str = "11111111-1111-1111-1111-111111111111";

trait Wire: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Wire for T {}
type RawIo = Box<dyn Wire>;
type Peer = ws::Peer<RawIo>;
type Opening = Pin<Box<dyn Future<Output = Peer> + Send>>;

#[derive(Clone, Copy)]
enum Protocol {
    Vless,
    Vmess,
    Trojan,
}
impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Vless => "vless-ws",
            Self::Vmess => "vmess-ws",
            Self::Trojan => "trojan-ws",
        }
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Header,
    Custom,
    Path,
}
const MODES: [Mode; 3] = [Mode::Header, Mode::Custom, Mode::Path];

#[derive(Clone, Copy)]
enum Layout {
    // 整个认证头与首载荷都仅从 early-data 交付。
    Full,
    // early 前缀之后，7 字节放进 HTTP 同写的原始帧，其余跨多个消息。
    Boundary(usize),
}

fn config(protocol: Protocol, mode: Mode, cert: Option<&Certificate>) -> Value {
    let mut value = socks_config();
    let mut inbound = json!({
        "type":protocol.name(), "tag":"early", "listen":"127.0.0.1:0",
        "websocket":{"path":"/proxy"}
    });
    inbound["users"] = match protocol {
        Protocol::Vless => json!([{"name":"test", "uuid":VLESS_UUID}]),
        Protocol::Vmess => json!([{"name":"test", "uuid":client::UUID}]),
        Protocol::Trojan => json!([{"name":"test", "password":PASSWORD}]),
    };
    let mut early = match mode {
        Mode::Header | Mode::Custom => json!({"mode":"header", "max_bytes":EARLY_LIMIT}),
        Mode::Path => json!({"mode":"path", "max_bytes":EARLY_LIMIT}),
    };
    if matches!(mode, Mode::Custom) {
        early["header_name"] = json!("X-Proxy-Early");
    }
    inbound["websocket"]["early_data"] = early;
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    } else if !matches!(protocol, Protocol::Vmess) {
        inbound["allow_insecure_transport"] = json!(true);
    }
    value["inbounds"] = json!([inbound]);
    value["limits"]["handshake_timeout_ms"] = json!(3000);
    value
}

async fn raw_connect(address: SocketAddr, cert: Option<&Certificate>) -> RawIo {
    if let Some(cert) = cert {
        let io = cert.connect(address).await;
        io.get_ref().0.set_nodelay(true).unwrap();
        Box::new(io)
    } else {
        let io = timeout(WAIT, TcpStream::connect(address))
            .await
            .unwrap()
            .unwrap();
        io.set_nodelay(true).unwrap();
        Box::new(io)
    }
}

async fn messages(peer: &mut Peer, bytes: &[u8]) {
    let mut offset = 0;
    for length in [1, 7, 17].into_iter().cycle() {
        if offset == bytes.len() {
            break;
        }
        let end = (offset + length).min(bytes.len());
        peer.send_message(2, &bytes[offset..end]).await;
        offset = end;
    }
}

async fn handshake(raw: RawIo, mode: Mode, early: &[u8], raw_prefix: &[u8]) -> Peer {
    assert!((1..=EARLY_LIMIT).contains(&early.len()));
    let encoded = URL_SAFE_NO_PAD.encode(early);
    let (path, headers) = match mode {
        Mode::Header => (
            "/proxy".to_owned(),
            format!("Sec-WebSocket-Protocol: {encoded}\r\n"),
        ),
        Mode::Custom => ("/proxy".to_owned(), format!("X-Proxy-Early: {encoded}\r\n")),
        Mode::Path => (format!("/proxy{encoded}"), String::new()),
    };
    ws::upgrade(raw, &path, &headers, raw_prefix).await
}

async fn upgrade(raw: RawIo, mode: Mode, layout: Layout, bytes: Vec<u8>) -> Peer {
    let prefix = match layout {
        Layout::Full => bytes.len(),
        Layout::Boundary(prefix) => prefix,
    };
    assert!(prefix <= bytes.len());
    let end = (prefix + 7).min(bytes.len());
    // 原始 WS 帧与 HTTP 请求同一次写入；不能把 framing 或控制载荷当业务明文。
    let mut raw_prefix = ws::masked(true, 2, &[]);
    raw_prefix.extend(ws::masked(true, 9, b"early-control"));
    if end != prefix {
        raw_prefix.extend(ws::masked(true, 2, &bytes[prefix..end]));
    }
    let mut peer = handshake(raw, mode, &bytes[..prefix], &raw_prefix).await;
    messages(&mut peer, &bytes[end..]).await;
    peer
}

async fn settled(server: &Running, payload: usize) {
    timeout(WAIT, async {
        loop {
            let stats = server.stats.snapshot();
            if stats.connections == 0 && stats.tcp_flows == 0 && stats.udp_associations == 0 {
                assert_eq!(stats.uplink, payload as u64);
                assert_eq!(stats.downlink, payload as u64);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("early-data 业务计量或子任务未归还");
}

async fn finish(peer: &mut Peer) {
    peer.close().await;
    ws::closed(peer).await;
}

fn vless_header(address: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend([0x11; 16]);
    bytes.extend([0, 1]);
    // 测试端独立 VLESS 地址：端口在前，IPv6 类型为 3。
    bytes.extend(client::target(address));
    bytes
}

fn plain_header(protocol: Protocol, address: SocketAddr) -> Vec<u8> {
    match protocol {
        Protocol::Vless => vless_header(address),
        Protocol::Trojan => common::trojan_header(1, common::address(address), PASSWORD),
        Protocol::Vmess => panic!("VMess 应使用独立 AEAD 测试端"),
    }
}

async fn plain_response(protocol: Protocol, peer: &mut Peer, expected: &[u8]) {
    if matches!(protocol, Protocol::Vless) {
        let mut response = [0xff; 2];
        read_exact(peer, &mut response).await;
        assert_eq!(response, [0, 0], "仅出现一次 VLESS 响应");
    }
    let mut bytes = vec![0; expected.len()];
    read_exact(peer, &mut bytes).await;
    // Trojan 没有成功头；第一字节就必须来自目标，不能误接受其他协议回复。
    assert_eq!(bytes, expected);
}

// 首次 flush 之前只暂存 Client::start 的有限首写，里面的 AEAD 头和首块
// 仍全部由独立客户端编码。第一次 flush 将该首写恰一次放入真实 HTTP
// early-data / 原始 WS 帧 / 后续 Binary；之后完全委托 Peer。
// 因而无需再次发送 request.wire，也无需暴露或复制私有 Body 编码器。
struct EarlyIo {
    raw: Option<RawIo>,
    mode: Mode,
    layout: Layout,
    initial: Vec<u8>,
    opening: Option<Opening>,
    peer: Option<Peer>,
}
impl EarlyIo {
    fn new(raw: RawIo, mode: Mode, layout: Layout) -> Self {
        Self {
            raw: Some(raw),
            mode,
            layout,
            initial: vec![],
            opening: None,
            peer: None,
        }
    }
    fn poll_open(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.peer.is_some() {
            return Poll::Ready(Ok(()));
        }
        if self.opening.is_none() {
            let raw = self.raw.take().expect("Upgrade 仅初始化一次");
            let bytes = std::mem::take(&mut self.initial);
            self.opening = Some(Box::pin(upgrade(raw, self.mode, self.layout, bytes)));
        }
        let peer = ready!(self.opening.as_mut().unwrap().as_mut().poll(cx));
        self.opening = None;
        self.peer = Some(peer);
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for EarlyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_open(cx))?;
        Pin::new(this.peer.as_mut().unwrap()).poll_read(cx, output)
    }
}
// 边界用例的认证头已经按 early/raw WS 完整发出时，无需延迟首写。
// 此窄包装只向 Client::start 报告已发前缀的长度，其他字节仍原样委托 Peer。
struct SkipHeader {
    peer: Peer,
    skip: usize,
}
impl AsyncRead for SkipHeader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().peer).poll_read(cx, output)
    }
}
impl AsyncWrite for SkipHeader {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.skip != 0 {
            let n = this.skip.min(bytes.len());
            this.skip -= n;
            return Poll::Ready(Ok(n));
        }
        Pin::new(&mut this.peer).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().peer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().peer).poll_shutdown(cx)
    }
}

impl AsyncWrite for EarlyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(peer) = this.peer.as_mut() {
            return Pin::new(peer).poll_write(cx, bytes);
        }
        if this.opening.is_some() {
            ready!(this.poll_open(cx))?;
            return Pin::new(this.peer.as_mut().unwrap()).poll_write(cx, bytes);
        }
        if bytes.len() > 16384 - this.initial.len() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        this.initial.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_open(cx))?;
        Pin::new(this.peer.as_mut().unwrap()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_open(cx))?;
        Pin::new(this.peer.as_mut().unwrap()).poll_shutdown(cx)
    }
}

fn layouts(protocol: Protocol, header_len: usize) -> Vec<Layout> {
    let mut layouts = vec![Layout::Full];
    let boundaries: &[usize] = match protocol {
        Protocol::Vless => &[1, 16, 17, 18, 19, 20, 21],
        Protocol::Vmess => &[1, 15, 16, 17, 33, 34, 41, 42],
        Protocol::Trojan => &[1, 55, 56, 57, 58, 59, 60],
    };
    for &boundary in boundaries {
        assert!(boundary < header_len);
        layouts.push(Layout::Boundary(boundary));
    }
    layouts.push(Layout::Boundary(header_len - 1));
    layouts.push(Layout::Boundary(header_len));
    layouts.push(Layout::Boundary(header_len + 1));
    if matches!(protocol, Protocol::Vmess) {
        // 首个 chunk 的长度、密文及认证 tag 均跨 early-data 尾部。
        layouts.push(Layout::Boundary(header_len + 2));
        layouts.push(Layout::Boundary(header_len + 3));
        layouts.push(Layout::Boundary(header_len + 18));
        layouts.push(Layout::Boundary(header_len + 31));
    }
    layouts
}

struct ServerFirst {
    address: SocketAddr,
    tasks: JoinSet<()>,
}
impl ServerFirst {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut flows = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut io, _) = accepted.unwrap();
                        flows.spawn(async move {
                            io.write_all(b"server-before-client-body").await.unwrap();
                            let mut bytes = vec![0; SECOND.len()];
                            io.read_exact(&mut bytes).await.unwrap();
                            assert_eq!(bytes, SECOND);
                            io.write_all(&bytes).await.unwrap();
                            // 已回包才等待会话结束，绝不 after_eof。
                            let mut end = [0];
                            let _ = io.read(&mut end).await;
                        });
                    }
                    result = flows.join_next(), if !flows.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        });
        Self { address, tasks }
    }
    async fn stop(mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

#[tokio::test]
async fn all_protocols_ws_wss_all_early_carriers_auth_only_server_first() {
    let cert = Certificate::new();
    let target = ServerFirst::start().await;
    const GREETING: &[u8] = b"server-before-client-body";
    for protocol in [Protocol::Vless, Protocol::Vmess, Protocol::Trojan] {
        for tls in [false, true] {
            let certificate = tls.then_some(&cert);
            for mode in MODES {
                let server = Running::start(config(protocol, mode, certificate)).await;
                let raw = raw_connect(server.address, certificate).await;
                let peer = if matches!(protocol, Protocol::Vmess) {
                    let request = Request::new(1, client::target(target.address), 3, 13);
                    let skip = request.wire.len();
                    let peer = upgrade(raw, mode, Layout::Full, request.wire.clone()).await;
                    let mut client = Client::start(SkipHeader { peer, skip }, request, None).await;
                    assert_eq!(client.read(GREETING.len()).await, GREETING);
                    client.send(SECOND).await;
                    assert_eq!(client.read(SECOND.len()).await, SECOND);
                    finish(&mut client.io.peer).await;
                    client.io.peer
                } else {
                    let header = plain_header(protocol, target.address);
                    let mut peer = upgrade(raw, mode, Layout::Full, header).await;
                    plain_response(protocol, &mut peer, GREETING).await;
                    messages(&mut peer, SECOND).await;
                    let mut bytes = vec![0; SECOND.len()];
                    read_exact(&mut peer, &mut bytes).await;
                    assert_eq!(bytes, SECOND);
                    finish(&mut peer).await;
                    peer
                };
                drop(peer);
                timeout(WAIT, async {
                    loop {
                        let stats = server.stats.snapshot();
                        if stats.connections == 0 && stats.tcp_flows == 0 {
                            assert_eq!(stats.uplink, SECOND.len() as u64);
                            assert_eq!(stats.downlink, (GREETING.len() + SECOND.len()) as u64);
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                server.shutdown().await;
            }
        }
    }
    target.stop().await;
}

async fn assert_no_target(listener: &TcpListener) {
    assert!(
        timeout(Duration::from_millis(40), listener.accept())
            .await
            .is_err(),
        "坏认证不得拨号目标"
    );
}

async fn invalid_plain_matrix(protocol: Protocol) {
    let cert = Certificate::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        for mode in MODES {
            let server = Running::start(config(protocol, mode, certificate)).await;
            let mut header = plain_header(protocol, address);
            match protocol {
                Protocol::Vless => header[1] ^= 0xff,
                // 保持 56 位 hex 长度合法，仅改变真实摘要，不是测 HTTP/early 语法。
                Protocol::Trojan => header[0] = if header[0] == b'0' { b'1' } else { b'0' },
                Protocol::Vmess => unreachable!(),
            }
            let mut bytes = header.clone();
            bytes.extend(b"must-not-reach-target\x00\xff");
            for layout in [Layout::Full, Layout::Boundary(header.len() - 1)] {
                let prefix = match layout {
                    Layout::Full => bytes.len(),
                    Layout::Boundary(prefix) => prefix,
                };
                // 认证失败后服务端可能立刻关闭；后缀随 HTTP 同写，避免测试端
                // 因继续发送到已关闭连接而先失败，掩盖零业务数据的核心断言。
                let raw_prefix = ws::masked(true, 2, &bytes[prefix..]);
                let raw = raw_connect(server.address, certificate).await;
                let mut peer = timeout(WAIT, handshake(raw, mode, &bytes[..prefix], &raw_prefix))
                    .await
                    .unwrap();
                ws::closed(&mut peer).await;
            }
            assert_no_target(&target).await;
            settled(&server, 0).await;
            server.shutdown().await;
        }
    }
}

#[tokio::test]
async fn vless_ws_wss_all_early_carriers_bad_uuid_never_dial_or_deliver_payload() {
    invalid_plain_matrix(Protocol::Vless).await;
}

#[tokio::test]
async fn trojan_ws_wss_all_early_carriers_bad_digest_never_dial_or_deliver_payload() {
    invalid_plain_matrix(Protocol::Trojan).await;
}

#[tokio::test]
async fn vmess_ws_wss_all_early_carriers_bad_identity_or_aead_never_dial_or_reply() {
    let cert = Certificate::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        for mode in MODES {
            let server = Running::start(config(Protocol::Vmess, mode, certificate)).await;
            for security in [3, 4] {
                for bad_identity in [false, true] {
                    for full in [false, true] {
                        let timestamp = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let mut request = Request::at(
                            1,
                            client::target(address),
                            security,
                            1,
                            if bad_identity { [0x33; 16] } else { client::ID },
                            timestamp,
                            None,
                        );
                        if !bad_identity {
                            *request.wire.last_mut().unwrap() ^= 1;
                        }
                        let prefix = if full { request.wire.len() } else { 16 };
                        // 不要求坏认证去解正文；有目标首载荷也不得触发业务拨号。
                        let mut complete = request.wire;
                        complete.extend(b"must-not-reach-target");
                        let prefix = if full { complete.len() } else { prefix };
                        let raw_prefix = ws::masked(true, 2, &complete[prefix..]);
                        let raw = raw_connect(server.address, certificate).await;
                        let mut peer =
                            timeout(WAIT, handshake(raw, mode, &complete[..prefix], &raw_prefix))
                                .await
                                .unwrap();
                        ws::closed(&mut peer).await;
                    }
                }
            }
            assert_no_target(&target).await;
            settled(&server, 0).await;
            server.shutdown().await;
        }
    }
}

async fn plain_matrix(protocol: Protocol) {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        for mode in MODES {
            let server = Running::start(config(protocol, mode, certificate)).await;
            let header = plain_header(protocol, echo.address);
            let mut wire = header.clone();
            wire.extend(FIRST);
            let layouts = layouts(protocol, header.len());
            let total = layouts.len() * (FIRST.len() + SECOND.len());
            for layout in layouts {
                let raw = raw_connect(server.address, certificate).await;
                let mut peer = timeout(WAIT, upgrade(raw, mode, layout, wire.clone()))
                    .await
                    .unwrap();
                plain_response(protocol, &mut peer, FIRST).await;
                messages(&mut peer, SECOND).await;
                let mut bytes = vec![0; SECOND.len()];
                read_exact(&mut peer, &mut bytes).await;
                assert_eq!(bytes, SECOND);
                finish(&mut peer).await;
                drop(peer);
            }
            settled(&server, total).await;
            server.shutdown().await;
        }
    }
}

#[tokio::test]
async fn vless_ws_wss_header_custom_path_complete_and_boundary_early_data() {
    plain_matrix(Protocol::Vless).await;
}

#[tokio::test]
async fn trojan_ws_wss_header_custom_path_complete_and_boundary_early_data() {
    plain_matrix(Protocol::Trojan).await;
}

#[tokio::test]
async fn vmess_ws_wss_header_custom_path_complete_first_body_and_aead_boundaries() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        for mode in MODES {
            let server = Running::start(config(Protocol::Vmess, mode, certificate)).await;
            let mut total = 0;
            for security in [3, 4] {
                let header_len = Request::new(1, client::target(echo.address), security, 13)
                    .wire
                    .len();
                for layout in layouts(Protocol::Vmess, header_len) {
                    let request = Request::new(1, client::target(echo.address), security, 13);
                    let raw = raw_connect(server.address, certificate).await;
                    match layout {
                        Layout::Full => {
                            let io = EarlyIo::new(raw, mode, layout);
                            let mut client = timeout(WAIT, Client::start(io, request, Some(FIRST)))
                                .await
                                .unwrap();
                            assert_eq!(client.read(FIRST.len()).await, FIRST);
                            client.send(SECOND).await;
                            assert_eq!(client.read(SECOND.len()).await, SECOND);
                            finish(client.io.peer.as_mut().unwrap()).await;
                        }
                        Layout::Boundary(prefix) => {
                            if prefix <= request.wire.len() {
                                let peer =
                                    timeout(WAIT, upgrade(raw, mode, layout, request.wire.clone()))
                                        .await
                                        .unwrap();
                                let skip = request.wire.len();
                                let mut client =
                                    Client::start(SkipHeader { peer, skip }, request, Some(FIRST))
                                        .await;
                                assert_eq!(client.read(FIRST.len()).await, FIRST);
                                let wire = client.wire(SECOND);
                                messages(&mut client.io.peer, &wire).await;
                                assert_eq!(client.read(SECOND.len()).await, SECOND);
                                finish(&mut client.io.peer).await;
                            } else {
                                // 首块长度/tag 自身跨 early 与 WS，不能只测认证头边界。
                                let io = EarlyIo::new(raw, mode, layout);
                                let mut client =
                                    timeout(WAIT, Client::start(io, request, Some(FIRST)))
                                        .await
                                        .unwrap();
                                assert_eq!(client.read(FIRST.len()).await, FIRST);
                                client.send(SECOND).await;
                                assert_eq!(client.read(SECOND.len()).await, SECOND);
                                finish(client.io.peer.as_mut().unwrap()).await;
                            }
                        }
                    }
                    total += FIRST.len() + SECOND.len();
                }
            }
            settled(&server, total).await;
            server.shutdown().await;
        }
    }
}

#[tokio::test]
async fn vless_trojan_ws_wss_exact_8192_early_bytes_plus_http_first_frame() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    for protocol in [Protocol::Vless, Protocol::Trojan] {
        for tls in [false, true] {
            let certificate = tls.then_some(&cert);
            for mode in MODES {
                let server = Running::start(config(protocol, mode, certificate)).await;
                let header = plain_header(protocol, echo.address);
                let mut first = vec![0x9d; EARLY_LIMIT - header.len()];
                first[..4].copy_from_slice(b"size");
                let mut early = header;
                early.extend(&first);
                assert_eq!(early.len(), EARLY_LIMIT);
                let extra = b"http-frame-after-8192\x00\xff";
                let mut raw_prefix = ws::masked(true, 2, extra);
                raw_prefix.extend(ws::masked(true, 9, b"limit-control"));
                let raw = raw_connect(server.address, certificate).await;
                let mut peer = timeout(WAIT, handshake(raw, mode, &early, &raw_prefix))
                    .await
                    .unwrap();
                let mut expected = first;
                expected.extend(extra);
                plain_response(protocol, &mut peer, &expected).await;
                messages(&mut peer, SECOND).await;
                let mut bytes = vec![0; SECOND.len()];
                read_exact(&mut peer, &mut bytes).await;
                assert_eq!(bytes, SECOND);
                finish(&mut peer).await;
                drop(peer);
                settled(&server, expected.len() + SECOND.len()).await;
                server.shutdown().await;
            }
        }
    }
}
