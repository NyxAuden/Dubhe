//! 反向 Mux portal（Xray `app/reverse` 的 portal 侧）。
//!
//! 入站 VLESS 命令 4（`v1.rvs.cool`）不拨号目标，而是把该连接注册为一条
//! 反向隧道；隧道上运行 Mux 客户端，普通流量经 `reverse` 出站打开会话，
//! 由远端 Bridge（Mux 服务端）拨号。本模块只实现 portal 侧所需的最小
//! 子集：TCP 会话、End/Keep 处理、Control 心跳与有界资源。

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicU16, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Notify, Semaphore, mpsc},
};
use tokio_util::sync::{CancellationToken, PollSender};

use crate::{
    config::Config,
    forward::{Context, Upstream},
    mux::{self, Status},
    route::ProxyOutbound,
    session::{Host, Network, Target},
};

/// 单条反向隧道允许的并发 Mux 会话数。
const MAX_SESSIONS: usize = 256;
/// 单 portal 允许的并发反向隧道数。
const MAX_CARRIERS: usize = 64;
/// Bridge 侧控制会话的固定目标。
const CONTROL_DOMAIN: &str = "reverse";
/// 控制心跳间隔；Bridge 的 worker 空闲期限为 60 秒。
const HEARTBEAT: Duration = Duration::from_secs(5);

/// 所有 `reverse` 出站对应的 portal；按出站 tag 索引。
#[derive(Default)]
pub(crate) struct Registry {
    portals: HashMap<String, Arc<Portal>>,
}

struct Portal {
    clients: StdMutex<Vec<Weak<ClientInner>>>,
}

/// UDP 回包通道：数据报附带实际来源目标。
type UdpReplySender = mpsc::Sender<(Target, Vec<u8>)>;
type UdpReplyReceiver = mpsc::Receiver<(Target, Vec<u8>)>;

struct ClientInner {
    writer: mpsc::Sender<Vec<u8>>,
    sessions: StdMutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>,
    /// Mux UDP 会话：回包携带实际来源目标。
    udp_sessions: StdMutex<HashMap<u16, UdpReplySender>>,
    next: AtomicU16,
    closed: StdMutex<bool>,
    /// 隧道关闭时唤醒心跳任务，避免停机等待下一次 5 秒心跳。
    closed_notify: Notify,
}

impl ClientInner {
    fn close(&self) {
        *self
            .closed
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        // 丢弃会话发送端会让对应 SessionStream 读到 EOF。
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.udp_sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        // 同时唤醒心跳与隧道写入任务；任务在循环顶部再次检查 closed，
        // 避免通知早于等待时丢失。
        self.closed_notify.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        *self
            .closed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn allocate(&self, target: &Target) -> io::Result<(u16, mpsc::Receiver<Vec<u8>>)> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if *self
            .closed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "反向隧道已关闭",
            ));
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "反向隧道会话已满",
            ));
        }
        let udp = self
            .udp_sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut id = self.next.fetch_add(1, Ordering::Relaxed);
        while id == 0 || sessions.contains_key(&id) || udp.contains_key(&id) {
            id = self.next.fetch_add(1, Ordering::Relaxed);
        }
        drop(udp);
        let (tx, rx) = mpsc::channel(8);
        sessions.insert(id, tx);
        let frame = mux::encode_new(id, Network::Tcp, target, &[])?;
        if self.writer.try_send(frame).is_err() {
            sessions.remove(&id);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "反向隧道写队列已满",
            ));
        }
        Ok((id, rx))
    }

    fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
            + self
                .udp_sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len()
    }

    fn allocate_udp(&self, target: &Target) -> io::Result<(u16, UdpReplyReceiver)> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "反向隧道已关闭",
            ));
        }
        if self.session_count() >= MAX_SESSIONS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "反向隧道会话已满",
            ));
        }
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut udp = self
            .udp_sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if udp.len() >= MAX_SESSIONS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "反向隧道 UDP 会话已满",
            ));
        }
        let mut id = self.next.fetch_add(1, Ordering::Relaxed);
        while id == 0 || sessions.contains_key(&id) || udp.contains_key(&id) {
            id = self.next.fetch_add(1, Ordering::Relaxed);
        }
        let (tx, rx) = mpsc::channel(8);
        udp.insert(id, tx);
        let frame = mux::encode_new(id, Network::Udp, target, &[])?;
        if self.writer.try_send(frame).is_err() {
            udp.remove(&id);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "反向隧道写队列已满",
            ));
        }
        Ok((id, rx))
    }

    fn remove_udp(&self, id: u16) {
        self.udp_sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&id);
    }
}

impl Registry {
    pub(crate) fn new(config: &Config) -> anyhow::Result<Self> {
        let mut portals = HashMap::new();
        for outbound in &config.outbounds {
            if outbound.kind != crate::config::OutboundKind::Reverse {
                continue;
            }
            // domain 仍是配置必填项：缺失时报错，但运行期不再按域名反查 portal。
            outbound
                .domain
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("reverse 出站缺少 domain"))?;
            portals.insert(
                outbound.tag.clone(),
                Arc::new(Portal {
                    clients: StdMutex::new(Vec::new()),
                }),
            );
        }
        Ok(Self { portals })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.portals.is_empty()
    }

    /// 把一条已认证的入站连接注册为反向隧道。
    pub(crate) fn attach<S>(&self, tag: &str, stream: S, ctx: &Arc<Context>) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Some(portal) = self.portals.get(tag) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "反向 portal 不存在",
            ));
        };
        {
            let mut clients = portal
                .clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            clients.retain(|client| client.strong_count() > 0);
            if clients.len() >= MAX_CARRIERS {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "反向隧道数量已满",
                ));
            }
        }
        let (mut read, mut write) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        let inner = Arc::new(ClientInner {
            writer: tx,
            sessions: StdMutex::new(HashMap::new()),
            udp_sessions: StdMutex::new(HashMap::new()),
            next: AtomicU16::new(1),
            closed: StdMutex::new(false),
            closed_notify: Notify::new(),
        });

        let writer_inner = inner.clone();
        let tracker = ctx.children.clone();
        ctx.children.spawn(tracker.track_future(async move {
            loop {
                if writer_inner.is_closed() {
                    break;
                }
                let frame = tokio::select! {
                    biased;
                    _ = writer_inner.closed_notify.notified() => break,
                    frame = rx.recv() => frame,
                };
                let Some(frame) = frame else { break };
                if write.write_all(&frame).await.is_err() {
                    break;
                }
            }
            let _ = write.shutdown().await;
            writer_inner.close();
        }));

        let budget = Arc::new(Semaphore::new(256 * 1024));
        let reader_inner = inner.clone();
        ctx.children.spawn(tracker.track_future(async move {
            while let Ok(Some(frame)) = mux::read_frame(&mut read, &budget).await {
                if !handle_frame(frame, &reader_inner) {
                    break;
                }
            }
            reader_inner.close();
        }));

        spawn_heartbeat(inner.clone(), ctx);
        portal
            .clients
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(Arc::downgrade(&inner));
        Ok(())
    }

    /// 通过指定 portal 的最新可用隧道打开一条 Mux 会话。
    pub(crate) async fn open(&self, tag: &str, target: &Target) -> io::Result<Upstream> {
        let Some(portal) = self.portals.get(tag) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "反向 portal 不存在",
            ));
        };
        let client = {
            let clients = portal
                .clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            clients
                .iter()
                .rev()
                .filter_map(Weak::upgrade)
                .find(|client| client.session_count() < MAX_SESSIONS)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "没有可用的反向隧道"))?
        };
        let (id, incoming) = client.allocate(target)?;
        Ok(Upstream::from_parts(
            Box::new(SessionStream {
                id,
                client,
                incoming,
                outgoing: None,
                buffer: Vec::new(),
                offset: 0,
                shutdown: false,
            }),
            // 反向隧道没有真实本地地址；SOCKS5 应答使用通配地址。
            Some(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
            None,
        ))
    }
}

impl Registry {
    /// 通过指定 portal 的最新可用隧道打开一条 Mux UDP 会话。
    pub(crate) fn open_udp(
        &self,
        tag: &str,
        target: &Target,
    ) -> io::Result<(UdpSender, UdpReceiver)> {
        let Some(portal) = self.portals.get(tag) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "反向 portal 不存在",
            ));
        };
        let client = {
            let clients = portal
                .clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            clients
                .iter()
                .rev()
                .filter_map(Weak::upgrade)
                .find(|client| client.session_count() < MAX_SESSIONS)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "没有可用的反向隧道"))?
        };
        let (id, incoming) = client.allocate_udp(target)?;
        Ok((UdpSender { id, client }, UdpReceiver { incoming }))
    }
}

/// Portal 侧的 Mux UDP 发送端；目标随每个数据报携带。
pub(crate) struct UdpSender {
    id: u16,
    client: Arc<ClientInner>,
}

impl UdpSender {
    pub(crate) async fn send(&self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let frame = mux::encode_data(self.id, Some(target), payload)?;
        self.client
            .writer
            .send(frame)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "反向隧道已关闭"))
    }
}

impl Drop for UdpSender {
    fn drop(&mut self) {
        self.client.remove_udp(self.id);
        let _ = self.client.writer.try_send(mux::encode_end(self.id, true));
    }
}

pub(crate) struct UdpReceiver {
    incoming: mpsc::Receiver<(Target, Vec<u8>)>,
}

impl UdpReceiver {
    pub(crate) async fn recv(&mut self) -> Option<(Target, Vec<u8>)> {
        self.incoming.recv().await
    }
}

/// Bridge 后台循环：主动拨入 Portal，完成 VLESS 命令 4 后在隧道上运行
/// Mux 服务端；连接结束后按配置间隔重连。
pub(crate) async fn bridge_loop(
    ctx: Arc<Context>,
    tag: String,
    proxy: Arc<ProxyOutbound>,
    reconnect: Duration,
    stop: CancellationToken,
    force: CancellationToken,
) {
    loop {
        let result = tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = force.cancelled() => return,
            result = bridge_once(ctx.clone(), tag.clone(), proxy.clone()) => result,
        };
        if let Err(error) = result {
            tracing::debug!(event = "reverse_bridge_disconnected", bridge = %tag, kind = ?error.kind());
        }
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = force.cancelled() => return,
            _ = tokio::time::sleep(reconnect) => {}
        }
    }
}

async fn bridge_once(ctx: Arc<Context>, tag: String, proxy: Arc<ProxyOutbound>) -> io::Result<()> {
    let stream = ctx.dial_proxy_transport(&proxy, false).await?;
    let stream = crate::outbound::vless_reverse_connect(stream, &proxy).await?;
    // Portal 可通过同一隧道建立 Mux UDP 会话；Bridge 侧按本地路由拨出。
    mux::serve(stream, ctx, tag, true, None).await
}

/// 处理 Bridge 下行帧；返回 `false` 表示隧道应终止。
fn handle_frame(frame: mux::Frame, client: &Arc<ClientInner>) -> bool {
    match frame.status {
        Status::Keep if matches!(frame.network, Some(Network::Udp)) => {
            let (Some(target), Some(chunk)) = (frame.target, frame.payload) else {
                return true;
            };
            let sender = client
                .udp_sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(&frame.id)
                .cloned();
            match sender {
                Some(sender) => {
                    if sender.try_send((target, chunk.payload)).is_err() {
                        client.remove_udp(frame.id);
                        let _ = client.writer.try_send(mux::encode_end(frame.id, true));
                    }
                }
                None => {
                    let _ = client.writer.try_send(mux::encode_end(frame.id, true));
                }
            }
            true
        }
        Status::Keep => {
            let Some(chunk) = frame.payload else {
                return true;
            };
            let sender = client
                .sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(&frame.id)
                .cloned();
            match sender {
                Some(sender) => {
                    if sender.try_send(chunk.payload).is_err() {
                        // 会话读取过慢：丢弃并结束该会话，不阻塞整条隧道。
                        let _ = sender.try_send(Vec::new());
                    }
                }
                None => {
                    let _ = client.writer.try_send(mux::encode_end(frame.id, true));
                }
            }
            true
        }
        Status::End => {
            client
                .sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&frame.id);
            client.remove_udp(frame.id);
            true
        }
        Status::KeepAlive => true,
        // 客户端方向不应收到 New；丢弃其负载并继续。
        Status::New => true,
    }
}

fn spawn_heartbeat(client: Arc<ClientInner>, ctx: &Arc<Context>) {
    let tracker = ctx.children.clone();
    ctx.children.spawn(tracker.track_future(async move {
        heartbeat_loop(client).await;
    }));
}

async fn heartbeat_loop(client: Arc<ClientInner>) {
    let id = client.next.fetch_add(1, Ordering::Relaxed);
    let control = Target {
        host: Host::Domain(CONTROL_DOMAIN.to_owned()),
        port: 0,
    };
    if let Ok(frame) = mux::encode_new(id, Network::Udp, &control, &[]) {
        let _ = client.writer.send(frame).await;
    }
    let mut interval = tokio::time::interval(HEARTBEAT);
    interval.tick().await;
    loop {
        if client.is_closed() {
            return;
        }
        tokio::select! {
            biased;
            _ = client.closed_notify.notified() => return,
            _ = interval.tick() => {}
        }
        if client.is_closed() {
            return;
        }
        let Ok(frame) = mux::encode_data(id, None, &control_message()) else {
            return;
        };
        if client.writer.send(frame).await.is_err() {
            return;
        }
    }
}

/// 手写 protobuf：`Control { state = ACTIVE(0), random = bytes }`。
fn control_message() -> Vec<u8> {
    let mut random = vec![0u8; 64];
    let _ = aws_lc_rs::rand::fill(&mut random);
    let mut message = Vec::with_capacity(3 + random.len());
    // 字段 99，wire type 2。
    message.extend_from_slice(&[0x9a, 0x06]);
    message.push(random.len() as u8);
    message.extend_from_slice(&random);
    message
}

struct SessionStream {
    id: u16,
    client: Arc<ClientInner>,
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: Option<PollSender<Vec<u8>>>,
    buffer: Vec<u8>,
    offset: usize,
    shutdown: bool,
}

impl SessionStream {
    fn sender(&mut self) -> &mut PollSender<Vec<u8>> {
        if self.outgoing.is_none() {
            self.outgoing = Some(PollSender::new(self.client.writer.clone()));
        }
        self.outgoing.as_mut().expect("发送端已初始化")
    }

    fn release(&self) {
        self.client
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.id);
    }
}

impl Drop for SessionStream {
    fn drop(&mut self) {
        self.release();
        if !self.shutdown {
            let _ = self.client.writer.try_send(mux::encode_end(self.id, false));
        }
    }
}

impl AsyncRead for SessionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.offset < this.buffer.len() {
                let count = buf.remaining().min(this.buffer.len() - this.offset);
                buf.put_slice(&this.buffer[this.offset..this.offset + count]);
                this.offset += count;
                return Poll::Ready(Ok(()));
            }
            this.buffer.clear();
            this.offset = 0;
            match this.incoming.poll_recv(cx) {
                Poll::Ready(Some(payload)) => this.buffer = payload,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SessionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.as_mut().get_mut();
        let frame = mux::encode_data(this.id, None, buf)?;
        let sender = this.sender();
        match sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                if sender.send_item(frame).is_err() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "反向隧道已关闭",
                    )));
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "反向隧道已关闭",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shutdown {
            let _ = this.client.writer.try_send(mux::encode_end(this.id, false));
            this.shutdown = true;
            this.release();
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn portal_context() -> Arc<Context> {
        let config = Config::from_json(
            r#"{
                "version": 1,
                "inbounds": [{"type":"socks5","tag":"in","listen":"127.0.0.1:0"}],
                "outbounds": [
                    {"type":"reverse","tag":"portal","domain":"v1.rvs.cool"},
                    {"type":"direct","tag":"direct"}
                ],
                "route": {"default": "portal"}
            }"#,
        )
        .unwrap();
        Arc::new(Context::new(&config).unwrap())
    }

    fn bridge_context() -> Arc<Context> {
        let config = Config::from_json(
            r#"{
                "version": 1,
                "inbounds": [{"type":"socks5","tag":"in","listen":"127.0.0.1:0"}],
                "outbounds": [{"type":"direct","tag":"direct"}],
                "route": {"default": "direct"}
            }"#,
        )
        .unwrap();
        Arc::new(Context::new(&config).unwrap())
    }

    #[tokio::test]
    async fn portal_session_relays_through_mux_server() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });

        let ctx = portal_context();
        let registry = Registry::new(
            &Config::from_json(
                r#"{
                "version": 1,
                "inbounds": [{"type":"socks5","tag":"in","listen":"127.0.0.1:0"}],
                "outbounds": [
                    {"type":"reverse","tag":"portal","domain":"v1.rvs.cool"},
                    {"type":"direct","tag":"direct"}
                ],
                "route": {"default": "portal"}
            }"#,
            )
            .unwrap(),
        )
        .unwrap();
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let bridge = bridge_context();
        let bridge_task = tokio::spawn(crate::mux::serve(
            server_side,
            bridge,
            "bridge".into(),
            true,
            None,
        ));
        registry.attach("portal", client_side, &ctx).unwrap();

        let target = Target {
            host: Host::Ip("127.0.0.1".parse().unwrap()),
            port: echo_address.port(),
        };
        let mut upstream = registry.open("portal", &target).await.unwrap();
        upstream.write_all(b"reverse-mux").await.unwrap();
        let mut echoed = [0u8; 11];
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::io::AsyncReadExt::read_exact(&mut upstream, &mut echoed),
        )
        .await
        .expect("反向 Mux 回显超时")
        .unwrap();
        assert_eq!(&echoed, b"reverse-mux");

        drop(upstream);
        bridge_task.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn open_without_carrier_fails_closed() {
        let registry = Registry::new(
            &Config::from_json(
                r#"{
                "version": 1,
                "inbounds": [{"type":"socks5","tag":"in","listen":"127.0.0.1:0"}],
                "outbounds": [
                    {"type":"reverse","tag":"portal","domain":"v1.rvs.cool"},
                    {"type":"direct","tag":"direct"}
                ],
                "route": {"default": "portal"}
            }"#,
            )
            .unwrap(),
        )
        .unwrap();
        let target = Target {
            host: Host::Ip("127.0.0.1".parse().unwrap()),
            port: 9,
        };
        let error = registry.open("portal", &target).await.expect_err("应失败");
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn uuid_bytes() -> [u8; 16] {
        let hex: String = UUID.chars().filter(|ch| *ch != '-').collect();
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        bytes
    }

    #[tokio::test]
    async fn vless_command_four_registers_a_portal_tunnel() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });

        let config = Config::from_json(&format!(
            r#"{{
                "version": 1,
                "inbounds": [
                    {{"type":"vless","tag":"vless","listen":"127.0.0.1:0",
                      "users":[{{"name":"u","uuid":"{UUID}"}}]}},
                    {{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}}
                ],
                "outbounds": [
                    {{"type":"reverse","tag":"portal","domain":"v1.rvs.cool"}},
                    {{"type":"direct","tag":"direct"}}
                ],
                "route": {{
                    "default": "direct",
                    "rules": [
                        {{"domains": ["v1.rvs.cool"], "outbound": "portal"}},
                        {{"inbounds": ["socks"], "outbound": "portal"}}
                    ]
                }},
                "limits": {{"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}}
            }}"#
        ))
        .unwrap();
        let server = crate::runtime::Server::bind(config).await.unwrap();
        let vless_address = server.local_addr("vless").unwrap();
        let socks_address = server.local_addr("socks").unwrap();
        let stop = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn(server.run(stop.clone()));

        // 建立反向隧道：VLESS 命令 4。
        let mut carrier = TcpStream::connect(vless_address).await.unwrap();
        let mut header = vec![0u8];
        header.extend_from_slice(&uuid_bytes());
        header.push(0);
        header.push(4);
        carrier.write_all(&header).await.unwrap();
        let mut reply = [0u8; 2];
        carrier.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0, 0]);

        // 测试端充当 Bridge：在同一连接上运行 Mux 服务端。
        let bridge_config = Config::from_json(
            r#"{
                "version": 1,
                "inbounds": [{"type":"socks5","tag":"in","listen":"127.0.0.1:0"}],
                "outbounds": [{"type":"direct","tag":"direct"}],
                "route": {"default": "direct"}
            }"#,
        )
        .unwrap();
        let bridge_ctx = Arc::new(Context::new(&bridge_config).unwrap());
        let bridge = tokio::spawn(crate::mux::serve(
            carrier,
            bridge_ctx,
            "bridge".into(),
            true,
            None,
        ));

        // 通过 SOCKS5 入站的普通连接经 portal 的 mux 会话到达 echo。
        let mut socks = TcpStream::connect(socks_address).await.unwrap();
        socks.write_all(&[5, 1, 0]).await.unwrap();
        socks.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend_from_slice(&echo_address.port().to_be_bytes());
        socks.write_all(&connect).await.unwrap();
        let mut head = [0u8; 3];
        socks.read_exact(&mut head).await.unwrap();
        assert_eq!(head, [5, 0, 0]);
        // ATYP(1) + IPv4(4) + 端口(2)；通配地址为 0.0.0.0:0。
        let mut bound = [0u8; 7];
        socks.read_exact(&mut bound).await.unwrap();

        socks.write_all(b"runtime-reverse").await.unwrap();
        let mut echoed = [0u8; 15];
        tokio::time::timeout(Duration::from_secs(3), socks.read_exact(&mut echoed))
            .await
            .expect("反向 Mux 运行时回显超时")
            .unwrap();
        assert_eq!(&echoed, b"runtime-reverse");

        drop(socks);
        bridge.abort();
        stop.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        echo_task.abort();
    }
}
