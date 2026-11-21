//! mKCP 出站：在独立 UDP 套接字上承载一条限定对端的可靠 KCP 流。
//!
//! 每条流绑定独立端口、生成随机非零 `conv`；协议、重传和密码全部复用
//! `transport::kcp`。收包与 driver 是同一任务中的两个 future，任一方退出都会
//! 回收另一方。取消时给现有 driver 一段发送 Terminate 的有界宽限期；Drop
//! 只发出取消信号，不派生清理任务。运行时应使用 `connect_tracked` 接入
//! `Context.children`，普通 `connect` 保留相同的连接所有权与回收行为。

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::{mpsc, mpsc::error::TrySendError},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::kcp::{
    Prepared,
    conn::{Driver, KcpStream, start},
    segment::{ACK_LIMIT, COMMAND_PING, COMMAND_TERMINATE, DATA_OVERHEAD, Segment, parse},
};

/// 足以容纳完整 UDP 报文；不能按 MSS 截短，driver 可能合并多个分段。
const UDP_BUFFER: usize = 65_536;
/// 队列满时丢包，由已有 KCP 重传机制恢复。
const RX_QUEUE: usize = 256;
/// 取消后允许 driver 发送 Terminate；超时直接丢弃其 future，释放 socket。
const CLOSE_GRACE: Duration = Duration::from_secs(1);
/// 显式关闭的额外保险；取消关闭 future 不会取走任务句柄。
#[cfg(test)]
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Client {
    prepared: Arc<Prepared>,
}

impl Client {
    pub(crate) fn new(prepared: Arc<Prepared>) -> Self {
        Self { prepared }
    }

    /// 绑定同族本地地址并限定收包对端；不代表对端已经应答或认证成功。
    #[cfg(test)]
    pub(crate) async fn connect(&self, peer: SocketAddr) -> io::Result<KcpClientStream> {
        self.connect_tracked(peer, TaskTracker::new()).await
    }

    /// 与 `connect` 相同，但把整个连接任务纳入调用方的子任务跟踪器。
    ///
    /// 所有可能失败的异步初始化都发生在 spawn 之前；spawn 后没有 await，
    /// 因此取消建连不会留下没有流所有者的后台任务。
    pub(crate) async fn connect_tracked(
        &self,
        peer: SocketAddr,
        tasks: TaskTracker,
    ) -> io::Result<KcpClientStream> {
        let socket = Arc::new(UdpSocket::bind(local_addr(peer)).await?);
        // 保持未连接 socket：Driver 复用 send_to，receive_loop 显式校验来源。
        let conv = random_conv()?;
        let (stream, shared, wake) = start(&self.prepared);
        let stop = CancellationToken::new();
        let lifecycle = Arc::new(Lifecycle::default());
        let (sender, receiver) = mpsc::channel(RX_QUEUE);
        let receive = receive_loop(
            socket.clone(),
            peer,
            self.prepared.clone(),
            conv,
            sender,
            stop.clone(),
        );
        let driver = Driver {
            socket,
            dest: peer,
            mask: self.prepared.mask.clone(),
            conv,
            prepared: self.prepared.clone(),
            rx: receiver,
            stop: stop.clone(),
            on_exit: None,
        };
        // 在 spawn 前构造守卫，即使任务在首次 poll 前被取消也能发布结束状态。
        let completion = Completion {
            stop: stop.clone(),
            lifecycle: lifecycle.clone(),
            normal: false,
        };
        let task = tasks.spawn(async move {
            let mut completion = completion;
            run_connection(
                driver.run(shared, wake),
                receive,
                &completion.stop,
                &completion.lifecycle,
            )
            .await;
            completion.normal = true;
        });

        Ok(KcpClientStream {
            inner: stream,
            stop,
            lifecycle,
            task: Some(task),
        })
    }
}

/// 正常结束时允许读完内层缓冲；失败则所有后续操作持续返回首个错误。
#[derive(Default)]
struct Lifecycle {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    error: Option<io::Error>,
    finished: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl Lifecycle {
    #[cfg(test)]
    fn error(&self) -> Option<io::Error> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        copy_error(&state.error)
    }

    /// 注册与检查共用一把锁，避免任务退出与外层 poll 之间丢失唤醒。
    fn poll_state(&self, cx: &Context<'_>, reading: bool) -> io::Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(error) = copy_error(&state.error) {
            return Err(error);
        }
        let waker = if reading {
            &mut state.reader
        } else {
            &mut state.writer
        };
        if !waker
            .as_ref()
            .is_some_and(|waker| waker.will_wake(cx.waker()))
        {
            *waker = Some(cx.waker().clone());
        }
        Ok(state.finished)
    }

    fn fail(&self, error: io::Error) {
        let (reader, writer) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.error.is_none() {
                state.error = Some(error);
            }
            (state.reader.take(), state.writer.take())
        };
        wake(reader, writer);
    }

    fn finish(&self) {
        let (reader, writer) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.finished = true;
            (state.reader.take(), state.writer.take())
        };
        wake(reader, writer);
    }
}

fn copy_error(error: &Option<io::Error>) -> Option<io::Error> {
    error
        .as_ref()
        .map(|error| io::Error::new(error.kind(), error.to_string()))
}

fn wake(reader: Option<Waker>, writer: Option<Waker>) {
    if let Some(waker) = reader {
        waker.wake();
    }
    if let Some(waker) = writer {
        waker.wake();
    }
}

/// 任务 panic/abort 时，内层 Shared 未必被 driver.close 更新，必须单独唤醒流。
struct Completion {
    stop: CancellationToken,
    lifecycle: Arc<Lifecycle>,
    normal: bool,
}

impl Drop for Completion {
    fn drop(&mut self) {
        self.stop.cancel();
        if !self.normal {
            self.lifecycle
                .fail(io::Error::other("mKCP 连接任务被取消或异常退出"));
        }
        self.lifecycle.finish();
    }
}

/// 不再 spawn driver 或 receiver：丢弃本任务就能释放两者及全部 socket 引用。
async fn run_connection(
    driver: impl Future<Output = ()>,
    receive: impl Future<Output = io::Result<()>>,
    stop: &CancellationToken,
    lifecycle: &Lifecycle,
) {
    let mut driver = Box::pin(driver);
    let mut receive = Box::pin(receive);
    let driver_done = tokio::select! {
        biased;
        _ = stop.cancelled() => false,
        _ = &mut driver => true,
        result = &mut receive => {
            match result {
                Err(error) => lifecycle.fail(error),
                Ok(()) if !stop.is_cancelled() => {
                    lifecycle.fail(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mKCP 收包通道意外关闭",
                    ));
                }
                Ok(()) => {}
            }
            false
        }
    };
    stop.cancel();
    // Driver 自然结束时也立即丢弃 recv future，不依赖下一份报文才能回收。
    drop(receive);
    if !driver_done && timeout(CLOSE_GRACE, &mut driver).await.is_err() {
        lifecycle.fail(io::Error::new(io::ErrorKind::TimedOut, "mKCP 驱动关闭超时"));
    }
    // 超时会在此直接丢弃 driver future，包括卡在 send_to 的关闭发送。
}

pub(crate) struct KcpClientStream {
    inner: KcpStream,
    stop: CancellationToken,
    lifecycle: Arc<Lifecycle>,
    /// 仅测试的 `shutdown()` 会等待该句柄；生产 Drop 只取消 `stop`，
    /// 任务由 `TaskTracker` 跟踪。保留句柄以便测试观察回收。
    #[cfg_attr(not(test), allow(dead_code))]
    task: Option<JoinHandle<()>>,
}

impl KcpClientStream {
    /// 完整关闭而非半关闭：取消收包，让 driver 尽力发送 Terminate 并等待回收。
    ///
    /// 取消此方法的 future 后句柄仍在流中，可再次等待；Drop 仍会发出取消。
    /// 首个失败保留在生命周期中，重复关闭也不会把失败变成成功。
    #[cfg(test)]
    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.stop.cancel();
        if let Some(task) = self.task.as_mut() {
            match timeout(SHUTDOWN_TIMEOUT, &mut *task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => self
                    .lifecycle
                    .fail(io::Error::other(format!("mKCP 连接任务退出失败: {error}"))),
                Err(_) => {
                    self.lifecycle.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "mKCP 连接任务回收超时",
                    ));
                    task.abort();
                    let _ = task.await;
                }
            }
        }
        self.task.take();
        match self.lifecycle.error().or_else(|| self.inner.error()) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl AsyncRead for KcpClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let finished = match this.lifecycle.poll_state(cx, true) {
            Ok(finished) => finished,
            Err(error) => return Poll::Ready(Err(error)),
        };
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            // 正常退出仍先读完已交付的字节；没有 driver 后不能再永久 Pending。
            Poll::Pending if finished => Poll::Ready(Ok(())),
            result => result,
        }
    }
}

impl AsyncWrite for KcpClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let finished = match this.lifecycle.poll_state(cx, false) {
            Ok(finished) => finished,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Some(error) = this.inner.error() {
            return Poll::Ready(Err(error));
        }
        if finished || this.stop.is_cancelled() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mKCP 会话已关闭",
            )));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.lifecycle.poll_state(cx, false) {
            return Poll::Ready(Err(error));
        }
        // 与 KcpStream 一致：通知 driver 刷新即可，不额外等待对端 ACK。
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.lifecycle.poll_state(cx, false) {
            return Poll::Ready(Err(error));
        }
        // 保留 KcpStream 的关闭/排空流程，不把 AsyncWrite 关闭改成立即取消。
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl Drop for KcpClientStream {
    fn drop(&mut self) {
        // 任务已在建连时创建（可被 Context.children 跟踪），Drop 不创建新任务。
        self.stop.cancel();
    }
}

fn local_addr(peer: SocketAddr) -> SocketAddr {
    if peer.is_ipv4() {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    }
}

fn random_conv() -> io::Result<u16> {
    loop {
        let mut bytes = [0u8; 2];
        aws_lc_rs::rand::fill(&mut bytes).map_err(|_| io::Error::other("mKCP 无法生成会话号"))?;
        let conv = u16::from_be_bytes(bytes);
        if conv != 0 {
            return Ok(conv);
        }
    }
}

async fn receive_loop(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    prepared: Arc<Prepared>,
    conv: u16,
    sender: mpsc::Sender<Vec<Segment>>,
    stop: CancellationToken,
) -> io::Result<()> {
    let mut buffer = vec![0u8; UDP_BUFFER];
    let overhead = prepared
        .mask
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .overhead();
    // MTU 描述 KCP 明文层；外层混淆/认证开销额外占用 UDP 载荷。
    let udp_limit = prepared.mtu.saturating_add(overhead).min(65_507);
    loop {
        let received = tokio::select! {
            biased;
            _ = stop.cancelled() => return Ok(()),
            _ = sender.closed() => return Ok(()),
            received = socket.recv_from(&mut buffer) => received,
        };
        let (length, source) = match received {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("mKCP 收包失败: {error}"),
                ));
            }
        };
        // socket 保持未连接以复用 Driver::send_to；来源不匹配时甚至不解码掩码。
        if source != peer || length == 0 || length > udp_limit {
            continue;
        }
        let decoded = prepared
            .mask
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .decode(&buffer[..length]);
        let Some(payload) = decoded else { continue };
        let Some(segments) = checked_segments(&payload, conv, prepared.mss) else {
            continue;
        };
        match sender.try_send(segments) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Closed(_)) => return Ok(()),
        }
    }
}

/// 复用解析器，但不接收其“有效前缀”：任何尾部截断、未知命令、混合 conv、
/// 保留 option 位、超长数据/ACK 都导致整份报文丢弃，控制段也不能例外。
fn checked_segments(payload: &[u8], conv: u16, mss: usize) -> Option<Vec<Segment>> {
    let segments = parse(payload);
    if segments.is_empty() {
        return None;
    }
    let mut consumed = 0;
    for segment in &segments {
        if segment.conv() != conv {
            return None;
        }
        let (option, length) = match segment {
            Segment::Data(data) if data.payload.len() <= mss => {
                (data.option, DATA_OVERHEAD + data.payload.len())
            }
            Segment::Ack(ack) if ack.numbers.len() <= ACK_LIMIT => {
                (ack.option, 17 + ack.numbers.len() * 4)
            }
            Segment::Cmd(cmd) if matches!(cmd.command, COMMAND_PING | COMMAND_TERMINATE) => {
                (cmd.option, 16)
            }
            _ => return None,
        };
        if option & !1 != 0 {
            return None;
        }
        consumed += length;
    }
    (consumed == payload.len()).then_some(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{pending, poll_fn},
        sync::atomic::{AtomicBool, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        config::{Kcp, KcpSecurity},
        transport::kcp::{
            prepare,
            segment::{AckSegment, CmdSegment, DataSegment},
        },
    };

    const WAIT: Duration = Duration::from_secs(3);
    const CONV: u16 = 7;

    fn raw_client() -> Client {
        Client::new(
            prepare(&Kcp {
                security: KcpSecurity::None,
                tti: 10,
                ..Kcp::default()
            })
            .unwrap(),
        )
    }

    fn data(conv: u16, payload: &[u8]) -> Segment {
        Segment::Data(DataSegment {
            conv,
            option: 0,
            timestamp: 0,
            number: 0,
            sending_next: 0,
            payload: payload.to_vec(),
        })
    }

    fn command(conv: u16, command: u8) -> Segment {
        Segment::Cmd(CmdSegment {
            conv,
            command,
            option: 0,
            sending_next: 1,
            receiving_next: 1,
            peer_rto: 100,
        })
    }

    async fn first_packet(peer: &UdpSocket) -> (SocketAddr, u16) {
        let mut buffer = vec![0; UDP_BUFFER];
        let (length, source) = timeout(WAIT, peer.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let segments = parse(&buffer[..length]);
        assert!(!segments.is_empty());
        (source, segments[0].conv())
    }

    async fn wait_tasks(tasks: &TaskTracker) {
        tasks.close();
        timeout(WAIT, tasks.wait())
            .await
            .expect("连接任务未按时回收");
        assert!(tasks.is_empty());
    }

    #[test]
    fn whole_packet_validation_rejects_partial_mixed_and_unknown_segments() {
        let one = data(CONV, b"one").encode();
        let ping = command(CONV, COMMAND_PING).encode();
        let mut packet = one.clone();
        packet.extend(&ping);
        assert_eq!(checked_segments(&packet, CONV, 3).unwrap().len(), 2);
        assert!(checked_segments(&[], CONV, 3).is_none());
        assert!(checked_segments(&one, CONV, 2).is_none());
        assert!(checked_segments(&one, CONV + 1, 3).is_none());

        for tail in [
            vec![0],
            ping[..15].to_vec(),
            command(CONV + 1, COMMAND_TERMINATE).encode(),
        ] {
            let mut malformed = one.clone();
            malformed.extend(tail);
            assert!(checked_segments(&malformed, CONV, 3).is_none());
        }
        assert!(checked_segments(&one[..one.len() - 1], CONV, 3).is_none());
        assert!(checked_segments(&command(CONV, 255).encode(), CONV, 3).is_none());
        let mut reserved_option = command(CONV, COMMAND_TERMINATE).encode();
        reserved_option[3] = 2;
        assert!(checked_segments(&reserved_option, CONV, 3).is_none());
        let ack = Segment::Ack(AckSegment {
            conv: CONV,
            option: 0,
            receiving_window: 32,
            receiving_next: 0,
            timestamp: 0,
            numbers: vec![0; ACK_LIMIT + 1],
        });
        assert!(checked_segments(&ack.encode(), CONV, 3).is_none());
    }

    #[tokio::test]
    async fn fatal_error_is_sticky_for_read_write_flush_and_shutdown() {
        let client = raw_client();
        let (inner, _, _) = start(&client.prepared);
        let lifecycle = Arc::new(Lifecycle::default());
        let mut stream = KcpClientStream {
            inner,
            stop: CancellationToken::new(),
            lifecycle: lifecycle.clone(),
            task: None,
        };
        lifecycle.fail(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "first failure",
        ));
        lifecycle.fail(io::Error::other("must not replace first failure"));
        for _ in 0..2 {
            assert_eq!(
                stream.read(&mut [0]).await.unwrap_err().kind(),
                io::ErrorKind::ConnectionReset
            );
            assert_eq!(
                stream.write(b"data").await.unwrap_err().kind(),
                io::ErrorKind::ConnectionReset
            );
            assert_eq!(
                stream.flush().await.unwrap_err().kind(),
                io::ErrorKind::ConnectionReset
            );
            assert_eq!(
                AsyncWriteExt::shutdown(&mut stream)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::ConnectionReset
            );
            assert_eq!(
                stream.shutdown().await.unwrap_err().kind(),
                io::ErrorKind::ConnectionReset
            );
        }
    }

    #[tokio::test]
    async fn flush_notifies_driver_without_waiting_for_an_ack() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut stream = raw_client()
            .connect(peer.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        stream.write_all(b"not acknowledged").await.unwrap();
        timeout(Duration::from_millis(100), stream.flush())
            .await
            .unwrap()
            .unwrap();
        AsyncWriteExt::shutdown(&mut stream).await.unwrap();
        assert!(
            !stream.stop.is_cancelled(),
            "AsyncWrite 关闭应保留内层排空流程"
        );
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn receive_failure_cancels_driver_and_preserves_the_original_error() {
        let stop = CancellationToken::new();
        let lifecycle = Lifecycle::default();
        let driver = async { stop.cancelled().await };
        let receive = async {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "receive failed",
            ))
        };
        run_connection(driver, receive, &stop, &lifecycle).await;
        assert!(stop.is_cancelled());
        for _ in 0..2 {
            assert_eq!(
                lifecycle.error().unwrap().kind(),
                io::ErrorKind::ConnectionReset
            );
        }
    }

    #[tokio::test]
    async fn driver_natural_exit_reclaims_receiver_and_port_while_stream_is_alive() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tasks = TaskTracker::new();
        let mut stream = raw_client()
            .connect_tracked(peer.local_addr().unwrap(), tasks.clone())
            .await
            .unwrap();
        stream.write_all(b"probe").await.unwrap();
        let (source, conv) = first_packet(&peer).await;
        peer.send_to(&command(conv, COMMAND_TERMINATE).encode(), source)
            .await
            .unwrap();
        let mut buffer = [0];
        assert_eq!(
            timeout(WAIT, stream.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        // 保持应用流存活且不再发任何报文，任务也必须自然结束。
        wait_tasks(&tasks).await;
        let _rebound = UdpSocket::bind(source)
            .await
            .expect("自然退出后 UDP 端口仍被收包任务持有");
        assert_eq!(
            stream.write(b"closed").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn drop_sends_terminate_and_releases_outbound_port() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tasks = TaskTracker::new();
        let mut stream = raw_client()
            .connect_tracked(peer.local_addr().unwrap(), tasks.clone())
            .await
            .unwrap();
        stream.write_all(b"probe").await.unwrap();
        let (source, conv) = first_packet(&peer).await;
        drop(stream);
        timeout(WAIT, async {
            let mut buffer = vec![0; UDP_BUFFER];
            loop {
                let (length, from) = peer.recv_from(&mut buffer).await.unwrap();
                assert_eq!(from, source);
                if parse(&buffer[..length])
                    .iter()
                    .any(|segment| segment.conv() == conv && segment.command() == COMMAND_TERMINATE)
                {
                    break;
                }
            }
        })
        .await
        .expect("Drop 后未收到 Terminate");
        wait_tasks(&tasks).await;
        let _rebound = UdpSocket::bind(source)
            .await
            .expect("Drop 后 UDP 端口未释放");
    }

    #[tokio::test]
    async fn timed_out_handshake_owns_and_drops_the_stream() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tasks = TaskTracker::new();
        let mut stream = raw_client()
            .connect_tracked(peer.local_addr().unwrap(), tasks.clone())
            .await
            .unwrap();
        let handshake = timeout(Duration::from_millis(100), async move {
            stream.write_all(b"unanswered").await.unwrap();
            stream.read(&mut [0]).await
        });
        let (result, (source, _)) = tokio::join!(handshake, first_packet(&peer));
        assert!(result.is_err());
        wait_tasks(&tasks).await;
        let _rebound = UdpSocket::bind(source)
            .await
            .expect("超时取消握手后 UDP 端口未释放");
    }

    #[tokio::test]
    async fn cancelled_shutdown_retains_handle_for_another_wait() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tasks = TaskTracker::new();
        let mut stream = raw_client()
            .connect_tracked(peer.local_addr().unwrap(), tasks.clone())
            .await
            .unwrap();
        let mut closing = Box::pin(stream.shutdown());
        let pending = poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx).is_pending())).await;
        assert!(pending, "首次关闭应等待尚未运行的连接任务");
        drop(closing);
        assert!(stream.task.is_some(), "取消关闭不能丢失清理句柄");
        timeout(WAIT, stream.shutdown()).await.unwrap().unwrap();
        wait_tasks(&tasks).await;
    }

    #[tokio::test]
    async fn task_abort_wakes_pending_read_and_never_reopens_writes() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tasks = TaskTracker::new();
        let mut stream = raw_client()
            .connect_tracked(peer.local_addr().unwrap(), tasks.clone())
            .await
            .unwrap();
        let mut buffer = [0];
        let mut reading = Box::pin(stream.read(&mut buffer));
        assert!(poll_fn(|cx| Poll::Ready(reading.as_mut().poll(cx).is_pending())).await);
        drop(reading);
        stream.task.as_ref().unwrap().abort();
        // 不先等待 tracker：这一 read 必须由 Completion 的外层 waker 唤醒。
        assert!(
            timeout(WAIT, stream.read(&mut buffer))
                .await
                .unwrap()
                .is_err()
        );
        assert!(stream.read(&mut buffer).await.is_err());
        assert!(stream.write(b"never queued").await.is_err());
        assert!(stream.flush().await.is_err());
        wait_tasks(&tasks).await;
    }

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stuck_driver_is_dropped_after_bounded_cancel_grace() {
        let flag = Arc::new(AtomicBool::new(false));
        let guard = Dropped(flag.clone());
        let driver = async move {
            let _guard = guard;
            pending::<()>().await;
        };
        let stop = CancellationToken::new();
        let lifecycle = Lifecycle::default();
        stop.cancel();
        // 使用永不返回的 future 模拟 driver 卡在 UDP 发送；不改动协议实现。
        run_connection(driver, pending::<io::Result<()>>(), &stop, &lifecycle).await;
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(lifecycle.error().unwrap().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn foreign_source_and_malformed_control_cannot_close_a_stream() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tasks = TaskTracker::new();
        let mut stream = raw_client()
            .connect_tracked(peer.local_addr().unwrap(), tasks.clone())
            .await
            .unwrap();
        stream.write_all(b"probe").await.unwrap();
        let (source, conv) = first_packet(&peer).await;
        let terminate = command(conv, COMMAND_TERMINATE).encode();
        stranger.send_to(&terminate, source).await.unwrap();
        peer.send_to(
            &command(conv.wrapping_add(1), COMMAND_TERMINATE).encode(),
            source,
        )
        .await
        .unwrap();
        let mut truncated = terminate.clone();
        truncated.push(0);
        peer.send_to(&truncated, source).await.unwrap();
        peer.send_to(&command(conv, 254).encode(), source)
            .await
            .unwrap();
        let mut buffer = [0];
        assert!(
            timeout(Duration::from_millis(100), stream.read(&mut buffer))
                .await
                .is_err()
        );
        peer.send_to(&data(conv, b"valid").encode(), source)
            .await
            .unwrap();
        let mut received = [0; 5];
        timeout(WAIT, stream.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"valid");
        stream.shutdown().await.unwrap();
        wait_tasks(&tasks).await;
    }
}
