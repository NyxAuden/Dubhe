//! 精确 h2/prost 候选 API 背压、半关闭、取消与 protobuf 语义原型。
//!
//! 只验证候选库的可执行行为；不代表 gRPC 入口、官方客户端或完整资源模型通过。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};
use tokio::sync::{Notify, oneshot};

#[derive(Clone, PartialEq, Message)]
struct Hunk {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct MultiHunk {
    #[prost(bytes = "vec", repeated, tag = "1")]
    data: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct Node {
    #[prost(message, optional, boxed, tag = "1")]
    child: Option<Box<Node>>,
}

fn request(path: &str) -> http::Request<()> {
    http::Request::builder()
        .method("POST")
        .uri(format!("https://example{path}"))
        .header("content-type", "application/grpc")
        .body(())
        .unwrap()
}

/// h2 连接必须持续被poll：读取流数据时与 `poll_closed` 一起轮询。
macro_rules! recv_with_driver {
    ($closed:ident, $body:expr) => {
        tokio::select! {
            data = $body.data() => data,
            closed = &mut $closed => panic!("连接在RPC活动时结束: {:?}", closed.is_err()),
        }
    };
}

#[tokio::test]
async fn response_trailers_do_not_close_request_receive_direction() {
    let (client_io, server_io) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .max_concurrent_streams(2)
            .handshake(server_io)
            .await
            .unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut closed = std::pin::pin!(std::future::poll_fn(|cx| connection.poll_closed(cx)));
        let mut body = request.into_body();
        let first = recv_with_driver!(closed, body).unwrap().unwrap();
        assert_eq!(&first[..], b"first");

        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(prost::bytes::Bytes::from_static(b"reply"), false)
            .unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        send.send_trailers(trailers).unwrap();

        // 响应方向已END_STREAM；请求方向仍活动，必须能继续读取。
        let second = recv_with_driver!(closed, body).unwrap().unwrap();
        assert_eq!(&second[..], b"second");
        assert!(recv_with_driver!(closed, body).is_none());
    });

    let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, mut stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    stream
        .send_data(prost::bytes::Bytes::from_static(b"first"), false)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let reply = body.data().await.unwrap().unwrap();
    assert_eq!(&reply[..], b"reply");
    let trailers = body.trailers().await.unwrap().unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    // 响应方向已结束仍可发送剩余请求数据。
    stream
        .send_data(prost::bytes::Bytes::from_static(b"second"), true)
        .unwrap();
    drop(stream);
    drop(send_request);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn dropping_response_handles_with_open_request_resets_the_stream() {
    let (client_io, server_io) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, respond) = connection.accept().await.unwrap().unwrap();
        drop(respond);
        drop(request);
    });

    let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, mut stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    stream
        .send_data(prost::bytes::Bytes::from_static(b"payload"), false)
        .unwrap();
    // 请求仍活动而服务端丢弃全部句柄：必须显式失败，不能冒充成功EOF。
    assert!(response.await.is_err());
    let _ = stream.send_data(prost::bytes::Bytes::new(), true);
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[tokio::test]
async fn graceful_shutdown_keeps_accepted_rpc_and_fails_new_ones() {
    let (client_io, server_io) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        {
            let mut closed = std::pin::pin!(std::future::poll_fn(|cx| connection.poll_closed(cx)));
            let mut body = request.into_body();
            // 首RPC请求方向已END_STREAM，必须驱动连接读到真实EOF再响应。
            assert!(recv_with_driver!(closed, body).is_none());
        }
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        send.send_trailers(trailers).unwrap();
        connection.graceful_shutdown();
        // 排空期间持续poll；超时后直接关闭，使新流得到真实失败。
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(result) = connection.accept().await {
                if let Ok((request, respond)) = result {
                    drop(respond);
                    drop(request);
                }
            }
        })
        .await;
    });

    let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, stream) = send_request
        .send_request(request("/GunService/Tun"), true)
        .unwrap();
    drop(stream);
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert!(body.data().await.is_none());
    assert_eq!(
        body.trailers()
            .await
            .unwrap()
            .unwrap()
            .get("grpc-status")
            .unwrap(),
        "0"
    );

    // 首RPC完成后才发起的新请求，在GOAWAY排空期间不得得到成功响应。
    let result = send_request.send_request(request("/GunService/Tun"), true);
    if let Ok((response, stream)) = result {
        drop(stream);
        assert!(response.await.is_err());
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[tokio::test]
async fn server_handshake_ready_does_not_wait_for_client_settings() {
    let (mut raw_client, server_io) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), connection.accept())
                .await
                .is_err()
        );
    });
    // HTTP/2 client preface；故意不发送SETTINGS，验证Ready只到preface边界。
    raw_client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    raw_client.flush().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// 记录本端真正写入下层IO的字节，用于观察SETTINGS ACK是否完整输出。
struct SpyIo<IO> {
    inner: IO,
    written: Arc<StdMutex<Vec<u8>>>,
}

impl<IO: AsyncRead + Unpin> AsyncRead for SpyIo<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for SpyIo<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = std::task::ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.written
            .lock()
            .unwrap()
            .extend_from_slice(&buf[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn has_settings_ack(written: &[u8]) -> bool {
    const ACK: [u8; 9] = [0, 0, 0, 4, 1, 0, 0, 0, 0];
    written.windows(ACK.len()).any(|window| window == ACK)
}

/// 可暂停写入的IO：模拟下层socket暂时不可写，观察库并发名额的释放时机。
#[derive(Clone)]
struct Gate {
    paused: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Gate {
    fn new() -> Self {
        Self {
            paused: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

struct GatedIo<IO> {
    inner: IO,
    gate: Gate,
    wait: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl<IO: AsyncRead + Unpin> AsyncRead for GatedIo<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for GatedIo<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            if !this.gate.paused.load(Ordering::SeqCst) {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            if this.wait.is_none() {
                let notified = this.gate.notify.clone().notified_owned();
                this.wait = Some(Box::pin(notified));
            }
            match this.wait.as_mut().unwrap().as_mut().poll(cx) {
                Poll::Ready(()) => this.wait = None,
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn send_capacity_and_release_capacity_track_flow_control() {
    let (client_io, server_io) = duplex(64 * 1024);
    let (n_tx, n_rx) = oneshot::channel::<usize>();
    let (go_tx, go_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        {
            let mut closed = std::pin::pin!(std::future::poll_fn(|cx| connection.poll_closed(cx)));
            let mut body = request.into_body();
            assert!(recv_with_driver!(closed, body).is_none());
        }
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        let mut closed = std::pin::pin!(std::future::poll_fn(|cx| connection.poll_closed(cx)));

        send.reserve_capacity(65535);
        let capacity = tokio::select! {
            cap = std::future::poll_fn(|cx| send.poll_capacity(cx)) => cap,
            closed = &mut closed => panic!("连接提前结束: {:?}", closed.is_err()),
        }
        .expect("窗口关闭")
        .expect("容量错误");
        assert!(capacity > 0);
        n_tx.send(capacity).unwrap();
        // 一次写恰好耗尽当前窗口，对应适配器单次有界写模型。
        send.reserve_capacity(capacity);
        send.send_data(prost::bytes::Bytes::from(vec![0u8; capacity]), false)
            .unwrap();

        // 窗口耗尽后不能无条件堆积：必须等对端真实归还。
        send.reserve_capacity(1);
        let pending = tokio::time::timeout(Duration::from_millis(100), async {
            tokio::select! {
                cap = std::future::poll_fn(|cx| send.poll_capacity(cx)) => cap,
                closed = &mut closed => panic!("连接提前结束: {:?}", closed.is_err()),
            }
        })
        .await;
        assert!(pending.is_err(), "窗口耗尽却仍报告可写容量: {pending:?}");
        go_tx.send(()).unwrap();

        let restored = tokio::select! {
            cap = std::future::poll_fn(|cx| send.poll_capacity(cx)) => cap,
            closed = &mut closed => panic!("连接提前结束: {:?}", closed.is_err()),
        }
        .expect("窗口关闭")
        .expect("容量错误");
        assert!(restored > 0, "对端release后容量未恢复");

        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        send.send_trailers(trailers).unwrap();
        tokio::select! {
            _ = done_rx => {}
            closed = &mut closed => panic!("连接提前结束: {:?}", closed.is_err()),
        }
    });

    let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, stream) = send_request
        .send_request(request("/GunService/Tun"), true)
        .unwrap();
    drop(stream);
    let n = n_rx.await.unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut received = 0usize;
    while received < n {
        let chunk = body.data().await.unwrap().unwrap();
        received += chunk.len();
    }
    assert_eq!(received, n);
    // 未release前对端窗口必须保持耗尽。
    go_rx.await.unwrap();
    body.flow_control().release_capacity(n).unwrap();
    let trailers = body.trailers().await.unwrap().unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    done_tx.send(()).unwrap();
    drop(body);
    drop(send_request);
    let _ = tokio::time::timeout(Duration::from_secs(2), driver).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn real_tcp_flow_control_round_trip_restores_capacity() {
    const TOTAL: usize = 1024 * 1024;
    const WRITE: usize = 16 * 1024;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        {
            let mut closed = std::pin::pin!(std::future::poll_fn(|cx| connection.poll_closed(cx)));
            let mut body = request.into_body();
            assert!(recv_with_driver!(closed, body).is_none());
        }
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        let mut closed = std::pin::pin!(std::future::poll_fn(|cx| connection.poll_closed(cx)));
        let mut sent = 0usize;
        while sent < TOTAL {
            send.reserve_capacity(WRITE);
            let capacity = tokio::select! {
                cap = std::future::poll_fn(|cx| send.poll_capacity(cx)) => cap,
                closed = &mut closed => panic!("连接提前结束: {:?}", closed.is_err()),
            }
            .expect("窗口关闭")
            .expect("容量错误");
            let n = capacity.min(WRITE).min(TOTAL - sent);
            send.send_data(prost::bytes::Bytes::from(vec![0u8; n]), false)
                .unwrap();
            sent += n;
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        send.send_trailers(trailers).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while connection.accept().await.is_some() {}
        })
        .await;
    });

    let io = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut send_request, connection) = h2::client::handshake(io).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, stream) = send_request
        .send_request(request("/GunService/Tun"), true)
        .unwrap();
    drop(stream);
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    let mut body = response.into_body();
    let mut received = 0usize;
    while received < TOTAL {
        let chunk = body.data().await.unwrap().unwrap();
        body.flow_control().release_capacity(chunk.len()).unwrap();
        received += chunk.len();
    }
    assert_eq!(received, TOTAL);
    let trailers = body.trailers().await.unwrap().unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    drop(body);
    drop(send_request);
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
}

#[tokio::test]
async fn server_settings_ack_is_observable_on_io() {
    let (mut raw_client, server_io) = duplex(64 * 1024);
    let written = Arc::new(StdMutex::new(Vec::new()));
    let spy = SpyIo {
        inner: server_io,
        written: written.clone(),
    };
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let server_written = written.clone();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(spy).await.unwrap();
        // HANDshake Ready只到preface：此时本端SETTINGS已写出，但客户端SETTINGS尚未处理。
        assert!(!has_settings_ack(&server_written.lock().unwrap()));
        ready_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), connection.accept())
                .await
                .is_err()
        );
        // 客户端SETTINGS被处理且本端ACK完整交给下层IO后才可观察。
        assert!(has_settings_ack(&server_written.lock().unwrap()));
    });

    raw_client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    raw_client.flush().await.unwrap();
    ready_rx.await.unwrap();
    // 空SETTINGS帧：长度0、类型4、flags0、stream0。
    raw_client
        .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    raw_client.flush().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn peer_cannot_start_next_rpc_until_response_end_stream_arrives() {
    let (client_io, server_io) = duplex(64 * 1024);
    let gate = Gate::new();
    let server_gate = gate.clone();
    let (checked_tx, checked_rx) = oneshot::channel::<()>();
    let (resume_tx, resume_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let io = GatedIo {
            inner: server_io,
            gate: server_gate.clone(),
            wait: None,
        };
        let mut connection: h2::server::Connection<_, prost::bytes::Bytes> =
            h2::server::Builder::new()
                .max_concurrent_streams(1)
                .handshake(io)
                .await
                .unwrap();
        let response = || {
            http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap()
        };

        // 首个请求正常往返，确保客户端已处理服务端max_concurrent_streams=1。
        let (request_a, mut respond_a) = connection.accept().await.unwrap().unwrap();
        {
            let mut closed = std::pin::pin!(std::future::poll_fn(|cx| connection.poll_closed(cx)));
            let mut body = request_a.into_body();
            assert!(recv_with_driver!(closed, body).is_none());
        }
        respond_a.send_response(response(), true).unwrap();

        let (request_b, mut respond_b) = connection.accept().await.unwrap().unwrap();
        {
            let mut closed = std::pin::pin!(std::future::poll_fn(|cx| connection.poll_closed(cx)));
            let mut body = request_b.into_body();
            assert!(recv_with_driver!(closed, body).is_none());
        }
        // 响应END_STREAM只入队；下层写入被暂停，库不得提前释放并发名额。
        server_gate.pause();
        respond_b.send_response(response(), true).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), connection.accept())
                .await
                .is_err(),
            "END_STREAM未写下层时不得接受下一RPC"
        );
        checked_tx.send(()).unwrap();
        resume_rx.await.unwrap();
        server_gate.resume();

        let (request_c, mut respond_c) =
            tokio::time::timeout(Duration::from_secs(2), connection.accept())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        drop(request_c);
        respond_c.send_response(response(), true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while connection.accept().await.is_some() {}
        })
        .await;
    });

    let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response_a, stream_a) = send_request
        .send_request(request("/GunService/Tun"), true)
        .unwrap();
    drop(stream_a);
    let response_a = tokio::time::timeout(Duration::from_secs(2), response_a)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response_a.status(), 200);

    let (response_b, stream_b) = send_request
        .send_request(request("/GunService/Tun"), true)
        .unwrap();
    drop(stream_b);
    // 并发上限为1时：首流响应END_STREAM未真正到达前，库拒绝再排队一个请求。
    assert!(
        send_request
            .send_request(request("/GunService/Tun"), true)
            .is_err()
    );
    checked_rx.await.unwrap();
    resume_tx.send(()).unwrap();
    let response_b = tokio::time::timeout(Duration::from_secs(2), response_b)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response_b.status(), 200);
    // 首流响应写出并被对端接收后，才可发起下一RPC。
    let (response_c, stream_c) = send_request
        .send_request(request("/GunService/Tun"), true)
        .unwrap();
    drop(stream_c);
    let response_c = tokio::time::timeout(Duration::from_secs(2), response_c)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response_c.status(), 200);
    drop(send_request);
    let _ = tokio::time::timeout(Duration::from_secs(2), driver).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[test]
fn prost_duplicate_singular_and_repeated_bytes_follow_wire_semantics() {
    let first = Hunk {
        data: b"old".to_vec(),
    }
    .encode_to_vec();
    let second = Hunk {
        data: b"new".to_vec(),
    }
    .encode_to_vec();
    let mut wire = first.clone();
    wire.extend_from_slice(&second);
    let merged = Hunk::decode(&wire[..]).unwrap();
    assert_eq!(merged.data, b"new");

    let multi = MultiHunk {
        data: vec![b"a".to_vec(), b"".to_vec(), b"b".to_vec()],
    };
    let encoded = multi.encode_to_vec();
    assert_eq!(MultiHunk::decode(&encoded[..]).unwrap(), multi);

    let empty = MultiHunk::default().encode_to_vec();
    assert!(empty.is_empty());
    assert_eq!(MultiHunk::decode(&empty[..]).unwrap(), MultiHunk::default());
}

#[test]
fn prost_top_level_scan_and_recursion_limit_are_available() {
    use prost::bytes::Buf;
    use prost::encoding::{DecodeContext, decode_key, skip_field};

    let mut wire = Hunk {
        data: b"x".to_vec(),
    }
    .encode_to_vec();
    wire.extend_from_slice(
        &Hunk {
            data: b"y".to_vec(),
        }
        .encode_to_vec(),
    );
    let mut cursor = &wire[..];
    let mut fields = 0;
    while cursor.has_remaining() {
        let (tag, wire_type) = decode_key(&mut cursor).unwrap();
        assert_eq!(tag, 1);
        skip_field(wire_type, tag, &mut cursor, DecodeContext::default()).unwrap();
        fields += 1;
    }
    assert_eq!(fields, 2);

    // 默认递归预算100：101层嵌套必须有限失败，而不是栈溢出。
    let mut node = Node { child: None };
    for _ in 0..101 {
        node = Node {
            child: Some(Box::new(node)),
        };
    }
    assert!(Node::decode(&node.encode_to_vec()[..]).is_err());
}
