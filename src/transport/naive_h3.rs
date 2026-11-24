//! Naive HTTP/3 普通 CONNECT：复用固定依赖的 QUIC/TLS/H3，不使用
//! 扩展CONNECT。padding按固定forwardproxy行为，仅在请求声明后开启。
use super::{
    naive_padding::{self, PaddedStream},
    xhttp::{H3Reader, Tunnel},
};
use crate::{
    config::{Inbound, User},
    forward::Context,
    protocol::http as proxy_http,
    telemetry::Gauge,
};
use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::timeout,
};
use tokio_util::{
    sync::{CancellationToken, PollSender},
    task::TaskTracker,
};

type Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type SendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
fn error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    socket: UdpSocket,
    tls: Arc<rustls::ServerConfig>,
    config: Arc<Inbound>,
    ctx: Arc<Context>,
    slots: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let Inbound::Naive { tag, users, .. } = &*config else {
        return Err(io::Error::other("入口不是Naive"));
    };
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(error)?;
    let mut quic = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(
        ctx.limits.max_grpc_streams_per_connection as u32,
    ));
    transport.max_concurrent_uni_streams(3u32.into());
    transport.stream_receive_window((64u32 * 1024).into());
    transport.receive_window((1024u32 * 1024).into());
    transport.send_window(1024 * 1024);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_millis(ctx.limits.udp_idle_timeout_ms))
            .map_err(error)?,
    ));
    quic.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quic),
        socket.into_std()?,
        Arc::new(quinn::TokioRuntime),
    )?;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            _=force.cancelled()=>break,
            Some(_)=connections.join_next(),if !connections.is_empty()=>{}
            incoming=endpoint.accept()=>{
                let Some(incoming)=incoming else {break};
                let Ok(slot)=slots.clone().try_acquire_owned() else {ctx.stats.reject();incoming.refuse();continue};
                let Ok(handshake)=handshakes.clone().try_acquire_owned() else {ctx.stats.reject();incoming.refuse();continue};
                let (ctx,tag,users,streams)=(ctx.clone(),tag.clone(),users.clone(),streams.clone());
                let (stop,force)=(stop.clone(),force.clone());
                let children=ctx.children.clone();
                connections.spawn(children.track_future(async move {
                    let _slot=slot;let _gauge=ctx.stats.enter(Gauge::Connection);
                    let wait=Duration::from_millis(ctx.limits.handshake_timeout_ms);
                    let Ok(Ok(connection))=timeout(wait,incoming).await else {return};
                    if let Err(error)=serve_connection(connection,&tag,&users,ctx,crate::runtime::HandshakePermits::new(handshake, None),streams,stop,force).await {
                        tracing::debug!(?error,"Naive H3连接结束");
                    }
                }));
            }
        }
    }
    endpoint.close(0u32.into(), b"shutdown");
    if timeout(
        Duration::from_millis(ctx.limits.shutdown_timeout_ms),
        async { while connections.join_next().await.is_some() {} },
    )
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    let _ = timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    connection: quinn::Connection,
    tag: &str,
    users: &[User],
    ctx: Arc<Context>,
    handshake: crate::runtime::HandshakePermits,
    slots: Arc<Semaphore>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    struct Close(quinn::Connection);
    impl Drop for Close {
        fn drop(&mut self) {
            self.0.close(0u32.into(), b"closed");
        }
    }
    let _close = Close(connection.clone());
    let mut builder = h3::server::builder();
    builder.max_field_section_size(8192);
    let mut h3 = timeout(
        Duration::from_millis(ctx.limits.handshake_timeout_ms),
        builder.build::<_, Bytes>(h3_quinn::Connection::new(connection)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Naive H3初始化超时"))?
    .map_err(error)?;
    drop(handshake);
    let mut tasks = JoinSet::new();
    let writers = TaskTracker::new();
    let local = Arc::new(Semaphore::new(ctx.limits.max_grpc_streams_per_connection));
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            _=force.cancelled()=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{}
            request=h3.accept()=>{
                let resolver=match request {Ok(Some(resolver))=>resolver,Ok(None)=>break,Err(err)=>{failure=Some(error(err));break}};
                let Ok(local_slot)=local.clone().try_acquire_owned() else {
                    ctx.stats.reject();
                    _close.0.close(quinn::VarInt::from_u32(0x107),b"request limit"); // H3_EXCESSIVE_LOAD
                    break;
                };
                let slots=slots.clone();
                let (tag,users,ctx)=(tag.to_owned(),users.to_vec(),ctx.clone());
                let writers=writers.clone();let force=force.clone();let children=ctx.children.clone();
                tasks.spawn(children.track_future(async move{
                    let _local=local_slot;
                    // 头部读取属于独立的有界流任务，不能阻塞 H3 控制流和其他请求。
                    let (request,mut stream)=match timeout(Duration::from_millis(ctx.limits.handshake_timeout_ms),resolver.resolve_request()).await {
                        Ok(Ok(value))=>value,
                        _=>{ctx.stats.reject();return;}
                    };
                    let Ok(_slot)=slots.try_acquire_owned() else {
                        ctx.stats.reject();
                        stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                        stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                        return;
                    };
                    let wait=Duration::from_millis(ctx.limits.dial_timeout_ms);
                    if let Err(error)=handle(request,stream,&tag,&users,ctx,writers,force,wait).await {
                        tracing::debug!(?error,"Naive H3流结束");
                    }
                }));
            }
        }
    }
    if timeout(
        Duration::from_millis(ctx.limits.shutdown_timeout_ms),
        async { while tasks.join_next().await.is_some() {} },
    )
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    writers.close();
    let _ = timeout(
        Duration::from_millis(ctx.limits.shutdown_timeout_ms),
        writers.wait(),
    )
    .await;
    if let Some(error) = failure {
        Err(error)
    } else {
        Ok(())
    }
}

async fn reject(
    stream: &mut Stream,
    status: StatusCode,
    ctx: &crate::forward::Context,
) -> io::Result<()> {
    let mut response = Response::builder().status(status);
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        // 认证失败计入 rejected：运维需要区分「无人连接」与
        // 「有人在反复猜密码」。与 H1/H2 及 Hysteria2/TUIC 的修复一致。
        ctx.stats.reject();
        response = response.header("proxy-authenticate", "Basic realm=\"proxy\"");
    }
    stream
        .send_response(response.body(()).expect("合法响应"))
        .await
        .map_err(error)?;
    stream.finish().await.map_err(error)
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    request: http::Request<()>,
    mut stream: Stream,
    tag: &str,
    users: &[User],
    ctx: Arc<Context>,
    writers: TaskTracker,
    force: CancellationToken,
    wait: Duration,
) -> io::Result<()> {
    // Naive使用普通CONNECT：只有 :authority，不接受扩展 :protocol、scheme/path。
    if request.method() != http::Method::CONNECT
        || request.extensions().get::<h3::ext::Protocol>().is_some()
        || request.uri().scheme().is_some()
        || !request.uri().path().is_empty()
    {
        return reject(&mut stream, StatusCode::BAD_REQUEST, &ctx).await;
    }
    let target = match request
        .uri()
        .authority()
        .and_then(|authority| super::naive::authority_target(authority.as_str()).ok())
    {
        Some(target) => target,
        None => return reject(&mut stream, StatusCode::BAD_REQUEST, &ctx).await,
    };
    let mut auth = request.headers().get_all("proxy-authorization").iter();
    let authorization = auth.next().and_then(|value| value.to_str().ok());
    if auth.next().is_some() {
        return reject(&mut stream, StatusCode::PROXY_AUTHENTICATION_REQUIRED, &ctx).await;
    }
    let user = match proxy_http::authenticate_header(authorization, users) {
        Ok(user) => user,
        Err(_) => {
            return reject(&mut stream, StatusCode::PROXY_AUTHENTICATION_REQUIRED, &ctx).await;
        }
    };
    let padding = request
        .headers()
        .get("padding")
        .is_some_and(|value| !value.is_empty());
    let uot = (target.port == 0)
        .then(|| crate::udp::uot_version(&target))
        .flatten();
    let upstream = if uot.is_some() {
        None
    } else {
        match ctx.connect(tag, &target).await {
            Ok(target) => Some(target),
            Err(_) => return reject(&mut stream, StatusCode::BAD_GATEWAY, &ctx).await,
        }
    };
    let mut response = Response::builder().status(StatusCode::OK);
    if padding {
        response = response.header(
            "padding",
            HeaderValue::from_bytes(&naive_padding::header_value()?).map_err(error)?,
        );
    }
    stream
        .send_response(response.body(()).expect("合法响应"))
        .await
        .map_err(error)?;
    let (send, recv) = stream.split();
    let (tx, rx) = mpsc::channel(8);
    let writer = writers.spawn(ctx.children.track_future(pump(send, rx, force, wait)));
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _abort = AbortOnDrop(writer.abort_handle());
    let tunnel = Tunnel::new(H3Reader::new(recv), H3Writer::new(tx));
    let tunnel = PaddedStream::new(tunnel, padding);
    let result = if let Some(version) = uot {
        crate::udp::uot(
            tunnel,
            ctx.clone(),
            tag.to_owned(),
            version,
            user.as_deref(),
        )
        .await
    } else {
        let tunnel = ctx.stats.admit_counter(tag, user.as_deref(), tunnel)?;
        crate::forward::relay(tunnel, upstream.expect("非UoT已建目标"), ctx.stats.clone()).await
    };
    let sent = writer.await.map_err(error)?;
    result?;
    sent
}

enum Write {
    Data(Bytes),
    Flush(oneshot::Sender<io::Result<()>>),
    Finish(oneshot::Sender<io::Result<()>>),
}
async fn pump(
    mut stream: SendStream,
    mut rx: mpsc::Receiver<Write>,
    force: CancellationToken,
    wait: Duration,
) -> io::Result<()> {
    while let Some(item) = rx.recv().await {
        let finishing = matches!(&item, Write::Finish(_));
        let write = async {
            match item {
                Write::Data(data) => stream.send_data(data).await.map_err(error),
                Write::Flush(done) => {
                    let _ = done.send(Ok(()));
                    Ok(())
                }
                Write::Finish(done) => {
                    let result = stream.finish().await.map_err(error);
                    let _ = done.send(
                        result
                            .as_ref()
                            .map(|_| ())
                            .map_err(|error| io::Error::new(error.kind(), error.to_string())),
                    );
                    result
                }
            }
        };
        tokio::select! {
            biased;
            _=force.cancelled()=>return Ok(()),
            result=timeout(wait,write)=>result.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"Naive H3写超时"))??,
        }
        if finishing {
            return Ok(());
        }
    }
    tokio::select! {
        biased;
        _=force.cancelled()=>Ok(()),
        result=timeout(wait,stream.finish())=>result.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"Naive H3 FIN超时"))?.map_err(error),
    }
}

struct H3Writer {
    tx: PollSender<Write>,
    pending: Option<oneshot::Receiver<io::Result<()>>>,
    finishing: bool,
    closed: bool,
}
impl H3Writer {
    fn new(tx: mpsc::Sender<Write>) -> Self {
        Self {
            tx: PollSender::new(tx),
            pending: None,
            finishing: false,
            closed: false,
        }
    }
    fn barrier(&mut self, cx: &mut TaskContext<'_>, finish: bool) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_none() {
            std::task::ready!(self.tx.poll_reserve(cx))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Naive H3写任务结束"))?;
            let (tx, rx) = oneshot::channel();
            self.tx
                .send_item(if finish {
                    Write::Finish(tx)
                } else {
                    Write::Flush(tx)
                })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Naive H3写任务结束"))?;
            self.finishing = finish;
            self.pending = Some(rx);
        }
        let pending = self.pending.as_mut().expect("已设置确认");
        let result = std::task::ready!(Pin::new(pending).poll(cx));
        self.pending = None;
        result.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Naive H3写任务未确认"))??;
        if self.finishing {
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl tokio::io::AsyncWrite for H3Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Naive H3已关闭",
            )));
        }
        if self.pending.is_some() {
            std::task::ready!(self.barrier(cx, false))?;
        }
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Naive H3已关闭",
            )));
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.tx.poll_reserve(cx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Naive H3写任务结束"))?;
        let count = buffer.len().min(16 * 1024);
        self.tx
            .send_item(Write::Data(Bytes::copy_from_slice(&buffer[..count])))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Naive H3写任务结束"))?;
        Poll::Ready(Ok(count))
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
mod tests {
    use super::*;
    use tokio::io::AsyncWrite;

    #[test]
    fn writer_bounds_queue_and_preserves_cancelled_flush_and_fin() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut writer = H3Writer::new(tx);
        let mut cx = TaskContext::from_waker(std::task::Waker::noop());
        let data = vec![7; 32 * 1024];
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &data),
            Poll::Ready(Ok(16384))
        ));
        assert!(
            Pin::new(&mut writer)
                .poll_write(&mut cx, b"not-accepted")
                .is_pending()
        );
        let Write::Data(accepted) = rx.try_recv().unwrap() else {
            panic!("应为数据")
        };
        assert_eq!(accepted.len(), 16384);
        assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
        let Write::Flush(done) = rx.try_recv().unwrap() else {
            panic!("应为flush")
        };
        // 取消flush后下一次不同write仍先等待同一个完成确认，不重复排队。
        assert!(
            Pin::new(&mut writer)
                .poll_write(&mut cx, b"next")
                .is_pending()
        );
        assert!(rx.try_recv().is_err());
        done.send(Ok(())).unwrap();
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"next"),
            Poll::Ready(Ok(4))
        ));
        let Write::Data(next) = rx.try_recv().unwrap() else {
            panic!("应为新数据")
        };
        assert_eq!(&next[..], b"next");
        assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());
        let Write::Finish(done) = rx.try_recv().unwrap() else {
            panic!("应为FIN")
        };
        assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());
        assert!(rx.try_recv().is_err());
        done.send(Ok(())).unwrap();
        assert!(matches!(
            Pin::new(&mut writer).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, b"late"),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn writer_reports_pump_errors_and_missing_confirmation() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut writer = H3Writer::new(tx);
        let mut cx = TaskContext::from_waker(std::task::Waker::noop());
        assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
        let Write::Flush(done) = rx.try_recv().unwrap() else {
            panic!("应为flush")
        };
        done.send(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "测试写任务失败",
        )))
        .unwrap();
        let Poll::Ready(Err(error)) = Pin::new(&mut writer).poll_flush(&mut cx) else {
            panic!("必须返回发送错误")
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());
        drop(rx.try_recv().unwrap());
        let Poll::Ready(Err(error)) = Pin::new(&mut writer).poll_shutdown(&mut cx) else {
            panic!("必须返回确认丢失")
        };
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}
