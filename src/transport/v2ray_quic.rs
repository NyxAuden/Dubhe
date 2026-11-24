//! V2Ray QUIC 传输服务端（sing-box `v2ray-quic` 语义）。
//!
//! QUIC 连接本身由 TLS 1.3 保护，ALPN 固定 `h3`；客户端每开一条双向流
//! 就承载一条 VLESS/VMess/Trojan 连接，没有额外的 Xray `quicSettings`
//! 加密或混淆层。

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use quinn::{RecvStream, SendStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Inbound, V2rayQuic},
    forward::Context,
    protocol::vmess,
    transport::v2ray_tunnel::dispatch,
};

pub(crate) async fn serve(
    socket: UdpSocket,
    tls: Arc<rustls::ServerConfig>,
    config: Arc<Inbound>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let quic = quic_config(&config)?.clone();
    let server = server_config(tls, &quic)?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| io::Error::other("V2Ray QUIC 需要异步运行时"))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server),
        socket.into_std()?,
        runtime,
    )
    .map_err(|_| io::Error::other("V2Ray QUIC 端点创建失败"))?;
    let connections = Arc::new(Semaphore::new(ctx.limits.max_connections.max(1)));
    let handshakes = Arc::new(Semaphore::new(ctx.limits.max_handshakes.max(1)));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let Ok(connection_permit) = connections.clone().try_acquire_owned() else { continue };
                let Ok(handshake_permit) = handshakes.clone().try_acquire_owned() else { continue };
                let config = config.clone();
                let vmess = vmess.clone();
                let ctx = ctx.clone();
                let stop = stop.clone();
                let force = force.clone();
                // 连接任务也可能在停机关闭后被暂停在「登记流」之前；登记父任务
                // 才能保证 `children.wait()` 不会先于它结束。
                let tracker = ctx.children.clone();
                tasks.spawn(tracker.track_future(async move {
                    let _connection_permit = connection_permit;
                    let _handshake_permit = handshake_permit;
                    let wait = Duration::from_millis(ctx.limits.handshake_timeout_ms);
                    let Ok(Ok(connection)) = timeout(wait, incoming).await else { return };
                    let _ = serve_connection(connection, config, vmess, ctx, stop, force).await;
                }));
            }
            Some(_) = tasks.join_next() => {}
        }
    }
    let shutdown = Duration::from_millis(ctx.limits.shutdown_timeout_ms);
    let _ = timeout(shutdown, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    let _ = timeout(Duration::from_secs(3), endpoint.wait_idle()).await;
    Ok(())
}

async fn serve_connection(
    connection: quinn::Connection,
    config: Arc<Inbound>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = force.cancelled() => break,
            _ = stop.cancelled() => break,
            accepted = connection.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(streams) => streams,
                    Err(_) => break,
                };
                let deadline = Instant::now()
                    + Duration::from_millis(ctx.limits.handshake_timeout_ms);
                let config = config.clone();
                let vmess = vmess.clone();
                let ctx = ctx.clone();
                let tracker = ctx.children.clone();
                streams.spawn(tracker.track_future(async move {
                    let stream = QuicStream { send, recv };
                    let _ = dispatch(stream, config, vmess, true, ctx, deadline, None).await;
                }));
            }
            Some(_) = streams.join_next() => {}
        }
    }
    let shutdown = Duration::from_millis(ctx.limits.shutdown_timeout_ms);
    let _ = timeout_at(Instant::now() + shutdown, async {
        while streams.join_next().await.is_some() {}
    })
    .await;
    // 上面的宽限 drain 可能超时；abort 之后仍需等到任务真正被 drop，
    // 否则它们持有的 `Gauge::Tcp` 会晚于连接任务结束。
    streams.abort_all();
    let _ = timeout_at(Instant::now() + shutdown, async {
        while streams.join_next().await.is_some() {}
    })
    .await;
    connection.close(quinn::VarInt::from_u32(0), b"");
    Ok(())
}

fn quic_config(inbound: &Inbound) -> io::Result<&V2rayQuic> {
    match inbound {
        Inbound::VlessQuic { quic, .. }
        | Inbound::VmessQuic { quic, .. }
        | Inbound::TrojanQuic { quic, .. } => Ok(quic),
        _ => Err(io::Error::other("入口不是 V2Ray QUIC 传输")),
    }
}

fn server_config(
    tls: Arc<rustls::ServerConfig>,
    quic: &V2rayQuic,
) -> io::Result<quinn::ServerConfig> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // QUIC 不使用 0-RTT。
    tls.max_early_data_size = 0;
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "V2Ray QUIC TLS 配置不支持 QUIC",
            )
        })?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(quic.max_bidi_streams));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    let idle = quinn::IdleTimeout::try_from(Duration::from_millis(quic.idle_timeout_ms))
        .map_err(|_| io::Error::other("V2Ray QUIC 空闲超时超出范围"))?;
    transport.max_idle_timeout(Some(idle));
    if quic.keep_alive_ms > 0 {
        transport.keep_alive_interval(Some(Duration::from_millis(quic.keep_alive_ms)));
    }
    server.transport_config(Arc::new(transport));
    Ok(server)
}

/// quinn 的分离读写流组合成 `AsyncRead + AsyncWrite`。
struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(context)
    }
}
