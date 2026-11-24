//! mKCP 传输：UDP 上的 KCP 可靠流，之上可再承载 TLS 与 VLESS/VMess/Trojan。
//!
//! 一个 UDP 监听端口按 `(源地址, conv)` 复用会话，与 Xray `kcp.Listener` 一致；
//! 首个非 Terminate 分段创建会话，Terminate 只作用于已存在会话。

pub(crate) mod conn;
pub(crate) mod mask;
pub(crate) mod segment;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use tokio::{
    net::UdpSocket,
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Inbound, Kcp},
    forward::{self, Context},
    protocol::{trojan, vless, vmess},
    session::Command,
    telemetry::Gauge,
    transport::kcp::{
        conn::{Driver, KcpStream, start},
        mask::Mask,
        segment::{COMMAND_TERMINATE, Segment, parse},
    },
};

/// 单个 UDP 载荷允许的最大长度；超出部分由发送端分段。
const UDP_BUFFER: usize = 65_536;

pub(crate) struct Prepared {
    /// 包含混淆头、认证层与 KCP 分段的最大 UDP 载荷。
    pub mtu: usize,
    pub mss: usize,
    pub tti_ms: u32,
    pub sending_in_flight: u32,
    pub receiving_in_flight: u32,
    pub sending_buffer: u32,
    pub cwnd_multiplier: u32,
    pub mask: Arc<Mutex<Mask>>,
}

pub(crate) fn prepare(config: &Kcp) -> Result<Arc<Prepared>> {
    config.validate(0)?;
    Ok(Arc::new(Prepared {
        mtu: config.mtu as usize,
        mss: config.mss(),
        tti_ms: config.tti,
        sending_in_flight: config.sending_in_flight(),
        receiving_in_flight: config.receiving_in_flight(),
        sending_buffer: config.sending_buffer_segments(),
        cwnd_multiplier: config.cwnd_multiplier,
        mask: Arc::new(Mutex::new(Mask::new(config)?)),
    }))
}

/// 会话表：按 (来源地址, conversation) 索引上行发送端。
type SessionTable = Arc<Mutex<HashMap<(SocketAddr, u16), mpsc::Sender<Vec<Segment>>>>>;

/// 监听 UDP 端口并分派会话；`socket` 已由运行时绑定。
// 入站入口的固定句柄集合，与其它入口签名保持一致。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    socket: UdpSocket,
    prepared: Arc<Prepared>,
    tls: Option<TlsAcceptor>,
    config: Arc<Inbound>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    stop: CancellationToken,
    force: CancellationToken,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let sessions: SessionTable = Arc::new(Mutex::new(HashMap::new()));
    let handshakes = Arc::new(Semaphore::new(ctx.limits.max_handshakes.max(1)));
    let slots = Arc::new(Semaphore::new(ctx.limits.max_connections.max(1)));
    let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let mut buffer = vec![0u8; UDP_BUFFER];
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            _ = force.cancelled() => break,
            received = socket.recv_from(&mut buffer) => {
                let (length, source) = match received {
                    Ok(value) => value,
                    Err(error) => {
                        // 不能带着还在跑的会话任务直接返回：先取消并等它们
                        // 释放（它们持有连接计数与字节 gauge），再返回原错误。
                        tasks.abort_all();
                        while tasks.join_next().await.is_some() {}
                        return Err(error);
                    }
                };
                let decoded = {
                    let mask = prepared.mask.lock().unwrap_or_else(|error| error.into_inner());
                    mask.decode(&buffer[..length])
                };
                let Some(payload) = decoded else { continue };
                let segments = parse(&payload);
                if segments.is_empty() {
                    continue;
                }
                let conv = segments[0].conv();
                let key = (source, conv);
                {
                    let sessions = sessions.lock().unwrap_or_else(|error| error.into_inner());
                    if let Some(sender) = sessions.get(&key) {
                        let _ = sender.try_send(segments);
                        continue;
                    }
                }
                if segments[0].command() == COMMAND_TERMINATE {
                    continue;
                }
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    ctx.stats.reject();
                    continue;
                };
                let Ok(handshake) = handshakes.clone().try_acquire_owned() else {
                    ctx.stats.reject();
                    continue;
                };
                let (sender, receiver) = mpsc::channel(256);
                {
                    let mut sessions = sessions.lock().unwrap_or_else(|error| error.into_inner());
                    sessions.insert(key, sender.clone());
                }
                let (stream, shared, wake) = start(&prepared);
                let cleanup = sessions.clone();
                let driver = Driver {
                    socket: socket.clone(),
                    dest: source,
                    mask: prepared.mask.clone(),
                    conv,
                    prepared: prepared.clone(),
                    rx: receiver,
                    stop: stop.clone(),
                    on_exit: Some(Box::new(move || {
                        cleanup
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .remove(&key);
                    })),
                };
                tasks.spawn(driver.run(shared, wake));
                let config = config.clone();
                let tls = tls.clone();
                let vmess = vmess.clone();
                let ctx = ctx.clone();
                let force = force.clone();
                tasks.spawn(async move {
                    let _slot = slot;
                    let _gauge = ctx.stats.enter(Gauge::Connection);
                    let result = tokio::select! {
                        biased;
                        _ = force.cancelled() => Ok(()),
                        result = dispatch(stream, config.clone(), tls, vmess, ctx.clone(), crate::runtime::HandshakePermits::new(handshake, None), deadline) => result,
                    };
                    if let Err(error) = result {
                        if !forward::is_route_rejection(&error) {
                            ctx.stats.reject();
                        }
                        tracing::debug!(
                            event = "kcp_session_closed",
                            inbound = config.tag(),
                            reason = ?error.kind()
                        );
                    }
                });
                let _ = sender.try_send(segments);
            }
        }
    }
    // stop 已取消：driver 收到信号后发送 Terminate 并释放会话；协议任务随流关闭结束。
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// KCP 流之上的协议分派；TLS 是可选的外层。
async fn dispatch(
    stream: KcpStream,
    config: Arc<Inbound>,
    tls: Option<TlsAcceptor>,
    vmess: Option<Arc<vmess::Prepared>>,
    ctx: Arc<Context>,
    handshake: crate::runtime::HandshakePermits,
    deadline: Duration,
) -> io::Result<()> {
    let tls_enabled = tls.is_some();
    let mut stream: Box<dyn crate::tls::Io> = match tls {
        Some(acceptor) => Box::new(
            timeout(deadline, acceptor.accept(stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mKCP TLS 握手超时"))??,
        ),
        None => Box::new(stream),
    };
    match &*config {
        Inbound::VlessKcp {
            tag, users, xudp, ..
        } => {
            let mut stream: Box<dyn crate::tls::Io> = match ctx.vless_encryption(tag) {
                Some(prepared) => Box::new(
                    timeout(deadline, prepared.accept(stream))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "mKCP/VLESS Encryption 超时")
                        })??,
                ),
                None => stream,
            };
            let accepted = timeout(
                deadline,
                vless::handshake_with_xudp(&mut stream, users, *xudp),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mKCP/VLESS 认证超时"))??;
            drop(handshake);
            crate::runtime::serve_plain_vless(stream, accepted, tag, ctx, deadline, *xudp).await
        }
        Inbound::VmessKcp { tag, .. } => {
            let prepared = vmess.ok_or_else(|| io::Error::other("VMess 未准备"))?;
            let accepted = timeout(deadline, prepared.handshake(&mut stream, tls_enabled))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mKCP/VMess 认证超时"))??;
            let allow_udp = prepared.allow_udp();
            drop(handshake);
            crate::runtime::serve_vmess(stream, accepted, tag, ctx, deadline, allow_udp).await
        }
        Inbound::TrojanKcp { tag, users, .. } => {
            let request = timeout(deadline, trojan::read_request(&mut stream, users))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mKCP/Trojan 认证超时"))??;
            drop(handshake);
            match request.command {
                Command::Connect => {
                    crate::runtime::serve_trojan_connect(stream, tag, ctx, &request).await
                }
                Command::UdpAssociate => {
                    crate::udp::trojan(stream, ctx, tag.clone(), request.user.as_deref()).await
                }
                Command::Bind => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "该协议不支持 BIND",
                )),
            }
        }
        _ => Err(io::Error::other("mKCP 入口类型无效")),
    }
}
