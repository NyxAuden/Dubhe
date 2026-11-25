//! Shadowsocks协议适配；内核拥有socket、精确重放准入、路由及明文转发。
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use shadowsocks::{
    config::{ReplayAttackPolicy, ServerType},
    context::Context,
    relay::{Address, tcprelay::ProxyServerStream},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::timeout,
};

use crate::{
    config::ShadowsocksKeys,
    forward,
    session::{Host, Target},
    transport::DetourStream,
};

pub(crate) mod packet_window;
pub(crate) mod replay;
mod salt_io;
#[cfg(test)]
mod tcp_tests;

use replay::{Domain, ReplayPool, Window};
use salt_io::SaltIo;

pub(crate) struct Prepared {
    pub keys: ShadowsocksKeys,
    pub inbound: usize,
    pub replay: Arc<ReplayPool>,
}

impl Prepared {
    /// 由身份序号取回配置里的用户名；未配置多用户时返回 None。
    pub(crate) fn user_name(&self, identity: usize) -> Option<String> {
        let users = self.keys.users.as_ref()?;
        let index = identity.checked_sub(1)?;
        users
            .users_iter()
            .nth(index)
            .map(|user| user.name().to_owned())
    }

    pub(crate) fn identity(&self, user_key: Option<&[u8]>) -> io::Result<usize> {
        match (&self.keys.users, user_key) {
            (None, None) => Ok(0),
            (Some(users), Some(key)) => users
                .users_iter()
                .position(|user| user.key() == key)
                .map(|index| index + 1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "认证身份无效")),
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "认证身份无效",
            )),
        }
    }
}

// 握手失败、超时或future取消均用相同的零linger关闭；成功后恢复正常半关闭。
struct HandshakeSocket<S: DetourStream> {
    stream: S,
    abort_on_drop: bool,
}

impl<S: DetourStream> Drop for HandshakeSocket<S> {
    fn drop(&mut self) {
        if self.abort_on_drop {
            self.stream.abort_linger();
        }
    }
}

impl<S: DetourStream> AsyncRead for HandshakeSocket<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl<S: DetourStream> AsyncWrite for HandshakeSocket<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(crate) async fn serve_tcp(
    stream: TcpStream,
    prepared: Arc<Prepared>,
    ctx: Arc<forward::Context>,
    tag: &str,
    handshake: crate::runtime::HandshakePermits,
) -> io::Result<()> {
    serve_generic(stream, prepared, ctx, tag, handshake).await
}

/// ShadowTLS 内层流复用同一 Shadowsocks 服务端实现。
pub(crate) async fn serve_generic<S: DetourStream + 'static>(
    stream: S,
    prepared: Arc<Prepared>,
    ctx: Arc<forward::Context>,
    tag: &str,
    handshake: crate::runtime::HandshakePermits,
) -> io::Result<()> {
    let method = prepared.keys.method;
    let is_2022 = method.is_aead_2022();
    let domain = Domain {
        inbound: prepared.inbound,
        identity: 0,
    };
    let stream = HandshakeSocket {
        stream,
        abort_on_drop: is_2022,
    };
    let observed = SaltIo::new(
        stream,
        method.salt_len(),
        (!is_2022).then(|| (prepared.replay.clone(), domain)),
    );
    let mut context = Context::new(ServerType::Server);
    // 2022内部仍强制Reject，但每连接Context只持有本连接的有限状态。
    context.set_replay_attack_policy(ReplayAttackPolicy::Ignore);
    let mut stream = ProxyServerStream::from_stream_with_user_manager(
        Arc::new(context),
        observed,
        method,
        &prepared.keys.key,
        prepared.keys.users.clone(),
    );
    let target = timeout(
        Duration::from_millis(ctx.limits.handshake_timeout_ms),
        async {
            let address = stream
                .handshake()
                .await
                .map_err(|error| io::Error::new(error.kind(), "Shadowsocks握手失败"))?;
            let target = match address {
                Address::SocketAddress(address) => Target::from(address),
                Address::DomainNameAddress(domain, port) => Target {
                    host: Host::Domain(domain),
                    port,
                },
            };
            // 库的地址读取不代替内核的域名/端口校验；不执行DNS或目标连接。
            super::address::encode(&target)?;
            let identity = prepared.identity(stream.user_key())?;
            prepared.replay.admit(
                Domain { identity, ..domain },
                stream.get_ref().received_salt()?,
                if is_2022 {
                    Window::Aead2022
                } else {
                    Window::Aead2017
                },
            )?;
            Ok::<_, io::Error>(target)
        },
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Shadowsocks握手超时"))??;
    stream.get_mut().inner.abort_on_drop = false;
    drop(handshake);
    let identity = prepared.identity(stream.user_key())?;
    let user = prepared.user_name(identity);
    let stream = ctx.stats.admit_counter(tag, user.as_deref(), stream)?;
    if let Some(version) = crate::udp::uot_version(&target) {
        return crate::udp::uot(stream, ctx, tag.to_owned(), version, user.as_deref()).await;
    }
    if target.port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "无效目标端口"));
    }
    let (stream, route, dial) =
        crate::transport::sniff::sniff_route(&ctx, tag, stream, &target).await;
    let target = ctx.connect_routed(tag, &route, &dial).await?;
    // SS2022 的线上记录此前只有约 8 KiB（受中继块限制），而 sing-box 是
    // 16 KiB 级：每 GiB 多出约 8 倍记录数。只把**下行**放大到 32 KiB，
    // 代价是每条已建立连接多 24 KiB；上行保持 8 KiB，避免双向翻倍。
    if is_2022 {
        return forward::relay_sized(
            stream,
            target,
            ctx.stats.clone(),
            forward::COPY_BLOCK,
            32 * 1024,
        )
        .await;
    }
    forward::relay(stream, target, ctx.stats.clone()).await
}
