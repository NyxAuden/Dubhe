//! V2Ray HTTP/QUIC 传输共用的协议分派。
//!
//! 两种传输都把一条双向字节流交给这里，之后与 TCP/mKCP 一样进入
//! VLESS/VMess/Trojan 的认证与业务层。

use std::{io, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::OwnedSemaphorePermit,
    time::{Instant, timeout_at},
};

use crate::{
    config::Inbound,
    forward::Context,
    protocol::{trojan, vless, vmess},
    session::Command,
};

/// 在已验证的传输流上完成协议认证并转入转发。
///
/// `tls_enabled` 表示外层是否已有真实 TLS（QUIC 恒为真），供 VMess 判定
/// security=5 是否可用；`handshake` 在认证完成或失败时释放。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch<S>(
    mut stream: S,
    config: Inbound,
    vmess: Option<Arc<vmess::Prepared>>,
    tls_enabled: bool,
    ctx: Arc<Context>,
    deadline: Instant,
    handshake: Option<OwnedSemaphorePermit>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let duration = std::time::Duration::from_millis(ctx.limits.handshake_timeout_ms);
    match config {
        Inbound::VlessHttp {
            tag, users, xudp, ..
        }
        | Inbound::VlessQuic {
            tag, users, xudp, ..
        } => {
            let mut stream: Box<dyn crate::tls::Io> = match ctx.vless_encryption(&tag) {
                Some(prepared) => Box::new(
                    timeout_at(deadline, prepared.accept(stream))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "V2Ray/VLESS Encryption 超时")
                        })??,
                ),
                None => Box::new(stream),
            };
            let accepted = match timeout_at(
                deadline,
                vless::handshake_with_xudp(&mut stream, &users, xudp),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray 传输/VLESS 认证超时"))
            .and_then(|result| result)
            {
                Ok(accepted) => accepted,
                Err(error) => {
                    // 认证阶段的失败计入 rejected：H2 与 QUIC 此前用 `let _`
                    // 吞掉错误，同一入口 H1 能看见爆破、H2 看不见。
                    ctx.stats.reject();
                    return Err(error);
                }
            };
            drop(handshake);
            crate::runtime::serve_plain_vless(stream, accepted, &tag, ctx, duration, xudp).await
        }
        Inbound::VmessHttp { tag, .. } | Inbound::VmessQuic { tag, .. } => {
            let prepared = vmess.ok_or_else(|| io::Error::other("VMess 未准备"))?;
            let accepted = match timeout_at(deadline, prepared.handshake(&mut stream, tls_enabled))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray 传输/VMess 认证超时"))
                .and_then(|result| result)
            {
                Ok(accepted) => accepted,
                Err(error) => {
                    ctx.stats.reject();
                    return Err(error);
                }
            };
            let allow_udp = prepared.allow_udp();
            drop(handshake);
            crate::runtime::serve_vmess(stream, accepted, &tag, ctx, duration, allow_udp).await
        }
        Inbound::TrojanHttp { tag, users, .. } | Inbound::TrojanQuic { tag, users, .. } => {
            let request = match timeout_at(deadline, trojan::read_request(&mut stream, &users))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "V2Ray 传输/Trojan 认证超时"))
                .and_then(|result| result)
            {
                Ok(request) => request,
                Err(error) => {
                    ctx.stats.reject();
                    return Err(error);
                }
            };
            drop(handshake);
            match request.command {
                Command::Connect => {
                    crate::runtime::serve_trojan_connect(stream, &tag, ctx, &request).await
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
        _ => Err(io::Error::other("V2Ray 传输入口类型无效")),
    }
}
