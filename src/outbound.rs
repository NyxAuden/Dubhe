//! 上游代理出站（SOCKS5 / HTTP CONNECT / VLESS / Trojan / Shadowsocks）。
//!
//! 这里只做握手；握手完成后仍在同一条流上继续承载业务字节（可能是明文
//! TCP，也可能由调用方先完成到上游的 TLS）。Shadowsocks 需要记录层包装，
//! 因此该路径返回新的 `Upstream`；其余协议原地写入请求头。上游代理本身
//! 不参与本内核的统计与限额，限额在进入转发层之前已经结算。

use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use base64::Engine as _;
use futures_util::{Sink, Stream};
use prost::Message as ProstMessage;
use sha2::{Digest, Sha224};
use shadowsocks::{
    config::{ServerAddr, ServerConfig, ServerType},
    context::{Context as ShadowsocksContext, SharedContext},
    relay::{Address as ShadowsocksAddress, tcprelay::ProxyClientStream},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    forward::Upstream,
    protocol::vmess::{body as vmess_body, client as vmess_client},
    route::ProxyOutbound,
    session::{Host, Target},
};

/// HTTP CONNECT 响应头上限；正常代理只返回数百字节。
const MAX_HTTP_HEADER: usize = 8 * 1024;

/// 在已连接到上游代理的流上完成握手，使随后写入的字节直达 `target`。
///
/// Shadowsocks 会在记录层包装底层流，因此返回新的 `Upstream`；其余协议
/// 复用原流。返回值的本地地址与管理接口句柄保持不变。
pub async fn connect(
    stream: Upstream,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<Upstream> {
    if proxy
        .transport
        .as_ref()
        .is_some_and(|transport| transport.uses_udp_socket())
    {
        // KCP/QUIC/H3 必须先由 Context 建立底层连接，不能把普通 TCP 假装成承载。
        return Err(protocol_error("该出站传输需要内核连接工厂"));
    }
    if let Some(reality) = &proxy.reality {
        let stream = reality
            .connect(stream, crate::forward::transport_alpn(proxy))
            .await?;
        let stream = wrap_transport(stream, proxy).await?;
        return connect_prepared(stream, proxy, target).await;
    }
    let stream = wrap_transport(stream, proxy).await?;
    connect_prepared(stream, proxy, target).await
}

/// 承载/TLS/HTTP 包装已由连接工厂完成；这里只处理代理协议。
pub(crate) fn connect_prepared<'a>(
    stream: Upstream,
    proxy: &'a ProxyOutbound,
    target: &'a Target,
) -> Pin<Box<dyn std::future::Future<Output = io::Result<Upstream>> + Send + 'a>> {
    // 仅在建连边界分配；多协议握手不能逐层内联到所有入口/测试的默认线程栈。
    Box::pin(connect_prepared_impl(stream, proxy, target))
}

async fn connect_prepared_impl(
    stream: Upstream,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<Upstream> {
    match proxy.kind {
        crate::config::OutboundKind::Socks5 | crate::config::OutboundKind::Http => {
            let mut stream = stream;
            match proxy.kind {
                crate::config::OutboundKind::Socks5 => {
                    socks5_connect(&mut stream, proxy, target).await?
                }
                _ => http_connect(&mut stream, proxy, target).await?,
            }
            Ok(stream)
        }
        crate::config::OutboundKind::Vless => {
            if proxy.flow == crate::config::VlessFlow::Vision {
                return vless_vision_connect(stream, proxy, target).await;
            }
            let stream = wrap_vless_encryption(stream, proxy).await?;
            match vless_connect(stream, proxy, target).await {
                Ok(stream) => Ok(stream),
                Err(error) => {
                    if let Some(encryption) = &proxy.encryption {
                        encryption.invalidate();
                    }
                    Err(error)
                }
            }
        }
        crate::config::OutboundKind::Vmess => {
            let mut stream = stream;
            let uuid = proxy
                .uuid
                .ok_or_else(|| protocol_error("VMess 出站缺少 uuid"))?;
            let state = vmess_client::handshake_request(
                &mut stream,
                &uuid,
                target,
                proxy.security.unwrap_or(3),
                1,
            )
            .await?;
            let (inner, local_addr, session) = stream.into_parts();
            let wrapped = vmess_body::Stream::new_client(
                SkipPrefix::new(inner, 38),
                state.security,
                state.options,
                state.key,
                state.iv,
            )?;
            Ok(Upstream::from_parts(Box::new(wrapped), local_addr, session))
        }
        crate::config::OutboundKind::Trojan => {
            let mut stream = stream;
            trojan_connect(&mut stream, proxy, target).await?;
            Ok(stream)
        }
        crate::config::OutboundKind::Shadowsocks => shadowsocks_connect(stream, proxy, target),
        crate::config::OutboundKind::Naive => {
            Err(protocol_error("Naive出站需要内核运行时连接工厂"))
        }
        crate::config::OutboundKind::Snell => {
            if proxy.snell_pool.is_some() {
                return Err(protocol_error("Snell reuse需要内核运行时连接工厂"));
            }
            let options = proxy
                .snell
                .as_deref()
                .ok_or_else(|| protocol_error("Snell出站未初始化"))?;
            let local = stream.local_addr().ok();
            let client = crate::protocol::snell::client::connect(stream, options, target).await?;
            Ok(Upstream::new_send(client, local))
        }
        crate::config::OutboundKind::ShadowTls => {
            Err(protocol_error("ShadowTLS 只能作为 via detour"))
        }
        crate::config::OutboundKind::Anytls => {
            let password = proxy
                .secret
                .as_deref()
                .ok_or_else(|| protocol_error("AnyTLS 出站缺少 password"))?;
            let (inner, local_addr, session) = stream.into_parts();
            let schemes = proxy
                .anytls_padding
                .clone()
                .ok_or_else(|| protocol_error("AnyTLS方案未初始化"))?;
            let stream = crate::transport::anytls_client::connect_with_scheme(
                inner, target, password, schemes,
            )
            .await?;
            Ok(Upstream::from_parts(Box::new(stream), local_addr, session))
        }
        _ => Err(protocol_error("该出站不是上游代理")),
    }
}

/// VLESS Vision 的 addons：字段 1、长度 16、`xtls-rprx-vision`。
const VLESS_ADDONS_VISION: &[u8] = b"\x0a\x10xtls-rprx-vision";

/// VLESS v0 无 flow 的 TCP 请求头；所有流式承载都惰性消费应答头。
///
/// mKCP 也是流式承载：官方 Xray 服务端可能等目标产生首包时才写出 VLESS
/// 应答头，若客户端在返回 SOCKS 成功前同步读取，会与目标等待形成死锁。
/// 因此 mKCP 与 TCP/WS 等一样，把应答头的校验推迟到首次业务读取。
async fn vless_connect(
    stream: Upstream,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<Upstream> {
    let uuid = proxy
        .uuid
        .ok_or_else(|| protocol_error("VLESS 出站缺少 uuid"))?;
    let (mut inner, local_addr, session) = stream.into_parts();
    write_vless_request(&mut inner, uuid, 1, &[], target).await?;
    inner.flush().await?;
    Ok(Upstream::from_parts(
        Box::new(VlessResponse::new(inner)),
        local_addr,
        session,
    ))
}

/// 延迟消费 VLESS 应答头。
///
/// 官方 Xray 可能把应答头与首个目标数据合并，或等到有数据时才 flush；
/// 客户端若在返回前阻塞读取应答，会和服务端互相等待。此包装允许请求头
/// 发送后立即写业务数据，在首次读取时再跳过版本/addons。
struct VlessResponse<S> {
    inner: S,
    header_done: bool,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl<S> VlessResponse<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            header_done: false,
            pending: Vec::new(),
            pending_offset: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessResponse<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pending_offset < this.pending.len() {
            let count = buf
                .remaining()
                .min(this.pending.len() - this.pending_offset);
            buf.put_slice(&this.pending[this.pending_offset..this.pending_offset + count]);
            this.pending_offset += count;
            if this.pending_offset == this.pending.len() {
                this.pending.clear();
                this.pending_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if !this.header_done {
            loop {
                let mut scratch = [0u8; 257];
                let mut read = ReadBuf::new(&mut scratch);
                std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(if this.pending.len() < 2 {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VLESS 出站应答头截断",
                        ))
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VLESS 出站应答 addons 截断",
                        ))
                    });
                }
                this.pending.extend_from_slice(&scratch[..count]);
                if this.pending.len() >= 2 {
                    if this.pending[0] != 0 {
                        return Poll::Ready(Err(protocol_error("VLESS 出站应答版本不匹配")));
                    }
                    let addons = usize::from(this.pending[1]);
                    let header_len = 2 + addons;
                    if this.pending.len() >= header_len {
                        this.pending.drain(..header_len);
                        this.header_done = true;
                        break;
                    }
                }
            }
            if this.pending.is_empty() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let count = buf.remaining().min(this.pending.len());
            buf.put_slice(&this.pending[..count]);
            this.pending_offset = count;
            if this.pending_offset == this.pending.len() {
                this.pending.clear();
                this.pending_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessResponse<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

/// 在首次读取时丢弃固定长度的服务器应答头（VMess 固定 38 字节）。
struct SkipPrefix<S> {
    inner: S,
    remaining: usize,
}

impl<S> SkipPrefix<S> {
    fn new(inner: S, remaining: usize) -> Self {
        Self { inner, remaining }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SkipPrefix<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.remaining > 0 {
            let mut scratch = [0u8; 64];
            let limit = this.remaining.min(scratch.len());
            let mut read = ReadBuf::new(&mut scratch[..limit]);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let count = read.filled().len();
            if count == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "VMess 出站应答头截断",
                )));
            }
            this.remaining -= count;
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SkipPrefix<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

/// Vision 出站：受控 TLS 1.3、带 addons 的 VLESS 请求、原始应答，
/// 之后由 Vision 记录层接管业务字节。VLESS Encryption 位于 TLS 与 Vision 之间；
/// 此时 Vision 只帧化业务，不再切换 TLS 原始记录层。
async fn vision_from_controlled<S>(
    mut controlled: crate::tls::controlled::Controlled<S>,
    proxy: &ProxyOutbound,
    uuid: [u8; 16],
    target: Option<&Target>,
    local_addr: Option<std::net::SocketAddr>,
    session: Option<Arc<crate::connections::Connection>>,
) -> io::Result<Upstream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    if let Some(encryption) = &proxy.encryption {
        let mut encrypted = encryption.connect(controlled).await.map_err(|error| {
            protocol_error(format!("Vision VLESS Encryption 握手失败: {error}"))
        })?;
        match target {
            Some(target) => {
                write_vless_request(&mut encrypted, uuid, 1, VLESS_ADDONS_VISION, target).await?
            }
            None => write_vless_reverse_request(&mut encrypted, uuid, VLESS_ADDONS_VISION).await?,
        }
        encrypted.flush().await?;
        let vision = crate::tls::vision::Vision::client_plain(VlessResponse::new(encrypted), uuid);
        return Ok(Upstream::from_parts(Box::new(vision), local_addr, session));
    }
    match target {
        Some(target) => {
            write_vless_request(&mut controlled, uuid, 1, VLESS_ADDONS_VISION, target).await?
        }
        None => write_vless_reverse_request(&mut controlled, uuid, VLESS_ADDONS_VISION).await?,
    }
    controlled.flush().await?;
    let vision = crate::tls::vision::Vision::client_lazy(controlled, uuid);
    Ok(Upstream::from_parts(Box::new(vision), local_addr, session))
}

async fn vless_vision_connect(
    stream: Upstream,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<Upstream> {
    let uuid = proxy
        .uuid
        .ok_or_else(|| protocol_error("VLESS 出站缺少 uuid"))?;
    let (inner, local_addr, session) = stream.into_parts();
    if let Some(reality) = &proxy.reality {
        let controlled = reality
            .connect_controlled(inner, None)
            .await
            .map_err(|error| protocol_error(format!("Vision REALITY 握手失败: {error}")))?;
        return vision_from_controlled(controlled, proxy, uuid, Some(target), local_addr, session)
            .await;
    }
    let tls = proxy
        .tls
        .as_deref()
        .ok_or_else(|| protocol_error("Vision 出站缺少 TLS 配置"))?;
    let controlled = crate::tls::controlled::Controlled::connect(
        inner,
        tls.config.clone(),
        tls.server_name.clone(),
    )
    .await
    .map_err(|error| protocol_error(format!("Vision TLS 握手失败: {error}")))?;
    vision_from_controlled(controlled, proxy, uuid, Some(target), local_addr, session).await
}

/// 反向 Mux Bridge：VLESS 命令 4（无目标字段），随后由调用方运行 Mux 服务端。
pub(crate) async fn vless_reverse_connect(
    stream: Upstream,
    proxy: &ProxyOutbound,
) -> io::Result<Upstream> {
    let uuid = proxy
        .uuid
        .ok_or_else(|| protocol_error("VLESS 出站缺少 uuid"))?;
    if proxy.flow == crate::config::VlessFlow::Vision {
        let (inner, local_addr, session) = stream.into_parts();
        if let Some(reality) = &proxy.reality {
            let controlled = reality
                .connect_controlled(inner, None)
                .await
                .map_err(|error| protocol_error(format!("Vision REALITY 握手失败: {error}")))?;
            return vision_from_controlled(controlled, proxy, uuid, None, local_addr, session)
                .await;
        }
        let tls = proxy
            .tls
            .as_deref()
            .ok_or_else(|| protocol_error("Vision 出站缺少 TLS 配置"))?;
        let controlled = crate::tls::controlled::Controlled::connect(
            inner,
            tls.config.clone(),
            tls.server_name.clone(),
        )
        .await
        .map_err(|error| protocol_error(format!("Vision TLS 握手失败: {error}")))?;
        return vision_from_controlled(controlled, proxy, uuid, None, local_addr, session).await;
    }
    let mut stream = wrap_vless_encryption(stream, proxy).await?;
    write_vless_reverse_request(&mut stream, uuid, &[]).await?;
    stream.flush().await?;
    read_vless_reply(&mut stream).await?;
    Ok(stream)
}

async fn write_vless_reverse_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    uuid: [u8; 16],
    addons: &[u8],
) -> io::Result<()> {
    if addons.len() > 255 {
        return Err(protocol_error("VLESS 出站 addons 过长"));
    }
    let mut header = Vec::with_capacity(1 + 16 + 1 + addons.len() + 1);
    header.push(0);
    header.extend_from_slice(&uuid);
    header.push(addons.len() as u8);
    header.extend_from_slice(addons);
    header.push(4); // REVERSE
    stream.write_all(&header).await
}

/// 写入 VLESS 请求头；`command` 为 1（TCP）或 2（UDP）。
async fn write_vless_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    uuid: [u8; 16],
    command: u8,
    addons: &[u8],
    target: &Target,
) -> io::Result<()> {
    if addons.len() > 255 {
        return Err(protocol_error("VLESS 出站 addons 过长"));
    }
    let mut header = Vec::with_capacity(24 + addons.len() + 1 + 2 + 1 + 255);
    header.push(0);
    header.extend_from_slice(&uuid);
    header.push(addons.len() as u8);
    header.extend_from_slice(addons);
    header.push(command);
    header.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            header.push(1);
            header.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            header.push(3);
            header.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 255
                || !domain.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(protocol_error("VLESS 出站目标域名无效"));
            }
            header.push(2);
            header.push(domain.len() as u8);
            header.extend_from_slice(domain.as_bytes());
        }
    }
    stream.write_all(&header).await
}

/// 读取 VLESS 应答头（版本 0、可选 addons）；业务字节留给调用方。
async fn read_vless_reply<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let version = stream.read_u8().await?;
    if version != 0 {
        return Err(protocol_error("VLESS 出站应答版本不匹配"));
    }
    let addons = usize::from(stream.read_u8().await?);
    if addons > 0 {
        let mut skip = vec![0u8; addons];
        stream.read_exact(&mut skip).await?;
    }
    Ok(())
}

/// VLESS UDP（命令 2）：写入目标头并读取服务器应答，随后流中为
/// `u16 长度 + 载荷` 的固定目标数据报。
/// 在 VLESS 协议层之前应用出站 Encryption；未配置时原样返回。
pub(crate) async fn wrap_vless_encryption(
    stream: Upstream,
    proxy: &ProxyOutbound,
) -> io::Result<Upstream> {
    let Some(encryption) = &proxy.encryption else {
        return Ok(stream);
    };
    let (inner, local_addr, session) = stream.into_parts();
    let encrypted = encryption
        .connect(inner)
        .await
        .map_err(|error| protocol_error(format!("VLESS Encryption 握手失败: {error}")))?;
    Ok(Upstream::from_parts(
        Box::new(encrypted),
        local_addr,
        session,
    ))
}

pub(crate) async fn vless_udp_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<()> {
    let uuid = proxy
        .uuid
        .ok_or_else(|| protocol_error("VLESS 出站缺少 uuid"))?;
    write_vless_request(stream, uuid, 2, &[], target).await?;
    stream.flush().await?;
    read_vless_reply(stream).await
}

/// Trojan UDP（命令 3）：认证头与任意目标地址，随后逐包携带目标。
pub(crate) async fn trojan_udp_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyOutbound,
) -> io::Result<()> {
    let password = proxy
        .secret
        .as_deref()
        .ok_or_else(|| protocol_error("Trojan 出站缺少 password"))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut header = Vec::with_capacity(64);
    for byte in digest.iter() {
        header.push(HEX[usize::from(byte >> 4)]);
        header.push(HEX[usize::from(byte & 0x0f)]);
    }
    header.extend_from_slice(b"\r\n");
    header.push(3); // UDP ASSOCIATE
    let wildcard = Target {
        host: Host::Ip(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        port: 0,
    };
    header.extend_from_slice(&crate::protocol::address::encode(&wildcard)?);
    header.extend_from_slice(b"\r\n");
    stream.write_all(&header).await?;
    stream.flush().await?;
    Ok(())
}

/// Shadowsocks UDP 客户端配置；返回 vendor 客户端的共享上下文与服务器配置。
pub(crate) fn shadowsocks_udp_config(
    proxy: &ProxyOutbound,
) -> io::Result<(SharedContext, ServerConfig)> {
    let method = proxy
        .method
        .ok_or_else(|| protocol_error("Shadowsocks 出站缺少 method"))?;
    let password = proxy
        .secret
        .as_deref()
        .ok_or_else(|| protocol_error("Shadowsocks 出站缺少 password"))?;
    let server_addr = match &proxy.endpoint.host {
        Host::Ip(IpAddr::V4(ip)) => {
            ServerAddr::SocketAddr(std::net::SocketAddr::new((*ip).into(), proxy.endpoint.port))
        }
        Host::Ip(IpAddr::V6(ip)) => {
            ServerAddr::SocketAddr(std::net::SocketAddr::new((*ip).into(), proxy.endpoint.port))
        }
        Host::Domain(domain) => ServerAddr::DomainName(domain.clone(), proxy.endpoint.port),
    };
    let config = ServerConfig::new(server_addr, password.to_owned(), method.cipher())
        .map_err(|error| protocol_error(format!("Shadowsocks 出站配置无效: {error}")))?;
    Ok((shadowsocks_context(), config))
}

/// Trojan 请求头：SHA-224 小写十六进制、CRLF、CONNECT 与目标地址、CRLF。
async fn trojan_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<()> {
    let password = proxy
        .secret
        .as_deref()
        .ok_or_else(|| protocol_error("Trojan 出站缺少 password"))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut header = Vec::with_capacity(56 + 2 + 1 + 259 + 2);
    for byte in digest.iter() {
        header.push(HEX[usize::from(byte >> 4)]);
        header.push(HEX[usize::from(byte & 0x0f)]);
    }
    header.extend_from_slice(b"\r\n");
    header.push(1);
    header.extend_from_slice(&crate::protocol::address::encode(target)?);
    header.extend_from_slice(b"\r\n");
    stream.write_all(&header).await?;
    stream.flush().await?;
    Ok(())
}

/// Shadowsocks 客户端记录层；包装失败时不建立任何上游业务流。
pub(crate) fn shadowsocks_connect(
    stream: Upstream,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<Upstream> {
    let method = proxy
        .method
        .ok_or_else(|| protocol_error("Shadowsocks 出站缺少 method"))?;
    let password = proxy
        .secret
        .as_deref()
        .ok_or_else(|| protocol_error("Shadowsocks 出站缺少 password"))?;
    let server_addr = match &proxy.endpoint.host {
        Host::Ip(IpAddr::V4(ip)) => {
            ServerAddr::SocketAddr(std::net::SocketAddr::new((*ip).into(), proxy.endpoint.port))
        }
        Host::Ip(IpAddr::V6(ip)) => {
            ServerAddr::SocketAddr(std::net::SocketAddr::new((*ip).into(), proxy.endpoint.port))
        }
        Host::Domain(domain) => ServerAddr::DomainName(domain.clone(), proxy.endpoint.port),
    };
    let config = ServerConfig::new(server_addr, password.to_owned(), method.cipher())
        .map_err(|error| protocol_error(format!("Shadowsocks 出站配置无效: {error}")))?;
    let address = match &target.host {
        Host::Ip(ip) => {
            ShadowsocksAddress::SocketAddress(std::net::SocketAddr::new(*ip, target.port))
        }
        Host::Domain(domain) => ShadowsocksAddress::DomainNameAddress(domain.clone(), target.port),
    };
    let (inner, local_addr, session) = stream.into_parts();
    let wrapped: ProxyClientStream<_> =
        ProxyClientStream::from_stream(shadowsocks_context(), inner, &config, address);
    Ok(Upstream::from_parts(Box::new(wrapped), local_addr, session))
}

/// 逐字节读取 HTTP 响应头，避免越过分隔符吞掉升级后的业务字节。
async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > 8192 {
            return Err(protocol_error("HTTPUpgrade 响应头过长"));
        }
    }
}

/// 在协议握手之前应用出站传输包装（WS/gRPC/HTTPUpgrade）。
pub(crate) async fn wrap_transport(
    stream: Upstream,
    proxy: &ProxyOutbound,
) -> io::Result<Upstream> {
    let Some(transport) = &proxy.transport else {
        return Ok(stream);
    };
    match transport.kind {
        // 底层承载已由 Context 的工厂建立，不再额外封装协议。
        crate::config::OutboundTransportType::Kcp | crate::config::OutboundTransportType::Quic => {
            Ok(stream)
        }
        crate::config::OutboundTransportType::Xhttp => {
            let options =
                crate::transport::xhttp_client::ClientOptions {
                    path: transport.path.clone().unwrap_or_else(|| "/".into()),
                    host: Some(transport.host.clone().unwrap_or_else(
                        || match &proxy.endpoint.host {
                            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", proxy.endpoint.port),
                            Host::Ip(ip) => format!("{ip}:{}", proxy.endpoint.port),
                            Host::Domain(domain) => format!("{domain}:{}", proxy.endpoint.port),
                        },
                    )),
                    mode: transport.mode.unwrap_or_default(),
                    h3: transport.http_version() == crate::config::OutboundHttpVersion::Http3,
                    headers: transport.headers.clone(),
                    x_padding: transport.x_padding,
                    max_post_bytes: transport.max_post_bytes.unwrap_or(64 * 1024),
                };
            let local = stream.local_addr().ok();
            let stream = match transport.http_version() {
                crate::config::OutboundHttpVersion::Http1 => {
                    crate::transport::xhttp_client::connect_h1(stream, &options).await?
                }
                crate::config::OutboundHttpVersion::Http2 => {
                    crate::transport::xhttp_client::connect_h2(stream, &options).await?
                }
                crate::config::OutboundHttpVersion::Http3 => {
                    return Err(protocol_error("XHTTP/3 必须由 QUIC 连接工厂建立"));
                }
            };
            Ok(Upstream::new_send(stream, local))
        }
        crate::config::OutboundTransportType::Ws => {
            let host = transport
                .host
                .clone()
                .unwrap_or_else(|| match &proxy.endpoint.host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Domain(domain) => domain.clone(),
                });
            let authority = if host.starts_with('[') {
                format!("{host}:{}", proxy.endpoint.port)
            } else if host.contains(':') {
                format!("[{host}]:{}", proxy.endpoint.port)
            } else {
                format!("{host}:{}", proxy.endpoint.port)
            };
            let path = transport.path.as_deref().unwrap_or("/");
            let request = format!("ws://{authority}{path}");
            let (inner, local_addr, session) = stream.into_parts();
            let (socket, response) = tokio_tungstenite::client_async(request, inner)
                .await
                .map_err(|error| protocol_error(format!("WebSocket 握手失败: {error}")))?;
            if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
                return Err(protocol_error(format!(
                    "WebSocket 上游返回状态 {}",
                    response.status()
                )));
            }
            Ok(Upstream::from_parts(
                Box::new(WsStream::new(socket)),
                local_addr,
                session,
            ))
        }
        crate::config::OutboundTransportType::HttpUpgrade => {
            let host = transport
                .host
                .clone()
                .unwrap_or_else(|| match &proxy.endpoint.host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Domain(domain) => domain.clone(),
                });
            let authority = format!("{host}:{}", proxy.endpoint.port);
            let path = transport.path.as_deref().unwrap_or("/");
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            );
            let (inner, local_addr, session) = stream.into_parts();
            let mut stream = Upstream::from_parts(inner, local_addr, session);
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            let head = read_http_head(&mut stream).await?;
            if !head.starts_with(b"HTTP/1.1 101") && !head.starts_with(b"HTTP/1.0 101") {
                return Err(protocol_error(format!(
                    "HTTPUpgrade 上游返回非 101 状态: {}",
                    String::from_utf8_lossy(&head)
                )));
            }
            Ok(stream)
        }
        crate::config::OutboundTransportType::Grpc => {
            let path = transport
                .path
                .clone()
                .ok_or_else(|| protocol_error("gRPC 传输缺少 path"))?;
            let multi = transport.multi.unwrap_or(false);
            let authority = grpc_authority(transport, proxy);
            let uri = format!("http://{authority}{path}");
            let (inner, local_addr, session) = stream.into_parts();
            let mut builder = h2::client::Builder::new();
            if let Some(size) = transport.initial_windows_size.filter(|size| *size > 0) {
                builder.initial_window_size(size);
            }
            let (mut send_request, mut connection) = builder
                .handshake::<_, prost::bytes::Bytes>(inner)
                .await
                .map_err(|error| protocol_error(format!("gRPC h2 握手失败: {error}")))?;
            let ping_pong = transport
                .idle_timeout
                .is_some_and(|seconds| seconds > 0)
                .then(|| connection.ping_pong())
                .flatten();
            // GrpcStream drop时显式结束连接任务，避免keepalive任务把连接留到下一次失败。
            let (close_tx, close_rx) = tokio::sync::oneshot::channel();
            if let Some(mut ping_pong) = ping_pong {
                let (fail_tx, fail_rx) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = connection => {}
                        _ = close_rx => {}
                        _ = fail_rx => {}
                    }
                });
                // 与 grpc-go 客户端一致：keepalive 间隔下限 10 秒，未配置应答
                // 超时时使用 20 秒。当前每条 h2 连接只承载一个 RPC，
                // permit_without_stream 不改变该模型下的行为。
                let interval =
                    Duration::from_secs(u64::from(transport.idle_timeout.unwrap_or(10)).max(10));
                let ack = Duration::from_secs(u64::from(
                    transport
                        .health_check_timeout
                        .filter(|seconds| *seconds > 0)
                        .unwrap_or(20),
                ));
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(interval).await;
                        match tokio::time::timeout(ack, ping_pong.ping(h2::Ping::opaque())).await {
                            Ok(Ok(_)) => {}
                            _ => {
                                let _ = fail_tx.send(());
                                break;
                            }
                        }
                    }
                });
            } else {
                tokio::spawn(async move {
                    tokio::select! {
                        _ = connection => {}
                        _ = close_rx => {}
                    }
                });
            }
            let mut request = http::Request::builder()
                .method("POST")
                .uri(uri.as_str())
                .header("content-type", "application/grpc")
                .header("te", "trailers");
            if let Some(user_agent) = grpc_user_agent(transport.user_agent.as_deref()) {
                request = request.header("user-agent", user_agent);
            }
            let request = request
                .body(())
                .map_err(|_| protocol_error("gRPC 请求头无效"))?;
            let (response, send) = send_request
                .send_request(request, false)
                .map_err(|error| protocol_error(format!("gRPC 建流失败: {error}")))?;
            // 不在此处等待响应头：上游可能直到收到首个 Hunk 才发送初始 metadata。
            // 首次读取时再等待并校验状态，避免与 VLESS 请求写入形成等待环。
            Ok(Upstream::from_parts(
                Box::new(GrpcStream::new(send, response, multi, close_tx)),
                local_addr,
                session,
            ))
        }
    }
}

/// Xray 的浏览器别名使用自身随机化版本；这里固定为对当前官方构建的静态快照，
/// 避免在无浏览器指纹实现时假装动态生成。自定义值原样发送。
const GRPC_CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";
const GRPC_FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0";
const GRPC_EDGE_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36Edg/151.0.0.0";

fn grpc_user_agent(configured: Option<&str>) -> Option<&str> {
    match configured {
        // 官方构建在未配置 user_agent 时不发送该头；golang 别名同样不伪装。
        None | Some("") | Some("golang") => None,
        Some("chrome") => Some(GRPC_CHROME_UA),
        Some("firefox") => Some(GRPC_FIREFOX_UA),
        Some("edge") => Some(GRPC_EDGE_UA),
        Some(custom) => Some(custom),
    }
}

fn grpc_endpoint_authority(endpoint: &Target) -> String {
    match &endpoint.host {
        Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", endpoint.port),
        Host::Ip(ip) => format!("{ip}:{}", endpoint.port),
        Host::Domain(domain) => format!("{domain}:{}", endpoint.port),
    }
}

/// 按 Xray 语义选择 `:authority`：显式配置 > TLS server_name > 明文域名
/// （不带端口）> 端点地址；REALITY 未显式配置时回落到端点地址。
fn grpc_authority(transport: &crate::config::OutboundTransport, proxy: &ProxyOutbound) -> String {
    if let Some(authority) = transport.authority.as_deref() {
        return authority.to_owned();
    }
    if let Some(tls) = &proxy.tls {
        return tls.server_name.to_str().into_owned();
    }
    if proxy.reality.is_none()
        && let Host::Domain(domain) = &proxy.endpoint.host
    {
        return domain.clone();
    }
    grpc_endpoint_authority(&proxy.endpoint)
}

#[derive(Clone, PartialEq, prost::Message)]
struct GrpcHunk {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GrpcMultiHunk {
    #[prost(bytes = "vec", repeated, tag = "1")]
    data: Vec<Vec<u8>>,
}

const GRPC_MAX_MESSAGE: usize = 1024 * 1024;

fn grpc_frame(multi: bool, data: &[u8]) -> Vec<u8> {
    let payload = if multi {
        GrpcMultiHunk {
            data: vec![data.to_vec()],
        }
        .encode_to_vec()
    } else {
        GrpcHunk {
            data: data.to_vec(),
        }
        .encode_to_vec()
    };
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn grpc_payload(payload: &[u8], multi: bool) -> io::Result<Vec<u8>> {
    if multi {
        Ok(GrpcMultiHunk::decode(payload)
            .map_err(|_| protocol_error("gRPC MultiHunk 解码失败"))?
            .data
            .concat())
    } else {
        Ok(GrpcHunk::decode(payload)
            .map_err(|_| protocol_error("gRPC Hunk 解码失败"))?
            .data)
    }
}

/// h2 双向流上的 gRPC 字节流适配器。
struct GrpcStream {
    send: h2::SendStream<prost::bytes::Bytes>,
    /// 初始响应尚未到达；首次读取时再等待，允许先发送业务 Hunk。
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    multi: bool,
    buffer: Vec<u8>,
    offset: usize,
    wire: Vec<u8>,
    /// 请求方向的DATA已结束，随后必须校验trailers。
    data_done: bool,
    /// 已收到合法grpc-status并确认成功，后续读取直接EOF。
    finished: bool,
    /// Trailers-Only响应或重复metadata中可能出现在初始响应头里。
    initial_status: Option<u32>,
    /// 流销毁时通知h2连接任务退出。
    close: Option<tokio::sync::oneshot::Sender<()>>,
}

impl GrpcStream {
    fn new(
        send: h2::SendStream<prost::bytes::Bytes>,
        response: h2::client::ResponseFuture,
        multi: bool,
        close: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self {
            send,
            response: Some(response),
            recv: None,
            multi,
            buffer: Vec::new(),
            offset: 0,
            wire: Vec::new(),
            data_done: false,
            finished: false,
            initial_status: None,
            close: Some(close),
        }
    }
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        if let Some(close) = self.close.take() {
            let _ = close.send(());
        }
    }
}

/// 读取一个单值 `grpc-status`；缺省返回 None，重复或非十进制即失败。
fn grpc_status(headers: &http::HeaderMap) -> io::Result<Option<u32>> {
    let mut values = headers.get_all("grpc-status").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(protocol_error("gRPC 含重复 grpc-status"));
    }
    let text = value
        .to_str()
        .map_err(|_| protocol_error("gRPC grpc-status 非ASCII"))?;
    Ok(Some(text.trim().parse().map_err(|_| {
        protocol_error("gRPC grpc-status 不是十进制数字")
    })?))
}

/// 按 gRPC 规范解码百分号转义的 `grpc-message`，并限制错误文本长度。
fn grpc_message(headers: &http::HeaderMap) -> Option<String> {
    let value = headers.get("grpc-message")?.to_str().ok()?;
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (nibble(bytes[index + 1]), nibble(bytes[index + 2]))
        {
            decoded.push(high << 4 | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(
        String::from_utf8_lossy(&decoded)
            .chars()
            .take(512)
            .collect::<String>(),
    )
}

fn grpc_status_error(status: u32, headers: &http::HeaderMap) -> io::Error {
    match grpc_message(headers).filter(|message| !message.is_empty()) {
        Some(message) => protocol_error(format!("gRPC 上游返回 grpc-status {status}: {message}")),
        None => protocol_error(format!("gRPC 上游返回 grpc-status {status}")),
    }
}

/// 客户端不支持任何压缩；响应头出现压缩或重复 content-type 时失败关闭。
fn validate_grpc_response_headers(headers: &http::HeaderMap) -> io::Result<()> {
    let content_type = headers.get_all("content-type").iter().collect::<Vec<_>>();
    if content_type.len() != 1 {
        return Err(protocol_error("gRPC 响应 content-type 数量非法"));
    }
    let base = content_type[0]
        .to_str()
        .map_err(|_| protocol_error("gRPC 响应 content-type 非ASCII"))?
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let lower = base.to_ascii_lowercase();
    if lower != "application/grpc" && !lower.starts_with("application/grpc+") {
        return Err(protocol_error("gRPC 响应 content-type 非法"));
    }
    if headers.contains_key("content-encoding") {
        return Err(protocol_error("gRPC 响应不允许 content-encoding"));
    }
    if let Some(encoding) = headers.get("grpc-encoding")
        && !encoding
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(protocol_error("gRPC 响应压缩不受支持"));
    }
    Ok(())
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.finished {
            return Poll::Ready(Ok(()));
        }
        if this.recv.is_none() {
            let mut response = this
                .response
                .take()
                .ok_or_else(|| protocol_error("gRPC 响应缺失"))?;
            match Pin::new(&mut response).poll(cx) {
                Poll::Ready(Ok(response)) => {
                    if response.status() != http::StatusCode::OK {
                        return Poll::Ready(Err(protocol_error(format!(
                            "gRPC 上游返回 HTTP 状态 {}",
                            response.status()
                        ))));
                    }
                    validate_grpc_response_headers(response.headers())?;
                    let initial = grpc_status(response.headers())?;
                    if let Some(status) = initial
                        && status != 0
                    {
                        return Poll::Ready(Err(grpc_status_error(status, response.headers())));
                    }
                    this.initial_status = initial;
                    this.recv = Some(response.into_body());
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(protocol_error(format!("gRPC 响应失败: {error}"))));
                }
                Poll::Pending => {
                    this.response = Some(response);
                    return Poll::Pending;
                }
            }
        }
        let Self {
            recv,
            multi,
            buffer,
            offset,
            wire,
            data_done,
            finished,
            initial_status,
            ..
        } = this;
        let recv = recv.as_mut().expect("响应已解析");
        loop {
            if *offset < buffer.len() {
                let count = buf.remaining().min(buffer.len() - *offset);
                buf.put_slice(&buffer[*offset..*offset + count]);
                *offset += count;
                return Poll::Ready(Ok(()));
            }
            buffer.clear();
            *offset = 0;
            // 解析已到达的完整 gRPC 消息。
            while wire.len() >= 5 {
                let length = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
                if wire[0] != 0 || length > GRPC_MAX_MESSAGE {
                    return Poll::Ready(Err(protocol_error("gRPC 消息头非法")));
                }
                if wire.len() < 5 + length {
                    break;
                }
                let payload: Vec<u8> = wire[5..5 + length].to_vec();
                wire.drain(..5 + length);
                let decoded = grpc_payload(&payload, *multi)?;
                if !decoded.is_empty() {
                    buffer.extend_from_slice(&decoded);
                }
            }
            if !buffer.is_empty() {
                continue;
            }
            if !*data_done {
                match recv.poll_data(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        let _ = recv.flow_control().release_capacity(chunk.len());
                        wire.extend_from_slice(&chunk);
                        continue;
                    }
                    Poll::Ready(Some(Err(error))) => {
                        return Poll::Ready(Err(protocol_error(format!("gRPC 读取失败: {error}"))));
                    }
                    Poll::Ready(None) => *data_done = true,
                    Poll::Pending => return Poll::Pending,
                }
            }
            // DATA已结束：任何残留半条消息都是截断；随后必须得到明确的成功状态。
            if !wire.is_empty() {
                return Poll::Ready(Err(protocol_error("gRPC 消息在边界前结束")));
            }
            match recv.poll_trailers(cx) {
                Poll::Ready(Ok(Some(trailers))) => {
                    let trailer_status = grpc_status(&trailers)?;
                    if let (Some(initial), Some(trailer)) = (*initial_status, trailer_status)
                        && initial != trailer
                    {
                        return Poll::Ready(Err(protocol_error(
                            "gRPC 初始响应头与trailers的grpc-status不一致",
                        )));
                    }
                    let Some(status) = trailer_status.or(*initial_status) else {
                        return Poll::Ready(Err(protocol_error(
                            "gRPC trailers 缺少 grpc-status，拒绝按成功结束",
                        )));
                    };
                    if status != 0 {
                        return Poll::Ready(Err(grpc_status_error(status, &trailers)));
                    }
                    *finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(None)) => {
                    // Trailers-Only 响应把 grpc-status 放在初始HEADERS中。
                    if *initial_status == Some(0) {
                        *finished = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(protocol_error("gRPC trailers 缺失，拒绝按成功结束")));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(protocol_error(format!(
                        "gRPC trailers 读取失败: {error}"
                    ))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.as_mut().get_mut();
        // 除数据本身外还需 5 字节前缀与 protobuf 长度开销；多请求一些，
        // 避免容量刚好等于数据长度时无法放入一条完整消息。
        this.send.reserve_capacity(buf.len().saturating_add(16));
        match this.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                // 一条 gRPC 消息必须完整放入本次 DATA 容量。
                // 帧开销：5 字节前缀 + 1 字节 protobuf tag + 变长长度字段。
                let mut take = buf.len().min(capacity.saturating_sub(7));
                while take > 0 && grpc_frame(this.multi, &buf[..take]).len() > capacity {
                    take -= 1;
                }
                if take == 0 {
                    return Poll::Pending;
                }
                let frame = grpc_frame(this.multi, &buf[..take]);
                this.send
                    .send_data(prost::bytes::Bytes::from(frame), false)
                    .map_err(|error| protocol_error(format!("gRPC 写入失败: {error}")))?;
                Poll::Ready(Ok(take))
            }
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Err(protocol_error(format!("gRPC 流控失败: {error}"))))
            }
            Poll::Ready(None) => Poll::Ready(Err(protocol_error("gRPC 流已关闭"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.send
            .send_data(prost::bytes::Bytes::new(), true)
            .map_err(|error| protocol_error(format!("gRPC 结束失败: {error}")))?;
        Poll::Ready(Ok(()))
    }
}

/// 把 WebSocket 消息流适配为字节流；只发送二进制帧，忽略 Pong。
struct WsStream<S> {
    inner: tokio_tungstenite::WebSocketStream<S>,
    buffer: Vec<u8>,
    offset: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
    fn new(inner: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            offset: 0,
        }
    }
}

fn ws_error(error: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::other(format!("WebSocket 传输失败: {error}"))
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use tokio_tungstenite::tungstenite::Message;
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
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(message))) => match message {
                    Message::Binary(data) => this.buffer.extend_from_slice(&data),
                    Message::Text(text) => this.buffer.extend_from_slice(text.as_bytes()),
                    Message::Ping(payload) => {
                        let _ = Pin::new(&mut this.inner).poll_ready(cx);
                        let _ = Pin::new(&mut this.inner).start_send(Message::Pong(payload));
                        let _ = Pin::new(&mut this.inner).poll_flush(cx);
                        continue;
                    }
                    Message::Pong(_) | Message::Frame(_) => continue,
                    Message::Close(_) => return Poll::Ready(Ok(())),
                },
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(ws_error(error))),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use tokio_tungstenite::tungstenite::Message;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.as_mut().get_mut();
        std::task::ready!(Pin::new(&mut this.inner).poll_ready(cx)).map_err(ws_error)?;
        Pin::new(&mut this.inner)
            .start_send(Message::binary(buf.to_vec()))
            .map_err(ws_error)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(ws_error)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(std::task::ready!(Pin::new(&mut self.inner).poll_close(cx)).map_err(ws_error))
    }
}

fn shadowsocks_context() -> SharedContext {
    static CONTEXT: OnceLock<SharedContext> = OnceLock::new();
    CONTEXT
        .get_or_init(|| ShadowsocksContext::new_shared(ServerType::Local))
        .clone()
}

async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<()> {
    socks5_negotiate(stream, proxy).await?;
    let request = socks5_request(target)?;
    stream.write_all(&request).await?;
    stream.flush().await?;
    let (code, _, _) = socks5_read_reply(stream).await?;
    if code != 0x00 {
        return Err(denied(format!("SOCKS5 CONNECT 失败，应答码 {code:#04x}")));
    }
    Ok(())
}

/// 建立 SOCKS5 UDP ASSOCIATE，返回 UDP 中继地址。
///
/// 调用方必须保持 `stream`（控制连接）开启；关闭它即通知上游释放关联。
/// `peer_ip` 是控制连接对端的 IP，用于解析上游返回的 `0.0.0.0`/`[::]`
/// 中继地址；TLS 包装后的流不再暴露 `peer_addr`。
pub(crate) async fn socks5_udp_associate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyOutbound,
    peer_ip: IpAddr,
) -> io::Result<std::net::SocketAddr> {
    socks5_negotiate(stream, proxy).await?;
    // CMD=UDP ASSOCIATE，DST.ADDR=0.0.0.0:0，由上游决定中继地址。
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await?;
    let (code, host, port) = socks5_read_reply(stream).await?;
    if code != 0x00 {
        return Err(denied(format!(
            "SOCKS5 UDP ASSOCIATE 失败，应答码 {code:#04x}"
        )));
    }
    let ip = match host {
        Host::Ip(ip) => ip,
        Host::Domain(_) => {
            return Err(protocol_error("SOCKS5 UDP ASSOCIATE 返回了域名中继地址"));
        }
    };
    // 0.0.0.0/[::] 表示沿用控制连接的对端地址。
    let ip = if ip.is_unspecified() { peer_ip } else { ip };
    Ok(std::net::SocketAddr::new(ip, port))
}

async fn socks5_negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyOutbound,
) -> io::Result<()> {
    // 方法协商：有凭据时同时提供 no-auth 与 username/password。
    let methods: &[u8] = if proxy.credentials.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;
    // 上一跳可能是 Snell 等有界缓冲记录流；读应答前必须实际排空请求。
    stream.flush().await?;

    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != 0x05 {
        return Err(protocol_error("SOCKS5 版本不匹配"));
    }
    match choice[1] {
        0x00 => Ok(()),
        0x02 => socks5_authenticate(stream, proxy).await,
        0xff => Err(denied("SOCKS5 上游没有可用的认证方式")),
        method => Err(protocol_error(format!(
            "SOCKS5 上游选择了不支持的认证方式 {method:#04x}"
        ))),
    }
}

async fn socks5_authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyOutbound,
) -> io::Result<()> {
    let Some((username, password)) = &proxy.credentials else {
        return Err(denied("SOCKS5 上游要求认证，但未配置凭据"));
    };
    // 长度已在配置校验中限制为 1..=255 字节。
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(denied("SOCKS5 认证失败"));
    }
    Ok(())
}

fn socks5_request(target: &Target) -> io::Result<Vec<u8>> {
    let mut request = vec![0x05, 0x01, 0x00];
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(protocol_error("SOCKS5 目标域名长度无效"));
            }
            request.push(0x03);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    Ok(request)
}

/// 读取 SOCKS5 应答：`VER REP RSV ATYP BND.ADDR BND.PORT`。
async fn socks5_read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(u8, Host, u16)> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(protocol_error("SOCKS5 应答版本不匹配"));
    }
    let host = match head[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Host::Ip(std::net::Ipv4Addr::from(octets).into())
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Host::Ip(std::net::Ipv6Addr::from(octets).into())
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; length];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain)
                .map_err(|_| protocol_error("SOCKS5 应答域名不是 UTF-8"))?;
            Host::Domain(domain)
        }
        other => {
            return Err(protocol_error(format!(
                "SOCKS5 应答地址类型未知 {other:#04x}"
            )));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok((head[1], host, u16::from_be_bytes(port)))
}

/// 编码 SOCKS5 UDP 请求：`RSV(2) FRAG(1) ATYP ADDR PORT DATA`。
pub fn socks5_udp_encode(target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut datagram = Vec::with_capacity(3 + 1 + 16 + 2 + payload.len());
    // 不使用分片：FRAG 固定为 0。
    datagram.extend_from_slice(&[0x00, 0x00, 0x00]);
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            datagram.push(0x01);
            datagram.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            datagram.push(0x04);
            datagram.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(protocol_error("SOCKS5 UDP 目标域名长度无效"));
            }
            datagram.push(0x03);
            datagram.push(bytes.len() as u8);
            datagram.extend_from_slice(bytes);
        }
    }
    datagram.extend_from_slice(&target.port.to_be_bytes());
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

/// 解析 SOCKS5 UDP 应答，返回源地址与业务载荷。
///
/// 分片（FRAG != 0）返回 `None`；当前不支持重组。
pub fn socks5_udp_parse(datagram: &[u8]) -> Option<(Target, &[u8])> {
    if datagram.len() < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0 {
        return None;
    }
    let mut offset = 3;
    let atyp = *datagram.get(offset)?;
    offset += 1;
    let host = match atyp {
        0x01 => {
            let octets: [u8; 4] = datagram.get(offset..offset + 4)?.try_into().ok()?;
            offset += 4;
            Host::Ip(std::net::Ipv4Addr::from(octets).into())
        }
        0x04 => {
            let octets: [u8; 16] = datagram.get(offset..offset + 16)?.try_into().ok()?;
            offset += 16;
            Host::Ip(std::net::Ipv6Addr::from(octets).into())
        }
        0x03 => {
            let length = *datagram.get(offset)? as usize;
            offset += 1;
            let domain = std::str::from_utf8(datagram.get(offset..offset + length)?).ok()?;
            if domain.is_empty() {
                return None;
            }
            offset += length;
            Host::Domain(domain.to_owned())
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*datagram.get(offset)?, *datagram.get(offset + 1)?]);
    offset += 2;
    Some((Target { host, port }, datagram.get(offset..)?))
}

async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<()> {
    let authority = authority(target);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((username, password)) = &proxy.credentials {
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // 逐字节读取，避免把 CONNECT 之后的首批数据一起吞进缓冲区。
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HTTP_HEADER {
            return Err(protocol_error("HTTP CONNECT 响应头过长"));
        }
    }
    let head = std::str::from_utf8(&head)
        .map_err(|_| protocol_error("HTTP CONNECT 响应头不是有效的 UTF-8"))?;
    let status = head
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| protocol_error("HTTP CONNECT 响应缺少状态码"))?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(denied(format!("HTTP CONNECT 失败，状态码 {status}")))
    }
}

fn authority(target: &Target) -> String {
    match &target.host {
        Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", target.port),
        Host::Ip(ip) => format!("{ip}:{}", target.port),
        Host::Domain(domain) => format!("{domain}:{}", target.port),
    }
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn denied(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::config::OutboundKind;

    fn proxy(kind: OutboundKind, credentials: Option<(&str, &str)>) -> ProxyOutbound {
        ProxyOutbound {
            kind,
            endpoint: "127.0.0.1:1080"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            credentials: credentials
                .map(|(user, password)| (Arc::<str>::from(user), Arc::<str>::from(password))),
            secret: None,
            uuid: None,
            flow: crate::config::VlessFlow::None,
            encryption: None,
            method: None,
            udp_over_tcp: false,
            security: None,
            transport: None,
            kcp: None,
            quic: None,
            tls: None,
            shadowtls: None,
            reality: None,
            via: None,
            wireguard: None,
            hysteria2: None,
            tuic: None,
            tuic_udp_mode: crate::config::TuicUdpRelayMode::Native,
            snell: None,
            snell_pool: None,
            naive: None,
            anytls_padding: None,
            anytls_pool: None,
            nw3: None,
        }
    }

    #[tokio::test]
    async fn skip_prefix_discards_fixed_response_header_before_body() {
        let (mut peer, inner) = tokio::io::duplex(64);
        let mut wire = vec![0x5au8; 38];
        wire.push(b'Z');
        peer.write_all(&wire).await.unwrap();
        let mut stream = SkipPrefix::new(inner, 38);
        let mut output = [0u8; 1];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"Z");

        let (mut peer, inner) = tokio::io::duplex(16);
        peer.write_all(&[0u8; 4]).await.unwrap();
        drop(peer);
        let mut stream = SkipPrefix::new(inner, 38);
        let error = stream.read_exact(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn vless_response_header_is_consumed_lazily_and_addons_are_skipped() {
        let (mut peer, inner) = tokio::io::duplex(64);
        peer.write_all(&[0, 2, b'a', b'b', b'X']).await.unwrap();
        let mut stream = VlessResponse::new(inner);
        let mut output = [0u8; 1];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"X");

        let (mut peer, inner) = tokio::io::duplex(64);
        peer.write_all(&[1, 0]).await.unwrap();
        let mut stream = VlessResponse::new(inner);
        let error = stream.read_exact(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    fn target(host: Host, port: u16) -> Target {
        Target { host, port }
    }

    #[test]
    fn socks5_request_encodes_domain_and_port() {
        let request = socks5_request(&target(Host::Domain("example.com".into()), 443)).unwrap();
        assert_eq!(&request[..5], &[0x05, 0x01, 0x00, 0x03, 11]);
        assert_eq!(&request[5..16], b"example.com");
        assert_eq!(&request[16..], &[0x01, 0xbb]);
    }

    #[test]
    fn socks5_request_encodes_ipv6() {
        let request =
            socks5_request(&target(Host::Ip("2001:db8::1".parse().unwrap()), 53)).unwrap();
        assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x04]);
        assert_eq!(request.len(), 4 + 16 + 2);
    }

    #[test]
    fn socks5_udp_datagram_round_trips_domain_and_ip() {
        for target in [
            Target {
                host: Host::Domain("example.com".into()),
                port: 53,
            },
            Target {
                host: Host::Ip("192.0.2.1".parse().unwrap()),
                port: 443,
            },
            Target {
                host: Host::Ip("2001:db8::1".parse().unwrap()),
                port: 8443,
            },
        ] {
            let datagram = socks5_udp_encode(&target, b"payload").unwrap();
            assert_eq!(&datagram[..3], &[0x00, 0x00, 0x00], "RSV/FRAG 固定为 0");
            let (parsed, payload) = socks5_udp_parse(&datagram).unwrap();
            assert_eq!(parsed, target);
            assert_eq!(payload, b"payload");
        }
    }

    #[test]
    fn socks5_udp_parse_rejects_fragments_and_truncation() {
        let target = Target {
            host: Host::Ip("192.0.2.1".parse().unwrap()),
            port: 53,
        };
        let mut datagram = socks5_udp_encode(&target, b"x").unwrap();
        datagram[2] = 0x01;
        assert!(socks5_udp_parse(&datagram).is_none(), "分片必须丢弃");
        assert!(socks5_udp_parse(&datagram[..6]).is_none(), "截断必须丢弃");
    }

    #[test]
    fn http_authority_brackets_ipv6() {
        let value = authority(&target(Host::Ip("2001:db8::1".parse().unwrap()), 443));
        assert_eq!(value, "[2001:db8::1]:443");
    }

    #[tokio::test]
    async fn socks5_handshake_completes_and_keeps_stream_usable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0u8; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x01]);
            // 跳过 BND.ADDR/BND.PORT。
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            stream.write_all(b"proxy-payload").await.unwrap();
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        socks5_connect(
            &mut stream,
            &proxy(OutboundKind::Socks5, None),
            &target(Host::Ip("192.0.2.1".parse().unwrap()), 80),
        )
        .await
        .unwrap();
        let mut payload = [0u8; 13];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"proxy-payload");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_sends_basic_auth_and_accepts_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                stream.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8(head).unwrap();
            assert!(head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(head.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            stream.write_all(b"tunneled").await.unwrap();
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        http_connect(
            &mut stream,
            &proxy(OutboundKind::Http, Some(("user", "pass"))),
            &target(Host::Domain("example.com".into()), 443),
        )
        .await
        .unwrap();
        let mut payload = [0u8; 8];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"tunneled");
        server.await.unwrap();
    }

    fn grpc_proxy(address: std::net::SocketAddr, value: serde_json::Value) -> ProxyOutbound {
        let mut proxy = proxy(OutboundKind::Vless, None);
        proxy.endpoint = address.into();
        proxy.transport = Some(serde_json::from_value(value).unwrap());
        proxy
    }

    fn grpc_frame_bytes(data: &[u8]) -> prost::bytes::Bytes {
        grpc_frame(false, data).into()
    }

    async fn grpc_client(
        address: std::net::SocketAddr,
        value: serde_json::Value,
    ) -> impl AsyncRead + AsyncWrite + Unpin {
        let proxy = grpc_proxy(address, value);
        let upstream = Upstream::new_send(TcpStream::connect(address).await.unwrap(), None);
        wrap_transport(upstream, &proxy).await.unwrap()
    }

    async fn start_grpc_server(
        listener: TcpListener,
    ) -> (
        h2::server::Connection<TcpStream, prost::bytes::Bytes>,
        h2::server::SendResponse<prost::bytes::Bytes>,
    ) {
        let (io, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake::<TcpStream>(io).await.unwrap();
        let (_request, respond) = connection.accept().await.unwrap().unwrap();
        (connection, respond)
    }

    #[tokio::test]
    async fn grpc_outbound_requires_zero_status_trailers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, mut respond) = start_grpc_server(listener).await;
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(grpc_frame_bytes(b"ok"), false).unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            send.send_trailers(trailers).unwrap();
            while connection.accept().await.is_some() {}
        });
        let mut stream = grpc_client(
            address,
            serde_json::json!({"type": "grpc", "path": "/GunService/Tun"}),
        )
        .await;
        let mut data = [0u8; 16];
        let read = stream.read(&mut data).await.unwrap();
        assert_eq!(&data[..read], b"ok");
        assert_eq!(stream.read(&mut data).await.unwrap(), 0);
        drop(stream);
        server.abort();
    }

    #[tokio::test]
    async fn grpc_outbound_rejects_nonzero_status_and_decodes_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, mut respond) = start_grpc_server(listener).await;
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(grpc_frame_bytes(b"ok"), false).unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "16".parse().unwrap());
            trailers.insert("grpc-message", "auth%20failed".parse().unwrap());
            send.send_trailers(trailers).unwrap();
            while connection.accept().await.is_some() {}
        });
        let mut stream = grpc_client(
            address,
            serde_json::json!({"type": "grpc", "path": "/GunService/Tun"}),
        )
        .await;
        let mut data = [0u8; 16];
        let read = stream.read(&mut data).await.unwrap();
        assert_eq!(&data[..read], b"ok");
        let error = stream.read(&mut data).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("grpc-status 16"), "{error}");
        assert!(error.to_string().contains("auth failed"), "{error}");
        drop(stream);
        server.abort();
    }

    #[tokio::test]
    async fn grpc_outbound_rejects_missing_trailers_and_trailers_only_errors() {
        // END_STREAM 但不发送 trailers：不得当作成功 EOF。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, mut respond) = start_grpc_server(listener).await;
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(grpc_frame_bytes(b"ok"), true).unwrap();
            while connection.accept().await.is_some() {}
        });
        let mut stream = grpc_client(
            address,
            serde_json::json!({"type": "grpc", "path": "/GunService/Tun"}),
        )
        .await;
        let mut data = [0u8; 16];
        let read = stream.read(&mut data).await.unwrap();
        assert_eq!(&data[..read], b"ok");
        let error = stream.read(&mut data).await.unwrap_err();
        assert!(error.to_string().contains("trailers 缺失"), "{error}");
        drop(stream);
        server.abort();

        // Trailers-Only：grpc-status 放在初始 HEADERS，且无 DATA。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, mut respond) = start_grpc_server(listener).await;
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .header("grpc-status", "16")
                .header("grpc-message", "bad%20identity")
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true).unwrap();
            while connection.accept().await.is_some() {}
        });
        let mut stream = grpc_client(
            address,
            serde_json::json!({"type": "grpc", "path": "/GunService/Tun"}),
        )
        .await;
        let error = stream.read(&mut data).await.unwrap_err();
        assert!(error.to_string().contains("grpc-status 16"), "{error}");
        assert!(error.to_string().contains("bad identity"), "{error}");
        drop(stream);
        server.abort();
    }

    #[tokio::test]
    async fn grpc_outbound_sends_configured_authority_and_user_agent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake::<TcpStream>(io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/GunService/Tun");
            assert_eq!(request.uri().authority().unwrap(), "front.example");
            assert_eq!(
                request.headers().get("content-type").unwrap(),
                "application/grpc"
            );
            assert_eq!(request.headers().get("te").unwrap(), "trailers");
            assert_eq!(
                request.headers().get("user-agent").unwrap(),
                "custom-ua/1.0"
            );
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            send.send_trailers(trailers).unwrap();
            while connection.accept().await.is_some() {}
        });
        let stream = grpc_client(
            address,
            serde_json::json!({
                "type": "grpc", "path": "/GunService/Tun",
                "authority": "front.example", "user_agent": "custom-ua/1.0"
            }),
        )
        .await;
        drop(stream);
        server.abort();
    }

    #[tokio::test]
    async fn http_connect_rejects_non_2xx() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                stream.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let error = http_connect(
            &mut stream,
            &proxy(OutboundKind::Http, None),
            &target(Host::Domain("example.com".into()), 443),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        server.await.unwrap();
    }
}
