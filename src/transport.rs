//! 有限传输适配；认证、业务封装和路由仍属于各协议层。
pub(crate) mod anytls;
pub(crate) mod anytls_client;
pub(crate) mod anytls_padding;
pub(crate) mod dokodemo;
pub(crate) mod grpc;
pub(crate) mod h2_progress;
pub(crate) mod httpupgrade;
pub(crate) mod hysteria2;
pub(crate) mod kcp;
pub(crate) mod kcp_client;
pub(crate) mod naive;
pub(crate) mod naive_client;
pub(crate) mod naive_h3;
pub(crate) mod naive_padding;
pub(crate) mod nw3;
pub(crate) mod shadowtls;
pub(crate) mod snell_obfs;
pub(crate) mod sniff;
pub(crate) mod tracked_quic_runtime;
pub(crate) mod tuic;
pub(crate) mod tuic_client;
pub(crate) mod tuic_udp;
pub(crate) mod tuic_udp_stream;
pub(crate) mod tunnel_udp;
pub(crate) mod v2ray_http;
pub(crate) mod v2ray_quic;
pub(crate) mod v2ray_quic_client;
pub(crate) mod v2ray_tunnel;
pub(crate) mod vless_encryption;
pub(crate) mod websocket;
pub(crate) mod wireguard;
pub(crate) mod wireguard_server;
pub(crate) mod xhttp;
pub(crate) mod xhttp_client;

/// 可被 ShadowTLS 注入的内层流；TCP 连接在认证失败时以 RST 关闭。
///
/// 该行为沿用 Shadowsocks 2022 握手期的零 linger 关闭，非 TCP 测试流为空操作。
pub(crate) trait DetourStream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
    fn abort_linger(&self) {}
}

impl DetourStream for tokio::net::TcpStream {
    fn abort_linger(&self) {
        let _ = socket2::SockRef::from(self).set_linger(Some(std::time::Duration::ZERO));
    }
}
