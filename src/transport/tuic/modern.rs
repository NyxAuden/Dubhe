//! TUIC v5 的现代 QUIC 能力策略。
//!
//! 本模块只承载**可在 TUIC 模块内独立完成**的 QUIC/TLS 配置决策，不实现任何
//! 线协议、密码学或 UDP 封装：
//!
//! - [`CongestionControl`]：映射到 quinn 自带的 Cubic/NewReno/BBR 控制器；
//! - [`ZeroRtt`]：服务端是否接受 TLS 1.3 0-RTT 早期数据，以及对应的
//!   `max_early_data_size`（QUIC 只允许 0 或 `u32::MAX`）。
//!
//! # 0-RTT 语义与重放风险
//!
//! TUIC v5 的身份认证仍然只在 QUIC 连接建立后通过 TLS exporter 派生 token 完成；
//! 0-RTT 不会绕过认证、版本检查或失败关闭：
//!
//! - 认证流在握手完成前无法调用 exporter（rustls 的 QUIC exporter 依赖握手中
//!   派生的密钥），因此服务端统一在握手完成后读取早期流；
//! - 未认证的连接不会处理 Connect/Packet/Dissociate，认证失败/超时、版本不为 5、
//!   数据报格式错误都会关闭整条连接；
//! - rustls 的 0-RTT 只支持**有状态会话存储**（`session_storage`，默认内存缓存），
//!   并在接受 PSK 时用 `take` 消费票据，因此同一票据在单实例内只能使用一次。
//!   这构成 TLS 层的票据重放防线。
//!
//! 但仍必须明确：TLS 1.3 0-RTT 数据在协议上**天生可被重放**。如果部署方把会话
//! 存储替换为可复制/共享且不消费票据的实现，或在票据被消费前录制并重放整个
//! 0-RTT flight，非幂等的 TCP Connect/UDP Packet 仍可能被执行。默认关闭 0-RTT；
//! 只有明确接受该风险时才应启用。`udp_over_stream` 是已舍弃的旧封装，本模块
//! 与 TUIC 服务端都不实现它。
//!
//! 会话票据、PSK、exporter 均由 rustls/quinn 真实实现，本模块不生成或伪造任何
//! QUIC 报文或密钥。

use std::{io, sync::Arc};

use quinn::TransportConfig;

/// QUIC 拥塞控制算法。
///
/// 三种算法都由当前锁定的 quinn-proto 0.11.19 真实提供：
/// `quinn::congestion::{CubicConfig, NewRenoConfig, BbrConfig}`。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CongestionControl {
    /// quinn 默认算法。
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

impl CongestionControl {
    /// 解析配置文本。接受上游常见的下划线与连字符写法。
    pub(crate) fn parse(value: &str) -> io::Result<Self> {
        match value {
            "cubic" => Ok(Self::Cubic),
            "new_reno" | "new-reno" => Ok(Self::NewReno),
            "bbr" => Ok(Self::Bbr),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC 拥塞控制算法无效（仅支持 cubic/new_reno/bbr）",
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
            Self::Bbr => "bbr",
        }
    }

    /// 把算法写入 quinn 传输配置。显式设置 Cubic 也能避免依赖 quinn 的默认值。
    pub(crate) fn apply(self, transport: &mut TransportConfig) {
        match self {
            Self::Cubic => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
            Self::NewReno => transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            )),
            Self::Bbr => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
        };
    }
}

/// 服务端 0-RTT 早期数据策略。
///
/// `Disabled` 是默认值：TLS 层设置 `max_early_data_size = 0`，客户端即使缓存了
/// 票据也无法发送早期数据。`Enabled` 设置 `u32::MAX`（QUIC 允许的唯一非零值），
/// 由 rustls 的有状态票据存储与单次 `take` 消费提供 TLS 层重放防护。
///
/// 注意：0-RTT 只减少客户端等待握手的时间，不改变 TUIC 的认证顺序。服务端仍在
/// 握手完成后校验 UUID 与 exporter token；早期数据不会让未认证连接获得转发能力。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ZeroRtt {
    #[default]
    Disabled,
    Enabled,
}

impl ZeroRtt {
    /// 解析配置文本；同时接受 JSON 布尔语义的 `true`/`false`。
    #[cfg(test)]
    pub(crate) fn parse(value: &str) -> io::Result<Self> {
        match value {
            "false" | "disabled" | "off" => Ok(Self::Disabled),
            "true" | "enabled" | "on" => Ok(Self::Enabled),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC 0-RTT 配置无效（仅支持 true/false）",
            )),
        }
    }

    pub(crate) fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// rustls/QUIC 的合法取值：0 或 `u32::MAX`，其他值会被 `QuicServerConfig`
    /// 或 rustls 的 QUIC 校验拒绝。
    pub(crate) fn max_early_data_size(self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Enabled => u32::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use quinn::{
        ClientConfig as QuinnClientConfig, Endpoint, IdleTimeout, TransportConfig,
        crypto::rustls::QuicClientConfig,
    };
    use rcgen::generate_simple_self_signed;
    use rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::time::timeout;

    use super::{CongestionControl, ZeroRtt};

    #[test]
    fn congestion_control_parsing_is_explicit() {
        assert_eq!(
            CongestionControl::parse("cubic").unwrap(),
            CongestionControl::Cubic
        );
        assert_eq!(
            CongestionControl::parse("new_reno").unwrap(),
            CongestionControl::NewReno
        );
        assert_eq!(
            CongestionControl::parse("new-reno").unwrap(),
            CongestionControl::NewReno
        );
        assert_eq!(
            CongestionControl::parse("bbr").unwrap(),
            CongestionControl::Bbr
        );
        assert_eq!(CongestionControl::default(), CongestionControl::Cubic);
        assert_eq!(CongestionControl::Bbr.as_str(), "bbr");
        for invalid in ["", "reno", "BBR", "cubic "] {
            assert!(CongestionControl::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn all_congestion_controllers_apply_to_transport_config() {
        // quinn 0.11.19 同时提供 Cubic/NewReno/BBR；这里验证三种工厂都能写入
        // TransportConfig，而不是伪造算法或静默回退。
        for algorithm in [
            CongestionControl::Cubic,
            CongestionControl::NewReno,
            CongestionControl::Bbr,
        ] {
            let mut transport = TransportConfig::default();
            algorithm.apply(&mut transport);
        }
    }

    #[test]
    fn zero_rtt_uses_only_quic_legal_early_data_sizes() {
        assert_eq!(ZeroRtt::default(), ZeroRtt::Disabled);
        assert_eq!(ZeroRtt::Disabled.max_early_data_size(), 0);
        assert_eq!(ZeroRtt::Enabled.max_early_data_size(), u32::MAX);
        assert!(!ZeroRtt::Disabled.is_enabled());
        assert!(ZeroRtt::Enabled.is_enabled());
        assert_eq!(ZeroRtt::parse("false").unwrap(), ZeroRtt::Disabled);
        assert_eq!(ZeroRtt::parse("true").unwrap(), ZeroRtt::Enabled);
        assert!(ZeroRtt::parse("maybe").is_err());
    }

    fn server_tls() -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
        let certified = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = certified.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
        // 与生产路径一致：0-RTT 的开关只由 ZeroRtt 策略决定。
        config.max_early_data_size = 0;
        (Arc::new(config), certificate)
    }

    fn client_config(certificate: CertificateDer<'static>) -> QuinnClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        // QUIC 客户端必须显式开启早期数据；默认 Resumption 是内存缓存。
        tls.enable_early_data = true;
        tls.alpn_protocols.clear();
        let crypto = QuicClientConfig::try_from(Arc::new(tls)).unwrap();
        let mut config = QuinnClientConfig::new(Arc::new(crypto));
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(5)).unwrap()));
        config.transport_config(Arc::new(transport));
        config
    }

    fn test_options(
        zero_rtt: ZeroRtt,
        congestion_control: CongestionControl,
    ) -> super::super::Options {
        super::super::Options {
            tag: "tuic-test".into(),
            users: vec![super::super::Credential {
                name: "u".into(),
                uuid: [0x11; 16],
                password: "password".into(),
            }],
            alpn: Vec::new(),
            heartbeat: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(3),
            max_connections: 8,
            max_handshakes: 8,
            max_streams: 16,
            stream_receive_window: 64 * 1024,
            connection_receive_window: 1024 * 1024,
            datagram_receive_buffer: 1024 * 1024,
            max_udp_sessions: 8,
            max_udp_targets: 8,
            udp_idle_timeout: Duration::from_secs(30),
            max_udp_payload: 65507,
            congestion_control,
            zero_rtt,
        }
    }

    /// 本机 QUIC 回环：证明 `prepare` 写入的 TLS 配置确实允许客户端使用 0-RTT，
    /// 且服务端在等待完整握手后仍能收到 0-RTT 早期单向上行流。不访问公网。
    #[tokio::test]
    async fn zero_rtt_loopback_delivers_early_streams() {
        let (tls, certificate) = server_tls();
        let prepared =
            super::super::prepare(test_options(ZeroRtt::Enabled, CongestionControl::Bbr), tls)
                .unwrap();
        let server = Endpoint::server(
            prepared.server.clone(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut connections = Vec::new();
            for _ in 0..2 {
                let incoming = timeout(Duration::from_secs(3), server.accept())
                    .await
                    .expect("等待连接超时")
                    .unwrap();
                // 与生产 `serve` 相同：等待完整握手后再接受流。0-RTT 早期流由
                // quinn 缓冲并在握手完成后交付，不能被丢弃。
                let connection = incoming.accept().unwrap().await.unwrap();
                let mut stream = timeout(Duration::from_secs(3), connection.accept_uni())
                    .await
                    .expect("等待单向流超时")
                    .unwrap();
                // "warm1" 与 "early" 都是 5 字节；用 read_exact 避免 quinn 固有
                // `RecvStream::read`（返回 Option<usize>）与 tokio 扩展方法的歧义。
                let mut payload = [0u8; 5];
                timeout(Duration::from_secs(3), stream.read_exact(&mut payload))
                    .await
                    .expect("读取单向流超时")
                    .unwrap();
                received.push(payload.to_vec());
                connections.push(connection);
            }
            received
        });

        let mut client_endpoint =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client_endpoint.set_default_client_config(client_config(certificate));

        // 第一次完整握手，获取 NewSessionTicket；票据由 rustls 在握手后异步下发。
        let first = timeout(
            Duration::from_secs(3),
            client_endpoint.connect(address, "localhost").unwrap(),
        )
        .await
        .expect("首次握手超时")
        .expect("首次握手失败");
        let mut warmup = first.open_uni().await.unwrap();
        warmup.write_all(b"warm1").await.unwrap();
        warmup.finish().unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        first.close(0u32.into(), b"");
        drop(warmup);
        drop(first);

        // 第二次连接必须能拿到 0-RTT 密钥；失败即说明服务端没有真正接受 0-RTT。
        let (second, established) = timeout(Duration::from_secs(3), async {
            client_endpoint
                .connect(address, "localhost")
                .unwrap()
                .into_0rtt()
                .map_err(|_| ())
        })
        .await
        .expect("0-RTT 连接超时")
        .expect("服务端未提供 0-RTT 密钥");
        let mut early = second.open_uni().await.expect("0-RTT 打开流失败");
        early.write_all(b"early").await.unwrap();
        early.finish().unwrap();
        let accepted = timeout(Duration::from_secs(3), established)
            .await
            .expect("0-RTT 握手确认超时");
        assert!(accepted, "服务端拒绝了 0-RTT");

        let received = timeout(Duration::from_secs(3), server_task)
            .await
            .expect("服务端任务超时")
            .unwrap();
        assert_eq!(received[0].as_slice(), b"warm1");
        assert_eq!(
            received[1].as_slice(),
            b"early",
            "服务端等待握手完成后仍必须收到 0-RTT 早期流"
        );

        second.close(0u32.into(), b"");
        drop(client_endpoint);
    }

    /// rustls 只对有状态会话存储接受 0-RTT；配置不满足时 `prepare` 必须失败，
    /// 不能“开启成功但永远不生效”。
    #[test]
    fn zero_rtt_requires_stateful_resumption() {
        let (tls, _) = server_tls();
        let mut config = (*tls).clone();
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let prepared = super::super::prepare(
            test_options(ZeroRtt::Enabled, CongestionControl::Cubic),
            Arc::new(config),
        );
        assert!(prepared.is_err(), "无状态会话存储必须拒绝启用 0-RTT");
    }

    /// 默认关闭时应 fail-closed：即使客户端开启了 early_data 并缓存了票据，
    /// 服务端票据也不会授予 0-RTT 能力，`into_0rtt` 必须失败而不是悄悄降级为
    /// “发送了但被丢弃”。
    #[tokio::test]
    async fn zero_rtt_disabled_denies_client_early_data() {
        let (tls, certificate) = server_tls();
        let prepared = super::super::prepare(
            test_options(ZeroRtt::Disabled, CongestionControl::Cubic),
            tls,
        )
        .unwrap();
        let server = Endpoint::server(
            prepared.server.clone(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(3), server.accept())
                .await
                .expect("等待连接超时")
                .unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            let mut stream = timeout(Duration::from_secs(3), connection.accept_uni())
                .await
                .expect("等待单向流超时")
                .unwrap();
            let mut payload = [0u8; 5];
            let _ = stream.read_exact(&mut payload).await;
            // 保持连接存活，让客户端有时间接收 NewSessionTicket。
            tokio::time::sleep(Duration::from_millis(600)).await;
        });

        let mut client_endpoint =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client_endpoint.set_default_client_config(client_config(certificate));
        let first = timeout(
            Duration::from_secs(3),
            client_endpoint.connect(address, "localhost").unwrap(),
        )
        .await
        .expect("首次握手超时")
        .expect("首次握手失败");
        let mut stream = first.open_uni().await.unwrap();
        stream.write_all(b"warm1").await.unwrap();
        stream.finish().unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        first.close(0u32.into(), b"");
        drop(first);

        let early = client_endpoint
            .connect(address, "localhost")
            .unwrap()
            .into_0rtt();
        assert!(
            early.is_err(),
            "服务端关闭 0-RTT 时客户端不得获得早期数据能力"
        );

        server_task.abort();
        drop(client_endpoint);
    }
}
