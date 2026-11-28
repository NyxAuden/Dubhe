use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Result, anyhow};
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

/// 已准备好的上游代理 TLS 客户端配置。
///
/// 每个出站只构建一次，连接复用同一个 `Arc<ClientConfig>`。
pub struct ClientTls {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) server_name: rustls::pki_types::ServerName<'static>,
}

/// 从 PEM 信任锚构建 TLS 客户端配置。
///
/// 不读取系统根证书：调用方必须显式提供 `ca_file`。
pub(crate) fn client_config(ca_file: &Path) -> Result<Arc<ClientConfig>> {
    client_config_versions(ca_file, rustls::DEFAULT_VERSIONS)
}

fn client_config_versions(
    ca_file: &Path,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<Arc<ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in
        CertificateDer::pem_file_iter(ca_file).map_err(|_| anyhow!("无法读取上游 CA 证书"))?
    {
        let certificate = certificate.map_err(|_| anyhow!("无法解析上游 CA 证书"))?;
        roots
            .add(certificate)
            .map_err(|_| anyhow!("上游 CA 证书无效"))?;
    }
    if roots.is_empty() {
        return Err(anyhow!("上游 CA 证书链为空"));
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .map_err(|_| anyhow!("无法配置上游 TLS 版本"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

/// 构建带指定 ALPN 的上游 TLS 客户端配置；用于 QUIC（`h3`）。
pub(crate) fn client_config_with_alpn(ca_file: &Path, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>> {
    let mut config = (*client_config(ca_file)?).clone();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

/// 从 PEM 信任锚构建上游 TLS 客户端。
pub(crate) fn client(ca_file: &Path, server_name: &str) -> Result<ClientTls> {
    Ok(ClientTls {
        config: client_config(ca_file)?,
        server_name: parse_server_name(server_name)?,
    })
}

/// Vision 只允许 TLS 1.3：服务端在 TLS 1.2 上会拒绝带 flow 的请求。
pub(crate) fn client_vision(ca_file: &Path, server_name: &str) -> Result<ClientTls> {
    Ok(ClientTls {
        config: client_config_versions(ca_file, &[&rustls::version::TLS13])?,
        server_name: parse_server_name(server_name)?,
    })
}

/// 解析 SNI/证书校验名；IP 字面量按 IP 地址校验，其余按 DNS 名校验。
pub(crate) fn parse_server_name(value: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
    }
    rustls::pki_types::ServerName::try_from(value.to_owned())
        .map_err(|_| anyhow!("上游 TLS server_name 无效"))
}

/// 入站安全层：真实 TLS 或 REALITY（二者互斥）。
#[derive(Clone)]
pub(crate) enum InboundSecurity {
    Tls(ServerTls),
    Reality(Arc<reality::Prepared>),
}

/// 安全层接受结果；REALITY 未认证流量已在内部完成回落。
pub(crate) enum AcceptedInbound {
    Stream {
        io: Box<dyn Io>,
        alpn: Option<Vec<u8>>,
    },
    Fallback,
}

pub(crate) trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

impl InboundSecurity {
    /// 执行 TLS/REALITY 握手；`deadline` 覆盖整个安全层握手。
    pub(crate) async fn accept(
        &self,
        stream: tokio::net::TcpStream,
        ctx: &crate::forward::Context,
        deadline: tokio::time::Instant,
    ) -> std::io::Result<AcceptedInbound> {
        match self {
            Self::Tls(tls) => {
                let accepted = tokio::time::timeout_at(deadline, tls.acceptor().accept(stream))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS 握手超时")
                    })??;
                let alpn = accepted.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                Ok(AcceptedInbound::Stream {
                    io: Box::new(accepted),
                    alpn,
                })
            }
            Self::Reality(prepared) => match prepared.accept(stream, ctx, deadline).await? {
                reality::Accepted::Fallback { client, target } => {
                    prepared.fallback(client, target).await?;
                    Ok(AcceptedInbound::Fallback)
                }
                reality::Accepted::Local(stream) => {
                    let alpn = stream.alpn_protocol();
                    Ok(AcceptedInbound::Stream {
                        io: Box::new(*stream),
                        alpn,
                    })
                }
            },
        }
    }
}

pub(crate) mod controlled;
pub(crate) mod reality;
pub(crate) mod reality_client;
pub(crate) mod reality_mldsa;
pub(crate) mod vision;

/// 可在运行期整体替换证书的服务端 TLS 配置。
///
/// 新连接读取当前配置；已建立的连接继续使用握手时的配置，因此轮换不会
/// 中断现有会话。ALPN 在每次加载后重新应用，保证轮换不改变传输契约。
#[derive(Clone)]
pub struct ServerTls {
    config: Arc<RwLock<Arc<ServerConfig>>>,
    alpn: Arc<[Vec<u8>]>,
}

impl ServerTls {
    pub(crate) fn new(loaded: Arc<ServerConfig>, alpn: Vec<Vec<u8>>) -> Self {
        let alpn: Arc<[Vec<u8>]> = alpn.into();
        let config = apply_alpn(loaded, &alpn);
        Self {
            config: Arc::new(RwLock::new(config)),
            alpn,
        }
    }

    /// 当前生效的 TLS 配置；握手开始时取一次快照。
    pub(crate) fn current(&self) -> Arc<ServerConfig> {
        self.config
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    /// 与 `TlsAcceptor::config` 兼容的只读快照访问器。
    pub(crate) fn config(&self) -> Arc<ServerConfig> {
        self.current()
    }

    pub(crate) fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.current())
    }

    /// 与 `TlsAcceptor` 同名方法保持调用点一致，每次握手读取最新配置。
    pub(crate) async fn accept<S>(
        &self,
        stream: S,
    ) -> std::io::Result<tokio_rustls::server::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.acceptor().accept(stream).await
    }

    /// 仅替换证书与私钥，保留本入口固定的 ALPN。
    pub(crate) fn replace(&self, loaded: Arc<ServerConfig>) {
        let next = apply_alpn(loaded, &self.alpn);
        *self
            .config
            .write()
            .unwrap_or_else(|error| error.into_inner()) = next;
    }
}

fn apply_alpn(loaded: Arc<ServerConfig>, alpn: &[Vec<u8>]) -> Arc<ServerConfig> {
    if loaded.alpn_protocols.as_slice() == alpn {
        return loaded;
    }
    let mut next = (*loaded).clone();
    next.alpn_protocols = alpn.to_vec();
    Arc::new(next)
}

struct ReloadEntry {
    certificate: PathBuf,
    private_key: PathBuf,
    tls: ServerTls,
}

/// 证书轮换句柄：只替换证书和私钥文件当前的内容。
///
/// 句柄不重新读取配置，也不改变监听或路由；调用方必须先确认配置本身未变。
/// 全部文件都加载成功后才一次性替换，任一文件失败时保持旧证书继续服务。
#[derive(Clone, Default)]
pub struct ReloadHandle {
    entries: Arc<Vec<ReloadEntry>>,
}

impl ReloadHandle {
    pub(crate) fn new(entries: Vec<(PathBuf, PathBuf, ServerTls)>) -> Self {
        Self {
            entries: Arc::new(
                entries
                    .into_iter()
                    .map(|(certificate, private_key, tls)| ReloadEntry {
                        certificate,
                        private_key,
                        tls,
                    })
                    .collect(),
            ),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 重新加载所有 TCP/TLS 入口的证书；返回替换的入口数量。
    pub fn reload(&self) -> Result<usize> {
        let mut loaded = Vec::with_capacity(self.entries.len());
        for entry in self.entries.iter() {
            loaded.push((&entry.tls, load(&entry.certificate, &entry.private_key)?));
        }
        for (tls, config) in &loaded {
            tls.replace(config.clone());
        }
        Ok(loaded.len())
    }
}

#[cfg(unix)]
fn check_private_key_permissions(file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file
        .metadata()
        .map_err(|_| anyhow!("无法读取 TLS 私钥"))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(anyhow!("TLS 私钥权限必须为 0600"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_key_permissions(_file: &std::fs::File) -> Result<()> {
    Ok(())
}

/// 加载 PEM 证书链及私钥，错误不包含路径、PEM 内容或底层解析详情。
pub fn load(certificate: &Path, private_key: &Path) -> Result<Arc<ServerConfig>> {
    let private_key = std::fs::File::open(private_key).map_err(|_| anyhow!("无法读取 TLS 私钥"))?;
    check_private_key_permissions(&private_key)?;
    let certificates = CertificateDer::pem_file_iter(certificate)
        .map_err(|_| anyhow!("无法读取 TLS 证书"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("无法解析 TLS 证书"))?;
    if certificates.is_empty() {
        return Err(anyhow!("TLS 证书链为空"));
    }
    let key =
        PrivateKeyDer::from_pem_reader(private_key).map_err(|_| anyhow!("无法解析 TLS 私钥"))?;

    // 显式选择局部 provider，不修改嵌入程序的全局密码学配置。
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| anyhow!("无法配置 TLS 版本"))?
            .with_no_client_auth()
            // rustls 的 ring provider 在构造阶段检查证书公钥与私钥是否匹配。
            .with_single_cert(certificates, key)
            .map_err(|_| anyhow!("TLS 证书或私钥无效，或两者不匹配"))?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{ClientConfig, ProtocolVersion, RootCertStore, pki_types::ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    fn fixture() -> (tempfile::TempDir, CertifiedKey) {
        let directory = tempfile::tempdir().unwrap();
        let certified = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(directory.path().join("cert.pem"), certified.cert.pem()).unwrap();
        let key = directory.path().join("key.pem");
        fs::write(&key, certified.key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        (directory, certified)
    }

    #[tokio::test]
    async fn matching_certificate_negotiates_tls12_and_tls13_with_verification() {
        let (directory, certified) = fixture();
        let server_config = load(
            &directory.path().join("cert.pem"),
            &directory.path().join("key.pem"),
        )
        .unwrap();
        for (version, expected) in [
            (&rustls::version::TLS12, ProtocolVersion::TLSv1_2),
            (&rustls::version::TLS13, ProtocolVersion::TLSv1_3),
        ] {
            let mut roots = RootCertStore::empty();
            roots.add(certified.cert.der().clone()).unwrap();
            let client_config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client_config));
            let acceptor = TlsAcceptor::from(server_config.clone());
            let (client, server) = tokio::io::duplex(16384);
            let client_task = async {
                let mut stream = connector
                    .connect(ServerName::try_from("localhost").unwrap(), client)
                    .await
                    .unwrap();
                assert_eq!(stream.get_ref().1.protocol_version(), Some(expected));
                stream.write_all(b"verified").await.unwrap();
                stream.flush().await.unwrap();
                let mut response = [0; 2];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"ok");
            };
            let server_task = async {
                let mut stream = acceptor.accept(server).await.unwrap();
                assert_eq!(stream.get_ref().1.protocol_version(), Some(expected));
                let mut payload = [0; 8];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"verified");
                stream.write_all(b"ok").await.unwrap();
                stream.flush().await.unwrap();
            };
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(client_task, server_task);
            })
            .await
            .unwrap();
        }
    }

    #[test]
    fn rejects_mismatched_private_key_without_disclosing_details() {
        let (directory, _) = fixture();
        let other = generate_simple_self_signed(vec!["other.test".into()]).unwrap();
        let key_pem = other.key_pair.serialize_pem();
        let key_path = directory.path().join("sensitive-private-key.pem");
        fs::write(&key_path, &key_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = load(&directory.path().join("cert.pem"), &key_path).unwrap_err();
        let message = format!("{error:#}");
        assert_eq!(message, "TLS 证书或私钥无效，或两者不匹配");
        assert!(!message.contains("sensitive-private-key"));
        assert!(!message.contains(&key_pem));
        assert!(error.source().is_none());
    }

    #[test]
    fn rejects_missing_empty_and_malformed_certificate_material() {
        let (directory, _) = fixture();
        let certificate = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        let missing = directory.path().join("sensitive-missing-file.pem");
        for (certificate_path, key_path) in [(&missing, &key), (&certificate, &missing)] {
            let error = load(certificate_path, key_path).unwrap_err();
            assert!(!format!("{error:#}").contains("sensitive-missing-file"));
            assert!(error.source().is_none());
        }
        for invalid in [
            "",
            "not-a-certificate",
            "-----BEGIN CERTIFICATE-----\n!bad!\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        ] {
            fs::write(&certificate, invalid).unwrap();
            assert!(load(&certificate, &key).is_err());
        }
        let (directory, _) = fixture();
        let certificate = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        for invalid in [
            "",
            "not-a-key",
            "-----BEGIN PRIVATE KEY-----\n!bad!\n-----END PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
        ] {
            fs::write(&key, invalid).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let error = load(&certificate, &key).unwrap_err();
            assert!(!format!("{error:#}").contains("bad!"));
            assert!(error.source().is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_readable_private_key() {
        use std::os::unix::fs::PermissionsExt;

        let (directory, _) = fixture();
        let certificate = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let error = load(&certificate, &key).unwrap_err();
        assert!(format!("{error:#}").contains("权限"), "{error:#}");

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&certificate, &key).is_ok());
    }
}
