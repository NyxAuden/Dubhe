//! 证书轮换：配置不变时替换证书不重启监听，现有连接继续可用。

mod common;

use common::{Certificate, Echo, PASSWORD, address, trojan_header};
use dubhe::{Config, Server};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;

fn client_config(der: rustls::pki_types::CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

async fn connect(
    config: &Arc<rustls::ClientConfig>,
    address: std::net::SocketAddr,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address).await?;
    let connector = TlsConnector::from(config.clone());
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    tokio::time::timeout(Duration::from_secs(3), connector.connect(name, tcp))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS 握手超时"))?
}

async fn exchange(stream: &mut TlsStream<TcpStream>, echo: std::net::SocketAddr) {
    let mut request = trojan_header(1, address(echo), PASSWORD);
    request.extend_from_slice(b"ping");
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"ping");
}

#[tokio::test]
async fn certificate_rotation_keeps_existing_connections() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let config = Config::from_json(
        &json!({
            "version": 1,
            "inbounds": [cert.inbound()],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"default": "direct"},
            "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 1000}
        })
        .to_string(),
    )
    .unwrap();
    let server = Server::bind(config).await.unwrap();
    let listen = server.local_addr("trojan").unwrap();
    let reload = server.reload_handle();
    let stop = CancellationToken::new();
    let task = tokio::spawn(server.run(stop.clone()));

    let old_client = client_config(cert.der.clone());
    let mut existing = connect(&old_client, listen).await.unwrap();
    // 先建立隧道并发出业务载荷；回程在轮换之后读取，验证旧会话不受影响。
    let mut request = trojan_header(1, address(echo.address), PASSWORD);
    request.extend_from_slice(b"ping");
    existing.write_all(&request).await.unwrap();

    // 覆盖同一路径下的证书与私钥，然后走不中断的证书轮换。
    let rotated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(cert.dir.path().join("cert.pem"), rotated.cert.pem()).unwrap();
    let key = cert.dir.path().join("key.pem");
    std::fs::write(&key, rotated.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(reload.reload().unwrap(), 1);

    // 已建立的连接继续可用（回程在轮换后到达）。
    let mut first = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), existing.read_exact(&mut first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&first, b"ping");

    // 新连接使用新证书：旧信任锚失败，新信任锚成功。
    let new_client = client_config(rotated.cert.der().clone());
    assert!(
        connect(&old_client, listen).await.is_err(),
        "轮换后旧证书不应再通过校验"
    );
    let mut fresh = connect(&new_client, listen).await.unwrap();
    exchange(&mut fresh, echo.address).await;

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
