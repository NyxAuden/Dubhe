//! 真正 WSS 协商边界；不把 HTTP 头当成 ALPN 或传输加密事实。
#[path = "common/vmess.rs"]
mod client;
mod common;
#[path = "common/websocket.rs"]
mod ws;

use common::{Certificate, Echo, PASSWORD, Running, read_exact, socks_config};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, net::TcpStream, time::timeout};

#[tokio::test]
async fn wss_only_negotiates_http11_or_no_alpn_and_rejects_h2_only() {
    for kind in ["vless-ws", "vmess-ws", "trojan-ws"] {
        let cert = Certificate::new();
        let mut value = socks_config();
        let mut inbound = cert.inbound();
        inbound["type"] = json!(kind);
        inbound["websocket"] = json!({"path":"/proxy"});
        if kind != "trojan-ws" {
            inbound["users"] = json!([{"name":"test", "uuid":client::UUID}]);
        }
        value["inbounds"] = json!([inbound]);
        value["limits"]["handshake_timeout_ms"] = json!(2000);
        let server = Running::start(value).await;
        let echo = Echo::tcp("127.0.0.1", false).await;
        for offers in [
            vec![],
            vec![b"http/1.1".to_vec()],
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            vec![b"h2".to_vec()],
        ] {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der.clone()).unwrap();
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.alpn_protocols = offers.clone();
            let tcp = TcpStream::connect(server.address).await.unwrap();
            tcp.set_nodelay(true).unwrap();
            let result = timeout(
                Duration::from_secs(3),
                tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect("localhost".try_into().unwrap(), tcp),
            )
            .await
            .unwrap();
            if offers == vec![b"h2".to_vec()] {
                assert!(
                    result.is_err(),
                    "仅 h2 必须在 TLS 阶段拒绝，不进入 HTTP Upgrade"
                );
                continue;
            }
            let io = result.unwrap();
            assert_eq!(
                io.get_ref().1.alpn_protocol(),
                if offers.is_empty() {
                    None
                } else {
                    Some(b"http/1.1".as_slice())
                }
            );
            let mut peer = ws::upgrade(io, "/proxy", "", &[]).await;
            let payload = b"alpn-business";
            if kind == "vmess-ws" {
                let mut client = client::Client::start(
                    peer,
                    client::Request::new(1, client::target(echo.address), 3, 1),
                    Some(payload),
                )
                .await;
                assert_eq!(client.read(payload.len()).await, payload);
                client.io.close().await;
                ws::closed(&mut client.io).await;
            } else {
                let mut wire = if kind == "vless-ws" {
                    let mut bytes = vec![0];
                    bytes.extend(client::ID);
                    bytes.extend([0, 1]);
                    bytes.extend(client::target(echo.address));
                    bytes
                } else {
                    common::trojan_header(1, common::address(echo.address), PASSWORD)
                };
                wire.extend(payload);
                peer.send_message(2, &wire).await;
                if kind == "vless-ws" {
                    let mut response = [0xff; 2];
                    read_exact(&mut peer, &mut response).await;
                    assert_eq!(response, [0, 0]);
                }
                let mut echoed = vec![0; payload.len()];
                read_exact(&mut peer, &mut echoed).await;
                assert_eq!(echoed, payload);
                peer.close().await;
                ws::closed(&mut peer).await;
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
            }
        }
        timeout(Duration::from_secs(3), async {
            while server.stats.snapshot().connections != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let stats = server.stats.snapshot();
        assert_eq!(stats.uplink, 3 * b"alpn-business".len() as u64);
        assert_eq!(stats.downlink, stats.uplink);
        server.shutdown().await;
    }
}
