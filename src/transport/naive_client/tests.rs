use super::*;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
mod h1;
const WAIT: Duration = Duration::from_secs(3);

fn context() -> Context {
    let config = crate::Config::from_json(r#"{"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"}}"#).unwrap();
    Context::new(&config).unwrap()
}
struct Fixture {
    _dir: tempfile::TempDir,
    tls: Arc<rustls::ServerConfig>,
    proxy: Arc<ProxyOutbound>,
}
fn fixture(version: NaiveHttpVersion, peer: std::net::SocketAddr) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.path().join("cert.pem"), cert.cert.pem()).unwrap();
    let key = dir.path().join("key.pem");
    std::fs::write(&key, cert.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut tls = (*crate::tls::load(&dir.path().join("cert.pem"), &dir.path().join("key.pem"))
        .unwrap())
    .clone();
    tls.alpn_protocols = vec![match version {
        NaiveHttpVersion::H1 => b"http/1.1".to_vec(),
        NaiveHttpVersion::H2 => b"h2".to_vec(),
        NaiveHttpVersion::H3 => b"h3".to_vec(),
    }];
    let config = crate::Config::from_json(&serde_json::json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"naive","tag":"up","endpoint":peer.to_string(),"username":"u","password":"p","tls":{"ca_file":dir.path().join("cert.pem"),"server_name":"localhost"},
        "naive":{"http_version":version,"h1_padding":version == NaiveHttpVersion::H1,"udp_over_tcp":true,"extra_headers":{"x-extra":"independent-peer"}}}],"route":{"default":"up"}}).to_string()).unwrap();
    let proxy = crate::route::Router::new(&config)
        .unwrap()
        .proxy_by_tag("up")
        .unwrap();
    Fixture {
        _dir: dir,
        tls: Arc::new(tls),
        proxy,
    }
}
fn target() -> Target {
    "127.0.0.1:443"
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into()
}
fn verify_request(request: &Request<()>) {
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().authority().unwrap().as_str(), "127.0.0.1:443");
    assert!(request.uri().scheme().is_none());
    assert!(request.uri().path().is_empty());
    assert!(request.extensions().get::<h3::ext::Protocol>().is_none());
    assert_eq!(request.headers()["proxy-authorization"], "Basic dTpw");
    assert!(!request.headers()["padding"].is_empty());
    assert_eq!(request.headers()["x-extra"], "independent-peer");
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
    frame.push(2);
    frame.extend_from_slice(bytes);
    frame.extend([0, 0]);
    frame
}
async fn finish(ctx: &Context) {
    ctx.outbound_stop.cancel();
    ctx.children.close();
    timeout(WAIT, ctx.children.wait()).await.unwrap();
}

#[tokio::test]
async fn independent_h2_peer_checks_connect_padding_first_eight_plain_ninth_and_reverse_fin() {
    for padded in [false, true] {
        let fixture = fixture(NaiveHttpVersion::H2, "127.0.0.1:1".parse().unwrap());
        let (wire, peer) = tokio::io::duplex(256 * 1024);
        let ctx = context();
        let (finished, done) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut h2 = h2::server::handshake(peer).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            let (parts, mut body) = request.into_parts();
            verify_request(&Request::from_parts(parts, ()));
            let mut response = http::Response::builder().status(200);
            if padded {
                response = response.header("padding", "independent-server");
            }
            let mut send = respond
                .send_response(response.body(()).unwrap(), false)
                .unwrap();
            let driver = tokio::spawn(async move { while h2.accept().await.is_some() {} });
            let mut wire = Vec::new();
            while let Some(bytes) = body.data().await {
                let bytes = bytes.unwrap();
                body.flow_control().release_capacity(bytes.len()).unwrap();
                wire.extend_from_slice(&bytes);
            }
            let mut expected = Vec::new();
            let mut offset = 0;
            if padded {
                for index in 0..8u8 {
                    let size = u16::from_be_bytes([wire[offset], wire[offset + 1]]) as usize;
                    let padding = wire[offset + 2] as usize;
                    assert_eq!(&wire[offset + 3..offset + 3 + size], &[index]);
                    assert!(
                        wire[offset + 3 + size..offset + 3 + size + padding]
                            .iter()
                            .all(|b| *b == 0)
                    );
                    expected.push(index);
                    offset += 3 + size + padding;
                }
            }
            expected.extend_from_slice(&wire[offset..]);
            assert_eq!(
                expected,
                [vec![0, 1, 2, 3, 4, 5, 6, 7], b"ninth".to_vec()].concat()
            );
            for index in 0..8u8 {
                send.send_data(
                    Bytes::from(if padded { frame(&[index]) } else { vec![index] }),
                    false,
                )
                .unwrap();
            }
            send.send_data(Bytes::from_static(b"ninth"), true).unwrap();
            // 发送泵由驱动实际推进，等待客户端确认读完后再结束fixture。
            let _ = done.await;
            driver.abort();
            let _ = driver.await;
        });
        let mut stream = connect_h2(
            Upstream::new_send(wire, None),
            &fixture.proxy,
            &target(),
            ctx.children.clone(),
            ctx.outbound_stop.clone(),
            WAIT,
        )
        .await
        .unwrap();
        for index in 0..8u8 {
            stream.write_all(&[index]).await.unwrap();
            stream.flush().await.unwrap();
        }
        stream.write_all(b"ninth").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            bytes,
            [vec![0, 1, 2, 3, 4, 5, 6, 7], b"ninth".to_vec()].concat()
        );
        let _ = finished.send(());
        drop(stream);
        finish(&ctx).await;
        timeout(WAIT, task).await.unwrap().unwrap();
    }
}

fn quic_endpoint(socket: tokio::net::UdpSocket, tls: Arc<rustls::ServerConfig>) -> quinn::Endpoint {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
        socket.into_std().unwrap(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap()
}
async fn wait_children(ctx: &Context) {
    timeout(WAIT, async {
        while !ctx.children.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn independent_h3_peer_sees_only_connect_authority_and_tracks_client_socket_drop() {
    for padded in [false, true] {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fixture = fixture(NaiveHttpVersion::H3, socket.local_addr().unwrap());
        let endpoint = quic_endpoint(socket, fixture.tls.clone());
        let incoming = endpoint.clone();
        let (local_tx, local_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let connection = incoming.accept().await.unwrap().await.unwrap();
            let _ = local_tx.send(connection.remote_address());
            let mut h3 = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let (request, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            verify_request(&request);
            let mut response = http::Response::builder().status(200);
            if padded {
                response = response.header("padding", "yes");
            }
            stream
                .send_response(response.body(()).unwrap())
                .await
                .unwrap();
            let driver =
                tokio::spawn(async move { while h3.accept().await.is_ok_and(|r| r.is_some()) {} });
            let mut wire = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                let remaining = data.remaining();
                wire.extend_from_slice(&data.copy_to_bytes(remaining));
            }
            let mut offset = 0;
            if padded {
                for index in 0..8u8 {
                    let size = u16::from_be_bytes([wire[offset], wire[offset + 1]]) as usize;
                    let padding = wire[offset + 2] as usize;
                    assert_eq!(&wire[offset + 3..offset + 3 + size], &[index]);
                    assert!(
                        wire[offset + 3 + size..offset + 3 + size + padding]
                            .iter()
                            .all(|b| *b == 0)
                    );
                    offset += 3 + size + padding;
                }
                assert_eq!(&wire[offset..], b"ninth");
            } else {
                assert_eq!(
                    wire,
                    [vec![0, 1, 2, 3, 4, 5, 6, 7], b"ninth".to_vec()].concat()
                );
            }
            for index in 0..8u8 {
                let bytes = if padded { frame(&[index]) } else { vec![index] };
                for byte in bytes {
                    stream.send_data(Bytes::from(vec![byte])).await.unwrap();
                }
            }
            stream
                .send_data(Bytes::from_static(b"ninth"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            connection.closed().await;
            driver.abort();
            let _ = driver.await;
        });
        let ctx = context();
        let mut stream = connect(&ctx, &fixture.proxy, &target()).await.unwrap();
        for index in 0..8u8 {
            stream.write_all(&[index]).await.unwrap();
            stream.flush().await.unwrap();
        }
        stream.write_all(b"ninth").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reply,
            [vec![0, 1, 2, 3, 4, 5, 6, 7], b"ninth".to_vec()].concat()
        );
        let local = local_rx.await.unwrap();
        drop(stream);
        wait_children(&ctx).await; // 不依赖全实例stop，Drop本身必须收回端点。
        finish(&ctx).await;
        timeout(WAIT, task).await.unwrap().unwrap();
        tokio::net::UdpSocket::bind(local).await.unwrap();
        endpoint.close(0u32.into(), b"done");
    }
}

#[tokio::test]
async fn h3_bad_response_partial_padding_and_cancelled_headers_release_endpoint_without_stop() {
    for scenario in 0..4 {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fixture = fixture(NaiveHttpVersion::H3, socket.local_addr().unwrap());
        let endpoint = quic_endpoint(socket, fixture.tls.clone());
        let incoming = endpoint.clone();
        let (local_tx, local_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let connection = incoming.accept().await.unwrap().await.unwrap();
            let _ = local_tx.send(connection.remote_address());
            let mut h3 = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let (request, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            verify_request(&request);
            let _ = ready_tx.send(());
            let driver =
                tokio::spawn(async move { while h3.accept().await.is_ok_and(|r| r.is_some()) {} });
            if scenario != 3 {
                let mut response = http::Response::builder()
                    .status(if scenario == 0 { 204 } else { 200 })
                    .header("padding", "yes");
                if scenario == 1 {
                    response = response.header("padding", "duplicate");
                }
                // 拒绝时客户端可能已主动关闭，不能将fixture写失败当作生产失败。
                let _ = stream.send_response(response.body(()).unwrap()).await;
                if scenario == 2 {
                    stream
                        .send_data(Bytes::from_static(&[0, 5, 1, b'a']))
                        .await
                        .unwrap();
                    stream.finish().await.unwrap();
                }
            }
            connection.closed().await;
            driver.abort();
            let _ = driver.await;
        });
        let ctx = context();
        let destination = target();
        if scenario == 3 {
            let mut operation = connect(&ctx, &fixture.proxy, &destination);
            tokio::select! { result = &mut operation => panic!("慢响应头不能提前完成: {result:?}"), _ = ready_rx => {} }
            drop(operation);
        } else {
            let result = timeout(WAIT, connect(&ctx, &fixture.proxy, &destination))
                .await
                .unwrap();
            if scenario == 2 {
                let mut stream = result.unwrap();
                assert!(
                    timeout(WAIT, stream.read_to_end(&mut Vec::new()))
                        .await
                        .unwrap()
                        .is_err()
                );
                assert!(stream.write_all(b"after-failure").await.is_err());
            } else {
                assert!(result.is_err());
            }
        }
        let local = local_rx.await.unwrap();
        wait_children(&ctx).await;
        tokio::net::UdpSocket::bind(local).await.unwrap();
        timeout(WAIT, task).await.unwrap().unwrap();
        finish(&ctx).await;
        endpoint.close(0u32.into(), b"done");
    }
}

#[tokio::test]
async fn h3_clean_connection_close_after_fin_keeps_eof_but_early_close_is_error() {
    for send_fin in [true, false] {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fixture = fixture(NaiveHttpVersion::H3, socket.local_addr().unwrap());
        let endpoint = quic_endpoint(socket, fixture.tls.clone());
        let incoming = endpoint.clone();
        let (reply_tx, reply_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let connection = incoming.accept().await.unwrap().await.unwrap();
            let mut h3 = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let (_, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            let drive =
                tokio::spawn(async move { while h3.accept().await.is_ok_and(|r| r.is_some()) {} });
            stream
                .send_data(Bytes::from_static(b"response"))
                .await
                .unwrap();
            if send_fin {
                stream.finish().await.unwrap();
            }
            reply_rx.await.unwrap();
            connection.close(
                h3::error::Code::H3_NO_ERROR.value().try_into().unwrap(),
                b"normal close",
            );
            drive.abort();
            let _ = drive.await;
        });
        let ctx = context();
        let mut client = connect(&ctx, &fixture.proxy, &target()).await.unwrap();
        let mut reply = [0; 8];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"response");
        if send_fin {
            assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        }
        reply_tx.send(()).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap();
        // 等控制driver观察对端关连接，不以实例取消制造错误。
        timeout(WAIT, async {
            while ctx.children.len() > 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let result = client.read(&mut [0; 1]).await;
        if send_fin {
            assert_eq!(result.unwrap(), 0);
        } else {
            assert!(result.is_err(), "没有流FIN的连接关闭不能伪装EOF");
        }
        drop(client);
        wait_children(&ctx).await;
        finish(&ctx).await;
        endpoint.close(0u32.into(), b"done");
    }
}

#[tokio::test]
async fn missing_h2_alpn_and_wrong_h3_alpn_fail_without_sending_connect() {
    for version in [NaiveHttpVersion::H2, NaiveHttpVersion::H3] {
        let ctx = context();
        if version == NaiveHttpVersion::H2 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut fixture = fixture(version, listener.local_addr().unwrap());
            Arc::make_mut(&mut fixture.tls).alpn_protocols.clear();
            let tls = fixture.tls.clone();
            let peer = tokio::spawn(async move {
                let (wire, _) = listener.accept().await.unwrap();
                let mut wire = tokio_rustls::TlsAcceptor::from(tls)
                    .accept(wire)
                    .await
                    .unwrap();
                assert!(wire.get_ref().1.alpn_protocol().is_none());
                let mut bytes = Vec::new();
                let _ = timeout(WAIT, wire.read_to_end(&mut bytes)).await.unwrap();
                assert!(bytes.is_empty(), "ALPN不匹配时不能发送HTTP/2前言或CONNECT");
            });
            assert!(
                timeout(WAIT, connect(&ctx, &fixture.proxy, &target()))
                    .await
                    .unwrap()
                    .is_err()
            );
            timeout(WAIT, peer).await.unwrap().unwrap();
        } else {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut fixture = fixture(version, socket.local_addr().unwrap());
            Arc::make_mut(&mut fixture.tls).alpn_protocols = vec![b"not-h3".to_vec()];
            let endpoint = quic_endpoint(socket, fixture.tls.clone());
            let incoming = endpoint.clone();
            let peer = tokio::spawn(async move {
                assert!(incoming.accept().await.unwrap().await.is_err());
            });
            assert!(
                timeout(WAIT, connect(&ctx, &fixture.proxy, &target()))
                    .await
                    .unwrap()
                    .is_err()
            );
            wait_children(&ctx).await;
            timeout(WAIT, peer).await.unwrap().unwrap();
            endpoint.close(0u32.into(), b"done");
        }
        finish(&ctx).await;
    }
}

#[tokio::test]
async fn cancelled_quic_handshake_releases_initial_endpoint_without_global_stop() {
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fixture = fixture(NaiveHttpVersion::H3, peer.local_addr().unwrap());
    let ctx = context();
    let destination = target();
    let mut operation = connect(&ctx, &fixture.proxy, &destination);
    let mut packet = [0; 1500];
    let local = tokio::select! {
        result = &mut operation => panic!("未收到握手应答不能完成: {result:?}"),
        result = peer.recv_from(&mut packet) => result.unwrap().1,
    };
    drop(operation);
    wait_children(&ctx).await;
    tokio::net::UdpSocket::bind(local).await.unwrap();
    finish(&ctx).await;
}

#[tokio::test]
async fn h2_rejects_non_200_duplicate_padding_truncated_frame_and_cancels_slow_headers() {
    for scenario in 0..4 {
        let fixture = fixture(NaiveHttpVersion::H2, "127.0.0.1:1".parse().unwrap());
        let (wire, peer) = tokio::io::duplex(65536);
        let ctx = context();
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut h2 = h2::server::handshake(peer).await.unwrap();
            let (_request, mut respond) = h2.accept().await.unwrap().unwrap();
            let _ = ready_tx.send(());
            if scenario == 3 {
                while h2.accept().await.is_some() {}
                return;
            }
            let mut response = http::Response::builder()
                .status(if scenario == 0 { 204 } else { 200 })
                .header("padding", "yes");
            if scenario == 1 {
                response = response.header("padding", "again");
            }
            let mut send = respond
                .send_response(response.body(()).unwrap(), false)
                .unwrap();
            if scenario == 2 {
                send.send_data(Bytes::from_static(&[0, 5, 1, b'a']), true)
                    .unwrap();
            }
            while h2.accept().await.is_some() {}
        });
        let destination = target();
        let operation = connect_h2(
            Upstream::new_send(wire, None),
            &fixture.proxy,
            &destination,
            ctx.children.clone(),
            ctx.outbound_stop.clone(),
            WAIT,
        );
        if scenario == 3 {
            let mut operation = Box::pin(operation);
            tokio::select! { result=&mut operation=>panic!("慢头不能提前成功: {result:?}"), _=ready_rx=>{} }
            drop(operation);
            // 不取消实例来代替future取消的证据；先等guard触发的真实析构。
            timeout(WAIT, async {
                while !ctx.children.is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        } else {
            let result = timeout(WAIT, operation).await.unwrap();
            if scenario == 2 {
                let mut stream = result.unwrap();
                assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
            } else {
                assert!(result.is_err());
            }
        }
        finish(&ctx).await;
        timeout(WAIT, task).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn routed_uot_budget_empty_packet_and_drop_release_all_permits() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cert.pem"), cert.cert.pem()).unwrap();
    let key = dir.path().join("key.pem");
    std::fs::write(&key, cert.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config=crate::Config::from_json(&serde_json::json!({"version":1,
        "inbounds":[{"type":"naive","tag":"up","listen":"127.0.0.1:0","users":[{"name":"u","password":"p"}],"certificate":dir.path().join("cert.pem"),"private_key":dir.path().join("key.pem")}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":300}}).to_string()).unwrap();
    let server = crate::Server::bind(config).await.unwrap();
    let address = server.local_addr("up").unwrap();
    let stop = CancellationToken::new();
    let task = tokio::spawn(server.run(stop.clone()));
    let config=crate::Config::from_json(&serde_json::json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"naive","tag":"up","endpoint":address.to_string(),"username":"u","password":"p","tls":{"ca_file":dir.path().join("cert.pem"),"server_name":"localhost"},"naive":{"udp_over_tcp":true}}],
        "route":{"default":"up"},"limits":{"udp_queue_bytes":4,"udp_queue_packets":1}}).to_string()).unwrap();
    let ctx = Arc::new(Context::new(&config).unwrap());
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = socket.local_addr().unwrap().into();
    let echo = tokio::spawn(async move {
        let mut bytes = [0; 16];
        while let Ok((n, peer)) = socket.recv_from(&mut bytes).await {
            socket.send_to(&bytes[..n], peer).await.unwrap();
        }
    });
    let mut flow = crate::udp::RoutedUdp::new(ctx.clone(), "local".into(), target)
        .await
        .unwrap();
    let held = ctx.udp_bytes.clone().acquire_many_owned(3).await.unwrap();
    assert_eq!(
        flow.send(b"no").await.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(held);
    flow.send(b"ok").await.unwrap();
    let packet = timeout(WAIT, flow.recv()).await.unwrap().unwrap();
    assert_eq!(packet.payload, b"ok");
    drop(packet);
    assert_eq!(ctx.udp_bytes.available_permits(), 4);
    flow.send(b"").await.unwrap();
    let packet = timeout(WAIT, flow.recv()).await.unwrap().unwrap();
    assert!(packet.payload.is_empty());
    assert_eq!(ctx.udp_bytes.available_permits(), 3);
    drop(packet);
    drop(flow);
    finish(&ctx).await;
    assert_eq!(ctx.udp_bytes.available_permits(), 4);
    assert_eq!(
        ctx.udp_slots.available_permits(),
        ctx.limits.max_udp_associations
    );
    stop.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    echo.abort();
    let _ = echo.await;
}

#[test]
fn writer_queue_barrier_cancel_and_finish_only_once_and_errors_stay_errors() {
    let shared = Shared::new();
    let (tx, mut rx) = mpsc::channel(1);
    let mut writer = Writer::new(tx, shared.clone());
    let mut cx = TaskContext::from_waker(std::task::Waker::noop());
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut cx, b"first"),
        Poll::Ready(Ok(5))
    ));
    assert!(
        Pin::new(&mut writer)
            .poll_write(&mut cx, b"not-accepted")
            .is_pending()
    );
    assert!(matches!(rx.try_recv().unwrap(),Write::Data(data) if data==b"first".as_slice()));
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
    let Write::Flush(ack) = rx.try_recv().unwrap() else {
        panic!("flush")
    };
    assert!(
        Pin::new(&mut writer)
            .poll_write(&mut cx, b"cancelled")
            .is_pending()
    );
    assert!(rx.try_recv().is_err());
    ack.send(()).unwrap();
    assert!(matches!(
        Pin::new(&mut writer).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());
    let Write::Finish(ack) = rx.try_recv().unwrap() else {
        panic!("finish")
    };
    assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());
    assert!(rx.try_recv().is_err());
    ack.send(()).unwrap();
    assert!(matches!(
        Pin::new(&mut writer).poll_shutdown(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut cx, b"late"),
        Poll::Ready(Err(_))
    ));
    shared.fail(io::Error::new(
        io::ErrorKind::ConnectionReset,
        "fixture failure",
    ));
    assert!(
        matches!(Pin::new(&mut writer).poll_flush(&mut cx),Poll::Ready(Err(e)) if e.kind()==io::ErrorKind::ConnectionReset)
    );
}
