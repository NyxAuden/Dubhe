//! 生产RoutedUdp关联的真实预算；独立H1/PaddedData/UoT对端不使用生产codec。
use super::*;

async fn read_padded<S: AsyncRead + Unpin>(wire: &mut S) -> Option<Vec<u8>> {
    let first = match wire.read_u8().await {
        Ok(byte) => byte,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return None,
        Err(error) => panic!("读取H1参考帧: {error}"),
    };
    let second = wire.read_u8().await.unwrap();
    let padding = wire.read_u8().await.unwrap() as usize;
    let mut payload = vec![0; u16::from_be_bytes([first, second]) as usize];
    wire.read_exact(&mut payload).await.unwrap();
    let mut waste = vec![0; padding];
    wire.read_exact(&mut waste).await.unwrap();
    assert!(waste.iter().all(|byte| *byte == 0));
    Some(payload)
}

#[tokio::test]
async fn padded_h1_routed_uot_keeps_packet_budget_and_recovers_slots_after_drop() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = h1_fixture(true, listener.local_addr().unwrap());
    let address = listener.local_addr().unwrap();
    let destination: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let tls = fixture.tls.clone();
    let peer = tokio::spawn(async move {
        let (wire, _) = listener.accept().await.unwrap();
        let mut wire = tokio_rustls::TlsAcceptor::from(tls)
            .accept(wire)
            .await
            .unwrap();
        verify_head(&read_head(&mut wire).await, "sp.v2.udp-over-tcp.arpa:0");
        wire.write_all(b"HTTP/1.1 200 OK\r\nPadding: yes\r\n\r\n")
            .await
            .unwrap();
        // 每次生产flush对应完整首八块之一，验证正式isConnect与IPv4目标地址。
        let request = read_padded(&mut wire).await.unwrap();
        let mut expected = vec![1, 1];
        expected.extend_from_slice(&[127, 0, 0, 1]);
        expected.extend_from_slice(&destination.port().to_be_bytes());
        assert_eq!(request, expected);
        let mut input = Vec::new();
        for expected in [b"ok".as_slice(), b""] {
            loop {
                if input.len() >= 2 {
                    let length = u16::from_be_bytes([input[0], input[1]]) as usize;
                    if input.len() >= length + 2 {
                        assert_eq!(&input[2..2 + length], expected);
                        input.drain(..2 + length);
                        break;
                    }
                }
                input.extend_from_slice(&read_padded(&mut wire).await.unwrap());
            }
            let mut uot = (expected.len() as u16).to_be_bytes().to_vec();
            uot.extend_from_slice(expected);
            wire.write_all(&frame(&uot)).await.unwrap();
            wire.flush().await.unwrap();
        }
        assert!(input.is_empty());
        // Drop关联必须关闭真实TLS，不用全实例stop代替。
        assert!(read_padded(&mut wire).await.is_none());
    });
    let config = crate::Config::from_json(&serde_json::json!({"version":1,
        "inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"naive","tag":"up","endpoint":address.to_string(),"username":"u","password":"p",
            "tls":{"ca_file":fixture._dir.path().join("cert.pem"),"server_name":"localhost"},
            "naive":{"http_version":"1.1","h1_padding":true,"udp_over_tcp":true,"extra_headers":{"x-extra":"independent-peer"}}}],
        "route":{"default":"up"},"limits":{"udp_queue_bytes":4,"udp_queue_packets":1,"dial_timeout_ms":1000}}).to_string()).unwrap();
    let ctx = Arc::new(Context::new(&config).unwrap());
    let mut flow = crate::udp::RoutedUdp::new(ctx.clone(), "local".into(), destination.into())
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
    assert_eq!(ctx.udp_bytes.available_permits(), 2);
    drop(packet);
    assert_eq!(ctx.udp_bytes.available_permits(), 4);
    flow.send(b"").await.unwrap();
    let packet = timeout(WAIT, flow.recv()).await.unwrap().unwrap();
    assert!(packet.payload.is_empty());
    assert_eq!(ctx.udp_bytes.available_permits(), 3);
    drop(packet);
    drop(flow);
    timeout(WAIT, peer).await.unwrap().unwrap();
    wait_children(&ctx).await;
    assert_eq!(ctx.udp_bytes.available_permits(), 4);
    assert_eq!(
        ctx.udp_slots.available_permits(),
        ctx.limits.max_udp_associations
    );
    finish(&ctx).await;
}
