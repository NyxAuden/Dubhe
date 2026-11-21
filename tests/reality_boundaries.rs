//! REALITY 新承载上的 Vision/Controlled 边界；仅独立受控回环，不继承旧 TLS 承载结果。
mod common;
#[path = "common/reality.rs"]
mod peer;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Running, socks_config};
use peer::{Outer, PreparedClient, TargetGroup, TargetOptions, TargetPeer};
use serde_json::{Value, json};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
fn config(target: SocketAddr) -> Value {
    let mut value = socks_config();
    value["limits"]["handshake_timeout_ms"] = json!(3000);
    value["inbounds"] = json!([{"type":"vless-reality","tag":"reality-boundary","listen":"127.0.0.1:0",
        "users":[{"name":"vision","uuid":peer::UUID,"flow":"xtls-rprx-vision"}],
        "reality":{"target":{"host":target.ip().to_string(),"port":target.port()},
            "private_key":URL_SAFE_NO_PAD.encode(peer::SERVER_PRIVATE_KEY),
            "server_names":["localhost"],"short_ids":["8172635445362718"]}}]);
    value
}
async fn idle(server: &Running) {
    timeout(LIMIT, async {
        while server.stats.snapshot().connections != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn block(client: &mut Outer, first: bool) -> (u8, Vec<u8>) {
    if first {
        assert_eq!(client.plain(16).await.unwrap(), peer::ID);
    }
    let header = client.plain(5).await.unwrap();
    let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
    let padding = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let body = client.plain(length).await.unwrap();
    client.plain(padding).await.unwrap();
    (header[0], body)
}
fn output(client: &mut Outer) -> Vec<u8> {
    let mut wire = Vec::new();
    while client.tls.wants_write() {
        client.tls.write_tls(&mut wire).unwrap();
    }
    wire
}

#[tokio::test]
async fn keyupdate_then_one_way_direct_other_way_stays_authenticated_tls() {
    for group in [TargetGroup::X25519, TargetGroup::Hybrid] {
        let target = TargetPeer::start(TargetOptions {
            group,
            ..Default::default()
        })
        .await
        .unwrap();
        let server = Running::start(config(target.address)).await;
        let echo = common::Echo::tcp("127.0.0.1", true).await;
        let mut client = PreparedClient::new(Default::default())
            .unwrap()
            .connect(server.address)
            .await
            .unwrap();
        // KeyUpdate 发生在任何 Direct 提交之前；其 response 必须仍经真实外层 TLS。
        client.tls.refresh_traffic_keys().unwrap();
        client.flush_tls().await.unwrap();
        let mut bytes = peer::vless_request(1, Some("xtls-rprx-vision"), peer::ID, echo.address);
        bytes.extend(peer::vision_block(true, 2, b"direct", 7));
        bytes.extend(b"same-record-tail");
        io::Write::write_all(&mut client.tls.writer(), &bytes).unwrap();
        let mut wire = output(&mut client);
        wire.extend(b"raw-after-keyupdate");
        // 一次 write 合并最后 TLS record 与首批 raw，不能把 raw 当下一 TLS header。
        client.io.write_all(&wire).await.unwrap();
        client.io.shutdown().await.unwrap();
        assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
        let (command, body) = block(&mut client, true).await;
        assert_eq!(command, 1, "下行未识别内层 TLS，保持外层 TLS 的 End");
        assert_eq!(body, b"directsame-record-tailraw-after-keyupdate");
        drop(client);
        idle(&server).await;
        let stats = server.stats.snapshot();
        let length = b"directsame-record-tailraw-after-keyupdate".len() as u64;
        assert_eq!((stats.uplink, stats.downlink), (length, length));
        server.shutdown().await;
        target.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn fragmented_ciphertext_and_repeated_keyupdates_preserve_business_and_close_notify() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let server = Running::start(config(target.address)).await;
    let echo = common::Echo::tcp("127.0.0.1", true).await;
    let mut client = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    let mut bytes = peer::vless_request(1, Some("xtls-rprx-vision"), peer::ID, echo.address);
    bytes.extend(peer::vision_block(true, 1, b"start", 11));
    io::Write::write_all(&mut client.tls.writer(), &bytes).unwrap();
    for byte in output(&mut client) {
        client.io.write_all(&[byte]).await.unwrap();
        tokio::task::yield_now().await;
    }
    assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
    for payload in [
        b"one".as_slice(),
        b"two\0binary".as_slice(),
        b"three".as_slice(),
    ] {
        client.tls.refresh_traffic_keys().unwrap();
        io::Write::write_all(&mut client.tls.writer(), payload).unwrap();
        // 小片段切过 TLS header/body/tag，真实 socket IO；不声称强制每次服务端 poll 都 Pending。
        for part in output(&mut client).chunks(3) {
            client.io.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
    }
    client.close_notify().await.unwrap();
    let expected = b"startonetwo\0binarythree";
    let (command, mut body) = block(&mut client, true).await;
    assert_eq!(command, 1);
    while body.len() < expected.len() {
        body.extend(client.plain(expected.len() - body.len()).await.unwrap());
    }
    assert_eq!(body, expected);
    // 必须拿到真实服务端 close_notify，不能只依赖 socket drop EOF。
    timeout(LIMIT, async {
        loop {
            match io::Read::read(&mut client.tls.reader(), &mut [0; 1]) {
                Ok(0) => break,
                Ok(_) => panic!("关闭后有多余业务明文"),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    client.record().await.unwrap();
                }
                Err(error) => panic!("缺少真实 close_notify: {error}"),
            }
        }
    })
    .await
    .unwrap();
    drop(client);
    idle(&server).await;
    let stats = server.stats.snapshot();
    assert_eq!(
        (stats.uplink, stats.downlink),
        (expected.len() as u64, expected.len() as u64)
    );
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn blocked_downlink_does_not_stop_ready_uplink_tls_records_or_keyupdate() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let server = Running::start(config(target.address)).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (blocked_tx, blocked_rx) = oneshot::channel();
    let (read_tx, read_rx) = oneshot::channel();
    let business = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (mut read, mut write) = socket.split();
        let writer = async {
            let bytes = [0x55; 65536];
            let mut sent = 0;
            let blocked = timeout(Duration::from_millis(500), async {
                for _ in 0..1024 {
                    write.write_all(&bytes).await.unwrap();
                    sent += bytes.len();
                }
            })
            .await
            .is_err();
            blocked_tx.send((blocked, sent)).unwrap();
            // 保持写端活着且继续不排出，不通过关闭解除背压。
            std::future::pending::<()>().await;
        };
        let reader = async {
            let mut bytes = [0; 25];
            read.read_exact(&mut bytes).await.unwrap();
            read_tx.send(bytes).unwrap();
            let mut rest = Vec::new();
            let _ = read.read_to_end(&mut rest).await;
        };
        tokio::select! { _ = writer => {}, _ = reader => {} }
    });
    let mut client = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    socket2::SockRef::from(&client.io)
        .set_recv_buffer_size(4096)
        .unwrap();
    let mut request = peer::vless_request(1, Some("xtls-rprx-vision"), peer::ID, address);
    request.extend(peer::vision_block(true, 1, &[], 0));
    client.send(&request).await.unwrap();
    assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
    let (blocked, sent) = timeout(LIMIT, blocked_rx).await.unwrap().unwrap();
    assert!(blocked, "下行必须真实达到背压，而不是只假设慢读");
    assert!(sent < 64 * 1024 * 1024);
    client.tls.refresh_traffic_keys().unwrap();
    client.send(b"uplink-while-backpressure").await.unwrap();
    let bytes = timeout(Duration::from_secs(2), read_rx)
        .await
        .expect("下行输出被阻塞时，已就绪入站 TLS record 仍须前进")
        .unwrap();
    assert_eq!(&bytes, b"uplink-while-backpressure");
    assert_eq!(server.stats.snapshot().uplink, bytes.len() as u64);
    let address = server.address;
    server.shutdown().await;
    timeout(LIMIT, business).await.unwrap().unwrap();
    let rebound = TcpListener::bind(address).await.unwrap();
    drop(rebound);
    drop(client);
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn truncated_tls_record_is_not_delivered_or_mistaken_for_direct_eof() {
    for partial in [0, 1, 4, 5, 9] {
        let target = TargetPeer::start(Default::default()).await.unwrap();
        let server = Running::start(config(target.address)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let business = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let _ = socket.read_to_end(&mut received).await;
            received
        });
        let mut client = PreparedClient::new(Default::default())
            .unwrap()
            .connect(server.address)
            .await
            .unwrap();
        let mut request = peer::vless_request(1, Some("xtls-rprx-vision"), peer::ID, address);
        request.extend(peer::vision_block(true, 1, b"complete", 0));
        client.send(&request).await.unwrap();
        assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
        io::Write::write_all(&mut client.tls.writer(), b"must-not-arrive").unwrap();
        let wire = output(&mut client);
        assert!(wire.len() > partial);
        client.io.write_all(&wire[..partial]).await.unwrap();
        // 不发 close_notify；0覆盖记录边界真截断，其他覆盖header/body截断。
        client.io.shutdown().await.unwrap();
        let received = timeout(LIMIT, business).await.unwrap().unwrap();
        assert_eq!(received, b"complete");
        drop(client);
        idle(&server).await;
        let stats = server.stats.snapshot();
        assert_eq!(stats.uplink, 8);
        assert_eq!(stats.downlink, 0);
        server.shutdown().await;
        target.shutdown().await.unwrap();
    }
}
