//! 独立 VMess WS/WSS 回环端；不调用生产协议编解码。
//! 正向业务均在 Close 前完成，不将 WS 关闭伪装成 TCP 单向 FIN。
#[path = "common/vmess.rs"]
mod client;
mod common;
#[path = "common/websocket.rs"]
mod ws;

use client::{Client, Request};
use common::{Certificate, Echo, Running, socks_config};
use serde_json::{Value, json};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

trait TestIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TestIo for T {}
type RawIo = Box<dyn TestIo>;
type Peer = ws::Peer<RawIo>;

fn config(cert: Option<&Certificate>) -> Value {
    let mut value = socks_config();
    let mut inbound = json!({
        "type":"vmess-ws", "tag":"vmess-ws", "listen":"127.0.0.1:0",
        "users":[{"name":"test", "uuid":client::UUID}],
        "websocket":{"path":"/proxy"}
    });
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    }
    value["inbounds"] = json!([inbound]);
    value["limits"]["handshake_timeout_ms"] = json!(1500);
    value["limits"]["udp_idle_timeout_ms"] = json!(5000);
    value
}

async fn raw_connect(addr: SocketAddr, cert: Option<&Certificate>) -> RawIo {
    if let Some(cert) = cert {
        Box::new(cert.connect(addr).await)
    } else {
        Box::new(TcpStream::connect(addr).await.unwrap())
    }
}

async fn connect(
    addr: SocketAddr,
    cert: Option<&Certificate>,
    headers: &str,
    raw_prefix: &[u8],
) -> Peer {
    ws::upgrade(raw_connect(addr, cert).await, "/proxy", headers, raw_prefix).await
}

async fn idle(server: &Running) {
    timeout(Duration::from_secs(3), async {
        loop {
            let stats = server.stats.snapshot();
            if stats.connections == 0 && stats.tcp_flows == 0 && stats.udp_associations == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("WS 会话及业务子任务应归还");
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// 只改变首个 VMess 认证头的传输布局，不理解或重编码协议。
// skip 字节已随 HTTP 后的原始 WS 帧发出，Client::start 不得再发第二遍。
struct HeaderIo {
    peer: Peer,
    skip: usize,
    remaining: usize,
    stride: usize,
}
impl AsyncRead for HeaderIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().peer).poll_read(cx, buf)
    }
}
impl AsyncWrite for HeaderIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.skip != 0 {
            let n = this.skip.min(bytes.len());
            this.skip -= n;
            return Poll::Ready(Ok(n));
        }
        let n = if this.remaining == 0 {
            bytes.len()
        } else {
            bytes.len().min(this.remaining).min(this.stride)
        };
        match Pin::new(&mut this.peer).poll_write(cx, &bytes[..n]) {
            Poll::Ready(Ok(n)) => {
                this.remaining = this.remaining.saturating_sub(n);
                Poll::Ready(Ok(n))
            }
            result => result,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().peer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().peer).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn ws_wss_security_three_four_options_first_payload_and_payload_only_accounting() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        value["inbounds"][0]["allow_authenticated_length"] = json!(true);
        let server = Running::start(value).await;
        let mut total = 0u64;
        for security in [3, 4] {
            for options in [0, 1, 4, 5, 12, 13, 16, 17, 20, 21, 28, 29] {
                let peer = connect(server.address, certificate, "", &[]).await;
                // 认证头和首载荷由独立测试端一次提交；响应头必须是真正 VMess AEAD。
                let first = b"first-binary\x00\xff";
                let mut client = Client::start(
                    peer,
                    Request::new(1, client::target(echo.address), security, options),
                    Some(first),
                )
                .await;
                let mut data = vec![0x73; 20001];
                data[16383..16387].copy_from_slice(b"edge");
                client.send(&data).await;
                let mut expected = first.to_vec();
                expected.extend(data);
                assert_eq!(
                    client.read(expected.len()).await,
                    expected,
                    "tls={tls},security={security},options={options}"
                );
                total += expected.len() as u64;
                // 不调用 finish：它最终 shutdown 底层，不能作为透明半关闭证据。
                client.io.close().await;
                ws::closed(&mut client.io).await;
            }
        }
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, total);
        assert_eq!(server.stats.snapshot().downlink, total);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_default_mask_padding_and_server_first_without_client_body() {
    let cert = Certificate::new();
    for (tls, allow_insecure_body) in [(false, false), (true, false), (false, true)] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        if allow_insecure_body {
            value["inbounds"][0]["allow_insecure_body"] = json!(true);
        }
        let server = Running::start(value).await;
        let mut matrix = vec![];
        for security in [3, 4] {
            for options in [0, 1, 4, 5, 12, 13] {
                matrix.push((security, options));
            }
        }
        if tls || allow_insecure_body {
            matrix.extend([(5, 0), (5, 1)]);
        }
        let exchanges = matrix.len();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            for _ in 0..exchanges {
                let (mut io, _) = listener.accept().await.unwrap();
                io.write_all(b"server-first").await.unwrap();
                let mut data = [0; 4];
                io.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"ping");
                io.write_all(b"pong").await.unwrap();
                // 收到客户端完整请求即回包，不等待客户端 EOF。
                let mut end = [0];
                let _ = io.read(&mut end).await;
            }
        });
        for (security, options) in matrix {
            let peer = connect(server.address, certificate, "", &[]).await;
            let mut client = Client::start(
                peer,
                Request::new(
                    1,
                    client::domain("localhost", addr.port()),
                    security,
                    options,
                ),
                None,
            )
            .await;
            assert_eq!(client.read(12).await, b"server-first");
            client.send(b"ping").await;
            assert_eq!(client.read(4).await, b"pong");
            client.io.close().await;
            ws::closed(&mut client.io).await;
            drop(client);
        }
        timeout(Duration::from_secs(3), target)
            .await
            .unwrap()
            .unwrap();
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, exchanges as u64 * 4);
        assert_eq!(server.stats.snapshot().downlink, exchanges as u64 * 16);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn security_five_needs_actual_wss_or_explicit_insecure_body_policy() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    for (tls, allow) in [(true, false), (false, true)] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        if allow {
            value["inbounds"][0]["allow_insecure_body"] = json!(true);
        }
        let server = Running::start(value).await;
        let mut total = 0;
        for options in [0, 1] {
            let peer = connect(server.address, certificate, "", &[]).await;
            let mut client = Client::start(
                peer,
                Request::new(1, client::target(echo.address), 5, options),
                Some(b"none-first\x00\xff"),
            )
            .await;
            assert_eq!(client.read(12).await, b"none-first\x00\xff");
            client.send(b"after").await;
            assert_eq!(client.read(5).await, b"after");
            total += 17;
            client.io.close().await;
            ws::closed(&mut client.io).await;
        }
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, total);
        assert_eq!(server.stats.snapshot().downlink, total);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = connect(server.address, certificate, "", &[]).await;
        let request = Request::new(1, client::target(target.local_addr().unwrap()), 3, 17);
        peer.send_message(2, &request.wire).await;
        ws::closed(&mut peer).await;
        assert!(
            timeout(Duration::from_millis(40), target.accept())
                .await
                .is_err()
        );
        // 真实 TLS 或 insecure-body=true 都不能隐式开启 authenticated-length。
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, total);
        assert_eq!(server.stats.snapshot().downlink, total);
        server.shutdown().await;
    }
    // 两个正文策略开关互不授予：A=true 不能让明文 WS 的 security5 安全。
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut value = config(None);
    value["inbounds"][0]["allow_authenticated_length"] = json!(true);
    let server = Running::start(value).await;
    for options in [0, 1] {
        let mut peer = connect(server.address, None, "", &[]).await;
        let request = Request::new(1, client::target(target.local_addr().unwrap()), 5, options);
        peer.send_message(2, &request.wire).await;
        ws::closed(&mut peer).await;
    }
    assert!(
        timeout(Duration::from_millis(40), target.accept())
            .await
            .is_err()
    );
    idle(&server).await;
    assert_eq!(server.stats.snapshot().uplink, 0);
    assert_eq!(server.stats.snapshot().downlink, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn ws_wss_http_tail_header_message_splits_continuations_and_coalesced_body_chunks() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        let server = Running::start(config(certificate)).await;
        let mut total = 0u64;
        for security in [3, 4] {
            for (split, stride) in [
                (0, 1),
                (1, 7),
                (15, 17),
                (16, 1),
                (17, 7),
                (33, 17),
                (34, 1),
                (41, 7),
                (42, 17),
                (usize::MAX, 1),
            ] {
                let request = Request::new(1, client::target(echo.address), security, 13);
                let prefix_len = split.min(request.wire.len());
                let mut raw_prefix = ws::masked(true, 2, &[]);
                raw_prefix.extend(ws::masked(true, 9, b"http-tail"));
                raw_prefix.extend(ws::masked(true, 2, &request.wire[..prefix_len]));
                let peer = connect(server.address, certificate, "", &raw_prefix).await;
                let io = HeaderIo {
                    peer,
                    skip: prefix_len,
                    remaining: request.wire.len() - prefix_len,
                    stride,
                };
                let mut client = Client::start(io, request, Some(b"first")).await;
                assert_eq!(client.read(5).await, b"first");
                // 一个 VMess chunk 跨多个完整 Binary 消息。
                let wire = client.wire(b"split-message");
                for byte in wire {
                    client.io.peer.send_message(2, &[byte]).await;
                }
                assert_eq!(client.read(13).await, b"split-message");
                // 两个 VMess chunk 合并为一个分片 Binary 消息；控制帧不属于正文。
                let mut wire = client.wire(b"one");
                wire.extend(client.wire(b"two"));
                let middle = wire.len() / 2;
                client
                    .io
                    .peer
                    .send_fragment(false, 2, &wire[..middle])
                    .await;
                client.io.peer.send_message(9, b"between-fragments").await;
                client.io.peer.send_fragment(true, 0, &wire[middle..]).await;
                client.io.peer.send_message(2, &[]).await;
                assert_eq!(client.read(6).await, b"onetwo");
                // 空 WS 消息不是正文 EOF，后续请求必须仍可用。
                client.send(b"after-empty").await;
                assert_eq!(client.read(11).await, b"after-empty");
                total += 35;
                client.io.peer.close().await;
                ws::closed(&mut client.io.peer).await;
            }
        }
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, total);
        assert_eq!(server.stats.snapshot().downlink, total);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_native_udp_ipv4_ipv6_chunk_boundaries_not_websocket_message_boundaries() {
    let v4 = Echo::udp("127.0.0.1").await;
    let v6 = Echo::udp("::1").await;
    let cert = Certificate::new();
    for (tls, allow_insecure_body) in [(false, false), (true, false), (false, true)] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        value["inbounds"][0]["allow_authenticated_length"] = json!(true);
        if allow_insecure_body {
            value["inbounds"][0]["allow_insecure_body"] = json!(true);
        }
        let server = Running::start(value).await;
        let mut total = 0u64;
        for address in [v4.address, v6.address] {
            let matrix: &[(u8, u8)] = if tls || allow_insecure_body {
                &[(3, 0), (3, 13), (3, 29), (4, 1), (4, 5), (4, 28), (5, 1)]
            } else {
                &[(3, 0), (3, 13), (3, 29), (4, 1), (4, 5), (4, 28)]
            };
            for &(security, options) in matrix {
                let peer = connect(server.address, certificate, "", &[]).await;
                let mut client = Client::start(
                    peer,
                    Request::new(2, client::target(address), security, options),
                    Some(b"first-datagram\x00\xff"),
                )
                .await;
                assert_eq!(client.recv().await, b"first-datagram\x00\xff");
                total += 16;
                let a = b"one";
                let b = vec![0x5a; 4096];
                let mut wire = client.wire(a);
                wire.extend(client.wire(&b));
                wire.extend(client.wire(b"three"));
                // 三个包同一 WS 消息，仍须逐包收回；不得当作一个 UDP 包。
                client.io.send_message(2, &wire).await;
                for expected in [a.as_slice(), b.as_slice(), b"three"] {
                    assert_eq!(client.recv().await, expected);
                    total += expected.len() as u64;
                }
                // 一个包的长度、tag 和载荷跨多条 WS 消息。
                let wire = client.wire(b"split-packet");
                for chunk in wire.chunks(3) {
                    client.io.send_message(2, chunk).await;
                }
                assert_eq!(client.recv().await, b"split-packet");
                total += 12;
                // 只发 VMess 原生终止块，不调用会底层 shutdown 的 finish。
                client.send(&[]).await;
                ws::closed(&mut client.io).await;
            }
        }
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, total);
        assert_eq!(server.stats.snapshot().downlink, total);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_packetaddr_explicit_enable_per_packet_v4_v6_sources_and_empty_payload() {
    let v4 = Echo::udp("127.0.0.1").await;
    let v6 = Echo::udp("::1").await;
    let cert = Certificate::new();
    for (tls, allow_insecure_body) in [(false, false), (true, false), (false, true)] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        value["inbounds"][0]["packetaddr"] = json!(true);
        if allow_insecure_body {
            value["inbounds"][0]["allow_insecure_body"] = json!(true);
        }
        let server = Running::start(value).await;
        let mut total = 0u64;
        let matrix: &[(u8, u8)] = if tls || allow_insecure_body {
            &[(3, 13), (4, 13), (5, 1)]
        } else {
            &[(3, 13), (4, 13)]
        };
        for &(security, options) in matrix {
            let peer = connect(server.address, certificate, "", &[]).await;
            let mut client = Client::start(
                peer,
                Request::new(
                    2,
                    client::domain("sp.packet-addr.v2fly.arpa", 0),
                    security,
                    options,
                ),
                None,
            )
            .await;
            // 同一承载交替实际 IPv4/IPv6 目标；回复须含该包的真实来源。
            for (address, payload) in [
                (v4.address, b"v4-first".as_slice()),
                (v6.address, b"v6-next".as_slice()),
                (v4.address, b"".as_slice()),
                (v6.address, b"".as_slice()),
            ] {
                let packet = client::packetaddr(address, payload);
                let wire = client.wire(&packet);
                for chunk in wire.chunks(2) {
                    client.io.send_message(2, chunk).await;
                }
                assert_eq!(client.recv().await, packet);
                total += payload.len() as u64;
            }
            let a = client::packetaddr(v6.address, b"coalesced-v6");
            let b = client::packetaddr(v4.address, b"coalesced-v4");
            let mut wire = client.wire(&a);
            wire.extend(client.wire(&b));
            client.io.send_message(2, &wire).await;
            let mut replies = vec![client.recv().await, client.recv().await];
            let mut expected = vec![a, b];
            replies.sort();
            expected.sort();
            assert_eq!(replies, expected);
            total += 24;
            client.io.close().await;
            ws::closed(&mut client.io).await;
        }
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, total);
        assert_eq!(server.stats.snapshot().downlink, total);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_xudp_explicit_enable_v4_v6_switch_frames_split_and_merged() {
    let v4 = Echo::udp("127.0.0.1").await;
    let v6 = Echo::udp("::1").await;
    let cert = Certificate::new();
    for (tls, allow_insecure_body) in [(false, false), (true, false), (false, true)] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        value["inbounds"][0]["xudp"] = json!(true);
        if allow_insecure_body {
            value["inbounds"][0]["allow_insecure_body"] = json!(true);
        }
        let server = Running::start(value).await;
        let mut total = 0u64;
        let matrix: &[(u8, u8)] = if tls || allow_insecure_body {
            &[(3, 13), (4, 5), (5, 0), (5, 1)]
        } else {
            &[(3, 13), (4, 5)]
        };
        for &(security, options) in matrix {
            let peer = connect(server.address, certificate, "", &[]).await;
            let first = client::xframe_gid(
                7,
                1,
                Some(client::target(v4.address)),
                [0x11; 8],
                Some(b"first"),
            );
            let mut client = Client::start(
                peer,
                Request::new(3, vec![], security, options),
                Some(&first),
            )
            .await;
            client::xexpect(&mut client, 7, v4.address, b"first").await;
            total += 5;
            // 不同 session 同一 Binary，且 session 7 临时改写该包的目标。
            let mut frames = client::xframe(
                9,
                1,
                Some(client::target(v4.address)),
                false,
                Some(b"other"),
            );
            frames.extend(client::xframe(
                7,
                2,
                Some(client::target(v6.address)),
                false,
                Some(b"switch-v6"),
            ));
            let wire = client.wire(&frames);
            client.io.send_message(2, &wire).await;
            let mut replies = vec![];
            for _ in 0..2 {
                replies.push(client::xrecv(&mut client).await);
            }
            let mut v4_header = vec![0, 9, 2, 1, 2];
            v4_header.extend(client::target(v4.address));
            let mut v6_header = vec![0, 7, 2, 1, 2];
            v6_header.extend(client::target(v6.address));
            let mut expected = vec![
                (v4_header, b"other".to_vec()),
                (v6_header, b"switch-v6".to_vec()),
            ];
            replies.sort();
            expected.sort();
            assert_eq!(replies, expected);
            total += 14;
            // XUDP 帧逐字节放进独立 VMess chunk；每块又跨 WS 消息。
            // 无 address 的 KEEP 应回到 session 的初始 v4 目标。
            let frame = client::xframe(7, 2, None, false, Some(b"initial"));
            for byte in frame {
                let wire = client.wire(&[byte]);
                let middle = wire.len() / 2;
                client.io.send_message(2, &wire[..middle]).await;
                client.io.send_message(2, &wire[middle..]).await;
            }
            client::xexpect(&mut client, 7, v4.address, b"initial").await;
            total += 7;
            client.send(&client::xframe(7, 3, None, false, None)).await;
            client
                .send(&client::xframe_gid(
                    7,
                    1,
                    Some(client::target(v6.address)),
                    [0x11; 8],
                    Some(b"reuse"),
                ))
                .await;
            client::xexpect(&mut client, 7, v6.address, b"reuse").await;
            total += 5;
            client.io.close().await;
            ws::closed(&mut client.io).await;
        }
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, total);
        assert_eq!(server.stats.snapshot().downlink, total);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn xudp_packetaddr_flags_are_independent_and_do_not_grant_body_or_length_policy() {
    let cert = Certificate::new();
    let echo = Echo::udp("127.0.0.1").await;
    let tcp_echo = Echo::tcp("127.0.0.1", false).await;
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        for (xudp, packetaddr) in [(false, false), (true, false), (false, true)] {
            let mut value = config(certificate);
            value["inbounds"][0]["xudp"] = json!(xudp);
            value["inbounds"][0]["packetaddr"] = json!(packetaddr);
            let server = Running::start(value).await;

            // 命令 3 始终是 Mux；xudp 只门控其 UDP 会话。
            let peer = connect(server.address, certificate, "", &[]).await;
            let mut client = Client::start(peer, Request::new(3, vec![], 3, 1), None).await;
            if xudp {
                client
                    .send(&client::xframe(
                        1,
                        1,
                        Some(client::target(echo.address)),
                        false,
                        Some(b"enabled"),
                    ))
                    .await;
                client::xexpect(&mut client, 1, echo.address, b"enabled").await;
            } else {
                let mut frame = client::xframe(
                    1,
                    1,
                    Some(client::target(tcp_echo.address)),
                    false,
                    Some(b"enabled"),
                );
                frame[6] = 1;
                client.send(&frame).await;
                let (metadata, payload) = client::xrecv(&mut client).await;
                assert_eq!(metadata, [0, 1, 2, 1]);
                assert_eq!(payload, b"enabled");
            }
            client.io.close().await;
            ws::closed(&mut client.io).await;

            // packetaddr 是命令 2 的独立扩展，不受 xudp 或 Mux 影响。
            if packetaddr {
                let peer = connect(server.address, certificate, "", &[]).await;
                let mut client = Client::start(
                    peer,
                    Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 4, 13),
                    None,
                )
                .await;
                let packet = client::packetaddr(echo.address, b"enabled");
                client.send(&packet).await;
                assert_eq!(client.recv().await, packet);
                client.io.close().await;
                ws::closed(&mut client.io).await;
            } else {
                let mut peer = connect(server.address, certificate, "", &[]).await;
                peer.send_message(
                    2,
                    &Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 4, 13).wire,
                )
                .await;
                ws::closed(&mut peer).await;
            }

            let mut denied = vec![Request::new(
                1,
                client::target(tcp.local_addr().unwrap()),
                3,
                17,
            )];
            if !tls {
                denied.push(Request::new(
                    1,
                    client::target(tcp.local_addr().unwrap()),
                    5,
                    1,
                ));
            }
            for request in denied {
                let mut peer = connect(server.address, certificate, "", &[]).await;
                peer.send_message(2, &request.wire).await;
                ws::closed(&mut peer).await;
            }
            no_target_io(&tcp, &udp).await;
            idle(&server).await;
            // 命令 3 的 TCP 或 UDP 会话都计 7 字节；packetaddr 另计 7 字节。
            let expected = 7 + if packetaddr { 7 } else { 0 };
            assert_eq!(server.stats.snapshot().uplink, expected);
            assert_eq!(server.stats.snapshot().downlink, expected);
            server.shutdown().await;
        }
    }
}

#[tokio::test]
async fn same_server_replay_authid_and_session_material_shared_across_ws_wss_and_old_vmess() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let dials = Arc::new(AtomicUsize::new(0));
    let accepted = dials.clone();
    let mut targets = tokio::task::JoinSet::new();
    targets.spawn(async move {
        let mut flows = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted_stream = listener.accept() => {
                    let (mut io, _) = accepted_stream.unwrap();
                    accepted.fetch_add(1, Ordering::Relaxed);
                    flows.spawn(async move {
                        let (mut read, mut write) = io.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
                _ = flows.join_next(), if !flows.is_empty() => {}
            }
        }
    });
    let cert = Certificate::new();
    let mut value = config(None);
    let mut wss = config(Some(&cert))["inbounds"][0].clone();
    wss["tag"] = json!("vmess-wss");
    let mut old_tls = json!({
        "type":"vmess", "tag":"old-vmess-tls", "listen":"127.0.0.1:0",
        "users":[{"name":"different-name", "uuid":client::UUID}]
    });
    old_tls["certificate"] = json!(cert.dir.path().join("cert.pem"));
    old_tls["private_key"] = json!(cert.dir.path().join("key.pem"));
    value["inbounds"].as_array_mut().unwrap().extend([
        wss,
        json!({
            "type":"vmess", "tag":"old-vmess", "listen":"127.0.0.1:0",
            "users":[{"name":"old-name", "uuid":client::UUID}]
        }),
        old_tls,
    ]);
    let server = Running::start(value).await;
    // 四种承载各自首先成功，然后在同一 Server 的其余所有入口拒重放。
    // 名称不同但 UUID 相同，重放域不得按 tag、用户显示名或连接切分。
    for source in 0..4 {
        let certificate = matches!(source, 1 | 3).then_some(&cert);
        let raw = raw_connect(server.addresses[source], certificate).await;
        let io: RawIo = if source < 2 {
            Box::new(ws::upgrade(raw, "/proxy", "", &[]).await)
        } else {
            raw
        };
        let request = Request::new(1, client::target(address), 3, 1);
        let mut live = Client::start(io, request.clone(), Some(b"first")).await;
        assert_eq!(live.read(5).await, b"first");
        for destination in 0..4 {
            let certificate = matches!(destination, 1 | 3).then_some(&cert);
            for replay in [
                request.clone(),
                // 新 AuthID/connection nonce，不同于逐字节重放；key/iv 相同也须拒绝。
                Request::at(
                    1,
                    client::target(address),
                    3,
                    1,
                    client::ID,
                    now(),
                    Some((request.key, request.iv)),
                ),
            ] {
                let raw = raw_connect(server.addresses[destination], certificate).await;
                if destination < 2 {
                    let mut peer =
                        ws::upgrade(raw, "/proxy", "", &ws::masked(true, 2, &replay.wire)).await;
                    ws::closed(&mut peer).await;
                } else {
                    let mut raw = raw;
                    raw.write_all(&replay.wire).await.unwrap();
                    raw.flush().await.unwrap();
                    client::closed(&mut raw).await;
                }
            }
        }
        live.send(b"still-live").await;
        assert_eq!(live.read(10).await, b"still-live");
        drop(live);
    }
    idle(&server).await;
    assert_eq!(server.stats.snapshot().uplink, 60);
    assert_eq!(server.stats.snapshot().downlink, 60);
    assert_eq!(dials.load(Ordering::Relaxed), 4, "重放不得额外拨号");
    server.shutdown().await;
    targets.abort_all();
    while targets.join_next().await.is_some() {}
}

#[tokio::test]
async fn ws_wss_reject_precedes_tcp_native_udp_success_reply_and_target_io() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cert = Certificate::new();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        value["route"]["default"] = json!("reject");
        let server = Running::start(value).await;
        let mut count = 0;
        for security in [3, 4] {
            for (command, target) in [
                (1, client::target(tcp.local_addr().unwrap())),
                (
                    1,
                    client::domain("localhost", tcp.local_addr().unwrap().port()),
                ),
                (2, client::target(udp.local_addr().unwrap())),
                (
                    2,
                    client::domain("localhost", udp.local_addr().unwrap().port()),
                ),
            ] {
                let request = Request::new(command, target, security, 13);
                let mut peer = connect(server.address, certificate, "", &[]).await;
                peer.send_message(2, &request.wire).await;
                // 认证已成功；VMess 响应头可能先于路由拒绝写出，仅要求最终结束。
                ws::closed_after_optional_response(&mut peer).await;
                count += 1;
            }
        }
        no_target_io(&tcp, &udp).await;
        idle(&server).await;
        assert_eq!(server.stats.snapshot().rejected, count);
        assert_eq!(server.stats.snapshot().uplink, 0);
        assert_eq!(server.stats.snapshot().downlink, 0);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_udp_extension_rejects_each_target_without_datagram_or_payload_success() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
    let cert = Certificate::new();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        value["inbounds"][0]["xudp"] = json!(true);
        value["inbounds"][0]["packetaddr"] = json!(true);
        value["route"]["default"] = json!("reject");
        let server = Running::start(value).await;
        let mut rejected = 0;
        for xudp in [false, true] {
            let request = if xudp {
                Request::new(3, vec![], 3, 13)
            } else {
                Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 4, 5)
            };
            let peer = connect(server.address, certificate, "", &[]).await;
            // cmd3/packetaddr 的认证头不含业务目标，合法 VMess 响应不代表某包路由成功。
            let mut client = Client::start(peer, request, None).await;
            for address in [v4.local_addr().unwrap(), v6.local_addr().unwrap()] {
                let previous = server.stats.snapshot().rejected;
                let payload = if xudp {
                    client::xframe(7, 1, Some(client::target(address)), false, Some(b"reject"))
                } else {
                    client::packetaddr(address, b"reject")
                };
                client.send(&payload).await;
                timeout(Duration::from_secs(2), async {
                    while server.stats.snapshot().rejected == previous {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("扩展逐包目标应经过 Reject 路由");
                if xudp {
                    // XUDP 允许明确的错误 END；它不是业务成功数据，须先独立验证。
                    let (metadata, payload) = client::xrecv(&mut client).await;
                    assert_eq!(metadata, [0, 7, 3, 2]);
                    assert!(payload.is_empty());
                }
                rejected += 1;
            }
            if !xudp {
                // 原生VMess数据报用自身已认证终止块结束；WS Close不能代替正文EOF。
                client.send(&[]).await;
                idle(&server).await;
                ws::closed(&mut client.io).await;
                continue;
            }
            client.io.close().await;
            ws::closed(&mut client.io).await;
        }
        no_target_io(&tcp, &v4).await;
        assert!(
            timeout(Duration::from_millis(40), v6.recv_from(&mut [0; 64]))
                .await
                .is_err()
        );
        idle(&server).await;
        assert_eq!(server.stats.snapshot().rejected, rejected);
        assert_eq!(server.stats.snapshot().uplink, 0);
        assert_eq!(server.stats.snapshot().downlink, 0);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn ws_wss_bad_body_tag_packetaddr_header_and_tcp_mux_target_tracking() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_echo = Echo::tcp("127.0.0.1", false).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap();
    let cert = Certificate::new();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        let mut value = config(certificate);
        value["inbounds"][0]["xudp"] = json!(true);
        value["inbounds"][0]["packetaddr"] = json!(true);
        let server = Running::start(value).await;
        for security in [3, 4] {
            let peer = connect(server.address, certificate, "", &[]).await;
            let mut client = Client::start(
                peer,
                Request::new(2, client::target(address), security, 1),
                None,
            )
            .await;
            let mut bad = client.wire(b"bad-tag");
            *bad.last_mut().unwrap() ^= 1;
            client.io.send_message(2, &bad).await;
            ws::closed(&mut client.io).await;
        }
        for bad in [
            vec![1, 127, 0],
            vec![2; 18],
            vec![3; 19],
            vec![1, 127, 0, 0, 1, 0, 0],
        ] {
            let peer = connect(server.address, certificate, "", &[]).await;
            let mut client = Client::start(
                peer,
                Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 3, 1),
                None,
            )
            .await;
            // 一条 WS 消息中坏 chunk 后紧邻合法 chunk，不得跨 chunk 补齐坏地址。
            let mut wire = client.wire(&bad);
            wire.extend(client.wire(&client::packetaddr(address, b"must-not-arrive")));
            client.io.send_message(2, &wire).await;
            ws::closed(&mut client.io).await;
        }
        let peer = connect(server.address, certificate, "", &[]).await;
        let mut client = Client::start(peer, Request::new(3, vec![], 4, 5), None).await;
        let mut frame = client::xframe(
            9,
            1,
            Some(client::target(tcp_echo.address)),
            false,
            Some(b"tcp"),
        );
        frame[6] = 1; // network=TCP：命令 3 的完整 Mux 会话。
        client.send(&frame).await;
        assert_eq!(
            client::xrecv(&mut client).await,
            (vec![0, 9, 2, 1], b"tcp".to_vec())
        );
        client.io.close().await;
        ws::closed(&mut client.io).await;
        // 受控 UDP 目标与未使用的监听仍未收到任何连接/数据报。
        no_target_io(&tcp, &udp).await;
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, 3);
        assert_eq!(server.stats.snapshot().downlink, 3);
        server.shutdown().await;
    }
}

async fn no_target_io(tcp: &TcpListener, udp: &UdpSocket) {
    assert!(
        timeout(Duration::from_millis(40), tcp.accept())
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(40), udp.recv_from(&mut [0; 64]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn ws_wss_invalid_identity_time_aead_security_options_and_default_extensions_never_reply() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cert = Certificate::new();
    for tls in [false, true] {
        let certificate = tls.then_some(&cert);
        let server = Running::start(config(certificate)).await;
        let timestamp = now();
        let mut requests = vec![
            Request::at(1, client::target(addr), 3, 1, [0x33; 16], timestamp, None),
            Request::at(
                1,
                client::target(addr),
                3,
                1,
                client::ID,
                timestamp - 121,
                None,
            ),
            Request::at(
                1,
                client::target(addr),
                3,
                1,
                client::ID,
                timestamp + 3600,
                None,
            ),
            Request::new(1, client::target(addr), 3, 17),
            Request::new(1, client::target(addr), 4, 29),
            // 命令 3 现在合法进入 Mux，不能放入“必须无成功响应”的列表。
            Request::new(2, client::domain("sp.packet-addr.v2fly.arpa", 0), 3, 1),
            Request::new(1, client::target(addr), 5, 5),
            Request::new(2, client::target(udp.local_addr().unwrap()), 5, 0),
            Request::new(0, client::target(addr), 3, 1),
            Request::new(4, client::target(addr), 3, 1),
        ];
        if !tls {
            requests.push(Request::new(1, client::target(addr), 5, 0));
            requests.push(Request::new(1, client::target(addr), 5, 1));
        }
        for security in [0, 1, 2, 6, 15] {
            requests.push(Request::new(1, client::target(addr), security, 1));
        }
        for options in [2, 8, 9, 32, 255] {
            requests.push(Request::new(1, client::target(addr), 3, options));
        }
        for offset in [0, 16, 34, usize::MAX] {
            let mut request = Request::new(1, client::target(addr), 3, 1);
            let offset = offset.min(request.wire.len() - 1);
            request.wire[offset] ^= 1;
            requests.push(request);
        }
        // localhost 是本地正向域名路径；此处只观察目标 IO，不冒称自持 DNS 查询计数。
        requests.push(Request::at(
            1,
            client::domain("localhost", addr.port()),
            3,
            1,
            [0x33; 16],
            timestamp,
            None,
        ));
        for request in requests {
            let raw_prefix = ws::masked(true, 2, &request.wire);
            let mut peer = connect(server.address, certificate, "", &raw_prefix).await;
            // HTTP 101 不是代理成功；任何 VMess/VLESS 成功字节均使断言失败。
            ws::closed(&mut peer).await;
        }
        for end in [1, 15, 16, 33, 34, 41, 42, usize::MAX] {
            let request = Request::new(1, client::target(addr), 3, 1);
            let end = end.min(request.wire.len() - 1);
            let mut peer = connect(
                server.address,
                certificate,
                "",
                &ws::masked(true, 2, &request.wire[..end]),
            )
            .await;
            peer.close().await;
            ws::closed(&mut peer).await;
        }
        no_target_io(&tcp, &udp).await;
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, 0);
        assert_eq!(server.stats.snapshot().downlink, 0);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn forwarded_headers_do_not_make_cleartext_ws_security_five_or_authenticated_length_safe() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = Running::start(config(None)).await;
    for headers in [
        "Forwarded: for=127.0.0.1;proto=https;host=localhost\r\n",
        "X-Forwarded-Proto: https\r\nX-Forwarded-Ssl: on\r\n",
        "Forwarded: proto=https\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Port: 443\r\n",
    ] {
        for (command, target, security, options) in [
            (1, client::target(tcp.local_addr().unwrap()), 5, 0),
            (1, client::target(tcp.local_addr().unwrap()), 5, 1),
            (2, client::target(udp.local_addr().unwrap()), 5, 1),
            (1, client::target(tcp.local_addr().unwrap()), 3, 17),
        ] {
            let request = Request::new(command, target, security, options);
            let mut peer = connect(
                server.address,
                None,
                headers,
                &ws::masked(true, 2, &request.wire),
            )
            .await;
            ws::closed(&mut peer).await;
        }
    }
    no_target_io(&tcp, &udp).await;
    idle(&server).await;
    assert_eq!(server.stats.snapshot().uplink, 0);
    assert_eq!(server.stats.snapshot().downlink, 0);
    server.shutdown().await;
}
