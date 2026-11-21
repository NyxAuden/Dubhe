//! D6 的有限关闭证据：协议自身 EOF 与 WS 会话 Close 不可混同。
//! 所有跨向顺序均由目标 IO 和 oneshot 屏障确定，不依赖 sleep 或随机竞态。
#[path = "common/vmess.rs"]
mod client;
mod common;
#[path = "common/websocket.rs"]
mod ws;

use client::{Client, Request};
use common::{Certificate, PASSWORD, Running, read_exact, socks_config, trojan_header};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);
const VLESS_UUID: &str = "11111111-1111-1111-1111-111111111111";

fn config(protocol: &str, cert: Option<&Certificate>) -> Value {
    let mut value = socks_config();
    let mut inbound = json!({
        "type":protocol, "tag":"ws-eof", "listen":"127.0.0.1:0",
        "websocket":{"path":"/proxy"}
    });
    inbound["users"] = match protocol {
        "vmess-ws" => json!([{"name":"test","uuid":client::UUID}]),
        "vless-ws" => json!([{"name":"test","uuid":VLESS_UUID}]),
        "trojan-ws" => json!([{"name":"test","password":PASSWORD}]),
        _ => unreachable!(),
    };
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    } else if protocol != "vmess-ws" {
        inbound["allow_insecure_transport"] = json!(true);
    }
    value["inbounds"] = json!([inbound]);
    value["limits"]["handshake_timeout_ms"] = json!(2000);
    value
}

fn vless_header(addr: SocketAddr) -> Vec<u8> {
    let std::net::IpAddr::V4(ip) = addr.ip() else {
        unreachable!();
    };
    let mut bytes = vec![0];
    bytes.extend([0x11; 16]);
    bytes.extend([0, 1]);
    bytes.extend(addr.port().to_be_bytes());
    bytes.push(1);
    bytes.extend(ip.octets());
    bytes
}

async fn idle(server: &Running) {
    timeout(WAIT, async {
        loop {
            let stats = server.stats.snapshot();
            if stats.connections == 0 && stats.tcp_flows == 0 && stats.udp_associations == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("关闭后的连接与业务任务必须有限结束");
}

#[tokio::test]
async fn vmess_authenticated_body_eof_keeps_ws_active_for_the_other_direction() {
    let cert = Certificate::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Running::start(config("vmess-ws", Some(&cert))).await;
    let (fin_seen, fin_received) = oneshot::channel();
    let (allow_reply, reply_allowed) = oneshot::channel();
    let (allow_target_end, target_end_allowed) = oneshot::channel();
    let uplink = b"payload-before-authenticated-eof";
    let downlink = b"target-reply-only-after-fin";

    let target = async {
        let (mut io, _) = listener.accept().await.unwrap();
        let mut bytes = vec![0; uplink.len()];
        read_exact(&mut io, &mut bytes).await;
        assert_eq!(bytes, uplink);
        let mut byte = [0];
        assert_eq!(io.read(&mut byte).await.unwrap(), 0);
        fin_seen.send(()).unwrap();
        // 读向已收到真正 FIN，但不关闭目标写向，明确让 WS 仍有下行可传。
        reply_allowed.await.unwrap();
        io.write_all(downlink).await.unwrap();
        io.flush().await.unwrap();
        target_end_allowed.await.unwrap();
        io.shutdown().await.unwrap();
    };
    let proxy_client = async {
        let io = cert.connect(server.address).await;
        io.get_ref().0.set_nodelay(true).unwrap();
        let peer = ws::upgrade(io, "/proxy", "", &[]).await;
        // security=3 的空正文块含真实 AEAD tag，不是空 WS 消息或私有 EOF。
        let mut client = Client::start(
            peer,
            Request::new(1, client::target(addr), 3, 1),
            Some(uplink),
        )
        .await;
        let eof = client.wire(&[]);
        assert_eq!(eof.len(), 18, "2 字节长度加空明文的 16 字节认证 tag");
        client.io.send_message(2, &eof).await;
        // 不调用 Client::finish，它会额外 shutdown 底层，不能证明本场景。
        fin_received.await.unwrap();
        assert_eq!(server.stats.snapshot().connections, 1);
        assert_eq!(server.stats.snapshot().tcp_flows, 1);
        client.io.send_message(9, b"ws-still-active").await;
        allow_reply.send(()).unwrap();
        assert_eq!(client.read(downlink.len()).await, downlink);
        // 目标尚未结束写向，此处业务回包证明 VMess EOF 没有变成 WS Close。
        allow_target_end.send(()).unwrap();
        client.eof().await;
        // 原 Writer 在回程 EOF 后仍 shutdown 承载；不扩称通用透明半关闭。
        ws::closed(&mut client.io).await;
    };
    timeout(WAIT, async { tokio::join!(target, proxy_client) })
        .await
        .expect("VMess 协议 EOF、下行回包与最终关闭必须有限完成");
    idle(&server).await;
    assert_eq!(server.stats.snapshot().uplink, uplink.len() as u64);
    assert_eq!(server.stats.snapshot().downlink, downlink.len() as u64);
    server.shutdown().await;
}

#[tokio::test]
async fn vless_and_trojan_ws_close_is_not_a_transparent_tcp_half_close() {
    let uplink = b"request-for-an-eof-dependent-application";
    let late_reply = b"reply-generated-only-after-client-fin";
    for protocol in ["vless-ws", "trojan-ws"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Running::start(config(protocol, None)).await;
        let (body_seen, body_received) = oneshot::channel();
        let (fin_seen, fin_received) = oneshot::channel();
        let (allow_reply, reply_allowed) = oneshot::channel();
        let target = async {
            let (mut io, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; uplink.len()];
            read_exact(&mut io, &mut bytes).await;
            assert_eq!(bytes, uplink);
            body_seen.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(io.read(&mut byte).await.unwrap(), 0);
            fin_seen.send(()).unwrap();
            // 应用只有 FIN 后才能生产回包；再用屏障排除 Close 前抢跑的时序。
            reply_allowed.await.unwrap();
            let _ = io.write_all(late_reply).await;
            let _ = io.flush().await;
            let _ = io.shutdown().await;
        };
        let proxy_client = async {
            let io = TcpStream::connect(server.address).await.unwrap();
            io.set_nodelay(true).unwrap();
            let mut bytes = if protocol == "vless-ws" {
                vless_header(addr)
            } else {
                trojan_header(1, common::address(addr), PASSWORD)
            };
            bytes.extend(uplink);
            let mut peer = ws::upgrade(io, "/proxy", "", &ws::masked(true, 2, &bytes)).await;
            if protocol == "vless-ws" {
                let mut response = [0xff; 2];
                read_exact(&mut peer, &mut response).await;
                assert_eq!(response, [0, 0]);
            }
            body_received.await.unwrap();
            peer.close().await;
            // 只接受会话结束或真实终止错误，不接受伪造成功字节/回显头。
            ws::closed(&mut peer).await;
            fin_received.await.unwrap();
            allow_reply.send(()).unwrap();
            ws::closed(&mut peer).await;
        };
        timeout(WAIT, async { tokio::join!(target, proxy_client) })
            .await
            .expect("EOF 依赖目标与 WS 会话 Close 必须有限结束");
        idle(&server).await;
        assert_eq!(server.stats.snapshot().uplink, uplink.len() as u64);
        assert_eq!(
            server.stats.snapshot().downlink,
            0,
            "Close 后迟到回包不得被伪造为已成功转发的业务"
        );
        server.shutdown().await;
    }
}
