//! mKCP 出站公开配置回环测试；使用真实 Server，不构造替身 Context。
//!
//! 底层 Driver/recv 的自然退出、错误保持、过滤、取消与端口回收边界另见
//! `src/transport/kcp_client.rs` 内的单元测试。本文件与这些用例均只补写，
//! 由主线程在完整接线后统一编译、执行。

mod common;

use std::{net::SocketAddr, time::Duration};

use common::{Certificate, Echo, Running};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const WAIT: Duration = Duration::from_secs(3);

fn upstream(inbound: Value) -> Value {
    json!({
        "version": 1,
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 2000}
    })
}

fn downstream(outbound: Value) -> Value {
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [outbound],
        "route": {"default": "up"},
        "limits": {
            "shutdown_timeout_ms": 100,
            "handshake_timeout_ms": 2000,
            "dial_timeout_ms": 1000
        }
    })
}

fn vless_inbound(kcp: Value) -> Value {
    json!({
        "type": "vless-kcp", "tag": "kcp-up", "listen": "127.0.0.1:0",
        "users": [{"name": "test", "uuid": UUID}],
        "allow_insecure_transport": true,
        "kcp": kcp
    })
}

fn vless_outbound(peer: SocketAddr, kcp: Value) -> Value {
    json!({
        "type": "vless", "tag": "up", "endpoint": peer.to_string(), "uuid": UUID,
        "transport": {"type": "kcp", "kcp": kcp}
    })
}

fn tls(cert: &Certificate) -> Value {
    json!({
        "ca_file": cert.dir.path().join("cert.pem"),
        "server_name": "localhost"
    })
}

async fn tcp_tunnel(server: SocketAddr, target: SocketAddr) -> TcpStream {
    timeout(WAIT, common::socks(1, common::address(target), server))
        .await
        .expect("SOCKS 经 mKCP 建连超时")
        .0
}

async fn exchange(stream: &mut TcpStream, payload: &[u8]) {
    timeout(WAIT, async {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut received = vec![0; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
    })
    .await
    .expect("mKCP 双向数据超时");
}

async fn assert_tcp_relay(kcp: Value) {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let up = Running::start(upstream(vless_inbound(kcp.clone()))).await;
    let down = Running::start(downstream(vless_outbound(up.address, kcp))).await;
    let mut first = tcp_tunnel(down.address, echo.address).await;
    let mut second = tcp_tunnel(down.address, echo.address).await;
    exchange(&mut first, b"first kcp connection").await;
    exchange(&mut second, b"second independent conversation").await;
    // 超过普通 UDP 最大载荷，覆盖驱动按 MTU 分包与双向可靠重组。
    let payload: Vec<u8> = (0..96_000).map(|index| (index % 251) as u8).collect();
    exchange(&mut first, &payload).await;
    drop(first);
    exchange(&mut second, b"dropping first must not stop second").await;
    drop(second);
    down.shutdown().await;
    let address = up.address;
    up.shutdown().await;
    drop(common::rebind_udp(address).await);
}

#[tokio::test]
async fn vless_kcp_outbound_is_bidirectional_in_legacy_and_raw_modes() {
    for security in ["legacy", "none"] {
        assert_tcp_relay(json!({"security": security, "tti": 10})).await;
    }
}

#[tokio::test]
async fn vless_kcp_outbound_composes_all_masks_with_seed() {
    for header in [
        json!({"type": "none"}),
        json!({"type": "srtp"}),
        json!({"type": "utp"}),
        json!({"type": "wireguard"}),
        json!({"type": "dtls"}),
        json!({"type": "wechat"}),
        json!({"type": "dns", "domain": "kcp.example.com"}),
    ] {
        assert_tcp_relay(json!({
            "header": header, "seed": "outbound-kcp-seed", "tti": 10
        }))
        .await;
    }
}

#[tokio::test]
async fn vmess_and_tls_trojan_use_the_same_kcp_reliable_stream() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    for protocol in ["vmess", "trojan"] {
        let mut inbound = json!({
            "type": format!("{protocol}-kcp"), "tag": "kcp-up", "listen": "127.0.0.1:0",
            "kcp": {"tti": 10}
        });
        let mut outbound = json!({
            "type": protocol, "tag": "up",
            "transport": {"type": "kcp", "kcp": {"tti": 10}}
        });
        if protocol == "vmess" {
            inbound["users"] = json!([{"name": "test", "uuid": UUID}]);
            inbound["allow_insecure_body"] = true.into();
            outbound["uuid"] = UUID.into();
            outbound["security"] = 3.into();
        } else {
            inbound["users"] = json!([{"name": "test", "password": common::PASSWORD}]);
            inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
            inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
            outbound["password"] = common::PASSWORD.into();
            outbound["tls"] = tls(&cert);
        }
        let up = Running::start(upstream(inbound)).await;
        outbound["endpoint"] = up.address.to_string().into();
        let down = Running::start(downstream(outbound)).await;
        let mut stream = tcp_tunnel(down.address, echo.address).await;
        exchange(&mut stream, b"protocol on kcp").await;
        drop(stream);
        down.shutdown().await;
        up.shutdown().await;
    }
}

#[tokio::test]
async fn vless_kcp_udp_command_stays_inside_the_reliable_stream() {
    let echo = Echo::udp("127.0.0.1").await;
    let kcp = json!({"seed": "udp-kcp-seed", "header": {"type": "srtp"}, "tti": 10});
    let up = Running::start(upstream(vless_inbound(kcp.clone()))).await;
    let down = Running::start(downstream(vless_outbound(up.address, kcp))).await;
    let (control, relay) = timeout(
        WAIT,
        common::socks(
            3,
            common::address("0.0.0.0:0".parse().unwrap()),
            down.address,
        ),
    )
    .await
    .unwrap();
    let relay = if relay.ip().is_unspecified() {
        SocketAddr::new(down.address.ip(), relay.port())
    } else {
        relay
    };
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(relay).await.unwrap();
    for payload in [b"udp via kcp".as_slice(), &[0x5a; 2048]] {
        let mut packet = vec![0, 0, 0];
        packet.extend(common::address(echo.address));
        packet.extend(payload);
        client.send(&packet).await.unwrap();
        let mut buffer = vec![0; 4096];
        let count = timeout(WAIT, client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..count], packet);
    }
    drop(client);
    drop(control);
    down.shutdown().await;
    up.shutdown().await;
}

#[tokio::test]
async fn wrong_seed_gets_no_data_and_never_falls_back_to_direct() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = Running::start(upstream(vless_inbound(json!({
        "seed": "correct-seed", "tti": 10
    }))))
    .await;
    let down = Running::start(downstream(vless_outbound(
        up.address,
        json!({"seed": "wrong-seed", "tti": 10}),
    )))
    .await;
    // 与上游客户端一致：KCP 建连和 VLESS 请求写出后即返回 SOCKS 成功，
    // 不等待服务端应答头；错误 seed 只能表现为后续无数据/超时。
    let (mut client, _) = timeout(
        WAIT,
        common::socks(
            1,
            common::address(target.local_addr().unwrap()),
            down.address,
        ),
    )
    .await
    .expect("错误 seed 不应阻塞 SOCKS 建连");
    client.write_all(b"no data may cross").await.unwrap();
    let mut reply = [0; 1];
    assert!(
        timeout(Duration::from_millis(500), client.read(&mut reply))
            .await
            .is_err(),
        "错误 seed 不得收到任何业务数据"
    );
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err(),
        "KCP 认证失败不能绕过上游直连目标"
    );
    drop(client);
    // 超时会丢弃握手中的 KCP 流；停机必须等到 children 完成有界清理。
    down.shutdown().await;
    up.shutdown().await;
}

#[tokio::test]
async fn stopping_downstream_cancels_an_unanswered_kcp_handshake_and_reclaims_port() {
    // 保持黑洞 socket 存活，避免 ICMP 提前结束会话；不运行任何假服务端。
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut value = downstream(vless_outbound(
        blackhole.local_addr().unwrap(),
        json!({"security": "none", "tti": 10}),
    ));
    value["limits"]["dial_timeout_ms"] = 10_000.into();
    let down = Running::start(value).await;
    let mut client = TcpStream::connect(down.address).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0; 2];
    timeout(WAIT, client.read_exact(&mut choice))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(choice, [5, 0]);
    let mut request = vec![5, 1, 0];
    request.extend(common::address("127.0.0.1:9".parse().unwrap()));
    client.write_all(&request).await.unwrap();
    let mut buffer = vec![0; 65_536];
    let (_, source) = timeout(WAIT, blackhole.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    // 调用停机前仍在等待 VLESS 应答；force 取消应触发流 Drop，而不是遗留 recv。
    down.shutdown().await;
    drop(common::rebind_udp(source).await);
    drop(client);
}

#[tokio::test]
async fn stopping_upstream_propagates_end_of_stream_to_downstream() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let kcp = json!({"tti": 10});
    let up = Running::start(upstream(vless_inbound(kcp.clone()))).await;
    let up_address = up.address;
    let down = Running::start(downstream(vless_outbound(up.address, kcp))).await;
    let mut stream = tcp_tunnel(down.address, echo.address).await;
    exchange(&mut stream, b"before upstream stop").await;
    up.shutdown().await;
    let result = timeout(WAIT, stream.read(&mut [0]))
        .await
        .expect("上游终止应传递到业务流");
    assert!(matches!(result, Ok(0) | Err(_)), "终止后仍交付了新业务字节");
    drop(common::rebind_udp(up_address).await);
    drop(stream);
    down.shutdown().await;
}
