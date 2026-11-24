//! NW3（Nowhere Protocol v3）Portal 与 vendored Nowhere Vector 客户端的回环测试。
//! 直接使用 vendor 内的上游客户端，不经过本仓库自建的客户端代码。

mod common;

use std::{
    net::{SocketAddr, TcpListener},
    time::Duration,
};

use common::{Certificate, Echo, Running};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const KEY: &str = "0123456789abcdef0123456789abcdef";

/// Portal / Vector 的就绪等待上限。
///
/// 原来是 5 秒。全量测试并行跑 76 个二进制时（每个静态链接整份代码），
/// Portal 起监听 + QUIC 端点 + 内部 SOCKS5 relay 的调度延迟会超过它，
/// 造成与代码无关的间歇失败（实测 `t32` 一轮 4 个 NW3 用例因此变红，
/// 单跑该文件 9 项全过）。这里只是「多久之内必须就绪」，不是性能断言。
const READY: Duration = Duration::from_secs(20);

/// 单次收发的等待上限。理由同上。
const REPLY: Duration = Duration::from_secs(10);

/// 取一个测试专用端口。
///
/// 不用 `bind("127.0.0.1:0")`：Linux 的临时端口范围是 32768–60999，
/// 这个范围会被并发测试的 TCP 连接当作源端口占用，导致「释放后再绑定」
/// 间歇性 `AddrInUse`。这里在范围之外顺序探测。
fn free_port() -> u16 {
    // 并发测试必须各自拿到不同端口，否则会互相抢占导致「未就绪」超时。
    static ISSUED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    let issued = ISSUED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    // 本文件独占 22500–24999 段。`reserve_port` 的 HashSet 只能在**当前测试二进制**
    // 内去重，cargo 并行跑多个测试二进制时互相看不见；此前四个文件共用
    // 20000–29999，实测出现过 `入口 X 绑定失败: AddrInUse`。
    for port in 22500u16..25000 {
        if issued.lock().unwrap().contains(&port) {
            continue;
        }
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            if issued.lock().unwrap().insert(port) {
                return port;
            }
        }
    }
    panic!("没有可用测试端口");
}

fn pin(cert: &Certificate) -> String {
    Sha256::digest(cert.der.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn udp_associate(server: SocketAddr) -> std::io::Result<(TcpStream, UdpSocket)> {
    let mut control = TcpStream::connect(server).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut choice = [0u8; 2];
    control.read_exact(&mut choice).await?;
    if choice != [5, 0] {
        return Err(std::io::Error::other("SOCKS5 方法协商失败"));
    }
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut head = [0u8; 3];
    control.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(std::io::Error::other("SOCKS5 UDP ASSOCIATE 失败"));
    }
    let bound = common::read_address(&mut control).await;
    let relay = if bound.ip().is_unspecified() {
        SocketAddr::new(control.peer_addr()?.ip(), bound.port())
    } else {
        bound
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(relay).await?;
    Ok((control, socket))
}

fn datagram(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend_from_slice(&common::address(target));
    bytes.extend_from_slice(payload);
    bytes
}

fn parse_datagram(bytes: &[u8]) -> (SocketAddr, Vec<u8>) {
    let (host, offset) = match bytes[3] {
        1 => (
            std::net::IpAddr::from(<[u8; 4]>::try_from(&bytes[4..8]).unwrap()),
            8,
        ),
        4 => (
            std::net::IpAddr::from(<[u8; 16]>::try_from(&bytes[4..20]).unwrap()),
            20,
        ),
        other => panic!("未知 ATYP {other}"),
    };
    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    (SocketAddr::new(host, port), bytes[offset + 2..].to_vec())
}

#[tokio::test]
async fn nw3_portal_relays_udp_with_vendored_vector_client() {
    let cert = Certificate::new();
    let port = free_port();
    let socks_port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "direct",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::udp("127.0.0.1").await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:{socks_port}",
        pin(&cert)
    );
    let vector = nowhere::Vector::new(url.parse().unwrap(), nowhere::Logger).unwrap();
    let task = tokio::spawn(vector.run());
    let socks: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let (_control, socket) = timeout(READY, async {
        loop {
            match udp_associate(socks).await {
                Ok(pair) => break pair,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Vector SOCKS 未在期限内就绪");
    let payload = b"nw3-udp";
    socket.send(&datagram(echo.address, payload)).await.unwrap();
    let mut buffer = [0u8; 8192];
    let length = timeout(REPLY, socket.recv(&mut buffer))
        .await
        .expect("NW3 UDP 回包超时")
        .unwrap();
    assert_eq!(parse_datagram(&buffer[..length]).1, payload);
    drop(socket);
    drop(_control);
    task.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn nw3_portal_egress_relays_udp_with_vendored_vector_client() {
    let cert = Certificate::new();
    let port = free_port();
    let socks_port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "egress",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "nw3_egress": {
            "tag": "nw3-exit",
            "endpoint": format!("127.0.0.1:{port}"),
            "key": KEY,
            "sni": "localhost",
            "pin": pin(&cert),
            "morph": false
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::udp("127.0.0.1").await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:{socks_port}",
        pin(&cert)
    );
    let vector = nowhere::Vector::new(url.parse().unwrap(), nowhere::Logger).unwrap();
    let task = tokio::spawn(vector.run());
    let socks: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let (_control, socket) = timeout(READY, async {
        loop {
            match udp_associate(socks).await {
                Ok(pair) => break pair,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Egress/UDP 未在期限内就绪");
    let payload = b"nw3-egress-udp";
    socket.send(&datagram(echo.address, payload)).await.unwrap();
    let mut buffer = [0u8; 8192];
    let length = timeout(REPLY, socket.recv(&mut buffer))
        .await
        .expect("NW3 Egress UDP 回包超时")
        .unwrap();
    assert_eq!(parse_datagram(&buffer[..length]).1, payload);
    drop(socket);
    drop(_control);
    task.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn nw3_vector_udp_outbound_preserves_targets_and_empty_on_tls_and_quic() {
    let cert = Certificate::new();
    let port = free_port();
    let upstream = Running::start(json!({
        "version":1,
        "inbounds":[{"type":"nw3","tag":"portal","listen":format!("127.0.0.1:{port}"),
            "key":KEY,"morph":false,"out":"direct",
            "certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":500}
    })).await;
    let first = Echo::udp("127.0.0.1").await;
    let second = Echo::udp("127.0.0.1").await;
    for carrier in ["tcp", "udp"] {
        let url = format!(
            "vector://{KEY}@127.0.0.1/{carrier}:{port}?morph=0&sni=localhost&pin={}",
            pin(&cert)
        );
        let downstream = Running::start(json!({
            "version":1,"inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
            "outbounds":[{"type":"nw3-vector","tag":"up","url":url}],"route":{"default":"up"},
            "limits":{"shutdown_timeout_ms":500,"dial_timeout_ms":2000}
        }))
        .await;
        let (control, socket) = udp_associate(downstream.address).await.unwrap();
        for (target, payload) in [
            (first.address, b"nw3-first".as_slice()),
            (second.address, b"nw3-second"),
            (first.address, b""),
            (second.address, b"again"),
        ] {
            socket.send(&datagram(target, payload)).await.unwrap();
            let mut buffer = vec![0; 8192];
            let length = timeout(REPLY, socket.recv(&mut buffer))
                .await
                .expect("NW3 出站 UDP 超时")
                .unwrap();
            let (source, reply) = parse_datagram(&buffer[..length]);
            assert_eq!(source, target);
            assert_eq!(reply, payload);
        }
        drop(socket);
        drop(control);
        downstream.shutdown().await;
    }
    upstream.shutdown().await;
}

#[tokio::test]
async fn nw3_vector_udp_wrong_key_never_falls_back_to_direct() {
    let cert = Certificate::new();
    let port = free_port();
    let upstream=Running::start(json!({"version":1,
        "inbounds":[{"type":"nw3","tag":"portal","listen":format!("127.0.0.1:{port}"),"key":KEY,"morph":false,
            "certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":500}
    })).await;
    let url = format!(
        "vector://11111111111111111111111111111111@127.0.0.1/tcp:{port}?morph=0&sni=localhost&pin={}",
        pin(&cert)
    );
    let downstream = Running::start(json!({"version":1,
        "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"nw3-vector","tag":"up","url":url}],"route":{"default":"up"},
        "limits":{"shutdown_timeout_ms":500,"dial_timeout_ms":300}
    }))
    .await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (control, socket) = udp_associate(downstream.address).await.unwrap();
    socket
        .send(&datagram(target.local_addr().unwrap(), b"denied"))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(600), target.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert_eq!(downstream.stats.snapshot().uplink, 0);
    drop(socket);
    drop(control);
    downstream.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn nw3_udp_reject_route_does_not_open_flow() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let downstream=Running::start(json!({"version":1,
        "inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"nw3-vector","tag":"up","url":format!("vector://{KEY}@127.0.0.1:9?morph=0&sni=localhost")},
            {"type":"reject","tag":"blocked"}],
        "route":{"default":"up","rules":[{"networks":["udp"],"outbound":"blocked"}]},
        "limits":{"shutdown_timeout_ms":500}
    })).await;
    let (control, socket) = udp_associate(downstream.address).await.unwrap();
    socket
        .send(&datagram(target.local_addr().unwrap(), b"blocked"))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(150), target.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert!(downstream.stats.snapshot().rejected > 0);
    assert_eq!(downstream.stats.snapshot().uplink, 0);
    drop(socket);
    drop(control);
    downstream.shutdown().await;
}

#[tokio::test]
async fn nw3_vector_outbound_relays_tcp_through_portal() {
    let cert = Certificate::new();
    let port = free_port();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "direct",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:1",
        pin(&cert)
    );
    let downstream = Running::start(json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [{"type": "nw3-vector", "tag": "up", "url": url}],
        "route": {"default": "up"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 3000}
    }))
    .await;
    let (mut tunnel, _) = timeout(
        READY,
        common::socks(1, common::address(echo.address), downstream.address),
    )
    .await
    .expect("NW3 Vector 出站建连超时");
    tunnel.write_all(b"nw3-vector").await.unwrap();
    tunnel.flush().await.unwrap();
    let mut echoed = vec![0; b"nw3-vector".len()];
    tunnel.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"nw3-vector");
    drop(tunnel);
    downstream.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn nw3_portal_egress_relays_tcp_with_vendored_vector_client() {
    let cert = Certificate::new();
    let port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "egress",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "nw3_egress": {
            "tag": "nw3-exit",
            "endpoint": format!("127.0.0.1:{port}"),
            "key": KEY,
            "sni": "localhost",
            "pin": pin(&cert),
            "morph": false
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:1",
        pin(&cert)
    );
    let client = nowhere::VectorClient::new(url.parse().unwrap(), nowhere::Logger).unwrap();
    let mut stream = timeout(READY, async {
        loop {
            match client.connect_tcp("127.0.0.1", echo.address.port()).await {
                Ok(stream) => break stream,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Egress 未在期限内完成注册");
    stream.write_all(b"nw3-egress").await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0; b"nw3-egress".len()];
    timeout(REPLY, stream.read_exact(&mut echoed))
        .await
        .expect("NW3 Egress 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"nw3-egress");
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn nw3_portal_relays_tcp_with_vendored_vector_client() {
    let cert = Certificate::new();
    let port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "direct",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:1",
        pin(&cert)
    );
    let client = nowhere::VectorClient::new(url.parse().unwrap(), nowhere::Logger).unwrap();
    let mut stream = timeout(READY, async {
        loop {
            match client.connect_tcp("127.0.0.1", echo.address.port()).await {
                Ok(stream) => break stream,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Portal 未在期限内就绪");
    stream.write_all(b"nw3-loopback").await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0; b"nw3-loopback".len()];
    timeout(REPLY, stream.read_exact(&mut echoed))
        .await
        .expect("NW3 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"nw3-loopback");
    drop(stream);
    server.shutdown().await;
}

/// NW3 的 `out` 为 `direct` 时，Portal 的出站应经过本内核的 loopback SOCKS5，
/// 因此 `route.rules` 对 NW3 流量生效。
///
/// 修复前 Portal 自己直连，`route`/`limits`/`stats` 对 NW3 全部无效。
///
/// 关键设计：用 `dns.hosts` 把 `blocked.example` 指到回显服务。这样**绕过
/// 内核直连也会成功**——只有真正经过内核才会被规则拒绝，测试不会因「域名
/// 本来解析不了」而假通过。
#[tokio::test]
async fn nw3_portal_out_direct_respects_kernel_routes() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let blocked_ip = echo.address.ip().to_string();
    let port = free_port();
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "nw3",
            "tag": "nw3-in",
            "listen": format!("127.0.0.1:{port}"),
            "key": KEY,
            "morph": false,
            "out": "direct",
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "reject", "tag": "reject"}
        ],
        "dns": {"hosts": {"blocked.example": [blocked_ip]}},
        // 带入口条件：这是此前失效的形态。`inbounds: ["nw3-in"]` 必须能
        // 匹配到经内部 relay 的 NW3 流量，否则这条规则形同不存在。
        "route": {
            "default": "direct",
            "rules": [{
                "inbounds": ["nw3-in"],
                "domains": ["blocked.example"],
                "outbound": "reject"
            }]
        },
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;
    let url = format!(
        "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:1",
        pin(&cert)
    );
    let client = nowhere::VectorClient::new(url.parse().unwrap(), nowhere::Logger).unwrap();

    // 控制组：目标 IP 不在拒绝规则里，回显正常。
    let mut allowed = timeout(READY, async {
        loop {
            match client.connect_tcp("127.0.0.1", echo.address.port()).await {
                Ok(stream) => break stream,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("NW3 Portal 未在期限内就绪");
    allowed.write_all(b"ok").await.unwrap();
    allowed.flush().await.unwrap();
    let mut echoed = [0u8; 2];
    timeout(REPLY, allowed.read_exact(&mut echoed))
        .await
        .expect("NW3 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"ok");
    drop(allowed);
    // 直接证据：NW3 的业务字节现在会计入内核的全局统计。
    // 修复前 Portal 自己出站，`uplink`/`downlink` 对 NW3 恒为 0。
    let snapshot = server.stats.snapshot();
    assert!(
        snapshot.uplink >= 2 && snapshot.downlink >= 2,
        "NW3 流量应计入内核统计，实际 uplink={} downlink={}",
        snapshot.uplink,
        snapshot.downlink
    );

    // 命中 reject：`blocked.example` 能解析到回显服务，若 Portal 绕过内核
    // 就会直连成功；只有走内核才会被拒绝。
    let denied = timeout(READY, async {
        match client
            .connect_tcp("blocked.example", echo.address.port())
            .await
        {
            Ok(mut stream) => {
                let mut byte = [0u8; 1];
                let _ = stream.write_all(b"x").await;
                match timeout(Duration::from_millis(500), stream.read(&mut byte)).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => true,
                    Ok(Ok(_)) => false,
                }
            }
            Err(_) => true,
        }
    })
    .await
    .expect("NW3 拒绝路径超时");
    assert!(denied, "命中 reject 的域名不应建立可用连接");

    server.shutdown().await;
}

/// 同一进程里 `out=direct` 与 `out=egress` 两个 Portal 必须各自保持出站语义。
///
/// 此前任一 `direct` Portal 都会触发内部 relay 注入，而 relay 地址被无差别
/// 传给**所有** Portal，导致 `egress` 的 Portal 也被指向回环——出口语义被改。
#[tokio::test]
async fn mixed_direct_and_egress_portals_keep_their_own_out() {
    let cert = Certificate::new();
    let direct_port = free_port();
    let egress_port = free_port();
    // 两个 Portal 同进程：一个直连、一个走 Egress。Egress 要注册到直连那个
    // Portal 上（`out=egress` 的 Portal 自己就是出口，不需要注册）。
    let server = Running::start(json!({
        "version": 1,
        "inbounds": [
            {
                "type": "nw3", "tag": "direct-in",
                "listen": format!("127.0.0.1:{direct_port}"),
                "key": KEY, "morph": false, "out": "direct",
                "certificate": cert.dir.path().join("cert.pem"),
                "private_key": cert.dir.path().join("key.pem")
            },
            {
                "type": "nw3", "tag": "egress-in",
                "listen": format!("127.0.0.1:{egress_port}"),
                "key": KEY, "morph": false, "out": "egress",
                "certificate": cert.dir.path().join("cert.pem"),
                "private_key": cert.dir.path().join("key.pem")
            }
        ],
        // Egress 必须注册到 `out=egress` 那个 Portal 上：它才是把流量交出去
        // 的入口。`direct-in` 与它互不影响。
        "nw3_egress": {
            "tag": "nw3-exit",
            "endpoint": format!("127.0.0.1:{egress_port}"),
            "key": KEY,
            "sni": "localhost",
            "pin": pin(&cert),
            "morph": false
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 500, "handshake_timeout_ms": 3000}
    }))
    .await;

    let echo = Echo::tcp("127.0.0.1", false).await;
    // 两个 Portal 都必须真的能出站。若 `egress` 那侧被指向回环且没有可用
    // Egress，它就会失败——这正是此前被隐藏的错误。
    for (label, port) in [("direct", direct_port), ("egress", egress_port)] {
        let url = format!(
            "vector://{KEY}@127.0.0.1:{port}?morph=0&sni=localhost&pin={}&in=127.0.0.1:1",
            pin(&cert)
        );
        let client = nowhere::VectorClient::new(url.parse().unwrap(), nowhere::Logger).unwrap();
        let mut stream = timeout(READY, async {
            loop {
                match client.connect_tcp("127.0.0.1", echo.address.port()).await {
                    Ok(stream) => break stream,
                    Err(_) => sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{label} Portal 未在期限内就绪"));
        stream.write_all(label.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0; label.len()];
        timeout(REPLY, stream.read_exact(&mut echoed))
            .await
            .unwrap_or_else(|_| panic!("{label} Portal 回显超时"))
            .unwrap();
        assert_eq!(&echoed, label.as_bytes(), "{label} Portal 回显不一致");
        drop(stream);
    }

    server.shutdown().await;
}
