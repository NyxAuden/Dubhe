mod common;

use common::*;
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const UUID: &str = "11111111-1111-4111-8111-111111111111";
const ID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

fn config(cert: &Certificate) -> Value {
    let mut value = socks_config();
    value["inbounds"] = json!([{
        "type":"vless","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "certificate":cert.dir.path().join("cert.pem"),
        "private_key":cert.dir.path().join("key.pem")
    }]);
    value
}

// 独立请求编码：不调用任何生产 VLESS 编解码或 UUID 解析函数。
fn request(command: u8, target: SocketAddr, domain: bool) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend(ID);
    bytes.extend([0, command]);
    bytes.extend(target.port().to_be_bytes());
    if domain {
        bytes.extend([2, 9]);
        bytes.extend(b"localhost");
    } else {
        match target.ip() {
            std::net::IpAddr::V4(ip) => {
                bytes.push(1);
                bytes.extend(ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                bytes.push(3);
                bytes.extend(ip.octets());
            }
        }
    }
    bytes
}
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = (payload.len() as u16).to_be_bytes().to_vec();
    bytes.extend(payload);
    bytes
}
async fn response<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut head = [9; 2];
    read_exact(stream, &mut head).await;
    assert_eq!(head, [0, 0]);
}
async fn packet<S: AsyncRead + Unpin>(stream: &mut S, expected: &[u8]) {
    let mut length = [0; 2];
    read_exact(stream, &mut length).await;
    assert_eq!(u16::from_be_bytes(length) as usize, expected.len());
    let mut data = vec![0; expected.len()];
    read_exact(stream, &mut data).await;
    assert_eq!(data, expected);
}
async fn closed<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut b = [0; 1];
    let result = timeout(Duration::from_secs(2), stream.read(&mut b))
        .await
        .expect("连接应及时关闭");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "关闭前不应返回成功载荷: {result:?}"
    );
}

#[tokio::test]
async fn tcp_tls_headers_half_close_domain_and_payload_accounting() {
    let cert = Certificate::new();
    let target = Echo::tcp("127.0.0.1", true).await;
    let server = Running::start(config(&cert)).await;
    for split in [false, true] {
        let mut stream = cert.connect(server.address).await;
        let mut bytes = request(1, target.address, split);
        bytes.extend(b"payload-after-header");
        if split {
            for byte in bytes {
                stream.write_all(&[byte]).await.unwrap();
            }
        } else {
            stream.write_all(&bytes).await.unwrap();
        }
        response(&mut stream).await;
        stream.shutdown().await.unwrap();
        let mut result = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut result))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, b"payload-after-header");
    }
    let counts = server.stats.snapshot();
    assert_eq!(counts.uplink, 40);
    assert_eq!(counts.downlink, 40);
    server.shutdown().await;
}

#[tokio::test]
async fn invalid_identity_addons_commands_and_route_never_dial() {
    let cert = Certificate::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap();
    let server = Running::start(config(&cert)).await;
    let base = request(1, addr, false);
    let mut invalid = Vec::new();
    for (offset, value) in [
        (0, 1),
        (1, 0xff),
        (17, 1),
        // 命令 3/4 是已知请求；此处只覆盖未知命令。
        (18, 0),
        (21, 4),
    ] {
        let mut bytes = base.clone();
        bytes[offset] = value;
        invalid.push(bytes);
    }
    invalid.push(base[..16].to_vec());
    for bytes in invalid {
        let mut stream = cert.connect(server.address).await;
        stream.write_all(&bytes).await.unwrap();
        closed(&mut stream).await;
    }
    // 命令 4 是合法反向 Mux 请求；未配置 reverse 出站时应答后失败关闭，
    // 且不能拨号任何目标。
    let mut command4 = base[..19].to_vec();
    command4[18] = 4;
    let mut stream = cert.connect(server.address).await;
    stream.write_all(&command4).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0, 0]);
    closed(&mut stream).await;
    assert!(
        timeout(Duration::from_millis(40), target.accept())
            .await
            .is_err()
    );
    assert_eq!(server.stats.snapshot().uplink, 0);
    server.shutdown().await;

    let mut value = config(&cert);
    value["route"]["default"] = json!("reject");
    let server = Running::start(value).await;
    for command in [1, 2] {
        let mut stream = cert.connect(server.address).await;
        stream
            .write_all(&request(command, addr, false))
            .await
            .unwrap();
        closed(&mut stream).await;
    }
    assert!(
        timeout(Duration::from_millis(40), target.accept())
            .await
            .is_err()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn udp_frames_preserve_boundaries_and_drop_empty() {
    let cert = Certificate::new();
    let target = Echo::udp("127.0.0.1").await;
    let server = Running::start(config(&cert)).await;
    let mut stream = cert.connect(server.address).await;
    let mut bytes = request(2, target.address, true);
    bytes.extend(frame(b"first"));
    bytes.extend(frame(b""));
    bytes.extend(frame(b"second"));
    stream.write_all(&bytes).await.unwrap();
    response(&mut stream).await;
    packet(&mut stream, b"first").await;
    packet(&mut stream, b"second").await;
    let large = vec![0x5a; 300];
    for byte in frame(&large) {
        stream.write_all(&[byte]).await.unwrap();
    }
    stream.flush().await.unwrap();
    packet(&mut stream, &large).await;
    assert_eq!(server.stats.snapshot().uplink, 311);
    assert_eq!(server.stats.snapshot().downlink, 311);
    assert!(server.stats.snapshot().dropped >= 1);
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn udp_limit_idle_and_malformed_frames_return_slots() {
    let cert = Certificate::new();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap();
    let mut value = config(&cert);
    value["limits"]["max_udp_associations"] = json!(1);
    value["limits"]["max_udp_payload"] = json!(16);
    value["limits"]["udp_idle_timeout_ms"] = json!(150);
    let server = Running::start(value).await;
    let mut first = cert.connect(server.address).await;
    first.write_all(&request(2, addr, false)).await.unwrap();
    response(&mut first).await;
    let mut extra = cert.connect(server.address).await;
    extra.write_all(&request(2, addr, false)).await.unwrap();
    closed(&mut extra).await;
    // 超限在读取载荷前即失败，不需要等待补齐17字节。
    first.write_all(&[0, 17]).await.unwrap();
    closed(&mut first).await;
    timeout(Duration::from_secs(1), async {
        while server.stats.snapshot().udp_associations != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let mut truncated = cert.connect(server.address).await;
    truncated.write_all(&request(2, addr, false)).await.unwrap();
    response(&mut truncated).await;
    truncated.write_all(&[0, 4, 1]).await.unwrap();
    truncated.shutdown().await.unwrap();
    closed(&mut truncated).await;
    timeout(Duration::from_secs(1), async {
        while server.stats.snapshot().udp_associations != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let mut idle = cert.connect(server.address).await;
    idle.write_all(&request(2, addr, false)).await.unwrap();
    response(&mut idle).await;
    closed(&mut idle).await;
    assert!(
        timeout(Duration::from_millis(30), target.recv(&mut [0; 16]))
            .await
            .is_err()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn forced_stop_reclaims_udp_socket_and_tcp_flow() {
    let cert = Certificate::new();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(&cert)).await;
    let mut stream = cert.connect(server.address).await;
    stream
        .write_all(&request(2, target.local_addr().unwrap(), false))
        .await
        .unwrap();
    response(&mut stream).await;
    stream.write_all(&frame(b"active")).await.unwrap();
    let mut data = [0; 16];
    let (_, mapping) = timeout(Duration::from_secs(2), target.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    let mut tcp_stream = cert.connect(server.address).await;
    tcp_stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut tcp_stream).await;
    exchange(&mut tcp_stream, b"live").await;
    server.shutdown().await;
    closed(&mut stream).await;
    closed(&mut tcp_stream).await;
    let rebound = UdpSocket::bind(mapping).await.unwrap();
    drop(rebound);
}

#[tokio::test]
async fn ipv6_vless_tcp_and_udp_when_available() {
    let Ok(probe) = TcpListener::bind("[::1]:0").await else {
        eprintln!("SKIP VLESS IPv6：当前环境不可用");
        return;
    };
    drop(probe);
    let cert = Certificate::new();
    let tcp = Echo::tcp("::1", false).await;
    let udp = Echo::udp("::1").await;
    let server = Running::start(config(&cert)).await;
    let mut stream = cert.connect(server.address).await;
    stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"ipv6").await;
    let mut packets = cert.connect(server.address).await;
    packets
        .write_all(&request(2, udp.address, false))
        .await
        .unwrap();
    response(&mut packets).await;
    packets.write_all(&frame(b"ipv6-udp")).await.unwrap();
    packet(&mut packets, b"ipv6-udp").await;
    drop(stream);
    drop(packets);
    server.shutdown().await;
}

#[tokio::test]
async fn vless_example_checks_and_starts_with_test_credentials() {
    let cert = Certificate::new();
    let mut value: Value = serde_json::from_str(include_str!("../examples/vless.json")).unwrap();
    value["inbounds"][0] = config(&cert)["inbounds"][0].clone();
    let cfg = dubhe::Config::from_json(&value.to_string()).unwrap();
    dubhe::Server::check(&cfg).unwrap();
    let server = Running::start(value).await;
    let target = Echo::tcp("127.0.0.1", false).await;
    let mut stream = cert.connect(server.address).await;
    stream
        .write_all(&request(1, target.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"example").await;
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn plaintext_vless_tcp_and_udp_without_tls() {
    // Xray 允许 VLESS 不带 TLS；省略 certificate/private_key 即明文入站。
    let mut value = socks_config();
    value["inbounds"] = json!([{
        "type":"vless","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}]
    }]);
    let server = Running::start(value).await;
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let udp = Echo::udp("127.0.0.1").await;

    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"plain-tcp").await;

    let mut packets = TcpStream::connect(server.address).await.unwrap();
    packets
        .write_all(&request(2, udp.address, false))
        .await
        .unwrap();
    response(&mut packets).await;
    packets.write_all(&frame(b"plain-udp")).await.unwrap();
    packet(&mut packets, b"plain-udp").await;

    drop(stream);
    drop(packets);
    server.shutdown().await;
}
