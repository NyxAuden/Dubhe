//! TUIC v5 线格式测试与端到端回环测试。
//!
//! 本文件通过 `#[path]` 引入生产用纯编解码模块 `src/transport/tuic/wire.rs`；
//! 线格式部分的期望字节由本文件内的参考编码器独立构造，不复用被测编码函数。
//! 端到端部分启动真实服务端，用 quinn 客户端完成认证、TCP 与 UDP 转发。

mod common;

// 测试 crate 只覆盖部分编解码入口，未覆盖的生产函数在此按需放行。
#[allow(dead_code)]
#[path = "../src/transport/tuic/wire.rs"]
mod wire;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use common::{Echo, Running};
use rustls::{
    client::{
        ClientSessionMemoryCache, ClientSessionStore, Tls12ClientSessionValue,
        Tls13ClientSessionValue,
    },
    pki_types::ServerName,
};
use serde_json::json;
use tokio::time::timeout;
use wire::{Command, MAX_FRAGMENTS, MAX_UDP_DATA, VERSION, WireAddress, WireError};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "tuic-loopback-password";

fn uuid_bytes() -> [u8; 16] {
    let hex: String = UUID.chars().filter(|character| *character != '-').collect();
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

// ---------- 独立参考编码器（不调用被测代码） ----------

fn reference_authenticate(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(50);
    frame.push(5); // 版本
    frame.push(0); // Authenticate
    frame.extend_from_slice(uuid);
    frame.extend_from_slice(token);
    frame
}

fn reference_ipv4(octets: [u8; 4], port: u16) -> Vec<u8> {
    let mut address = Vec::with_capacity(7);
    address.push(0x01);
    address.extend_from_slice(&octets);
    address.extend_from_slice(&port.to_be_bytes());
    address
}

fn reference_ipv6(octets: [u8; 16], port: u16) -> Vec<u8> {
    let mut address = Vec::with_capacity(19);
    address.push(0x02);
    address.extend_from_slice(&octets);
    address.extend_from_slice(&port.to_be_bytes());
    address
}

fn reference_domain(name: &str, port: u16) -> Vec<u8> {
    let mut address = Vec::with_capacity(4 + name.len());
    address.push(0x00);
    address.push(name.len() as u8);
    address.extend_from_slice(name.as_bytes());
    address.extend_from_slice(&port.to_be_bytes());
    address
}

/// 参考 UDP 消息体编码器；`address` 为已编码的地址字节。
fn reference_udp_body(
    session_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    address: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + address.len() + payload.len());
    body.extend_from_slice(&session_id.to_be_bytes());
    body.extend_from_slice(&packet_id.to_be_bytes());
    body.push(fragment_total);
    body.push(fragment_id);
    body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    body.extend_from_slice(address);
    body.extend_from_slice(payload);
    body
}

fn reference_udp_datagram(
    session_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    address: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2);
    frame.push(5);
    frame.push(2);
    frame.extend_from_slice(&reference_udp_body(
        session_id,
        packet_id,
        fragment_total,
        fragment_id,
        address,
        payload,
    ));
    frame
}

// ---------- 认证帧 ----------

#[test]
fn authentication_frame_round_trips() {
    let uuid = [0x11u8; 16];
    let token = [0x22u8; 32];
    let expected = reference_authenticate(&uuid, &token);
    let actual = wire::encode_authenticate(&uuid, &token);
    assert_eq!(actual.as_slice(), expected.as_slice());
    assert_eq!(actual.len(), 50);

    let decoded = wire::decode_authenticate(&expected).unwrap();
    assert_eq!(decoded.uuid, uuid);
    assert_eq!(decoded.token, token);
}

#[test]
fn authentication_frame_rejects_bad_framing() {
    let uuid = [0x11u8; 16];
    let token = [0x22u8; 32];
    let frame = reference_authenticate(&uuid, &token);

    // 少一个字节
    assert_eq!(
        wire::decode_authenticate(&frame[..49]).unwrap_err(),
        WireError::Truncated
    );
    // 多一个字节
    let mut too_long = frame.clone();
    too_long.push(0);
    assert_eq!(
        wire::decode_authenticate(&too_long).unwrap_err(),
        WireError::LengthMismatch
    );
    // 版本错误
    let mut wrong_version = frame.clone();
    wrong_version[0] = 4;
    assert_eq!(
        wire::decode_authenticate(&wrong_version).unwrap_err(),
        WireError::UnsupportedVersion
    );
    // 命令错误
    let mut wrong_command = frame;
    wrong_command[1] = 1;
    assert_eq!(
        wire::decode_authenticate(&wrong_command).unwrap_err(),
        WireError::UnknownCommand
    );
}

#[test]
fn unknown_uuid_and_wrong_token_are_rejected() {
    let known = [[0x11u8; 16], [0x33u8; 16]];
    let unknown = [0x22u8; 16];
    let token = [0x44u8; 32];
    let frame = reference_authenticate(&unknown, &token);
    let decoded = wire::decode_authenticate(&frame).unwrap();
    assert_eq!(decoded.uuid, unknown);
    assert_eq!(wire::lookup_uuid(&known, &decoded.uuid), None);
    assert_eq!(wire::lookup_uuid(&known, &known[1]), Some(1));

    // token 必须逐字节一致
    assert!(wire::ct_eq(&[0x44u8; 32], &decoded.token));
    assert!(!wire::ct_eq(&[0x45u8; 32], &decoded.token));
    assert!(!wire::ct_eq(&[0x44u8; 31], &decoded.token));
}

#[test]
fn uuid_text_parsing_is_strict() {
    let expected = [0x11u8; 16];
    assert_eq!(
        wire::parse_uuid("11111111-1111-1111-1111-111111111111"),
        Some(expected)
    );
    assert_eq!(
        wire::parse_uuid("11111111111111111111111111111111"),
        Some(expected)
    );
    assert_eq!(
        wire::parse_uuid("urn:uuid:11111111-1111-1111-1111-111111111111"),
        Some(expected)
    );
    assert_eq!(wire::parse_uuid(""), None);
    assert_eq!(wire::parse_uuid("1111"), None);
    assert_eq!(
        wire::parse_uuid("11111111-1111-1111-1111-11111111111z"),
        None
    );
    assert_eq!(
        wire::parse_uuid("1111111-11111-1111-1111-111111111111"),
        None
    );
}

// ---------- 命令头 ----------

#[test]
fn command_header_matches_reference_layout() {
    for (byte, command) in [
        (0u8, Command::Authenticate),
        (1, Command::Connect),
        (2, Command::Packet),
        (3, Command::Dissociate),
        (4, Command::Heartbeat),
    ] {
        let header = [VERSION, byte];
        assert_eq!(wire::decode_command_header(&header).unwrap(), command);
        assert_eq!(command.byte(), byte);
    }
    assert_eq!(
        wire::decode_command_header(&[VERSION, 5]).unwrap_err(),
        WireError::UnknownCommand
    );
    assert_eq!(
        wire::decode_command_header(&[4, 1]).unwrap_err(),
        WireError::UnsupportedVersion
    );
    assert_eq!(
        wire::decode_command_header(&[]).unwrap_err(),
        WireError::Truncated
    );
}

// ---------- 地址编码 ----------

#[test]
fn address_encoding_matches_reference_bytes() {
    let ipv4 = WireAddress::Ipv4 {
        octets: [192, 0, 2, 7],
        port: 443,
    };
    let mut actual = Vec::new();
    wire::encode_address(&ipv4, &mut actual).unwrap();
    assert_eq!(actual, reference_ipv4([192, 0, 2, 7], 443));
    assert_eq!(wire::decode_address(&actual).unwrap(), (ipv4, 7));

    let ipv6 = WireAddress::Ipv6 {
        octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port: 53,
    };
    let mut actual = Vec::new();
    wire::encode_address(&ipv6, &mut actual).unwrap();
    assert_eq!(
        actual,
        reference_ipv6(
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            53
        )
    );
    assert_eq!(wire::decode_address(&actual).unwrap(), (ipv6, 19));

    let domain = WireAddress::Domain {
        name: "example.org".into(),
        port: 8443,
    };
    let mut actual = Vec::new();
    wire::encode_address(&domain, &mut actual).unwrap();
    assert_eq!(actual, reference_domain("example.org", 8443));
    assert_eq!(
        wire::decode_address(&actual).unwrap(),
        (domain, actual.len())
    );

    // Empty 仅 1 字节，无端口。
    assert_eq!(
        wire::decode_address(&[0xff]).unwrap(),
        (WireAddress::Empty, 1)
    );
}

#[test]
fn address_decoding_rejects_bad_families_and_overruns() {
    // TUIC 不使用 SOCKS5 的 0x03/0x04，必须拒绝。
    assert_eq!(
        wire::decode_address(&[0x03, 1, 2, 3]).unwrap_err(),
        WireError::UnknownAddressFamily
    );
    assert_eq!(
        wire::decode_address(&[0x04, 1, 2, 3]).unwrap_err(),
        WireError::UnknownAddressFamily
    );
    assert_eq!(
        wire::decode_address(&[0x01, 1, 2, 3]).unwrap_err(),
        WireError::Truncated
    );
    // 声明域名长度 10，实际不足。
    let mut truncated = vec![0x00, 10];
    truncated.extend_from_slice(b"short");
    assert_eq!(
        wire::decode_address(&truncated).unwrap_err(),
        WireError::Truncated
    );
    // 空域名。
    assert_eq!(
        wire::decode_address(&[0x00, 0, 0, 80]).unwrap_err(),
        WireError::InvalidAddress
    );
    // 非可打印字符。
    assert_eq!(
        wire::decode_address(&[0x00, 1, b' ', 0, 80]).unwrap_err(),
        WireError::InvalidAddress
    );
    // 编码侧拒绝超过 255 字节的域名。
    assert_eq!(
        wire::encode_address(
            &WireAddress::Domain {
                name: "a".repeat(256),
                port: 1,
            },
            &mut Vec::new(),
        )
        .unwrap_err(),
        WireError::InvalidAddress
    );
}

// ---------- UDP 消息 ----------

#[test]
fn udp_body_matches_reference_layout() {
    let address = reference_ipv4([127, 0, 0, 1], 53);
    let expected = reference_udp_body(7, 9, 1, 0, &address, b"hello");
    let destination = WireAddress::Ipv4 {
        octets: [127, 0, 0, 1],
        port: 53,
    };
    let actual = wire::encode_udp_body(7, 9, 1, 0, &destination, b"hello").unwrap();
    assert_eq!(actual, expected);

    let decoded = wire::decode_udp_body(&expected).unwrap();
    assert_eq!(decoded.session_id, 7);
    assert_eq!(decoded.packet_id, 9);
    assert_eq!(decoded.fragment_total, 1);
    assert_eq!(decoded.fragment_id, 0);
    assert_eq!(decoded.destination, destination);
    assert_eq!(decoded.payload, b"hello");
}

#[test]
fn udp_datagram_decodes_with_command_prefix() {
    let address = reference_domain("example.net", 5353);
    let datagram = reference_udp_datagram(1, 2, 1, 0, &address, b"dns");
    let decoded = wire::decode_udp_datagram(&datagram).unwrap();
    assert_eq!(decoded.session_id, 1);
    assert_eq!(
        decoded.destination,
        WireAddress::Domain {
            name: "example.net".into(),
            port: 5353,
        }
    );
    assert_eq!(decoded.payload, b"dns");

    // 版本与命令不匹配
    let mut wrong = datagram.clone();
    wrong[0] = 4;
    assert_eq!(
        wire::decode_udp_datagram(&wrong).unwrap_err(),
        WireError::UnsupportedVersion
    );
    let mut wrong = datagram;
    wrong[1] = 4;
    assert_eq!(
        wire::decode_udp_datagram(&wrong).unwrap_err(),
        WireError::UnknownCommand
    );
}

#[test]
fn udp_length_fields_are_bounded_and_exact() {
    let address = reference_ipv4([127, 0, 0, 1], 53);

    // data_len 声明 5，实际只有 4 字节。
    let mut truncated = reference_udp_body(1, 1, 1, 0, &address, b"1234");
    let data_len_offset = 6;
    truncated[data_len_offset..data_len_offset + 2].copy_from_slice(&5u16.to_be_bytes());
    assert_eq!(
        wire::decode_udp_body(&truncated).unwrap_err(),
        WireError::Truncated
    );

    // 数据后多出字节。
    let mut trailing = reference_udp_body(1, 1, 1, 0, &address, b"1234");
    trailing.push(0);
    assert_eq!(
        wire::decode_udp_body(&trailing).unwrap_err(),
        WireError::LengthMismatch
    );

    // 固定头不足 8 字节。
    assert_eq!(
        wire::decode_udp_fixed(&[0u8; 7]).unwrap_err(),
        WireError::Truncated
    );

    // 编码超界：u16 长度放不下。
    assert_eq!(
        wire::encode_udp_body(
            1,
            1,
            1,
            0,
            &WireAddress::Empty,
            &vec![0u8; MAX_UDP_DATA + 1]
        )
        .unwrap_err(),
        WireError::Oversize
    );

    // 分片字段越界。
    assert_eq!(
        wire::encode_udp_body(1, 1, 0, 0, &WireAddress::Empty, b"x").unwrap_err(),
        WireError::Oversize
    );
    assert_eq!(
        wire::encode_udp_body(1, 1, MAX_FRAGMENTS + 1, 0, &WireAddress::Empty, b"x").unwrap_err(),
        WireError::Oversize
    );
    assert_eq!(
        wire::encode_udp_body(1, 1, 2, 2, &WireAddress::Empty, b"x").unwrap_err(),
        WireError::InvalidFragment
    );

    // 非首分片使用 Empty 地址，编码长度仍受控。
    let body = wire::encode_udp_body(1, 1, 2, 1, &WireAddress::Empty, b"tail").unwrap();
    assert_eq!(body[4], 2);
    assert_eq!(body[5], 1);
    let decoded = wire::decode_udp_body(&body).unwrap();
    assert_eq!(decoded.destination, WireAddress::Empty);
    assert_eq!(decoded.payload, b"tail");
}

#[test]
fn fragmented_message_uses_one_header_and_shared_packet_id() {
    let address = reference_ipv6(
        [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        53,
    );
    let first = reference_udp_body(9, 10, 2, 0, &address, b"head");
    let empty = vec![0xff];
    let second = reference_udp_body(9, 10, 2, 1, &empty, b"tail");

    let first = wire::decode_udp_body(&first).unwrap();
    let second = wire::decode_udp_body(&second).unwrap();
    assert_eq!(first.session_id, second.session_id);
    assert_eq!(first.packet_id, second.packet_id);
    assert_eq!(first.fragment_total, 2);
    assert_eq!(first.fragment_id, 0);
    assert_eq!(second.fragment_id, 1);
    assert_eq!(
        first.destination,
        WireAddress::Ipv6 {
            octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            port: 53,
        }
    );
    assert_eq!(second.destination, WireAddress::Empty);
    assert_eq!(second.payload, b"tail");
}

// ---------- 端到端回环 ----------

fn config(cert: &common::Certificate) -> serde_json::Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID, "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"handshake_timeout_ms": 3000, "shutdown_timeout_ms": 500}
    })
}

fn client_config(cert: &common::Certificate) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols.clear();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).unwrap();
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(5)).unwrap(),
    ));
    client.transport_config(Arc::new(transport));
    client
}

/// 统计 rustls 客户端收到的 TLS 1.3 票据数量，避免用固定 sleep 猜测票据是否到达。
#[derive(Debug)]
struct Tickets {
    inner: ClientSessionMemoryCache,
    inserted: AtomicUsize,
}

impl Tickets {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: ClientSessionMemoryCache::new(8),
            inserted: AtomicUsize::new(0),
        })
    }

    async fn wait_for(&self, minimum: usize) {
        timeout(Duration::from_secs(3), async {
            while self.inserted.load(Ordering::SeqCst) < minimum {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("等待 TLS 1.3 会话票据超时");
    }
}

impl ClientSessionStore for Tickets {
    fn set_kx_hint(&self, name: ServerName<'static>, group: rustls::NamedGroup) {
        self.inner.set_kx_hint(name, group);
    }
    fn kx_hint(&self, name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.inner.kx_hint(name)
    }
    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(name, value);
    }
    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(name)
    }
    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        self.inner.remove_tls12_session(name);
    }
    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.inner.insert_tls13_ticket(name, value);
        self.inserted.fetch_add(1, Ordering::SeqCst);
    }
    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(name)
    }
}

/// 0-RTT 客户端配置：显式开启 early data 并使用可观测的票据存储。
fn client_config_0rtt(cert: &common::Certificate, tickets: Arc<Tickets>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.enable_early_data = true;
    tls.resumption = rustls::client::Resumption::store(tickets);
    tls.alpn_protocols.clear();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).unwrap();
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(5)).unwrap(),
    ));
    client.transport_config(Arc::new(transport));
    client
}

/// 0-RTT 验证专用配置：唯一 tag 便于从日志中过滤，且服务端显式接受早期数据。
fn config_0rtt(cert: &common::Certificate) -> serde_json::Value {
    let mut value = config(cert);
    value["inbounds"][0]["tag"] = json!("tuic-0rtt-evidence");
    value["inbounds"][0]["zero_rtt_handshake"] = json!(true);
    value
}

/// 进程内日志捕获；只在测试里把过滤级别降到 DEBUG，生产 main 仍默认 INFO。
#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_logs() -> LogCapture {
    static CAPTURE: std::sync::OnceLock<LogCapture> = std::sync::OnceLock::new();
    CAPTURE
        .get_or_init(|| {
            let capture = LogCapture::default();
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .with_writer(capture.clone())
                .try_init();
            capture
        })
        .clone()
}

async fn wait_for_log(capture: &LogCapture, needle: &str) {
    timeout(Duration::from_secs(3), async {
        loop {
            let text = String::from_utf8_lossy(&capture.0.lock().unwrap()).into_owned();
            if text.contains(needle) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("等待服务端 0-RTT debug 事件超时");
}

async fn connect(
    running: &Running,
    cert: &common::Certificate,
) -> (quinn::Endpoint, quinn::Connection) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config(cert));
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(running.addresses[0], "localhost").unwrap(),
    )
    .await
    .expect("TUIC QUIC 握手超时")
    .expect("TUIC QUIC 握手失败");
    (endpoint, connection)
}

async fn authenticate(connection: &quinn::Connection) {
    let uuid = uuid_bytes();
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, &uuid, PASSWORD.as_bytes())
        .unwrap();
    let mut stream = connection.open_uni().await.unwrap();
    stream
        .write_all(&reference_authenticate(&uuid, &token))
        .await
        .unwrap();
    stream.finish().unwrap();
}

#[tokio::test]
async fn authenticated_tcp_stream_relays_to_the_target() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let running = Running::start(config(&cert)).await;
    let (endpoint, connection) = connect(&running, &cert).await;
    authenticate(&connection).await;

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut request = vec![VERSION, Command::Connect.byte()];
    request.extend_from_slice(&reference_ipv4(
        match echo.address.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("echo 应绑定 IPv4"),
        },
        echo.address.port(),
    ));
    send.write_all(&request).await.unwrap();
    send.write_all(b"tuic-tcp").await.unwrap();

    let mut echoed = [0u8; 8];
    timeout(Duration::from_secs(3), recv.read_exact(&mut echoed))
        .await
        .expect("TCP 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"tuic-tcp");
    send.finish().unwrap();
    drop(endpoint);
    running.shutdown().await;
}

#[tokio::test]
async fn authenticated_datagram_relays_udp_and_returns_the_reply() {
    let echo = Echo::udp("127.0.0.1").await;
    let cert = common::Certificate::new();
    let running = Running::start(config(&cert)).await;
    let (endpoint, connection) = connect(&running, &cert).await;
    authenticate(&connection).await;

    let payload = b"tuic-udp";
    let mut datagram = vec![VERSION, Command::Packet.byte()];
    datagram.extend_from_slice(&reference_udp_body(
        1,
        1,
        1,
        1,
        &reference_ipv4(
            match echo.address.ip() {
                std::net::IpAddr::V4(ip) => ip.octets(),
                std::net::IpAddr::V6(_) => panic!("echo 应绑定 IPv4"),
            },
            echo.address.port(),
        ),
        payload,
    ));
    connection
        .send_datagram(prost::bytes::Bytes::from(datagram))
        .unwrap();

    let reply = timeout(Duration::from_secs(3), connection.read_datagram())
        .await
        .expect("UDP 回包超时")
        .unwrap();
    assert_eq!(&reply[..2], &[VERSION, Command::Packet.byte()]);
    assert!(
        reply.windows(payload.len()).any(|window| window == payload),
        "{reply:?}"
    );
    drop(endpoint);
    running.shutdown().await;
}

#[tokio::test]
async fn unsupported_version_is_fail_closed() {
    let cert = common::Certificate::new();
    let running = Running::start(config(&cert)).await;
    let (endpoint, connection) = connect(&running, &cert).await;
    authenticate(&connection).await;

    // TUIC v5 没有多版本协商：任何非 5 版本的命令都必须关闭连接，而不是猜测或回落。
    let mut stream = connection.open_uni().await.unwrap();
    stream
        .write_all(&[4, Command::Authenticate.byte()])
        .await
        .unwrap();
    stream.finish().unwrap();

    timeout(Duration::from_secs(3), connection.closed())
        .await
        .expect("版本不支持时应关闭连接");

    drop(endpoint);
    running.shutdown().await;
}

/// 服务端真实 0-RTT 重连证据：同一 quinn 客户端进程先完整握手拿到票据，
/// 第二次连接通过 `into_0rtt` 在握手完成前发送 Connect 元数据，随后完成
/// 认证并从回环 TCP 目标取回数据。服务端必须输出 `tuic_0rtt_accepted`。
#[tokio::test]
async fn zero_rtt_reconnect_is_observed_on_the_server_and_relays_tcp() {
    let logs = capture_logs();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let running = Running::start(config_0rtt(&cert)).await;
    let tickets = Tickets::new();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config_0rtt(&cert, tickets.clone()));

    let mut request = vec![VERSION, Command::Connect.byte()];
    request.extend_from_slice(&reference_ipv4(
        match echo.address.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("echo 应绑定 IPv4"),
        },
        echo.address.port(),
    ));

    // 第一次连接：完整握手、认证、领取 NewSessionTicket。
    let first = timeout(
        Duration::from_secs(3),
        endpoint.connect(running.addresses[0], "localhost").unwrap(),
    )
    .await
    .expect("首次握手超时")
    .expect("首次握手失败");
    authenticate(&first).await;
    let (mut send, mut recv) = first.open_bi().await.unwrap();
    send.write_all(&request).await.unwrap();
    send.write_all(b"warm").await.unwrap();
    let mut warm = [0u8; 4];
    timeout(Duration::from_secs(3), recv.read_exact(&mut warm))
        .await
        .expect("首次 TCP 回显超时")
        .unwrap();
    assert_eq!(&warm, b"warm");
    tickets.wait_for(1).await;
    first.close(0u32.into(), b"");
    let _ = timeout(Duration::from_secs(3), first.closed()).await;

    // 第二次连接：必须拿到 0-RTT 密钥，而不是静默回退为完整握手。
    let (second, accepted) = endpoint
        .connect(running.addresses[0], "localhost")
        .unwrap()
        .into_0rtt()
        .expect("服务端未提供 0-RTT 密钥");
    // TUIC 的 exporter 认证只能在完整握手后计算；先在 0-RTT 中发送
    // Connect 元数据，再完成握手与认证，与内核出站的策略一致。
    let (mut send, mut recv) = second.open_bi().await.unwrap();
    send.write_all(&request).await.unwrap();

    assert!(
        timeout(Duration::from_secs(3), accepted)
            .await
            .expect("0-RTT 握手确认超时"),
        "服务端拒绝了 0-RTT"
    );
    authenticate(&second).await;
    send.write_all(b"early").await.unwrap();
    let mut echoed = [0u8; 5];
    timeout(Duration::from_secs(3), recv.read_exact(&mut echoed))
        .await
        .expect("0-RTT 重连 TCP 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"early");

    wait_for_log(&logs, "tuic_0rtt_accepted").await;
    let text = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    let events: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("tuic_0rtt_accepted"))
        .collect();
    assert!(
        events
            .iter()
            .any(|line| line.contains("tuic-0rtt-evidence")),
        "0-RTT 事件必须带唯一 tag: {text}"
    );
    for line in events {
        assert!(
            !line.contains(UUID)
                && !line.contains(PASSWORD)
                && !line.contains("token")
                && !line.contains("password"),
            "debug 事件不得输出 UUID/password/token: {line}"
        );
    }

    second.close(0u32.into(), b"");
    drop(endpoint);
    running.shutdown().await;
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let cert = common::Certificate::new();
    let running = Running::start(config(&cert)).await;
    let (endpoint, connection) = connect(&running, &cert).await;

    let uuid = uuid_bytes();
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, &uuid, b"wrong-password")
        .unwrap();
    let mut stream = connection.open_uni().await.unwrap();
    stream
        .write_all(&reference_authenticate(&uuid, &token))
        .await
        .unwrap();
    stream.finish().unwrap();

    // 认证失败后服务端关闭整个连接；随后的双向流不得完成。
    let closed = timeout(Duration::from_secs(3), async {
        loop {
            match connection.open_bi().await {
                Ok((mut send, _recv)) => {
                    let _ = send.write_all(b"\x05\x01").await;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(_) => return,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "认证失败后连接应被关闭");

    drop(endpoint);
    running.shutdown().await;
}
