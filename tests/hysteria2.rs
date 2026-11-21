//! Hysteria2 线协议单元测试。
//!
//! 不启动真实网络：`wire` 与 `obfs` 都是自包含的纯编解码模块，通过
//! `#[path]` 直接包含。认证、TCP/UDP 承载的端到端互操作由用户后续统一验收。

// 测试 crate 只覆盖部分编解码入口，未覆盖的生产函数在此按需放行。
#[allow(dead_code)]
#[path = "../src/transport/hysteria2/obfs.rs"]
mod obfs;
// wire.rs 的客户端侧解码入口仅生产/测试各用一部分，测试 crate 内按需放行。
#[allow(dead_code)]
#[path = "../src/transport/hysteria2/wire.rs"]
mod wire;

use http::HeaderValue;

fn varint(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    wire::encode_varint(value, &mut output).unwrap();
    output
}

#[test]
fn varint_round_trips_every_width_and_rejects_overflow() {
    for value in [
        0u64,
        1,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        wire::MAX_VARINT,
    ] {
        let encoded = varint(value);
        let expected_len = wire::varint_len(value).unwrap();
        assert_eq!(encoded.len(), expected_len, "值 {value} 的编码长度");
        assert_eq!(
            wire::decode_varint(&encoded).unwrap(),
            (value, expected_len)
        );
    }
    assert!(wire::varint_len(wire::MAX_VARINT + 1).is_err());
    assert!(wire::decode_varint(&[]).is_err());
    // 前缀声明 8 字节但只给出 2 字节。
    assert!(wire::decode_varint(&[0xc0, 0x00]).is_err());
}

#[test]
fn tcp_request_round_trips_with_padding_and_payload() {
    let frame = wire::encode_tcp_request("example.com:443", b"payload").unwrap();
    assert_eq!(
        wire::decode_varint(&frame).unwrap(),
        (wire::FRAME_TYPE_TCP_REQUEST, 2)
    );
    let (address, payload) = wire::decode_tcp_request(&frame[2..]).unwrap();
    assert_eq!(address, "example.com:443");
    assert_eq!(payload, b"payload".as_slice());
}

#[tokio::test]
async fn async_reader_matches_sync_tcp_request_decoder() {
    use tokio::io::AsyncReadExt;

    let frame = wire::encode_tcp_request("[2001:db8::1]:8443", b"hello").unwrap();
    let mut reader = frame.as_slice();
    let frame_type = wire::read_varint(&mut reader).await.unwrap();
    assert_eq!(frame_type, wire::FRAME_TYPE_TCP_REQUEST);
    let address = wire::read_tcp_request(&mut reader).await.unwrap();
    assert_eq!(address, "[2001:db8::1]:8443");
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest.as_slice(), b"hello".as_slice());
}

#[test]
fn tcp_request_rejects_oversize_address_padding_and_truncation() {
    // 地址长度 2049 > 2048。
    assert!(wire::decode_tcp_request(&varint(2049)).is_err());

    // 地址合法，但填充长度 4097 > 4096。
    let mut frame = varint(1);
    frame.extend_from_slice(b"a");
    frame.extend_from_slice(&varint(4097));
    assert!(wire::decode_tcp_request(&frame).is_err());

    // 声明 4 字节地址但只提供 2 字节。
    let mut frame = varint(4);
    frame.extend_from_slice(b"ab");
    assert!(wire::decode_tcp_request(&frame).is_err());

    // 缺少填充长度字段。
    let mut frame = varint(1);
    frame.push(b'a');
    assert!(wire::decode_tcp_request(&frame).is_err());
}

#[test]
fn tcp_response_round_trips_success_and_failure() {
    let success = wire::encode_tcp_response(true, "", b"body").unwrap();
    assert_eq!(
        wire::decode_tcp_response(&success).unwrap(),
        (true, String::new())
    );

    let failure = wire::encode_tcp_response(false, "connect failed", &[]).unwrap();
    assert_eq!(
        wire::decode_tcp_response(&failure).unwrap(),
        (false, "connect failed".to_owned())
    );

    // 消息长度超限。
    let mut frame = vec![0u8];
    frame.extend_from_slice(&varint(2049));
    assert!(wire::decode_tcp_response(&frame).is_err());
}

#[test]
fn padding_lengths_and_characters_stay_in_range() {
    for (min, max) in [(64usize, 512usize), (128, 1024), (256, 2048)] {
        for _ in 0..32 {
            let padding = wire::random_padding(min, max).unwrap();
            assert!(padding.len() >= min && padding.len() < max);
            assert!(
                padding.iter().all(|byte| byte.is_ascii_alphanumeric()),
                "填充必须为字母或数字"
            );
        }
    }
    assert!(wire::random_padding(0, 16).is_err());
    assert!(wire::random_padding(16, 16).is_err());
}

#[test]
fn auth_request_headers_parse_and_reject_missing_or_empty_password() {
    let mut headers = http::HeaderMap::new();
    headers.insert(wire::HEADER_AUTH, HeaderValue::from_static("secret"));
    headers.insert(wire::HEADER_CC_RX, HeaderValue::from_static("12500000"));
    let request = wire::parse_auth_request(&headers).unwrap();
    assert_eq!(request.password.as_slice(), b"secret".as_slice());
    assert_eq!(request.rx, 12_500_000);

    // 非法 CC-RX 按 0 处理，与上游忽略解析错误一致。
    headers.insert(wire::HEADER_CC_RX, HeaderValue::from_static("auto"));
    assert_eq!(wire::parse_auth_request(&headers).unwrap().rx, 0);

    headers.insert(wire::HEADER_AUTH, HeaderValue::from_static(""));
    assert!(wire::parse_auth_request(&headers).is_err());

    headers.remove(wire::HEADER_AUTH);
    assert!(wire::parse_auth_request(&headers).is_err());
}

#[test]
fn auth_endpoint_matching_uses_post_authority_and_path() {
    let uri: http::Uri = "https://hysteria/auth".parse().unwrap();
    assert!(wire::is_auth_request(&http::Method::POST, &uri));
    assert!(!wire::is_auth_request(&http::Method::GET, &uri));

    let wrong_host: http::Uri = "https://example.com/auth".parse().unwrap();
    assert!(!wire::is_auth_request(&http::Method::POST, &wrong_host));

    let wrong_path: http::Uri = "https://hysteria/other".parse().unwrap();
    assert!(!wire::is_auth_request(&http::Method::POST, &wrong_path));
}

#[test]
fn auth_response_headers_round_trip_and_padding_is_bounded() {
    let headers = wire::auth_ok_headers(true, 0).unwrap();
    let response = wire::parse_auth_response(&headers);
    assert!(response.udp_enabled);
    assert_eq!(response.rx, 0);
    assert!(!response.rx_auto);

    let padding = headers.get(wire::HEADER_PADDING).unwrap().as_bytes();
    assert!(padding.len() >= 256 && padding.len() < 2048);
    assert!(padding.iter().all(|byte| byte.is_ascii_alphanumeric()));

    let headers = wire::auth_ok_headers(false, 42).unwrap();
    assert!(!wire::parse_auth_response(&headers).udp_enabled);
    assert_eq!(wire::parse_auth_response(&headers).rx, 42);
}

#[test]
fn auth_response_auto_matches_upstream_ignore_client_bandwidth() {
    // 上游 IgnoreClientBandwidth 使用字符串哨兵 "auto"。
    let headers = wire::auth_ok_headers_auto(true, 0, true).unwrap();
    assert_eq!(headers.get(wire::HEADER_CC_RX).unwrap().as_bytes(), b"auto");
    let response = wire::parse_auth_response(&headers);
    assert!(response.rx_auto);
    assert_eq!(response.rx, 0);
}

#[test]
fn password_digest_match_rejects_wrong_and_empty_passwords() {
    let expected = [wire::digest_password(b"correct horse")];
    assert!(wire::match_password_digest(b"correct horse", &expected));
    assert!(!wire::match_password_digest(b"wrong", &expected));
    assert!(!wire::match_password_digest(b"", &expected));
    assert!(!wire::match_password_digest(b"correct horse", &[]));
    // 长度不同也不能因前缀相同而通过。
    assert!(!wire::match_password_digest(
        b"correct horse battery",
        &expected
    ));
}

#[test]
fn udp_message_round_trips_and_fragmentation_reassembles() {
    let payload: Vec<u8> = (0..4000u32).map(|value| (value % 251) as u8).collect();
    let fragments =
        wire::fragment_udp_message(7, 9, "example.com:53", &payload, wire::UDP_MTU).unwrap();
    assert!(fragments.len() > 1);

    let mut reassembled = Vec::new();
    for (index, frame) in fragments.iter().enumerate() {
        assert!(frame.len() <= wire::UDP_MTU);
        let message = wire::decode_udp_message(frame).unwrap();
        assert_eq!(message.session_id, 7);
        assert_eq!(message.packet_id, 9);
        assert_eq!(message.destination, "example.com:53");
        assert_eq!(message.fragment_total as usize, fragments.len());
        assert_eq!(message.fragment_id as usize, index);
        reassembled.extend_from_slice(message.payload);
    }
    assert_eq!(reassembled, payload);
}

#[test]
fn udp_message_rejects_oversize_target_and_invalid_fragment_fields() {
    let mut frame = vec![0u8; 8];
    frame[7] = 1; // fragmentTotal 合法，确保失败来自超长目标
    frame.extend_from_slice(&varint(2049));
    assert!(wire::decode_udp_message(&frame).is_err());

    // fragmentTotal = 0。
    let mut frame = vec![0u8, 0, 0, 0, 0, 1, 0, 0];
    frame.extend_from_slice(&varint(1));
    frame.push(b'a');
    assert!(wire::decode_udp_message(&frame).is_err());

    // fragmentID >= fragmentTotal。
    let mut frame = vec![0u8, 0, 0, 0, 0, 1, 1, 1];
    frame.extend_from_slice(&varint(1));
    frame.push(b'a');
    assert!(wire::decode_udp_message(&frame).is_err());

    assert!(wire::encode_udp_message(0, 0, 0, 1, "", b"x").is_err());
    assert!(wire::encode_udp_message(0, 0, 0, 0, "a:1", b"x").is_err());
    assert!(wire::fragment_udp_message(0, 0, "a:1", &[0u8; 4097], wire::UDP_MTU).is_err());
}

#[test]
fn host_port_parsing_matches_sing_socksaddr_format() {
    assert_eq!(
        wire::parse_host_port("example.com:443").unwrap(),
        ("example.com".to_owned(), 443)
    );
    assert_eq!(
        wire::parse_host_port("192.0.2.7:80").unwrap(),
        ("192.0.2.7".to_owned(), 80)
    );
    assert_eq!(
        wire::parse_host_port("[2001:db8::1]:8443").unwrap(),
        ("2001:db8::1".to_owned(), 8443)
    );
    // 裸 IPv6 缺少方括号，Go 侧同样无法按 host:port 解析。
    for invalid in [
        "2001:db8::1:443",
        "example.com",
        ":443",
        "example.com:",
        "exa mple.com:443",
        "example.com:99999",
        "[2001:db8::1:443",
        "[fe80::1%en0]:443",
    ] {
        assert!(wire::parse_host_port(invalid).is_err(), "{invalid}");
    }
    assert_eq!(
        wire::format_host_port("2001:db8::1", 443),
        "[2001:db8::1]:443"
    );
    assert_eq!(
        wire::format_host_port("example.com", 443),
        "example.com:443"
    );
}

#[test]
fn salamander_round_trip_and_wire_layout() {
    let password = b"obfs-password";
    let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let plaintext = b"hysteria2-quic-packet";

    let sealed = obfs::seal_with_salt(password, salt, plaintext);
    assert_eq!(&sealed[..obfs::SALT_LEN], &salt);

    let key = obfs::derive_key(password, &salt);
    for (index, byte) in plaintext.iter().enumerate() {
        assert_eq!(
            sealed[obfs::SALT_LEN + index],
            byte ^ key[index % obfs::KEY_LEN]
        );
    }
    assert_eq!(obfs::open(password, &sealed).unwrap().as_slice(), plaintext);

    // 相同明文、不同 salt 必须产生不同的线上字节。
    let other = obfs::seal_with_salt(password, [9u8; obfs::SALT_LEN], plaintext);
    assert_ne!(&sealed[..], &other[..]);
    assert_eq!(obfs::open(password, &other).unwrap().as_slice(), plaintext);
}

#[test]
fn salamander_rejects_short_or_wrong_password_packets() {
    assert!(obfs::open(b"pw", &[]).is_err());
    assert!(obfs::open(b"pw", &[0u8; obfs::SALT_LEN]).is_err());
    assert!(obfs::open(b"pw", &[0u8; obfs::SALT_LEN - 1]).is_err());

    let sealed = obfs::seal_with_salt(b"pw", [7u8; obfs::SALT_LEN], b"payload");
    let wrong = obfs::open(b"other", &sealed).unwrap();
    assert_ne!(wrong.as_slice(), b"payload".as_slice());
}

#[test]
fn salamander_open_into_rejects_small_output_buffer() {
    let sealed = obfs::seal_with_salt(b"pw", [3u8; obfs::SALT_LEN], b"0123456789");
    let mut output = [0u8; 4];
    assert!(obfs::open_into(b"pw", &sealed, &mut output).is_err());

    let mut output = [0u8; 16];
    let opened = obfs::open_into(b"pw", &sealed, &mut output).unwrap();
    assert_eq!(&*opened, b"0123456789".as_slice());
}

// ---------- 端到端回环 ----------

mod common;

use std::{sync::Arc, time::Duration};

use common::{Echo, Running};
use prost::bytes::Buf as _;
use serde_json::json;
use tokio::{io::AsyncReadExt, time::timeout};

const PASSWORD: &str = "hysteria2-loopback-password";

fn config(cert: &common::Certificate) -> serde_json::Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hy2",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"handshake_timeout_ms": 3000, "shutdown_timeout_ms": 500}
    })
}

fn quic_client(cert: &common::Certificate) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).unwrap();
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(5)).unwrap(),
    ));
    client.transport_config(Arc::new(transport));
    client
}

/// 建立 QUIC 连接并通过 HTTP/3 完成认证；返回仍可打开原始流的连接。
async fn authenticated(
    running: &Running,
    cert: &common::Certificate,
) -> (quinn::Endpoint, quinn::Connection) {
    let (endpoint, connection, _) = authenticate_with_rx(running, cert, "0").await;
    (endpoint, connection)
}

/// 与 [`authenticated`] 相同，但可指定认证请求里的 `Hysteria-CC-RX`，
/// 并返回认证响应头用于校验带宽通告。
async fn authenticate_with_rx(
    running: &Running,
    cert: &common::Certificate,
    rx: &'static str,
) -> (quinn::Endpoint, quinn::Connection, http::HeaderMap) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quic_client(cert));
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(running.addresses[0], "localhost").unwrap(),
    )
    .await
    .expect("Hysteria2 QUIC 握手超时")
    .expect("Hysteria2 QUIC 握手失败");

    let (mut h3_connection, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
    let driver = tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });

    let request = http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", PASSWORD)
        .header("Hysteria-CC-RX", rx)
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("认证响应超时")
        .unwrap();
    assert_eq!(response.status().as_u16(), wire::STATUS_AUTH_OK);
    assert_eq!(
        response.headers().get("Hysteria-UDP").map(|v| v.as_bytes()),
        Some(&b"true"[..])
    );
    let headers = response.headers().clone();
    // 服务端认证后改用原始双向流；停止 h3 驱动，避免其处理后续仓促的流状态。
    driver.abort();
    drop(send_request);
    drop(stream);
    (endpoint, connection, headers)
}

/// 在基础配置的 hysteria2 入站上覆盖字段。
fn config_with(cert: &common::Certificate, extra: serde_json::Value) -> serde_json::Value {
    let mut value = config(cert);
    let inbound = value["inbounds"]
        .as_array_mut()
        .and_then(|inbounds| inbounds.first_mut())
        .and_then(|inbound| inbound.as_object_mut())
        .expect("测试配置必须包含 hysteria2 入站");
    for (key, value) in extra.as_object().expect("extra 必须是对象") {
        inbound.insert(key.clone(), value.clone());
    }
    value
}

fn tcp_request(destination: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    wire::encode_varint(wire::FRAME_TYPE_TCP_REQUEST, &mut bytes).unwrap();
    wire::encode_varint(destination.len() as u64, &mut bytes).unwrap();
    bytes.extend_from_slice(destination.as_bytes());
    wire::encode_varint(0, &mut bytes).unwrap();
    bytes.extend_from_slice(payload);
    bytes
}

async fn read_varint(stream: &mut quinn::RecvStream) -> u64 {
    wire::read_varint(stream).await.unwrap()
}

#[tokio::test]
async fn authenticated_tcp_stream_relays_to_the_target() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let running = Running::start(config(&cert)).await;
    let (endpoint, connection) = authenticated(&running, &cert).await;

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&tcp_request(&echo.address.to_string(), b"hy2-tcp"))
        .await
        .unwrap();

    assert_eq!(recv.read_u8().await.unwrap(), 0, "TCP 响应状态应为成功");
    assert_eq!(read_varint(&mut recv).await, 0, "成功响应消息为空");
    let padding = read_varint(&mut recv).await;
    let mut skipped = tokio::io::sink();
    let copied = tokio::io::copy(&mut (&mut recv).take(padding), &mut skipped)
        .await
        .unwrap();
    assert_eq!(copied, padding);

    let mut echoed = [0u8; 7];
    timeout(Duration::from_secs(3), recv.read_exact(&mut echoed))
        .await
        .expect("TCP 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"hy2-tcp");

    let _ = send.finish();
    drop(endpoint);
    running.shutdown().await;
}

#[tokio::test]
async fn authenticated_datagram_relays_udp_and_returns_the_reply() {
    let echo = Echo::udp("127.0.0.1").await;
    let cert = common::Certificate::new();
    let running = Running::start(config(&cert)).await;
    let (endpoint, connection) = authenticated(&running, &cert).await;

    let payload = b"hy2-udp";
    let destination = echo.address.to_string();
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&1u32.to_be_bytes()); // sessionID
    datagram.extend_from_slice(&1u16.to_be_bytes()); // packetID
    datagram.push(0); // fragmentID
    datagram.push(1); // fragmentTotal
    wire::encode_varint(destination.len() as u64, &mut datagram).unwrap();
    datagram.extend_from_slice(destination.as_bytes());
    datagram.extend_from_slice(payload);
    connection
        .send_datagram(prost::bytes::Bytes::from(datagram))
        .unwrap();

    let reply = timeout(Duration::from_secs(3), connection.read_datagram())
        .await
        .expect("UDP 回包超时")
        .unwrap();
    let (target_length, offset) = wire::decode_varint(&reply[8..]).unwrap();
    let target_start = 8 + offset;
    let target_end = target_start + target_length as usize;
    assert_eq!(
        std::str::from_utf8(&reply[target_start..target_end]).unwrap(),
        destination
    );
    assert_eq!(&reply[target_end..], payload, "回程载荷应保持一致");

    drop(endpoint);
    running.shutdown().await;
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let cert = common::Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quic_client(&cert));
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(running.addresses[0], "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();

    let (mut h3_connection, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
    let driver = tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });
    let request = http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", "wrong-password")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    // 服务端在失败路径上尽力发送 404 后立即关闭 QUIC 连接；客户端可能先
    // 收到 404，也可能只看到连接关闭。两者都表示认证被拒绝。
    if let Ok(Ok(response)) = timeout(Duration::from_secs(3), stream.recv_response()).await {
        assert_eq!(response.status().as_u16(), 404)
    }
    driver.abort();

    drop(endpoint);
    running.shutdown().await;
}

#[tokio::test]
async fn client_declared_rx_activates_brutal_send_path() {
    // 客户端声明 1 MB/s 接收带宽后，服务端发送方向进入 Brutal；这里验证
    // 该路径上的流中继仍然工作（服务端 up 未配置，不做 MaxTx 裁剪）。
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let running = Running::start(config(&cert)).await;
    let (endpoint, connection, headers) = authenticate_with_rx(&running, &cert, "1000000").await;
    assert_eq!(
        headers
            .get(wire::HEADER_CC_RX)
            .map(|value| value.as_bytes()),
        Some(&b"0"[..]),
        "down 未配置时 MaxRx 为 0"
    );

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&tcp_request(&echo.address.to_string(), b"brutal"))
        .await
        .unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), 0);
    assert_eq!(read_varint(&mut recv).await, 0);
    let padding = read_varint(&mut recv).await;
    let mut skipped = tokio::io::sink();
    tokio::io::copy(&mut (&mut recv).take(padding), &mut skipped)
        .await
        .unwrap();
    let mut echoed = [0u8; 6];
    timeout(Duration::from_secs(3), recv.read_exact(&mut echoed))
        .await
        .expect("Brutal 路径回显超时")
        .unwrap();
    assert_eq!(&echoed, b"brutal");

    let _ = send.finish();
    drop(endpoint);
    running.shutdown().await;
}

#[tokio::test]
async fn auth_advertises_server_downlink_as_max_rx_bytes_per_second() {
    let cert = common::Certificate::new();
    // bandwidth.down/MaxRx 通告给客户端，单位 byte/s。
    let running = Running::start(config_with(&cert, json!({"down_mbps": 8}))).await;
    let (endpoint, _connection, headers) = authenticate_with_rx(&running, &cert, "0").await;
    assert_eq!(
        headers
            .get(wire::HEADER_CC_RX)
            .map(|value| value.as_bytes()),
        Some(&b"1000000"[..])
    );
    drop(endpoint);
    running.shutdown().await;
}

#[tokio::test]
async fn ignore_client_bandwidth_returns_upstream_auto_sentinel() {
    let cert = common::Certificate::new();
    let running = Running::start(config_with(
        &cert,
        json!({"down_mbps": 8, "ignore_client_bandwidth": true}),
    ))
    .await;
    let (endpoint, _connection, headers) = authenticate_with_rx(&running, &cert, "2500000").await;
    assert_eq!(
        headers
            .get(wire::HEADER_CC_RX)
            .map(|value| value.as_bytes()),
        Some(&b"auto"[..]),
        "ignoreClientBandwidth 必须使用上游 auto 哨兵"
    );
    drop(endpoint);
    running.shutdown().await;
}

// ---------- gecko obfs 回环客户端（独立实现） ----------

mod gecko_client {
    use std::{
        collections::HashMap,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU8, Ordering},
        },
        task::{Context, Poll, ready},
    };

    use blake2::{Blake2b, Digest, digest::consts::U32};
    use quinn::udp::{RecvMeta, Transmit};
    use quinn::{AsyncUdpSocket, UdpPoller};
    use tokio::net::UdpSocket;

    type Blake2b256 = Blake2b<U32>;
    const SALT: usize = 8;
    const HEADER: usize = 5;
    const MIN_PACKET: usize = 512;
    const MAX_PACKET: usize = 1200;

    pub struct ClientSocket {
        io: Arc<UdpSocket>,
        password: Vec<u8>,
        message_id: AtomicU8,
        reassembly: Mutex<HashMap<u8, Vec<Option<Vec<u8>>>>>,
    }

    impl ClientSocket {
        pub async fn new(server: std::net::SocketAddr, password: &str) -> Arc<Self> {
            let io = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            io.connect(server).await.unwrap();
            Arc::new(Self {
                io: Arc::new(io),
                password: password.as_bytes().to_vec(),
                message_id: AtomicU8::new(0),
                reassembly: Mutex::new(HashMap::new()),
            })
        }

        fn key(&self, salt: &[u8]) -> [u8; 32] {
            let mut hasher = Blake2b256::new();
            hasher.update(&self.password);
            hasher.update(salt);
            hasher.finalize().into()
        }

        fn seal(&self, frame: &[u8]) -> Vec<u8> {
            let mut salt = [0u8; SALT];
            aws_lc_rs::rand::fill(&mut salt).unwrap();
            let key = self.key(&salt);
            let mut wire = Vec::with_capacity(SALT + frame.len());
            wire.extend_from_slice(&salt);
            wire.extend(
                frame
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % 32]),
            );
            wire
        }

        fn open(&self, wire: &[u8]) -> Option<Vec<u8>> {
            if wire.len() <= SALT {
                return None;
            }
            let key = self.key(&wire[..SALT]);
            Some(
                wire[SALT..]
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % 32])
                    .collect(),
            )
        }

        fn frames(&self, packet: &[u8]) -> Vec<Vec<u8>> {
            let chunks = 3usize;
            let chunk_size = packet.len() / chunks;
            let message_id = self.message_id.fetch_add(1, Ordering::Relaxed);
            let mut frames = Vec::with_capacity(chunks);
            for index in 0..chunks {
                let start = index * chunk_size;
                let end = if index + 1 == chunks {
                    packet.len()
                } else {
                    start + chunk_size
                };
                let chunk = &packet[start..end];
                let base = SALT + HEADER + chunk.len();
                let pad = MIN_PACKET
                    .saturating_sub(base)
                    .min(MAX_PACKET.saturating_sub(base));
                let mut frame = vec![0u8; HEADER + pad + chunk.len()];
                frame[0] = 0x80;
                frame[1] = message_id;
                frame[2] = ((index as u8) << 4) | chunks as u8;
                frame[3..5].copy_from_slice(&(pad as u16).to_be_bytes());
                aws_lc_rs::rand::fill(&mut frame[HEADER..HEADER + pad]).unwrap();
                frame[HEADER + pad..].copy_from_slice(chunk);
                frames.push(frame);
            }
            frames
        }

        fn accept(&self, frame: &[u8]) -> Option<Vec<u8>> {
            if frame.len() < HEADER || frame[0] & 0x80 == 0 {
                return None;
            }
            let message_id = frame[1];
            let chunk_index = frame[2] >> 4;
            let total = frame[2] & 0x0f;
            if !(2..=8).contains(&total) || chunk_index >= total {
                return None;
            }
            let pad = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
            let payload = frame.get(HEADER + pad..)?.to_vec();
            let mut guard = self.reassembly.lock().unwrap();
            let chunks = guard
                .entry(message_id)
                .or_insert_with(|| vec![None; usize::from(total)]);
            if chunks.len() != usize::from(total) {
                return None;
            }
            *chunks.get_mut(usize::from(chunk_index))? = Some(payload);
            if chunks.iter().any(Option::is_none) {
                return None;
            }
            let chunks = guard.remove(&message_id)?;
            Some(chunks.into_iter().flatten().flatten().collect())
        }
    }

    impl std::fmt::Debug for ClientSocket {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("ClientSocket")
                .finish_non_exhaustive()
        }
    }

    impl AsyncUdpSocket for ClientSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(WritePoller {
                io: self.io.clone(),
            })
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
            let segment = transmit
                .segment_size
                .filter(|size| *size > 0)
                .unwrap_or(transmit.contents.len().max(1));
            for packet in transmit.contents.chunks(segment) {
                if packet.first().is_some_and(|byte| byte & 0x80 != 0) {
                    for frame in self.frames(packet) {
                        let wire = self.seal(&frame);
                        let _ = self.io.try_send(&wire)?;
                    }
                } else {
                    let wire = self.seal(packet);
                    let _ = self.io.try_send(&wire)?;
                }
            }
            Ok(())
        }

        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            bufs: &mut [std::io::IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<std::io::Result<usize>> {
            let Some(buffer) = bufs.first_mut() else {
                return Poll::Ready(Ok(0));
            };
            let Some(metadata) = meta.first_mut() else {
                return Poll::Ready(Ok(0));
            };
            let mut scratch = vec![0u8; 65_543];
            loop {
                ready!(self.io.poll_recv_ready(cx))?;
                let length = match self.io.try_recv(&mut scratch) {
                    Ok(length) => length,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                let Some(plain) = self.open(&scratch[..length]) else {
                    continue;
                };
                let packet = if plain.first().is_some_and(|byte| byte & 0x80 != 0) {
                    let Some(packet) = self.accept(&plain) else {
                        continue;
                    };
                    packet
                } else {
                    plain
                };
                if packet.len() > buffer.len() {
                    continue;
                }
                buffer[..packet.len()].copy_from_slice(&packet);
                metadata.addr = self.io.peer_addr()?;
                metadata.len = packet.len();
                metadata.stride = packet.len();
                metadata.ecn = None;
                metadata.dst_ip = None;
                return Poll::Ready(Ok(1));
            }
        }

        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            self.io.local_addr()
        }

        fn max_transmit_segments(&self) -> usize {
            1
        }

        fn max_receive_segments(&self) -> usize {
            1
        }

        fn may_fragment(&self) -> bool {
            false
        }
    }

    struct WritePoller {
        io: Arc<UdpSocket>,
    }

    impl std::fmt::Debug for WritePoller {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.debug_struct("WritePoller").finish()
        }
    }

    impl UdpPoller for WritePoller {
        fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.io.poll_send_ready(cx)
        }
    }
}

#[tokio::test]
async fn authenticated_tcp_stream_relays_over_gecko_obfs() {
    const OBFS: &str = "gecko-loopback-password";
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = common::Certificate::new();
    let mut value = config(&cert);
    value["inbounds"][0]["obfs"] = json!({
        "type": "gecko",
        "password": OBFS,
        "min_packet_size": 512,
        "max_packet_size": 1200
    });
    let running = Running::start(value).await;

    let socket = gecko_client::ClientSocket::new(running.addresses[0], OBFS).await;
    let runtime = Arc::new(quinn::TokioRuntime);
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )
    .unwrap();
    endpoint.set_default_client_config(quic_client(&cert));
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(running.addresses[0], "localhost").unwrap(),
    )
    .await
    .expect("gecko QUIC 握手超时")
    .expect("gecko QUIC 握手失败");

    let (mut h3_connection, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
    let driver = tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });
    let request = http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", PASSWORD)
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("认证响应超时")
        .unwrap();
    assert_eq!(response.status().as_u16(), wire::STATUS_AUTH_OK);
    driver.abort();
    drop(send_request);
    drop(stream);

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&tcp_request(&echo.address.to_string(), b"gecko-tcp"))
        .await
        .unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), 0, "TCP 响应状态应为成功");
    assert_eq!(read_varint(&mut recv).await, 0);
    let padding = read_varint(&mut recv).await;
    let mut skipped = tokio::io::sink();
    let copied = tokio::io::copy(&mut (&mut recv).take(padding), &mut skipped)
        .await
        .unwrap();
    assert_eq!(copied, padding);
    let mut echoed = [0u8; 9];
    timeout(Duration::from_secs(3), recv.read_exact(&mut echoed))
        .await
        .expect("gecko TCP 回显超时")
        .unwrap();
    assert_eq!(&echoed, b"gecko-tcp");

    let _ = send.finish();
    drop(endpoint);
    running.shutdown().await;
}

// ---------- masquerade ----------

async fn masquerade_request(
    running: &Running,
    cert: &common::Certificate,
    path: &str,
) -> (u16, Vec<u8>) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quic_client(cert));
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(running.addresses[0], "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut h3_connection, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
    let driver = tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://hysteria{path}"))
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("masquerade 响应超时")
        .unwrap();
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = timeout(Duration::from_secs(3), stream.recv_data())
        .await
        .expect("masquerade 正文超时")
        .unwrap()
    {
        let mut chunk = chunk;
        let size = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(size));
    }
    driver.abort();
    drop(endpoint);
    (status, body)
}

#[tokio::test]
async fn masquerade_string_serves_unauthenticated_requests() {
    let cert = common::Certificate::new();
    let mut value = config(&cert);
    value["inbounds"][0]["masquerade"] = json!({
        "type": "string",
        "content": "masquerade-string"
    });
    let running = Running::start(value).await;
    let (status, body) = masquerade_request(&running, &cert, "/anything").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"masquerade-string");
    running.shutdown().await;
}

#[tokio::test]
async fn masquerade_file_serves_directory_content() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("index.html"), b"<h1>index</h1>").unwrap();
    std::fs::write(directory.path().join("data.txt"), b"file-body").unwrap();
    let cert = common::Certificate::new();
    let mut value = config(&cert);
    value["inbounds"][0]["masquerade"] = json!({
        "type": "file",
        "directory": directory.path().to_string_lossy()
    });
    let running = Running::start(value).await;

    let (status, body) = masquerade_request(&running, &cert, "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"<h1>index</h1>");

    let (status, body) = masquerade_request(&running, &cert, "/data.txt").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"file-body");

    let (status, _) = masquerade_request(&running, &cert, "/missing.txt").await;
    assert_eq!(status, 404);
    running.shutdown().await;
}
