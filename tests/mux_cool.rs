//! Mux.Cool 服务端集成测试。
//!
//! 这里的最小帧编码器/解码器完全独立实现，只用字面量状态与选项值，
//! 不调用被测模块的编码函数来构造期望值。

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpListener,
    time::timeout,
};

// `src/mux.rs` 使用 `crate::forward/...`；测试 crate 根部的同名重导出让它
// 能以 `#[path]` 方式直接编译，而无需把模块注册进 lib.rs。
pub use dubhe::{config, forward, outbound, route, session, telemetry};

// 测试 crate 只覆盖 mux 的部分入口，未覆盖的生产函数在此按需放行。
#[allow(dead_code)]
#[path = "../src/mux.rs"]
mod mux;

use config::Config;
use forward::Context;
use session::Target;

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;
const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;

fn context() -> Arc<Context> {
    let config = Config::from_json(
        r#"{
            "version": 1,
            "inbounds": [{"type":"socks5","tag":"test","listen":"127.0.0.1:0"}],
            "outbounds": [{"type":"direct","tag":"direct"}],
            "route": {"default":"direct"},
            "limits": {"udp_queue_bytes":262144,"udp_queue_packets":64}
        }"#,
    )
    .expect("测试配置有效");
    Arc::new(Context::new(&config).expect("测试上下文可构造"))
}

fn address_bytes(host: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    match host.parse::<IpAddr>().expect("测试地址有效") {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(3);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes
}

fn domain_bytes(domain: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(2);
    bytes.push(domain.len() as u8);
    bytes.extend_from_slice(domain.as_bytes());
    bytes
}

fn meta(id: u16, status: u8, option: u8, body: &[u8]) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.push(status);
    metadata.push(option);
    metadata.extend_from_slice(body);
    assert!(metadata.len() <= 512);
    let mut frame = Vec::new();
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame
}

/// New 帧：network、端口、地址（可选 8 字节 GlobalID），Data 时追加长度与负载。
fn new_frame(
    id: u16,
    network: u8,
    host: &str,
    port: u16,
    data: Option<&[u8]>,
    global_id: Option<[u8; 8]>,
) -> Vec<u8> {
    let mut body = vec![network];
    body.extend_from_slice(&port.to_be_bytes());
    if host.parse::<IpAddr>().is_ok() {
        body.extend_from_slice(&address_bytes(host));
    } else {
        body.extend_from_slice(&domain_bytes(host));
    }
    if let Some(global_id) = global_id {
        body.extend_from_slice(&global_id);
    }
    let option = if data.is_some() { OPTION_DATA } else { 0 };
    let mut frame = meta(id, STATUS_NEW, option, &body);
    if let Some(data) = data {
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
    }
    frame
}

/// Keep+Data 帧；可选携带 UDP 目标。
fn keep_frame(id: u16, target: Option<(&str, u16)>, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some((host, port)) = target {
        body.push(NETWORK_UDP);
        body.extend_from_slice(&port.to_be_bytes());
        if host.parse::<IpAddr>().is_ok() {
            body.extend_from_slice(&address_bytes(host));
        } else {
            body.extend_from_slice(&domain_bytes(host));
        }
    }
    let mut frame = meta(id, STATUS_KEEP, OPTION_DATA, &body);
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn end_frame(id: u16, error: bool) -> Vec<u8> {
    let [high, low] = id.to_be_bytes();
    vec![
        0,
        4,
        high,
        low,
        STATUS_END,
        if error { OPTION_ERROR } else { 0 },
    ]
}

/// 测试侧的独立下行解码结果；`network`/`target` 为保持与线格式一致而保留，
/// 当前断言只看 id/status/option/payload。
#[derive(Debug)]
#[allow(dead_code)]
struct Decoded {
    id: u16,
    status: u8,
    option: u8,
    network: Option<u8>,
    target: Option<(String, u16)>,
    payload: Option<Vec<u8>>,
}

fn decode_address(bytes: &[u8]) -> (String, usize) {
    match bytes[0] {
        1 => {
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[1..5]).unwrap());
            (ip.to_string(), 5)
        }
        2 => {
            let length = usize::from(bytes[1]);
            let domain = std::str::from_utf8(&bytes[2..2 + length])
                .unwrap()
                .to_owned();
            (domain, 2 + length)
        }
        3 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[1..17]).unwrap());
            (ip.to_string(), 17)
        }
        other => panic!("未知地址类型 {other}"),
    }
}

/// 独立解码服务端下行帧；仅用于测试观察，不参与被测逻辑。
async fn decode<R: AsyncRead + Unpin>(read: &mut R) -> io::Result<Option<Decoded>> {
    let mut length = [0u8; 2];
    match read.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let meta_length = usize::from(u16::from_be_bytes(length));
    assert!((4..=512).contains(&meta_length));
    let mut metadata = vec![0u8; meta_length];
    read.read_exact(&mut metadata).await?;

    let id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let option = metadata[3];
    let mut network = None;
    let mut target = None;
    if meta_length > 4 && metadata[4] == NETWORK_UDP {
        network = Some(NETWORK_UDP);
        let port = u16::from_be_bytes([metadata[5], metadata[6]]);
        let (host, _) = decode_address(&metadata[7..]);
        target = Some((host, port));
    }
    let payload = if option & OPTION_DATA != 0 {
        let mut size = [0u8; 2];
        read.read_exact(&mut size).await?;
        let size = usize::from(u16::from_be_bytes(size));
        let mut payload = vec![0u8; size];
        read.read_exact(&mut payload).await?;
        Some(payload)
    } else {
        None
    };
    Ok(Some(Decoded {
        id,
        status,
        option,
        network,
        target,
        payload,
    }))
}

async fn echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut read, mut write) = stream.into_split();
        let _ = tokio::io::copy(&mut read, &mut write).await;
    });
    address
}

async fn start_ctx(
    ctx: Arc<Context>,
    allow_udp: bool,
) -> (DuplexStream, tokio::task::JoinHandle<io::Result<()>>) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(mux::serve(server, ctx, "test".into(), allow_udp));
    (client, task)
}

async fn start_with(allow_udp: bool) -> (DuplexStream, tokio::task::JoinHandle<io::Result<()>>) {
    start_ctx(context(), allow_udp).await
}

fn sniff_context(extra: &str) -> Arc<Context> {
    let config = Config::from_json(&format!(
        r#"{{
            "version": 1,
            "inbounds": [{{"type":"socks5","tag":"test","listen":"127.0.0.1:0"}}],
            "outbounds": [
                {{"type":"direct","tag":"direct"}},
                {{"type":"reject","tag":"blocked"}}
            ],
            "route": {{
                "default": "direct",
                "rules": [{{"domain_suffix": ["blocked.test"], "outbound": "blocked"}}]
            }},
            "dns": {{"hosts": {{"override.test": ["127.0.0.1"]}}}},
            "sniffing": {{"enabled": true, "timeout_ms": 150{extra}}}
        }}"#
    ))
    .expect("嗅探测试配置有效");
    Arc::new(Context::new(&config).expect("测试上下文可构造"))
}

/// 独立构造带 SNI 的最小 TLS 1.3 ClientHello 记录。
fn tls_client_hello(server_name: &str) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.push(0x00);
    entry.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    entry.extend_from_slice(server_name.as_bytes());
    let mut data = Vec::new();
    data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    data.extend_from_slice(&entry);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&data);

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x11; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

async fn start() -> (DuplexStream, tokio::task::JoinHandle<io::Result<()>>) {
    start_with(true).await
}

#[tokio::test]
async fn independent_wire_codec_round_trip() {
    let budget = Arc::new(tokio::sync::Semaphore::new(4096));
    let global_id = [1, 2, 3, 4, 5, 6, 7, 8];
    let wire = new_frame(
        0x1234,
        NETWORK_UDP,
        "127.0.0.1",
        53,
        Some(b"abc"),
        Some(global_id),
    );
    let frame = mux::read_frame(&mut wire.as_slice(), &budget)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.id, 0x1234);
    assert_eq!(frame.status, mux::Status::New);
    assert_eq!(frame.network, Some(session::Network::Udp));
    assert_eq!(frame.target.as_ref().unwrap().port, 53);
    assert_eq!(frame.global_id, Some(global_id));
    assert_eq!(frame.payload.as_ref().unwrap().payload.as_slice(), b"abc");

    let wire = new_frame(7, NETWORK_TCP, "example.org", 443, None, None);
    let frame = mux::read_frame(&mut wire.as_slice(), &budget)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.id, 7);
    assert!(frame.network == Some(session::Network::Tcp));
    assert!(frame.payload.is_none());

    // 下行编码必须与独立编码器逐字节一致。
    assert_eq!(
        mux::encode_data(0x1234, None, b"hello").unwrap(),
        keep_frame(0x1234, None, b"hello")
    );
    let target = Target::from("127.0.0.1:53".parse::<SocketAddr>().unwrap());
    assert_eq!(
        mux::encode_data(0x1234, Some(&target), b"hi").unwrap(),
        keep_frame(0x1234, Some(("127.0.0.1", 53)), b"hi")
    );
    assert_eq!(mux::encode_end(0x1234, true), end_frame(0x1234, true));

    // 帧边界 EOF 是正常结束；半长度仍是错误。
    assert!(
        mux::read_frame(&mut &b""[..], &budget)
            .await
            .unwrap()
            .is_none()
    );
    assert!(mux::read_frame(&mut &b"\x00"[..], &budget).await.is_err());
}

#[tokio::test]
async fn two_concurrent_tcp_sessions_do_not_cross() {
    let first = echo().await;
    let second = echo().await;
    let (mut client, task) = start().await;

    let port = |address: SocketAddr| address.port();
    client
        .write_all(&new_frame(
            1,
            NETWORK_TCP,
            "127.0.0.1",
            port(first),
            Some(b"alpha"),
            None,
        ))
        .await
        .unwrap();
    client
        .write_all(&new_frame(
            2,
            NETWORK_TCP,
            "127.0.0.1",
            port(second),
            Some(b"beta"),
            None,
        ))
        .await
        .unwrap();
    client
        .write_all(&keep_frame(1, None, b"-one"))
        .await
        .unwrap();
    client
        .write_all(&keep_frame(2, None, b"-two"))
        .await
        .unwrap();

    let mut received = [Vec::new(), Vec::new()];
    let converged = timeout(Duration::from_secs(10), async {
        while received[0].as_slice() != b"alpha-one" || received[1].as_slice() != b"beta-two" {
            let frame = decode(&mut client).await.unwrap().unwrap();
            assert!(frame.status == STATUS_KEEP);
            let payload = frame.payload.unwrap();
            match frame.id {
                1 => received[0].extend_from_slice(&payload),
                2 => received[1].extend_from_slice(&payload),
                other => panic!("未知会话 {other}"),
            }
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "两个并发会话未在期限内完成: {received:?}"
    );

    let _ = client.shutdown().await;
    drop(client);
    let _ = timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn unknown_session_keep_gets_end_and_connection_stays_usable() {
    let echo = echo().await;
    let (mut client, task) = start().await;

    client
        .write_all(&keep_frame(0x7777, None, b"orphan"))
        .await
        .unwrap();
    let end = timeout(Duration::from_secs(5), decode(&mut client))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(end.id, 0x7777);
    assert_eq!(end.status, STATUS_END);
    assert_eq!(end.option, 0);
    assert!(end.payload.is_none());

    // 未知会话不应中断整条 Mux 连接。
    client
        .write_all(&new_frame(
            3,
            NETWORK_TCP,
            "127.0.0.1",
            echo.port(),
            Some(b"alive"),
            None,
        ))
        .await
        .unwrap();
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(5), async {
        while echoed.as_slice() != b"alive" {
            let frame = decode(&mut client).await.unwrap().unwrap();
            assert_eq!(frame.id, 3);
            echoed.extend_from_slice(&frame.payload.unwrap());
        }
    })
    .await
    .unwrap();

    let _ = client.shutdown().await;
    drop(client);
    let _ = timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn oversized_metadata_is_rejected() {
    let (mut client, task) = start().await;
    // 513 > 512：读端应在读取元数据前直接失败。
    client.write_all(&[0x02, 0x01]).await.unwrap();
    let result = timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn new_without_data_then_keep_carries_payload() {
    let echo = echo().await;
    let (mut client, task) = start().await;

    client
        .write_all(&new_frame(
            9,
            NETWORK_TCP,
            "127.0.0.1",
            echo.port(),
            None,
            None,
        ))
        .await
        .unwrap();
    // 不等待拨号完成；Keep 负载应在会话队列中等待。
    client
        .write_all(&keep_frame(9, None, b"later"))
        .await
        .unwrap();

    let mut echoed = Vec::new();
    timeout(Duration::from_secs(5), async {
        while echoed.as_slice() != b"later" {
            let frame = decode(&mut client).await.unwrap().unwrap();
            assert_eq!(frame.id, 9);
            echoed.extend_from_slice(&frame.payload.unwrap());
        }
    })
    .await
    .unwrap();

    let _ = client.shutdown().await;
    drop(client);
    let _ = timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn udp_sessions_require_allow_udp_and_connection_stays_usable() {
    let echo = echo().await;
    let (mut client, task) = start_with(false).await;

    // 入站未开启 xudp：UDP New 只收到 End+Error，整条 Mux 连接不关闭。
    client
        .write_all(&new_frame(
            5,
            NETWORK_UDP,
            "127.0.0.1",
            53,
            Some(b"blocked"),
            None,
        ))
        .await
        .unwrap();
    let end = timeout(Duration::from_secs(5), decode(&mut client))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(end.id, 5);
    assert_eq!(end.status, STATUS_END);
    assert_eq!(end.option, OPTION_ERROR);
    assert!(end.payload.is_none());

    // 同一连接上的 TCP Mux 会话仍可正常使用。
    client
        .write_all(&new_frame(
            6,
            NETWORK_TCP,
            "127.0.0.1",
            echo.port(),
            Some(b"alive"),
            None,
        ))
        .await
        .unwrap();
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(5), async {
        while echoed.as_slice() != b"alive" {
            let frame = decode(&mut client).await.unwrap().unwrap();
            assert_eq!(frame.id, 6);
            echoed.extend_from_slice(&frame.payload.unwrap());
        }
    })
    .await
    .unwrap();

    let _ = client.shutdown().await;
    drop(client);
    let _ = timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn tcp_sniff_rejects_when_sni_matches_route_rule() {
    let echo_address = echo().await;
    let (mut client, task) = start_ctx(sniff_context(""), true).await;
    let hello = tls_client_hello("blocked.test");
    client
        .write_all(&new_frame(
            1,
            NETWORK_TCP,
            &echo_address.ip().to_string(),
            echo_address.port(),
            None,
            None,
        ))
        .await
        .unwrap();
    client
        .write_all(&keep_frame(1, None, &hello))
        .await
        .unwrap();

    let frame = timeout(Duration::from_secs(2), decode(&mut client))
        .await
        .expect("应收到 End")
        .unwrap()
        .expect("连接未提前关闭");
    assert_eq!(frame.id, 1);
    assert_eq!(frame.status, STATUS_END);
    assert_eq!(
        frame.option & OPTION_ERROR,
        OPTION_ERROR,
        "路由拒绝应带错误"
    );

    drop(client);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn tcp_sniff_replays_the_prefix_after_dialing_the_original_target() {
    let echo_address = echo().await;
    let (mut client, task) = start_ctx(sniff_context(""), true).await;
    let hello = tls_client_hello("allowed.test");
    client
        .write_all(&new_frame(
            7,
            NETWORK_TCP,
            &echo_address.ip().to_string(),
            echo_address.port(),
            None,
            None,
        ))
        .await
        .unwrap();
    client
        .write_all(&keep_frame(7, None, &hello))
        .await
        .unwrap();

    let mut echoed = Vec::new();
    while !echoed.windows(hello.len()).any(|window| window == hello) {
        let frame = timeout(Duration::from_secs(2), decode(&mut client))
            .await
            .expect("等待回显超时")
            .unwrap()
            .expect("连接不应提前关闭");
        if let Some(payload) = frame.payload {
            echoed.extend_from_slice(&payload);
        }
    }
    assert_eq!(echoed, hello, "嗅探过的首包必须原样回放");

    drop(client);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn tcp_sniff_dest_override_replaces_the_dial_target() {
    let echo_address = echo().await;
    let (mut client, task) = start_ctx(sniff_context(r#", "dest_override": ["tls"]"#), true).await;
    let hello = tls_client_hello("override.test");
    // New 帧先声明一个不可达目标；只有 dest_override 生效才能经 hosts 命中回环。
    client
        .write_all(&new_frame(
            9,
            NETWORK_TCP,
            "192.0.2.1",
            echo_address.port(),
            None,
            None,
        ))
        .await
        .unwrap();
    client
        .write_all(&keep_frame(9, None, &hello))
        .await
        .unwrap();

    let mut echoed = Vec::new();
    while !echoed.windows(hello.len()).any(|window| window == hello) {
        let frame = timeout(Duration::from_secs(2), decode(&mut client))
            .await
            .expect("等待回显超时")
            .unwrap()
            .expect("连接不应提前关闭");
        if let Some(payload) = frame.payload {
            echoed.extend_from_slice(&payload);
        }
    }
    assert_eq!(echoed, hello, "dest_override 应使用嗅探域名拨号并回放首包");

    drop(client);
    task.await.unwrap().unwrap();
}
