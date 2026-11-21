mod common;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use common::{Certificate, Echo, Running};
use md5::Digest as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const PASSWORD: &str = "anytls-test-password";
/// 协议规范中的默认 padding scheme：UTF-8、行间 `\n`、无结尾换行。
const DEFAULT_PADDING_SCHEME: &str = "stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";
/// 上述字符串的小写十六进制 MD5，独立于服务端实现硬编码用于帧断言。
const DEFAULT_PADDING_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";

fn config(cert: &Certificate) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "anytls",
            "tag": "anytls",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

fn frame(command: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![command];
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn address(target: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes
}

async fn prologue_custom<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    password: &str,
    padding: &[u8],
    settings: Option<&[u8]>,
) {
    let digest: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    stream.write_all(&digest).await.unwrap();
    // 上游客户端写的是大端 u16 填充长度，随后紧跟全部零字节。
    stream
        .write_all(&(padding.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(padding).await.unwrap();
    if let Some(payload) = settings {
        stream.write_all(&frame(4, 0, payload)).await.unwrap();
    }
    stream.flush().await.unwrap();
}

async fn prologue_with_padding<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    password: &str,
    padding: &[u8],
    settings: bool,
) {
    // 默认声明与服务端一致的 padding-md5，避免无关用例收到 UpdatePaddingScheme；
    // 方案更新本身由独立用例覆盖。
    let settings = settings.then(|| format!("v=2\nclient=test\npadding-md5={DEFAULT_PADDING_MD5}"));
    prologue_custom(
        stream,
        password,
        padding,
        settings.as_deref().map(str::as_bytes),
    )
    .await;
}

async fn prologue<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    password: &str,
    settings: bool,
) {
    prologue_with_padding(stream, password, &[], settings).await;
}

async fn next_frame<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(u8, u32, Vec<u8>)> {
    let mut header = [0u8; 7];
    stream.read_exact(&mut header).await?;
    let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await?;
    Ok((header[0], id, payload))
}

async fn next_frame_timeout<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, u32, Vec<u8>) {
    timeout(Duration::from_secs(3), next_frame(stream))
        .await
        .expect("等待帧超时")
        .expect("读取帧失败")
}

#[tokio::test]
async fn configured_padding_scheme_is_raw_and_only_sent_on_md5_mismatch() {
    const CUSTOM: &str = "stop=3\n0=7-7\n1=200-200\n2=300-300,c\n";
    let cert = Certificate::new();
    let mut value = config(&cert);
    value["inbounds"][0]["padding_scheme"] = json!(CUSTOM);
    let running = Running::start(value).await;
    for matching in [false, true] {
        let mut stream = cert.connect(running.address).await;
        let digest: String = md5::Md5::digest(CUSTOM.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let settings = format!(
            "padding-md5={}\nv=2",
            if matching {
                digest.as_str()
            } else {
                DEFAULT_PADDING_MD5
            }
        );
        prologue_custom(&mut stream, PASSWORD, &[], Some(settings.as_bytes())).await;
        let (command, id, payload) = next_frame_timeout(&mut stream).await;
        if !matching {
            assert_eq!((command, id), (6, 0));
            assert_eq!(payload, CUSTOM.as_bytes());
            let next = next_frame_timeout(&mut stream).await;
            assert_eq!((next.0, next.1, next.2), (10, 0, b"v=2".to_vec()));
        } else {
            assert_eq!((command, id, payload), (10, 0, b"v=2".to_vec()));
        }
    }
    running.shutdown().await;
}

#[tokio::test]
async fn stop_reclaims_session_writer_and_bridges_while_peer_holds_partial_frame() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config(&cert);
    value["limits"] = json!({"shutdown_timeout_ms":100,"handshake_timeout_ms":1000});
    value["inbounds"][0]["padding_scheme"] = json!("stop=3\n0=7-7\n1=200-200");
    let running = Running::start(value).await;
    let listener_address = running.address;
    let mut stream = cert.connect(listener_address).await;
    prologue(&mut stream, PASSWORD, true).await;
    let mut request = address(echo.address);
    request.extend(b"alive");
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.write_all(&frame(2, 1, &request)).await.unwrap();
    stream.flush().await.unwrap();
    loop {
        let (command, _, payload) = next_frame_timeout(&mut stream).await;
        if command == 2 {
            assert_eq!(payload, b"alive");
            break;
        }
    }
    stream.write_all(&[2, 0, 0]).await.unwrap();
    stream.flush().await.unwrap();
    running.shutdown().await;
    drop(stream);
    tokio::net::TcpListener::bind(listener_address)
        .await
        .unwrap();
}

#[test]
fn padding_scheme_configuration_rejects_invalid_or_unbounded_generation() {
    let cert = Certificate::new();
    for raw in [
        "",
        "stop=no",
        "stop=8\n0=65536-65536",
        "stop=8\n1=999999999-999999999",
    ] {
        let mut value = config(&cert);
        value["inbounds"][0]["padding_scheme"] = json!(raw);
        assert!(dubhe::Config::from_json(&value.to_string()).is_err());
    }
}

#[tokio::test]
async fn authenticated_session_relays_a_stream() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue(&mut stream, PASSWORD, true).await;

    let mut request = address(echo.address);
    request.extend_from_slice(b"anytls-hello");
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.write_all(&frame(2, 1, &request)).await.unwrap();
    stream.flush().await.unwrap();

    let mut payload = Vec::new();
    let mut synack = false;
    while !payload.windows(12).any(|window| window == b"anytls-hello") {
        let (command, id, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
            .await
            .unwrap()
            .unwrap();
        if command == 7 && id == 1 {
            synack = true;
            assert!(body.is_empty(), "成功 SYNACK 不带错误文本");
        }
        if command == 2 && id == 1 {
            payload.extend_from_slice(&body);
        }
    }
    assert!(synack, "服务端应在拨号成功后发送空 SYNACK");
}

#[tokio::test]
async fn independent_streams_are_multiplexed() {
    let first = Echo::tcp("127.0.0.1", false).await;
    let second = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue(&mut stream, PASSWORD, true).await;

    for (id, echo, text) in [
        (1u32, &first, b"stream-one".as_slice()),
        (2u32, &second, b"stream-two".as_slice()),
    ] {
        let mut request = address(echo.address);
        request.extend_from_slice(text);
        stream.write_all(&frame(1, id, &[])).await.unwrap();
        stream.write_all(&frame(2, id, &request)).await.unwrap();
    }
    stream.flush().await.unwrap();

    let mut one = Vec::new();
    let mut two = Vec::new();
    while one.windows(10).all(|window| window != b"stream-one")
        || two.windows(10).all(|window| window != b"stream-two")
    {
        let (command, id, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
            .await
            .unwrap()
            .unwrap();
        if command != 2 {
            continue;
        }
        match id {
            1 => one.extend_from_slice(&body),
            2 => two.extend_from_slice(&body),
            _ => {}
        }
    }
}

#[tokio::test]
async fn wrong_password_closes_without_relaying() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue(&mut stream, "wrong-password", true).await;
    let mut request = address(echo.address);
    request.extend_from_slice(b"x");
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.write_all(&frame(2, 1, &request)).await.unwrap();
    let mut buffer = [0u8; 1];
    // 认证失败直接关闭，不保证 TLS close_notify；客户端观察到 EOF 或读取错误都成立。
    let result = timeout(Duration::from_secs(3), stream.read(&mut buffer))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)), "{result:?}");
}

#[tokio::test]
async fn syn_before_settings_gets_an_alert() {
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue(&mut stream, PASSWORD, false).await;
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.flush().await.unwrap();
    let (command, _, payload) = timeout(Duration::from_secs(3), next_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(command, 5);
    assert!(!payload.is_empty());
}

#[tokio::test]
async fn handshake_padding_is_consumed_before_frames() {
    // 上游默认方案 0=30-30，客户端在密码后写入长度 30 和 30 个零字节。
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue_with_padding(&mut stream, PASSWORD, &[0u8; 30], true).await;

    let mut request = address(echo.address);
    request.extend_from_slice(b"padded-hello");
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.write_all(&frame(2, 1, &request)).await.unwrap();
    stream.flush().await.unwrap();

    let mut payload = Vec::new();
    while payload.windows(12).all(|window| window != b"padded-hello") {
        let (command, _, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
            .await
            .unwrap()
            .unwrap();
        if command == 2 {
            payload.extend_from_slice(&body);
        }
    }
}

#[tokio::test]
async fn version_two_gets_server_settings_then_empty_synack() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue(&mut stream, PASSWORD, true).await;

    // 上游 settings.Bytes() 的一行 v=2，不追加换行。
    let (command, id, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((command, id), (10, 0));
    assert_eq!(body, b"v=2".to_vec());

    let mut request = address(echo.address);
    request.extend_from_slice(b"v2-hello");
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.write_all(&frame(2, 1, &request)).await.unwrap();
    stream.flush().await.unwrap();

    let (command, id, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((command, id), (7, 1));
    assert!(body.is_empty(), "成功 SYNACK 不携带错误文本");

    let mut payload = Vec::new();
    while payload.windows(8).all(|window| window != b"v2-hello") {
        let (command, _, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
            .await
            .unwrap()
            .unwrap();
        if command == 2 {
            payload.extend_from_slice(&body);
        }
    }
}

#[tokio::test]
async fn missing_padding_md5_gets_default_scheme_update_before_server_settings() {
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    // 同时附带规范未定义的 padding-scheme 键：服务端不得把它当作方案回显。
    prologue_custom(
        &mut stream,
        PASSWORD,
        &[],
        Some(b"v=2\nclient=legacy\npadding-scheme=stop=1\n0=1-1\n".as_slice()),
    )
    .await;

    let (command, id, payload) = next_frame_timeout(&mut stream).await;
    assert_eq!((command, id), (6, 0), "缺失 padding-md5 应触发方案更新");
    assert_eq!(payload, DEFAULT_PADDING_SCHEME.as_bytes());
    assert_eq!(
        payload.len(),
        137,
        "7 字节帧头中的 u16 长度应等于方案字节数"
    );
    assert!(!payload.ends_with(b"\n"), "不得为方案补结尾换行");

    // 更新帧先于版本 2 的 ServerSettings，顺序与上游 cmdSettings 分支一致。
    let (command, id, payload) = next_frame_timeout(&mut stream).await;
    assert_eq!((command, id), (10, 0));
    assert_eq!(payload, b"v=2");
}

#[tokio::test]
async fn different_padding_md5_gets_scheme_update() {
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue_custom(
        &mut stream,
        PASSWORD,
        &[],
        Some(b"v=2\nclient=test\npadding-md5=00000000000000000000000000000000".as_slice()),
    )
    .await;

    let (command, id, payload) = next_frame_timeout(&mut stream).await;
    assert_eq!((command, id), (6, 0), "不同 md5 应触发方案更新");
    assert_eq!(payload, DEFAULT_PADDING_SCHEME.as_bytes());
}

#[tokio::test]
async fn matching_padding_md5_suppresses_scheme_update() {
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue(&mut stream, PASSWORD, true).await;

    // 首个下行帧直接是 ServerSettings；不应先出现命令 6。
    let (command, id, payload) = next_frame_timeout(&mut stream).await;
    assert_eq!((command, id), (10, 0));
    assert_eq!(payload, b"v=2");
}

#[tokio::test]
async fn version_one_gets_no_server_settings_or_synack() {
    // 上游只在客户端版本 >= 2 时回 ServerSettings/SYNACK；v1 客户端应直接收到数据。
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    let settings = format!("v=1\nclient=legacy\npadding-md5={DEFAULT_PADDING_MD5}");
    prologue_custom(&mut stream, PASSWORD, &[], Some(settings.as_bytes())).await;

    let mut request = address(echo.address);
    request.extend_from_slice(b"v1-hello");
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.write_all(&frame(2, 1, &request)).await.unwrap();
    stream.flush().await.unwrap();

    // 第一个下行帧就是业务 PSH；若误发 ServerSettings 或 SYNACK 会先出现。
    let (command, id, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((command, id), (2, 1));
    assert!(body.starts_with(b"v1-hello"));
}

#[tokio::test]
async fn waste_frames_are_skipped_and_heartbeat_is_answered() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue(&mut stream, PASSWORD, true).await;
    let (command, _, _) = timeout(Duration::from_secs(3), next_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(command, 10);

    // 客户端填充产生的 waste 帧必须被完整跳过，不能影响后续帧边界。
    stream.write_all(&frame(0, 0, &[0u8; 100])).await.unwrap();
    stream.write_all(&frame(8, 0, &[])).await.unwrap();
    stream.flush().await.unwrap();
    let (command, id, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((command, id), (9, 0), "心跳响应应沿用请求的流 ID");
    assert!(body.is_empty());

    let mut request = address(echo.address);
    request.extend_from_slice(b"after-waste");
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.write_all(&frame(2, 1, &request)).await.unwrap();
    stream.flush().await.unwrap();

    let mut payload = Vec::new();
    while payload.windows(11).all(|window| window != b"after-waste") {
        let (command, _, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
            .await
            .unwrap()
            .unwrap();
        if command == 2 {
            payload.extend_from_slice(&body);
        }
    }
}

#[tokio::test]
async fn peer_fin_is_not_echoed() {
    // 上游 closeByPeer 回送方向为空；对端 FIN 之后服务器不应再发 FIN。
    let echo = Echo::tcp("127.0.0.1", false).await;
    let cert = Certificate::new();
    let running = Running::start(config(&cert)).await;
    let mut stream = cert.connect(running.address).await;
    prologue(&mut stream, PASSWORD, true).await;
    let (command, _, _) = timeout(Duration::from_secs(3), next_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(command, 10);

    let mut request = address(echo.address);
    request.extend_from_slice(b"fin-hello");
    stream.write_all(&frame(1, 1, &[])).await.unwrap();
    stream.write_all(&frame(2, 1, &request)).await.unwrap();
    stream.flush().await.unwrap();

    let mut payload = Vec::new();
    while payload.windows(9).all(|window| window != b"fin-hello") {
        let (command, _, body) = timeout(Duration::from_secs(3), next_frame(&mut stream))
            .await
            .unwrap()
            .unwrap();
        if command == 2 {
            payload.extend_from_slice(&body);
        }
    }

    stream.write_all(&frame(3, 1, &[])).await.unwrap();
    stream.flush().await.unwrap();
    // 回显端关闭后，若回送 FIN 会很快到达；预期是静默到超时。
    let result = timeout(Duration::from_millis(300), next_frame(&mut stream)).await;
    assert!(result.is_err(), "收到不应存在的帧: {result:?}");
}
