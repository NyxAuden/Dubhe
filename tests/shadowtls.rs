//! ShadowTLS v3 端到端回环测试。
//!
//! 本文件构造最小 TLS 记录层与固定伪装服务器，验证：
//! - 合格 ClientHello 完成 v3 认证，内层 SOCKS5 经 detour 转发到真实目标；
//! - 认证后的双向记录按 HMAC 链校验；
//! - 密码不符的 ClientHello 原样回落到伪装服务器。
//!
//! 伪装服务器只返回形状合法、带 TLS 1.3 supported_versions 的 ServerHello，
//! 不执行真实 TLS 握手；这足以覆盖 ShadowTLS 服务端对握手中转的行为。

mod common;

use std::{net::SocketAddr, time::Duration};

use aws_lc_rs::hmac::{Context as HmacContext, HMAC_SHA1_FOR_LEGACY_USE_ONLY, Key};
use common::{Echo, Running};
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const PASSWORD: &str = "shadowtls-loopback-secret";
const TLS_HEADER_SIZE: usize = 5;
const HMAC_SIZE: usize = 4;
const TLS_RANDOM_SIZE: usize = 32;
const SERVER_RANDOM_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
const SESSION_ID_LENGTH_INDEX: usize = SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE;
const CLIENT_HELLO_MIN_LEN: usize = SESSION_ID_LENGTH_INDEX + 1 + 32;
const CLIENT_HELLO_HMAC_INDEX: usize = SESSION_ID_LENGTH_INDEX + 1 + 32 - HMAC_SIZE;
const SERVER_RANDOM: [u8; TLS_RANDOM_SIZE] = [0x42; TLS_RANDOM_SIZE];
const TLS_RECORD_APPLICATION_DATA: u8 = 23;
const TLS_RECORD_HANDSHAKE: u8 = 22;

fn hmac_key(password: &[u8]) -> Key {
    Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, password)
}

fn build_client_hello(password: &str) -> Vec<u8> {
    build_client_hello_with_sni(password, None)
}

fn build_client_hello_with_sni(password: &str, server_name: Option<&str>) -> Vec<u8> {
    let mut frame = vec![0u8; CLIENT_HELLO_MIN_LEN];
    frame[0] = TLS_RECORD_HANDSHAKE;
    frame[1] = 3;
    frame[2] = 1;
    frame[5] = 1;
    frame[9] = 3;
    frame[10] = 3;
    frame[SESSION_ID_LENGTH_INDEX] = 32;
    if let Some(server_name) = server_name {
        // 使 ClientHello 结构可被 SNI 解析器识别：密码套件与压缩方法。
        frame.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        frame.extend_from_slice(&[0x01, 0x00]);
        let mut entry = vec![0x00];
        entry.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        entry.extend_from_slice(server_name.as_bytes());
        let mut data = Vec::new();
        data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        data.extend_from_slice(&entry);
        // extensions 总长度 + server_name 扩展。
        frame.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(&data);
    }
    let body = u16::try_from(frame.len() - TLS_HEADER_SIZE).unwrap();
    frame[3..5].copy_from_slice(&body.to_be_bytes());
    let handshake_len = u16::try_from(frame.len() - 9).unwrap().to_be_bytes();
    frame[6] = 0;
    frame[7] = handshake_len[0];
    frame[8] = handshake_len[1];
    let mut context = HmacContext::with_key(&hmac_key(password.as_bytes()));
    context.update(&frame[TLS_HEADER_SIZE..CLIENT_HELLO_HMAC_INDEX]);
    context.update(&[0, 0, 0, 0]);
    context.update(&frame[CLIENT_HELLO_HMAC_INDEX + HMAC_SIZE..]);
    let tag = context.sign();
    frame[CLIENT_HELLO_HMAC_INDEX..CLIENT_HELLO_HMAC_INDEX + HMAC_SIZE]
        .copy_from_slice(&tag.as_ref()[..HMAC_SIZE]);
    frame
}

fn build_server_hello(random: [u8; TLS_RANDOM_SIZE]) -> Vec<u8> {
    let mut frame = vec![0u8; SESSION_ID_LENGTH_INDEX + 1 + 3];
    frame[0] = TLS_RECORD_HANDSHAKE;
    frame[1] = 3;
    frame[2] = 3;
    frame[5] = 2;
    frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE].copy_from_slice(&random);
    frame[SESSION_ID_LENGTH_INDEX] = 0;
    frame.extend_from_slice(&6u16.to_be_bytes());
    frame.extend_from_slice(&43u16.to_be_bytes());
    frame.extend_from_slice(&2u16.to_be_bytes());
    frame.extend_from_slice(&0x0304u16.to_be_bytes());
    let body = u16::try_from(frame.len() - TLS_HEADER_SIZE).unwrap();
    frame[3..5].copy_from_slice(&body.to_be_bytes());
    frame
}

async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut header = [0u8; TLS_HEADER_SIZE];
    stream.read_exact(&mut header).await.unwrap();
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut frame = vec![0u8; TLS_HEADER_SIZE + length];
    frame[..TLS_HEADER_SIZE].copy_from_slice(&header);
    stream
        .read_exact(&mut frame[TLS_HEADER_SIZE..])
        .await
        .unwrap();
    frame
}

/// 伪装握手服务器：`ServerHello` 模式回应固定 ServerHello，`Echo` 模式回显标记。
enum FakeMode {
    ServerHello,
    Echo,
}

async fn fake_handshake_server(mode: FakeMode) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let hello = read_record(&mut socket).await;
        assert_eq!(hello[0], TLS_RECORD_HANDSHAKE);
        match mode {
            FakeMode::ServerHello => {
                socket
                    .write_all(&build_server_hello(SERVER_RANDOM))
                    .await
                    .unwrap();
                let mut buffer = [0u8; 1024];
                while socket.read(&mut buffer).await.unwrap_or(0) > 0 {}
            }
            FakeMode::Echo => {
                socket.write_all(b"fallback-marker").await.unwrap();
                let mut buffer = [0u8; 1024];
                while socket.read(&mut buffer).await.unwrap_or(0) > 0 {}
            }
        }
    });
    (address, task)
}

fn config(handshake: SocketAddr) -> serde_json::Value {
    json!({
        "version": 1,
        "inbounds": [
            {
                "type": "shadowtls",
                "tag": "stls",
                "listen": "127.0.0.1:0",
                "version": 3,
                "users": [{"name": "u", "password": PASSWORD}],
                "handshake": {"server": "127.0.0.1", "server_port": handshake.port()},
                "strict_mode": true,
                "detour": "inner"
            },
            {"type": "socks5", "tag": "inner", "listen": "127.0.0.1:0"}
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"handshake_timeout_ms": 2000, "shutdown_timeout_ms": 500}
    })
}

/// 客户端 HMAC 链：发送方向与接收方向各自独立。
struct Chain(HmacContext);

impl Chain {
    fn new(direction: &[u8]) -> Self {
        let mut context = HmacContext::with_key(&hmac_key(PASSWORD.as_bytes()));
        context.update(&SERVER_RANDOM);
        context.update(direction);
        Self(context)
    }

    /// 封装一条内层记录，并推进发送链。
    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        self.0.update(payload);
        let tag = self.0.clone().sign();
        let mut record = Vec::with_capacity(TLS_HEADER_SIZE + HMAC_SIZE + payload.len());
        record.push(TLS_RECORD_APPLICATION_DATA);
        record.extend_from_slice(&[3, 3]);
        let length = u16::try_from(HMAC_SIZE + payload.len()).unwrap();
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(&tag.as_ref()[..HMAC_SIZE]);
        record.extend_from_slice(payload);
        self.0.update(&tag.as_ref()[..HMAC_SIZE]);
        record
    }

    /// 校验并解出一条服务端记录，同时推进接收链。
    fn open(&mut self, frame: &[u8]) -> Vec<u8> {
        assert_eq!(frame[0], TLS_RECORD_APPLICATION_DATA, "记录类型");
        assert_eq!(&frame[1..3], &[3, 3], "记录版本");
        let payload = &frame[TLS_HEADER_SIZE..];
        assert!(payload.len() > HMAC_SIZE, "记录长度");
        let mut check = self.0.clone();
        check.update(&payload[HMAC_SIZE..]);
        let tag = check.sign();
        assert_eq!(
            &tag.as_ref()[..HMAC_SIZE],
            &payload[..HMAC_SIZE],
            "HMAC 链校验"
        );
        self.0.update(&payload[HMAC_SIZE..]);
        self.0.update(&payload[..HMAC_SIZE]);
        payload[HMAC_SIZE..].to_vec()
    }
}

async fn socks_reply(stream: &mut TcpStream, chain: &mut Chain) -> Vec<u8> {
    let frame = timeout(Duration::from_secs(3), read_record(stream))
        .await
        .expect("等待 ShadowTLS 下行业务超时");
    chain.open(&frame)
}

#[tokio::test]
async fn authenticated_client_reaches_the_detour_inbound() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let (handshake, server_task) = fake_handshake_server(FakeMode::ServerHello).await;
    let running = Running::start(config(handshake)).await;
    let mut stream = TcpStream::connect(running.addresses[0]).await.unwrap();

    stream
        .write_all(&build_client_hello(PASSWORD))
        .await
        .unwrap();
    let server_hello = read_record(&mut stream).await;
    assert_eq!(server_hello[5], 2, "应收到 ServerHello");

    // 首个已认证记录携带 SOCKS5 问候；tag 以 server_random||"C" 起链。
    let mut write = Chain::new(b"C");
    let mut first = HmacContext::with_key(&hmac_key(PASSWORD.as_bytes()));
    first.update(&SERVER_RANDOM);
    first.update(b"C");
    first.update(&[5, 1, 0]);
    let tag = first.clone().sign();
    let mut record = vec![TLS_RECORD_APPLICATION_DATA, 3, 3];
    record.extend_from_slice(&(HMAC_SIZE as u16 + 3).to_be_bytes());
    record.extend_from_slice(&tag.as_ref()[..HMAC_SIZE]);
    record.extend_from_slice(&[5, 1, 0]);
    stream.write_all(&record).await.unwrap();
    // 服务端把首帧 payload 与 tag 追加进读链；客户端写链需同步推进。
    write.0.update(&[5, 1, 0]);
    write.0.update(&tag.as_ref()[..HMAC_SIZE]);

    let mut read = Chain::new(b"S");
    assert_eq!(socks_reply(&mut stream, &mut read).await, vec![5, 0]);

    let mut connect = vec![5, 1, 0];
    match echo.address.ip() {
        std::net::IpAddr::V4(ip) => {
            connect.push(1);
            connect.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            connect.push(4);
            connect.extend_from_slice(&ip.octets());
        }
    }
    connect.extend_from_slice(&echo.address.port().to_be_bytes());
    stream.write_all(&write.seal(&connect)).await.unwrap();

    let reply = socks_reply(&mut stream, &mut read).await;
    assert_eq!(&reply[..2], &[5, 0], "SOCKS5 CONNECT 应成功: {reply:?}");

    stream.write_all(&write.seal(b"ping")).await.unwrap();
    let mut echoed = Vec::new();
    while !echoed.windows(4).any(|window| window == b"ping") {
        echoed.extend_from_slice(&socks_reply(&mut stream, &mut read).await);
    }
    assert!(echoed.windows(4).any(|window| window == b"ping"));

    drop(stream);
    running.shutdown().await;
    server_task.abort();
}

#[tokio::test]
async fn unauthenticated_client_hello_falls_back_to_handshake_server() {
    let (handshake, server_task) = fake_handshake_server(FakeMode::Echo).await;
    let running = Running::start(config(handshake)).await;
    let mut stream = TcpStream::connect(running.addresses[0]).await.unwrap();

    stream
        .write_all(&build_client_hello("wrong-password"))
        .await
        .unwrap();
    let mut marker = vec![0u8; "fallback-marker".len()];
    timeout(Duration::from_secs(3), stream.read_exact(&mut marker))
        .await
        .expect("回落读取不应挂起")
        .unwrap();
    assert_eq!(&marker, b"fallback-marker");

    drop(stream);
    running.shutdown().await;
    server_task.abort();
}

#[tokio::test]
async fn handshake_for_server_name_selects_the_mapped_target() {
    let (global, global_task) = fake_handshake_server(FakeMode::Echo).await;
    let (mapped, mapped_task) = fake_handshake_server(FakeMode::ServerHello).await;
    let mut value = config(global);
    value["inbounds"][0]["handshake_for_server_name"] = json!({
        "mapped.test": {"server": "127.0.0.1", "server_port": mapped.port()}
    });
    let running = Running::start(value).await;
    let mut stream = TcpStream::connect(running.addresses[0]).await.unwrap();
    stream
        .write_all(&build_client_hello_with_sni(PASSWORD, Some("mapped.test")))
        .await
        .unwrap();

    let server_hello = timeout(Duration::from_secs(3), read_record(&mut stream))
        .await
        .expect("映射目标的 ServerHello 超时");
    assert_eq!(server_hello[5], 2, "应来自映射的伪装服务器");

    // 首帧认证与问候仍然成立，证明映射目标被用于真实 TLS 握手。
    let mut first = HmacContext::with_key(&hmac_key(PASSWORD.as_bytes()));
    first.update(&SERVER_RANDOM);
    first.update(b"C");
    first.update(&[5, 1, 0]);
    let tag = first.clone().sign();
    let mut record = vec![TLS_RECORD_APPLICATION_DATA, 3, 3];
    record.extend_from_slice(&(HMAC_SIZE as u16 + 3).to_be_bytes());
    record.extend_from_slice(&tag.as_ref()[..HMAC_SIZE]);
    record.extend_from_slice(&[5, 1, 0]);
    stream.write_all(&record).await.unwrap();
    let mut read = Chain::new(b"S");
    assert_eq!(socks_reply(&mut stream, &mut read).await, vec![5, 0]);

    drop(stream);
    running.shutdown().await;
    global_task.abort();
    mapped_task.abort();
}
