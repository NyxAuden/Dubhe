//! Snell v4/v5 独立 wire 测试。
//!
//! 本文件自带一个最小的客户端记录编码/解码器，只使用 Argon2id 与 AES-128-GCM
//! 原语，不复用 `src/protocol/snell.rs` 的任何帧构造代码。
//!
//! 依赖主代理把 `Inbound::Snell` 接入 config/runtime；配置字段使用：
//! `psk`、`version`、`users[{name,userkey}]`。

mod common;

// 复用同一 v6 shaped 编解码源做端到端接线；其内部测试另有独立 Python 参考向量。
#[path = "../src/protocol/snell_v6.rs"]
mod snell_v6;

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use serde_json::{Value, json};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};

const PSK: &str = "snell-test-psk-not-for-production";
const USERKEY: &str = "snell-test-userkey";
const WAIT: Duration = Duration::from_secs(5);

const HEADER_VERSION: u8 = 0x04;
const HEADER_PLAIN_LEN: usize = 7;
const TAG_LEN: usize = 16;
const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + TAG_LEN;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MAX_PAYLOAD: usize = 0x3fff;

const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_CONNECT_V2: u8 = 0x05;
const COMMAND_UDP: u8 = 0x06;
const REQUEST_VERSION: u8 = 0x01;

static SALT_COUNTER: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// 独立客户端实现
// ---------------------------------------------------------------------------

fn derive_key(psk: &[u8], salt: &[u8; SALT_LEN]) -> [u8; 16] {
    let params = Params::new(8, 3, 1, Some(32)).unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon.hash_password_into(psk, salt, &mut output).unwrap();
    output[..16].try_into().unwrap()
}

fn unique_salt() -> [u8; SALT_LEN] {
    let value = SALT_COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes();
    let mut salt = [0u8; SALT_LEN];
    salt[..8].copy_from_slice(&value);
    salt[8..].copy_from_slice(&value);
    salt
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
    panic!("测试 nonce 溢出");
}

fn interleave(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    let mut index = 0;
    while index < limit {
        std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
        index += 2;
    }
}

struct ClientWriter {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_LEN],
}

impl ClientWriter {
    /// 写出 16 字节 salt，并返回后续记录使用同一个密钥的编码器。
    fn new(psk: &[u8], out: &mut Vec<u8>) -> Self {
        let salt = unique_salt();
        out.extend_from_slice(&salt);
        let key = derive_key(psk, &salt);
        Self {
            cipher: Aes128Gcm::new_from_slice(&key).unwrap(),
            nonce: [0; NONCE_LEN],
        }
    }

    fn write_record(&mut self, payload: &[u8], padding_len: usize, out: &mut Vec<u8>) {
        assert!(!payload.is_empty() && payload.len() <= MAX_PAYLOAD);
        assert!(padding_len <= MAX_PAYLOAD);

        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());

        let header_cipher = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &header,
                    aad: &[],
                },
            )
            .unwrap();
        increment_nonce(&mut self.nonce);

        let mut padding = vec![0x5a; padding_len];
        let mut payload_cipher = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: payload,
                    aad: &[],
                },
            )
            .unwrap();
        increment_nonce(&mut self.nonce);
        interleave(&mut padding, &mut payload_cipher);

        out.extend_from_slice(&header_cipher);
        out.extend_from_slice(&padding);
        out.extend_from_slice(&payload_cipher);
    }

    fn write_data(&mut self, mut data: &[u8], out: &mut Vec<u8>) {
        while !data.is_empty() {
            let count = data.len().min(MAX_PAYLOAD);
            self.write_record(&data[..count], 0, out);
            data = &data[count..];
        }
    }

    /// 零块：只写加密头，不写 padding 和 payload tag。
    fn write_zero(&mut self, out: &mut Vec<u8>) {
        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        let header_cipher = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &header,
                    aad: &[],
                },
            )
            .unwrap();
        increment_nonce(&mut self.nonce);
        out.extend_from_slice(&header_cipher);
    }

    /// 只写一个声明了超长 payload 的头，用于验证服务端在分配前拒绝。
    fn write_oversized_header(&mut self, payload_len: u16, out: &mut Vec<u8>) {
        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[5..7].copy_from_slice(&payload_len.to_be_bytes());
        let header_cipher = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &header,
                    aad: &[],
                },
            )
            .unwrap();
        increment_nonce(&mut self.nonce);
        out.extend_from_slice(&header_cipher);
    }
}

struct ClientReader {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_LEN],
}

impl ClientReader {
    async fn new(stream: &mut TcpStream, psk: &[u8]) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        stream.read_exact(&mut salt).await?;
        let key = derive_key(psk, &salt);
        Ok(Self {
            cipher: Aes128Gcm::new_from_slice(&key).unwrap(),
            nonce: [0; NONCE_LEN],
        })
    }

    /// `Ok(None)` 表示零块；底层 EOF 返回 `UnexpectedEof`。
    async fn read_record(&mut self, stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
        let mut header_cipher = [0u8; HEADER_CIPHER_LEN];
        stream.read_exact(&mut header_cipher).await?;
        let header = self
            .cipher
            .decrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &header_cipher,
                    aad: &[],
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "测试头解密失败"))?;
        increment_nonce(&mut self.nonce);

        assert_eq!(header[0], HEADER_VERSION);
        let padding_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let payload_len = usize::from(u16::from_be_bytes([header[5], header[6]]));
        if payload_len == 0 {
            assert_eq!(padding_len, 0);
            return Ok(None);
        }

        let mut padding = vec![0u8; padding_len];
        stream.read_exact(&mut padding).await?;
        let mut payload_cipher = vec![0u8; payload_len + TAG_LEN];
        stream.read_exact(&mut payload_cipher).await?;
        interleave(&mut padding, &mut payload_cipher);
        let payload = self
            .cipher
            .decrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &payload_cipher,
                    aad: &[],
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "测试载荷解密失败"))?;
        increment_nonce(&mut self.nonce);
        assert_eq!(payload.len(), payload_len);
        Ok(Some(payload))
    }
}

// ---------------------------------------------------------------------------
// 请求/地址编码
// ---------------------------------------------------------------------------

fn connect_request(command: u8, user: &str, target: SocketAddr, early: &[u8]) -> Vec<u8> {
    let mut request = vec![REQUEST_VERSION, command, user.len() as u8];
    request.extend_from_slice(user.as_bytes());
    // CONNECT 目标始终是主机字符串，即使是字面 IP。
    let host = target.ip().to_string();
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(early);
    request
}

fn udp_request(user: &str) -> Vec<u8> {
    let mut request = vec![REQUEST_VERSION, COMMAND_UDP, user.len() as u8];
    request.extend_from_slice(user.as_bytes());
    request
}

fn udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    // [0x01][0x00][family][ip][port][payload]
    let mut packet = vec![0x01, 0x00];
    match target {
        SocketAddr::V4(address) => {
            packet.push(0x04);
            packet.extend_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            packet.push(0x06);
            packet.extend_from_slice(&address.ip().octets());
        }
    }
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

// ---------------------------------------------------------------------------
// 配置与回环目标
// ---------------------------------------------------------------------------

fn snell_config(version: u8, psk: &str, users: Value) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "snell",
            "tag": "snell",
            "listen": "127.0.0.1:0",
            "psk": psk,
            "version": version,
            "users": users
        }],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "reject", "tag": "reject"}
        ],
        "route": {"default": "direct"},
        "limits": {
            "handshake_timeout_ms": 1000,
            "dial_timeout_ms": 1000,
            "udp_idle_timeout_ms": 1000,
            "shutdown_timeout_ms": 100
        }
    })
}

fn one_user() -> Value {
    json!([{"name": "alice", "userkey": USERKEY}])
}

async fn tcp_echo() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    (address, task)
}

async fn udp_echo() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        loop {
            let Ok((count, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let _ = socket.send_to(&buffer[..count], peer).await;
        }
    });
    (address, task)
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    timeout(WAIT, future).await.expect("Snell 测试超时")
}

async fn read_one(reader: &mut ClientReader, stream: &mut TcpStream) -> Option<Vec<u8>> {
    match within(reader.read_record(stream)).await {
        Ok(payload) => payload,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => None,
        Err(error) => panic!("读取 Snell 记录失败: {error}"),
    }
}

/// 严格断言下一条记录是零块（而不是 TCP EOF）。
async fn read_zero(reader: &mut ClientReader, stream: &mut TcpStream) {
    match within(reader.read_record(stream)).await {
        Ok(None) => {}
        Ok(Some(payload)) => panic!("期望零块，收到 {} 字节", payload.len()),
        Err(error) => panic!("期望零块，读取失败: {error}"),
    }
}

/// 读取记录直到累计达到 `expected` 字节；用于回环 echo 的分片。
async fn collect(reader: &mut ClientReader, stream: &mut TcpStream, expected: usize) -> Vec<u8> {
    let mut data = Vec::new();
    while data.len() < expected {
        let payload = read_one(reader, stream)
            .await
            .unwrap_or_else(|| panic!("在收到 {expected} 字节前遇到 EOF"));
        data.extend_from_slice(&payload);
    }
    data.truncate(expected);
    data
}

async fn expect_closed_without_data(stream: &mut TcpStream) {
    let mut byte = [0u8; 1];
    match within(stream.read(&mut byte)).await {
        Ok(0) => {}
        // 对端在仍有未读数据时关闭，macOS 可能返回 ECONNRESET。
        Err(_) => {}
        Ok(count) => panic!("服务端在拒绝路径上写出了 {count} 字节"),
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v4_tcp_roundtrip_with_early_data_and_padding() {
    let (target, echo) = tcp_echo().await;
    let running = common::Running::start(snell_config(4, PSK, one_user())).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();

    let mut wire = Vec::new();
    let mut writer = ClientWriter::new(PSK.as_bytes(), &mut wire);
    // v4 客户端实际使用 0x05；首个记录带非零 padding 以覆盖交换逻辑。
    let request = connect_request(COMMAND_CONNECT_V2, USERKEY, target, b"early");
    writer.write_record(&request, 0x133, &mut wire);
    stream.write_all(&wire).await.unwrap();

    let mut reader = ClientReader::new(&mut stream, PSK.as_bytes())
        .await
        .unwrap();
    assert_eq!(read_one(&mut reader, &mut stream).await, Some(vec![0x00]));
    assert_eq!(
        collect(&mut reader, &mut stream, 5).await.as_slice(),
        &b"early"[..]
    );

    let mut wire = Vec::new();
    writer.write_data(b"hello", &mut wire);
    stream.write_all(&wire).await.unwrap();
    assert_eq!(
        collect(&mut reader, &mut stream, 5).await.as_slice(),
        &b"hello"[..]
    );

    let mut wire = Vec::new();
    writer.write_zero(&mut wire);
    stream.write_all(&wire).await.unwrap();
    // 复用命令：服务端以零块结束该逻辑流。
    read_zero(&mut reader, &mut stream).await;

    drop(stream);
    echo.abort();
    running.shutdown().await;
}

#[tokio::test]
async fn v5_tcp_roundtrip_reuses_one_tunnel_for_two_streams() {
    let (target, echo) = tcp_echo().await;
    let running = common::Running::start(snell_config(5, PSK, one_user())).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();

    let mut wire = Vec::new();
    let mut writer = ClientWriter::new(PSK.as_bytes(), &mut wire);
    writer.write_record(
        &connect_request(COMMAND_CONNECT_V2, USERKEY, target, b"one"),
        0x100,
        &mut wire,
    );
    stream.write_all(&wire).await.unwrap();

    let mut reader = ClientReader::new(&mut stream, PSK.as_bytes())
        .await
        .unwrap();
    assert_eq!(read_one(&mut reader, &mut stream).await, Some(vec![0x00]));
    assert_eq!(
        collect(&mut reader, &mut stream, 3).await.as_slice(),
        &b"one"[..]
    );

    let mut wire = Vec::new();
    writer.write_zero(&mut wire);
    stream.write_all(&wire).await.unwrap();
    read_zero(&mut reader, &mut stream).await;

    // 同一条加密隧道上的第二个逻辑流；记录不再带首记录 padding。
    let mut wire = Vec::new();
    writer.write_record(
        &connect_request(COMMAND_CONNECT_V2, USERKEY, target, b"two"),
        0,
        &mut wire,
    );
    stream.write_all(&wire).await.unwrap();
    assert_eq!(read_one(&mut reader, &mut stream).await, Some(vec![0x00]));
    assert_eq!(
        collect(&mut reader, &mut stream, 3).await.as_slice(),
        &b"two"[..]
    );

    let mut wire = Vec::new();
    writer.write_zero(&mut wire);
    stream.write_all(&wire).await.unwrap();
    read_zero(&mut reader, &mut stream).await;

    drop(stream);
    echo.abort();
    running.shutdown().await;
}

#[tokio::test]
async fn wrong_key_is_rejected_without_any_response() {
    let running = common::Running::start(snell_config(5, PSK, one_user())).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();
    let target_sink: SocketAddr = "127.0.0.1:9".parse().unwrap();

    let mut wire = Vec::new();
    let mut writer = ClientWriter::new(b"wrong-pre-shared-key", &mut wire);
    writer.write_record(
        &connect_request(COMMAND_CONNECT, USERKEY, target_sink, b""),
        0x100,
        &mut wire,
    );
    stream.write_all(&wire).await.unwrap();

    expect_closed_without_data(&mut stream).await;
    drop(stream);
    running.shutdown().await;
}

#[tokio::test]
async fn oversized_payload_length_is_rejected_before_allocation() {
    let running = common::Running::start(snell_config(5, PSK, one_user())).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();

    let mut wire = Vec::new();
    let mut writer = ClientWriter::new(PSK.as_bytes(), &mut wire);
    // 0x4000 > MAX_PAYLOAD (0x3fff)，并且故意不发送任何载荷。
    writer.write_oversized_header(0x4000, &mut wire);
    stream.write_all(&wire).await.unwrap();

    expect_closed_without_data(&mut stream).await;
    drop(stream);
    running.shutdown().await;
}

#[tokio::test]
async fn v5_udp_over_stream_roundtrip() {
    let (echo, echo_task) = udp_echo().await;
    let running = common::Running::start(snell_config(5, PSK, one_user())).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();

    let mut wire = Vec::new();
    let mut writer = ClientWriter::new(PSK.as_bytes(), &mut wire);
    writer.write_record(&udp_request(USERKEY), 0x155, &mut wire);
    stream.write_all(&wire).await.unwrap();

    let mut reader = ClientReader::new(&mut stream, PSK.as_bytes())
        .await
        .unwrap();
    // UDP 关联的首个服务端记录是 ReplyTunnel。
    assert_eq!(read_one(&mut reader, &mut stream).await, Some(vec![0x00]));

    let mut wire = Vec::new();
    writer.write_record(&udp_packet(echo, b"ping"), 0, &mut wire);
    stream.write_all(&wire).await.unwrap();

    let SocketAddr::V4(echo_v4) = echo else {
        panic!("测试 UDP 回环必须是 IPv4");
    };
    let reply = read_one(&mut reader, &mut stream)
        .await
        .expect("UDP 应答记录缺失");
    assert_eq!(reply.first(), Some(&0x04));
    assert_eq!(&reply[1..5], &echo_v4.ip().octets()[..]);
    assert_eq!(&reply[5..7], &echo_v4.port().to_be_bytes()[..]);
    assert_eq!(&reply[7..], &b"ping"[..]);

    let mut wire = Vec::new();
    writer.write_zero(&mut wire);
    stream.write_all(&wire).await.unwrap();

    drop(stream);
    echo_task.abort();
    running.shutdown().await;
}

// ---------------------------------------------------------------------------
// Snell v6（unshaped / unsafe-raw）
// ---------------------------------------------------------------------------

fn snell_v6_config(mode: &str) -> Value {
    let mut value = snell_config(6, PSK, one_user());
    value["inbounds"][0]["mode"] = json!(mode);
    value
}

fn raw_record(payload: &[u8]) -> Vec<u8> {
    let mut record = vec![0u8; HEADER_PLAIN_LEN];
    record[0] = HEADER_VERSION;
    record[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

async fn raw_read(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0u8; HEADER_PLAIN_LEN];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], HEADER_VERSION);
    let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
    if length == 0 {
        return None;
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await.unwrap();
    Some(payload)
}

#[tokio::test]
async fn v6_unshaped_tcp_roundtrip_with_zero_padding() {
    let (target, echo) = tcp_echo().await;
    let running = common::Running::start(snell_v6_config("unshaped")).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();

    let mut wire = Vec::new();
    let mut writer = ClientWriter::new(PSK.as_bytes(), &mut wire);
    writer.write_record(
        &connect_request(COMMAND_CONNECT, USERKEY, target, b"v6"),
        0,
        &mut wire,
    );
    stream.write_all(&wire).await.unwrap();

    let mut reader = ClientReader::new(&mut stream, PSK.as_bytes())
        .await
        .unwrap();
    assert_eq!(read_one(&mut reader, &mut stream).await, Some(vec![0x00]));
    assert_eq!(
        collect(&mut reader, &mut stream, 2).await.as_slice(),
        &b"v6"[..]
    );

    let mut wire = Vec::new();
    writer.write_data(b"hello", &mut wire);
    stream.write_all(&wire).await.unwrap();
    assert_eq!(
        collect(&mut reader, &mut stream, 5).await.as_slice(),
        &b"hello"[..]
    );

    drop(stream);
    echo.abort();
    running.shutdown().await;
}

async fn shaped_read(
    reader: &mut snell_v6::ShapedReader,
    stream: &mut TcpStream,
) -> Option<Vec<u8>> {
    match within(async {
        loop {
            match reader.next_record()? {
                Some(record) => return Ok(Some(record)),
                None => {
                    let mut buffer = [0u8; 4096];
                    let count = stream.read(&mut buffer).await?;
                    if count == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    reader.push(&buffer[..count]);
                }
            }
        }
    })
    .await
    {
        Ok(Some(snell_v6::DecodedRecord::Data(data))) => Some(data),
        Ok(Some(snell_v6::DecodedRecord::Zero)) => None,
        Ok(None) => unreachable!(),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => None,
        Err(error) => panic!("读取 v6 shaped 记录失败: {error}"),
    }
}

#[tokio::test]
async fn v6_default_shaped_tcp_roundtrip() {
    let (target, echo) = tcp_echo().await;
    // 省略 mode 必须按上游默认值使用 default/shaped。
    let running = common::Running::start(snell_config(6, PSK, one_user())).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();

    let mut writer = snell_v6::ShapedWriter::new_random(PSK.as_bytes()).unwrap();
    let request = connect_request(COMMAND_CONNECT, USERKEY, target, b"v6d");
    let wire = writer.write_data_at(&request, 1_700_000_000).unwrap();
    stream.write_all(&wire).await.unwrap();

    let mut reader = snell_v6::ShapedReader::new(PSK.as_bytes());
    assert_eq!(shaped_read(&mut reader, &mut stream).await, Some(vec![0]));

    let mut early = Vec::new();
    while early.len() < 3 {
        early.extend_from_slice(
            &shaped_read(&mut reader, &mut stream)
                .await
                .expect("缺少 v6 early data"),
        );
    }
    assert_eq!(&early[..3], b"v6d");

    let wire = writer.write_data_at(b"hello", 1_700_000_001).unwrap();
    stream.write_all(&wire).await.unwrap();
    let mut echoed = Vec::new();
    while echoed.len() < 5 {
        echoed.extend_from_slice(
            &shaped_read(&mut reader, &mut stream)
                .await
                .expect("缺少 v6 echo"),
        );
    }
    assert_eq!(&echoed[..5], b"hello");

    drop(stream);
    echo.abort();
    running.shutdown().await;
}

#[tokio::test]
async fn v6_unsafe_raw_tcp_roundtrip() {
    let (target, echo) = tcp_echo().await;
    let running = common::Running::start(snell_v6_config("unsafe-raw")).await;
    let mut stream = TcpStream::connect(running.address).await.unwrap();

    let request = connect_request(COMMAND_CONNECT, USERKEY, target, b"raw");
    stream.write_all(&raw_record(&request)).await.unwrap();
    assert_eq!(raw_read(&mut stream).await, Some(vec![0x00]));
    assert_eq!(raw_read(&mut stream).await, Some(b"raw".to_vec()));

    stream.write_all(&raw_record(b"hello")).await.unwrap();
    assert_eq!(raw_read(&mut stream).await, Some(b"hello".to_vec()));

    drop(stream);
    echo.abort();
    running.shutdown().await;
}
