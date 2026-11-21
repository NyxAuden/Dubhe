//! mKCP 回环测试。
//!
//! 客户端编解码完全独立实现（KCP 分段、Xray legacy 认证层、混淆头、AES-GCM），
//! 不调用生产代码，避免“同一实现自证正确”。

mod common;

#[path = "common/vmess.rs"]
mod vmess_client;

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit},
};
use common::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
    time::{interval, sleep, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};

const CONV: u16 = 0x5151;
const MTU: usize = 1350;
const MSS: usize = MTU - 18;
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const ID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

// ---------------------------------------------------------------------------
// 独立客户端线格式
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Wire {
    security: Security,
    header: HeaderState,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // 测试参考实现，与生产端保持了相同形状。
enum Security {
    Raw,
    Legacy,
    Aes(Aes128Gcm),
}

#[derive(Clone)]
enum HeaderState {
    None,
    Srtp(u16),
}

impl Wire {
    fn legacy() -> Self {
        Self {
            security: Security::Legacy,
            header: HeaderState::None,
        }
    }
    fn raw() -> Self {
        Self {
            security: Security::Raw,
            header: HeaderState::None,
        }
    }
    fn seeded(seed: &str, srtp: bool) -> Self {
        let key = Sha256::digest(seed.as_bytes());
        Self {
            security: Security::Aes(Aes128Gcm::new_from_slice(&key[..16]).unwrap()),
            header: if srtp {
                HeaderState::Srtp(0)
            } else {
                HeaderState::None
            },
        }
    }
    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let body = match &self.security {
            Security::Raw => payload.to_vec(),
            Security::Legacy => legacy_seal(payload),
            Security::Aes(cipher) => {
                let mut nonce = [0u8; 12];
                aws_lc_rs::rand::fill(&mut nonce).unwrap();
                let mut out = nonce.to_vec();
                out.extend(
                    cipher
                        .encrypt(
                            &aes_gcm::Nonce::try_from(nonce.as_slice()).unwrap(),
                            payload,
                        )
                        .unwrap(),
                );
                out
            }
        };
        let mut out = Vec::new();
        match &mut self.header {
            HeaderState::None => {}
            HeaderState::Srtp(number) => {
                *number = number.wrapping_add(1);
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&number.to_be_bytes());
            }
        }
        out.extend_from_slice(&body);
        out
    }
    fn open(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let size = match self.header {
            HeaderState::None => 0,
            HeaderState::Srtp(_) => 4,
        };
        if packet.len() <= size {
            return None;
        }
        let body = &packet[size..];
        match &self.security {
            Security::Raw => Some(body.to_vec()),
            Security::Legacy => legacy_open(body),
            Security::Aes(cipher) => {
                if body.len() < 28 {
                    return None;
                }
                cipher
                    .decrypt(&aes_gcm::Nonce::try_from(&body[..12]).ok()?, &body[12..])
                    .ok()
            }
        }
    }
}

fn legacy_seal(plain: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 6 + plain.len()];
    out[4..6].copy_from_slice(&(plain.len() as u16).to_be_bytes());
    out[6..].copy_from_slice(plain);
    let hash = fnv(&out[4..]);
    out[..4].copy_from_slice(&hash.to_be_bytes());
    let length = out.len();
    let extra = (4 - length % 4) % 4;
    out.resize(length + extra, 0);
    for index in 4..out.len() {
        out[index] ^= out[index - 4];
    }
    out.truncate(length);
    out
}

fn legacy_open(cipher: &[u8]) -> Option<Vec<u8>> {
    if cipher.len() <= 6 {
        return None;
    }
    let length = cipher.len();
    let extra = (4 - length % 4) % 4;
    let mut buffer = cipher.to_vec();
    buffer.resize(length + extra, 0);
    for index in (4..buffer.len()).rev() {
        buffer[index] ^= buffer[index - 4];
    }
    buffer.truncate(length);
    if u32::from_be_bytes(buffer[..4].try_into().ok()?) != fnv(&buffer[4..]) {
        return None;
    }
    let payload = usize::from(u16::from_be_bytes(buffer[4..6].try_into().ok()?));
    if buffer.len() - 6 != payload {
        return None;
    }
    Some(buffer[6..].to_vec())
}

fn fnv(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

enum Segment {
    Data {
        conv: u16,
        option: u8,
        timestamp: u32,
        number: u32,
        sending_next: u32,
        payload: Vec<u8>,
    },
    Ack {
        conv: u16,
        receiving_next: u32,
        numbers: Vec<u32>,
    },
    Cmd {
        conv: u16,
        command: u8,
        option: u8,
        receiving_next: u32,
    },
}

fn encode(segment: &Segment) -> Vec<u8> {
    match segment {
        Segment::Data {
            conv,
            option,
            timestamp,
            number,
            sending_next,
            payload,
        } => {
            let mut out = conv.to_be_bytes().to_vec();
            out.extend([1, *option]);
            out.extend_from_slice(&timestamp.to_be_bytes());
            out.extend_from_slice(&number.to_be_bytes());
            out.extend_from_slice(&sending_next.to_be_bytes());
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        Segment::Ack {
            conv,
            receiving_next,
            numbers,
        } => {
            let mut out = conv.to_be_bytes().to_vec();
            out.extend([0, 0]);
            out.extend_from_slice(&(receiving_next + 1024).to_be_bytes());
            out.extend_from_slice(&receiving_next.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.push(numbers.len() as u8);
            for number in numbers {
                out.extend_from_slice(&number.to_be_bytes());
            }
            out
        }
        Segment::Cmd {
            conv,
            command,
            option,
            receiving_next,
        } => {
            let mut out = conv.to_be_bytes().to_vec();
            out.extend([*command, *option]);
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&receiving_next.to_be_bytes());
            out.extend_from_slice(&100u32.to_be_bytes());
            out
        }
    }
}

fn decode(mut buf: &[u8]) -> Vec<Segment> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let conv = u16::from_be_bytes([buf[0], buf[1]]);
        let command = buf[2];
        let option = buf[3];
        let body = &buf[4..];
        match command {
            1 => {
                if body.len() < 14 {
                    break;
                }
                let length = usize::from(u16::from_be_bytes(body[12..14].try_into().unwrap()));
                if body.len() < 14 + length {
                    break;
                }
                out.push(Segment::Data {
                    conv,
                    option,
                    timestamp: u32::from_be_bytes(body[0..4].try_into().unwrap()),
                    number: u32::from_be_bytes(body[4..8].try_into().unwrap()),
                    sending_next: u32::from_be_bytes(body[8..12].try_into().unwrap()),
                    payload: body[14..14 + length].to_vec(),
                });
                buf = &buf[4 + 14 + length..];
            }
            0 => {
                if body.len() < 13 {
                    break;
                }
                let count = usize::from(body[12]);
                if body.len() < 13 + count * 4 {
                    break;
                }
                let mut numbers = Vec::new();
                for index in 0..count {
                    let offset = 13 + index * 4;
                    numbers.push(u32::from_be_bytes(
                        body[offset..offset + 4].try_into().unwrap(),
                    ));
                }
                out.push(Segment::Ack {
                    conv,
                    receiving_next: u32::from_be_bytes(body[4..8].try_into().unwrap()),
                    numbers,
                });
                buf = &buf[4 + 13 + count * 4..];
            }
            2 | 3 => {
                if body.len() < 12 {
                    break;
                }
                out.push(Segment::Cmd {
                    conv,
                    command,
                    option,
                    receiving_next: u32::from_be_bytes(body[4..8].try_into().unwrap()),
                });
                buf = &buf[4 + 12..];
            }
            _ => break,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 客户端会话
// ---------------------------------------------------------------------------

struct Unacked {
    number: u32,
    payload: Vec<u8>,
    sent_at: Option<u32>,
}

struct Client {
    socket: Arc<UdpSocket>,
    dest: SocketAddr,
    conv: u16,
    wire: Wire,
    started: Instant,
    next: u32,
    unacked: Vec<Unacked>,
    rcv_next: u32,
    pending: HashMap<u32, Vec<u8>>,
    drop_once: HashSet<u32>,
    sent_close: bool,
}

impl Client {
    async fn connect(dest: SocketAddr, conv: u16, wire: Wire) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Self {
            socket: Arc::new(socket),
            dest,
            conv,
            wire,
            started: Instant::now(),
            next: 0,
            unacked: Vec::new(),
            rcv_next: 0,
            pending: HashMap::new(),
            drop_once: HashSet::new(),
            sent_close: false,
        }
    }

    fn now(&self) -> u32 {
        self.started.elapsed().as_millis() as u32
    }

    fn into_stream(self) -> DuplexStream {
        let (application, driver) = tokio::io::duplex(1 << 20);
        tokio::spawn(self.run(driver));
        application
    }

    async fn run(mut self, io: DuplexStream) {
        let (mut app_read, mut app_write) = tokio::io::split(io);
        let mut app_buffer = vec![0u8; 4096];
        let mut net_buffer = vec![0u8; 65_536];
        let mut tick = interval(Duration::from_millis(100));
        let mut closed = false;
        loop {
            tokio::select! {
                biased;
                _ = tick.tick() => self.retransmit().await,
                read = app_read.read(&mut app_buffer), if !closed => {
                    match read {
                        Ok(0) => {
                            closed = true;
                            self.send_cmd(2, 1).await;
                        }
                        Ok(count) => {
                            self.push(&app_buffer[..count]);
                            self.send_pending().await;
                        }
                        Err(_) => break,
                    }
                }
                received = self.socket.recv_from(&mut net_buffer) => {
                    let (length, from) = match received {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    if from != self.dest {
                        continue;
                    }
                    let Some(payload) = self.wire.open(&net_buffer[..length]) else {
                        continue;
                    };
                    let mut acknowledged = Vec::new();
                    let mut terminated = false;
                    for segment in decode(&payload) {
                        match segment {
                            Segment::Data {
                                conv,
                                option,
                                number,
                                payload,
                                ..
                            } if conv == self.conv => {
                                if self.drop_once.remove(&number) {
                                    // 故意丢弃首份副本，验证服务端重传。
                                    continue;
                                }
                                if option & 1 == 1 {
                                    terminated = true;
                                }
                                acknowledged.push(number);
                                self.pending.entry(number).or_insert(payload);
                                self.drain_ordered(&mut app_write).await;
                            }
                            Segment::Ack { conv, receiving_next, numbers } if conv == self.conv => {
                                self.unacked.retain(|entry| {
                                    !numbers.contains(&entry.number)
                                        && ((entry.number.wrapping_sub(receiving_next) as i32) >= 0)
                                });
                            }
                            Segment::Cmd { conv, command, option, .. } if conv == self.conv => {
                                if command == 2 || option & 1 == 1 {
                                    terminated = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    if !acknowledged.is_empty() {
                        let segment = encode(&Segment::Ack {
                            conv: self.conv,
                            receiving_next: self.rcv_next,
                            numbers: acknowledged,
                        });
                        let packet = self.wire.seal(&segment);
                        let _ = self.socket.send_to(&packet, self.dest).await;
                    }
                    if terminated {
                        break;
                    }
                }
            }
        }
        if !self.sent_close && !closed {
            self.send_cmd(2, 0).await;
        }
        drop(app_write);
    }

    fn push(&mut self, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + MSS).min(data.len());
            self.unacked.push(Unacked {
                number: self.next,
                payload: data[offset..end].to_vec(),
                sent_at: None,
            });
            self.next += 1;
            offset = end;
        }
    }

    async fn send_pending(&mut self) {
        let now = self.now();
        let sending_next = self.next.saturating_sub(self.unacked.len() as u32);
        let mut segments = Vec::new();
        for entry in &mut self.unacked {
            if entry.sent_at.is_some() {
                continue;
            }
            entry.sent_at = Some(now);
            segments.push(encode(&Segment::Data {
                conv: self.conv,
                option: if self.sent_close { 1 } else { 0 },
                timestamp: now,
                number: entry.number,
                sending_next,
                payload: entry.payload.clone(),
            }));
        }
        self.send_segments(&segments).await;
    }

    async fn retransmit(&mut self) {
        let now = self.now();
        let sending_next = self.next.saturating_sub(self.unacked.len() as u32);
        let mut segments = Vec::new();
        for entry in &mut self.unacked {
            let Some(sent_at) = entry.sent_at else {
                continue;
            };
            if now.wrapping_sub(sent_at) < 150 {
                continue;
            }
            entry.sent_at = Some(now);
            segments.push(encode(&Segment::Data {
                conv: self.conv,
                option: if self.sent_close { 1 } else { 0 },
                timestamp: now,
                number: entry.number,
                sending_next,
                payload: entry.payload.clone(),
            }));
        }
        self.send_segments(&segments).await;
    }

    async fn send_cmd(&mut self, command: u8, option: u8) {
        self.sent_close = true;
        let segment = encode(&Segment::Cmd {
            conv: self.conv,
            command,
            option,
            receiving_next: self.rcv_next,
        });
        self.send_segments(&[segment]).await;
    }

    async fn send_segments(&mut self, segments: &[Vec<u8>]) {
        if segments.is_empty() {
            return;
        }
        let mut payload = Vec::new();
        for segment in segments {
            payload.extend_from_slice(segment);
        }
        let packet = self.wire.seal(&payload);
        let _ = self.socket.send_to(&packet, self.dest).await;
    }

    async fn drain_ordered<W: AsyncWrite + Unpin>(&mut self, output: &mut W) {
        while let Some(payload) = self.pending.remove(&self.rcv_next) {
            if output.write_all(&payload).await.is_err() {
                return;
            }
            self.rcv_next = self.rcv_next.wrapping_add(1);
        }
        let _ = output.flush().await;
    }
}

// ---------------------------------------------------------------------------
// 请求与配置
// ---------------------------------------------------------------------------

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

fn config(inbound: Value) -> Value {
    let mut value = socks_config();
    value["inbounds"] = json!([inbound]);
    value
}

fn vless_inbound(extra: Value) -> Value {
    let mut inbound = json!({
        "type":"vless-kcp","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}]
    });
    merge(&mut inbound, extra);
    inbound
}

fn merge(target: &mut Value, extra: Value) {
    for (key, value) in extra.as_object().unwrap() {
        target[key] = value.clone();
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plaintext_vless_tcp_and_udp_over_legacy_kcp() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let udp = Echo::udp("127.0.0.1").await;
    let server = Running::start(config(vless_inbound(
        json!({"allow_insecure_transport": true}),
    )))
    .await;

    let mut stream = Client::connect(server.address, CONV, Wire::legacy())
        .await
        .into_stream();
    stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"kcp-tcp").await;

    let mut packets = Client::connect(server.address, CONV + 1, Wire::legacy())
        .await
        .into_stream();
    packets
        .write_all(&request(2, udp.address, false))
        .await
        .unwrap();
    response(&mut packets).await;
    packets.write_all(&frame(b"kcp-udp")).await.unwrap();
    packet(&mut packets, b"kcp-udp").await;

    drop(stream);
    drop(packets);
    server.shutdown().await;
}

#[tokio::test]
async fn tls_vless_over_kcp() {
    let cert = Certificate::new();
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(vless_inbound(json!({
        "certificate": cert.dir.path().join("cert.pem"),
        "private_key": cert.dir.path().join("key.pem")
    }))))
    .await;
    let stream = Client::connect(server.address, CONV, Wire::legacy())
        .await
        .into_stream();
    let mut stream = tls_connect(&cert, stream).await;
    stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"kcp-tls").await;
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn srtp_header_and_seeded_aead_are_accepted_but_wrong_keys_are_not() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(vless_inbound(json!({
        "allow_insecure_transport": true,
        "kcp": {"header": {"type": "srtp"}, "seed": "kcp-test-seed", "tti": 20}
    }))))
    .await;

    let mut stream = Client::connect(server.address, CONV, Wire::seeded("kcp-test-seed", true))
        .await
        .into_stream();
    stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"seeded").await;
    drop(stream);

    // 错误 seed：服务端无法解包，不会建立会话。
    let mut wrong = Client::connect(server.address, CONV + 2, Wire::seeded("other-seed", true))
        .await
        .into_stream();
    wrong
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    let mut head = [0u8; 2];
    assert!(
        timeout(Duration::from_millis(400), wrong.read_exact(&mut head))
            .await
            .is_err(),
        "错误 seed 不得得到 VLESS 应答"
    );
    drop(wrong);
    server.shutdown().await;
}

#[tokio::test]
async fn raw_security_matches_new_xray_default() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(vless_inbound(json!({
        "allow_insecure_transport": true,
        "kcp": {"security": "none"}
    }))))
    .await;
    let mut stream = Client::connect(server.address, CONV, Wire::raw())
        .await
        .into_stream();
    stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"raw").await;
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn conversations_are_isolated_and_terminate_closes_only_one_session() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(vless_inbound(json!({
        "allow_insecure_transport": true
    }))))
    .await;
    let mut first = Client::connect(server.address, 0x0101, Wire::legacy())
        .await
        .into_stream();
    let mut second = Client::connect(server.address, 0x0202, Wire::legacy())
        .await
        .into_stream();
    for stream in [&mut first, &mut second] {
        stream
            .write_all(&request(1, tcp.address, false))
            .await
            .unwrap();
        response(stream).await;
        exchange(stream, b"conv").await;
    }
    // 第一条流关闭（发送 Terminate）不影响第二条。
    drop(first);
    sleep(Duration::from_millis(150)).await;
    exchange(&mut second, b"still-alive").await;
    drop(second);
    server.shutdown().await;
}

#[tokio::test]
async fn lost_downlink_segment_is_retransmitted() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(vless_inbound(json!({
        "allow_insecure_transport": true,
        "kcp": {"tti": 20}
    }))))
    .await;
    let mut client = Client::connect(server.address, CONV, Wire::legacy()).await;
    // 服务端第 1 个数据段承载请求应答；丢弃首份副本验证 ARQ。
    client.drop_once.insert(1);
    let mut stream = client.into_stream();
    stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    let started = Instant::now();
    exchange(&mut stream, b"retransmitted").await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "重传应在 3 秒内完成"
    );
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn vmess_over_kcp() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(json!({
        "type":"vmess-kcp","tag":"vmess","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":vmess_client::UUID}],
        "allow_insecure_body": true
    })))
    .await;
    let stream = Client::connect(server.address, CONV, Wire::legacy())
        .await
        .into_stream();
    let mut client = vmess_client::Client::start(
        stream,
        vmess_client::Request::new(1, vmess_client::target(tcp.address), 5, 0),
        Some(b"vmess-kcp"),
    )
    .await;
    let mut received = client.read(9).await;
    assert_eq!(received, b"vmess-kcp");
    // KCP 的 Close 语义与 Xray 一致：本地关闭后不再接收，因此先读应答再关闭。
    client.send(b"ping").await;
    received = client.read(4).await;
    assert_eq!(received, b"ping");
    client.finish().await;
    server.shutdown().await;
}

#[tokio::test]
async fn trojan_over_kcp() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(json!({
        "type":"trojan-kcp","tag":"trojan","listen":"127.0.0.1:0",
        "users":[{"name":"test","password":PASSWORD}],
        "allow_insecure_transport": true
    })))
    .await;
    let mut stream = Client::connect(server.address, CONV, Wire::legacy())
        .await
        .into_stream();
    let mut hello = trojan_request(tcp.address);
    hello.extend(b"trojan-kcp");
    stream.write_all(&hello).await.unwrap();
    let mut echoed = vec![0u8; 10];
    read_exact(&mut stream, &mut echoed).await;
    assert_eq!(echoed, b"trojan-kcp");
    drop(stream);
    server.shutdown().await;
}

fn trojan_request(target: SocketAddr) -> Vec<u8> {
    use sha2::Sha224;
    let hash = Sha224::digest(PASSWORD.as_bytes());
    let mut request = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_bytes();
    request.extend_from_slice(b"\r\n");
    request.push(1);
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            request.push(1);
            request.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request.push(3);
            request.extend(ip.octets());
        }
    }
    request.extend(target.port().to_be_bytes());
    request.extend_from_slice(b"\r\n");
    request
}

#[tokio::test]
async fn shutdown_ends_sessions_and_releases_udp_port() {
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(vless_inbound(json!({
        "allow_insecure_transport": true
    }))))
    .await;
    let address = server.address;
    let mut stream = Client::connect(address, CONV, Wire::legacy())
        .await
        .into_stream();
    stream
        .write_all(&request(1, tcp.address, false))
        .await
        .unwrap();
    response(&mut stream).await;
    exchange(&mut stream, b"before-stop").await;
    server.shutdown().await;
    // 服务端停机发送 Terminate，客户端流应看到 EOF。
    let mut trailing = [0u8; 1];
    let result = timeout(Duration::from_secs(3), stream.read(&mut trailing))
        .await
        .expect("停机后应关闭会话");
    assert!(matches!(result, Ok(0) | Err(_)), "{result:?}");
    rebind_udp(address).await;
}

async fn tls_connect<S>(cert: &Certificate, stream: S) -> TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    timeout(
        Duration::from_secs(3),
        TlsConnector::from(Arc::new(config)).connect("localhost".try_into().unwrap(), stream),
    )
    .await
    .unwrap()
    .unwrap()
}

// ---------------------------------------------------------------------------
// 配置校验
// ---------------------------------------------------------------------------

fn parse(value: Value) -> anyhow::Result<dubhe::Config> {
    dubhe::Config::from_json(&value.to_string())
}

#[test]
fn kcp_settings_are_validated_and_defaulted() {
    let ok = vless_inbound(json!({"allow_insecure_transport": true}));
    let parsed = parse(config(ok)).unwrap();
    match &parsed.inbounds[0] {
        dubhe::config::Inbound::VlessKcp { kcp, .. } => {
            assert_eq!(kcp.mtu, 1350);
            assert_eq!(kcp.tti, 50);
            assert_eq!(kcp.max_sending_window, 2 * 1024 * 1024);
            assert_eq!(kcp.security, dubhe::config::KcpSecurity::Legacy);
        }
        other => panic!("应为 VlessKcp: {other:?}"),
    }

    for (kcp, message) in [
        (json!({"mtu": 20}), "mtu"),
        (json!({"mtu": 9001}), "mtu"),
        (json!({"tti": 9}), "tti"),
        (json!({"tti": 1001}), "tti"),
        (json!({"cwnd_multiplier": 0}), "cwnd_multiplier"),
        (
            json!({"mtu": 1350, "max_sending_window": 1349}),
            "max_sending_window",
        ),
        (
            json!({"seed": "x", "security": "none"}),
            "seed 不能与 security=none",
        ),
        (json!({"uplink_capacity": 100000}), "uplink_capacity"),
    ] {
        let inbound = vless_inbound(json!({
            "allow_insecure_transport": true,
            "kcp": kcp
        }));
        let error = parse(config(inbound)).unwrap_err().to_string();
        assert!(error.contains(message), "{error}");
    }

    let inbound = vless_inbound(json!({
        "allow_insecure_transport": true,
        "kcp": {"header": {"type": "dns", "domain": ""}}
    }));
    assert!(parse(config(inbound)).is_err());

    let inbound = vless_inbound(json!({
        "allow_insecure_transport": true,
        "kcp": {"header": {"type": "bogus"}}
    }));
    assert!(parse(config(inbound)).is_err());
}
