//! 原生 Server::run 的独立 UDP wire 测试；不调用 relay codec 或 ProxySocket。
//!
//! 布局依据 shadowsocks-org eb7862d19b5d1ade04b89e2d49f8c68d34c8b031
//! 的 aead.md、sip022.md、sip023.md；仅复用成熟 AEAD/KDF 与 AES/BLAKE3 原语。
//! 测试只持有本机回环 socket；不执行外部客户端或 DNS 查询。

mod common;

use aes::{
    Aes128, Aes256,
    cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{PASSWORD, socks_config};
use dubhe::{Config, Server, telemetry::Stats};
use serde_json::{Value, json};
use shadowsocks::crypto::{CipherKind, v1::Cipher, v2::udp::UdpCipher};
use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(2);
const QUIET: Duration = Duration::from_millis(40);
const METHODS: [&str; 6] = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];
const SESSION: u64 = 0x1122_3344_5566_7788;
static NONCE: AtomicU64 = AtomicU64::new(1);

async fn bounded<T>(future: impl Future<Output = io::Result<T>>) -> T {
    timeout(WAIT, future)
        .await
        .expect("受控回环操作超时")
        .expect("受控回环操作失败")
}

async fn run(future: impl Future<Output = ()>) {
    // 各测试都大量分配联合TCP/UDP临时端口，避免不同用例争抢两套协议的临时端口池。
    // 用例内部的多用户/多源并发保持不变，生产启动失败测试另外覆盖。
    static PORTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    timeout(Duration::from_secs(30), async {
        let _ports = PORTS.lock().await;
        timeout(Duration::from_secs(20), future)
            .await
            .expect("UDP wire 测试超时，所有 socket 与任务守卫随作用域析构");
    })
    .await
    .expect("UDP wire 测试隔离等待超时");
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn nonce(length: usize) -> Vec<u8> {
    let mut bytes = vec![0x96; length];
    bytes[..8].copy_from_slice(&NONCE.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    bytes
}

#[derive(Clone)]
struct Key {
    method: CipherKind,
    user: Vec<u8>,
    identity: Option<Vec<u8>>,
}

impl Key {
    fn chacha(&self) -> bool {
        self.method == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
    }

    fn prefix_len(&self) -> usize {
        if !self.method.is_aead_2022() {
            self.method.salt_len()
        } else if self.chacha() {
            24
        } else {
            16 + usize::from(self.identity.is_some()) * 16
        }
    }
}

fn configuration(method: &str, multiple: bool) -> (Value, Vec<Key>) {
    let method: CipherKind = method.parse().unwrap();
    let mut key = vec![0x31; method.key_len()];
    let password = if method.is_aead_2022() {
        STANDARD.encode(&key)
    } else {
        shadowsocks::crypto::v1::openssl_bytes_to_key(PASSWORD.as_bytes(), &mut key);
        PASSWORD.to_owned()
    };
    let mut config = socks_config();
    config["inbounds"] = json!([{
        "type":"shadowsocks", "tag":"ss", "listen":"127.0.0.1:0",
        "method":method.to_string(), "password":password
    }]);
    if !multiple {
        return (
            config,
            vec![Key {
                method,
                user: key,
                identity: None,
            }],
        );
    }
    assert!(matches!(
        method,
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
    ));
    let users: Vec<_> = [0x42, 0x53].into_iter().enumerate().map(|(index, byte)| {
        json!({"name":format!("wire-user-{index}"), "password":STANDARD.encode(vec![byte; method.key_len()])})
    }).collect();
    config["inbounds"][0]["users"] = json!(users);
    let keys = [0x42, 0x53]
        .into_iter()
        .map(|byte| Key {
            method,
            user: vec![byte; method.key_len()],
            identity: Some(key.clone()),
        })
        .collect();
    (config, keys)
}

// 自持 join handle，shutdown 也不在 await 前 take；取消/超时/panic 均 abort。
struct Kernel {
    address: SocketAddr,
    stats: Arc<Stats>,
    stop: CancellationToken,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Kernel {
    async fn start(value: Value) -> Self {
        let config = Config::from_json(&value.to_string()).unwrap();
        let server = timeout(WAIT, Server::bind(config)).await.unwrap().unwrap();
        let address = server.local_addr("ss").unwrap();
        assert!(address.ip().is_loopback());
        let stats = server.stats();
        let stop = CancellationToken::new();
        let task = Some(tokio::spawn(server.run(stop.clone())));
        Self {
            address,
            stats,
            stop,
            task,
        }
    }

    async fn shutdown(&mut self) {
        self.stop.cancel();
        timeout(WAIT, self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.task.take();
        let stats = self.stats.snapshot();
        assert_eq!(stats.connections, 0);
        assert_eq!(stats.tcp_flows, 0);
        assert_eq!(stats.udp_associations, 0);
        // 停机屏障之后，原入口 UDP 端口确已释放。
        let _rebound = bounded(UdpSocket::bind(self.address)).await;
    }
}

impl Drop for Kernel {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct Harness {
    kernel: Kernel,
    client: UdpSocket,
    target: UdpSocket,
}

impl Harness {
    async fn start(config: Value) -> Self {
        Self {
            kernel: Kernel::start(config).await,
            client: bounded(UdpSocket::bind("127.0.0.1:0")).await,
            target: bounded(UdpSocket::bind("127.0.0.1:0")).await,
        }
    }

    async fn send(&self, wire: &[u8]) {
        assert_eq!(
            bounded(self.client.send_to(wire, self.kernel.address)).await,
            wire.len()
        );
    }

    async fn exchange(
        &self,
        key: &Key,
        wire: &[u8],
        request: &[u8],
        reply: &[u8],
    ) -> (Decoded, Vec<u8>) {
        self.send(wire).await;
        let mut buffer = vec![0; 65536];
        let (length, source) = timeout(WAIT, self.target.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{}请求未到目标：{:?}",
                    key.method,
                    self.kernel.stats.snapshot()
                )
            })
            .unwrap();
        assert!(source.ip().is_loopback());
        assert_eq!(&buffer[..length], request);
        assert_eq!(
            bounded(self.target.send_to(reply, source)).await,
            reply.len()
        );
        let (length, source) = timeout(WAIT, self.client.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{}响应未到客户端：{:?}",
                    key.method,
                    self.kernel.stats.snapshot()
                )
            })
            .unwrap();
        assert_eq!(source, self.kernel.address);
        let wire = buffer[..length].to_vec();
        (decode(key, &wire).expect("独立响应认证/解析失败"), wire)
    }

    async fn rejects(&self, packets: &[Vec<u8>]) {
        let before = self.kernel.stats.snapshot().dropped;
        for packet in packets {
            self.send(packet).await;
        }
        timeout(WAIT, async {
            while self.kernel.stats.snapshot().dropped < before + packets.len() as u64 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("无效报文未在有界时间内处理完毕");
        let mut buffer = vec![0; 65536];
        assert!(
            timeout(QUIET, self.target.recv_from(&mut buffer))
                .await
                .is_err(),
            "无效报文不能产生目标流量"
        );
        assert!(
            timeout(QUIET, self.client.recv_from(&mut buffer))
                .await
                .is_err(),
            "无效报文不能产生响应"
        );
    }
}

fn aes_block(method: CipherKind, key: &[u8], input: [u8; 16], decrypt: bool) -> [u8; 16] {
    let mut block = Block::<Aes128>::from(input);
    match method {
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
            let cipher = Aes128::new_from_slice(key).unwrap();
            if decrypt {
                cipher.decrypt_block(&mut block);
            } else {
                cipher.encrypt_block(&mut block);
            }
        }
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
            let cipher = Aes256::new_from_slice(key).unwrap();
            if decrypt {
                cipher.decrypt_block(&mut block);
            } else {
                cipher.encrypt_block(&mut block);
            }
        }
        _ => panic!("只有 2022 AES 使用独立头/EIH"),
    }
    block.into()
}

fn address(target: SocketAddr) -> Vec<u8> {
    assert!(target.ip().is_loopback());
    let SocketAddr::V4(target) = target else {
        panic!("本测试使用 IPv4 回环目标");
    };
    let mut bytes = vec![1];
    bytes.extend_from_slice(&target.ip().octets());
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes
}

fn body(method: CipherKind, address: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if method.is_aead_2022() {
        bytes.push(0); // client direction
        bytes.extend_from_slice(&now().to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes()); // UDP padding length
    }
    bytes.extend_from_slice(address);
    bytes.extend_from_slice(payload);
    bytes
}

fn encode(key: &Key, session: u64, packet: u64, body: &[u8]) -> Vec<u8> {
    if !key.method.is_aead_2022() {
        let salt = nonce(key.method.salt_len());
        let mut cipher = Cipher::new(key.method, &key.user, &salt);
        let mut encrypted = body.to_vec();
        encrypted.resize(encrypted.len() + 16, 0);
        cipher.encrypt_packet(&mut encrypted);
        return [salt, encrypted].concat();
    }
    let separate: [u8; 16] = [session.to_be_bytes(), packet.to_be_bytes()]
        .concat()
        .try_into()
        .unwrap();
    let cipher = UdpCipher::new(key.method, &key.user, session);
    if key.chacha() {
        let nonce = nonce(24);
        let mut encrypted = [separate.as_slice(), body].concat();
        encrypted.resize(encrypted.len() + 16, 0);
        cipher.encrypt_packet(&nonce, &mut encrypted);
        return [nonce, encrypted].concat();
    }
    let identity = key.identity.as_deref().unwrap_or(&key.user);
    let mut wire = aes_block(key.method, identity, separate, false).to_vec();
    if key.identity.is_some() {
        // SIP023 UDP：直接 iPSK 加密 hash(uPSK)[..16] XOR 明文独立头。
        let hash = blake3::hash(&key.user);
        let mut identity_block = [0; 16];
        for index in 0..16 {
            identity_block[index] = hash.as_bytes()[index] ^ separate[index];
        }
        wire.extend_from_slice(&aes_block(key.method, identity, identity_block, false));
    }
    let mut encrypted = body.to_vec();
    encrypted.resize(encrypted.len() + 16, 0);
    cipher.encrypt_packet(&separate[4..], &mut encrypted);
    wire.extend_from_slice(&encrypted);
    wire
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "独立 wire 响应格式/认证无效")
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> io::Result<&'a [u8]> {
    if bytes.len() < length {
        return Err(invalid());
    }
    let (head, rest) = bytes.split_at(length);
    *bytes = rest;
    Ok(head)
}

fn read_u64(bytes: &mut &[u8]) -> io::Result<u64> {
    Ok(u64::from_be_bytes(take(bytes, 8)?.try_into().unwrap()))
}

#[derive(Debug)]
struct Control {
    server: u64,
    packet: u64,
    client: u64,
}

#[derive(Debug)]
struct Decoded {
    control: Option<Control>,
    target: SocketAddr,
    payload: Vec<u8>,
}

fn decode(key: &Key, wire: &[u8]) -> io::Result<Decoded> {
    let mut input = wire;
    let (mut plaintext, separate) = if !key.method.is_aead_2022() {
        let salt = take(&mut input, key.method.salt_len())?;
        if input.len() < 16 {
            return Err(invalid());
        }
        let mut encrypted = input.to_vec();
        if !Cipher::new(key.method, &key.user, salt).decrypt_packet(&mut encrypted) {
            return Err(invalid());
        }
        (encrypted, None)
    } else if key.chacha() {
        let nonce = take(&mut input, 24)?;
        if input.len() < 32 {
            return Err(invalid());
        }
        let mut encrypted = input.to_vec();
        if !UdpCipher::new(key.method, &key.user, 0).decrypt_packet(nonce, &mut encrypted) {
            return Err(invalid());
        }
        let separate = encrypted[..16].try_into().unwrap();
        (encrypted[16..].to_vec(), Some(separate))
    } else {
        // EIH 回程没有身份头，独立头与 AEAD 均必须使用已认证 uPSK。
        let separate = aes_block(
            key.method,
            &key.user,
            take(&mut input, 16)?.try_into().unwrap(),
            true,
        );
        if input.len() < 16 {
            return Err(invalid());
        }
        let session = u64::from_be_bytes(separate[..8].try_into().unwrap());
        let mut encrypted = input.to_vec();
        if !UdpCipher::new(key.method, &key.user, session)
            .decrypt_packet(&separate[4..], &mut encrypted)
        {
            return Err(invalid());
        }
        (encrypted, Some(separate))
    };
    plaintext.truncate(plaintext.len().checked_sub(16).ok_or_else(invalid)?);
    let mut plain = plaintext.as_slice();
    let control = if let Some(separate) = separate {
        let server = u64::from_be_bytes(separate[..8].try_into().unwrap());
        let packet = u64::from_be_bytes(separate[8..].try_into().unwrap());
        if take(&mut plain, 1)? != [1] {
            return Err(invalid());
        }
        if now().abs_diff(read_u64(&mut plain)?) > 30 {
            return Err(invalid());
        }
        let client = read_u64(&mut plain)?;
        let padding = u16::from_be_bytes(take(&mut plain, 2)?.try_into().unwrap());
        take(&mut plain, usize::from(padding))?;
        Some(Control {
            server,
            packet,
            client,
        })
    } else {
        None
    };
    if take(&mut plain, 1)? != [1] {
        return Err(invalid());
    }
    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(take(&mut plain, 4)?).unwrap());
    let port = u16::from_be_bytes(take(&mut plain, 2)?.try_into().unwrap());
    if !ip.is_loopback() || port == 0 {
        return Err(invalid());
    }
    Ok(Decoded {
        control,
        target: (ip, port).into(),
        payload: plain.to_vec(),
    })
}

#[tokio::test]
async fn six_methods_handwritten_requests_and_independently_authenticated_responses() {
    run(async {
        for method in METHODS {
            let (config, keys) = configuration(method, false);
            let key = &keys[0];
            let mut harness = Harness::start(config).await;
            let target = harness.target.local_addr().unwrap();
            let mut previous = None;
            for (packet, payload, reply) in [
                (0, b"request".as_slice(), b"response".as_slice()),
                (1, b"".as_slice(), b"".as_slice()),
            ] {
                let mut body = body(key.method, &address(target), payload);
                if key.method.is_aead_2022() {
                    // 合法的非零 padding，防止只验证零长度特例。
                    body[9..11].copy_from_slice(&3u16.to_be_bytes());
                    body.splice(11..11, [0xa1, 0xb2, 0xc3]);
                }
                let wire = encode(key, SESSION, packet, &body);
                let (decoded, response) = harness.exchange(key, &wire, payload, reply).await;
                assert_eq!(decoded.target, target);
                assert_eq!(decoded.payload, reply);
                if let Some(control) = decoded.control {
                    assert_eq!(control.client, SESSION);
                    assert_ne!(control.server, SESSION);
                    if let Some((server, packet)) = previous {
                        assert_eq!(control.server, server);
                        assert!(control.packet > packet);
                    }
                    previous = Some((control.server, control.packet));
                } else {
                    assert_ne!(
                        &response[..key.method.salt_len()],
                        &wire[..key.method.salt_len()]
                    );
                }
            }
            let stats = harness.kernel.stats.snapshot();
            assert_eq!(stats.uplink, 7);
            assert_eq!(stats.downlink, 8);
            assert_eq!(stats.dropped, 0);
            harness.kernel.shutdown().await;
        }
    })
    .await;
}

#[tokio::test]
async fn both_aes_eih_methods_two_users_share_sid_but_not_identity_or_response_key() {
    run(async {
        for method in &METHODS[3..5] {
            let (config, keys) = configuration(method, true);
            let mut harness = Harness::start(config).await;
            let target = harness.target.local_addr().unwrap();
            let message = body(keys[0].method, &address(target), b"eih");
            let mut wrong_identity = keys[0].clone();
            wrong_identity.identity = Some(vec![0x88; wrong_identity.method.key_len()]);
            let mut unknown_user = keys[0].clone();
            unknown_user.user.fill(0x99);
            let mut broken_eih = encode(&keys[0], SESSION, 0, &message);
            broken_eih[16] ^= 1;
            harness
                .rejects(&[
                    encode(&wrong_identity, SESSION, 0, &message),
                    encode(&unknown_user, SESSION, 0, &message),
                    broken_eih,
                ])
                .await;
            assert_eq!(harness.kernel.stats.snapshot().udp_associations, 0);
            let mut server_ids = Vec::new();
            for (index, key) in keys.iter().enumerate() {
                let mut previous = None;
                for packet in 0..2 {
                    let wire = encode(key, SESSION, packet, &message);
                    let (decoded, response) =
                        harness.exchange(key, &wire, b"eih", b"user reply").await;
                    assert_eq!(decoded.target, target);
                    assert_eq!(decoded.payload, b"user reply");
                    let control = decoded.control.unwrap();
                    assert_eq!(control.client, SESSION);
                    assert_ne!(control.server, SESSION);
                    if let Some((server, previous_packet)) = previous {
                        assert_eq!(control.server, server);
                        assert!(control.packet > previous_packet);
                    }
                    previous = Some((control.server, control.packet));
                    // 用另一个 uPSK 或 iPSK 解回程均必须认证失败。
                    assert!(decode(&keys[1 - index], &response).is_err());
                    let identity = Key {
                        method: key.method,
                        user: key.identity.clone().unwrap(),
                        identity: None,
                    };
                    assert!(decode(&identity, &response).is_err());
                }
                server_ids.push(previous.unwrap().0);
            }
            assert_ne!(server_ids[0], server_ids[1]);
            assert_eq!(harness.kernel.stats.snapshot().udp_associations, 2);
            harness.kernel.shutdown().await;
        }
    })
    .await;
}

#[tokio::test]
async fn legacy_sources_targets_and_tcp_udp_replay_share_one_exact_protection_domain() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    run(async {
        for method in &METHODS[..3] {
            let (config, keys) = configuration(method, false);
            let key = &keys[0];
            let mut harness = Harness::start(config).await;
            let second = bounded(UdpSocket::bind("127.0.0.1:0")).await;
            let other = bounded(UdpSocket::bind("127.0.0.1:0")).await;
            let tcp_target = bounded(TcpListener::bind("127.0.0.1:0")).await;
            let destination = harness.target.local_addr().unwrap();
            let first_wire = encode(
                key,
                0,
                0,
                &body(key.method, &address(destination), b"first"),
            );
            harness.send(&first_wire).await;
            let mut buffer = vec![0; 65536];
            let (length, first_peer) = bounded(harness.target.recv_from(&mut buffer)).await;
            assert_eq!(&buffer[..length], b"first");
            let second_wire = encode(
                key,
                0,
                0,
                &body(key.method, &address(destination), b"second"),
            );
            bounded(second.send_to(&second_wire, harness.kernel.address)).await;
            let (length, second_peer) = bounded(harness.target.recv_from(&mut buffer)).await;
            assert_eq!(&buffer[..length], b"second");
            assert_ne!(first_peer, second_peer);
            for (peer, client, reply) in [
                (first_peer, &harness.client, b"one"),
                (second_peer, &second, b"two"),
            ] {
                bounded(harness.target.send_to(reply, peer)).await;
                let (length, _) = bounded(client.recv_from(&mut buffer)).await;
                let decoded = decode(key, &buffer[..length]).unwrap();
                assert_eq!(decoded.target, destination);
                assert_eq!(decoded.payload, reply);
            }
            // 第一来源切换目标，再回到原目标；第二来源不能接收第一来源的回包。
            let wire = encode(
                key,
                0,
                0,
                &body(key.method, &address(other.local_addr().unwrap()), b"other"),
            );
            harness.send(&wire).await;
            let (length, peer) = bounded(other.recv_from(&mut buffer)).await;
            assert_eq!(&buffer[..length], b"other");
            bounded(other.send_to(b"other reply", peer)).await;
            let (length, _) = bounded(harness.client.recv_from(&mut buffer)).await;
            assert_eq!(
                decode(key, &buffer[..length]).unwrap().target,
                other.local_addr().unwrap()
            );
            let wire = encode(
                key,
                0,
                0,
                &body(key.method, &address(destination), b"again"),
            );
            harness.send(&wire).await;
            let (_, peer) = bounded(harness.target.recv_from(&mut buffer)).await;
            assert_eq!(peer, first_peer);
            assert!(timeout(QUIET, second.recv_from(&mut buffer)).await.is_err());
            // UDP已经登记的salt用来构造一个完全有效的TCP请求，仍必须在拨号前拒绝。
            let salt = &first_wire[..key.method.salt_len()];
            let mut cipher = Cipher::new(key.method, &key.user, salt);
            let plain = [
                address(tcp_target.local_addr().unwrap()),
                b"tcp replay".to_vec(),
            ]
            .concat();
            let mut length = (plain.len() as u16).to_be_bytes().to_vec();
            length.resize(18, 0);
            cipher.encrypt_packet(&mut length);
            let mut encrypted = plain;
            encrypted.resize(encrypted.len() + 16, 0);
            cipher.encrypt_packet(&mut encrypted);
            let mut tcp = bounded(TcpStream::connect(harness.kernel.address)).await;
            bounded(tcp.write_all(&[salt, &length, &encrypted].concat())).await;
            bounded(tcp.shutdown()).await;
            let mut response = Vec::new();
            match timeout(WAIT, tcp.read_to_end(&mut response)).await.unwrap() {
                Ok(_) => assert!(response.is_empty()),
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::ConnectionReset),
            }
            assert!(timeout(QUIET, tcp_target.accept()).await.is_err());
            // 反方向：先认证TCP，再使用相同salt构造有效UDP；不能绕过共用作用域。
            let salt = nonce(key.method.salt_len());
            let mut cipher = Cipher::new(key.method, &key.user, &salt);
            let plain = [
                address(tcp_target.local_addr().unwrap()),
                b"valid tcp".to_vec(),
            ]
            .concat();
            let mut length = (plain.len() as u16).to_be_bytes().to_vec();
            length.resize(18, 0);
            cipher.encrypt_packet(&mut length);
            let mut encrypted = plain;
            encrypted.resize(encrypted.len() + 16, 0);
            cipher.encrypt_packet(&mut encrypted);
            let mut tcp = bounded(TcpStream::connect(harness.kernel.address)).await;
            bounded(tcp.write_all(&[salt.as_slice(), &length, &encrypted].concat())).await;
            bounded(tcp.shutdown()).await;
            let (mut target, _) = bounded(tcp_target.accept()).await;
            let mut received = Vec::new();
            bounded(target.read_to_end(&mut received)).await;
            assert_eq!(received, b"valid tcp");
            bounded(target.shutdown()).await;
            bounded(tcp.read_to_end(&mut Vec::new())).await;
            let mut encrypted = body(key.method, &address(destination), b"udp replay");
            encrypted.resize(encrypted.len() + 16, 0);
            Cipher::new(key.method, &key.user, &salt).encrypt_packet(&mut encrypted);
            harness.rejects(&[[salt, encrypted].concat()]).await;
            harness.kernel.shutdown().await;
        }
    })
    .await;
}

#[tokio::test]
async fn full_wire_limit_counts_every_header_and_rejects_oversized_reply_without_accounting() {
    run(async {
        for method in METHODS {
            for multiple in [false, true] {
                if multiple && !METHODS[3..5].contains(&method) {
                    continue;
                }
                let (config, keys) = configuration(method, multiple);
                let key = &keys[0];
                let mut harness = Harness::start(config).await;
                // 只设置自持socket缓冲，不修改系统UDP配置。
                for socket in [&harness.client, &harness.target] {
                    socket2::SockRef::from(socket)
                        .set_send_buffer_size(262144)
                        .unwrap();
                    socket2::SockRef::from(socket)
                        .set_recv_buffer_size(262144)
                        .unwrap();
                }
                let target = harness.target.local_addr().unwrap();
                let overhead =
                    encode(key, SESSION, 0, &body(key.method, &address(target), &[])).len();
                let request = vec![0xa5; 65507 - overhead];
                let wire = encode(
                    key,
                    SESSION,
                    0,
                    &body(key.method, &address(target), &request),
                );
                assert_eq!(wire.len(), 65507);
                harness.send(&wire).await;
                let mut buffer = vec![0; 65536];
                let (length, peer) = bounded(harness.target.recv_from(&mut buffer)).await;
                assert_eq!(&buffer[..length], request);
                // 2022回程独立头16+type1+time8+clientSID8+paddingLen2+addr7+tag16。
                let reply_overhead = if key.method.is_aead_2022() {
                    58 + usize::from(key.chacha()) * 24
                } else {
                    key.method.salt_len() + 7 + 16
                };
                let reply = vec![0x5a; 65507 - reply_overhead];
                let dropped = harness.kernel.stats.snapshot().dropped;
                bounded(harness.target.send_to(&vec![0x5a; reply.len() + 1], peer)).await;
                timeout(WAIT, async {
                    while harness.kernel.stats.snapshot().dropped <= dropped {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert!(
                    timeout(QUIET, harness.client.recv_from(&mut buffer))
                        .await
                        .is_err()
                );
                assert_eq!(harness.kernel.stats.snapshot().downlink, 0);
                bounded(harness.target.send_to(&reply, peer)).await;
                let (length, _) = bounded(harness.client.recv_from(&mut buffer)).await;
                assert_eq!(length, 65507);
                let decoded = decode(key, &buffer[..length]).unwrap();
                assert_eq!(decoded.payload, reply);
                assert_eq!(decoded.target, target);
                assert_eq!(harness.kernel.stats.snapshot().uplink, request.len() as u64);
                assert_eq!(harness.kernel.stats.snapshot().downlink, reply.len() as u64);
                harness.kernel.shutdown().await;
            }
        }
    })
    .await;
}

#[tokio::test]
async fn malformed_authenticated_headers_bad_tags_and_selected_truncations_never_reach_target() {
    run(async {
        for method in METHODS {
            let (config, keys) = configuration(method, false);
            let key = &keys[0];
            let mut harness = Harness::start(config).await;
            let target = harness.target.local_addr().unwrap();
            let message = body(key.method, &address(target), b"valid");
            let valid = encode(key, SESSION, 7, &message);
            let mut bad_tag = valid.clone();
            *bad_tag.last_mut().unwrap() ^= 1;
            let mut wrong_key = key.clone();
            wrong_key.user.fill(0xe4);
            let mut bad = vec![bad_tag, encode(&wrong_key, SESSION, 7, &message)];
            // 选取 salt/nonce/独立头边界与尾 tag；不是 65507 个前缀的穷举。
            let prefix = key.prefix_len();
            for length in [0, 1, prefix - 1, prefix, prefix + 1, valid.len() - 1] {
                bad.push(valid[..length].to_vec());
            }
            let port = target.port().to_be_bytes();
            for malformed_address in [
                vec![2, 127, 0, 0, 1, port[0], port[1]], // 未知 ATYP
                vec![1, 127, 0, 0, 1, port[0]],          // 缺少端口低字节
                vec![1, 127, 0, 0, 1, 0, 0],             // 端口零
                vec![3, 0, port[0], port[1]],            // 空域名，不能进入 DNS
            ] {
                bad.push(encode(
                    key,
                    SESSION,
                    7,
                    &body(key.method, &malformed_address, &[]),
                ));
            }
            if key.method.is_aead_2022() {
                for direction in [1, 2] {
                    let mut invalid_type = message.clone();
                    invalid_type[0] = direction;
                    bad.push(encode(key, SESSION, 7, &invalid_type));
                }
                for time in [now() - 60, now() + 60] {
                    let mut invalid_time = message.clone();
                    invalid_time[1..9].copy_from_slice(&time.to_be_bytes());
                    bad.push(encode(key, SESSION, 7, &invalid_time));
                }
                let mut padding_past_end = message.clone();
                padding_past_end[9..11].copy_from_slice(&u16::MAX.to_be_bytes());
                bad.push(encode(key, SESSION, 7, &padding_past_end));
            }
            harness.rejects(&bad).await;
            let stats = harness.kernel.stats.snapshot();
            assert_eq!(stats.udp_associations, 0);
            assert_eq!(stats.uplink, 0);
            assert_eq!(stats.downlink, 0);
            // 同一 SID/packet 或同一 2017 salt 的合法包仍成功，拒绝不能提前占窗口。
            let (decoded, response) = harness.exchange(key, &valid, b"valid", b"confirmed").await;
            assert_eq!(decoded.target, target);
            assert_eq!(decoded.payload, b"confirmed");
            // 响应反射回入口必须因 2022 方向或 2017 共享 salt 池而拒绝。
            harness.rejects(&[response, valid]).await;
            harness.kernel.shutdown().await;
        }
    })
    .await;
}
