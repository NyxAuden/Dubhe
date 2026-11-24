//! serve_tcp 的独立回环 wire 测试：只复用密码原语，不使用协议 codec 或客户端流。
//!
//! 请求地址、长度、2022 固定/变量头与响应解析均在这里手写。
//! EIH使用独立aes/blake3测试依赖封装身份块，不调用生产EIH编码器。

use super::*;
use std::{
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

use hickory_resolver::config::ResolverOpts;
use shadowsocks::crypto::{CipherKind, v1::Cipher, v2::tcp::TcpCipher};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Barrier, Semaphore},
    task::JoinHandle,
};

use crate::{config::Config, dns::Dns, route::Router, telemetry::Stats};

const IO_LIMIT: Duration = Duration::from_secs(3);
const TEST_LIMIT: Duration = Duration::from_secs(15);
const FIRST: &[u8] = b"first payload survives the handshake";
const RESPONSE: &[u8] = b"independently decrypted server response";
const TAIL: &[u8] = b"still writable after the opposite half closed";
const METHODS: [CipherKind; 6] = [
    CipherKind::AES_128_GCM,
    CipherKind::AES_256_GCM,
    CipherKind::CHACHA20_POLY1305,
    CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
    CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
];

async fn bounded<T>(future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    timeout(IO_LIMIT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "回环测试操作超时"))?
}

async fn run(future: impl Future<Output = io::Result<()>>) {
    timeout(TEST_LIMIT, future)
        .await
        .expect("独立 TCP 测试超时；所有 socket/future 随作用域析构")
        .expect("独立 TCP 协议测试失败");
}

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

async fn listener() -> io::Result<TcpListener> {
    bounded(TcpListener::bind(loopback())).await
}

async fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = listener().await?;
    let address = listener.local_addr()?;
    assert!(address.ip().is_loopback());
    let client = bounded(TcpStream::connect(address)).await?;
    let (server, peer) = bounded(listener.accept()).await?;
    assert!(peer.ip().is_loopback());
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    Ok((client, server))
}

// JoinHandle 本身的 Drop 会 detach；本守卫在错误、panic 或外层超时时一律 abort。
struct Serving(JoinHandle<io::Result<()>>);

impl Serving {
    fn spawn(future: impl Future<Output = io::Result<()>> + Send + 'static) -> Self {
        Self(tokio::spawn(async move {
            timeout(TEST_LIMIT, future)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "服务测试任务超时"))?
        }))
    }

    async fn finish(&mut self) -> io::Result<()> {
        timeout(IO_LIMIT, &mut self.0)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "服务测试任务未结束"))?
            .map_err(io::Error::other)?
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Fixture {
    prepared: Arc<Prepared>,
    ctx: Arc<forward::Context>,
    handshakes: Arc<Semaphore>,
}

impl Fixture {
    fn new(method: CipherKind, handshake_timeout_ms: u64, slots: usize) -> Self {
        // 这里只借 Config 建立 direct 路由，不启动 Server，也不调用协议密钥准备器。
        let mut config = Config::from_json(
            r#"{"version":1,"inbounds":[{"type":"socks5","tag":"ss","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"}}"#,
        )
        .unwrap();
        config.limits.handshake_timeout_ms = handshake_timeout_ms;
        let ctx = forward::Context {
            limits: config.limits.clone(),
            router: Router::new(&config).unwrap(),
            // 空 nameserver 列表，且所有目标均为本测试持有的回环 IP；绝无公网 DNS。
            dns: Dns::new(
                crate::dns::empty_resolver(ResolverOpts::default()).unwrap(),
                1,
                IO_LIMIT,
            ),
            stats: Arc::new(Stats::default()),
            udp_slots: Arc::new(Semaphore::new(1)),
            udp_bytes: Arc::new(Semaphore::new(1)),
            vless_encryption: std::collections::HashMap::new(),
            children: tokio_util::task::TaskTracker::new(),
            outbound_stop: tokio_util::sync::CancellationToken::new(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            sniff: None,
            connections: Arc::new(crate::connections::Registry::default()),
            reverse: Arc::new(crate::reverse::Registry::default()),
            reverse_bridges: Vec::new(),
        };
        Self {
            prepared: Arc::new(Prepared {
                keys: ShadowsocksKeys {
                    method,
                    key: vec![0x11; method.key_len()],
                    users: None,
                },
                inbound: 0,
                replay: Arc::new(ReplayPool::new(64)),
            }),
            ctx: Arc::new(ctx),
            handshakes: Arc::new(Semaphore::new(slots)),
        }
    }

    fn start(&self, stream: TcpStream, gate: Option<Arc<Barrier>>) -> Serving {
        let prepared = self.prepared.clone();
        let ctx = self.ctx.clone();
        let permit = self.handshakes.clone().try_acquire_owned().unwrap();
        Serving::spawn(async move {
            if let Some(gate) = gate {
                gate.wait().await;
            }
            serve_tcp(
                stream,
                prepared,
                ctx,
                "ss",
                crate::runtime::HandshakePermits::new(permit, None),
            )
            .await
        })
    }
}

// 此枚举只封装密码调用与 nonce 递增；不承担任何协议 framing。
enum WireCipher {
    V1(Box<Cipher>),
    V2(Box<TcpCipher>),
}

impl WireCipher {
    fn new(method: CipherKind, key: &[u8], salt: &[u8]) -> Self {
        if method.is_aead_2022() {
            Self::V2(Box::new(TcpCipher::new(method, key, salt)))
        } else {
            Self::V1(Box::new(Cipher::new(method, key, salt)))
        }
    }

    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut packet = plaintext.to_vec();
        packet.resize(packet.len() + 16, 0);
        match self {
            Self::V1(cipher) => cipher.encrypt_packet(&mut packet),
            Self::V2(cipher) => cipher.encrypt_packet(&mut packet),
        }
        packet
    }

    fn open(&mut self, packet: &[u8]) -> io::Result<Vec<u8>> {
        if packet.len() < 16 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let mut plaintext = packet.to_vec();
        let valid = match self {
            Self::V1(cipher) => cipher.decrypt_packet(&mut plaintext),
            Self::V2(cipher) => cipher.decrypt_packet(&mut plaintext),
        };
        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "响应 AEAD tag 错误",
            ));
        }
        plaintext.truncate(packet.len() - 16);
        Ok(plaintext)
    }
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn address(target: SocketAddr) -> Vec<u8> {
    assert!(target.ip().is_loopback());
    let mut bytes = match target {
        SocketAddr::V4(target) => [vec![1], target.ip().octets().to_vec()].concat(),
        SocketAddr::V6(target) => [vec![4], target.ip().octets().to_vec()].concat(),
    };
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes
}

struct Request {
    method: CipherKind,
    salt: Vec<u8>,
    wire: Vec<u8>,
    cipher: WireCipher,
}

impl Request {
    fn new(method: CipherKind, key: &[u8], target: SocketAddr) -> Self {
        let salt = vec![0x66; method.salt_len()];
        let mut request = Self {
            method,
            wire: salt.clone(),
            cipher: WireCipher::new(method, key, &salt),
            salt,
        };
        let mut first = address(target);
        if method.is_aead_2022() {
            first.extend_from_slice(&0u16.to_be_bytes()); // padding length = 0
            first.extend_from_slice(FIRST);
            let mut header = vec![0]; // client stream type
            header.extend_from_slice(&timestamp().to_be_bytes());
            header.extend_from_slice(&u16::try_from(first.len()).unwrap().to_be_bytes());
            request.wire.extend(request.cipher.seal(&header));
            request.wire.extend(request.cipher.seal(&first));
        } else {
            first.extend_from_slice(FIRST);
            // 地址分别在 ATYP 后、双字节端口中间跨 authenticated chunk。
            // 这不是单纯把一个合法大 chunk 的 TCP write 切碎。
            for chunk in [&first[..1], &first[1..6], &first[6..]] {
                let packet = request.chunk(chunk);
                request.wire.extend(packet);
            }
        }
        request
    }

    fn with_first(method: CipherKind, key: &[u8], variable: &[u8], kind: u8, time: u64) -> Self {
        let salt = vec![0x66; method.salt_len()];
        let mut request = Self {
            method,
            wire: salt.clone(),
            cipher: WireCipher::new(method, key, &salt),
            salt,
        };
        let length = u16::try_from(variable.len()).expect("长度必须确实能编码为 u16");
        assert!(method.is_aead_2022() || length <= 0x3fff);
        let mut header = Vec::new();
        if method.is_aead_2022() {
            header.push(kind);
            header.extend_from_slice(&time.to_be_bytes());
        }
        header.extend_from_slice(&length.to_be_bytes());
        request.wire.extend(request.cipher.seal(&header));
        request.wire.extend(request.cipher.seal(variable));
        request
    }

    fn chunk(&mut self, data: &[u8]) -> Vec<u8> {
        let length = u16::try_from(data.len()).unwrap();
        assert!(self.method.is_aead_2022() || length <= 0x3fff);
        [
            self.cipher.seal(&length.to_be_bytes()),
            self.cipher.seal(data),
        ]
        .concat()
    }
}

fn explicit_request(method: CipherKind, variable: &[u8], kind: u8, time: u64) -> Vec<u8> {
    Request::with_first(method, &vec![0x11; method.key_len()], variable, kind, time).wire
}

#[tokio::test]
async fn independent_ipv6_and_domain_targets_preserve_payload() {
    run(async {
        for method in METHODS {
            for domain in [false, true] {
                let target = bounded(TcpListener::bind(if domain {
                    "127.0.0.1:0"
                } else {
                    "[::1]:0"
                }))
                .await?;
                let fixture = Fixture::new(method, 1000, 1);
                let mut variable = if domain {
                    [
                        vec![3, 9],
                        b"localhost".to_vec(),
                        target.local_addr()?.port().to_be_bytes().to_vec(),
                    ]
                    .concat()
                } else {
                    address(target.local_addr()?)
                };
                if method.is_aead_2022() {
                    variable.extend_from_slice(&[0, 0]);
                }
                variable.extend_from_slice(FIRST);
                let wire = explicit_request(method, &variable, 0, timestamp());
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&wire)).await?;
                bounded(client.shutdown()).await?;
                let mut serving = fixture.start(server, None);
                let (mut target, _) = bounded(target.accept()).await?;
                assert_eq!(read_to_eof(&mut target).await?, FIRST);
                bounded(target.write_all(RESPONSE)).await?;
                bounded(target.shutdown()).await?;
                let reply = read_to_eof(&mut client).await?;
                assert_eq!(
                    response(
                        method,
                        &fixture.prepared.keys.key,
                        &vec![0x66; method.salt_len()],
                        &reply
                    )?,
                    RESPONSE
                );
                serving.finish().await?;
            }
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn independent_invalid_headers_and_every_truncated_request_prefix_never_dial() {
    run(async {
        for method in METHODS {
            let target = listener().await?;
            let destination = target.local_addr()?;
            let valid = Request::new(method, &vec![0x11; method.key_len()], destination).wire;
            for end in 0..valid.len() {
                let fixture = Fixture::new(method, 100, 1);
                let (mut client, server) = tcp_pair().await?;
                // 2017的多chunk最后一块包含端口；缺少末尾tag不能完成地址认证。
                bounded(client.write_all(&valid[..end])).await?;
                bounded(client.shutdown()).await?;
                let mut serving = fixture.start(server, None);
                assert!(
                    serving.finish().await.is_err(),
                    "截断请求被接受：{method:?}/{end}"
                );
                assert_eq!(fixture.ctx.stats.snapshot().uplink, 0);
                closed_without_response(&mut client, method).await?;
            }
            no_target(&target).await;
            let mut invalid_variables = vec![
                vec![9, 0, 0],
                vec![3, 0, 0, 80],
                vec![3, 3, b'a', b' ', b'b', 0, 80],
                vec![1, 127, 0, 0, 1, 0, 0],
            ];
            if method.is_aead_2022() {
                let mut padding = address(destination);
                padding.extend_from_slice(&901u16.to_be_bytes());
                padding.extend_from_slice(&[7; 901]);
                invalid_variables.push(padding);
                let mut truncated = address(destination);
                truncated.extend_from_slice(&1u16.to_be_bytes());
                invalid_variables.push(truncated);
                let mut empty = address(destination);
                empty.extend_from_slice(&[0, 0]);
                invalid_variables.push(empty);
            }
            for variable in invalid_variables {
                let fixture = Fixture::new(method, 100, 1);
                let (mut client, server) = tcp_pair().await?;
                let wire = explicit_request(method, &variable, 0, timestamp());
                bounded(client.write_all(&wire)).await?;
                bounded(client.shutdown()).await?;
                let mut serving = fixture.start(server, None);
                assert!(serving.finish().await.is_err());
                closed_without_response(&mut client, method).await?;
            }
            if method.is_aead_2022() {
                let variable = [address(destination), vec![0, 0], FIRST.to_vec()].concat();
                for (kind, time) in [
                    (1, timestamp()),
                    (0, timestamp() - 60),
                    (0, timestamp() + 60),
                ] {
                    let fixture = Fixture::new(method, 100, 1);
                    let (mut client, server) = tcp_pair().await?;
                    bounded(client.write_all(&explicit_request(method, &variable, kind, time)))
                        .await?;
                    let mut serving = fixture.start(server, None);
                    assert!(serving.finish().await.is_err());
                    closed_without_response(&mut client, method).await?;
                }
            }
            no_target(&target).await;
        }
        Ok(())
    })
    .await;
}

fn pattern(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

#[tokio::test]
async fn six_methods_maximum_first_and_following_chunks_and_large_response() {
    run(async {
        for method in METHODS {
            let target_listener = listener().await?;
            let fixture = Fixture::new(method, 1_000, 1);
            let maximum = if method.is_aead_2022() {
                65_535
            } else {
                16_383
            };
            let mut first = address(target_listener.local_addr()?);
            if method.is_aead_2022() {
                first.extend_from_slice(&[0, 0]);
            }
            let first_payload = pattern(maximum - first.len(), 0x21);
            first.extend_from_slice(&first_payload);
            assert_eq!(first.len(), maximum);
            let mut request =
                Request::with_first(method, &fixture.prepared.keys.key, &first, 0, timestamp());
            let second_payload = pattern(maximum, 0x62);
            let second = request.chunk(&second_payload);
            let third = request.chunk(TAIL);
            let expected = [first_payload, second_payload, TAIL.to_vec()].concat();
            let (mut client, server) = tcp_pair().await?;
            bounded(client.write_all(&request.wire)).await?;
            let mut serving = fixture.start(server, None);
            let (mut target, _) = bounded(target_listener.accept()).await?;
            let (_, received) = tokio::try_join!(
                async {
                    bounded(client.write_all(&second)).await?;
                    bounded(client.write_all(&third)).await?;
                    bounded(client.shutdown()).await
                },
                read_to_eof(&mut target),
            )?;
            assert_eq!(received, expected, "{method:?} 最大分块/后续分块边界");
            // 超过两个最大协议块的响应，独立 parser 必须认证多个回程块。
            let reply = pattern(maximum * 2 + 37, 0xa3);
            let (_, wire) = tokio::try_join!(
                async {
                    bounded(target.write_all(&reply)).await?;
                    bounded(target.shutdown()).await
                },
                read_to_eof(&mut client),
            )?;
            assert_eq!(
                response(method, &fixture.prepared.keys.key, &request.salt, &wire)?,
                reply
            );
            serving.finish().await?;
            let stats = fixture.ctx.stats.snapshot();
            assert_eq!(stats.uplink, expected.len() as u64);
            assert_eq!(stats.downlink, reply.len() as u64);
            assert_eq!(stats.tcp_flows, 0);
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn aead2017_authenticated_reserved_length_bits_reject_before_target() {
    run(async {
        for &method in &METHODS[..3] {
            let target = listener().await?;
            for length in [0x4000u16, 0x8000, 0xffff] {
                let fixture = Fixture::new(method, 1_000, 1);
                let salt = vec![0x66; method.salt_len()];
                let mut cipher = WireCipher::new(method, &fixture.prepared.keys.key, &salt);
                let wire = [salt, cipher.seal(&length.to_be_bytes())].concat();
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&wire)).await?;
                // 不发送 body，不关写端：合法认证的非法长度必须立即拒绝。
                let mut serving = fixture.start(server, None);
                let error = serving.finish().await.unwrap_err();
                assert_eq!(error.to_string(), "Shadowsocks握手失败");
                assert_ne!(error.kind(), io::ErrorKind::TimedOut);
                assert_eq!(fixture.handshakes.available_permits(), 1);
                closed_without_response(&mut client, method).await?;
                assert_eq!(fixture.ctx.stats.snapshot().uplink, 0);
            }
            no_target(&target).await;
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn aead2022_declared_first_chunk_requires_complete_tag_and_rejects_trailing_garbage() {
    run(async {
        // 65536 无法编码为 u16；不制造截断 cast 的伪“超长”长度。
        assert!(u16::try_from(65_536usize).is_err());
        for &method in &METHODS[3..] {
            let target_listener = listener().await?;
            let variable = [
                address(target_listener.local_addr()?),
                vec![0, 0],
                FIRST.to_vec(),
            ]
            .concat();
            for missing in [1, 16] {
                let fixture = Fixture::new(method, 1_000, 1);
                let request = Request::with_first(
                    method,
                    &fixture.prepared.keys.key,
                    &variable,
                    0,
                    timestamp(),
                );
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&request.wire[..request.wire.len() - missing])).await?;
                bounded(client.shutdown()).await?;
                let mut serving = fixture.start(server, None);
                let error = serving.finish().await.unwrap_err();
                assert_eq!(error.to_string(), "Shadowsocks握手失败");
                closed_without_response(&mut client, method).await?;
                no_target(&target_listener).await;
            }
            let fixture = Fixture::new(method, 1_000, 1);
            let request = Request::with_first(
                method,
                &fixture.prepared.keys.key,
                &variable,
                0,
                timestamp(),
            );
            let (mut client, server) = tcp_pair().await?;
            bounded(client.write_all(&request.wire)).await?;
            let mut serving = fixture.start(server, None);
            let (mut target, _) = bounded(target_listener.accept()).await?;
            let mut first = vec![0; FIRST.len()];
            bounded(target.read_exact(&mut first)).await?;
            assert_eq!(first, FIRST);
            // 完整认证的前块已转发；额外原始字节应作为下一长度块的截断失败，
            // 不能被吞进前块、伪造成附加明文或无错误 EOF。
            bounded(client.write_all(&[0xde, 0xad, 0xbe, 0xef])).await?;
            bounded(client.shutdown()).await?;
            let error = serving.finish().await.unwrap_err();
            assert_ne!(error.kind(), io::ErrorKind::TimedOut);
            let mut extra = Vec::new();
            if let Err(error) = bounded(target.read_to_end(&mut extra)).await {
                assert!(matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ));
            }
            assert!(extra.is_empty(), "多余密文字节不能成为前块的明文");
            assert_eq!(fixture.ctx.stats.snapshot().uplink, FIRST.len() as u64);
            no_target(&target_listener).await;
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn aead2022_padding_900_allows_empty_first_payload_and_preserves_nonempty_payload() {
    run(async {
        for &method in &METHODS[3..] {
            for first_payload in [&[][..], FIRST] {
                let target_listener = listener().await?;
                let fixture = Fixture::new(method, 1_000, 1);
                let mut variable = address(target_listener.local_addr()?);
                variable.extend_from_slice(&900u16.to_be_bytes());
                variable.extend_from_slice(&[0xa5; 900]);
                variable.extend_from_slice(first_payload);
                let mut request = Request::with_first(
                    method,
                    &fixture.prepared.keys.key,
                    &variable,
                    0,
                    timestamp(),
                );
                let next = request.chunk(TAIL);
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&request.wire)).await?;
                let mut serving = fixture.start(server, None);
                let (mut target, _) = bounded(target_listener.accept()).await?;
                bounded(client.write_all(&next)).await?;
                bounded(client.shutdown()).await?;
                assert_eq!(
                    read_to_eof(&mut target).await?,
                    [first_payload, TAIL].concat()
                );
                bounded(target.write_all(RESPONSE)).await?;
                bounded(target.shutdown()).await?;
                let reply = read_to_eof(&mut client).await?;
                assert_eq!(
                    response(method, &fixture.prepared.keys.key, &request.salt, &reply)?,
                    RESPONSE
                );
                serving.finish().await?;
                assert_eq!(
                    fixture.ctx.stats.snapshot().uplink,
                    (first_payload.len() + TAIL.len()) as u64
                );
                assert_eq!(fixture.ctx.stats.snapshot().downlink, RESPONSE.len() as u64);
            }
        }
        Ok(())
    })
    .await;
}

// 时间边缘只对起止处于同一 wall-second 的尝试下结论；跨秒完整清理后重试。
// 观察窗口内只会对回环目标拨号，并以固定尝试数和外层 timeout 双重有界。
async fn timestamp_edge(method: CipherKind, offset: i64, accepted: bool) -> io::Result<()> {
    for _ in 0..8 {
        let target_listener = listener().await?;
        let fixture = Fixture::new(method, 1_000, 1);
        let (mut client, server) = tcp_pair().await?;
        let variable = [
            address(target_listener.local_addr()?),
            vec![0, 0],
            FIRST.to_vec(),
        ]
        .concat();
        let start = timestamp();
        let remote = start.checked_add_signed(offset).unwrap();
        let request = Request::with_first(method, &fixture.prepared.keys.key, &variable, 0, remote);
        bounded(client.write_all(&request.wire)).await?;
        bounded(client.shutdown()).await?;
        let mut serving = fixture.start(server, None);
        // 同时等待握手拒绝或目标连接；不为负例故意等待一个长 accept timeout。
        let observation = timeout(IO_LIMIT, async {
            tokio::select! {
                biased;
                joined = &mut serving.0 => {
                    Ok::<_, io::Error>((joined.map_err(io::Error::other)?, None))
                }
                connection = target_listener.accept() => {
                    Ok((Ok(()), Some(connection?.0)))
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "时间边缘握手未决"))??;
        let end = timestamp();
        let (result, mut target) = observation;
        let connected = target.is_some();
        if let Some(target) = &mut target {
            assert_eq!(read_to_eof(target).await?, FIRST);
            bounded(target.shutdown()).await?;
            serving.finish().await?;
        }
        if start != end {
            continue;
        }
        assert_eq!(connected, accepted, "{method:?} timestamp offset {offset}");
        if !accepted {
            assert_eq!(result.unwrap_err().to_string(), "Shadowsocks握手失败");
            closed_without_response(&mut client, method).await?;
            no_target(&target_listener).await;
        }
        return Ok(());
    }
    Err(io::Error::other(
        "8 次尝试均跨 wall-second，未对时间边缘作断言",
    ))
}

#[tokio::test]
async fn aead2022_timestamp_plus_minus_30_is_inclusive_and_31_rejects_same_second() {
    run(async {
        for &method in &METHODS[3..] {
            for (offset, accepted) in [(-30, true), (30, true), (-31, false), (31, false)] {
                timestamp_edge(method, offset, accepted).await?;
            }
        }
        Ok(())
    })
    .await;
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> io::Result<&'a [u8]> {
    if input.len() < length {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let (head, tail) = input.split_at(length);
    *input = tail;
    Ok(head)
}

fn response(
    method: CipherKind,
    key: &[u8],
    request_salt: &[u8],
    wire: &[u8],
) -> io::Result<Vec<u8>> {
    let mut input = wire;
    let server_salt = take(&mut input, method.salt_len())?;
    assert_ne!(server_salt, request_salt, "回程必须生成独立 salt");
    let mut cipher = WireCipher::new(method, key, server_salt);
    let mut plain = Vec::new();
    if method.is_aead_2022() {
        let header = cipher.open(take(&mut input, 1 + 8 + method.salt_len() + 2 + 16)?)?;
        let mut fields = header.as_slice();
        assert_eq!(take(&mut fields, 1)?, [1], "response stream type");
        let remote_time = u64::from_be_bytes(take(&mut fields, 8)?.try_into().unwrap());
        assert!(timestamp().abs_diff(remote_time) <= 30, "响应 timestamp");
        assert_eq!(take(&mut fields, method.salt_len())?, request_salt);
        let length = u16::from_be_bytes(take(&mut fields, 2)?.try_into().unwrap());
        assert!(fields.is_empty());
        plain.extend(cipher.open(take(&mut input, usize::from(length) + 16)?)?);
    }
    while !input.is_empty() {
        let length = cipher.open(take(&mut input, 2 + 16)?)?;
        let length = u16::from_be_bytes(length.as_slice().try_into().unwrap());
        assert!(method.is_aead_2022() || length <= 0x3fff);
        plain.extend(cipher.open(take(&mut input, usize::from(length) + 16)?)?);
    }
    Ok(plain)
}

async fn read_to_eof(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bounded(stream.read_to_end(&mut bytes)).await?;
    Ok(bytes)
}

async fn no_target(listener: &TcpListener) {
    // 检查发生在所有相关服务 future 结束后；仍检查监听队列中没有遗留拨号。
    assert!(
        timeout(Duration::from_millis(40), listener.accept())
            .await
            .is_err(),
        "握手失败/重放不应触及目标 listener"
    );
}

async fn closed_without_response(client: &mut TcpStream, method: CipherKind) -> io::Result<()> {
    let mut byte = [0];
    let result = bounded(client.read(&mut byte)).await;
    if method.is_aead_2022() {
        let error = result.expect_err("2022 失败握手必须真实 RST，不能仅观察到 FIN/EOF");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        return Ok(());
    }
    match result {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(())
        }
        other => panic!("失败握手必须关闭且不能输出密文：{other:?}"),
    }
}

async fn roundtrip(method: CipherKind, client_closes_first: bool) -> io::Result<()> {
    let target_listener = listener().await?;
    let fixture = Fixture::new(method, 1_000, 1);
    let (mut client, server) = tcp_pair().await?;
    let mut request = Request::new(
        method,
        &fixture.prepared.keys.key,
        target_listener.local_addr()?,
    );
    // 2022 首固定头要求一次 read：在启动 serve future 前一次写入完整请求。
    bounded(client.write_all(&request.wire)).await?;
    let mut serving = fixture.start(server, None);
    let (mut target, peer) = bounded(target_listener.accept()).await?;
    assert!(peer.ip().is_loopback());
    assert_eq!(fixture.handshakes.available_permits(), 1);
    let mut first = vec![0; FIRST.len()];
    bounded(target.read_exact(&mut first)).await?;
    assert_eq!(first, FIRST, "{method:?} 的首载荷不能丢失/重复");

    let (uplink, downlink) = if client_closes_first {
        bounded(client.shutdown()).await?;
        assert!(read_to_eof(&mut target).await?.is_empty());
        // 目标观察到客户端 EOF 后才返回数据，证明不是全关闭。
        bounded(target.write_all(RESPONSE)).await?;
        bounded(target.write_all(TAIL)).await?;
        bounded(target.shutdown()).await?;
        let wire = read_to_eof(&mut client).await?;
        assert_eq!(
            response(method, &fixture.prepared.keys.key, &request.salt, &wire)?,
            [RESPONSE, TAIL].concat(),
            "{method:?} 的客户端写半关闭后回程"
        );
        (FIRST.len(), RESPONSE.len() + TAIL.len())
    } else {
        bounded(target.write_all(RESPONSE)).await?;
        bounded(target.shutdown()).await?;
        let wire = read_to_eof(&mut client).await?;
        assert_eq!(
            response(method, &fixture.prepared.keys.key, &request.salt, &wire)?,
            RESPONSE
        );
        // 客户端已观察到响应 EOF，仍可继续发送一个新 encrypted chunk。
        bounded(client.write_all(&request.chunk(TAIL))).await?;
        bounded(client.shutdown()).await?;
        assert_eq!(read_to_eof(&mut target).await?, TAIL);
        (FIRST.len() + TAIL.len(), RESPONSE.len())
    };
    serving.finish().await?;
    let stats = fixture.ctx.stats.snapshot();
    assert_eq!(stats.tcp_flows, 0);
    assert_eq!(stats.uplink, uplink as u64);
    assert_eq!(stats.downlink, downlink as u64);
    Ok(())
}

fn eih(method: CipherKind, identity: &[u8], user: &[u8], salt: &[u8]) -> [u8; 16] {
    use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
    let material = [identity, salt].concat();
    let subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
    let mut block = Block::<aes::Aes128>::try_from(&blake3::hash(user).as_bytes()[..16]).unwrap();
    match method {
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM => aes::Aes128::new_from_slice(&subkey[..16])
            .unwrap()
            .encrypt_block(&mut block),
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM => aes::Aes256::new_from_slice(&subkey)
            .unwrap()
            .encrypt_block(&mut block),
        _ => unreachable!(),
    }
    block.into()
}

#[tokio::test]
async fn independent_aes_eih_users_and_wrong_identity_or_unknown_user() {
    use shadowsocks::config::{ServerUser, ServerUserManager};
    run(async {
        for method in [METHODS[3], METHODS[4]] {
            let mut fixture = Fixture::new(method, 1000, 1);
            let mut users = ServerUserManager::new();
            for (index, byte) in [0x22, 0x33].into_iter().enumerate() {
                users.add_user(ServerUser::new(
                    format!("user{index}"),
                    vec![byte; method.key_len()],
                ));
            }
            Arc::get_mut(&mut fixture.prepared).unwrap().keys.users = Some(Arc::new(users));
            let target_listener = listener().await?;
            for (index, byte) in [0x22, 0x33].into_iter().enumerate() {
                let user = vec![byte; method.key_len()];
                let mut request = Request::new(method, &user, target_listener.local_addr()?);
                let identity = eih(method, &fixture.prepared.keys.key, &user, &request.salt);
                request
                    .wire
                    .splice(request.salt.len()..request.salt.len(), identity);
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&request.wire)).await?;
                let mut serving = fixture.start(server, None);
                let (mut target, _) = bounded(target_listener.accept()).await?;
                let mut payload = [0; FIRST.len()];
                bounded(target.read_exact(&mut payload)).await?;
                assert_eq!(payload, FIRST);
                bounded(client.shutdown()).await?;
                assert!(read_to_eof(&mut target).await?.is_empty());
                bounded(target.write_all(RESPONSE)).await?;
                bounded(target.shutdown()).await?;
                let reply = read_to_eof(&mut client).await?;
                assert_eq!(response(method, &user, &request.salt, &reply)?, RESPONSE);
                serving.finish().await?;
                // 相同salt在两个独立身份域均准入，且身份索引不合并。
                assert_eq!(
                    fixture.ctx.stats.snapshot().uplink,
                    ((index + 1) * FIRST.len()) as u64
                );
            }
            // 正确 EIH 指向已配置用户，不能让错误 uPSK 或坏 body tag 触及目标。
            for fault in 0..3 {
                let user = vec![0x22; method.key_len()];
                let wrong_key = vec![0x77; method.key_len()];
                let payload_key = if fault == 0 { &wrong_key } else { &user };
                let mut request = Request::new(method, payload_key, target_listener.local_addr()?);
                if fault == 1 {
                    // 固定头用正确 uPSK，只有 nonce=1 的 body 用错误 uPSK。
                    let wrong = Request::new(method, &wrong_key, target_listener.local_addr()?);
                    let body_start = method.salt_len() + 11 + 16;
                    request.wire[body_start..].copy_from_slice(&wrong.wire[body_start..]);
                } else if fault == 2 {
                    // 正确 EIH、正确固定头、正确 body 密文，仅末尾 tag 损坏。
                    *request.wire.last_mut().unwrap() ^= 1;
                }
                request.wire.splice(
                    request.salt.len()..request.salt.len(),
                    eih(method, &fixture.prepared.keys.key, &user, &request.salt),
                );
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&request.wire)).await?;
                let mut serving = fixture.start(server, None);
                let error = serving.finish().await.unwrap_err();
                assert_eq!(error.to_string(), "Shadowsocks握手失败");
                closed_without_response(&mut client, method).await?;
                no_target(&target_listener).await;
            }
            for wrong_identity in [true, false] {
                let user = vec![if wrong_identity { 0x22 } else { 0x44 }; method.key_len()];
                let mut request = Request::new(method, &user, target_listener.local_addr()?);
                let identity = if wrong_identity {
                    vec![0x55; method.key_len()]
                } else {
                    fixture.prepared.keys.key.clone()
                };
                request.wire.splice(
                    request.salt.len()..request.salt.len(),
                    eih(method, &identity, &user, &request.salt),
                );
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&request.wire)).await?;
                let mut serving = fixture.start(server, None);
                assert!(serving.finish().await.is_err());
                closed_without_response(&mut client, method).await?;
                no_target(&target_listener).await;
            }
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn six_methods_first_payload_2017_cross_chunk_address_and_client_half_close() {
    run(async {
        for method in METHODS {
            roundtrip(method, true).await?;
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn target_half_close_keeps_client_to_target_direction_open() {
    run(async {
        for method in METHODS {
            roundtrip(method, false).await?;
        }
        Ok(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_identical_salt_connects_to_exactly_one_target() {
    run(async {
        const COPIES: usize = 4;
        for method in [
            CipherKind::AES_128_GCM,
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
        ] {
            let target_listener = listener().await?;
            let fixture = Fixture::new(method, 1_000, COPIES);
            let request = Request::new(
                method,
                &fixture.prepared.keys.key,
                target_listener.local_addr()?,
            );
            let gate = Arc::new(Barrier::new(COPIES + 1));
            let mut clients = Vec::new();
            let mut tasks = Vec::new();
            for _ in 0..COPIES {
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&request.wire)).await?;
                bounded(client.shutdown()).await?;
                clients.push(client);
                tasks.push(fixture.start(server, Some(gate.clone())));
            }
            timeout(IO_LIMIT, gate.wait())
                .await
                .expect("重放竞争 barrier 超时");
            let (mut target, _) = bounded(target_listener.accept()).await?;
            assert_eq!(read_to_eof(&mut target).await?, FIRST);
            bounded(target.shutdown()).await?;
            let mut successes = 0;
            for task in &mut tasks {
                match task.finish().await {
                    Ok(()) => successes += 1,
                    Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
                }
            }
            assert_eq!(successes, 1, "{method:?} 全局重放准入必须只有一个赢家");
            assert_eq!(fixture.handshakes.available_permits(), COPIES);
            assert_eq!(fixture.ctx.stats.snapshot().uplink, FIRST.len() as u64);
            no_target(&target_listener).await;
            drop(clients);
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn wrong_key_and_corrupted_header_or_payload_tag_never_touch_target() {
    run(async {
        // 六种方法；payload tag 失败时固定头已经成功认证。
        for method in METHODS {
            for fault in 0..3 {
                let target_listener = listener().await?;
                let fixture = Fixture::new(method, 1_000, 1);
                let key = if fault == 0 {
                    vec![0x44; method.key_len()]
                } else {
                    fixture.prepared.keys.key.clone()
                };
                let mut request = Request::new(method, &key, target_listener.local_addr()?);
                if fault == 1 {
                    let header_length = if method.is_aead_2022() { 11 } else { 2 };
                    request.wire[method.salt_len() + header_length + 15] ^= 1;
                } else if fault == 2 {
                    // 2017 的首 chunk 只含 ATYP，损坏其 tag，确保握手本身失败。
                    let first_data_end = if method.is_aead_2022() {
                        request.wire.len()
                    } else {
                        method.salt_len() + 18 + 1 + 16
                    };
                    request.wire[first_data_end - 1] ^= 1;
                }
                let (mut client, server) = tcp_pair().await?;
                bounded(client.write_all(&request.wire)).await?;
                let mut serving = fixture.start(server, None);
                let error = serving.finish().await.unwrap_err();
                assert_ne!(
                    error.kind(),
                    io::ErrorKind::TimedOut,
                    "认证失败不能靠超时兜底"
                );
                assert_eq!(error.to_string(), "Shadowsocks握手失败");
                assert_eq!(fixture.handshakes.available_permits(), 1);
                closed_without_response(&mut client, method).await?;
                no_target(&target_listener).await;
                assert_eq!(fixture.ctx.stats.snapshot().uplink, 0);
            }
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn aead2022_short_first_read_is_rejected_without_waiting_for_more_or_dialing() {
    run(async {
        for method in &METHODS[3..] {
            let target_listener = listener().await?;
            let fixture = Fixture::new(*method, 1_000, 1);
            let request = Request::new(
                *method,
                &fixture.prepared.keys.key,
                target_listener.local_addr()?,
            );
            let (mut client, server) = tcp_pair().await?;
            // 只给一个字节，保持写半端开启，不用 EOF 或补发余包诱导失败。
            bounded(client.write_all(&request.wire[..1])).await?;
            let mut serving = fixture.start(server, None);
            let error = serving.finish().await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert_eq!(error.to_string(), "Shadowsocks握手失败");
            assert_eq!(fixture.handshakes.available_permits(), 1);
            closed_without_response(&mut client, *method).await?;
            no_target(&target_listener).await;
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn handshake_timeout_closes_socket_and_releases_permit_without_dialing() {
    run(async {
        for method in [
            CipherKind::AES_128_GCM,
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
        ] {
            let target_listener = listener().await?;
            let fixture = Fixture::new(method, 100, 1);
            let (mut client, server) = tcp_pair().await?;
            let permit = fixture.handshakes.clone().try_acquire_owned().unwrap();
            assert_eq!(fixture.handshakes.available_permits(), 0);
            let error = bounded(serve_tcp(
                server,
                fixture.prepared.clone(),
                fixture.ctx.clone(),
                "ss",
                crate::runtime::HandshakePermits::new(permit, None),
            ))
            .await
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), "Shadowsocks握手超时");
            assert_eq!(fixture.handshakes.available_permits(), 1);
            let reacquired = fixture.handshakes.clone().try_acquire_owned().unwrap();
            drop(reacquired);
            closed_without_response(&mut client, method).await?;
            no_target(&target_listener).await;
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn cancelling_a_polled_handshake_closes_socket_and_releases_permit() {
    run(async {
        for method in [
            CipherKind::AES_128_GCM,
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
        ] {
            let target_listener = listener().await?;
            let fixture = Fixture::new(method, 1_000, 1);
            let (mut client, server) = tcp_pair().await?;
            let permit = fixture.handshakes.clone().try_acquire_owned().unwrap();
            let mut serving = Box::pin(serve_tcp(
                server,
                fixture.prepared.clone(),
                fixture.ctx.clone(),
                "ss",
                crate::runtime::HandshakePermits::new(permit, None),
            ));
            // 确定已经进入握手并读到 Pending，而不是只取消一个未运行的任务。
            poll_fn(|cx| {
                assert!(serving.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(fixture.handshakes.available_permits(), 0);
            drop(serving);
            assert_eq!(fixture.handshakes.available_permits(), 1);
            let reacquired = fixture.handshakes.clone().try_acquire_owned().unwrap();
            drop(reacquired);
            closed_without_response(&mut client, method).await?;
            no_target(&target_listener).await;
        }
        Ok(())
    })
    .await;
}
