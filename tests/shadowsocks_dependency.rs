//! 任务1.4的本地依赖适配探针，不是独立wire测试或官方客户端互通证据。
//!
//! socket全部由本测试bind/accept/connect；仅连接本测试刚bind的回环入口。
//! SOCKS目标只是地址元数据，不解析、不拨号。没有spawn任务，超时即析构整个测试future。
//!
//! 最初两个characterization测试曾复现上游接受padding>900和跨chunk变量头；
//! 经用户确认的最小协议补丁后，末尾测试要求明确拒绝，并保留合法边界对照。
//! 密码库没有公开nonce耗尽接口；协议层预算的近边界保护由vendor内独立单元测试验证。
//! 此处不通过unsafe访问私有状态，也不假称有限调用走完了2^96个nonce。

use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use shadowsocks::{
    config::{ReplayAttackPolicy, ServerConfig, ServerType, ServerUser, ServerUserManager},
    context::{Context, SharedContext},
    crypto::{CipherKind, v1::Cipher, v2::tcp::TcpCipher},
    relay::{
        socks5::Address,
        tcprelay::{ProxyClientStream, ProxyServerStream},
        udprelay::{
            crypto_io::{
                decrypt_client_payload, decrypt_server_payload, encrypt_client_payload,
                encrypt_server_payload,
            },
            options::UdpSocketControlData,
        },
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(15);
const FIRST: &[u8] = b"first payload must survive handshake";
const RESPONSE: &[u8] = b"first response with request salt binding";
const TAIL: &[u8] = b"data after peer write-half EOF";
const METHODS: [CipherKind; 6] = [
    CipherKind::AES_128_GCM,
    CipherKind::AES_256_GCM,
    CipherKind::CHACHA20_POLY1305,
    CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
    CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
];

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

fn context(kind: ServerType) -> SharedContext {
    let mut context = Context::new(kind);
    context.set_replay_attack_policy(ReplayAttackPolicy::Ignore);
    Arc::new(context)
}

async fn bounded(future: impl Future<Output = io::Result<()>>) {
    timeout(LIMIT, future)
        .await
        .expect("本地依赖适配探针超时；future及其中的socket已取消/析构")
        .expect("本地依赖适配探针失败");
}

async fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind(loopback()).await?;
    let addr = listener.local_addr()?;
    assert!(addr.ip().is_loopback());
    let client = TcpStream::connect(addr).await?;
    let (server, peer) = listener.accept().await?;
    assert!(peer.ip().is_loopback());
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    Ok((client, server))
}

// 只保留最多32字节salt，绝不保存无限密文历史。
#[derive(Default)]
struct Prefix {
    bytes: [u8; 32],
    len: usize,
    wanted: usize,
}

impl Prefix {
    fn new(wanted: usize) -> Self {
        assert!(wanted <= 32);
        Self {
            wanted,
            ..Self::default()
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.wanted - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

struct Observe<S> {
    inner: S,
    received: Prefix,
    sent: Prefix,
    read_polls: usize,
    read_ready: usize,
    first_read: Option<(usize, usize)>,
    first_write: Option<(usize, usize)>,
}

impl<S> Observe<S> {
    fn new(inner: S, salt_len: usize) -> Self {
        Self {
            inner,
            received: Prefix::new(salt_len),
            sent: Prefix::new(salt_len),
            read_polls: 0,
            read_ready: 0,
            first_read: None,
            first_write: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Observe<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let requested = buf.remaining();
        this.read_polls += 1;
        // 同一个ReadBuf、恰好一次底层调用，不预读、不缩短、不补齐、不拆分。
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let newly_read = &buf.filled()[before..];
            this.read_ready += 1;
            this.first_read.get_or_insert((requested, newly_read.len()));
            this.received.observe(newly_read);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Observe<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            this.first_write.get_or_insert((buf.len(), n));
            this.sent.observe(&buf[..n]);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

struct Fixture {
    server: ServerConfig,
    client: ServerConfig,
    expected_user: Option<&'static str>,
}

fn fixtures(method: CipherKind, eih: bool) -> Vec<Fixture> {
    let make_config = |password: String| ServerConfig::new(loopback(), password, method).unwrap();
    if !eih {
        let password = if method.is_aead_2022() {
            ServerUser::new("single-test-key", vec![0x11; method.key_len()]).encoded_key()
        } else {
            "dependency-adapter-test-only".to_owned()
        };
        return vec![Fixture {
            server: make_config(password.clone()),
            client: make_config(password),
            expected_user: None,
        }];
    }

    let identity = ServerUser::new("identity-test-key", vec![0x11; method.key_len()]);
    let users = [
        ServerUser::new("alice", vec![0x22; method.key_len()]),
        ServerUser::new("bob", vec![0x33; method.key_len()]),
    ];
    let mut manager = ServerUserManager::new();
    for user in &users {
        manager.add_user(user.clone());
    }
    assert_eq!(manager.user_count(), 2);
    users
        .iter()
        .zip(["alice", "bob"])
        .map(|(user, name)| {
            let mut server = make_config(identity.encoded_key());
            server.set_user_manager(manager.clone());
            Fixture {
                server,
                client: make_config(format!("{}:{}", identity.encoded_key(), user.encoded_key())),
                expected_user: Some(name),
            }
        })
        .collect()
}

fn header_len(fixture: &Fixture) -> usize {
    fixture.server.method().salt_len()
        + usize::from(fixture.expected_user.is_some()) * 16
        + 1
        + 8
        + 2
        + fixture.server.method().tag_len()
}

fn check_tcp_user<S>(stream: &ProxyServerStream<S>, fixture: &Fixture) {
    if fixture.expected_user.is_some() {
        assert!(stream.user_key() == Some(fixture.client.key()));
    } else {
        assert!(stream.user_key().is_none());
    }
}

async fn tcp_roundtrip(fixture: &Fixture, client_closes_first: bool) -> io::Result<()> {
    let method = fixture.server.method();
    let (client_socket, server_socket) = tcp_pair().await?;
    // 已持有的本地入口地址仅作为目标元数据，绝不对该目标再次拨号。
    let target = Address::SocketAddress(server_socket.local_addr()?);
    let mut client = ProxyClientStream::from_stream(
        context(ServerType::Local),
        Observe::new(client_socket, method.salt_len()),
        &fixture.client,
        target.clone(),
    );
    let mut server = ProxyServerStream::from_stream_with_user_manager(
        context(ServerType::Server),
        Observe::new(server_socket, method.salt_len()),
        method,
        fixture.server.key(),
        fixture.server.clone_user_manager(),
    );
    assert!(server.user_key().is_none());
    client.write_all(FIRST).await?;
    assert_eq!(server.handshake().await?, target);
    check_tcp_user(&server, fixture);
    assert_eq!(
        server.get_ref().received.as_slice(),
        client.get_ref().sent.as_slice()
    );
    assert_eq!(server.get_ref().received.len, method.salt_len());
    if method.is_aead_2022() {
        let expected = header_len(fixture);
        assert_eq!(server.get_ref().first_read, Some((expected, expected)));
        assert!(client.get_ref().first_write.unwrap().0 > expected);
    }

    let mut first = vec![0; FIRST.len()];
    server.read_exact(&mut first).await?;
    assert_eq!(first, FIRST);
    server.write_all(RESPONSE).await?;
    let mut response = vec![0; RESPONSE.len()];
    // 2022的ProxyClientStream同时校验响应中的请求salt绑定。
    client.read_exact(&mut response).await?;
    assert_eq!(response, RESPONSE);
    assert_eq!(
        client.get_ref().received.as_slice(),
        server.get_ref().sent.as_slice()
    );
    if method.is_aead_2022() {
        let expected = method.salt_len() * 2 + 1 + 8 + 2 + method.tag_len();
        assert_eq!(client.get_ref().first_read, Some((expected, expected)));
        assert!(server.get_ref().first_write.unwrap().0 > expected);
    }

    let mut eof = [0; 1];
    let mut tail = vec![0; TAIL.len()];
    if client_closes_first {
        client.shutdown().await?;
        assert_eq!(server.read(&mut eof).await?, 0);
        server.write_all(TAIL).await?;
        server.shutdown().await?;
        client.read_exact(&mut tail).await?;
        assert_eq!(client.read(&mut eof).await?, 0);
    } else {
        server.shutdown().await?;
        assert_eq!(client.read(&mut eof).await?, 0);
        client.write_all(TAIL).await?;
        client.shutdown().await?;
        server.read_exact(&mut tail).await?;
        assert_eq!(server.read(&mut eof).await?, 0);
    }
    assert_eq!(tail, TAIL);
    Ok(())
}

async fn udp_roundtrip(fixture: &Fixture) -> io::Result<()> {
    let method = fixture.server.method();
    // 测试拥有TCP和同端口UDP监听，不调用库listener/ProxySocket/resolver。
    let tcp_owner = TcpListener::bind(loopback()).await?;
    let server = UdpSocket::bind(tcp_owner.local_addr()?).await?;
    let client = UdpSocket::bind(loopback()).await?;
    let target = Address::SocketAddress(server.local_addr()?);
    let server_context = context(ServerType::Server);
    let client_context = context(ServerType::Local);
    let mut input = UdpSocketControlData::default();
    input.client_session_id = 0x0102_0304_0506_0708;
    // 在两个EIH用户中故意复用client SID，确认返回的认证身份不是源地址推断。
    for (packet_id, payload) in [FIRST, &[]].into_iter().enumerate() {
        input.packet_id = packet_id as u64;
        let mut wire = Default::default();
        encrypt_client_payload(
            &client_context,
            method,
            fixture.client.key(),
            &target,
            &input,
            fixture.client.identity_keys(),
            payload,
            &mut wire,
        );
        assert!(wire.len() <= 65_507);
        assert_eq!(
            client.send_to(&wire, server.local_addr()?).await?,
            wire.len()
        );
        let mut buffer = [0; 65_536];
        let (n, source) = server.recv_from(&mut buffer).await?;
        assert_eq!(source, client.local_addr()?);
        assert_eq!(n, wire.len());
        let mut damaged = buffer[..n].to_vec();
        damaged[n - 1] ^= 1;
        assert!(
            decrypt_client_payload(
                &server_context,
                method,
                fixture.server.key(),
                &mut damaged,
                fixture.server.user_manager(),
            )
            .is_err()
        );
        let (plain_len, addr, authenticated) = decrypt_client_payload(
            &server_context,
            method,
            fixture.server.key(),
            &mut buffer[..n],
            fixture.server.user_manager(),
        )
        .map_err(io::Error::other)?;
        assert_eq!(addr, target);
        assert_eq!(&buffer[..plain_len], payload);

        let mut reply = UdpSocketControlData::default();
        let reply_key = if method.is_aead_2022() {
            let authenticated = authenticated.expect("2022必须暴露control");
            assert_eq!(authenticated.client_session_id, input.client_session_id);
            assert_eq!(authenticated.server_session_id, 0);
            assert_eq!(authenticated.packet_id, input.packet_id);
            if let Some(name) = fixture.expected_user {
                let user = authenticated.user.as_ref().expect("EIH必须暴露已认证用户");
                assert_eq!(user.name(), name);
                assert!(user.key() == fixture.client.key());
            } else {
                assert!(authenticated.user.is_none());
            }
            // 不反射入站control：服务端SID/counter独立，client SID显式绑定。
            reply.client_session_id = authenticated.client_session_id;
            reply.server_session_id = 0x8877_6655_4433_2211;
            reply.packet_id = 40 + packet_id as u64;
            reply.user = authenticated.user;
            // 低层encrypt_server_payload不因control.user自动切换密钥。
            fixture.client.key()
        } else {
            assert!(authenticated.is_none());
            fixture.server.key()
        };
        let mut response = Default::default();
        encrypt_server_payload(
            &server_context,
            method,
            reply_key,
            &target,
            &reply,
            payload,
            &mut response,
        );
        assert_eq!(server.send_to(&response, source).await?, response.len());
        let (n, source) = client.recv_from(&mut buffer).await?;
        assert_eq!(source, server.local_addr()?);
        let (plain_len, addr, control) = decrypt_server_payload(
            &client_context,
            method,
            fixture.client.key(),
            &mut buffer[..n],
        )
        .map_err(io::Error::other)?;
        assert_eq!(addr, target);
        assert_eq!(&buffer[..plain_len], payload);
        if method.is_aead_2022() {
            let control = control.expect("2022响应必须暴露control");
            assert_eq!(control.client_session_id, input.client_session_id);
            assert_eq!(control.server_session_id, reply.server_session_id);
            assert_ne!(control.server_session_id, control.client_session_id);
            assert_eq!(control.packet_id, reply.packet_id);
            assert!(control.user.is_none());
        } else {
            assert!(control.is_none());
        }
        if fixture.expected_user.is_some() {
            let mut wrong_key_response = Default::default();
            encrypt_server_payload(
                &server_context,
                method,
                fixture.server.key(), // iPSK，故意不使用uPSK；user字段不能修正它。
                &target,
                &reply,
                payload,
                &mut wrong_key_response,
            );
            assert!(
                decrypt_server_payload(
                    &client_context,
                    method,
                    fixture.client.key(),
                    &mut wrong_key_response,
                )
                .is_err()
            );
        }
    }
    Ok(())
}

macro_rules! dependency_case {
    ($name:ident, $method:expr, $eih:expr) => {
        mod $name {
            use super::*;

            #[tokio::test]
            async fn tcp_public_api_and_both_half_closes() {
                bounded(async {
                    for fixture in fixtures($method, $eih) {
                        tcp_roundtrip(&fixture, true).await?;
                        tcp_roundtrip(&fixture, false).await?;
                    }
                    Ok(())
                })
                .await;
            }

            #[tokio::test]
            async fn udp_public_api_and_authenticated_control() {
                bounded(async {
                    for fixture in fixtures($method, $eih) {
                        udp_roundtrip(&fixture).await?;
                    }
                    Ok(())
                })
                .await;
            }
        }
    };
}

dependency_case!(aes_128_gcm, CipherKind::AES_128_GCM, false);
dependency_case!(aes_256_gcm, CipherKind::AES_256_GCM, false);
dependency_case!(chacha20_ietf_poly1305, CipherKind::CHACHA20_POLY1305, false);
dependency_case!(
    aead2022_aes_128,
    CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    false
);
dependency_case!(
    aead2022_aes_256,
    CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
    false
);
dependency_case!(
    aead2022_chacha20,
    CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
    false
);
dependency_case!(
    aead2022_aes_128_eih_two_users,
    CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    true
);
dependency_case!(
    aead2022_aes_256_eih_two_users,
    CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
    true
);

async fn captured_request(fixture: &Fixture) -> io::Result<Vec<u8>> {
    let (client, mut raw_server) = tcp_pair().await?;
    let target = Address::SocketAddress(raw_server.local_addr()?);
    let mut client =
        ProxyClientStream::from_stream(context(ServerType::Local), client, &fixture.client, target);
    client.write_all(FIRST).await?;
    client.shutdown().await?;
    let mut wire = Vec::new();
    raw_server.read_to_end(&mut wire).await?;
    Ok(wire)
}

// 不启动转发或目标任务。返回时两个socket与协议流已析构。
async fn raw_handshake(
    fixture: &Fixture,
    shared: SharedContext,
    wire: &[u8],
) -> io::Result<Address> {
    let (mut client, server) = tcp_pair().await?;
    client.write_all(wire).await?;
    client.shutdown().await?;
    let mut server = ProxyServerStream::from_stream_with_user_manager(
        shared,
        Observe::new(server, fixture.server.method().salt_len()),
        fixture.server.method(),
        fixture.server.key(),
        fixture.server.clone_user_manager(),
    );
    let result = server.handshake().await;
    if result.is_ok() {
        assert_eq!(
            server.get_ref().received.as_slice(),
            &wire[..fixture.server.method().salt_len()]
        );
        let mut payload = Vec::new();
        server.read_to_end(&mut payload).await?;
        assert_eq!(payload, FIRST);
    }
    result
}

#[tokio::test]
async fn aead2022_short_first_read_is_rejected_without_filling_the_header() {
    bounded(async {
        for method in &METHODS[3..] {
            let eih_modes: &[bool] = if *method == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 {
                &[false]
            } else {
                &[false, true]
            };
            for &eih in eih_modes {
                for fixture in fixtures(*method, eih) {
                    let wire = captured_request(&fixture).await?;
                    let (mut client, server) = tcp_pair().await?;
                    // 余下报文故意不发送，不能靠EOF或read_exact补齐制造失败。
                    client.write_all(&wire[..1]).await?;
                    let mut server = ProxyServerStream::from_stream_with_user_manager(
                        context(ServerType::Server),
                        Observe::new(server, method.salt_len()),
                        *method,
                        fixture.server.key(),
                        fixture.server.clone_user_manager(),
                    );
                    let error = server.handshake().await.unwrap_err();
                    assert_eq!(
                        error.to_string(),
                        format!(
                            "header too short, expecting {} bytes, but found 1 bytes",
                            header_len(&fixture)
                        )
                    );
                    assert_eq!(server.get_ref().read_ready, 1);
                    assert_eq!(server.get_ref().first_read, Some((header_len(&fixture), 1)));
                    assert_eq!(server.get_ref().received.as_slice(), &wire[..1]);
                    assert!(server.get_ref().first_write.is_none());
                }
            }
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn identical_salt_is_local_to_each_connection_context() {
    bounded(async {
        for method in METHODS {
            let fixture = fixtures(method, false).remove(0);
            let wire = captured_request(&fixture).await?;
            let shared = context(ServerType::Server);
            assert_eq!(shared.replay_attack_policy(), ReplayAttackPolicy::Ignore);
            let first = raw_handshake(&fixture, shared.clone(), &wire).await?;
            let duplicate = raw_handshake(&fixture, shared, &wire).await;
            if method.is_aead_2022() {
                assert_eq!(
                    duplicate.unwrap_err().to_string(),
                    "detected repeated nonce (iv/salt)"
                );
            } else {
                assert_eq!(duplicate?, first);
            }
            // 有限的两条独立连接；不声称测量了不可公开访问的内部池项数。
            for _ in 0..2 {
                let independent = context(ServerType::Server);
                let weak = Arc::downgrade(&independent);
                assert_eq!(raw_handshake(&fixture, independent, &wire).await?, first);
                assert!(weak.upgrade().is_none(), "连接结束必须释放独立Context");
            }
        }
        // 源码依据：Context::check_nonce_replay强制2022 Reject；ReplayProtector
        // 使用60秒精确池、无容量API。TCP DecryptedReader::poll_read_header仅首头
        // 调用一次check；后续chunk不调用。独立Context因此最多承受本连接一次入站
        // salt检查，而非全局输入量。该结论是源码推导，不是池计数/RSS实测。
        Ok(())
    })
    .await;
}

struct ScriptedIo {
    reads: VecDeque<Option<Vec<u8>>>,
    read_requests: Vec<usize>,
    writes: VecDeque<Option<usize>>,
    write_requests: Vec<usize>,
    written: Vec<u8>,
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_requests.push(buf.remaining());
        match self.reads.pop_front().expect("不允许观察器增加read") {
            None => Poll::Pending,
            Some(data) => {
                assert!(data.len() <= buf.remaining());
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_requests.push(buf.len());
        match self.writes.pop_front().expect("不允许观察器增加write") {
            None => Poll::Pending,
            Some(n) => {
                self.written.extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn salt_observer_preserves_pending_read_buffers_and_partial_writes() {
    let inner = ScriptedIo {
        reads: [None, Some(vec![1; 3]), Some(vec![2; 9]), Some(vec![3; 20])].into(),
        read_requests: Vec::new(),
        writes: [None, Some(3), Some(17)].into(),
        write_requests: Vec::new(),
        written: Vec::new(),
    };
    let mut stream = Observe::new(inner, 16);
    let mut task = TaskContext::from_waker(Waker::noop());
    for expected in [None, Some(3), Some(9), Some(20)] {
        let mut storage = [0; 64];
        let mut buffer = ReadBuf::new(&mut storage);
        buffer.put_slice(b"prefix");
        let result = Pin::new(&mut stream).poll_read(&mut task, &mut buffer);
        match expected {
            None => assert!(result.is_pending()),
            Some(n) => {
                assert!(matches!(result, Poll::Ready(Ok(()))));
                assert_eq!(buffer.filled().len(), 6 + n);
            }
        }
    }
    assert_eq!(stream.inner.read_requests, [58; 4]);
    assert_eq!(stream.read_polls, 4);
    assert_eq!(stream.read_ready, 3);
    assert_eq!(
        stream.received.as_slice(),
        [vec![1; 3], vec![2; 9], vec![3; 4]].concat()
    );
    let data = [7; 20];
    assert!(
        Pin::new(&mut stream)
            .poll_write(&mut task, &data)
            .is_pending()
    );
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut task, &data),
        Poll::Ready(Ok(3))
    ));
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut task, &data[3..]),
        Poll::Ready(Ok(17))
    ));
    assert_eq!(stream.inner.write_requests, [20, 20, 17]);
    assert_eq!(stream.inner.written, data);
    assert_eq!(stream.sent.as_slice(), &[7; 16]);
}

#[tokio::test]
async fn aead2017_authenticated_length_rejects_reserved_high_bits() {
    bounded(async {
        for &method in &METHODS[..3] {
            let fixture = fixtures(method, false).remove(0);
            for length in [0x4000_u16, 0x8000, 0xc000, 0xffff] {
                let salt = vec![0x55; method.salt_len()];
                let mut cipher = Cipher::new(method, fixture.client.key(), &salt);
                let mut encrypted_length = length.to_be_bytes().to_vec();
                encrypted_length.resize(2 + method.tag_len(), 0);
                cipher.encrypt_packet(&mut encrypted_length);
                let wire = [salt, encrypted_length].concat();
                let error = raw_handshake(&fixture, context(ServerType::Server), &wire)
                    .await
                    .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("higher two bits must be set to zero")
                );
            }
        }
        Ok(())
    })
    .await;
}

// 手工封装只用于探测依赖边界；AEAD/KDF仍完全交给公开的成熟密码接口。
// 这不是独立wire/完整规范认证测试。调用者每次创建新的连接Context。
fn aead2022_request(fixture: &Fixture, chunks: &[Vec<u8>]) -> Vec<u8> {
    let method = fixture.server.method();
    assert!(method.is_aead_2022());
    assert!(fixture.expected_user.is_none());
    assert!(!chunks.is_empty());
    let salt = vec![0x66; method.salt_len()];
    let mut cipher = TcpCipher::new(method, fixture.client.key(), &salt);
    let mut wire = salt;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (index, chunk) in chunks.iter().enumerate() {
        let mut header = Vec::new();
        if index == 0 {
            header.push(0); // 客户端方向
            header.extend_from_slice(&timestamp.to_be_bytes());
        }
        header.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_be_bytes());
        header.resize(header.len() + method.tag_len(), 0);
        cipher.encrypt_packet(&mut header);
        wire.extend_from_slice(&header);
        let mut data = chunk.clone();
        data.resize(data.len() + method.tag_len(), 0);
        cipher.encrypt_packet(&mut data);
        wire.extend_from_slice(&data);
    }
    wire
}

fn variable_header(padding: u16) -> (Address, Vec<u8>) {
    let target = Address::SocketAddress((Ipv4Addr::LOCALHOST, 9).into());
    let mut variable = Vec::new();
    target.write_to_buf(&mut variable);
    variable.extend_from_slice(&padding.to_be_bytes());
    variable.resize(variable.len() + usize::from(padding), 0);
    variable.extend_from_slice(FIRST);
    (target, variable)
}

#[tokio::test]
async fn aead2022_padding_accepts_900_and_rejects_901_or_truncation() {
    bounded(async {
        for &method in &METHODS[3..] {
            let fixture = fixtures(method, false).remove(0);
            let (target, variable) = variable_header(900);
            let wire = aead2022_request(&fixture, &[variable]);
            assert_eq!(
                raw_handshake(&fixture, context(ServerType::Server), &wire).await?,
                target
            );
            for padding in [901, u16::MAX] {
                let (_, mut variable) = variable_header(padding);
                // 上限检查应在消费padding前发生，无需发送宣称的超大填充。
                variable.truncate(target.serialized_len() + 2);
                let wire = aead2022_request(&fixture, &[variable]);
                let error = raw_handshake(&fixture, context(ServerType::Server), &wire)
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(error.to_string().contains("padding exceeds 900"));
            }
            let (_, mut truncated) = variable_header(1);
            truncated.truncate(target.serialized_len() + 2);
            let wire = aead2022_request(&fixture, &[truncated]);
            assert!(
                raw_handshake(&fixture, context(ServerType::Server), &wire)
                    .await
                    .is_err()
            );
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn aead2022_rejects_variable_header_crossing_first_authenticated_chunk() {
    bounded(async {
        for &method in &METHODS[3..] {
            let fixture = fixtures(method, false).remove(0);
            for padding in [0, 1, 900] {
                let (target, variable) = variable_header(padding);
                // 在ATYP、padding长度中间、padding中间分别切开。
                let mut splits = vec![1, target.serialized_len() + 1];
                if padding > 0 {
                    splits.push(target.serialized_len() + 2);
                }
                for split in splits {
                    let chunks = [variable[..split].to_vec(), variable[split..].to_vec()];
                    let wire = aead2022_request(&fixture, &chunks);
                    let error = raw_handshake(&fixture, context(ServerType::Server), &wire)
                        .await
                        .unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    assert!(
                        error
                            .to_string()
                            .contains("variable header crosses first data chunk")
                    );
                }
            }
        }
        Ok(())
    })
    .await;
}
