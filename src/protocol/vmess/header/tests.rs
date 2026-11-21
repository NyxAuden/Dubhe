use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
};

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, Payload},
};
use md5::{Digest, Md5};
use tokio::io::ReadBuf;

use super::*;

const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const OTHER_UUID: &str = "f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f";
const KEY: [u8; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const IV: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn prepared(pool: Arc<ReplayPool>, policy: Policy) -> Prepared {
    Prepared::new(
        &[VmessUser {
            name: "alice".into(),
            uuid: UUID.into(),
        }],
        pool,
        policy,
    )
    .unwrap()
}

fn fresh(policy: Policy) -> Prepared {
    prepared(Arc::new(ReplayPool::new(64)), policy)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn checksum(data: &[u8]) -> [u8; 4] {
    let mut value = 2166136261u32;
    for byte in data {
        value ^= u32::from(*byte);
        value = value.wrapping_mul(16777619);
    }
    value.to_be_bytes()
}

fn finish(mut header: Vec<u8>) -> Vec<u8> {
    header.extend(checksum(&header));
    header
}

fn target(domain: &str, port: u16) -> Vec<u8> {
    let mut out = port.to_be_bytes().to_vec();
    out.extend([2, u8::try_from(domain.len()).unwrap()]);
    out.extend(domain.as_bytes());
    out
}

fn inner(command: u8, security: u8, options: u8, address: &[u8], padding: u8) -> Vec<u8> {
    let mut header = vec![1];
    header.extend(IV);
    header.extend(KEY);
    header.extend([0x7f, options, padding << 4 | security, 0, command]);
    header.extend(address);
    header.extend(std::iter::repeat_n(0xab, usize::from(padding)));
    finish(header)
}

fn tcp_inner() -> Vec<u8> {
    inner(1, 3, 5, &target("example.com", 443), 0)
}

// 测试端直接调用成熟AES/GCM/MD5 API，不调用生产AuthID、Cipher或请求编码。
// 动态测试派生复用已由下方Python固定整头金样独立校验的KDF接口。
fn client_wire(
    uuid: &str,
    timestamp: u64,
    random: u32,
    header: &[u8],
    length: Option<u16>,
) -> Vec<u8> {
    let uuid = parse_uuid(uuid).unwrap();
    let command: [u8; 16] =
        Md5::digest([uuid.as_slice(), b"c48619fe-8f02-49e0-b9e9-edf763e17e21"].concat()).into();
    let auth_key = crypto::kdf16(&command, &[b"AES Auth ID Encryption"]);
    let mut auth = [0; 16];
    auth[..8].copy_from_slice(&timestamp.to_be_bytes());
    auth[8..12].copy_from_slice(&random.to_be_bytes());
    let crc = crc32fast::hash(&auth[..12]);
    auth[12..].copy_from_slice(&crc.to_be_bytes());
    let mut block = auth.into();
    aes::Aes128::new((&auth_key).into()).encrypt_block(&mut block);
    let auth: [u8; 16] = block.into();
    let connection = [1, 35, 69, 103, 137, 171, 205, 239];
    let seal = |key_label: &[u8], nonce_label: &[u8], plain: &[u8]| {
        let key = crypto::kdf16(&command, &[key_label, &auth, &connection]);
        let nonce: [u8; 12] = crypto::kdf(&command, &[nonce_label, &auth, &connection])[..12]
            .try_into()
            .unwrap();
        Aes128Gcm::new((&key).into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plain,
                    aad: &auth,
                },
            )
            .unwrap()
    };
    let mut out = auth.to_vec();
    out.extend(seal(
        b"VMess Header AEAD Key_Length",
        b"VMess Header AEAD Nonce_Length",
        &length.unwrap_or(header.len() as u16).to_be_bytes(),
    ));
    out.extend(connection);
    out.extend(seal(
        b"VMess Header AEAD Key",
        b"VMess Header AEAD Nonce",
        header,
    ));
    out
}

struct Wire {
    input: Vec<u8>,
    offset: usize,
    chunk: usize,
    pending: bool,
    alternate: bool,
    hold_end: bool,
    output: Vec<u8>,
    flushes: usize,
    fail_at: Option<usize>,
    fail_flush: bool,
}
impl Wire {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            offset: 0,
            chunk: usize::MAX,
            pending: false,
            alternate: false,
            hold_end: false,
            output: vec![],
            flushes: 0,
            fail_at: None,
            fail_flush: false,
        }
    }
    fn fragmented(mut self) -> Self {
        self.chunk = 1;
        self.alternate = true;
        self
    }
}
impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.hold_end && self.offset == self.input.len() {
            return Poll::Pending;
        }
        let size = out
            .remaining()
            .min(self.chunk)
            .min(self.input.len() - self.offset);
        out.put_slice(&self.input[self.offset..self.offset + size]);
        self.offset += size;
        self.pending = self.alternate;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Wire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.fail_at.is_some_and(|n| self.output.len() >= n) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "测试写失败")));
        }
        let size = data.len().min(self.chunk);
        self.output.extend_from_slice(&data[..size]);
        self.pending = self.alternate;
        Poll::Ready(Ok(size))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.flushes += 1;
        Poll::Ready(if self.fail_flush {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "测试flush失败"))
        } else {
            Ok(())
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn independent_python_whole_header_and_response_vectors() {
    // 2026-11-05，Python3标准hashlib/hmac/zlib + 已安装cryptography AES/ECB/AESGCM。
    // 每层factory=lambda data: hmac.new(label,data,digestmod=previous_factory)，无生产codec参与。
    // UUID如上，timestamp=1700000000，random=aabbccdd，connection=0123456789abcdef；
    // IV=00..0f/key=10..1f/auth=7f/options=05/security=3/padding=deadbe/目标example.com:443。
    let wire = hex(
        "38fd21379a6e1c79f89c4b53cb4c2ae3dcc50fdeecab71bdf3bb7031d05d01a698860123456789abcdef36d231601c2682e72af29e7dac9c396514d1e7c5d95c7a6fffcfb0ed4d8e32576fbc4ca3e53e80b499b41b30d08050b85db56fe4d27c286696a854602b45fa22f2fbac3051fda1c8f098d111",
    );
    let expected = hex(
        "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f7f0533000101bb020b6578616d706c652e636f6ddeadbe6952318b",
    );
    let prepared = fresh(Policy::default());
    let id = wire[..16].try_into().unwrap();
    let (user, timestamp) = prepared.identify(&id, 1700000000).unwrap();
    assert_eq!(timestamp, 1700000000);
    let connection = wire[34..42].try_into().unwrap();
    assert_eq!(
        open_request(&user.command_key, &id, &connection, true, &wire[16..34]).unwrap(),
        (expected.len() as u16).to_be_bytes()
    );
    assert_eq!(
        open_request(&user.command_key, &id, &connection, false, &wire[42..]).unwrap(),
        expected
    );
    let mut accepted = parse_header(&expected, Policy::default(), false).unwrap();
    assert_eq!(accepted.key, KEY);
    assert_eq!(accepted.iv, IV);
    assert_eq!(
        accepted.mode,
        Mode::Tcp(Target {
            host: Host::Domain("example.com".into()),
            port: 443
        })
    );
    assert_eq!(
        crypto::derive_response(&KEY).as_slice(),
        hex("fc2e2c73072bfa2bda03ff9307472deb")
    );
    assert_eq!(
        crypto::derive_response(&IV).as_slice(),
        hex("be45cb2605bf36bebde684841a28f0fd")
    );
    let mut output = Wire::new(vec![]).fragmented();
    accepted.reply(&mut output).await.unwrap();
    accepted.reply(&mut output).await.unwrap();
    assert_eq!(
        output.output,
        hex("9bdfb1639712b6a6348d0087b8d1af379ecf4dafb5eb5155d93b122be59d3650d9493bd89611")
    );
    assert_eq!(output.flushes, 1);
}

#[tokio::test]
async fn fragmented_and_coalesced_requests_preserve_first_body_and_send_no_early_reply() {
    for fragmented in [false, true] {
        let prepared = fresh(Policy::default());
        let mut data = client_wire(UUID, now(), 1, &tcp_inner(), None);
        data.extend(b"\0first\xffpayload");
        let mut wire = Wire::new(data);
        if fragmented {
            wire = wire.fragmented();
        }
        let accepted = prepared.handshake(&mut wire, false).await.unwrap();
        assert_eq!(accepted.user, "alice");
        assert_eq!((accepted.security, accepted.options), (3, 5));
        assert_eq!(accepted.key, KEY);
        assert_eq!(accepted.iv, IV);
        assert_eq!(&wire.input[wire.offset..], b"\0first\xffpayload");
        assert!(wire.output.is_empty());
        assert_eq!(wire.flushes, 0);
    }
}

#[tokio::test]
async fn every_header_truncation_fails_without_response() {
    let data = client_wire(UUID, now(), 1, &tcp_inner(), None);
    for end in 0..data.len() {
        let mut wire = Wire::new(data[..end].to_vec()).fragmented();
        assert!(
            fresh(Policy::default())
                .handshake(&mut wire, false)
                .await
                .is_err(),
            "截断 {end}"
        );
        assert!(wire.output.is_empty());
    }
}

#[tokio::test]
async fn encrypted_length_is_bounded_before_body_read() {
    for length in [0, 1, 41, 317, 65535] {
        let mut wire = Wire::new(client_wire(UUID, now(), 1, &tcp_inner(), Some(length)));
        assert!(
            fresh(Policy::default())
                .handshake(&mut wire, false)
                .await
                .is_err()
        );
        assert_eq!(wire.offset, 42, "长度 {length}");
        assert!(wire.output.is_empty());
    }
    let domain = "a".repeat(255);
    let data = inner(1, 3, 13, &target(&domain, 443), 15);
    assert_eq!(data.len(), 316);
    let mut wire = Wire::new(client_wire(UUID, now(), 1, &data, None));
    fresh(Policy::default())
        .handshake(&mut wire, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn ciphertext_nonce_auth_and_tag_tampering_are_bound() {
    let data = client_wire(UUID, now(), 1, &tcp_inner(), None);
    for index in 0..data.len() {
        let mut tampered = data.clone();
        tampered[index] ^= 1;
        let mut wire = Wire::new(tampered);
        assert!(
            fresh(Policy::default())
                .handshake(&mut wire, false)
                .await
                .is_err(),
            "篡改 {index}"
        );
        assert!(wire.output.is_empty());
    }
    let other = client_wire(UUID, now(), 2, &tcp_inner(), None);
    for range in [0..16, 16..34, 42..data.len()] {
        let mut splice = data.clone();
        splice[range.clone()].copy_from_slice(&other[range]);
        let mut wire = Wire::new(splice);
        assert!(
            fresh(Policy::default())
                .handshake(&mut wire, false)
                .await
                .is_err()
        );
    }
}

#[test]
fn auth_candidates_crc_time_and_unique_match_are_checked() {
    let prepared = fresh(Policy::default());
    for (timestamp, valid) in [
        (880, true),
        (1120, true),
        (879, false),
        (1121, false),
        (u64::MAX, false),
        (i64::MAX as u64 + 1, false),
    ] {
        let wire = client_wire(UUID, timestamp, 1, &tcp_inner(), None);
        let id = wire[..16].try_into().unwrap();
        assert_eq!(prepared.identify(&id, 1000).is_ok(), valid);
    }
    assert!(prepared.identify(&[0; 16], 1000).is_err());
    let wire = client_wire(OTHER_UUID, 1000, 1, &tcp_inner(), None);
    assert!(
        prepared
            .identify(&wire[..16].try_into().unwrap(), 1000)
            .is_err()
    );
    let user = &prepared.users[0];
    let mut bad = [0; 16];
    bad[..8].copy_from_slice(&1000u64.to_be_bytes());
    let bad = crypto::auth_id(&user.auth_key, &bad, true);
    assert!(prepared.identify(&bad, 1000).is_err());
    let mut duplicate = prepared;
    let user = &duplicate.users[0];
    duplicate.users.push(User {
        name: "bob".into(),
        uuid: user.uuid,
        command_key: user.command_key,
        auth_key: user.auth_key,
    });
    let wire = client_wire(UUID, 1000, 1, &tcp_inner(), None);
    assert!(
        duplicate
            .identify(&wire[..16].try_into().unwrap(), 1000)
            .is_err()
    );
}

#[test]
fn prepared_revalidates_user_count_names_identity_and_redacts_credentials() {
    for users in [
        vec![],
        vec![VmessUser {
            name: "".into(),
            uuid: UUID.into(),
        }],
        vec![VmessUser {
            name: "secret".into(),
            uuid: "bad-secret-uuid".into(),
        }],
        vec![
            VmessUser {
                name: "alice".into(),
                uuid: UUID.into(),
            },
            VmessUser {
                name: "bob".into(),
                uuid: UUID.to_uppercase(),
            },
        ],
        vec![
            VmessUser {
                name: "alice".into(),
                uuid: UUID.into(),
            },
            VmessUser {
                name: "alice".into(),
                uuid: OTHER_UUID.into(),
            },
        ],
    ] {
        let error =
            Prepared::new(&users, Arc::new(ReplayPool::new(2)), Policy::default()).unwrap_err();
        assert!(!format!("{error:?}").contains("secret"));
        assert!(!format!("{error:?}").contains(UUID));
    }
    let users = (0..1025)
        .map(|i| VmessUser {
            name: format!("user-{i}"),
            uuid: format!("00000000-0000-0000-0000-{i:012x}"),
        })
        .collect::<Vec<_>>();
    assert!(Prepared::new(&users, Arc::new(ReplayPool::new(2)), Policy::default()).is_err());
    for rendered in [
        format!("{:?}", fresh(Policy::default())),
        format!("{:#?}", fresh(Policy::default())),
    ] {
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(UUID));
    }
}

#[tokio::test]
async fn malformed_inner_headers_fail_after_aead_without_success_or_session_commit() {
    let base = tcp_inner();
    let mut cases = vec![];
    for (index, value) in [
        (0, 0),
        (0, 2),
        (36, 1),
        (37, 0),
        (37, 4),
        (40, 0),
        (40, 4),
        (41, 0),
        (38, 0),
        (39, 0),
    ] {
        let mut changed = base[..base.len() - 4].to_vec();
        changed[index] = value;
        // 两个端口字节需要同时为0才是非法端口。
        if index == 38 || index == 39 {
            changed[38] = 0;
            changed[39] = 0;
        }
        cases.push(finish(changed));
    }
    let mut fnv = base.clone();
    *fnv.last_mut().unwrap() ^= 1;
    cases.push(fnv);
    for bad_domain in [vec![0], vec![b' '], vec![b'\n'], vec![0xff]] {
        let mut address = vec![0, 80, 2, 1];
        address.extend(bad_domain);
        cases.push(inner(1, 3, 5, &address, 0));
    }
    let mut extra = base[..base.len() - 4].to_vec();
    extra.push(0);
    cases.push(finish(extra));
    let mut excessive_padding = base.clone();
    excessive_padding[35] = 0xf3;
    let n = excessive_padding.len();
    let crc = checksum(&excessive_padding[..n - 4]);
    excessive_padding[n - 4..].copy_from_slice(&crc);
    cases.push(excessive_padding);
    for (i, header) in cases.into_iter().enumerate() {
        let pool = Arc::new(ReplayPool::new(2));
        let prepared = prepared(pool.clone(), Policy::default());
        let mut wire = Wire::new(client_wire(UUID, now(), i as u32, &header, None));
        assert!(
            prepared.handshake(&mut wire, false).await.is_err(),
            "结构case {i}"
        );
        assert!(wire.output.is_empty());
        // 结构失败只占AuthID，不应提交正文材料。
        pool.session(parse_uuid(UUID).unwrap(), KEY, IV).unwrap();
    }
}

#[test]
fn all_security_option_combinations_follow_explicit_policy() {
    for security in 0..16 {
        for options in 0..=255 {
            for command in [1, 2, 3] {
                for tls in [false, true] {
                    for opt_in in [false, true] {
                        let policy = Policy {
                            xudp: true,
                            packetaddr: true,
                            allow_insecure_body: opt_in,
                            allow_authenticated_length: opt_in,
                        };
                        let known = [0, 1, 4, 5, 12, 13];
                        let auth = [16, 17, 20, 21, 28, 29];
                        let expected = match security {
                            3 | 4 => known.contains(&options) || opt_in && auth.contains(&options),
                            5 => (tls || opt_in) && (options == 1 || options == 0 && command != 2),
                            _ => false,
                        };
                        assert_eq!(
                            validate_options(security, options, command, policy, tls).is_ok(),
                            expected,
                            "security={security} options={options} cmd={command} tls={tls} opt={opt_in}"
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn modes_addresses_cmd3_omission_and_packetaddr_are_explicit() {
    let v4 = [0, 53, 1, 192, 0, 2, 1];
    let v6 = [
        0, 53, 3, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let policy = Policy {
        xudp: true,
        packetaddr: true,
        ..Policy::default()
    };
    for (command, address, expected) in [
        (
            1,
            target("example.com", 443),
            Mode::Tcp(Target {
                host: Host::Domain("example.com".into()),
                port: 443,
            }),
        ),
        (
            2,
            v4.to_vec(),
            Mode::Udp(Target {
                host: Host::Ip("192.0.2.1".parse().unwrap()),
                port: 53,
            }),
        ),
        (
            2,
            v6.to_vec(),
            Mode::Udp(Target {
                host: Host::Ip("2001:db8::1".parse().unwrap()),
                port: 53,
            }),
        ),
        (3, vec![], Mode::Mux),
        (2, target(PACKET_ADDR, 0), Mode::PacketAddr),
    ] {
        for padding in [0, 15] {
            let header = inner(command, 4, 13, &address, padding);
            let mut wire = Wire::new(client_wire(UUID, now(), 1, &header, None));
            let accepted = fresh(policy).handshake(&mut wire, false).await.unwrap();
            assert_eq!(accepted.mode, expected);
            assert!(wire.output.is_empty());
        }
    }
    // 命令 3 的准入与 xudp 无关；无目标约束仍然生效。
    assert_eq!(
        parse_header(&inner(3, 3, 5, &[], 0), Policy::default(), false)
            .unwrap()
            .mode,
        Mode::Mux
    );
    for (command, address, policy) in [
        (3, v4.to_vec(), policy),
        (2, target(PACKET_ADDR, 443), Policy::default()),
        (1, target(PACKET_ADDR, 443), policy),
    ] {
        assert!(parse_header(&inner(command, 3, 5, &address, 0), policy, false).is_err());
    }
}

#[tokio::test]
async fn early_auth_commit_survives_aead_failure_cancellation_and_capacity_failure() {
    for capacity in [1, 2] {
        let pool = Arc::new(ReplayPool::new(capacity));
        let prepared = prepared(pool.clone(), Policy::default());
        let data = client_wire(UUID, now(), 1, &tcp_inner(), None);
        let id = data[..16].try_into().unwrap();
        let mut stalled = Wire::new(data[..16].to_vec());
        stalled.hold_end = true;
        {
            let future = prepared.handshake(&mut stalled, false);
            tokio::pin!(future);
            poll_fn(|cx| {
                assert!(future.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert!(
            pool.auth(parse_uuid(UUID).unwrap(), id, now(), now())
                .is_err()
        );
        let mut retry = Wire::new(data);
        assert!(prepared.handshake(&mut retry, false).await.is_err());
    }
    let pool = Arc::new(ReplayPool::new(2));
    let prepared = prepared(pool.clone(), Policy::default());
    let mut data = client_wire(UUID, now(), 1, &tcp_inner(), None);
    data[16] ^= 1;
    let id = data[..16].try_into().unwrap();
    assert!(
        prepared
            .handshake(&mut Wire::new(data), false)
            .await
            .is_err()
    );
    assert!(
        pool.auth(parse_uuid(UUID).unwrap(), id, now(), now())
            .is_err()
    );
    pool.session(parse_uuid(UUID).unwrap(), KEY, IV).unwrap();
    let prepared = Prepared::new(
        &[VmessUser {
            name: "alice".into(),
            uuid: UUID.into(),
        }],
        Arc::new(ReplayPool::new(1)),
        Policy::default(),
    )
    .unwrap();
    let data = client_wire(UUID, now(), 2, &tcp_inner(), None);
    let mut wire = Wire::new(data.clone());
    assert_eq!(
        prepared
            .handshake(&mut wire, false)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        prepared
            .handshake(&mut Wire::new(data), false)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn garbage_auth_does_not_consume_pool_and_new_auth_cannot_reuse_body_material() {
    let pool = Arc::new(ReplayPool::new(4));
    let first = prepared(pool.clone(), Policy::default());
    let second = prepared(pool.clone(), Policy::default());
    for _ in 0..4 {
        assert!(
            first
                .handshake(&mut Wire::new(vec![0; 16]), false)
                .await
                .is_err()
        );
    }
    let first_wire = client_wire(UUID, now(), 1, &tcp_inner(), None);
    first
        .handshake(&mut Wire::new(first_wire.clone()), false)
        .await
        .unwrap();
    assert!(
        second
            .handshake(&mut Wire::new(first_wire), false)
            .await
            .is_err()
    );
    let second_wire = client_wire(UUID, now(), 2, &tcp_inner(), None);
    assert!(
        second
            .handshake(&mut Wire::new(second_wire.clone()), false)
            .await
            .is_err()
    );
    assert!(
        second
            .handshake(&mut Wire::new(second_wire), false)
            .await
            .is_err()
    );
    let mut header = tcp_inner();
    header[17] ^= 1;
    let n = header.len();
    let crc = checksum(&header[..n - 4]);
    header[n - 4..].copy_from_slice(&crc);
    let mut wire = Wire::new(client_wire(UUID, now(), 3, &header, None));
    assert_eq!(
        first.handshake(&mut wire, false).await.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn concurrent_shared_uuid_requests_only_accept_once_but_other_identity_is_independent() {
    let pool = Arc::new(ReplayPool::new(8));
    let users = [
        VmessUser {
            name: "alice".into(),
            uuid: UUID.into(),
        },
        VmessUser {
            name: "bob".into(),
            uuid: OTHER_UUID.into(),
        },
    ];
    let prepared = Arc::new(Prepared::new(&users, pool, Policy::default()).unwrap());
    let data = client_wire(UUID, now(), 1, &tcp_inner(), None);
    let mut tasks = vec![];
    for _ in 0..8 {
        let p = prepared.clone();
        let data = data.clone();
        tasks.push(tokio::spawn(async move {
            p.handshake(&mut Wire::new(data).fragmented(), false)
                .await
                .is_ok()
        }));
    }
    let mut successes = 0;
    for task in tasks {
        successes += usize::from(task.await.unwrap());
    }
    assert_eq!(successes, 1);
    let accepted = prepared
        .handshake(
            &mut Wire::new(client_wire(OTHER_UUID, now(), 1, &tcp_inner(), None)),
            false,
        )
        .await
        .unwrap();
    assert_eq!(accepted.user, "bob");
}

#[tokio::test]
async fn response_short_write_pending_cancellation_flush_and_failure_latch() {
    let mut accepted = parse_header(&tcp_inner(), Policy::default(), false).unwrap();
    let expected = accepted.response;
    let mut wire = Wire::new(vec![]).fragmented();
    {
        let future = accepted.reply(&mut wire);
        tokio::pin!(future);
        poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert_eq!(wire.output.len(), 1);
    accepted.reply(&mut wire).await.unwrap();
    accepted.reply(&mut wire).await.unwrap();
    assert_eq!(wire.output, expected);
    assert_eq!(wire.flushes, 1);
    for flush_failure in [false, true] {
        let mut accepted = parse_header(&tcp_inner(), Policy::default(), false).unwrap();
        let mut wire = Wire::new(vec![]).fragmented();
        if flush_failure {
            wire.fail_flush = true;
        } else {
            wire.fail_at = Some(4);
        }
        assert!(accepted.reply(&mut wire).await.is_err());
        let count = wire.output.len();
        assert!(accepted.reply(&mut wire).await.is_err());
        assert_eq!(wire.output.len(), count);
    }
    let rendered = format!("{accepted:#?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(&format!("{KEY:?}")));
    assert!(!rendered.contains(&format!("{IV:?}")));
}

#[test]
fn address_truncations_padding_underflow_and_extra_fields_are_rejected() {
    for address in [
        vec![0, 80, 1, 127, 0, 0, 1],
        target("example.com", 80),
        vec![0, 80, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    ] {
        for end in 0..address.len() {
            assert!(
                parse_header(
                    &inner(1, 3, 5, &address[..end], 0),
                    Policy::default(),
                    false
                )
                .is_err()
            );
        }
        let mut extra = address;
        extra.push(0);
        assert!(parse_header(&inner(1, 3, 5, &extra, 0), Policy::default(), false).is_err());
    }
    let mut padded = inner(3, 3, 5, &[], 0);
    padded[35] = 0xf3;
    let n = padded.len();
    let crc = checksum(&padded[..n - 4]);
    padded[n - 4..].copy_from_slice(&crc);
    assert!(
        parse_header(
            &padded,
            Policy {
                xudp: true,
                ..Policy::default()
            },
            false
        )
        .is_err()
    );
    for size in 0..=MAX_HEADER + 16 {
        assert!(parse_header(&vec![0; size], Policy::default(), false).is_err());
    }
}

#[tokio::test]
async fn tls_and_experimental_length_policy_are_applied_to_real_handshakes() {
    for (security, options, policy, tls, allowed) in [
        (5, 0, Policy::default(), true, true),
        (5, 1, Policy::default(), true, true),
        (5, 0, Policy::default(), false, false),
        (5, 1, Policy::default(), false, false),
        (
            5,
            0,
            Policy {
                allow_insecure_body: true,
                ..Policy::default()
            },
            false,
            true,
        ),
        (3, 0x15, Policy::default(), true, false),
        (
            4,
            0x1d,
            Policy {
                allow_authenticated_length: true,
                ..Policy::default()
            },
            false,
            true,
        ),
        (
            5,
            0x11,
            Policy {
                allow_authenticated_length: true,
                ..Policy::default()
            },
            true,
            false,
        ),
    ] {
        let data = client_wire(
            UUID,
            now(),
            1,
            &inner(1, security, options, &target("example.com", 443), 0),
            None,
        );
        let mut wire = Wire::new(data);
        assert_eq!(
            fresh(policy).handshake(&mut wire, tls).await.is_ok(),
            allowed
        );
        assert!(wire.output.is_empty());
    }
}

#[tokio::test]
async fn cancellation_at_each_request_phase_preserves_only_committed_auth() {
    let data = client_wire(UUID, now(), 1, &tcp_inner(), None);
    for end in [0, 8, 15, 16, 20, 34, 40, 42, 43, data.len() - 1] {
        let pool = Arc::new(ReplayPool::new(2));
        let prepared = prepared(pool.clone(), Policy::default());
        let mut wire = Wire::new(data[..end].to_vec());
        wire.hold_end = true;
        {
            let future = prepared.handshake(&mut wire, false);
            tokio::pin!(future);
            poll_fn(|cx| {
                assert!(future.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert!(wire.output.is_empty());
        let id = data[..16].try_into().unwrap();
        assert_eq!(
            pool.auth(parse_uuid(UUID).unwrap(), id, now(), now())
                .is_ok(),
            end < 16,
            "阶段{end}"
        );
        pool.session(parse_uuid(UUID).unwrap(), KEY, IV).unwrap();
    }
}

#[tokio::test]
async fn server_first_response_needs_no_body_and_is_flush_ready() {
    let (mut client, mut server) = tokio::io::duplex(512);
    let prepared = fresh(Policy::default());
    let task = tokio::spawn(async move {
        let mut accepted = prepared.handshake(&mut server, false).await.unwrap();
        accepted.reply(&mut server).await.unwrap();
        server.write_all(b"server-first").await.unwrap();
    });
    client
        .write_all(&client_wire(UUID, now(), 1, &tcp_inner(), None))
        .await
        .unwrap();
    let mut response = [0; 38];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, make_response(&KEY, &IV, 0x7f).unwrap());
    let mut payload = [0; 12];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"server-first");
    task.await.unwrap();
}
