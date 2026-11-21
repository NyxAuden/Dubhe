//! VLESS Encryption 回环测试：用与 Xray 客户端一致的线格式驱动服务端。
//!
//! 客户端侧只实现测试需要的最小路径（1-RTT 与 0-RTT），不进入生产代码。

use std::sync::Arc;

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use ml_kem::MlKem768;
use ml_kem::kem::{Encapsulate, KeyExport};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::*;

const KEY32: [u8; 32] = {
    let mut key = [0u8; 32];
    let mut index = 0;
    while index < key.len() {
        key[index] = index as u8 + 1;
        index += 1;
    }
    key
};
const KEY64: [u8; 64] = {
    let mut key = [0u8; 64];
    let mut index = 0;
    while index < key.len() {
        key[index] = index as u8 + 1;
        index += 1;
    }
    key
};

fn decryption(keys: Vec<AuthenticationKey>, xor_mode: XorMode, seconds: u64) -> Decryption {
    Decryption {
        keys,
        xor_mode,
        seconds_from: seconds,
        seconds_to: 0,
        padding_lens: vec![[100, 35, 35]],
        padding_gaps: Vec::new(),
    }
}

fn public_keys(keys: &[AuthenticationKey]) -> Vec<Vec<u8>> {
    keys.iter()
        .map(|key| match key {
            AuthenticationKey::X25519(seed) => {
                let private = PrivateKey::from_private_key(&X25519, seed).unwrap();
                private.compute_public_key().unwrap().as_ref().to_vec()
            }
            AuthenticationKey::MlKem768(seed) => {
                let key = ml_kem::DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
                key.encapsulation_key().to_bytes().as_slice().to_vec()
            }
        })
        .collect()
}

#[test]
fn derive_key_bytes_matches_upstream_str() {
    // 上游 `&str` 入口与本地字节入口必须完全等价。
    assert_eq!(
        blake3::hazmat::hash_derive_key_context("VLESS"),
        blake3::hazmat::hash_derive_key_context_bytes(b"VLESS")
    );
    // 任意字节上下文不能等于普通哈希（标志位不同）。
    let context = [0u8, 1, 2, 3, 250, 251, 252];
    assert_ne!(
        blake3::hazmat::hash_derive_key_context_bytes(&context),
        *blake3::hash(&context).as_bytes()
    );
    assert_eq!(
        derive_key(b"VLESS", b"material"),
        blake3::derive_key("VLESS", b"material")
    );
}

#[test]
fn record_header_validation_matches_upstream() {
    assert_eq!(decode_header(&record_header(17)).unwrap(), 17);
    assert_eq!(decode_header(&record_header(16640)).unwrap(), 16640);
    assert!(decode_header(&record_header(16)).is_err());
    assert!(decode_header(&record_header(16641)).is_err());
    // 魔数不符：上游把长度归零后判为非法。
    assert!(decode_header(&[22, 3, 3, 0, 100]).is_err());
    // 混淆层保留原始长度（魔数不符时为 0）。
    assert_eq!(skip_header_len(&[22, 3, 3, 0, 100]), 0);
    assert_eq!(skip_header_len(&record_header(100)), 100);
}

#[test]
fn counter_nonce_is_big_endian() {
    let nonce = counter_nonce(0x0102_0304_0506_0708);
    assert_eq!(nonce, [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    let mut value = [0u8; 12];
    value[11] = 0xff;
    increment_nonce(&mut value);
    assert_eq!(value[10], 1);
    assert_eq!(value[11], 0);
}

struct Cached {
    pfs_key: [u8; 64],
    ticket: [u8; 16],
}

/// 最小的 Xray 客户端实现。
struct TestClient<'a> {
    public_keys: &'a [Vec<u8>],
    xor_mode: XorMode,
    use_aes: bool,
    force_relay_seed: Option<[u8; 32]>,
}

impl TestClient<'_> {
    async fn one_rtt<T>(&self, io: T) -> (Encrypted<T>, Cached)
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut io = io;
        let mut iv = [0u8; IV_LEN];
        random_fill(&mut iv).unwrap();
        let (relays, nfs_key) = self.relays(&iv);
        let nfs = derive_aead(&iv, &nfs_key, self.use_aes).unwrap();

        // 客户端 PFS 公钥：ML-KEM 封装公钥 + X25519 公钥。
        let seed: [u8; 64] = core::array::from_fn(|index| (index as u8).wrapping_mul(7));
        let decapsulation = ml_kem::DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed));
        let encapsulation = decapsulation.encapsulation_key().to_bytes();
        let x_private = PrivateKey::generate(&X25519).unwrap();
        let x_public = x_private.compute_public_key().unwrap();
        let mut pfs_public = Vec::with_capacity(PFS_PUBLIC_LEN);
        pfs_public.extend_from_slice(encapsulation.as_slice());
        pfs_public.extend_from_slice(x_public.as_ref());

        let mut hello = Vec::new();
        hello.extend_from_slice(&relays);
        hello.extend_from_slice(
            &seal_message(&nfs, &counter_nonce(1), &[], &encode_length(PFS_BLOCK_LEN)).unwrap(),
        );
        hello.extend_from_slice(&seal_message(&nfs, &counter_nonce(2), &[], &pfs_public).unwrap());
        let padding_len = 35;
        hello.extend_from_slice(
            &seal_message(
                &nfs,
                &counter_nonce(3),
                &[],
                &encode_length(padding_len - ENCRYPTED_LENGTH_LEN),
            )
            .unwrap(),
        );
        let padding_body = vec![0u8; padding_len - ENCRYPTED_LENGTH_LEN - TAG_LEN];
        hello
            .extend_from_slice(&seal_message(&nfs, &counter_nonce(4), &[], &padding_body).unwrap());
        io.write_all(&hello).await.unwrap();

        // 服务端 PFS 公钥：显式 MAX nonce。
        let mut server_block = [0u8; SERVER_PFS_LEN];
        io.read_exact(&mut server_block).await.unwrap();
        let server_plain = open_message(&nfs, &MAX_NONCE, &[], &server_block).unwrap();
        assert_eq!(server_plain.len(), MLKEM_CIPHERTEXT_LEN + X25519_LEN);

        let mut mlkem_ciphertext = [0u8; MLKEM_CIPHERTEXT_LEN];
        mlkem_ciphertext.copy_from_slice(&server_plain[..MLKEM_CIPHERTEXT_LEN]);
        let mut server_x = [0u8; X25519_LEN];
        server_x.copy_from_slice(&server_plain[MLKEM_CIPHERTEXT_LEN..]);

        let mlkem_shared =
            decapsulation.decapsulate(&ml_kem::Ciphertext::<MlKem768>::from(mlkem_ciphertext));
        let x_shared = agreement::agree(
            &x_private,
            UnparsedPublicKey::new(&X25519, server_x),
            (),
            |secret| {
                let mut key = [0u8; 32];
                key.copy_from_slice(secret);
                Ok(key)
            },
        )
        .unwrap();
        let mut pfs_key = [0u8; 64];
        pfs_key[..32].copy_from_slice(mlkem_shared.as_slice());
        pfs_key[32..].copy_from_slice(&x_shared);
        let mut united = [0u8; 96];
        united[..64].copy_from_slice(&pfs_key);
        united[64..].copy_from_slice(&nfs_key);

        // 服务端下行以自身 PFS 公钥为上下文，上行以客户端 PFS 公钥为上下文。
        let out_cipher = derive_aead(&pfs_public, &united, self.use_aes).unwrap();
        let in_cipher = derive_aead(&server_plain, &united, self.use_aes).unwrap();

        let mut encrypted_ticket = [0u8; ENCRYPTED_TICKET_LEN];
        io.read_exact(&mut encrypted_ticket).await.unwrap();
        let ticket_plain =
            open_message(&in_cipher, &counter_nonce(1), &[], &encrypted_ticket).unwrap();
        let mut ticket = [0u8; TICKET_LEN];
        ticket.copy_from_slice(&ticket_plain);

        let mut length_block = [0u8; ENCRYPTED_LENGTH_LEN];
        io.read_exact(&mut length_block).await.unwrap();
        let plain = open_message(&in_cipher, &counter_nonce(2), &[], &length_block).unwrap();
        let padding_len = decode_length(&plain);
        let mut padding = vec![0u8; padding_len];
        io.read_exact(&mut padding).await.unwrap();
        open_message(&in_cipher, &counter_nonce(3), &[], &padding).unwrap();

        let inner = match self.xor_mode {
            XorMode::Random => Inner::Xor(XorStream::new(
                io,
                Ctr::new(&united, &iv),
                Ctr::new(&united, &ticket),
                0,
                0,
            )),
            _ => Inner::Plain(io),
        };
        let stream = Encrypted::new(
            inner,
            Aead::from_cipher(out_cipher, united, self.use_aes, [0u8; 12]),
            Aead::from_cipher(in_cipher, united, self.use_aes, counter_nonce(3)),
            None,
        );
        (stream, Cached { pfs_key, ticket })
    }

    async fn zero_rtt<T>(&self, io: T, cached: &Cached) -> Encrypted<T>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut io = io;
        let mut iv = [0u8; IV_LEN];
        random_fill(&mut iv).unwrap();
        let (relays, nfs_key) = self.relays(&iv);
        let nfs = derive_aead(&iv, &nfs_key, self.use_aes).unwrap();

        let mut hello = Vec::new();
        hello.extend_from_slice(&relays);
        hello.extend_from_slice(
            &seal_message(&nfs, &counter_nonce(1), &[], &encode_length(32)).unwrap(),
        );
        let encrypted_ticket = seal_message(&nfs, &counter_nonce(2), &[], &cached.ticket).unwrap();
        hello.extend_from_slice(&encrypted_ticket);

        let mut united = [0u8; 96];
        united[..64].copy_from_slice(&cached.pfs_key);
        united[64..].copy_from_slice(&nfs_key);
        let out_cipher = derive_aead(&encrypted_ticket, &united, self.use_aes).unwrap();

        io.write_all(&hello).await.unwrap();
        // 服务端 0-RTT 的 16 字节随机前缀同时是下发 AEAD 的上下文。
        // 票据被拒绝时服务端会直接关闭，不会下发前缀；调用方随后只观察关闭。
        let mut server_random = [0u8; 16];
        if io.read_exact(&mut server_random).await.is_err() {
            server_random = [0u8; 16];
        }
        let in_cipher = derive_aead(&server_random, &united, self.use_aes).unwrap();

        let inner = match self.xor_mode {
            XorMode::Random => Inner::Xor(XorStream::new(
                io,
                Ctr::new(&united, &iv),
                Ctr::new(&united, &server_random),
                0,
                0,
            )),
            _ => Inner::Plain(io),
        };
        Encrypted::new(
            inner,
            Aead::from_cipher(out_cipher, united, self.use_aes, [0u8; 12]),
            Aead::from_cipher(in_cipher, united, self.use_aes, [0u8; 12]),
            None,
        )
    }

    /// 生成中继区，返回 `iv || relays` 与认证密钥协商结果。
    fn relays(&self, iv: &[u8; IV_LEN]) -> (Vec<u8>, [u8; 32]) {
        // 中继区每段长度是协商产物长度：X25519 为公钥，ML-KEM 为密文。
        let relays_len = self
            .public_keys
            .iter()
            .map(|key| {
                (match key.len() {
                    X25519_LEN => X25519_LEN,
                    _ => MLKEM_CIPHERTEXT_LEN,
                }) + 32
            })
            .sum::<usize>()
            - 32;
        let mut input = vec![0u8; IV_LEN + relays_len];
        input[..IV_LEN].copy_from_slice(iv);
        let relays = &mut input[IV_LEN..];
        let mut offset = 0usize;
        let mut nfs_key = [0u8; 32];
        let mut last_ctr: Option<Ctr> = None;
        for (position, public) in self.public_keys.iter().enumerate() {
            let index = match public.len() {
                X25519_LEN => X25519_LEN,
                _ => MLKEM_CIPHERTEXT_LEN,
            };
            let relay = &mut relays[offset..offset + index];
            match public.len() {
                X25519_LEN => {
                    let private = match self.force_relay_seed {
                        Some(seed) => PrivateKey::from_private_key(&X25519, &seed).unwrap(),
                        None => PrivateKey::generate(&X25519).unwrap(),
                    };
                    let ephemeral = private.compute_public_key().unwrap();
                    relay.copy_from_slice(ephemeral.as_ref());
                    nfs_key = agreement::agree(
                        &private,
                        UnparsedPublicKey::new(&X25519, public),
                        (),
                        |secret| {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(secret);
                            Ok(key)
                        },
                    )
                    .unwrap();
                }
                _ => {
                    let mut bytes = [0u8; MLKEM_PUBLIC_LEN];
                    bytes.copy_from_slice(public);
                    let key = ml_kem::EncapsulationKey::<MlKem768>::new(&bytes.into()).unwrap();
                    let (ciphertext, shared) = key.encapsulate();
                    relay.copy_from_slice(ciphertext.as_slice());
                    nfs_key.copy_from_slice(shared.as_slice());
                }
            }
            // 中继区先填入本段协商材料，再叠加上一密钥的 CTR 与当前密钥的混淆；
            // 顺序颠倒会被随后写入的密文覆盖。
            if let Some(ctr) = last_ctr.as_mut() {
                ctr.apply(&mut relay[..X25519_LEN]);
            }
            if self.xor_mode != XorMode::Native {
                Ctr::new(public, iv).apply(relay);
            }
            if position + 1 == self.public_keys.len() {
                break;
            }
            offset += index;
            let mut ctr = Ctr::new(&nfs_key, iv);
            let hash = *blake3::hash(&self.public_keys[position + 1]).as_bytes();
            relays[offset..offset + 32].copy_from_slice(&hash);
            ctr.apply(&mut relays[offset..offset + 32]);
            offset += 32;
            last_ctr = Some(ctr);
        }
        (input, nfs_key)
    }
}

async fn exercise<T>(server: Encrypted<T>, client: Encrypted<T>) -> (Vec<u8>, Vec<u8>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut client = client;
    let server = tokio::spawn(async move {
        let mut server = server;
        let mut payload = vec![0u8; 5];
        server.read_exact(&mut payload).await.unwrap();
        server.write_all(b"world").await.unwrap();
        server.flush().await.unwrap();
        payload
    });
    client.write_all(b"hello").await.unwrap();
    let mut reply = [0u8; 5];
    client.read_exact(&mut reply).await.unwrap();
    (server.await.unwrap(), reply.to_vec())
}

async fn one_rtt_case(keys: Vec<AuthenticationKey>, xor_mode: XorMode, use_aes: bool) {
    let prepared = Arc::new(Prepared::new(&decryption(keys.clone(), xor_mode, 0), 64).unwrap());
    let public = public_keys(&keys);
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn({
        let prepared = prepared.clone();
        async move { prepared.accept(server_io).await.unwrap() }
    });
    let client = TestClient {
        public_keys: &public,
        xor_mode,
        use_aes,
        force_relay_seed: None,
    };
    let (client, _cached) = client.one_rtt(client_io).await;
    let server = server.await.unwrap();
    let (request, reply) = exercise(server, client).await;
    assert_eq!(request, b"hello");
    assert_eq!(reply, b"world");
}

#[tokio::test]
async fn x25519_native_aes() {
    one_rtt_case(
        vec![AuthenticationKey::X25519(KEY32)],
        XorMode::Native,
        true,
    )
    .await;
}

#[tokio::test]
async fn x25519_xorpub_chacha() {
    one_rtt_case(
        vec![AuthenticationKey::X25519(KEY32)],
        XorMode::Public,
        false,
    )
    .await;
}

#[tokio::test]
async fn mlkem_random_aes() {
    one_rtt_case(
        vec![AuthenticationKey::MlKem768(KEY64)],
        XorMode::Random,
        true,
    )
    .await;
}

#[tokio::test]
async fn chained_keys_random_chacha() {
    one_rtt_case(
        vec![
            AuthenticationKey::X25519(KEY32),
            AuthenticationKey::MlKem768(KEY64),
            AuthenticationKey::X25519([7u8; 32]),
        ],
        XorMode::Random,
        false,
    )
    .await;
}

#[tokio::test]
async fn zero_rtt_roundtrip_and_replay() {
    let keys = vec![AuthenticationKey::X25519(KEY32)];
    let prepared =
        Arc::new(Prepared::new(&decryption(keys.clone(), XorMode::Random, 600), 64).unwrap());
    let public = public_keys(&keys);

    // 先做一次 1-RTT，拿到票据与 PFS 密钥。
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn({
        let prepared = prepared.clone();
        async move { prepared.accept(server_io).await.unwrap() }
    });
    let client = TestClient {
        public_keys: &public,
        xor_mode: XorMode::Random,
        use_aes: true,
        force_relay_seed: None,
    };
    let (client, cached) = client.one_rtt(client_io).await;
    let server = server.await.unwrap();
    let (request, reply) = exercise(server, client).await;
    assert_eq!(request, b"hello");
    assert_eq!(reply, b"world");

    // 0-RTT 复用票据；固定中继私钥以便随后重放。
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn({
        let prepared = prepared.clone();
        async move { prepared.accept(server_io).await.unwrap() }
    });
    let client = TestClient {
        public_keys: &public,
        xor_mode: XorMode::Random,
        use_aes: true,
        force_relay_seed: Some([9u8; 32]),
    };
    let client = client.zero_rtt(client_io, &cached).await;
    let server = server.await.unwrap();
    let (request, reply) = exercise(server, client).await;
    assert_eq!(request, b"hello");
    assert_eq!(reply, b"world");

    // 相同中继密钥重放同一会话：服务端必须拒绝。
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn({
        let prepared = prepared.clone();
        async move { prepared.accept(server_io).await }
    });
    let replay = TestClient {
        public_keys: &public,
        xor_mode: XorMode::Random,
        use_aes: true,
        force_relay_seed: Some([9u8; 32]),
    };
    let stream = replay.zero_rtt(client_io, &cached).await;
    drop(stream);
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn expired_ticket_is_rejected() {
    let keys = vec![AuthenticationKey::X25519(KEY32)];
    let prepared =
        Arc::new(Prepared::new(&decryption(keys.clone(), XorMode::Native, 1), 64).unwrap());
    let public = public_keys(&keys);
    let bogus = Cached {
        pfs_key: [3u8; 64],
        ticket: [4u8; 16],
    };

    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn({
        let prepared = prepared.clone();
        async move { prepared.accept(server_io).await }
    });
    let client = TestClient {
        public_keys: &public,
        xor_mode: XorMode::Native,
        use_aes: true,
        force_relay_seed: None,
    };
    let stream = client.zero_rtt(client_io, &bogus).await;
    drop(stream);
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn fragmented_reads_and_writes() {
    let keys = vec![AuthenticationKey::MlKem768(KEY64)];
    let prepared =
        Arc::new(Prepared::new(&decryption(keys.clone(), XorMode::Random, 0), 64).unwrap());
    let public = public_keys(&keys);
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn({
        let prepared = prepared.clone();
        async move { prepared.accept(server_io).await.unwrap() }
    });
    let client = TestClient {
        public_keys: &public,
        xor_mode: XorMode::Random,
        use_aes: false,
        force_relay_seed: None,
    };
    let (mut client, _) = client.one_rtt(client_io).await;
    let mut server = server.await.unwrap();

    // 大块数据跨越 8192 分片边界，读侧每次只取 7 字节。
    let payload: Vec<u8> = (0..20_000u32).map(|index| index as u8).collect();
    let expected = payload.clone();
    let writer = tokio::spawn(async move {
        server.write_all(&payload).await.unwrap();
        server.flush().await.unwrap();
        server.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    let mut chunk = [0u8; 7];
    loop {
        let read = client.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..read]);
    }
    writer.await.unwrap();
    assert_eq!(received, expected);
}
