//! VLESS Encryption 出站客户端（Xray `mlkem768x25519plus`）。
//!
//! 与同目录服务端记录层共享 AEAD/CTR/记录分片实现；本文件只负责客户端
//! 握手：认证公钥中继、1-RTT PFS 交换、0-RTT 票据与双向记录层初始化。

use std::{
    io,
    sync::Mutex,
    time::{Duration, Instant},
};

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768, Seed};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::vless_encryption::{ClientEncryption, ClientKey, XorMode};

use super::*;

/// 客户端认证公钥。
struct KeyEntry {
    public: Vec<u8>,
    index: usize,
    hash: [u8; 32],
    mlkem: bool,
}

impl KeyEntry {
    fn new(key: &ClientKey) -> io::Result<Self> {
        let public = key.0.clone();
        match public.len() {
            X25519_LEN => Ok(Self {
                hash: *blake3::hash(&public).as_bytes(),
                public,
                index: X25519_LEN,
                mlkem: false,
            }),
            MLKEM_PUBLIC_LEN => {
                // 构造一次以尽早拒绝非法公钥；握手时重新构造。
                let bytes: [u8; MLKEM_PUBLIC_LEN] =
                    public.as_slice().try_into().expect("长度已校验");
                EncapsulationKey::<MlKem768>::new(&bytes.into())
                    .map_err(|_| invalid("VLESS Encryption ML-KEM 公钥无效"))?;
                Ok(Self {
                    hash: *blake3::hash(&public).as_bytes(),
                    public,
                    index: MLKEM_CIPHERTEXT_LEN,
                    mlkem: true,
                })
            }
            _ => Err(invalid("VLESS Encryption 客户端认证公钥长度无效")),
        }
    }
}

struct Session {
    pfs_key: [u8; 64],
    ticket: [u8; TICKET_LEN],
    expire: Instant,
}

pub(crate) struct ClientPrepared {
    keys: Vec<KeyEntry>,
    relays_len: usize,
    xor_mode: XorMode,
    zero_rtt: bool,
    padding: Padding,
    session: Mutex<Option<Session>>,
}

impl ClientPrepared {
    pub(crate) fn new(config: &ClientEncryption) -> io::Result<Self> {
        if config.keys.is_empty() {
            return Err(invalid("VLESS Encryption 至少需要一个认证密钥"));
        }
        let keys = config
            .keys
            .iter()
            .map(KeyEntry::new)
            .collect::<io::Result<Vec<_>>>()?;
        let relays_len = keys.iter().map(|key| key.index + 32).sum::<usize>() - 32;
        Ok(Self {
            keys,
            relays_len,
            xor_mode: config.xor_mode,
            zero_rtt: config.zero_rtt,
            padding: Padding::new(&config.padding_lens, &config.padding_gaps),
            session: Mutex::new(None),
        })
    }

    /// 丢弃缓存的 0-RTT 票据；下一次拨号回到完整 1-RTT 握手。
    pub(crate) fn invalidate(&self) {
        if let Ok(mut session) = self.session.lock() {
            *session = None;
        }
    }

    /// 在已建立的承载流上完成加密握手，返回明文记录层。
    pub(crate) async fn connect<S>(&self, mut stream: S) -> io::Result<Encrypted<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut iv = [0u8; IV_LEN];
        random_fill(&mut iv)?;
        let (relays, nfs_key, use_aes) = self.build_relays(&iv)?;
        let nfs = derive_aead(&iv, &nfs_key, use_aes)?;

        if self.zero_rtt {
            let cached = {
                let session = self
                    .session
                    .lock()
                    .map_err(|_| io::Error::other("VLESS Encryption 会话锁失效"))?;
                session.as_ref().and_then(|session| {
                    (Instant::now() < session.expire).then_some((session.pfs_key, session.ticket))
                })
            };
            if let Some((pfs_key, ticket)) = cached {
                return Self::connect_zero_rtt(
                    stream,
                    iv,
                    relays,
                    nfs,
                    nfs_key,
                    use_aes,
                    pfs_key,
                    ticket,
                    self.xor_mode,
                )
                .await;
            }
        }

        let mlkem_seed = random::<64>()?;
        let mlkem = DecapsulationKey::<MlKem768>::from_seed(Seed::from(mlkem_seed));
        let mut mlkem_public = [0u8; MLKEM_PUBLIC_LEN];
        mlkem_public.copy_from_slice(mlkem.encapsulation_key().to_bytes().as_slice());
        let x25519 = PrivateKey::generate(&X25519)
            .map_err(|_| invalid("VLESS Encryption 临时密钥生成失败"))?;
        let x25519_public = x25519
            .compute_public_key()
            .map_err(|_| invalid("VLESS Encryption 临时公钥推导失败"))?;
        let mut client_pfs = Vec::with_capacity(PFS_PUBLIC_LEN);
        client_pfs.extend_from_slice(&mlkem_public);
        client_pfs.extend_from_slice(x25519_public.as_ref());

        let (padding_len, mut lengths, gaps) = self.padding.choose()?;
        if padding_len < MIN_PADDING {
            return Err(invalid("VLESS Encryption padding 长度不足"));
        }
        let prefix = IV_LEN + self.relays_len;
        let pfs_exchange_len = ENCRYPTED_LENGTH_LEN + PFS_PUBLIC_LEN + TAG_LEN;
        let mut hello = vec![0u8; prefix + pfs_exchange_len + padding_len];
        hello[..IV_LEN].copy_from_slice(&iv);
        hello[IV_LEN..prefix].copy_from_slice(&relays);
        let sealed_length = seal_message(
            &nfs,
            &counter_nonce(1),
            &[],
            &encode_length(PFS_PUBLIC_LEN + TAG_LEN),
        )?;
        hello[prefix..prefix + ENCRYPTED_LENGTH_LEN].copy_from_slice(&sealed_length);
        let sealed_pfs = seal_message(&nfs, &counter_nonce(2), &[], &client_pfs)?;
        hello[prefix + ENCRYPTED_LENGTH_LEN..prefix + pfs_exchange_len]
            .copy_from_slice(&sealed_pfs);
        let padding_start = prefix + pfs_exchange_len;
        let sealed_padding_len = seal_message(
            &nfs,
            &counter_nonce(3),
            &[],
            &encode_length(padding_len - ENCRYPTED_LENGTH_LEN),
        )?;
        hello[padding_start..padding_start + ENCRYPTED_LENGTH_LEN]
            .copy_from_slice(&sealed_padding_len);
        let padding_body_len = padding_len - ENCRYPTED_LENGTH_LEN - TAG_LEN;
        let sealed_padding =
            seal_message(&nfs, &counter_nonce(4), &[], &vec![0u8; padding_body_len])?;
        hello[padding_start + ENCRYPTED_LENGTH_LEN..].copy_from_slice(&sealed_padding);

        if let Some(first) = lengths.first_mut() {
            *first += prefix + pfs_exchange_len;
        }
        let mut written = 0usize;
        for (index, length) in lengths.iter().enumerate() {
            if *length > 0 {
                stream.write_all(&hello[written..written + length]).await?;
                written += length;
            }
            if let Some(gap) = gaps.get(index)
                && !gap.is_zero()
            {
                tokio::time::sleep(*gap).await;
            }
        }
        if written != hello.len() {
            return Err(invalid("VLESS Encryption 客户端 padding 长度不一致"));
        }
        stream.flush().await?;

        let mut server_pfs = vec![0u8; SERVER_PFS_LEN];
        stream.read_exact(&mut server_pfs).await?;
        let server_pfs_plain = open_message(&nfs, &MAX_NONCE, &[], &server_pfs)?;
        let mut mlkem_ciphertext = [0u8; MLKEM_CIPHERTEXT_LEN];
        mlkem_ciphertext.copy_from_slice(&server_pfs_plain[..MLKEM_CIPHERTEXT_LEN]);
        let shared = mlkem.decapsulate(&Ciphertext::<MlKem768>::from(mlkem_ciphertext));
        let mut peer_x25519 = [0u8; X25519_LEN];
        peer_x25519.copy_from_slice(
            &server_pfs_plain[MLKEM_CIPHERTEXT_LEN..MLKEM_CIPHERTEXT_LEN + X25519_LEN],
        );
        let x25519_shared = agreement::agree(
            &x25519,
            UnparsedPublicKey::new(&X25519, peer_x25519),
            invalid("VLESS Encryption PFS X25519 协商失败"),
            |secret| {
                let mut key = [0u8; 32];
                key.copy_from_slice(secret);
                Ok(key)
            },
        )?;
        let mut pfs_key = [0u8; 64];
        pfs_key[..32].copy_from_slice(shared.as_slice());
        pfs_key[32..].copy_from_slice(&x25519_shared);
        let mut united = [0u8; 96];
        united[..64].copy_from_slice(&pfs_key);
        united[64..].copy_from_slice(&nfs_key);

        let out_cipher = derive_aead(&client_pfs, &united, use_aes)?;
        let in_cipher = derive_aead(
            &server_pfs_plain[..MLKEM_CIPHERTEXT_LEN + X25519_LEN],
            &united,
            use_aes,
        )?;
        let mut peer = Aead::from_cipher(in_cipher, united, use_aes, [0u8; 12]);

        let mut encrypted_ticket = [0u8; ENCRYPTED_TICKET_LEN];
        stream.read_exact(&mut encrypted_ticket).await?;
        let ticket_plain = open_message(&peer.cipher, &counter_nonce(1), &[], &encrypted_ticket)?;
        if ticket_plain.len() != TICKET_LEN {
            return Err(invalid("VLESS Encryption 票据长度异常"));
        }
        let mut ticket = [0u8; TICKET_LEN];
        ticket.copy_from_slice(&ticket_plain);
        let seconds = u16::from_be_bytes([ticket[0], ticket[1]]);

        let mut encrypted_length = [0u8; ENCRYPTED_LENGTH_LEN];
        stream.read_exact(&mut encrypted_length).await?;
        let length_plain = open_message(&peer.cipher, &counter_nonce(2), &[], &encrypted_length)?;
        let padding_len = decode_length(&length_plain);
        let mut padding = vec![0u8; padding_len];
        stream.read_exact(&mut padding).await?;
        open_message(&peer.cipher, &counter_nonce(3), &[], &padding)?;
        // 票据/长度/padding 已消耗服务端记录 nonce 1/2/3；首条业务记录从 4 开始。
        peer.nonce = counter_nonce(3);

        if seconds > 0
            && let Ok(mut session) = self.session.lock()
        {
            *session = Some(Session {
                pfs_key,
                ticket,
                expire: Instant::now() + Duration::from_secs(u64::from(seconds)),
            });
        }

        let out = Aead::from_cipher(out_cipher, united, use_aes, [0u8; 12]);
        Self::wrap(
            stream,
            out,
            peer,
            use_aes,
            self.xor_mode,
            united,
            iv,
            ticket,
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_zero_rtt<S>(
        mut stream: S,
        iv: [u8; IV_LEN],
        relays: Vec<u8>,
        nfs: Cipher,
        nfs_key: [u8; 32],
        use_aes: bool,
        pfs_key: [u8; 64],
        ticket: [u8; TICKET_LEN],
        xor_mode: XorMode,
    ) -> io::Result<Encrypted<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let prefix = IV_LEN + relays.len();
        let sealed_length = seal_message(&nfs, &counter_nonce(1), &[], &encode_length(32))?;
        let sealed_ticket = seal_message(&nfs, &counter_nonce(2), &[], &ticket)?;
        let mut pre_write = Vec::with_capacity(prefix + sealed_length.len() + sealed_ticket.len());
        pre_write.extend_from_slice(&iv);
        pre_write.extend_from_slice(&relays);
        pre_write.extend_from_slice(&sealed_length);
        pre_write.extend_from_slice(&sealed_ticket);
        stream.write_all(&pre_write).await?;
        stream.flush().await?;

        let mut server_random = [0u8; 16];
        stream.read_exact(&mut server_random).await?;
        let mut united = [0u8; 96];
        united[..64].copy_from_slice(&pfs_key);
        united[64..].copy_from_slice(&nfs_key);
        let out_cipher = derive_aead(&sealed_ticket, &united, use_aes)?;
        let in_cipher = derive_aead(&server_random, &united, use_aes)?;
        let out = Aead::from_cipher(out_cipher, united, use_aes, [0u8; 12]);
        let peer = Aead::from_cipher(in_cipher, united, use_aes, [0u8; 12]);
        Self::wrap(
            stream,
            out,
            peer,
            use_aes,
            xor_mode,
            united,
            iv,
            server_random,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn wrap<S>(
        stream: S,
        out: Aead,
        peer: Aead,
        _use_aes: bool,
        xor_mode: XorMode,
        united: [u8; 96],
        out_iv: [u8; IV_LEN],
        in_iv: [u8; IV_LEN],
    ) -> io::Result<Encrypted<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let inner = if xor_mode == XorMode::Random {
            Inner::Xor(XorStream::new(
                stream,
                Ctr::new(&united, &out_iv),
                Ctr::new(&united, &in_iv),
                0,
                0,
            ))
        } else {
            Inner::Plain(stream)
        };
        Ok(Encrypted::new(inner, out, peer, None))
    }

    /// 构造 IV 后的认证中继区，并返回 nfs 共享密钥。
    fn build_relays(&self, iv: &[u8; IV_LEN]) -> io::Result<(Vec<u8>, [u8; 32], bool)> {
        let mut relays = vec![0u8; self.relays_len];
        let mut offset = 0usize;
        let mut nfs_key = [0u8; 32];
        let mut last_ctr: Option<Ctr> = None;
        for (position, key) in self.keys.iter().enumerate() {
            let material = &mut relays[offset..offset + key.index];
            if key.mlkem {
                let public: [u8; MLKEM_PUBLIC_LEN] =
                    key.public.as_slice().try_into().expect("长度已校验");
                let encapsulation = EncapsulationKey::<MlKem768>::new(&public.into())
                    .map_err(|_| invalid("VLESS Encryption ML-KEM 公钥无效"))?;
                let (ciphertext, shared) = encapsulation.encapsulate();
                material.copy_from_slice(ciphertext.as_slice());
                nfs_key.copy_from_slice(shared.as_slice());
            } else {
                let private = PrivateKey::generate(&X25519)
                    .map_err(|_| invalid("VLESS Encryption 临时密钥生成失败"))?;
                let public = private
                    .compute_public_key()
                    .map_err(|_| invalid("VLESS Encryption 临时公钥推导失败"))?;
                material.copy_from_slice(public.as_ref());
                nfs_key = agreement::agree(
                    &private,
                    UnparsedPublicKey::new(&X25519, key.public.as_slice()),
                    invalid("VLESS Encryption X25519 协商失败"),
                    |secret| {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(secret);
                        Ok(key)
                    },
                )?;
            }
            if let Some(ctr) = last_ctr.as_mut() {
                ctr.apply(&mut material[..32]);
            }
            if self.xor_mode != XorMode::Native {
                Ctr::new(&key.public, iv).apply(material);
            }
            if position + 1 == self.keys.len() {
                break;
            }
            offset += key.index;
            relays[offset..offset + 32].copy_from_slice(&self.keys[position + 1].hash);
            let mut ctr = Ctr::new(&nfs_key, iv);
            ctr.apply(&mut relays[offset..offset + 32]);
            offset += 32;
            last_ctr = Some(ctr);
        }
        // Xray 客户端固定使用 AES-GCM；服务端会优先尝试 AES，失败再回退 ChaCha。
        Ok((relays, nfs_key, true))
    }
}

/// `random` 模式的 XOR 流与 AEAD 记录层需要直接访问父模块的记录头常量。
#[allow(dead_code)]
fn _assert_private_items() {
    let _ = RECORD_HEADER;
}

fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut output = [0u8; N];
    random_fill(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::config::vless_encryption::{AuthenticationKey, Decryption};
    use tokio::io::AsyncReadExt;

    fn x25519_public(seed: [u8; 32]) -> [u8; 32] {
        let private = PrivateKey::from_private_key(&X25519, &seed).unwrap();
        private
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap()
    }

    fn mlkem_public(seed: [u8; 64]) -> [u8; MLKEM_PUBLIC_LEN] {
        let key = DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed));
        key.encapsulation_key()
            .to_bytes()
            .as_slice()
            .try_into()
            .unwrap()
    }

    fn configs() -> (Decryption, ClientEncryption) {
        let x_seed = [7u8; 32];
        let m_seed = [9u8; 64];
        let decryption = Decryption {
            keys: vec![
                AuthenticationKey::X25519(x_seed),
                AuthenticationKey::MlKem768(m_seed),
            ],
            xor_mode: XorMode::Native,
            seconds_from: 60,
            seconds_to: 60,
            padding_lens: Vec::new(),
            padding_gaps: Vec::new(),
        };
        let encryption = ClientEncryption {
            keys: vec![
                ClientKey(x25519_public(x_seed).to_vec()),
                ClientKey(mlkem_public(m_seed).to_vec()),
            ],
            xor_mode: XorMode::Native,
            zero_rtt: true,
            padding_lens: Vec::new(),
            padding_gaps: Vec::new(),
        };
        (decryption, encryption)
    }

    async fn handshake() -> (
        Encrypted<tokio::io::DuplexStream>,
        Encrypted<tokio::io::DuplexStream>,
    ) {
        let (server_config, client_config) = configs();
        let server = Prepared::new(&server_config, 16).unwrap();
        let client = ClientPrepared::new(&client_config).unwrap();
        let (a, b) = tokio::io::duplex(65536);
        let (client_result, server_result) = tokio::join!(client.connect(b), server.accept(a));
        if let Err(error) = &client_result {
            eprintln!("client error: {error:?}");
        }
        if let Err(error) = &server_result {
            eprintln!("server error: {error:?}");
        }
        (client_result.unwrap(), server_result.unwrap())
    }

    #[tokio::test]
    async fn encrypted_record_layer_round_trips_both_directions() {
        let (mut client, mut server) = handshake().await;
        client.write_all(b"client-to-server").await.unwrap();
        client.flush().await.unwrap();
        let mut buffer = [0u8; 16];
        server.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"client-to-server");

        server.write_all(b"server-to-client").await.unwrap();
        server.flush().await.unwrap();
        let mut buffer = [0u8; 16];
        client.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"server-to-client");
    }

    #[tokio::test]
    async fn zero_rtt_ticket_is_reused_after_first_handshake() {
        let (server_config, client_config) = configs();
        let server = Prepared::new(&server_config, 16).unwrap();
        let client = ClientPrepared::new(&client_config).unwrap();
        for round in 0..2 {
            let (a, b) = tokio::io::duplex(65536);
            let (client_stream, server_stream) = tokio::join!(client.connect(b), server.accept(a));
            let mut client_stream = client_stream.unwrap();
            let mut server_stream = server_stream.unwrap();
            let payload: &[u8] = if round == 0 { b"first" } else { b"second" };
            client_stream.write_all(payload).await.unwrap();
            client_stream.flush().await.unwrap();
            let mut buffer = vec![0u8; payload.len()];
            server_stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, payload);
        }
    }
}
