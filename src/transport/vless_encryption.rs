//! VLESS Encryption（Xray `mlkem768x25519plus`）服务端记录层。
//!
//! 线格式与 Xray-core v26.10.31 `proxy/vless/encryption` 对齐：
//!
//! 1. 客户端发送 `iv(16) || relays`，其中每个认证密钥贡献 32（X25519）或 1088（ML-KEM-768）
//!    字节，非最后一个密钥后还跟随 32 字节的下一公钥 BLAKE3 摘要。
//! 2. `nfsAEAD = AEAD(ctx = iv, key = 认证密钥协商结果)`，nonce 从 1 起逐条递增；
//!    首条是 18 字节长度块，值为 32 时进入 0-RTT，否则是 PFS 公钥交换块长度。
//! 3. 服务端回 `PFS 公钥密文 || 票据密文 || padding`，其后双方使用 `unitedKey`
//!    派生的记录层 AEAD；`random` 模式额外用 AES-256-CTR 只混淆 5 字节记录头。
//!
//! 与上游一致：PFS 交换块长度允许大于 1232（未来版本可能扩展），多余的字节忽略。
//! 本模块只处理记录层，VLESS 协议解析由 `crate::protocol::vless` 完成。

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use chacha20poly1305::ChaCha20Poly1305;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{MlKem768, Seed};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::config::vless_encryption::{AuthenticationKey, Decryption, XorMode};

/// 伪装成 TLS 1.3 应用数据的记录头长度。
const RECORD_HEADER: usize = 5;
/// AEAD 认证标签长度。
const TAG_LEN: usize = 16;
/// 记录长度下限（与上游一致）。
const MIN_RECORD: usize = 17;
/// 记录长度上限：TLS 1.3 的 16384 + 256。
const MAX_RECORD: usize = 16640;
/// 单条记录承载的明文上限，与上游 8192 分片一致。
const MAX_PLAINTEXT: usize = 8192;
/// 初始 IV 长度。
const IV_LEN: usize = 16;
/// X25519 公钥/私钥长度。
const X25519_LEN: usize = 32;
/// ML-KEM-768 密文长度。
const MLKEM_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 封装公钥长度。
const MLKEM_PUBLIC_LEN: usize = 1184;
/// PFS 公钥（ML-KEM 公钥 + X25519 公钥）。
const PFS_PUBLIC_LEN: usize = MLKEM_PUBLIC_LEN + X25519_LEN;
/// PFS 交换块密文长度（含标签）。
const PFS_BLOCK_LEN: usize = PFS_PUBLIC_LEN + TAG_LEN;
/// 服务端 PFS 密文长度（含标签）。
const SERVER_PFS_LEN: usize = MLKEM_CIPHERTEXT_LEN + X25519_LEN + TAG_LEN;
/// 票据明文长度。
const TICKET_LEN: usize = 16;
/// 票据密文长度（含标签）。
const ENCRYPTED_TICKET_LEN: usize = TICKET_LEN + TAG_LEN;
/// 长度块明文长度。
const LENGTH_LEN: usize = 2;
/// 长度块密文长度（含标签）。
const ENCRYPTED_LENGTH_LEN: usize = LENGTH_LEN + TAG_LEN;
/// 服务端首个密文段之前的明文头部长度：PFS 密文 + 票据密文。
const SERVER_HELLO_PREFIX: usize = SERVER_PFS_LEN + ENCRYPTED_TICKET_LEN;
/// padding 长度字段之外的最小 padding 总量（长度块 + 标签 + 至少 1 字节实体）。
const MIN_PADDING: usize = ENCRYPTED_LENGTH_LEN + TAG_LEN + 1;
/// 显式使用全 0xFF nonce 一次后即重密钥。
const MAX_NONCE: [u8; 12] = [0xff; 12];
/// 单条连接允许的 AEAD 次数上限；远低于 96 位 nonce 空间，超限即失败关闭。
const MAX_AEAD_OPS: u64 = 1 << 63;
/// 记录层 CTR 的派生上下文（与上游 `NewCTR` 的字面量一致）。
const CTR_CONTEXT: &str = "VLESS";
/// 票据会话数量上限，避免无认证流量导致内存膨胀（只有成功握手才会写入）。
const MAX_SESSIONS: usize = 65536;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn random_fill(buffer: &mut [u8]) -> io::Result<()> {
    aws_lc_rs::rand::fill(buffer).map_err(|_| io::Error::other("随机数生成失败"))
}

/// 均匀随机数 `[0, bound)`；`bound <= 1` 时返回 0。
fn random_below(bound: u32) -> io::Result<u32> {
    if bound <= 1 {
        return Ok(0);
    }
    // 拒绝采样避免取模偏差。
    let zone = u32::MAX - (u32::MAX % bound);
    let mut bytes = [0u8; 4];
    loop {
        random_fill(&mut bytes)?;
        let value = u32::from_le_bytes(bytes);
        if value < zone {
            return Ok(value % bound);
        }
    }
}

/// 与上游 `crypto.RandBetween` 相同的半开区间：`[from, to)`；`to - from <= 1` 时返回 `from`。
fn random_between(from: u32, to: u32) -> io::Result<u32> {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    let distance = to - from;
    if distance <= 1 {
        return Ok(from);
    }
    Ok(from + random_below(distance)?)
}

fn increment_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn counter_nonce(value: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&value.to_be_bytes());
    nonce
}

fn encode_length(length: usize) -> [u8; LENGTH_LEN] {
    (length as u16).to_be_bytes()
}

fn decode_length(bytes: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn record_header(length: usize) -> [u8; RECORD_HEADER] {
    let [high, low] = (length as u16).to_be_bytes();
    [23, 3, 3, high, low]
}

/// 与上游 `DecodeHeader` 等价：魔数不符按长度 0 处理，最终统一校验范围。
fn decode_header(header: &[u8]) -> io::Result<usize> {
    let length = if header[0] == 23 && header[1] == 3 && header[2] == 3 {
        usize::from(u16::from_be_bytes([header[3], header[4]]))
    } else {
        0
    };
    if !(MIN_RECORD..=MAX_RECORD).contains(&length) {
        return Err(invalid("VLESS Encryption 记录头长度非法"));
    }
    Ok(length)
}

/// 混淆层的宽松解析：上游忽略错误并直接使用长度值（魔数不符时为 0）。
fn skip_header_len(header: &[u8]) -> usize {
    if header[0] == 23 && header[1] == 3 && header[2] == 3 {
        usize::from(u16::from_be_bytes([header[3], header[4]]))
    } else {
        0
    }
}

/// BLAKE3 derive-key；上下文可以是任意字节（VLESS Encryption 用随机材料做上下文）。
fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
    use blake3::hazmat::HasherExt as _;
    let context_key = blake3::hazmat::hash_derive_key_context_bytes(context);
    let mut hasher = blake3::Hasher::new_from_context_key(&context_key);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}

fn derive_aead(context: &[u8], material: &[u8], use_aes: bool) -> io::Result<Cipher> {
    Cipher::new(use_aes, &derive_key(context, material))
}

fn current_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn current_minute() -> i64 {
    (current_seconds() / 60) as i64
}

// --------------------------------------------------------------------------
// 服务端预置状态
// --------------------------------------------------------------------------

/// 认证密钥的私有部分。
enum Secret {
    X25519(PrivateKey),
    MlKem(Box<ml_kem::DecapsulationKey<MlKem768>>),
}

struct KeyEntry {
    secret: Secret,
    /// 线路上的公钥字节（X25519 32 字节 / ML-KEM 1184 字节）。
    public: Vec<u8>,
    /// 该密钥在中继区占用的字节数。
    index: usize,
    /// 下一密钥公钥的 BLAKE3 摘要。
    hash: [u8; 32],
}

impl KeyEntry {
    fn new(key: &AuthenticationKey) -> io::Result<Self> {
        match key {
            AuthenticationKey::X25519(seed) => {
                let private = PrivateKey::from_private_key(&X25519, seed)
                    .map_err(|_| invalid("VLESS Encryption X25519 私钥无效"))?;
                let public = private
                    .compute_public_key()
                    .map_err(|_| invalid("VLESS Encryption X25519 公钥推导失败"))?;
                let public = public.as_ref().to_vec();
                Ok(Self {
                    secret: Secret::X25519(private),
                    index: X25519_LEN,
                    hash: *blake3::hash(&public).as_bytes(),
                    public,
                })
            }
            AuthenticationKey::MlKem768(seed) => {
                let key = ml_kem::DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
                let public = key.encapsulation_key().to_bytes().as_slice().to_vec();
                if public.len() != MLKEM_PUBLIC_LEN {
                    return Err(invalid("VLESS Encryption ML-KEM 公钥长度异常"));
                }
                Ok(Self {
                    secret: Secret::MlKem(Box::new(key)),
                    index: MLKEM_CIPHERTEXT_LEN,
                    hash: *blake3::hash(&public).as_bytes(),
                    public,
                })
            }
        }
    }

    /// 用本端认证私钥从中继区恢复共享密钥。
    fn agree(&self, relay: &[u8]) -> io::Result<[u8; 32]> {
        match &self.secret {
            Secret::X25519(private) => {
                // 上游的可塑性防护：拒绝最后一字节最高位为 1 的公钥。
                if relay[X25519_LEN - 1] > 127 {
                    return Err(invalid("VLESS Encryption X25519 公钥最高位非法"));
                }
                agreement::agree(
                    private,
                    UnparsedPublicKey::new(&X25519, relay),
                    invalid("VLESS Encryption X25519 协商失败"),
                    |secret| {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(secret);
                        Ok(key)
                    },
                )
            }
            Secret::MlKem(key) => {
                let mut ciphertext = [0u8; MLKEM_CIPHERTEXT_LEN];
                ciphertext.copy_from_slice(relay);
                let shared = key.decapsulate(&ml_kem::Ciphertext::<MlKem768>::from(ciphertext));
                let mut out = [0u8; 32];
                out.copy_from_slice(shared.as_slice());
                Ok(out)
            }
        }
    }
}

/// padding 生成器；未配置时使用上游默认值。
struct Padding {
    lens: Vec<[u32; 3]>,
    gaps: Vec<[u32; 3]>,
}

impl Padding {
    const DEFAULT_LENS: [[u32; 3]; 2] = [[100, 111, 1111], [50, 0, 3333]];
    const DEFAULT_GAPS: [[u32; 3]; 1] = [[75, 0, 111]];

    fn new(lens: &[[u32; 3]], gaps: &[[u32; 3]]) -> Self {
        if lens.is_empty() {
            Self {
                lens: Self::DEFAULT_LENS.to_vec(),
                gaps: Self::DEFAULT_GAPS.to_vec(),
            }
        } else {
            Self {
                lens: lens.to_vec(),
                gaps: gaps.to_vec(),
            }
        }
    }

    /// 返回 padding 总长度、每段写入长度（首段尚未叠加固定前缀）与段间间隔。
    fn choose(&self) -> io::Result<(usize, Vec<usize>, Vec<Duration>)> {
        let mut total = 0usize;
        let mut lengths = Vec::with_capacity(self.lens.len());
        for group in &self.lens {
            let length = if group[0] >= random_below(100)? {
                random_between(group[1], group[2])? as usize
            } else {
                0
            };
            total += length;
            lengths.push(length);
        }
        let mut gaps = Vec::with_capacity(self.gaps.len());
        for group in &self.gaps {
            let gap = if group[0] >= random_below(100)? {
                random_between(group[1], group[2])?
            } else {
                0
            };
            gaps.push(Duration::from_millis(u64::from(gap)));
        }
        Ok((total, lengths, gaps))
    }
}

struct Session {
    pfs_key: [u8; 64],
    /// 已用过的 nfsKey，用于阻止 0-RTT 重放。
    used: HashSet<[u8; 32]>,
}

enum TicketLookup {
    Valid([u8; 64]),
    Expired,
    Replayed,
}

/// 0-RTT 票据与会话；与上游相同的分钟桶惰性清理。
struct Sessions {
    sessions: HashMap<[u8; TICKET_LEN], Session>,
    tickets: VecDeque<[u8; TICKET_LEN]>,
    lasts: HashMap<i64, [u8; TICKET_LEN]>,
    last_purged: i64,
}

impl Sessions {
    fn new(now_minute: i64) -> Self {
        Self {
            sessions: HashMap::new(),
            tickets: VecDeque::new(),
            lasts: HashMap::new(),
            last_purged: now_minute,
        }
    }

    /// 与上游每分钟清理协程等价：按分钟桶删除会话。
    fn purge(&mut self, minute: i64) {
        while self.last_purged < minute {
            let target = self.last_purged + 1;
            let last = self.lasts.remove(&target);
            self.lasts.remove(&(target - 1));
            if let Some(last) = last {
                while let Some(ticket) = self.tickets.pop_front() {
                    self.sessions.remove(&ticket);
                    if ticket == last {
                        break;
                    }
                }
            }
            self.last_purged = target;
        }
    }

    fn remember(&mut self, ticket: [u8; TICKET_LEN], pfs_key: [u8; 64], minute: i64) {
        self.sessions.insert(
            ticket,
            Session {
                pfs_key,
                used: HashSet::new(),
            },
        );
        self.tickets.push_back(ticket);
        self.lasts.insert(minute, ticket);
        // 上限与重放池一致；超出时淘汰最旧票据，客户端可回退到完整握手。
        while self.tickets.len() > MAX_SESSIONS {
            if let Some(oldest) = self.tickets.pop_front() {
                self.sessions.remove(&oldest);
            }
        }
    }

    fn lookup(
        &mut self,
        ticket: &[u8; TICKET_LEN],
        nfs_key: &[u8; 32],
        replay_limit: usize,
    ) -> TicketLookup {
        let Some(session) = self.sessions.get_mut(ticket) else {
            return TicketLookup::Expired;
        };
        if session.used.contains(nfs_key) || session.used.len() >= replay_limit {
            // 无法再安全记录重放时失败关闭。
            return TicketLookup::Replayed;
        }
        session.used.insert(*nfs_key);
        TicketLookup::Valid(session.pfs_key)
    }
}

/// 一个入站的 VLESS Encryption 服务端状态。
pub(crate) struct Prepared {
    keys: Vec<KeyEntry>,
    relays_len: usize,
    xor_mode: XorMode,
    seconds_from: u64,
    seconds_to: u64,
    padding: Padding,
    sessions: Mutex<Sessions>,
    replay_limit: usize,
}

impl Prepared {
    pub(crate) fn new(config: &Decryption, replay_limit: usize) -> io::Result<Self> {
        let mut keys = Vec::with_capacity(config.keys.len());
        for key in &config.keys {
            keys.push(KeyEntry::new(key)?);
        }
        if keys.is_empty() {
            return Err(invalid("VLESS Encryption 至少需要一个认证密钥"));
        }
        // 每个密钥贡献 index + 32 字节，最后一个不再跟随哈希块。
        let relays_len = keys.iter().map(|key| key.index + 32).sum::<usize>() - 32;
        Ok(Self {
            keys,
            relays_len,
            xor_mode: config.xor_mode,
            seconds_from: config.seconds_from,
            seconds_to: config.seconds_to,
            padding: Padding::new(&config.padding_lens, &config.padding_gaps),
            sessions: Mutex::new(Sessions::new(current_minute())),
            replay_limit: replay_limit.max(1),
        })
    }

    /// 完成 1-RTT/0-RTT 握手并返回记录层。
    pub(crate) async fn accept<S>(&self, mut stream: S) -> io::Result<Encrypted<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut iv_relays = vec![0u8; IV_LEN + self.relays_len];
        stream.read_exact(&mut iv_relays).await?;
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&iv_relays[..IV_LEN]);
        let relays = &mut iv_relays[IV_LEN..];

        let mut offset = 0usize;
        let mut nfs_key = [0u8; 32];
        let mut last_ctr: Option<Ctr> = None;
        for (position, key) in self.keys.iter().enumerate() {
            if let Some(ctr) = last_ctr.as_mut() {
                // 恢复被上一密钥 CTR 混淆的下一中继区。
                ctr.apply(&mut relays[offset..offset + X25519_LEN]);
            }
            let relay = &mut relays[offset..offset + key.index];
            if self.xor_mode != XorMode::Native {
                Ctr::new(&key.public, &iv).apply(relay);
            }
            nfs_key = key.agree(relay)?;
            if position + 1 == self.keys.len() {
                break;
            }
            offset += key.index;
            let mut ctr = Ctr::new(&nfs_key, &iv);
            ctr.apply(&mut relays[offset..offset + 32]);
            if relays[offset..offset + 32] != self.keys[position + 1].hash {
                return Err(invalid("VLESS Encryption 中继哈希不匹配"));
            }
            offset += 32;
            last_ctr = Some(ctr);
        }

        let mut length_block = [0u8; ENCRYPTED_LENGTH_LEN];
        stream.read_exact(&mut length_block).await?;
        // 客户端用 AES-256-GCM 或 ChaCha20-Poly1305；解码失败即切换（与上游一致）。
        let mut use_aes = true;
        let mut nfs = derive_aead(&iv, &nfs_key, use_aes)?;
        let length_plain = match open_message(&nfs, &counter_nonce(1), &[], &length_block) {
            Ok(plain) => plain,
            Err(_) => {
                use_aes = false;
                nfs = derive_aead(&iv, &nfs_key, use_aes)?;
                open_message(&nfs, &counter_nonce(1), &[], &length_block)?
            }
        };
        if length_plain.len() != LENGTH_LEN {
            return Err(invalid("VLESS Encryption 长度块异常"));
        }
        let length = decode_length(&length_plain);
        tracing::debug!(
            event = "vless_encryption_handshake",
            length,
            "VLESS Encryption 握手长度"
        );

        if length == ENCRYPTED_TICKET_LEN {
            return self
                .accept_zero_rtt(stream, iv, &nfs, use_aes, nfs_key)
                .await;
        }
        if length < PFS_BLOCK_LEN {
            return Err(invalid("VLESS Encryption PFS 交换块过短"));
        }

        let mut pfs_block = vec![0u8; length];
        stream.read_exact(&mut pfs_block).await?;
        let pfs_plain = open_message(&nfs, &counter_nonce(2), &[], &pfs_block)?;
        if pfs_plain.len() < PFS_PUBLIC_LEN {
            return Err(invalid("VLESS Encryption PFS 公钥长度不足"));
        }

        let mut mlkem_public = [0u8; MLKEM_PUBLIC_LEN];
        mlkem_public.copy_from_slice(&pfs_plain[..MLKEM_PUBLIC_LEN]);
        let mut peer_x25519 = [0u8; X25519_LEN];
        peer_x25519.copy_from_slice(&pfs_plain[MLKEM_PUBLIC_LEN..PFS_PUBLIC_LEN]);

        let encapsulation = ml_kem::EncapsulationKey::<MlKem768>::new(&mlkem_public.into())
            .map_err(|_| invalid("VLESS Encryption PFS ML-KEM 公钥无效"))?;
        let (encapsulated, mlkem_shared) = encapsulation.encapsulate();
        let ephemeral = PrivateKey::generate(&X25519)
            .map_err(|_| invalid("VLESS Encryption 临时密钥生成失败"))?;
        let ephemeral_public = ephemeral
            .compute_public_key()
            .map_err(|_| invalid("VLESS Encryption 临时公钥推导失败"))?;
        let x25519_shared = agreement::agree(
            &ephemeral,
            UnparsedPublicKey::new(&X25519, peer_x25519),
            invalid("VLESS Encryption PFS X25519 协商失败"),
            |secret| {
                let mut key = [0u8; 32];
                key.copy_from_slice(secret);
                Ok(key)
            },
        )?;

        let mut pfs_key = [0u8; 64];
        pfs_key[..32].copy_from_slice(mlkem_shared.as_slice());
        pfs_key[32..].copy_from_slice(&x25519_shared);
        let mut united = [0u8; 96];
        united[..64].copy_from_slice(&pfs_key);
        united[64..].copy_from_slice(&nfs_key);
        let mut pfs_public = Vec::with_capacity(PFS_PUBLIC_LEN);
        pfs_public.extend_from_slice(encapsulated.as_slice());
        pfs_public.extend_from_slice(ephemeral_public.as_ref());

        // 下行上下文是服务端 PFS 公钥明文，上行上下文是客户端 PFS 公钥明文。
        let out_cipher = derive_aead(&pfs_public, &united, use_aes)?;
        let in_cipher = derive_aead(&pfs_plain[..PFS_PUBLIC_LEN], &united, use_aes)?;

        let mut ticket = [0u8; TICKET_LEN];
        random_fill(&mut ticket)?;
        let seconds = self.ticket_seconds()?;
        ticket[..LENGTH_LEN].copy_from_slice(&(seconds as u16).to_be_bytes());
        if seconds > 0 {
            self.remember(&ticket, &pfs_key);
        }

        let (padding_len, mut lengths, gaps) = self.padding.choose()?;
        // 首组 padding 由配置保证至少 35 字节；这里再防御一次，避免长度字段下溢。
        if padding_len < MIN_PADDING || lengths.is_empty() {
            return Err(invalid("VLESS Encryption padding 长度不足"));
        }
        let total = SERVER_HELLO_PREFIX + padding_len;
        let mut hello = Vec::with_capacity(total);
        hello.extend_from_slice(&seal_message(&nfs, &MAX_NONCE, &[], &pfs_public)?);
        hello.extend_from_slice(&seal_message(&out_cipher, &counter_nonce(1), &[], &ticket)?);
        let padding_body = vec![0u8; padding_len - ENCRYPTED_LENGTH_LEN - TAG_LEN];
        hello.extend_from_slice(&seal_message(
            &out_cipher,
            &counter_nonce(2),
            &[],
            &encode_length(padding_len - ENCRYPTED_LENGTH_LEN),
        )?);
        hello.extend_from_slice(&seal_message(
            &out_cipher,
            &counter_nonce(3),
            &[],
            &padding_body,
        )?);
        debug_assert_eq!(hello.len(), total);

        // 首段长度叠加固定前缀后按 padding 分组分片写出。
        if let Some(first) = lengths.first_mut() {
            *first += SERVER_HELLO_PREFIX;
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
            return Err(invalid("VLESS Encryption padding 长度不一致"));
        }
        // 消息承载（WS/gRPC/XHTTP）需要显式 flush，否则会等待客户端读取前死锁。
        stream.flush().await?;

        // 客户端 padding：长度块与实体各占一个 nonce。
        let mut block = [0u8; ENCRYPTED_LENGTH_LEN];
        stream.read_exact(&mut block).await?;
        let plain = open_message(&nfs, &counter_nonce(3), &[], &block)?;
        let client_padding = decode_length(&plain);
        let mut padding = vec![0u8; client_padding];
        stream.read_exact(&mut padding).await?;
        open_message(&nfs, &counter_nonce(4), &[], &padding)?;

        let inner = self.wrap_inner(stream, &united, &ticket, &iv, 0, 0);
        Ok(Encrypted::new(
            inner,
            Aead::from_cipher(out_cipher, united, use_aes, counter_nonce(3)),
            Aead::from_cipher(in_cipher, united, use_aes, [0u8; 12]),
            None,
        ))
    }

    async fn accept_zero_rtt<S>(
        &self,
        mut stream: S,
        iv: [u8; IV_LEN],
        nfs: &Cipher,
        use_aes: bool,
        nfs_key: [u8; 32],
    ) -> io::Result<Encrypted<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if self.seconds_from == 0 && self.seconds_to == 0 {
            return Err(invalid("VLESS Encryption 未启用 0-RTT"));
        }
        let mut encrypted_ticket = [0u8; ENCRYPTED_TICKET_LEN];
        stream.read_exact(&mut encrypted_ticket).await?;
        let plain = open_message(nfs, &counter_nonce(2), &[], &encrypted_ticket)?;
        if plain.len() != TICKET_LEN {
            return Err(invalid("VLESS Encryption 票据长度异常"));
        }
        let mut ticket = [0u8; TICKET_LEN];
        ticket.copy_from_slice(&plain);

        // 锁不得跨 await：先取出查找结果，再处理需要写回噪声的分支。
        let lookup = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| io::Error::other("VLESS Encryption 会话锁失效"))?;
            sessions.purge(current_minute());
            sessions.lookup(&ticket, &nfs_key, self.replay_limit)
        };
        let pfs_key = match lookup {
            TicketLookup::Valid(key) => {
                tracing::debug!(
                    event = "vless_encryption_0rtt",
                    "VLESS Encryption 0-RTT 票据已接受"
                );
                key
            }
            TicketLookup::Replayed => {
                return Err(invalid("VLESS Encryption 检测到 0-RTT 重放"));
            }
            TicketLookup::Expired => {
                // 与上游一致：回一段随机噪声让客户端发起完整握手。
                let length = random_between(1279, 2279)? as usize;
                let mut noise = vec![0u8; length];
                loop {
                    random_fill(&mut noise)?;
                    if decode_header(&noise[..RECORD_HEADER]).is_err() {
                        break;
                    }
                }
                stream.write_all(&noise).await?;
                return Err(invalid("VLESS Encryption 票据已过期"));
            }
        };

        let mut united = [0u8; 96];
        united[..64].copy_from_slice(&pfs_key);
        united[64..].copy_from_slice(&nfs_key);

        let mut pre_write = [0u8; 16];
        random_fill(&mut pre_write)?;
        let out_cipher = derive_aead(&pre_write, &united, use_aes)?;
        // 上行上下文固定为客户端票据密文本身。
        let in_cipher = derive_aead(&encrypted_ticket, &united, use_aes)?;

        // 0-RTT 前缀必须在握手阶段立即写出：客户端会先读走这 16 字节再构造
        // XOR 层，若推迟到首条记录会互相等待。
        stream.write_all(&pre_write).await?;
        stream.flush().await?;
        let inner = self.wrap_inner(stream, &united, &pre_write, &iv, 0, 0);
        Ok(Encrypted::new(
            inner,
            Aead::from_cipher(out_cipher, united, use_aes, [0u8; 12]),
            Aead::from_cipher(in_cipher, united, use_aes, [0u8; 12]),
            None,
        ))
    }

    /// `random` 模式在记录层之下包裹 XOR 流；输出 IV 与跳过长度因握手方式而异。
    fn wrap_inner<S>(
        &self,
        stream: S,
        united: &[u8; 96],
        out_iv: &[u8; IV_LEN],
        in_iv: &[u8; IV_LEN],
        out_skip: usize,
        in_skip: usize,
    ) -> Inner<S> {
        if self.xor_mode == XorMode::Random {
            Inner::Xor(XorStream::new(
                stream,
                Ctr::new(united, out_iv),
                Ctr::new(united, in_iv),
                out_skip,
                in_skip,
            ))
        } else {
            Inner::Plain(stream)
        }
    }

    fn ticket_seconds(&self) -> io::Result<u64> {
        if self.seconds_to == 0 {
            // 上游：from * RandBetween(50, 100) / 100，即 50%~99%。
            let percent = random_between(50, 100)?;
            Ok(self.seconds_from * u64::from(percent) / 100)
        } else {
            Ok(u64::from(random_between(
                self.seconds_from as u32,
                self.seconds_to as u32,
            )?))
        }
    }

    fn remember(&self, ticket: &[u8; TICKET_LEN], pfs_key: &[u8; 64]) {
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        sessions.purge(current_minute());
        let keep = self.seconds_from.max(self.seconds_to);
        // 与上游相同的分钟桶：票据在 now + 有效期 之后再多保留两个桶。
        let target = current_seconds().saturating_add(keep) / 60 + 2;
        sessions.remember(*ticket, *pfs_key, target as i64);
    }
}

// --------------------------------------------------------------------------
// 密码原语封装
// --------------------------------------------------------------------------

/// AES-256-CTR，只用于 `random` 模式混淆记录头。
struct Ctr(Ctr128BE<aes::Aes256>);

impl Ctr {
    fn new(material: &[u8], iv: &[u8; IV_LEN]) -> Self {
        let key = blake3::derive_key(CTR_CONTEXT, material);
        Self(Ctr128BE::new(&key.into(), &(*iv).into()))
    }

    fn apply(&mut self, buffer: &mut [u8]) {
        self.0.apply_keystream(buffer);
    }
}

enum Cipher {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Cipher {
    fn new(use_aes: bool, key: &[u8; 32]) -> io::Result<Self> {
        if use_aes {
            Aes256Gcm::new_from_slice(key)
                .map(|cipher| Self::Aes(Box::new(cipher)))
                .map_err(|_| invalid("VLESS Encryption AEAD 密钥长度非法"))
        } else {
            ChaCha20Poly1305::new_from_slice(key)
                .map(|cipher| Self::ChaCha(Box::new(cipher)))
                .map_err(|_| invalid("VLESS Encryption AEAD 密钥长度非法"))
        }
    }

    fn seal(
        &self,
        nonce: &[u8; 12],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> io::Result<[u8; TAG_LEN]> {
        let nonce: Nonce<Aes256Gcm> = (*nonce).into();
        let produced = match self {
            Self::Aes(cipher) => {
                cipher.encrypt_inout_detached(&nonce, associated_data, buffer.into())
            }
            Self::ChaCha(cipher) => {
                cipher.encrypt_inout_detached(&nonce, associated_data, buffer.into())
            }
        }
        .map_err(|_| io::Error::other("VLESS Encryption 加密失败"))?;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&produced);
        Ok(tag)
    }

    fn open(
        &self,
        nonce: &[u8; 12],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> io::Result<()> {
        let nonce: Nonce<Aes256Gcm> = (*nonce).into();
        let tag: Tag<Aes256Gcm> = (*tag).into();
        match self {
            Self::Aes(cipher) => {
                cipher.decrypt_inout_detached(&nonce, associated_data, buffer.into(), &tag)
            }
            Self::ChaCha(cipher) => {
                cipher.decrypt_inout_detached(&nonce, associated_data, buffer.into(), &tag)
            }
        }
        .map_err(|_| invalid("VLESS Encryption 认证失败"))
    }
}

fn seal_message(
    cipher: &Cipher,
    nonce: &[u8; 12],
    associated_data: &[u8],
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let mut buffer = plaintext.to_vec();
    let tag = cipher.seal(nonce, associated_data, &mut buffer)?;
    buffer.extend_from_slice(&tag);
    Ok(buffer)
}

/// 解密并返回明文；不修改调用方缓冲区。
fn open_message(
    cipher: &Cipher,
    nonce: &[u8; 12],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    if ciphertext.len() < TAG_LEN {
        return Err(invalid("VLESS Encryption 密文过短"));
    }
    let mut buffer = ciphertext.to_vec();
    let length = buffer.len();
    let (body, tag) = buffer.split_at_mut(length - TAG_LEN);
    let tag: [u8; TAG_LEN] = tag.try_into().expect("标签长度已校验");
    cipher.open(nonce, associated_data, body, &tag)?;
    buffer.truncate(length - TAG_LEN);
    Ok(buffer)
}

/// 记录层 AEAD：12 字节大端计数器，首次使用 1；全 0xFF 后用整条记录重密钥。
struct Aead {
    cipher: Cipher,
    united: [u8; 96],
    use_aes: bool,
    nonce: [u8; 12],
    ops: u64,
}

impl Aead {
    fn from_cipher(cipher: Cipher, united: [u8; 96], use_aes: bool, nonce: [u8; 12]) -> Self {
        Self {
            cipher,
            united,
            use_aes,
            nonce,
            ops: 0,
        }
    }

    fn advance(&mut self) -> io::Result<()> {
        if self.ops >= MAX_AEAD_OPS {
            return Err(io::Error::other("VLESS Encryption 记录密钥用量超限"));
        }
        self.ops += 1;
        increment_nonce(&mut self.nonce);
        Ok(())
    }

    fn rekey(&mut self, context: &[u8]) -> io::Result<()> {
        self.cipher = derive_aead(context, &self.united, self.use_aes)?;
        self.nonce = [0u8; 12];
        Ok(())
    }

    fn seal(&mut self, header: &[u8; RECORD_HEADER], body: &mut [u8]) -> io::Result<[u8; TAG_LEN]> {
        let rekey = self.nonce == MAX_NONCE;
        self.advance()?;
        let tag = self.cipher.seal(&self.nonce, header, body)?;
        if rekey {
            let mut context = Vec::with_capacity(RECORD_HEADER + body.len() + TAG_LEN);
            context.extend_from_slice(header);
            context.extend_from_slice(body);
            context.extend_from_slice(&tag);
            self.rekey(&context)?;
        }
        Ok(tag)
    }

    fn open(
        &mut self,
        header: &[u8; RECORD_HEADER],
        body: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> io::Result<()> {
        let rekey = self.nonce == MAX_NONCE;
        // 重密钥上下文使用密文，必须在解密前取走。
        let context = if rekey {
            let mut context = Vec::with_capacity(RECORD_HEADER + body.len() + TAG_LEN);
            context.extend_from_slice(header);
            context.extend_from_slice(body);
            context.extend_from_slice(tag);
            Some(context)
        } else {
            None
        };
        self.advance()?;
        self.cipher.open(&self.nonce, header, body, tag)?;
        if let Some(context) = context {
            self.rekey(&context)?;
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------
// 记录层流
// --------------------------------------------------------------------------

/// 记录层之下的可选 XOR 混淆。
#[allow(clippy::large_enum_variant)] // 每个连接构造一次，热路径只匹配。
enum Inner<S> {
    Plain(S),
    Xor(XorStream<S>),
}

impl<S: AsyncRead + Unpin> AsyncRead for Inner<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Xor(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Inner<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Xor(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Xor(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Xor(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// 与上游 `XorConn` 相同：只用 CTR 混淆 5 字节记录头，并按头部长度跳过密文。
struct XorStream<S> {
    inner: S,
    out: Ctr,
    peer: Ctr,
    out_skip: usize,
    out_header: [u8; RECORD_HEADER],
    out_header_len: usize,
    in_skip: usize,
    in_header: [u8; RECORD_HEADER],
    in_header_len: usize,
    pending: Vec<u8>,
    pending_pos: usize,
    read_buffer: Vec<u8>,
    read_len: usize,
    read_pos: usize,
}

impl<S> XorStream<S> {
    fn new(inner: S, out: Ctr, peer: Ctr, out_skip: usize, in_skip: usize) -> Self {
        Self {
            inner,
            out,
            peer,
            out_skip,
            out_header: [0u8; RECORD_HEADER],
            out_header_len: 0,
            in_skip,
            in_header: [0u8; RECORD_HEADER],
            in_header_len: 0,
            pending: Vec::new(),
            pending_pos: 0,
            read_buffer: vec![0u8; MAX_RECORD],
            read_len: 0,
            read_pos: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> XorStream<S> {
    /// 把已缓冲的混淆后字节尽量写出；返回是否全部写完。
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(written)) => self.pending_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

/// 与上游 `XorConn` 的逐段混淆逻辑一致：只混淆记录头，按头部声明跳过密文。
///
/// `outgoing` 表示 `data` 在调用时是明文（写路径）还是密文（读路径）。跳过
/// 长度必须取自明文头，因此写路径要在 XOR 前组合头部，读路径在 XOR 后组合。
fn xor_apply(
    ctr: &mut Ctr,
    skip: &mut usize,
    header: &mut [u8; RECORD_HEADER],
    header_len: &mut usize,
    data: &mut [u8],
    outgoing: bool,
) {
    let mut position = 0usize;
    while position < data.len() {
        let remaining = data.len() - position;
        if remaining <= *skip {
            *skip -= remaining;
            break;
        }
        position += *skip;
        *skip = 0;
        let need = RECORD_HEADER - *header_len;
        if data.len() - position < need {
            let tail = &mut data[position..];
            if outgoing {
                header[*header_len..*header_len + tail.len()].copy_from_slice(tail);
            }
            ctr.apply(tail);
            if !outgoing {
                header[*header_len..*header_len + tail.len()].copy_from_slice(tail);
            }
            *header_len += tail.len();
            break;
        }
        let mut combined = [0u8; RECORD_HEADER];
        if outgoing {
            combined[..*header_len].copy_from_slice(&header[..*header_len]);
            combined[*header_len..].copy_from_slice(&data[position..position + need]);
        }
        ctr.apply(&mut data[position..position + need]);
        if !outgoing {
            combined[..*header_len].copy_from_slice(&header[..*header_len]);
            combined[*header_len..].copy_from_slice(&data[position..position + need]);
        }
        *skip = skip_header_len(&combined);
        *header_len = 0;
        position += need;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for XorStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_pos < this.read_len {
                let available = this.read_len - this.read_pos;
                let take = available.min(buf.remaining());
                buf.put_slice(&this.read_buffer[this.read_pos..this.read_pos + take]);
                this.read_pos += take;
                return Poll::Ready(Ok(()));
            }
            let mut staged = ReadBuf::new(&mut this.read_buffer);
            match Pin::new(&mut this.inner).poll_read(cx, &mut staged) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let filled = staged.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    xor_apply(
                        &mut this.peer,
                        &mut this.in_skip,
                        &mut this.in_header,
                        &mut this.in_header_len,
                        &mut this.read_buffer[..filled],
                        false,
                    );
                    this.read_len = filled;
                    this.read_pos = 0;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for XorStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.pending_pos < this.pending.len() {
            match this.flush_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        let take = buf.len().min(MAX_PLAINTEXT);
        this.pending.extend_from_slice(&buf[..take]);
        xor_apply(
            &mut this.out,
            &mut this.out_skip,
            &mut this.out_header,
            &mut this.out_header_len,
            &mut this.pending,
            true,
        );
        match this.flush_pending(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            // 已接受混淆后的字节；未写完的部分留到下一次写或 flush。
            _ => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
        }
    }
}

#[derive(Clone, Copy)]
enum ReadState {
    Header { filled: usize },
    Body { filled: usize },
    Ready,
}

struct RecordReader {
    cipher: Aead,
    header: [u8; RECORD_HEADER],
    state: ReadState,
    body: Vec<u8>,
    body_len: usize,
    body_pos: usize,
}

impl RecordReader {
    fn new(cipher: Aead) -> Self {
        Self {
            cipher,
            header: [0u8; RECORD_HEADER],
            state: ReadState::Header { filled: 0 },
            body: Vec::new(),
            body_len: 0,
            body_pos: 0,
        }
    }
}

struct RecordWriter {
    cipher: Aead,
    pre_write: Option<Vec<u8>>,
    pending: Vec<u8>,
    pending_pos: usize,
}

impl RecordWriter {
    fn new(cipher: Aead, pre_write: Option<Vec<u8>>) -> Self {
        Self {
            cipher,
            pre_write,
            pending: Vec::new(),
            pending_pos: 0,
        }
    }

    fn build(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut record = Vec::with_capacity(RECORD_HEADER + plaintext.len() + TAG_LEN + 16);
        if let Some(pre_write) = self.pre_write.take() {
            record.extend_from_slice(&pre_write);
        }
        let start = record.len();
        let header = record_header(plaintext.len() + TAG_LEN);
        record.extend_from_slice(&header);
        record.extend_from_slice(plaintext);
        let tag = {
            let body = &mut record[start + RECORD_HEADER..];
            self.cipher.seal(&header, body)?
        };
        record.extend_from_slice(&tag);
        self.pending = record;
        self.pending_pos = 0;
        Ok(())
    }

    /// 把待写记录尽量推给下层；返回是否全部写完。
    fn flush_pending<S: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut Inner<S>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut *inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(written)) => self.pending_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

/// 完成 VLESS Encryption 握手后的双向流。
pub(crate) struct Encrypted<S> {
    inner: Inner<S>,
    reader: RecordReader,
    writer: RecordWriter,
}

impl<S> Encrypted<S> {
    fn new(inner: Inner<S>, out_cipher: Aead, in_cipher: Aead, pre_write: Option<Vec<u8>>) -> Self {
        Self {
            inner,
            reader: RecordReader::new(in_cipher),
            writer: RecordWriter::new(out_cipher, pre_write),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Encrypted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 读之前尽力把已缓冲的记录推出去，避免只写不读的调用方让数据滞留；
        // `Pending` 只注册唤醒，不阻塞读。
        if this.writer.pending_pos < this.writer.pending.len()
            && let Poll::Ready(Err(error)) = this.writer.flush_pending(&mut this.inner, cx)
        {
            return Poll::Ready(Err(error));
        }
        loop {
            match this.reader.state {
                ReadState::Ready => {
                    let available = this.reader.body_len - this.reader.body_pos;
                    if available == 0 {
                        this.reader.state = ReadState::Header { filled: 0 };
                        continue;
                    }
                    let take = available.min(buf.remaining());
                    let start = this.reader.body_pos;
                    buf.put_slice(&this.reader.body[start..start + take]);
                    this.reader.body_pos += take;
                    return Poll::Ready(Ok(()));
                }
                ReadState::Header { filled } => {
                    let mut staged = ReadBuf::new(&mut this.reader.header[filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut staged) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = staged.filled().len();
                            if read == 0 {
                                return if filled == 0 {
                                    Poll::Ready(Ok(()))
                                } else {
                                    Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                                };
                            }
                            let filled = filled + read;
                            if filled < RECORD_HEADER {
                                this.reader.state = ReadState::Header { filled };
                                continue;
                            }
                            let length = decode_header(&this.reader.header)?;
                            this.reader.body.resize(length, 0);
                            this.reader.body_len = length;
                            this.reader.body_pos = 0;
                            this.reader.state = ReadState::Body { filled: 0 };
                        }
                    }
                }
                ReadState::Body { filled } => {
                    let mut staged = ReadBuf::new(&mut this.reader.body[filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut staged) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = staged.filled().len();
                            if read == 0 {
                                return Poll::Ready(Err(io::Error::from(
                                    io::ErrorKind::UnexpectedEof,
                                )));
                            }
                            let filled = filled + read;
                            this.reader.state = ReadState::Body { filled };
                            if filled < this.reader.body_len {
                                continue;
                            }
                            let header = this.reader.header;
                            let length = this.reader.body_len;
                            let (body, tag) = this.reader.body.split_at_mut(length - TAG_LEN);
                            let tag: [u8; TAG_LEN] = tag.try_into().expect("标签长度已校验");
                            this.reader.cipher.open(&header, body, &tag)?;
                            this.reader.body_len = length - TAG_LEN;
                            this.reader.body_pos = 0;
                            this.reader.state = ReadState::Ready;
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Encrypted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.writer.pending_pos < this.writer.pending.len() {
            match this.writer.flush_pending(&mut this.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MAX_PLAINTEXT);
        if let Err(error) = this.writer.build(&buf[..take]) {
            return Poll::Ready(Err(error));
        }
        match this.writer.flush_pending(&mut this.inner, cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            // 已加密并接受，未写完的部分留到下一次写或 flush。
            _ => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.writer.flush_pending(&mut this.inner, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.writer.flush_pending(&mut this.inner, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
        }
    }
}

mod client;

pub(crate) use client::ClientPrepared;

#[cfg(test)]
mod tests;
