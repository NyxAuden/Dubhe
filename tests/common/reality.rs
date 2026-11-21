//! 独立、仅回环的 REALITY 测试端；不调用生产 auth/hello/certificate/target。
//! 两遍构造均由真实 rustls 编码 CH，第二遍的密文 SID 从一开始就在客户端 transcript 中。
//! 本文件的互测是接口/回归证据，不是官方客户端兼容或独立金样。
#![allow(dead_code)]

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, anyhow, ensure};
use aws_lc_rs::{agreement, hkdf, hmac, kem, rand, signature};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, NamedGroup, ProtocolVersion,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ActiveKeyExchange, SecureRandom, SharedSecret, SupportedKxGroup},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    fmt, io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub const SERVER_PRIVATE_KEY: [u8; 32] = [0x59; 32];
pub const SHORT_ID: [u8; 8] = [0x81, 0x72, 0x63, 0x54, 0x45, 0x36, 0x27, 0x18];
pub const UUID: &str = "11111111-1111-1111-1111-111111111111";
pub const ID: [u8; 16] = [0x11; 16];
const DEADLINE: Duration = Duration::from_secs(3);

fn tls_error() -> Error {
    Error::General("独立 REALITY 测试端验证失败".into())
}
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    rand::fill(&mut bytes).expect("测试随机源");
    bytes
}
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    agreement::PrivateKey::from_private_key(&agreement::X25519, private)
        .unwrap()
        .compute_public_key()
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap()
}
fn x25519(private: &agreement::PrivateKey, peer: &[u8]) -> Result<Vec<u8>, Error> {
    agreement::agree(
        private,
        agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
        tls_error(),
        |secret| Ok(secret.to_vec()),
    )
}
struct Length32;
impl hkdf::KeyType for Length32 {
    fn len(&self) -> usize {
        32
    }
}
fn auth_key(
    private: &agreement::PrivateKey,
    server_public: &[u8; 32],
    random: &[u8; 32],
) -> Result<[u8; 32]> {
    let shared = x25519(private, server_public)?;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &random[..20]).extract(&shared);
    let mut key = [0; 32];
    prk.expand(&[b"REALITY"], Length32)
        .map_err(|_| anyhow!("HKDF expand"))?
        .fill(&mut key)
        .map_err(|_| anyhow!("HKDF fill"))?;
    Ok(key)
}

/// 测试配置不实现 Debug，避免失败诊断输出认证材料。
pub struct ClientOptions {
    pub server_public_key: [u8; 32],
    pub server_name: String,
    pub short_id: [u8; 8],
    pub version: [u8; 3],
    pub reserved: u8,
    pub unix_seconds: u32,
    pub ordinary_share: bool,
    pub mldsa65_public_key: Option<Vec<u8>>,
}
impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            server_public_key: public_key(&SERVER_PRIVATE_KEY),
            server_name: "localhost".into(),
            short_id: SHORT_ID,
            version: [26, 10, 31],
            reserved: 0,
            unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .try_into()
                .unwrap(),
            ordinary_share: true,
            mldsa65_public_key: None,
        }
    }
}

struct Material {
    hybrid: agreement::PrivateKey,
    ordinary: agreement::PrivateKey,
    kem: kem::DecapsulationKey,
    hybrid_public: Vec<u8>,
    ordinary_public: Vec<u8>,
    offer_ordinary: bool,
}
impl Material {
    fn new(offer_ordinary: bool) -> Result<Self> {
        let hybrid = agreement::PrivateKey::from_private_key(&agreement::X25519, &random::<32>())
            .map_err(|_| anyhow!("X25519 import"))?;
        let ordinary = agreement::PrivateKey::from_private_key(&agreement::X25519, &random::<32>())
            .map_err(|_| anyhow!("X25519 import"))?;
        let kem = kem::DecapsulationKey::generate(&kem::ML_KEM_768)
            .map_err(|_| anyhow!("ML-KEM generate"))?;
        let mut hybrid_public = kem
            .encapsulation_key()
            .map_err(|_| anyhow!("ML-KEM public"))?
            .key_bytes()
            .map_err(|_| anyhow!("ML-KEM encoding"))?
            .as_ref()
            .to_vec();
        hybrid_public.extend(
            hybrid
                .compute_public_key()
                .map_err(|_| anyhow!("X25519 public"))?
                .as_ref(),
        );
        let ordinary_public = ordinary
            .compute_public_key()
            .map_err(|_| anyhow!("X25519 public"))?
            .as_ref()
            .to_vec();
        ensure!(hybrid_public[1184..] != ordinary_public, "测试公钥必须不同");
        Ok(Self {
            hybrid,
            ordinary,
            kem,
            hybrid_public,
            ordinary_public,
            offer_ordinary,
        })
    }
}

// &'static provider 接点只在同步 ClientConnection::new 期间读取线程局部上下文。
// 不泄漏 Box，不安装全局 provider；握手中的 Active 持有自己的 Arc。
struct Construction {
    material: Arc<Material>,
    random: VecDeque<Vec<u8>>,
}
thread_local! { static CONSTRUCTION: RefCell<Option<Construction>> = const { RefCell::new(None) }; }
struct ConstructionGuard;
impl Drop for ConstructionGuard {
    fn drop(&mut self) {
        CONSTRUCTION.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
#[derive(Debug)]
struct ScriptedRandom;
static SCRIPTED_RANDOM: ScriptedRandom = ScriptedRandom;
impl SecureRandom for ScriptedRandom {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        CONSTRUCTION.with(|slot| {
            let mut slot = slot.borrow_mut();
            let source = slot
                .as_mut()
                .and_then(|context| context.random.pop_front())
                .ok_or(rustls::crypto::GetRandomFailed)?;
            if source.len() != bytes.len() {
                return Err(rustls::crypto::GetRandomFailed);
            }
            bytes.copy_from_slice(&source);
            Ok(())
        })
    }
}
#[derive(Debug)]
struct ReplayHybrid;
static REPLAY_HYBRID: ReplayHybrid = ReplayHybrid;
impl SupportedKxGroup for ReplayHybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        CONSTRUCTION.with(|slot| {
            let material = slot
                .borrow()
                .as_ref()
                .ok_or_else(tls_error)?
                .material
                .clone();
            Ok(Box::new(ActiveHybrid(material)) as Box<dyn ActiveKeyExchange>)
        })
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}
struct ActiveHybrid(Arc<Material>);
impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if peer.len() != 1120 {
            return Err(tls_error());
        }
        let pq = self
            .0
            .kem
            .decapsulate((&peer[..1088]).into())
            .map_err(|_| tls_error())?;
        let mut secret = pq.as_ref().to_vec();
        secret.extend(x25519(&self.0.hybrid, &peer[1088..])?);
        Ok(secret.into())
    }
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        self.0
            .offer_ordinary
            .then_some((NamedGroup::X25519, self.0.ordinary_public.as_slice()))
    }
    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        Ok(x25519(&self.0.ordinary, peer)?.into())
    }
    fn pub_key(&self) -> &[u8] {
        &self.0.hybrid_public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}

#[derive(Default, Debug)]
pub struct WireLog {
    pub raw_ch: Vec<u8>,
    pub raw_sh: Vec<u8>,
    pub sent_record_lengths: Vec<usize>,
    pub received_record_lengths: Vec<usize>,
}
/// 可人工驱动的真实客户端，已排出且保存首个 CH，未做任何网络 IO。
pub struct PreparedClient {
    pub tls: ClientConnection,
    pub initial_wire: Vec<u8>,
    pub raw_ch: Vec<u8>,
    pub log: Arc<Mutex<WireLog>>,
}
impl PreparedClient {
    pub fn new(options: ClientOptions) -> Result<Self> {
        let material = Arc::new(Material::new(options.ordinary_share)?);
        let ch_random = random::<32>();
        let shuffle = random::<2>();
        let auth_private = if options.ordinary_share {
            &material.ordinary
        } else {
            &material.hybrid
        };
        let key = auth_key(auth_private, &options.server_public_key, &ch_random)?;
        let log = Arc::new(Mutex::new(WireLog::default()));
        let verifier = Arc::new(RealityVerifier {
            key,
            mldsa_public: options.mldsa65_public_key,
            log: log.clone(),
        });
        let name: ServerName<'static> = options.server_name.try_into()?;
        let (_discarded, zero_wire) = construct(
            material.clone(),
            [0; 32],
            ch_random,
            shuffle,
            name.clone(),
            verifier.clone(),
        )?;
        let zero_ch = client_hello(&zero_wire)?;
        let sid = session_id_range(&zero_ch)?;
        ensure!(zero_ch[sid.clone()] == [0; 32], "首遍 SID 未置零");
        let mut plain = options.version.to_vec();
        plain.push(options.reserved);
        plain.extend(options.unix_seconds.to_be_bytes());
        plain.extend(options.short_id);
        let encrypted = Aes256Gcm::new((&key).into())
            .encrypt(
                <&[u8; 12]>::try_from(&ch_random[20..]).unwrap().into(),
                Payload {
                    msg: &plain,
                    aad: &zero_ch,
                },
            )
            .map_err(|_| anyhow!("测试 SID encryption"))?;
        let (tls, initial_wire) = construct(
            material,
            encrypted.try_into().unwrap(),
            ch_random,
            shuffle,
            name,
            verifier,
        )?;
        let raw_ch = client_hello(&initial_wire)?;
        let mut compare = raw_ch.clone();
        compare[sid].fill(0);
        ensure!(compare == zero_ch, "两遍 CH 除 SID 外必须逐字节一致");
        log.lock().unwrap().raw_ch = raw_ch.clone();
        Ok(Self {
            tls,
            initial_wire,
            raw_ch,
            log,
        })
    }
    pub async fn begin(self, address: SocketAddr) -> Result<Outer> {
        ensure!(address.ip().is_loopback(), "测试端只准回环地址");
        let mut outer = Outer {
            io: TcpStream::connect(address).await?,
            tls: self.tls,
            log: self.log,
            sh_buffer: Vec::new(),
        };
        outer.io.write_all(&self.initial_wire).await?;
        outer
            .log
            .lock()
            .unwrap()
            .sent_record_lengths
            .extend(record_lengths(&self.initial_wire)?);
        Ok(outer)
    }
    pub async fn connect(self, address: SocketAddr) -> Result<Outer> {
        let mut outer = self.begin(address).await?;
        timeout(DEADLINE, outer.handshake())
            .await
            .context("独立客户端握手超时")??;
        Ok(outer)
    }
}
fn construct(
    material: Arc<Material>,
    sid: [u8; 32],
    random: [u8; 32],
    shuffle: [u8; 2],
    name: ServerName<'static>,
    verifier: Arc<RealityVerifier>,
) -> Result<(ClientConnection, Vec<u8>)> {
    CONSTRUCTION.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.is_none(), "构造上下文不能嵌套");
        *slot = Some(Construction {
            material,
            random: VecDeque::from([sid.to_vec(), shuffle.to_vec(), random.to_vec()]),
        });
    });
    let _guard = ConstructionGuard;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.secure_random = &SCRIPTED_RANDOM;
    provider.kx_groups = vec![&REPLAY_HYBRID, rustls::crypto::aws_lc_rs::kx_group::X25519];
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    let mut tls = ClientConnection::new(Arc::new(config), name)?;
    ensure!(
        CONSTRUCTION.with(|slot| slot.borrow().as_ref().unwrap().random.is_empty()),
        "随机脚本未耗尽"
    );
    let wire = client_output(&mut tls)?;
    Ok((tls, wire))
}
fn client_output(tls: &mut ClientConnection) -> io::Result<Vec<u8>> {
    let mut wire = Vec::new();
    while tls.wants_write() {
        tls.write_tls(&mut wire)?;
    }
    Ok(wire)
}

/// 手动单 record 驱动，保持 Vision Direct 后的 raw 字节不被外层预读。
pub struct Outer {
    pub io: TcpStream,
    pub tls: ClientConnection,
    pub log: Arc<Mutex<WireLog>>,
    sh_buffer: Vec<u8>,
}
impl Outer {
    pub async fn handshake(&mut self) -> Result<()> {
        while self.tls.is_handshaking() {
            self.flush_tls().await?;
            if self.tls.is_handshaking() {
                self.record().await?;
            }
        }
        self.flush_tls().await
    }
    pub async fn flush_tls(&mut self) -> Result<()> {
        let wire = client_output(&mut self.tls)?;
        self.log
            .lock()
            .unwrap()
            .sent_record_lengths
            .extend(record_lengths(&wire)?);
        self.io.write_all(&wire).await?;
        Ok(())
    }
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        io::Write::write_all(&mut self.tls.writer(), data)?;
        self.flush_tls().await
    }
    pub async fn record(&mut self) -> Result<()> {
        let wire = raw_record(&mut self.io).await?;
        {
            let mut log = self.log.lock().unwrap();
            log.received_record_lengths.push(wire.len());
            if wire[0] == 22 && log.raw_sh.is_empty() {
                self.sh_buffer.extend(&wire[5..]);
                ensure!(self.sh_buffer.len() <= 65536, "测试 SH 上限");
                if self.sh_buffer.len() >= 4 {
                    let size = 4 + u24(&self.sh_buffer[1..4]);
                    if self.sh_buffer.len() >= size {
                        ensure!(self.sh_buffer[0] == 2, "首消息不是 SH");
                        log.raw_sh = self.sh_buffer[..size].to_vec();
                    }
                }
            }
        }
        let mut bytes = wire.as_slice();
        while !bytes.is_empty() {
            ensure!(self.tls.read_tls(&mut bytes)? > 0, "客户端 TLS 读取未推进");
            self.tls.process_new_packets()?;
        }
        Ok(())
    }
    pub async fn plain(&mut self, length: usize) -> Result<Vec<u8>> {
        timeout(DEADLINE, async {
            let mut plain = vec![0; length];
            let mut used = 0;
            while used < length {
                match io::Read::read(&mut self.tls.reader(), &mut plain[used..]) {
                    Ok(0) => return Err(anyhow!("TLS 明文提前 EOF")),
                    Ok(n) => used += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.record().await?;
                        self.flush_tls().await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(plain)
        })
        .await
        .context("测试明文读取超时")?
    }
    pub async fn close_notify(&mut self) -> Result<()> {
        self.tls.send_close_notify();
        self.flush_tls().await?;
        self.io.shutdown().await?;
        Ok(())
    }
}

pub async fn raw_record<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    timeout(DEADLINE, async {
        let mut header = [0; 5];
        reader.read_exact(&mut header).await?;
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        ensure!(length <= 18432, "测试 record 上限");
        let mut wire = header.to_vec();
        wire.resize(5 + length, 0);
        reader.read_exact(&mut wire[5..]).await?;
        Ok(wire)
    })
    .await
    .context("测试 record 超时")?
}
fn u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}
pub fn record_lengths(wire: &[u8]) -> Result<Vec<usize>> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(wire);
    while !cursor.empty() {
        let header = cursor.take(5)?;
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        cursor.take(length)?;
        out.push(length + 5);
    }
    Ok(out)
}
pub fn client_hello(wire: &[u8]) -> Result<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut cursor = Cursor::new(wire);
    while !cursor.empty() {
        let header = cursor.take(5)?;
        let body = cursor.take(usize::from(u16::from_be_bytes([header[3], header[4]])))?;
        ensure!(header[0] == 22, "CH record type");
        handshake.extend(body);
        ensure!(handshake.len() <= 65536, "CH size");
        if handshake.len() >= 4 {
            ensure!(handshake[0] == 1, "CH handshake type");
            let length = u24(&handshake[1..4]) + 4;
            if handshake.len() >= length {
                return Ok(handshake[..length].to_vec());
            }
        }
    }
    Err(anyhow!("CH 不完整"))
}
pub fn session_id_range(raw_ch: &[u8]) -> Result<std::ops::Range<usize>> {
    let mut cursor = Cursor::new(raw_ch);
    ensure!(cursor.u8()? == 1, "CH type");
    let length = u24(cursor.take(3)?);
    ensure!(length == raw_ch.len() - 4, "CH length");
    cursor.take(2 + 32)?;
    ensure!(cursor.u8()? == 32, "SID length");
    let start = cursor.pos;
    cursor.take(32)?;
    Ok(start..cursor.pos)
}
/// 独立解析 CH 的 key_share，仅供断言原始线字节，不调用生产 parser。
pub fn client_shares(raw_ch: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let sid = session_id_range(raw_ch)?;
    let mut cursor = Cursor::new(&raw_ch[sid.end..]);
    let suite_len = cursor.u16()?;
    cursor.take(suite_len)?;
    let compression_len = usize::from(cursor.u8()?);
    cursor.take(compression_len)?;
    let extension_len = cursor.u16()?;
    let mut extensions = Cursor::new(cursor.take(extension_len)?);
    ensure!(cursor.empty(), "CH trailing bytes");
    while !extensions.empty() {
        let typ = extensions.u16()?;
        let len = extensions.u16()?;
        let body = extensions.take(len)?;
        if typ == 51 {
            let mut vector = Cursor::new(body);
            let len = vector.u16()?;
            let mut shares = Cursor::new(vector.take(len)?);
            ensure!(vector.empty(), "share extension trailing");
            let mut out = Vec::new();
            while !shares.empty() {
                let group = shares.u16()?;
                let len = shares.u16()?;
                out.push((group.try_into().unwrap(), shares.take(len)?.to_vec()));
            }
            return Ok(out);
        }
    }
    Err(anyhow!("缺少 key_share"))
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).context("测试字段溢出")?;
        let bytes = self.bytes.get(self.pos..end).context("测试字段截断")?;
        self.pos = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<usize> {
        Ok(usize::from(u16::from_be_bytes(
            self.take(2)?.try_into().unwrap(),
        )))
    }
    fn empty(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

// yasna 负责 DER 长度、类型、BIT STRING 和上下文标签；不盲 patch 固定偏移。
struct ParsedCertificate {
    public: Vec<u8>,
    signature: Vec<u8>,
    extensions: Vec<(Vec<u64>, Vec<u8>)>,
}
fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate> {
    use yasna::{ASN1Error, ASN1ErrorKind, Tag};
    let invalid = || ASN1Error::new(ASN1ErrorKind::Invalid);
    let ed25519 = yasna::models::ObjectIdentifier::from_slice(&[1, 3, 101, 112]);
    let (tbs, signature) = yasna::parse_der(der, |reader| {
        reader.read_sequence(|reader| {
            let tbs = reader.next().read_der()?;
            reader.next().read_sequence(|reader| {
                if reader.next().read_oid()? != ed25519 {
                    return Err(invalid());
                }
                Ok(())
            })?;
            let (signature, bits) = reader.next().read_bitvec_bytes()?;
            if bits != 512 || signature.len() != 64 {
                return Err(invalid());
            }
            Ok((tbs, signature))
        })
    })
    .map_err(|_| anyhow!("证书 DER 外层"))?;
    let (public, extensions) = yasna::parse_der(&tbs, |reader| {
        reader.read_sequence(|reader| {
            let version = reader
                .next()
                .read_tagged(Tag::context(0), |reader| reader.read_u8())?;
            if version != 2 {
                return Err(invalid());
            }
            reader.next().read_der()?; // serial
            reader.next().read_sequence(|reader| {
                if reader.next().read_oid()? != ed25519 {
                    return Err(invalid());
                }
                Ok(())
            })?;
            reader.next().read_der()?; // issuer
            reader.next().read_der()?; // validity
            reader.next().read_der()?; // subject
            let public = reader.next().read_sequence(|reader| {
                reader.next().read_sequence(|reader| {
                    if reader.next().read_oid()? != ed25519 {
                        return Err(invalid());
                    }
                    Ok(())
                })?;
                let (public, bits) = reader.next().read_bitvec_bytes()?;
                if bits != 256 || public.len() != 32 {
                    return Err(invalid());
                }
                Ok(public)
            })?;
            let extensions = reader
                .read_optional(|reader| {
                    reader.read_tagged(Tag::context(3), |reader| {
                        reader.collect_sequence_of(|reader| {
                            reader.read_sequence(|reader| {
                                let oid = reader.next().read_oid()?.components().to_vec();
                                reader.read_default(false, |reader| reader.read_bool())?;
                                let value = reader.next().read_bytes()?;
                                Ok((oid, value))
                            })
                        })
                    })
                })?
                .unwrap_or_default();
            Ok((public, extensions))
        })
    })
    .map_err(|_| anyhow!("证书 DER TBS"))?;
    Ok(ParsedCertificate {
        public,
        signature,
        extensions,
    })
}
struct RealityVerifier {
    key: [u8; 32],
    mldsa_public: Option<Vec<u8>>,
    log: Arc<Mutex<WireLog>>,
}
impl fmt::Debug for RealityVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IndependentRealityVerifier([REDACTED])")
    }
}
impl RealityVerifier {
    fn check_certificate(&self, der: &[u8]) -> Result<()> {
        let parsed = parse_certificate(der)?;
        let key = hmac::Key::new(hmac::HMAC_SHA512, &self.key);
        hmac::verify(&key, &parsed.public, &parsed.signature)
            .map_err(|_| anyhow!("REALITY 证书 HMAC"))?;
        if let Some(public) = &self.mldsa_public {
            ensure!(public.len() == 1952, "ML-DSA 公钥长度");
            let (oid, signature) = parsed.extensions.first().context("ML-DSA 扩展缺失")?;
            ensure!(
                *oid == [0, 0] && signature.len() == 3309,
                "ML-DSA 必须为首扩展 OID0.0"
            );
            let log = self.log.lock().unwrap();
            ensure!(
                !log.raw_ch.is_empty() && !log.raw_sh.is_empty(),
                "ML-DSA 必须绑定实际 CH/SH"
            );
            let mut input = parsed.public;
            input.extend(&log.raw_ch);
            input.extend(&log.raw_sh);
            let message = hmac::sign(&key, &input);
            signature::UnparsedPublicKey::new(&signature::ML_DSA_65, public)
                .verify(message.as_ref(), signature)
                .map_err(|_| anyhow!("ML-DSA 实际 transcript 绑定验证"))?;
        }
        Ok(())
    }
}
impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(tls_error());
        }
        self.check_certificate(end.as_ref())
            .map_err(|_| tls_error())?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(tls_error())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// 独立 VLESS v0 编码，可复用 common 的受控目标/Running/计量断言。
pub fn vless_request(command: u8, flow: Option<&str>, id: [u8; 16], target: SocketAddr) -> Vec<u8> {
    let mut out = vec![0];
    out.extend(id);
    if let Some(flow) = flow {
        out.extend([
            (flow.len() + 2).try_into().unwrap(),
            10,
            flow.len().try_into().unwrap(),
        ]);
        out.extend(flow.as_bytes());
    } else {
        out.push(0);
    }
    out.push(command);
    if command != 3 {
        out.extend(target.port().to_be_bytes());
        match target.ip() {
            std::net::IpAddr::V4(ip) => {
                out.push(1);
                out.extend(ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                out.push(3);
                out.extend(ip.octets());
            }
        }
    }
    out
}
pub fn vision_block(first: bool, command: u8, body: &[u8], padding: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if first {
        out.extend(ID);
    }
    out.push(command);
    out.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    out.extend(u16::try_from(padding).unwrap().to_be_bytes());
    out.extend(body);
    out.resize(out.len() + padding, 0x77);
    out
}

#[derive(Clone, Copy, Debug)]
pub enum TargetGroup {
    X25519,
    Hybrid,
}
#[derive(Clone, Debug)]
pub enum TargetBehavior {
    Echo,
    EchoAfterEof,
    ServerFirst(Vec<u8>),
    /// 不解释 TLS 的固定回环回落端。保留首条 CH 原文，再发固定响应并回显后续原文。
    Raw(Vec<u8>),
    /// 读入 CH 后不输出，用于绝对期限/取消测试。
    Silent,
}
pub struct TargetOptions {
    pub group: TargetGroup,
    /// rcgen 自定义非关键扩展的真实字节，扩大标准 TLS 聚合 flight，不使用 REALITY hook。
    pub certificate_padding: usize,
    /// target 支持的 ALPN；REALITY 的 SH 模板会携带该选择。
    pub alpn: Vec<Vec<u8>>,
    pub behavior: TargetBehavior,
}
impl Default for TargetOptions {
    fn default() -> Self {
        Self {
            group: TargetGroup::X25519,
            certificate_padding: 8192,
            alpn: Vec::new(),
            behavior: TargetBehavior::Echo,
        }
    }
}
#[derive(Clone, Default, Debug)]
pub struct PeerConnection {
    pub received_wire: Vec<u8>,
    pub sent_wire: Vec<u8>,
    pub raw_ch: Vec<u8>,
    pub raw_sh: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub handshake_complete: bool,
}
#[derive(Default)]
pub struct PeerObservation {
    pub accepted: AtomicUsize,
    pub active: AtomicUsize,
    pub completed: AtomicUsize,
    pub connections: Mutex<Vec<PeerConnection>>,
}
/// 独立普通 TLS1.3 target，永不启用 ServerConfig.reality，不解析生产模板。
pub struct TargetPeer {
    pub address: SocketAddr,
    pub certificate: CertificateDer<'static>,
    pub observation: Arc<PeerObservation>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl TargetPeer {
    pub async fn start(options: TargetOptions) -> Result<Self> {
        ensure!(options.certificate_padding <= 12000, "测试 target 证书上限");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
        if options.certificate_padding > 0 {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 55555, 1],
                    vec![0x61; options.certificate_padding],
                ));
        }
        let certificate = params.self_signed(&key)?.der().clone();
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
        provider.kx_groups = vec![match options.group {
            TargetGroup::X25519 => rustls::crypto::aws_lc_rs::kx_group::X25519,
            TargetGroup::Hybrid => rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        }];
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )?;
        config.send_tls13_tickets = 0;
        config.alpn_protocols = options.alpn.clone();
        assert!(config.reality.is_none(), "普通 target 不能启 REALITY 钩子");
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let observation = Arc::new(PeerObservation::default());
        let stop = CancellationToken::new();
        let worker_observation = observation.clone();
        let worker_stop = stop.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    _ = worker_stop.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break; };
                        assert!(peer.ip().is_loopback());
                        let id = worker_observation.accepted.fetch_add(1, Ordering::SeqCst);
                        if id >= 128 { break; }
                        worker_observation.connections.lock().unwrap().push(PeerConnection::default());
                        let observation = worker_observation.clone();
                        let stop = worker_stop.clone();
                        let config = config.clone();
                        let behavior = options.behavior.clone();
                        tasks.spawn(async move {
                            observation.active.fetch_add(1, Ordering::SeqCst);
                            tokio::select! {
                                _ = stop.cancelled() => {},
                                _ = serve_target(stream, config, behavior, observation.clone(), id) => {},
                            }
                            observation.active.fetch_sub(1, Ordering::SeqCst);
                        });
                    },
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                }
            }
            worker_stop.cancel();
            while tasks.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            certificate,
            observation,
            stop,
            task: Some(task),
        })
    }
    pub fn ordinary_client_config(&self) -> Result<Arc<ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.certificate.clone())?;
        let mut config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Arc::new(config))
    }
    pub async fn shutdown(mut self) -> Result<()> {
        self.stop.cancel();
        timeout(DEADLINE, self.task.as_mut().unwrap()).await??;
        self.task.take();
        ensure!(
            self.observation.active.load(Ordering::SeqCst) == 0,
            "target 子任务未清空"
        );
        Ok(())
    }
}
impl Drop for TargetPeer {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
fn observe(observation: &PeerObservation, id: usize, incoming: bool, bytes: &[u8]) -> Result<()> {
    let mut connections = observation.connections.lock().unwrap();
    let connection = connections.get_mut(id).context("target observation id")?;
    let target = if incoming {
        &mut connection.received_wire
    } else {
        &mut connection.sent_wire
    };
    ensure!(target.len() + bytes.len() <= 131072, "target 观察字节上限");
    target.extend(bytes);
    Ok(())
}
async fn serve_target(
    mut io: TcpStream,
    config: Arc<rustls::ServerConfig>,
    behavior: TargetBehavior,
    observation: Arc<PeerObservation>,
    id: usize,
) -> Result<()> {
    let mut tls = rustls::ServerConnection::new(config)?;
    let mut seen_complete = false;
    let mut after_eof = Vec::new();
    loop {
        let record = raw_record(&mut io).await?;
        observe(&observation, id, true, &record)?;
        let ch = {
            let connections = observation.connections.lock().unwrap();
            client_hello(&connections[id].received_wire).ok()
        };
        if let Some(ch) = ch {
            observation.connections.lock().unwrap()[id].raw_ch = ch;
            if let TargetBehavior::Raw(response) = &behavior {
                io.write_all(response).await?;
                observe(&observation, id, false, response)?;
                let mut bytes = [0; 4096];
                loop {
                    let count = io.read(&mut bytes).await?;
                    if count == 0 {
                        io.shutdown().await?;
                        return Ok(());
                    }
                    observe(&observation, id, true, &bytes[..count])?;
                    io.write_all(&bytes[..count]).await?;
                    observe(&observation, id, false, &bytes[..count])?;
                }
            }
            if matches!(behavior, TargetBehavior::Silent) {
                std::future::pending::<()>().await;
            }
        }
        let mut input = record.as_slice();
        while !input.is_empty() {
            ensure!(tls.read_tls(&mut input)? > 0, "target TLS 读取未推进");
            tls.process_new_packets()?;
        }
        if !tls.is_handshaking() && !seen_complete {
            seen_complete = true;
            observation.completed.fetch_add(1, Ordering::SeqCst);
            observation.connections.lock().unwrap()[id].handshake_complete = true;
            if let TargetBehavior::ServerFirst(bytes) = &behavior {
                io::Write::write_all(&mut tls.writer(), bytes)?;
            }
        }
        let mut eof = false;
        loop {
            let mut bytes = [0; 4096];
            match io::Read::read(&mut tls.reader(), &mut bytes) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => {
                    {
                        let mut connections = observation.connections.lock().unwrap();
                        ensure!(
                            connections[id].plaintext.len() + n <= 65536,
                            "target plaintext 上限"
                        );
                        connections[id].plaintext.extend(&bytes[..n]);
                    }
                    if matches!(behavior, TargetBehavior::EchoAfterEof) {
                        after_eof.extend(&bytes[..n]);
                    } else {
                        io::Write::write_all(&mut tls.writer(), &bytes[..n])?;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        if eof {
            if matches!(behavior, TargetBehavior::EchoAfterEof) {
                io::Write::write_all(&mut tls.writer(), &after_eof)?;
            }
            tls.send_close_notify();
        }
        let mut wire = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut wire)?;
        }
        if !wire.is_empty() {
            {
                let mut connections = observation.connections.lock().unwrap();
                if connections[id].raw_sh.is_empty() {
                    let mut records = Cursor::new(&wire);
                    let header = records.take(5)?;
                    let body =
                        records.take(usize::from(u16::from_be_bytes([header[3], header[4]])))?;
                    if header[0] == 22 && body.len() >= 4 && body[0] == 2 {
                        connections[id].raw_sh = body[..4 + u24(&body[1..4])].to_vec();
                    }
                }
            }
            observe(&observation, id, false, &wire)?;
            io.write_all(&wire).await?;
        }
        if eof {
            io.shutdown().await?;
            return Ok(());
        }
    }
}

#[cfg(test)]
mod self_tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair as _;
    use sha2::{Digest, Sha256};

    fn hex(bytes: &str) -> Vec<u8> {
        bytes
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }

    // 来源：本机 Python cryptography 50.0.2，2026-11-05 离线生成。
    // X25519PrivateKey.from_private_bytes、HKDF(SHA256)、AESGCM、HMAC(SHA512)。
    // AAD 是固定握手形状的完整 CH，不含 record 头；不冒充完整 hybrid TLS CH。
    #[test]
    fn offline_python_auth_sid_and_hmac_vector() {
        let client =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &[0x31; 32]).unwrap();
        let ch_random: [u8; 32] = std::array::from_fn(|i| i as u8);
        let expected_public =
            hex("1889bfc482d64c91ac9b3910a30c5dba1ac348fe1f4073904515cbea0b486067");
        assert_eq!(public_key(&SERVER_PRIVATE_KEY).as_slice(), expected_public);
        let key = auth_key(&client, &expected_public.try_into().unwrap(), &ch_random).unwrap();
        assert_eq!(
            key.as_slice(),
            hex("c1e3dedd0ac9025866395a77a2a12d47897eccfb249af04d9de58c15d66dfbda")
        );
        let ch = hex(
            "0100004b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000000000000000000000000000000000000000000000000000000000000000002130101000000",
        );
        let mut plain = vec![26, 10, 31, 0];
        plain.extend(hex("6a0000018172635445362718"));
        let cipher = Aes256Gcm::new((&key).into());
        let sid = cipher
            .encrypt(
                <&[u8; 12]>::try_from(&ch_random[20..]).unwrap().into(),
                Payload {
                    msg: &plain,
                    aad: &ch,
                },
            )
            .unwrap();
        assert_eq!(
            sid,
            hex("a4fa744a57781b41227b0177937432668d7755d9bf06e5919bfb11df06ea63a7")
        );
        assert_eq!(
            cipher
                .decrypt(
                    <&[u8; 12]>::try_from(&ch_random[20..]).unwrap().into(),
                    Payload {
                        msg: &sid,
                        aad: &ch
                    }
                )
                .unwrap(),
            plain
        );
        let mut changed = ch.clone();
        changed[5] ^= 1;
        assert!(
            cipher
                .decrypt(
                    <&[u8; 12]>::try_from(&ch_random[20..]).unwrap().into(),
                    Payload {
                        msg: &sid,
                        aad: &changed
                    }
                )
                .is_err()
        );
        assert_eq!(
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, &key), &[0x27; 32]).as_ref(),
            hex(
                "7084ba6856baa48dc9c061720d3c205cda64f8d5871b7bb39dc6d6826fa211d77dfe38e0f80e26f8dd644d2696f95858babe75103ef91c907fbe66b57f93ddbd"
            )
        );
    }

    #[test]
    fn two_pass_client_has_authenticated_sid_and_distinct_shares() {
        for ordinary_share in [false, true] {
            let client = PreparedClient::new(ClientOptions {
                ordinary_share,
                ..ClientOptions::default()
            })
            .unwrap();
            let shares = client_shares(&client.raw_ch).unwrap();
            assert_eq!(shares[0].0, 0x11ec);
            assert_eq!(shares[0].1.len(), 1216);
            assert_eq!(shares.len(), if ordinary_share { 2 } else { 1 });
            let authentication_public = if ordinary_share {
                assert_eq!(shares[1].0, 29);
                assert_eq!(shares[1].1.len(), 32);
                assert_ne!(shares[0].1[1184..], shares[1].1);
                shares[1].1.as_slice()
            } else {
                &shares[0].1[1184..]
            };
            let server =
                agreement::PrivateKey::from_private_key(&agreement::X25519, &SERVER_PRIVATE_KEY)
                    .unwrap();
            let random: [u8; 32] = client.raw_ch[6..38].try_into().unwrap();
            let key =
                auth_key(&server, &authentication_public.try_into().unwrap(), &random).unwrap();
            let sid = session_id_range(&client.raw_ch).unwrap();
            let mut aad = client.raw_ch.clone();
            aad[sid.clone()].fill(0);
            let plain = Aes256Gcm::new((&key).into())
                .decrypt(
                    <&[u8; 12]>::try_from(&random[20..]).unwrap().into(),
                    Payload {
                        msg: &client.raw_ch[sid],
                        aad: &aad,
                    },
                )
                .unwrap();
            assert_eq!(&plain[..4], &[26, 10, 31, 0]);
            assert_eq!(&plain[8..], &SHORT_ID);
        }
    }

    struct HmacCertificate {
        public: Vec<u8>,
        signature: Vec<u8>,
    }
    impl rcgen::RemoteKeyPair for HmacCertificate {
        fn public_key(&self) -> &[u8] {
            &self.public
        }
        fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            Ok(self.signature.clone())
        }
        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_ED25519
        }
    }
    fn test_certificate(
        key: &[u8; 32],
        raw_ch: &[u8],
        raw_sh: &[u8],
        mldsa: bool,
    ) -> (
        CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let real_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mac_key = hmac::Key::new(hmac::HMAC_SHA512, key);
        let remote = rcgen::KeyPair::from_remote(Box::new(HmacCertificate {
            public: real_key.public_key_raw().to_vec(),
            signature: hmac::sign(&mac_key, real_key.public_key_raw())
                .as_ref()
                .to_vec(),
        }))
        .unwrap();
        let mut params = rcgen::CertificateParams::default();
        if mldsa {
            let signer =
                signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &[0x42; 32])
                    .unwrap();
            let input = [real_key.public_key_raw(), raw_ch, raw_sh].concat();
            let message = hmac::sign(&mac_key, &input);
            let mut signature = vec![0; 3309];
            assert_eq!(
                signer.sign(message.as_ref(), &mut signature).unwrap(),
                signature.len()
            );
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(&[0, 0], signature));
        }
        let cert = params.self_signed(&remote).unwrap().der().clone();
        (
            cert,
            rustls::pki_types::PrivatePkcs8KeyDer::from(real_key.serialize_der()).into(),
        )
    }
    fn corrupt_mldsa_extension(cert: &[u8], move_from_first: bool) -> Vec<u8> {
        // 成熟 DER reader/writer 重建扩展；不猜测固定偏移。
        let mut outer = yasna::parse_der(cert, |reader| {
            reader.collect_sequence_of(|reader| reader.read_der())
        })
        .unwrap();
        let mut fields = yasna::parse_der(&outer[0], |reader| {
            reader.collect_sequence_of(|reader| reader.read_der())
        })
        .unwrap();
        let last = fields.last_mut().unwrap();
        let mut extensions = yasna::parse_der(last, |reader| {
            reader.read_tagged(yasna::Tag::context(3), |reader| {
                reader.collect_sequence_of(|reader| reader.read_der())
            })
        })
        .unwrap();
        if move_from_first {
            let unrelated = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&yasna::models::ObjectIdentifier::from_slice(&[1, 2, 3, 4]));
                    writer.next().write_bytes(&[0]);
                })
            });
            extensions.insert(0, unrelated);
        } else {
            let (oid, mut signature) = yasna::parse_der(&extensions[0], |reader| {
                reader.read_sequence(|reader| {
                    Ok((reader.next().read_oid()?, reader.next().read_bytes()?))
                })
            })
            .unwrap();
            signature[0] ^= 1;
            extensions[0] = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    writer.next().write_oid(&oid);
                    writer.next().write_bytes(&signature);
                })
            });
        }
        *last = yasna::construct_der(|writer| {
            writer.write_tagged(yasna::Tag::context(3), |writer| {
                writer.write_sequence(|writer| {
                    for extension in extensions {
                        writer.next().write_der(&extension);
                    }
                })
            })
        });
        outer[0] = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                for field in fields {
                    writer.next().write_der(&field);
                }
            })
        });
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                for field in outer {
                    writer.next().write_der(&field);
                }
            })
        })
    }

    #[test]
    fn der_hmac_and_mldsa_bind_exact_ch_sh_and_first_extension() {
        let key = [0x61; 32];
        let log = Arc::new(Mutex::new(WireLog {
            raw_ch: b"original ciphertext SID CH".to_vec(),
            raw_sh: b"actual final SH".to_vec(),
            ..WireLog::default()
        }));
        let mldsa =
            signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &[0x42; 32]).unwrap();
        // 独立 Python cryptography50.0.2 mldsa.MLDSA65PrivateKey.from_seed_bytes 的公钥摘要。
        assert_eq!(
            Sha256::digest(mldsa.public_key().as_ref()).as_slice(),
            hex("2f40048b7202cf1d33e0af88f0695e076d00fea5be3d201d667021afe09c23c1")
        );
        for enabled in [false, true] {
            let guard = log.lock().unwrap();
            let (cert, _) = test_certificate(&key, &guard.raw_ch, &guard.raw_sh, enabled);
            drop(guard);
            let verifier = RealityVerifier {
                key,
                mldsa_public: enabled.then(|| mldsa.public_key().as_ref().to_vec()),
                log: log.clone(),
            };
            verifier.check_certificate(&cert).unwrap();
            let ordinary_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let ordinary_cert = rcgen::CertificateParams::default()
                .self_signed(&ordinary_key)
                .unwrap();
            assert!(
                verifier.check_certificate(ordinary_cert.der()).is_err(),
                "普通自签证书不能取代 REALITY HMAC"
            );
            let mut corrupt = cert.to_vec();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(verifier.check_certificate(&corrupt).is_err());
            let wrong_key = RealityVerifier {
                key: [0x62; 32],
                mldsa_public: None,
                log: log.clone(),
            };
            assert!(wrong_key.check_certificate(&cert).is_err());
            if enabled {
                assert!(
                    verifier
                        .check_certificate(&corrupt_mldsa_extension(&cert, false))
                        .is_err()
                );
                assert!(
                    verifier
                        .check_certificate(&corrupt_mldsa_extension(&cert, true))
                        .is_err()
                );
                log.lock().unwrap().raw_ch[0] ^= 1;
                assert!(verifier.check_certificate(&cert).is_err());
                log.lock().unwrap().raw_ch[0] ^= 1;
                log.lock().unwrap().raw_sh[0] ^= 1;
                assert!(verifier.check_certificate(&cert).is_err());
                log.lock().unwrap().raw_sh[0] ^= 1;
                let wrong_public =
                    signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &[0x43; 32])
                        .unwrap();
                let verifier = RealityVerifier {
                    key,
                    mldsa_public: Some(wrong_public.public_key().as_ref().to_vec()),
                    log: log.clone(),
                };
                assert!(verifier.check_certificate(&cert).is_err());
            }
        }
    }

    #[derive(Debug)]
    struct CorruptCv(Arc<dyn rustls::sign::SigningKey>);
    impl rustls::sign::SigningKey for CorruptCv {
        fn choose_scheme(
            &self,
            offered: &[SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            self.0
                .choose_scheme(offered)
                .map(|signer| Box::new(CorruptSigner(signer)) as Box<dyn rustls::sign::Signer>)
        }
        fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
            self.0.public_key()
        }
        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            self.0.algorithm()
        }
    }
    #[derive(Debug)]
    struct CorruptSigner(Box<dyn rustls::sign::Signer>);
    impl rustls::sign::Signer for CorruptSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            let mut signature = self.0.sign(message)?;
            signature[0] ^= 1;
            Ok(signature)
        }
        fn scheme(&self) -> SignatureScheme {
            self.0.scheme()
        }
    }
    fn ordinary_server_for_client(
        client: &PreparedClient,
        group: TargetGroup,
        bad_cv: bool,
    ) -> rustls::ServerConnection {
        let shares = client_shares(&client.raw_ch).unwrap();
        let ordinary = shares.iter().find(|(group, _)| *group == 29);
        let auth_public = ordinary.map_or(&shares[0].1[1184..], |(_, public)| public.as_slice());
        let static_private =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &SERVER_PRIVATE_KEY)
                .unwrap();
        let random = client.raw_ch[6..38].try_into().unwrap();
        let key = auth_key(&static_private, &auth_public.try_into().unwrap(), &random).unwrap();
        let (cert, private) = test_certificate(&key, &[], &[], false);
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![match group {
            TargetGroup::X25519 => rustls::crypto::aws_lc_rs::kx_group::X25519,
            TargetGroup::Hybrid => rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        }];
        let signer = provider.key_provider.load_private_key(private).unwrap();
        let signer: Arc<dyn rustls::sign::SigningKey> = if bad_cv {
            Arc::new(CorruptCv(signer))
        } else {
            signer
        };
        let key = rustls::sign::CertifiedKey::new(vec![cert], signer);
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
        config.send_tls13_tickets = 0;
        assert!(config.reality.is_none());
        rustls::ServerConnection::new(Arc::new(config)).unwrap()
    }

    // 无生产 REALITY 钩子的普通服务端 + 独立特殊证书：只证明客户端公开 API/transcript 门禁。
    #[test]
    fn real_client_transcript_contains_ciphertext_sid_and_checks_cv_and_finished() {
        for (ordinary_share, group) in [
            (true, TargetGroup::X25519),
            (true, TargetGroup::Hybrid),
            (false, TargetGroup::Hybrid),
        ] {
            for bad_cv in [false, true] {
                let mut client = PreparedClient::new(ClientOptions {
                    ordinary_share,
                    ..ClientOptions::default()
                })
                .unwrap();
                let mut server = ordinary_server_for_client(&client, group, bad_cv);
                let mut ch = client.initial_wire.as_slice();
                while !ch.is_empty() {
                    server.read_tls(&mut ch).unwrap();
                    server.process_new_packets().unwrap();
                }
                let mut server_flight = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut server_flight).unwrap();
                }
                let mut input = server_flight.as_slice();
                let mut error = None;
                while !input.is_empty() {
                    client.tls.read_tls(&mut input).unwrap();
                    if let Err(e) = client.tls.process_new_packets() {
                        error = Some(e);
                        break;
                    }
                }
                if bad_cv {
                    assert!(error.is_some(), "损坏 CV 必须失败，不能 dangerous 跳过");
                    continue;
                }
                assert!(error.is_none(), "正确 CV/Finished 必须通过 {error:?}");
                assert!(!client.tls.is_handshaking());
                let output = client_output(&mut client.tls).unwrap();
                let mut input = output.as_slice();
                while !input.is_empty() {
                    server.read_tls(&mut input).unwrap();
                    server.process_new_packets().unwrap();
                }
                assert!(
                    !server.is_handshaking(),
                    "服务端必须真实验证客户端 Finished"
                );
                io::Write::write_all(&mut client.tls.writer(), b"actual application").unwrap();
                let output = client_output(&mut client.tls).unwrap();
                server.read_tls(&mut output.as_slice()).unwrap();
                server.process_new_packets().unwrap();
                let mut plain = [0; 18];
                io::Read::read_exact(&mut server.reader(), &mut plain).unwrap();
                assert_eq!(&plain, b"actual application");
            }
        }
    }

    // 独立工具门禁：不让普通 cargo test 隐含依赖机器上的 Python；需显式 --ignored 执行。
    #[test]
    #[ignore = "显式离线门禁：需本机 Python cryptography >=50 的成熟 MLDSA API"]
    fn mldsa65_python_cryptography_cross_verifies_aws_lc_both_directions() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use std::process::{Command, Stdio};
        let key =
            signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &[0x42; 32]).unwrap();
        let message = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA512, &[0x61; 32]),
            b"pub32 || originalCH || finalSH",
        );
        let mut sig = vec![0; 3309];
        key.sign(message.as_ref(), &mut sig).unwrap();
        let request = serde_json::json!({"public":STANDARD.encode(key.public_key().as_ref()),
            "signature":STANDARD.encode(&sig),"message":STANDARD.encode(message.as_ref())});
        let script = r#"
import base64, json, sys, cryptography
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
request=json.load(sys.stdin)
decode=base64.b64decode
message=decode(request['message'])
key=mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes([0x42])*32)
public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
assert public == decode(request['public'])
key.public_key().verify(decode(request['signature']),message)
try:
    key.public_key().verify(decode(request['signature']),message+b'wrong')
    raise AssertionError('modified message accepted')
except InvalidSignature:
    pass
print(json.dumps({'version':cryptography.__version__,'public':base64.b64encode(public).decode(),
                  'signature':base64.b64encode(key.sign(message)).decode()}))
"#;
        let mut child = Command::new("python3")
            .args(["-I", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        io::Write::write_all(
            &mut child.stdin.take().unwrap(),
            request.to_string().as_bytes(),
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "Python跨库验证失败 {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let public = STANDARD
            .decode(response["public"].as_str().unwrap())
            .unwrap();
        let python_sig = STANDARD
            .decode(response["signature"].as_str().unwrap())
            .unwrap();
        assert_eq!(public, key.public_key().as_ref());
        signature::UnparsedPublicKey::new(&signature::ML_DSA_65, &public)
            .verify(message.as_ref(), &python_sig)
            .unwrap();
        let mut wrong_sig = python_sig;
        wrong_sig[0] ^= 1;
        assert!(
            signature::UnparsedPublicKey::new(&signature::ML_DSA_65, &public)
                .verify(message.as_ref(), &wrong_sig)
                .is_err()
        );
        eprintln!(
            "离线跨库验证：cryptography {} ↔ aws-lc-rs 1.19.0，seed42公钥相同，pure MLDSA65/空context双向签名通过",
            response["version"]
        );
    }

    #[tokio::test]
    async fn ordinary_target_has_no_reality_hook_and_real_tls_group_echo_and_halfclose() {
        for group in [TargetGroup::X25519, TargetGroup::Hybrid] {
            let peer = TargetPeer::start(TargetOptions {
                group,
                behavior: TargetBehavior::EchoAfterEof,
                ..TargetOptions::default()
            })
            .await
            .unwrap();
            let config = peer.ordinary_client_config().unwrap();
            let mut stream = tokio_rustls::TlsConnector::from(config)
                .connect(
                    "localhost".try_into().unwrap(),
                    TcpStream::connect(peer.address).await.unwrap(),
                )
                .await
                .unwrap();
            stream.write_all(b"half-close reverse drain").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            timeout(DEADLINE, stream.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, b"half-close reverse drain");
            {
                let connections = peer.observation.connections.lock().unwrap();
                assert_eq!(connections.len(), 1);
                assert!(connections[0].handshake_complete);
                assert!(!connections[0].raw_ch.is_empty());
                assert!(!connections[0].raw_sh.is_empty());
                // 本机普通 target 使用聚合 flight；首加密槽 >512，可容纳 MLDSA。
                let sizes = record_lengths(&connections[0].sent_wire).unwrap();
                assert!(sizes.iter().any(|size| *size > 8192));
            }
            drop(stream);
            peer.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn raw_target_keeps_original_ch_and_bytes_exactly_once() {
        let peer = TargetPeer::start(TargetOptions {
            behavior: TargetBehavior::Raw(b"fixed-target".to_vec()),
            ..TargetOptions::default()
        })
        .await
        .unwrap();
        let client = PreparedClient::new(ClientOptions::default()).unwrap();
        let wire = client.initial_wire.clone();
        let mut stream = TcpStream::connect(peer.address).await.unwrap();
        for byte in &wire {
            stream.write_all(&[*byte]).await.unwrap();
        }
        let mut response = [0; 12];
        timeout(DEADLINE, stream.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"fixed-target");
        stream.write_all(b"raw-after-ch").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(DEADLINE, stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"raw-after-ch");
        {
            let connections = peer.observation.connections.lock().unwrap();
            assert_eq!(connections[0].raw_ch, client.raw_ch);
            assert_eq!(
                connections[0].received_wire,
                [wire, b"raw-after-ch".to_vec()].concat()
            );
        }
        drop(stream);
        peer.shutdown().await.unwrap();
    }
}
