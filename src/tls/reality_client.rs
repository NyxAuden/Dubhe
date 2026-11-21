//! REALITY 出站 TLS 客户端。
//!
//! 只把 REALITY 的 wire 认证接入现有 rustls：自定义 X25519 KX 生成密钥并
//! 派生 auth key，调用方提供的 `BuildsSessionId` 写入 ClientHello session ID，
//! 自定义 verifier 验证临时证书的 HMAC 与 TLS 1.3 Ed25519 CertificateVerify。
//! 密码学全部由 aws-lc/rustls 执行，不实现新的密码原语。

use std::{
    fmt, io,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use aws_lc_rs::{
    agreement::{self, PrivateKey, UnparsedPublicKey, X25519},
    hkdf,
    signature::{ED25519, UnparsedPublicKey as VerifyKey},
};
use ml_kem::{Ciphertext, DecapsulationKey, KeyExport, MlKem768, Seed, kem::Decapsulate};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, NamedGroup, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::TLS13,
};
use tokio_rustls::TlsConnector;
use x509_parser::parse_x509_certificate;

use crate::config::OutboundReality;
use crate::forward::{Upstream, UpstreamStream};
use crate::tls::controlled::Controlled;

const REALITY_INFO: &[u8] = b"REALITY";
const DEFAULT_VERSION: [u8; 3] = [26, 10, 31];
const X25519_LEN: usize = 32;
const MLKEM_PUBLIC_LEN: usize = 1184;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;

/// 固定 X25519 KX 组；只用于 REALITY 客户端。
#[derive(Debug)]
struct RealityKxGroup;

static REALITY_KX: RealityKxGroup = RealityKxGroup;

/// REALITY 的 hybrid 组 `X25519MLKEM768`；保留独立的 X25519 组件供认证。
#[derive(Debug)]
struct RealityHybridGroup;

static REALITY_HYBRID: RealityHybridGroup = RealityHybridGroup;

struct RealityHybrid {
    decaps: DecapsulationKey<MlKem768>,
    key_share: Vec<u8>,
    x_private: PrivateKey,
    x_public: [u8; X25519_LEN],
}

impl fmt::Debug for RealityHybrid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealityHybrid([REDACTED])")
    }
}

impl SupportedKxGroup for RealityHybridGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut seed = [0u8; 64];
        aws_lc_rs::rand::fill(&mut seed)
            .map_err(|_| Error::General("REALITY hybrid 随机源失败".into()))?;
        let decaps = DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed));
        let mlkem_public = decaps.encapsulation_key().to_bytes();
        let x_private = PrivateKey::generate(&X25519)
            .map_err(|_| Error::General("REALITY hybrid X25519 失败".into()))?;
        let x_public: [u8; X25519_LEN] = x_private
            .compute_public_key()
            .map_err(|_| Error::General("REALITY hybrid X25519 公钥失败".into()))?
            .as_ref()
            .try_into()
            .map_err(|_| Error::General("REALITY hybrid X25519 长度错误".into()))?;
        let mut key_share = Vec::with_capacity(MLKEM_PUBLIC_LEN + X25519_LEN);
        key_share.extend_from_slice(mlkem_public.as_slice());
        key_share.extend_from_slice(&x_public);
        Ok(Box::new(RealityHybrid {
            decaps,
            key_share,
            x_private,
            x_public,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn fips(&self) -> bool {
        false
    }
}

impl ActiveKeyExchange for RealityHybrid {
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn pub_key(&self) -> &[u8] {
        &self.key_share
    }

    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != MLKEM_CIPHERTEXT_LEN + X25519_LEN {
            return Err(Error::General("REALITY hybrid 对端 share 长度错误".into()));
        }
        let ciphertext: [u8; MLKEM_CIPHERTEXT_LEN] = peer_pub_key[..MLKEM_CIPHERTEXT_LEN]
            .try_into()
            .map_err(|_| Error::General("REALITY hybrid 密文长度错误".into()))?;
        let pq = self
            .decaps
            .decapsulate(&Ciphertext::<MlKem768>::from(ciphertext));
        let x_shared = agreement::agree(
            &self.x_private,
            UnparsedPublicKey::new(&X25519, &peer_pub_key[MLKEM_CIPHERTEXT_LEN..]),
            Error::General("REALITY hybrid X25519 协商失败".into()),
            |shared| {
                let mut key = [0u8; X25519_LEN];
                key.copy_from_slice(shared);
                Ok(key)
            },
        )?;
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(pq.as_slice());
        secret.extend_from_slice(&x_shared);
        Ok(SharedSecret::from(secret))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, &self.x_public))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        let shared = agreement::agree(
            &self.x_private,
            UnparsedPublicKey::new(&X25519, peer_pub_key),
            Error::General("REALITY hybrid 组件协商失败".into()),
            |shared| Ok(SharedSecret::from(shared)),
        )?;
        Ok(shared)
    }

    fn reality_auth_key(&self, server_public: &[u8], random: &[u8; 32]) -> Option<[u8; 32]> {
        derive_auth_key(&self.x_private, server_public, random)
    }
}

impl SupportedKxGroup for RealityKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let private = PrivateKey::generate(&X25519)
            .map_err(|_| Error::General("REALITY 临时 X25519 密钥生成失败".into()))?;
        let public = private
            .compute_public_key()
            .map_err(|_| Error::General("REALITY 临时 X25519 公钥推导失败".into()))?;
        Ok(Box::new(RealityKx {
            private,
            public: public.as_ref().to_vec(),
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn fips(&self) -> bool {
        false
    }
}

struct RealityKx {
    private: PrivateKey,
    public: Vec<u8>,
}

impl fmt::Debug for RealityKx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealityKx([REDACTED])")
    }
}

fn derive_auth_key(
    private: &PrivateKey,
    server_public: &[u8],
    random: &[u8; 32],
) -> Option<[u8; 32]> {
    let peer = UnparsedPublicKey::new(&X25519, server_public);
    agreement::agree(private, peer, (), |shared| {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &random[..20]);
        let prk = salt.extract(shared);
        let okm = prk
            .expand(&[REALITY_INFO], hkdf::HKDF_SHA256)
            .map_err(|_| ())?;
        let mut key = [0u8; 32];
        okm.fill(&mut key).map_err(|_| ())?;
        Ok(key)
    })
    .ok()
}

impl ActiveKeyExchange for RealityKx {
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer = UnparsedPublicKey::new(&X25519, peer_pub_key);
        agreement::agree(
            &self.private,
            peer,
            Error::General("REALITY X25519 协商失败".into()),
            |shared| Ok(SharedSecret::from(shared)),
        )
    }

    fn reality_auth_key(&self, server_public: &[u8], random: &[u8; 32]) -> Option<[u8; 32]> {
        derive_auth_key(&self.private, server_public, random)
    }
}

#[derive(Default)]
struct AuthState {
    key: Mutex<Option<[u8; 32]>>,
    raw_client_hello: Mutex<Vec<u8>>,
    raw_server_hello: Mutex<Vec<u8>>,
}

impl fmt::Debug for AuthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealityAuthState([REDACTED])")
    }
}

struct SessionBuilder {
    server_public: [u8; 32],
    short_id: [u8; 8],
    version: [u8; 3],
    state: Arc<AuthState>,
}

impl fmt::Debug for SessionBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealitySessionBuilder([REDACTED])")
    }
}

impl rustls::client::reality::BuildsSessionId for SessionBuilder {
    fn build(
        &self,
        random: [u8; 32],
        key_share: &dyn ActiveKeyExchange,
        zero_hello: &[u8],
    ) -> Result<[u8; 32], Error> {
        let auth = key_share
            .reality_auth_key(&self.server_public, &random)
            .ok_or_else(|| Error::General("REALITY auth key 派生失败".into()))?;
        *self
            .state
            .key
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(auth);
        let mut plain = [0u8; 16];
        plain[..3].copy_from_slice(&self.version);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::General("REALITY 时间无效".into()))?
            .as_secs()
            .try_into()
            .map_err(|_| Error::General("REALITY 时间超出 u32".into()))?;
        plain[4..8].copy_from_slice(&u32::to_be_bytes(timestamp));
        plain[8..].copy_from_slice(&self.short_id);
        let cipher = Aes256Gcm::new((&auth).into());
        let nonce: &[u8; 12] = random[20..]
            .try_into()
            .map_err(|_| Error::General("REALITY nonce 长度错误".into()))?;
        let session_id = cipher
            .encrypt(
                nonce.into(),
                Payload {
                    msg: &plain,
                    aad: zero_hello,
                },
            )
            .map_err(|_| Error::General("REALITY session id 加密失败".into()))?;
        let session_id: [u8; 32] = session_id
            .try_into()
            .map_err(|_| Error::General("REALITY session id 长度错误".into()))?;
        // `zero_hello` is a complete ClientHello handshake message:
        // 4-byte header + 2 legacy_version + 32 random + 1 session-id length.
        const SESSION_ID_OFFSET: usize = 39;
        if zero_hello.len() < SESSION_ID_OFFSET + 32 || zero_hello[SESSION_ID_OFFSET - 1] != 32 {
            return Err(Error::General(
                "REALITY ClientHello session id 布局错误".into(),
            ));
        }
        let mut raw_client_hello = zero_hello.to_vec();
        raw_client_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(&session_id);
        *self
            .state
            .raw_client_hello
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = raw_client_hello;
        Ok(session_id)
    }

    fn server_hello(&self, encoded: &[u8]) {
        *self
            .state
            .raw_server_hello
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = encoded.to_vec();
    }
}

struct RealityVerifier {
    state: Arc<AuthState>,
    mldsa65_public_key: Option<Vec<u8>>,
}

impl fmt::Debug for RealityVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealityVerifier([REDACTED])")
    }
}

fn bad_cert() -> Error {
    Error::InvalidCertificate(CertificateError::BadEncoding)
}

fn cert_public(cert: &CertificateDer<'_>) -> Result<[u8; 32], Error> {
    let (_, parsed) = parse_x509_certificate(cert.as_ref()).map_err(|_| bad_cert())?;
    parsed
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| bad_cert())
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() || !ocsp_response.is_empty() {
            return Err(bad_cert());
        }
        let (_, parsed) = parse_x509_certificate(end_entity.as_ref()).map_err(|_| bad_cert())?;
        let signature = parsed.signature_value.data.as_ref();
        let spki = parsed.tbs_certificate.subject_pki.raw;
        let first_extension = parsed.extensions().first().map(|extension| extension.value);
        let auth = self
            .state
            .key
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .ok_or_else(bad_cert)?;
        let raw_client_hello = self
            .state
            .raw_client_hello
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let raw_server_hello = self
            .state
            .raw_server_hello
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        crate::tls::reality_mldsa::verify_certificate(
            &crate::tls::reality_mldsa::CertVerificationInput {
                auth_key: &auth,
                ed25519_spki: spki,
                certificate_signature: signature,
                first_extension_value: first_extension,
                raw_client_hello: &raw_client_hello,
                raw_server_hello: &raw_server_hello,
                mldsa65_public_key: self.mldsa65_public_key.as_deref(),
            },
        )
        .map_err(|_| bad_cert())?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("REALITY 仅支持 TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(Error::General("REALITY 不接受非 Ed25519 签名".into()));
        }
        let public = cert_public(cert)?;
        VerifyKey::new(&ED25519, &public)
            .verify(message, dss.signature())
            .map_err(|_| Error::General("REALITY CertificateVerify 无效".into()))?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // 该列表进入 ClientHello 的 signature_algorithms，供固定目标完成
        // 普通 TLS 握手；REALITY 临时证书本身仍只接受 Ed25519。
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// 已解析的 REALITY 出站配置；每次连接创建独立 rustls ClientConfig 与 auth state。
pub(crate) struct RealityClient {
    server_name: ServerName<'static>,
    public_key: [u8; 32],
    short_id: [u8; 8],
    version: [u8; 3],
    mldsa65_public_key: Option<Vec<u8>>,
}

impl fmt::Debug for RealityClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityClient")
            .field("server_name", &self.server_name)
            .field("public_key", &"[REDACTED]")
            .field("short_id", &"[REDACTED]")
            .field(
                "mldsa65_verify",
                &self.mldsa65_public_key.as_ref().map(|_| "[CONFIGURED]"),
            )
            .finish()
    }
}

impl RealityClient {
    pub(crate) fn from_config(options: &OutboundReality) -> anyhow::Result<Arc<Self>> {
        use base64::Engine as _;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&options.public_key)
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&options.public_key)
            })
            .map_err(|_| anyhow::anyhow!("REALITY public_key 不是 base64"))?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("REALITY public_key 必须是32字节"))?;
        let short_bytes = decode_hex(&options.short_id)?;
        let mut short_id = [0u8; 8];
        short_id[..short_bytes.len()].copy_from_slice(&short_bytes);
        let version = match &options.version {
            None => DEFAULT_VERSION,
            Some(version) => {
                let parts: Vec<_> = version.split('.').collect();
                if parts.len() != 3 {
                    anyhow::bail!("REALITY version 必须是三段十进制");
                }
                let mut out = [0u8; 3];
                for (index, part) in parts.iter().enumerate() {
                    out[index] = part
                        .parse::<u8>()
                        .map_err(|_| anyhow::anyhow!("REALITY version 段越界"))?;
                }
                out
            }
        };
        let server_name = ServerName::try_from(options.server_name.clone())
            .map_err(|_| anyhow::anyhow!("REALITY server_name 无效"))?;
        if matches!(server_name, ServerName::IpAddress(_)) {
            anyhow::bail!("REALITY server_name 必须是 DNS 名");
        }
        let mldsa65_public_key = options
            .mldsa65_verify
            .as_deref()
            .map(|value| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value))
                    .map_err(|_| anyhow::anyhow!("REALITY mldsa65Verify 不是 base64"))
            })
            .transpose()?;
        if mldsa65_public_key
            .as_ref()
            .is_some_and(|key| key.len() != 1952)
        {
            anyhow::bail!("REALITY mldsa65Verify 必须是1952字节 ML-DSA-65 公钥");
        }
        Ok(Arc::new(Self {
            server_name,
            public_key,
            short_id,
            version,
            mldsa65_public_key,
        }))
    }

    fn client_config(
        &self,
        alpn: Option<&[u8]>,
        state: Arc<AuthState>,
    ) -> io::Result<Arc<ClientConfig>> {
        let builder = Arc::new(SessionBuilder {
            server_public: self.public_key,
            short_id: self.short_id,
            version: self.version,
            state: state.clone(),
        });
        let hook = Arc::new(rustls::client::reality::Config::new(builder));
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![&REALITY_HYBRID, &REALITY_KX];
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&TLS13])
            .map_err(|_| io::Error::other("REALITY TLS 配置无效"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RealityVerifier {
                state,
                mldsa65_public_key: self.mldsa65_public_key.clone(),
            }))
            .with_no_client_auth();
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        config.alpn_protocols = alpn.map(|alpn| vec![alpn.to_vec()]).unwrap_or_default();
        config.reality = Some(hook);
        Ok(Arc::new(config))
    }

    /// 在裸 TCP 流上完成 REALITY TLS 1.3 握手。
    pub(crate) async fn connect(
        &self,
        stream: Upstream,
        alpn: Option<&[u8]>,
    ) -> io::Result<Upstream> {
        let local = stream.local_addr().ok();
        let config = self.client_config(alpn, Arc::new(AuthState::default()))?;
        let stream = TlsConnector::from(config)
            .connect(self.server_name.clone(), stream)
            .await?;
        ensure_alpn(stream.get_ref().1.alpn_protocol(), alpn)?;
        Ok(Upstream::new(Box::new(stream), local))
    }

    /// 完成 REALITY 握手但保留受控记录层，供 VLESS Vision 原始记录切换。
    pub(crate) async fn connect_controlled(
        &self,
        stream: UpstreamStream,
        alpn: Option<&[u8]>,
    ) -> io::Result<Controlled<UpstreamStream>> {
        let config = self.client_config(alpn, Arc::new(AuthState::default()))?;
        let controlled = Controlled::connect(stream, config, self.server_name.clone()).await?;
        ensure_alpn(controlled.alpn_protocol().as_deref(), alpn)?;
        Ok(controlled)
    }
}

fn ensure_alpn(negotiated: Option<&[u8]>, expected: Option<&[u8]>) -> io::Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    // Xray 的 REALITY 服务端在 gRPC 场景可能不回显 ALPN；gRPC 仍可按
    // HTTP/2 prior-knowledge 运行。其它传输仍要求精确匹配。
    let mismatch = match negotiated {
        Some(protocol) => protocol != expected,
        None => expected != b"h2",
    };
    if mismatch {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "上游 REALITY ALPN 与配置的传输不一致",
        ));
    }
    Ok(())
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.len() > 16 {
        anyhow::bail!("REALITY short_id 必须是偶数个十六进制字符");
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let text =
            std::str::from_utf8(pair).map_err(|_| anyhow::anyhow!("REALITY short_id 无效"))?;
        output.push(
            u8::from_str_radix(text, 16).map_err(|_| anyhow::anyhow!("REALITY short_id 无效"))?,
        );
    }
    Ok(output)
}
