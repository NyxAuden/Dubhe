//! REALITY 出站临时证书与 ML-DSA-65 扩展校验核心。
//!
//! 校验顺序与 Xray-core `transport/internet/reality/reality.go` 的
//! `UConn.VerifyPeerCertificate` 保持一致：
//!
//! 1. 证书 SubjectPublicKeyInfo 必须是 Ed25519，取出 32 字节公钥；
//! 2. 计算 `HMAC-SHA512(auth_key, ed25519_pubkey)`，与证书
//!    `signatureValue` 做常数时间比较；
//! 3. 若调用方配置了 `mldsa65Verify`，在同一 HMAC 状态上继续写入
//!    raw ClientHello 与 raw ServerHello，再以
//!    `HMAC-SHA512(auth_key, ed25519_pubkey || rawCH || rawSH)` 为消息、
//!    证书第一个扩展的 Value 为签名，用客户端配置的 ML-DSA-65 公钥校验。
//!
//! 密码学全部复用 AWS-LC（`aws-lc-rs`）：HMAC-SHA512 与 ML-DSA-65
//! 验签均由 AWS-LC 执行，本模块不实现任何密码原语，也不解析完整的
//! X.509 证书。调用方负责从证书中提取以下原始字节：
//!
//! - Ed25519 SPKI（`tbsCertificate.subjectPublicKeyInfo` 的 DER 编码）；
//! - 证书 `signatureValue`；
//! - 第一个扩展的 `extnValue`（注意不是外层 OCTET STRING，而是其内容，
//!   与 Go `x509.Certificate.Extensions[0].Value` 一致）；
//! - 原始 ClientHello / ServerHello 记录（`Raw` 字段，含握手头）。
//!
//! 未配置 ML-DSA-65 公钥时，只执行 HMAC 校验，与上游行为一致：即使证书
//! 带有扩展也不会被检查。配置了公钥但证书没有扩展、扩展校验失败或临时
//! 证书 HMAC 不匹配时，调用方应视为未通过 REALITY 认证并回落到普通证书
//! 校验路径。

use aws_lc_rs::{
    constant_time, hmac,
    signature::{ML_DSA_65, ParsedPublicKey},
};

/// Ed25519 公钥原始字节长度。
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 的 `id-Ed25519` OID（1.3.101.112）完整 DER 内容。
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// 单个 REALITY 临时证书的校验输入。
///
/// 所有字段都是证书/握手报文的原始字节，本模块不持有所有权。
#[derive(Clone, Copy)]
pub struct CertVerificationInput<'a> {
    /// REALITY 握手派生的 32 字节 auth key。
    pub auth_key: &'a [u8],
    /// 临时证书的 Ed25519 SubjectPublicKeyInfo（DER）。
    pub ed25519_spki: &'a [u8],
    /// 临时证书的 `signatureValue`，即 `HMAC-SHA512(auth_key, pubkey)`。
    pub certificate_signature: &'a [u8],
    /// 证书第一个扩展的 Value；配置了 ML-DSA-65 公钥时必需。
    pub first_extension_value: Option<&'a [u8]>,
    /// 原始 ClientHello（含握手消息头）。
    pub raw_client_hello: &'a [u8],
    /// 原始 ServerHello（含握手消息头）。
    pub raw_server_hello: &'a [u8],
    /// 客户端配置的 ML-DSA-65 公钥（原始 1952 字节，AWS-LC 也接受
    /// RFC 5280 DER）；`None` 表示未启用扩展校验。
    pub mldsa65_public_key: Option<&'a [u8]>,
}

/// 校验通过后的认证级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedCertificate {
    /// 临时证书 HMAC 通过；未配置 ML-DSA-65 公钥。
    Hmac,
    /// 临时证书 HMAC 与 ML-DSA-65 扩展校验均通过。
    HmacAndMldsa65,
}

impl VerifiedCertificate {
    /// 是否完成了 ML-DSA-65 扩展校验。
    #[must_use]
    #[cfg(test)]
    pub fn mldsa65_verified(self) -> bool {
        matches!(self, Self::HmacAndMldsa65)
    }
}

/// REALITY 临时证书校验错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// SubjectPublicKeyInfo 不是合法的 Ed25519 SPKI。
    InvalidEd25519Spki,
    /// 证书签名不等于 `HMAC-SHA512(auth_key, ed25519_pubkey)`。
    HmacMismatch,
    /// 配置了 ML-DSA-65 公钥，但证书没有扩展。
    MissingFirstExtension,
    /// ML-DSA-65 公钥无法被 AWS-LC 接受。
    InvalidMldsa65PublicKey,
    /// 第一个扩展的 Value 不是有效的 ML-DSA-65 签名。
    Mldsa65SignatureInvalid,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::InvalidEd25519Spki => "REALITY 临时证书 Ed25519 SPKI 无效",
            Self::HmacMismatch => "REALITY 临时证书 HMAC 不匹配",
            Self::MissingFirstExtension => "REALITY 临时证书缺少 ML-DSA-65 扩展",
            Self::InvalidMldsa65PublicKey => "REALITY ML-DSA-65 公钥无效",
            Self::Mldsa65SignatureInvalid => "REALITY ML-DSA-65 扩展签名无效",
        };
        f.write_str(message)
    }
}

impl std::error::Error for VerifyError {}

/// 校验 REALITY 临时证书，并在配置了公钥时校验第一个扩展。
///
/// 返回值只表示认证级别；任何失败都通过 [`VerifyError`] 返回，便于调用方
/// 记录原因并回落到普通证书校验。校验过程不修改输入。
pub fn verify_certificate(
    input: &CertVerificationInput<'_>,
) -> Result<VerifiedCertificate, VerifyError> {
    let public_key = ed25519_public_key_from_spki(input.ed25519_spki)?;

    let key = hmac::Key::new(hmac::HMAC_SHA512, input.auth_key);
    let mut context = hmac::Context::with_key(&key);
    context.update(&public_key);

    // 克隆保留当前 HMAC 状态：上游在同一个 hmac.Hash 上先 Sum 再继续写入。
    let certificate_hmac = context.clone().sign();
    constant_time::verify_slices_are_equal(certificate_hmac.as_ref(), input.certificate_signature)
        .map_err(|_| VerifyError::HmacMismatch)?;

    let Some(mldsa65_public_key) = input.mldsa65_public_key else {
        return Ok(VerifiedCertificate::Hmac);
    };

    let extension_value = input
        .first_extension_value
        .ok_or(VerifyError::MissingFirstExtension)?;

    context.update(input.raw_client_hello);
    context.update(input.raw_server_hello);
    let message = context.sign();

    // AWS-LC 同时接受原始公钥与 RFC 5280 DER；先解析公钥，把
    // “公钥配置错误”和“签名错误”区分开。
    let verifier = ParsedPublicKey::new(&ML_DSA_65, mldsa65_public_key)
        .map_err(|_| VerifyError::InvalidMldsa65PublicKey)?;
    match verifier.verify_sig(message.as_ref(), extension_value) {
        Ok(()) => Ok(VerifiedCertificate::HmacAndMldsa65),
        Err(_) => Err(VerifyError::Mldsa65SignatureInvalid),
    }
}

/// 从 Ed25519 SPKI 中取出 32 字节原始公钥。
///
/// 只接受 RFC 8410 定义的精确结构：
///
/// ```text
/// SEQUENCE {
///   SEQUENCE { OBJECT IDENTIFIER 1.3.101.112 }
///   BIT STRING { 0x00, 32 字节公钥 }
/// }
/// ```
///
/// 不接受额外字段或尾部数据，避免把其他算法/结构的公钥误认为 Ed25519。
pub fn ed25519_public_key_from_spki(
    spki: &[u8],
) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], VerifyError> {
    let mut outer = DerReader::new(spki);
    let body = outer.expect(0x30)?;
    if !outer.is_empty() {
        return Err(VerifyError::InvalidEd25519Spki);
    }

    let mut sequence = DerReader::new(body);
    let algorithm = sequence.expect(0x30)?;
    if algorithm != ED25519_OID_DER {
        return Err(VerifyError::InvalidEd25519Spki);
    }
    let bit_string = sequence.expect(0x03)?;
    if !sequence.is_empty() || bit_string.len() != ED25519_PUBLIC_KEY_LEN + 1 {
        return Err(VerifyError::InvalidEd25519Spki);
    }
    if bit_string[0] != 0 {
        return Err(VerifyError::InvalidEd25519Spki);
    }

    let mut public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
    public_key.copy_from_slice(&bit_string[1..]);
    Ok(public_key)
}

/// 极简 DER TLV 读取器，仅服务 Ed25519 SPKI 的固定结构。
struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8], VerifyError> {
        let rest = &self.bytes[self.offset..];
        let (&actual, rest) = rest.split_first().ok_or(VerifyError::InvalidEd25519Spki)?;
        if actual != tag {
            return Err(VerifyError::InvalidEd25519Spki);
        }
        let (&first, rest) = rest.split_first().ok_or(VerifyError::InvalidEd25519Spki)?;
        let (length, rest) = if first & 0x80 == 0 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            // SPKI 远小于 64 KiB，拒绝超长长度编码与非最短编码。
            if count == 0 || count > 2 || rest.len() < count {
                return Err(VerifyError::InvalidEd25519Spki);
            }
            let (length_bytes, rest) = rest.split_at(count);
            if length_bytes[0] == 0 {
                return Err(VerifyError::InvalidEd25519Spki);
            }
            let mut length = 0usize;
            for &byte in length_bytes {
                length = (length << 8) | usize::from(byte);
            }
            if length < 0x80 {
                return Err(VerifyError::InvalidEd25519Spki);
            }
            (length, rest)
        };
        if rest.len() < length {
            return Err(VerifyError::InvalidEd25519Spki);
        }
        let (value, rest) = rest.split_at(length);
        self.offset = self.bytes.len() - rest.len();
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        hmac,
        signature::{KeyPair, ML_DSA_65_SIGNING, PqdsaKeyPair},
    };

    /// RFC 8032 测试向量中的 Ed25519 公钥。
    const ED25519_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const AUTH_KEY: [u8; 32] = [0x42; 32];
    const RAW_CH: &[u8] = b"raw-client-hello";
    const RAW_SH: &[u8] = b"raw-server-hello";

    fn spki(public_key: &[u8; 32]) -> Vec<u8> {
        let mut der = Vec::with_capacity(44);
        der.extend_from_slice(&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
        der.extend_from_slice(&[0x03, 0x21, 0x00]);
        der.extend_from_slice(public_key);
        der
    }

    fn hmac_pub() -> Vec<u8> {
        hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA512, &AUTH_KEY),
            &ED25519_PUBLIC,
        )
        .as_ref()
        .to_vec()
    }

    fn hmac_full() -> Vec<u8> {
        let mut context = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, &AUTH_KEY));
        context.update(&ED25519_PUBLIC);
        context.update(RAW_CH);
        context.update(RAW_SH);
        context.sign().as_ref().to_vec()
    }

    fn input<'a>(
        spki: &'a [u8],
        signature: &'a [u8],
        extension: Option<&'a [u8]>,
        raw_ch: &'a [u8],
        raw_sh: &'a [u8],
        mldsa65_public_key: Option<&'a [u8]>,
    ) -> CertVerificationInput<'a> {
        CertVerificationInput {
            auth_key: &AUTH_KEY,
            ed25519_spki: spki,
            certificate_signature: signature,
            first_extension_value: extension,
            raw_client_hello: raw_ch,
            raw_server_hello: raw_sh,
            mldsa65_public_key,
        }
    }

    fn mldsa_sign(key_pair: &PqdsaKeyPair, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let length = key_pair.sign(message, &mut signature).unwrap();
        signature.truncate(length);
        signature
    }

    #[test]
    fn parses_ed25519_spki() {
        assert_eq!(
            ed25519_public_key_from_spki(&spki(&ED25519_PUBLIC)).unwrap(),
            ED25519_PUBLIC
        );
    }

    #[test]
    fn rejects_malformed_spki() {
        let valid = spki(&ED25519_PUBLIC);

        // 尾部多余字节。
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            ed25519_public_key_from_spki(&trailing),
            Err(VerifyError::InvalidEd25519Spki)
        );

        // 错误的算法 OID。
        let mut wrong_oid = valid.clone();
        wrong_oid[8] = 0x2c;
        assert_eq!(
            ed25519_public_key_from_spki(&wrong_oid),
            Err(VerifyError::InvalidEd25519Spki)
        );

        // BIT STRING 未使用位不为 0。
        let mut bad_bits = valid;
        bad_bits[11] = 1;
        assert_eq!(
            ed25519_public_key_from_spki(&bad_bits),
            Err(VerifyError::InvalidEd25519Spki)
        );
    }

    #[test]
    fn accepts_hmac_only_when_mldsa65_not_configured() {
        let spki = spki(&ED25519_PUBLIC);
        let signature = hmac_pub();
        let verified = verify_certificate(&input(
            &spki,
            &signature,
            Some(b"ignored extension"),
            RAW_CH,
            RAW_SH,
            None,
        ))
        .unwrap();
        assert_eq!(verified, VerifiedCertificate::Hmac);
        assert!(!verified.mldsa65_verified());
    }

    #[test]
    fn rejects_wrong_hmac() {
        let spki = spki(&ED25519_PUBLIC);
        let mut signature = hmac_pub();
        *signature.last_mut().unwrap() ^= 0xff;
        assert_eq!(
            verify_certificate(&input(&spki, &signature, None, RAW_CH, RAW_SH, None)),
            Err(VerifyError::HmacMismatch)
        );
    }

    #[test]
    fn rejects_hmac_over_different_public_key() {
        let spki = spki(&[0x11; 32]);
        let signature = hmac_pub();
        assert_eq!(
            verify_certificate(&input(&spki, &signature, None, RAW_CH, RAW_SH, None)),
            Err(VerifyError::HmacMismatch)
        );
    }

    #[test]
    fn verifies_mldsa65_over_pubkey_and_raw_hellos() {
        let key_pair = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let spki = spki(&ED25519_PUBLIC);
        let signature = hmac_pub();
        let extension = mldsa_sign(&key_pair, &hmac_full());

        let verified = verify_certificate(&input(
            &spki,
            &signature,
            Some(&extension),
            RAW_CH,
            RAW_SH,
            Some(&public_key),
        ))
        .unwrap();
        assert_eq!(verified, VerifiedCertificate::HmacAndMldsa65);
        assert!(verified.mldsa65_verified());
    }

    #[test]
    fn rejects_mldsa65_that_omits_raw_hellos() {
        let key_pair = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let spki = spki(&ED25519_PUBLIC);
        let signature = hmac_pub();
        // 只签 HMAC(pubkey)，没有继续吸收 rawCH/rawSH。
        let extension = mldsa_sign(&key_pair, &hmac_pub());

        assert_eq!(
            verify_certificate(&input(
                &spki,
                &signature,
                Some(&extension),
                RAW_CH,
                RAW_SH,
                Some(&public_key),
            )),
            Err(VerifyError::Mldsa65SignatureInvalid)
        );
    }

    #[test]
    fn rejects_mldsa65_with_changed_raw_client_hello() {
        let key_pair = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let spki = spki(&ED25519_PUBLIC);
        let signature = hmac_pub();
        let extension = mldsa_sign(&key_pair, &hmac_full());

        assert_eq!(
            verify_certificate(&input(
                &spki,
                &signature,
                Some(&extension),
                b"changed-client-hello",
                RAW_SH,
                Some(&public_key),
            )),
            Err(VerifyError::Mldsa65SignatureInvalid)
        );
    }

    #[test]
    fn rejects_mldsa65_with_wrong_public_key() {
        let signer = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let other = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let spki = spki(&ED25519_PUBLIC);
        let signature = hmac_pub();
        let extension = mldsa_sign(&signer, &hmac_full());
        let other_public_key = other.public_key().as_ref().to_vec();

        assert_eq!(
            verify_certificate(&input(
                &spki,
                &signature,
                Some(&extension),
                RAW_CH,
                RAW_SH,
                Some(&other_public_key),
            )),
            Err(VerifyError::Mldsa65SignatureInvalid)
        );
    }

    #[test]
    fn rejects_missing_extension_when_mldsa65_configured() {
        let key_pair = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let spki = spki(&ED25519_PUBLIC);
        let signature = hmac_pub();

        assert_eq!(
            verify_certificate(&input(
                &spki,
                &signature,
                None,
                RAW_CH,
                RAW_SH,
                Some(&public_key),
            )),
            Err(VerifyError::MissingFirstExtension)
        );
    }

    #[test]
    fn rejects_truncated_public_key() {
        let spki = spki(&ED25519_PUBLIC);
        let signature = hmac_pub();
        let short_key = [0u8; 32];

        assert_eq!(
            verify_certificate(&input(
                &spki,
                &signature,
                Some(b"signature"),
                RAW_CH,
                RAW_SH,
                Some(&short_key),
            )),
            Err(VerifyError::InvalidMldsa65PublicKey)
        );
    }

    #[test]
    fn rejects_hmac_before_checking_extension() {
        let key_pair = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let spki = spki(&ED25519_PUBLIC);
        let mut signature = hmac_pub();
        *signature.last_mut().unwrap() ^= 0x01;

        assert_eq!(
            verify_certificate(&input(
                &spki,
                &signature,
                Some(b"irrelevant"),
                RAW_CH,
                RAW_SH,
                Some(&public_key),
            )),
            Err(VerifyError::HmacMismatch)
        );
    }
}
