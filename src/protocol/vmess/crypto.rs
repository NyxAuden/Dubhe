//! VMess 协议派生的有限组合；AES、AEAD、摘要与每层 HMAC 均委托成熟库。
use std::io;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use cryptoxide::{digest::Digest as LegacyDigest, hmac::Hmac, mac::Mac, sha2::Sha256};
use md5::{Digest, Md5};

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "VMess 密码处理失败")
}

// 只转发 Digest/Mac 接口，不实现 HMAC 的密钥块、填充或摘要算法。
enum Nested {
    // RustCrypto 的 clone + finalize 提供 Digest 要求的可重复读取；
    // cryptoxide 0.5 的 SHA256 result 会消耗状态，不能直接用于该适配。
    Sha(sha2::Sha256),
    Mac(Box<Hmac<Nested>>),
}
impl LegacyDigest for Nested {
    fn input(&mut self, input: &[u8]) {
        match self {
            Self::Sha(h) => sha2::Digest::update(h, input),
            Self::Mac(h) => h.input(input),
        }
    }
    fn result(&mut self, out: &mut [u8]) {
        match self {
            Self::Sha(h) => out[..32].copy_from_slice(&sha2::Digest::finalize(h.clone())),
            Self::Mac(h) => h.raw_result(out),
        }
    }
    fn reset(&mut self) {
        match self {
            Self::Sha(h) => sha2::Digest::reset(h),
            Self::Mac(h) => h.reset(),
        }
    }
    fn output_bits(&self) -> usize {
        256
    }
    fn block_size(&self) -> usize {
        64
    }
}

pub(crate) fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    // 路径由本模块调用方的固定协议 labels 构成，不接受任意网络递归深度。
    assert!(path.len() <= 4);
    let mut hash = Nested::Mac(Box::new(Hmac::new(
        Nested::Sha(sha2::Sha256::default()),
        b"VMess AEAD KDF",
    )));
    for part in path {
        hash = Nested::Mac(Box::new(Hmac::new(hash, part)));
    }
    hash.input(key);
    let mut output = [0; 32];
    hash.result(&mut output);
    output
}

pub(crate) fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().expect("固定摘要长度")
}

pub(crate) fn command_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(uuid);
    md5.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    md5.finalize().into()
}

pub(crate) fn derive_response(input: &[u8; 16]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.input(input);
    let mut output = [0; 32];
    hash.result(&mut output);
    output[..16].try_into().expect("固定摘要长度")
}

pub(crate) fn chacha_key(input: &[u8; 16]) -> [u8; 32] {
    let first = Md5::digest(input);
    let second = Md5::digest(first);
    let mut output = [0; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

pub(crate) fn auth_id(key: &[u8; 16], block: &[u8; 16], encrypt: bool) -> [u8; 16] {
    let cipher = aes::Aes128::new(key.into());
    let mut block = (*block).into();
    if encrypt {
        cipher.encrypt_block(&mut block);
    } else {
        cipher.decrypt_block(&mut block);
    }
    block.into()
}

pub(crate) enum Cipher {
    Aes(Box<Aes128Gcm>),
    ChaCha(ChaCha20Poly1305),
}
impl Cipher {
    pub(crate) fn new(security: u8, key: &[u8; 16]) -> io::Result<Self> {
        match security {
            3 => Ok(Self::Aes(Box::new(Aes128Gcm::new(key.into())))),
            4 => Ok(Self::ChaCha(ChaCha20Poly1305::new(
                (&chacha_key(key)).into(),
            ))),
            _ => Err(invalid()),
        }
    }
    pub(crate) fn seal(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            Self::Aes(cipher) => cipher.encrypt(nonce.into(), payload),
            Self::ChaCha(cipher) => cipher.encrypt(nonce.into(), payload),
        }
        .map_err(|_| invalid())
    }
    pub(crate) fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> io::Result<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            Self::Aes(cipher) => cipher.decrypt(nonce.into(), payload),
            Self::ChaCha(cipher) => cipher.decrypt(nonce.into(), payload),
        }
        .map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn mature_aes_gcm_nist_and_aes_block_vectors() {
        // NIST SP800-38D：全零128位key/96位nonce/空正文、空AAD。
        let cipher = Cipher::new(3, &[0; 16]).unwrap();
        assert_eq!(
            cipher.seal(&[0; 12], &[], &[]).unwrap(),
            hex("58e2fccefa7e3061367f1d57a4e7455a")
        );
        // FIPS197 AES128 单块：用于 AuthID 的原语，不是生产自编码互测。
        let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let input: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        assert_eq!(
            auth_id(&key, &input, true).as_slice(),
            hex("69c4e0d86a7b0430d8cdb78070b4c55a")
        );
        assert_eq!(auth_id(&key, &auth_id(&key, &input, true), false), input);
    }
    #[test]
    fn protocol_derivation_independent_python_standard_hmac_vectors() {
        // 独立 Python hashlib/hmac.new 嵌套构造器生成，未运行参考内核。
        let key = std::array::from_fn::<_, 16, _>(|n| n as u8);
        for (path, expected) in [
            (
                vec![],
                "ebdb909829820c287b7d7601fe00d5b093f4485a027311c2205e9007d5fc9c16",
            ),
            (
                vec![b"AES Auth ID Encryption".as_slice()],
                "9fa4289c41650861a45b34aeab3879fe4785dce57ab3f68cfb0cc60fca69460a",
            ),
            (
                vec![
                    b"VMess Header AEAD Key_Length".as_slice(),
                    key.as_slice(),
                    &key[..8],
                ],
                "5159f29b961518a54f03a0e844e3299d9d7c7e1f33350fa73adec01a4cd76fc1",
            ),
            (
                vec![b"auth_len".as_slice()],
                "1dccf11d87f6b6c6ffbaa5b90794383cc545c3407e3116bcc48f5891d4acb9eb",
            ),
        ] {
            assert_eq!(kdf(&key, &path).as_slice(), hex(expected));
            assert_eq!(kdf16(&key, &path).as_slice(), &hex(expected)[..16]);
        }
        assert_eq!(
            command_key(&key).as_slice(),
            hex("8e12bc156ecaf05b7f0a83a21aa77742")
        );
        assert_eq!(
            chacha_key(&key).as_slice(),
            hex("1ac1ef01e96caf1be0d329331a4fc2a8e0542db5418c43d256a6a643afa553fe")
        );
        assert_eq!(
            derive_response(&key).as_slice(),
            hex("be45cb2605bf36bebde684841a28f0fd")
        );
    }
    #[test]
    fn nested_digest_reset_and_repeated_result() {
        let mut h = Nested::Mac(Box::new(Hmac::new(
            Nested::Sha(sha2::Sha256::default()),
            &[0x0b; 20],
        )));
        h.input(b"Hi There");
        let mut first = [0; 32];
        h.result(&mut first);
        assert_eq!(
            first.as_slice(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        let mut second = [0; 32];
        h.result(&mut second);
        assert_eq!(first, second);
        h.reset();
        h.input(b"Hi There");
        h.result(&mut second);
        assert_eq!(first, second);
    }
}
