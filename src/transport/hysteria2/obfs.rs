//! Salamander obfs（UDP 层）。
//!
//! 上游行为（`sing-quic/.../hysteria2/salamander.go`）：
//! - 每个 UDP 报文先放 8 字节随机 salt；
//! - `key = BLAKE2b-256(password || salt)`，输出正好 32 字节；
//! - 线上第 `8 + i` 字节 = 明文第 `i` 字节 XOR `key[i % 32]`。
//!
//! 接收端要求报文长度大于 8；salt 之后的全部字节参与解密。该模块不依赖
//! crate 内其它模块，便于测试独立包含。

use std::io;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

pub(crate) const SALT_LEN: usize = 8;
pub(crate) const KEY_LEN: usize = 32;
/// 线上单个 UDP 报文的最大长度（IPv4 UDP 载荷上限）。
pub(crate) const MAX_WIRE_PACKET: usize = 65_535;

type Blake2b256 = Blake2b<U32>;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// 由密码与 salt 派生 32 字节流密钥。
pub(crate) fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = Blake2b256::new();
    hasher.update(password);
    hasher.update(salt);
    let digest = hasher.finalize();
    let mut key = [0u8; KEY_LEN];
    for (target, source) in key.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    key
}

fn xor_stream(key: &[u8; KEY_LEN], data: &mut [u8]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index % KEY_LEN];
    }
}

/// 使用固定 salt 封装，便于测试向量与确定性校验。
pub(crate) fn seal_with_salt(password: &[u8], salt: [u8; SALT_LEN], plaintext: &[u8]) -> Vec<u8> {
    let key = derive_key(password, &salt);
    let mut output = Vec::with_capacity(SALT_LEN + plaintext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(plaintext);
    if let Some(ciphertext) = output.get_mut(SALT_LEN..) {
        xor_stream(&key, ciphertext);
    }
    output
}

/// 使用系统 CSPRNG 生成 salt 并封装一个 UDP 报文。
pub(crate) fn seal(password: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    if plaintext.len() + SALT_LEN > MAX_WIRE_PACKET {
        return Err(invalid("UDP 报文超过长度上限"));
    }
    let mut salt = [0u8; SALT_LEN];
    aws_lc_rs::rand::fill(&mut salt).map_err(|_| io::Error::other("随机数生成失败"))?;
    Ok(seal_with_salt(password, salt, plaintext))
}

/// 解密到调用方缓冲区，返回明文切片；报文过短或缓冲区不足时报错。
pub(crate) fn open_into<'a>(
    password: &[u8],
    packet: &[u8],
    output: &'a mut [u8],
) -> io::Result<&'a mut [u8]> {
    if packet.len() <= SALT_LEN {
        return Err(invalid("obfs 报文过短"));
    }
    let payload_length = packet.len() - SALT_LEN;
    if output.len() < payload_length {
        return Err(invalid("obfs 输出缓冲区不足"));
    }
    let salt = packet
        .get(..SALT_LEN)
        .ok_or_else(|| invalid("obfs salt 不完整"))?;
    let key = derive_key(password, salt);
    let ciphertext = packet
        .get(SALT_LEN..)
        .ok_or_else(|| invalid("obfs 密文不完整"))?;
    for (index, byte) in ciphertext.iter().enumerate() {
        if let Some(target) = output.get_mut(index) {
            *target = *byte ^ key[index % KEY_LEN];
        }
    }
    output
        .get_mut(..payload_length)
        .ok_or_else(|| invalid("obfs 输出缓冲区不足"))
}

/// 解密并复制到新的 `Vec`。
// 供 tests/hysteria2.rs 通过 #[path] 引入使用；lib 内只走 open_into。
#[allow(dead_code)]
pub(crate) fn open(password: &[u8], packet: &[u8]) -> io::Result<Vec<u8>> {
    if packet.len() <= SALT_LEN {
        return Err(invalid("obfs 报文过短"));
    }
    let mut output = vec![0u8; packet.len() - SALT_LEN];
    open_into(password, packet, &mut output)?;
    Ok(output)
}
