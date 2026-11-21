//! VMess AEAD 客户端请求头。
//!
//! 支持标准 TCP（命令 1）与固定目标 UDP（命令 2）、AEAD 请求头与 security 3/4；正文加密由
//! [`super::body::Stream::new_client`] 负责。不与入站解析共享“信任输入”
//! 的假设：所有长度都由本地目标生成。

use std::{
    io,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::crypto;
use crate::session::{Host, Target};
use crate::util::fnv1a;

/// 客户端请求头协商出的正文参数。
pub(crate) struct State {
    pub security: u8,
    pub options: u8,
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut output = [0u8; N];
    aws_lc_rs::rand::fill(&mut output)
        .map_err(|_| io::Error::other("VMess 客户端随机数生成失败"))?;
    Ok(output)
}

fn target_bytes(target: &Target) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1 + 2 + 259);
    bytes.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            bytes.push(3);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 255
                || !domain.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(invalid("VMess 出站目标域名无效"));
            }
            bytes.push(2);
            bytes.push(domain.len() as u8);
            bytes.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(bytes)
}

fn seal_request(
    key: &[u8; 16],
    id: &[u8; 16],
    connection_nonce: &[u8; 8],
    length: bool,
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let (key_label, nonce_label): (&[u8], &[u8]) = if length {
        (
            b"VMess Header AEAD Key_Length",
            b"VMess Header AEAD Nonce_Length",
        )
    } else {
        (b"VMess Header AEAD Key", b"VMess Header AEAD Nonce")
    };
    let nonce: [u8; 12] = crypto::kdf(key, &[nonce_label, id, connection_nonce])[..12]
        .try_into()
        .expect("固定长度");
    let key = crypto::kdf16(key, &[key_label, id, connection_nonce]);
    crypto::Cipher::new(3, &key)?.seal(&nonce, id, plaintext)
}

/// 写入 VMess AEAD 请求头并消耗 38 字节服务器应答。
///
/// `security` 仅允许 3（AES-128-GCM）或 4（ChaCha20-Poly1305）；选项固定为 0，
/// padding 为 0。`command` 为 1（TCP）或 2（固定目标 UDP）。
pub(crate) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    uuid: &[u8; 16],
    target: &Target,
    security: u8,
    command: u8,
) -> io::Result<State> {
    let state = handshake_request(io, uuid, target, security, command).await?;
    // 服务器应答固定 38 字节；客户端不校验其内容，但必须消费以对齐正文。
    let mut response = [0u8; 38];
    io.read_exact(&mut response).await?;
    Ok(state)
}

/// 仅写入 VMess AEAD 请求头；38 字节应答由调用方在首次正文读取时惰性消费。
pub(crate) async fn handshake_request<S: AsyncWrite + Unpin>(
    io: &mut S,
    uuid: &[u8; 16],
    target: &Target,
    security: u8,
    command: u8,
) -> io::Result<State> {
    if !matches!(command, 1 | 2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VMess 出站命令只支持 TCP(1)/UDP(2)",
        ));
    }
    if !matches!(security, 3 | 4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VMess 出站只支持 security 3/4",
        ));
    }
    let command_key = crypto::command_key(uuid);
    let auth_key = crypto::kdf16(&command_key, &[b"AES Auth ID Encryption"]);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("系统时间早于 UNIX 纪元"))?
        .as_secs();
    let mut auth_plain = [0u8; 16];
    auth_plain[..8].copy_from_slice(&timestamp.to_be_bytes());
    auth_plain[8..12].copy_from_slice(&random::<4>()?);
    let crc = crc32fast::hash(&auth_plain[..12]);
    auth_plain[12..].copy_from_slice(&crc.to_be_bytes());
    let id = crypto::auth_id(&auth_key, &auth_plain, true);

    let iv = random::<16>()?;
    let key = random::<16>()?;
    let options = 0u8;
    let mut header = Vec::with_capacity(38 + 259 + 4);
    header.push(1);
    header.extend_from_slice(&iv);
    header.extend_from_slice(&key);
    header.push(0); // response auth
    header.push(options);
    header.push(security);
    header.push(0); // 保留位
    header.push(command);
    header.extend_from_slice(&target_bytes(target)?);
    let crc = fnv1a(&header);
    header.extend_from_slice(&crc.to_be_bytes());

    let length = u16::try_from(header.len()).map_err(|_| invalid("VMess 请求头过长"))?;
    let connection_nonce = random::<8>()?;
    let encrypted_length = seal_request(
        &command_key,
        &id,
        &connection_nonce,
        true,
        &length.to_be_bytes(),
    )?;
    let encrypted_header = seal_request(&command_key, &id, &connection_nonce, false, &header)?;

    io.write_all(&id).await?;
    io.write_all(&encrypted_length).await?;
    io.write_all(&connection_nonce).await?;
    io.write_all(&encrypted_header).await?;
    io.flush().await?;
    Ok(State {
        security,
        options,
        key,
        iv,
    })
}
