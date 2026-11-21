//! mKCP 的 UDP 混淆头与数据包认证层。
//!
//! 线序与 Xray 一致：先写混淆头，再写认证层，最后是 KCP 分段。
//! `legacy` 认证层对应 Xray 25 及更早版本的 `SimpleAuthenticator`
//! （4 字节 FNV-1a + 2 字节长度 + 4 字节字级 XOR）；
//! `seed` 存在时改用 SHA-256(seed)[..16] 派生的 AES-128-GCM。

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

use crate::config::{Kcp, KcpHeader, KcpSecurity};
use crate::util::fnv1a;

const LEGACY_OVERHEAD: usize = 6;
const GCM_NONCE: usize = 12;
const GCM_TAG: usize = 16;

pub struct Mask {
    header: Header,
    security: Security,
}

#[allow(clippy::large_enum_variant)] // 每个连接构造一次，热路径只匹配。
enum Security {
    None,
    Legacy,
    AesGcm(Aes128Gcm),
}

enum Header {
    None,
    Dns { prefix: Vec<u8> },
    Dtls { length: u16, sequence: u32 },
    Srtp { number: u16 },
    Utp,
    Wechat { sn: u32 },
    Wireguard,
}

impl Mask {
    pub fn new(config: &Kcp) -> Result<Self> {
        let security = match (&config.seed, config.security) {
            (Some(seed), KcpSecurity::Legacy) => {
                let key = Sha256::digest(seed.as_bytes());
                let cipher = Aes128Gcm::new_from_slice(&key[..16])
                    .map_err(|_| anyhow::anyhow!("mKCP seed 无法派生 AES-128-GCM 密钥"))?;
                Security::AesGcm(cipher)
            }
            (None, KcpSecurity::Legacy) => Security::Legacy,
            (None, KcpSecurity::None) => Security::None,
            (Some(_), KcpSecurity::None) => {
                anyhow::bail!("mKCP seed 不能与 security=none 并存")
            }
        };
        let header = match &config.header {
            KcpHeader::None => Header::None,
            KcpHeader::Dns { domain } => Header::Dns {
                prefix: dns_prefix(domain)?,
            },
            KcpHeader::Dtls => Header::Dtls {
                length: 0,
                sequence: 0,
            },
            KcpHeader::Srtp => Header::Srtp { number: 0 },
            KcpHeader::Utp => Header::Utp,
            KcpHeader::Wechat => Header::Wechat { sn: 0 },
            KcpHeader::Wireguard => Header::Wireguard,
        };
        Ok(Self { header, security })
    }

    /// 每条 UDP 报文的固定封装开销，供 MTU 分组与 MSS 计算共用。
    pub fn overhead(&self) -> usize {
        self.header.size()
            + match &self.security {
                Security::None => 0,
                Security::Legacy => LEGACY_OVERHEAD,
                Security::AesGcm(_) => GCM_NONCE + GCM_TAG,
            }
    }

    /// 去掉混淆头与认证层；任何认证失败都返回 `None`。
    pub fn decode(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let size = self.header.size();
        if packet.len() <= size {
            return None;
        }
        let body = &packet[size..];
        match &self.security {
            Security::None => Some(body.to_vec()),
            Security::Legacy => legacy_open(body),
            Security::AesGcm(cipher) => {
                if body.len() < GCM_NONCE + GCM_TAG {
                    return None;
                }
                let nonce = aes_gcm::Nonce::try_from(&body[..GCM_NONCE]).ok()?;
                cipher.decrypt(&nonce, &body[GCM_NONCE..]).ok()
            }
        }
    }

    /// 写入混淆头与认证层；随机源失败时返回 `None`（丢弃该包）。
    pub fn encode(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let body = match &self.security {
            Security::None => payload.to_vec(),
            Security::Legacy => legacy_seal(payload)?,
            Security::AesGcm(cipher) => {
                let mut nonce = [0u8; GCM_NONCE];
                aws_lc_rs::rand::fill(&mut nonce).ok()?;
                let nonce = aes_gcm::Nonce::try_from(nonce.as_slice()).ok()?;
                let ciphertext = cipher.encrypt(&nonce, payload).ok()?;
                let mut out = Vec::with_capacity(GCM_NONCE + ciphertext.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&ciphertext);
                out
            }
        };
        let mut packet = vec![0u8; self.header.size()];
        self.header.serialize(&mut packet);
        packet.extend_from_slice(&body);
        Some(packet)
    }
}

/// Xray `SimpleAuthenticator.Seal`。
fn legacy_seal(plain: &[u8]) -> Option<Vec<u8>> {
    let length = u16::try_from(plain.len()).ok()?;
    let mut out = vec![0u8; LEGACY_OVERHEAD + plain.len()];
    out[4..6].copy_from_slice(&length.to_be_bytes());
    out[6..].copy_from_slice(plain);
    let hash = fnv1a(&out[4..]);
    out[..4].copy_from_slice(&hash.to_be_bytes());
    let length = out.len();
    let extra = (4 - length % 4) % 4;
    out.resize(length + extra, 0);
    for index in 4..out.len() {
        out[index] ^= out[index - 4];
    }
    out.truncate(length);
    Some(out)
}

/// Xray `SimpleAuthenticator.Open`。
fn legacy_open(ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() <= LEGACY_OVERHEAD {
        return None;
    }
    let length = ciphertext.len();
    let extra = (4 - length % 4) % 4;
    let mut buffer = ciphertext.to_vec();
    buffer.resize(length + extra, 0);
    for index in (4..buffer.len()).rev() {
        buffer[index] ^= buffer[index - 4];
    }
    buffer.truncate(length);
    let hash = u32::from_be_bytes(buffer[..4].try_into().ok()?);
    if hash != fnv1a(&buffer[4..]) {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes(buffer[4..6].try_into().ok()?));
    if buffer.len() - LEGACY_OVERHEAD != payload_len {
        return None;
    }
    Some(buffer[LEGACY_OVERHEAD..].to_vec())
}

impl Header {
    fn size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Dns { prefix } => prefix.len(),
            Self::Dtls { .. } => 13,
            Self::Srtp { .. } | Self::Utp | Self::Wireguard => 4,
            Self::Wechat { .. } => 13,
        }
    }

    fn serialize(&mut self, buffer: &mut [u8]) {
        match self {
            Self::None => {}
            Self::Dns { prefix } => {
                buffer.copy_from_slice(prefix);
                let mut transaction = [0u8; 2];
                if aws_lc_rs::rand::fill(&mut transaction).is_ok() {
                    buffer[..2].copy_from_slice(&transaction);
                }
            }
            Self::Dtls { length, sequence } => {
                buffer[0] = 23;
                buffer[1] = 254;
                buffer[2] = 253;
                // epoch 固定为 0。
                buffer[3] = 0;
                buffer[4] = 0;
                buffer[5] = 0;
                buffer[6] = 0;
                buffer[7..11].copy_from_slice(&sequence.to_be_bytes());
                buffer[11..13].copy_from_slice(&length.to_be_bytes());
                *sequence = sequence.wrapping_add(1);
                *length = length.saturating_add(17);
                if *length > 100 {
                    *length -= 50;
                }
            }
            Self::Srtp { number } => {
                *number = number.wrapping_add(1);
                buffer[2..4].copy_from_slice(&number.to_be_bytes());
            }
            Self::Utp => {}
            Self::Wechat { sn } => {
                *sn = sn.wrapping_add(1);
                buffer[0] = 0xa1;
                buffer[1] = 0x08;
                buffer[2..6].copy_from_slice(&sn.to_be_bytes());
                buffer[6..13].copy_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            Self::Wireguard => buffer.copy_from_slice(&[0x04, 0x00, 0x00, 0x00]),
        }
    }
}

/// 12 字节 DNS 头 + 问题名 + QTYPE/QCLASS。
fn dns_prefix(domain: &str) -> Result<Vec<u8>> {
    let mut prefix = vec![0u8; 12];
    prefix[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // 标准查询
    prefix[4..6].copy_from_slice(&0x0001u16.to_be_bytes()); // 1 个问题
    for label in domain.trim_end_matches('.').split('.') {
        ensure!(!label.is_empty() && label.len() <= 63, "DNS 混淆头域名无效");
        prefix.push(label.len() as u8);
        prefix.extend_from_slice(label.as_bytes());
    }
    prefix.push(0);
    prefix.extend_from_slice(&0x0001u16.to_be_bytes()); // Type A
    prefix.extend_from_slice(&0x0001u16.to_be_bytes()); // Class IN
    ensure!(
        (1..=512).contains(&prefix.len()),
        "DNS 混淆头编码后长度无效"
    );
    Ok(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(security: KcpSecurity, header: KcpHeader) -> Kcp {
        Kcp {
            security,
            header,
            ..Kcp::default()
        }
    }

    #[test]
    fn legacy_round_trip_and_padding() {
        let mut mask = Mask::new(&config(KcpSecurity::Legacy, KcpHeader::None)).unwrap();
        for payload in [b"1".as_slice(), b"12", b"123", b"1234", &[0x5a; 1350]] {
            let packet = mask.encode(payload).unwrap();
            assert_eq!(packet.len(), payload.len() + LEGACY_OVERHEAD);
            assert_eq!(mask.decode(&packet).unwrap(), payload);
        }
        // Xray 的 PacketReader 拒绝长度不超过认证开销的包；空载荷不会出现在 KCP 里。
        let empty = mask.encode(b"").unwrap();
        assert!(mask.decode(&empty).is_none());
    }

    #[test]
    fn legacy_rejects_forged_or_truncated_packets() {
        let mut mask = Mask::new(&config(KcpSecurity::Legacy, KcpHeader::None)).unwrap();
        let mut packet = mask.encode(b"authentic").unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 0x40;
        assert!(mask.decode(&packet).is_none());
        packet.truncate(5);
        assert!(mask.decode(&packet).is_none());
    }

    #[test]
    fn seed_uses_aes_gcm_with_fresh_nonce() {
        let mut config = config(KcpSecurity::Legacy, KcpHeader::None);
        config.seed = Some("test-seed".to_owned());
        let mut mask = Mask::new(&config).unwrap();
        let first = mask.encode(b"payload").unwrap();
        let second = mask.encode(b"payload").unwrap();
        assert_ne!(first, second, "每次加密必须使用新的随机 nonce");
        assert_eq!(mask.decode(&first).unwrap(), b"payload");
        assert_eq!(mask.decode(&second).unwrap(), b"payload");
        let mut wrong = config.clone();
        wrong.seed = Some("other-seed".to_owned());
        assert!(Mask::new(&wrong).unwrap().decode(&first).is_none());
    }

    #[test]
    fn raw_mode_matches_bare_packets() {
        let mask = Mask::new(&config(KcpSecurity::None, KcpHeader::None)).unwrap();
        assert_eq!(mask.decode(b"abcdef").unwrap(), b"abcdef");
    }

    #[test]
    fn headers_add_expected_prefix_lengths() {
        for (header, size) in [
            (KcpHeader::Srtp, 4),
            (KcpHeader::Utp, 4),
            (KcpHeader::Wireguard, 4),
            (KcpHeader::Dtls, 13),
            (KcpHeader::Wechat, 13),
            (
                KcpHeader::Dns {
                    domain: "www.baidu.com".to_owned(),
                },
                12 + 1 + 3 + 1 + 5 + 1 + 3 + 1 + 4,
            ),
        ] {
            let mut mask = Mask::new(&config(KcpSecurity::None, header)).unwrap();
            let packet = mask.encode(b"segments").unwrap();
            assert_eq!(packet.len(), size + 8);
            assert_eq!(mask.decode(&packet).unwrap(), b"segments");
        }
    }

    #[test]
    fn srtp_and_wechat_counters_advance_per_packet() {
        let mut mask = Mask::new(&config(KcpSecurity::None, KcpHeader::Srtp)).unwrap();
        let first = mask.encode(b"x").unwrap();
        let second = mask.encode(b"x").unwrap();
        assert_eq!(&first[2..4], &1u16.to_be_bytes());
        assert_eq!(&second[2..4], &2u16.to_be_bytes());

        let mut mask = Mask::new(&config(KcpSecurity::None, KcpHeader::Wechat)).unwrap();
        let first = mask.encode(b"x").unwrap();
        let second = mask.encode(b"x").unwrap();
        assert_eq!(&first[2..6], &1u32.to_be_bytes());
        assert_eq!(&second[2..6], &2u32.to_be_bytes());
        assert_eq!(&first[..2], &[0xa1, 0x08]);
    }

    #[test]
    fn dns_header_has_query_shape() {
        let mut mask = Mask::new(&config(
            KcpSecurity::None,
            KcpHeader::Dns {
                domain: "example.com".to_owned(),
            },
        ))
        .unwrap();
        let packet = mask.encode(b"").unwrap();
        assert_eq!(&packet[4..6], &1u16.to_be_bytes());
        assert_eq!(packet[12], 7);
        assert_eq!(&packet[13..20], b"example");
        assert_eq!(packet[20], 3);
        assert_eq!(&packet[21..24], b"com");
        assert_eq!(packet[24], 0);
    }
}
