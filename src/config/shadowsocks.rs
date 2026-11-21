//! Shadowsocks显式方法、严格密钥校验与准备；不绑定socket或解析业务目标。
use std::{collections::HashSet, fmt, sync::Arc};

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize};
use shadowsocks::{
    config::{ServerUser, ServerUserManager},
    crypto::CipherKind,
};

use super::User;
use super::validate::validate_users;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ShadowsocksMethod {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20Poly1305,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aead2022Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aead2022Aes256Gcm,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Aead2022Chacha20Poly1305,
}

impl ShadowsocksMethod {
    pub fn cipher(self) -> CipherKind {
        match self {
            Self::Aes128Gcm => CipherKind::AES_128_GCM,
            Self::Aes256Gcm => CipherKind::AES_256_GCM,
            Self::Chacha20Poly1305 => CipherKind::CHACHA20_POLY1305,
            Self::Aead2022Aes128Gcm => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            Self::Aead2022Aes256Gcm => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            Self::Aead2022Chacha20Poly1305 => CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        }
    }

    pub fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Aead2022Aes128Gcm | Self::Aead2022Aes256Gcm | Self::Aead2022Chacha20Poly1305
        )
    }

    pub fn supports_users(self) -> bool {
        matches!(self, Self::Aead2022Aes128Gcm | Self::Aead2022Aes256Gcm)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

// 缺省字段为None；显式null不是有效的用户列表，不与缺省混同。
pub(super) fn present_users<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<User>>, D::Error> {
    Vec::<User>::deserialize(deserializer).map(Some)
}

pub(crate) struct ShadowsocksKeys {
    pub method: CipherKind,
    pub key: Vec<u8>,
    pub users: Option<Arc<ServerUserManager>>,
}

impl fmt::Debug for ShadowsocksKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksKeys")
            .field("method", &self.method)
            .field("key", &"[REDACTED]")
            .field(
                "users",
                &self.users.as_ref().map(|users| users.user_count()),
            )
            .finish()
    }
}

fn decode_psk(password: &str, length: usize) -> Result<Vec<u8>> {
    // 标准Base64要求规范padding；解码错误不可保留原始输入或外部错误链。
    ensure!(
        password.len() == length.div_ceil(3) * 4,
        "Shadowsocks PSK编码或长度错误"
    );
    let key = STANDARD
        .decode(password)
        .map_err(|_| anyhow::anyhow!("Shadowsocks PSK编码或长度错误"))?;
    ensure!(
        key.len() == length && STANDARD.encode(&key) == password,
        "Shadowsocks PSK编码或长度错误"
    );
    Ok(key)
}

pub(crate) fn prepare(
    method: ShadowsocksMethod,
    password: &Secret,
    users: Option<&[User]>,
    index: usize,
) -> Result<ShadowsocksKeys> {
    let cipher = method.cipher();
    let key = if method.is_2022() {
        decode_psk(&password.0, cipher.key_len())?
    } else {
        ensure!(
            !password.0.is_empty(),
            "inbounds[{index}].password 不得为空"
        );
        let mut key = vec![0; cipher.key_len()];
        shadowsocks::crypto::v1::openssl_bytes_to_key(password.0.as_bytes(), &mut key);
        key
    };
    let users = match users {
        None => None,
        Some(users) => {
            ensure!(
                method.supports_users(),
                "inbounds[{index}] 该方法不支持users"
            );
            ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
            validate_users(users, false, index)?;
            let mut keys = HashSet::new();
            let mut hashes = HashSet::new();
            let mut manager = ServerUserManager::new();
            for user in users {
                let user_key = decode_psk(&user.password, cipher.key_len())?;
                ensure!(
                    user_key != key,
                    "inbounds[{index}] 用户密钥不得等于身份密钥"
                );
                ensure!(
                    keys.insert(user_key.clone()),
                    "inbounds[{index}] 用户密钥重复"
                );
                let user = ServerUser::new(user.name.clone(), user_key);
                ensure!(
                    hashes.insert(user.identity_hash().to_vec()),
                    "inbounds[{index}] 用户身份索引冲突"
                );
                manager.add_user(user);
            }
            Some(Arc::new(manager))
        }
    };
    Ok(ShadowsocksKeys {
        method: cipher,
        key,
        users,
    })
}
