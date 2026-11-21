//! 静态 REALITY 认证与 TLS 临时 KX 严格分离，密码原语委托成熟库。
use std::{io, time::Duration};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use aws_lc_rs::{
    agreement::{self, UnparsedPublicKey, X25519},
    hkdf,
};

use super::hello::Hello;
use crate::config::{PreparedReality, Reality};

// 不派生 Debug：AuthKey 不得进入日志。
pub(crate) struct Auth {
    pub auth_key: [u8; 32],
    pub server_public: [u8; 32],
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "REALITY 认证输入无效")
}

/// None 只用于可接受结构的认证/策略失配，允许外层固定目标回落。
/// 合法长度但低阶 X25519 点由成熟 ECDH 库拒绝，不授予 REALITY；视为未认证回落。
/// 畸形、重复、PSK、early_data 已由 hello::read 硬拒绝；本函数不调用目标或重放池。
pub(crate) fn authenticate(
    config: &Reality,
    prepared: &PreparedReality,
    hello: &Hello,
    now: Duration,
) -> io::Result<Option<Auth>> {
    if hello
        .session_id
        .end
        .checked_sub(hello.session_id.start)
        .is_none()
        || hello.raw_ch.get(hello.session_id.clone()).is_none()
    {
        return Err(invalid());
    }
    if hello.session_id.len() != 32 || !hello.supported_versions.contains(&0x0304) {
        return Ok(None);
    }
    let Some(hybrid) = &hello.hybrid else {
        return Ok(None);
    };
    if hybrid.len() != 1216 {
        return Err(invalid());
    }
    let selected: &[u8] = hello
        .x25519
        .as_ref()
        .map_or(&hybrid[1184..], |key| key.as_slice());
    let peer = UnparsedPublicKey::new(&X25519, selected);
    let result = agreement::agree(&prepared.static_private, peer, (), |shared| {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &hello.random[..20]);
        let prk = salt.extract(shared);
        let info: &[&[u8]] = &[b"REALITY"];
        let okm = prk.expand(info, hkdf::HKDF_SHA256).map_err(|_| ())?;
        let mut key = [0; 32];
        okm.fill(&mut key).map_err(|_| ())?;
        Ok(key)
    });
    let Ok(auth_key) = result else {
        return Ok(None);
    };
    let mut aad = hello.raw_ch.clone();
    aad.get_mut(hello.session_id.clone())
        .ok_or_else(invalid)?
        .fill(0);
    let cipher = Aes256Gcm::new((&auth_key).into());
    let nonce: &[u8; 12] = hello.random[20..].try_into().map_err(|_| invalid())?;
    let plaintext = cipher.decrypt(
        nonce.into(),
        Payload {
            msg: hello
                .raw_ch
                .get(hello.session_id.clone())
                .ok_or_else(invalid)?,
            aad: &aad,
        },
    );
    let Ok(plaintext) = plaintext else {
        return Ok(None);
    };
    if plaintext.len() != 16 {
        return Err(invalid());
    }
    let version: [u8; 3] = plaintext[..3].try_into().map_err(|_| invalid())?;
    if plaintext[3] != 0
        || config.min_client_version.is_some_and(|min| version < min)
        || config.max_client_version.is_some_and(|max| version > max)
        || !hello
            .sni
            .as_ref()
            .is_some_and(|name| config.server_names.contains(name))
        || !prepared
            .short_ids
            .iter()
            .any(|id| id.as_slice() == &plaintext[8..16])
    {
        return Ok(None);
    }
    let timestamp = u32::from_be_bytes(plaintext[4..8].try_into().map_err(|_| invalid())?);
    let client_ms = u64::from(timestamp).checked_mul(1000).ok_or_else(invalid)?;
    u64::try_from(now.as_millis()).map_err(|_| invalid())?;
    if now.abs_diff(Duration::from_millis(client_ms))
        > Duration::from_millis(config.max_time_diff_ms)
    {
        return Ok(None);
    }
    Ok(Some(Auth {
        auth_key,
        server_public: prepared.public_key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::reality::hello;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    // Python 3.15.2 / cryptography 50.0.2 独立离线生成：X25519 -> HKDF(SHA256)
    // -> AESGCM，客户端编码未使用生产 parser/auth；金样 SHA256 另在测试固定。
    // server private=01..20，hybrid private=11*32，普通 private=22*32，random=00..1f。
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        std::array::from_fn(|n| u8::from_str_radix(&text[n * 2..n * 2 + 2], 16).unwrap())
    }
    fn vector(data: &[u8]) -> Vec<u8> {
        [(data.len() as u16).to_be_bytes().to_vec(), data.to_vec()].concat()
    }
    fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
        [kind.to_be_bytes().to_vec(), vector(data)].concat()
    }
    fn fixture(both: bool, reserved: bool) -> Vec<u8> {
        let hybrid_pub =
            hex::<32>("7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13");
        let plain_pub =
            hex::<32>("0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20");
        let mut shares = [
            vec![0x11, 0xec],
            vector(&[vec![85; 1184], hybrid_pub.to_vec()].concat()),
        ]
        .concat();
        if both {
            shares.extend([vec![0, 29], vector(&plain_pub)].concat());
        }
        let extensions = [
            ext(0, &vector(&[vec![0], vector(b"example.test")].concat())),
            ext(43, &[2, 3, 4]),
            ext(51, &vector(&shares)),
        ]
        .concat();
        let b = [
            vec![3, 3],
            (0..32).collect(),
            vec![32],
            vec![0; 32],
            vec![0, 2, 0x13, 1, 1, 0],
            vector(&extensions),
        ]
        .concat();
        let mut raw = [
            vec![
                1,
                ((b.len() >> 16) & 255) as u8,
                ((b.len() >> 8) & 255) as u8,
                (b.len() & 255) as u8,
            ],
            b,
        ]
        .concat();
        let sid = match (both, reserved) {
            (false, false) => "29d9907193adc400f5df7303f0bc84522e126120c03d88cba7eee59f277e14d6",
            (false, true) => "29d9907093adc400f5df7303f0bc8452f4cd88073284ab75613c6304211941c5",
            (true, false) => "eb793948d2f50f50ed225e0b40122e21ce65009dad8c439c72f086c56fb2ce61",
            (true, true) => "eb793949d2f50f50ed225e0b40122e21870bfc50655768d6c1f7b4feb805d469",
        };
        raw[39..71].copy_from_slice(&hex::<32>(sid));
        raw
    }
    async fn parsed(raw: Vec<u8>) -> Hello {
        hello::read(&mut [vec![22, 3, 1], vector(&raw)].concat().as_slice())
            .await
            .unwrap()
    }
    fn cfg() -> Reality {
        serde_json::from_value(json!({"target":{"host":"localhost","port":443},"private_key":URL_SAFE_NO_PAD.encode((1u8..=32).collect::<Vec<_>>()),"server_names":["example.test"],"short_ids":["1234"]})).unwrap()
    }
    const CLIENT_MS: u64 = 1_700_000_000_000;

    #[tokio::test]
    async fn independent_hybrid_only_and_distinct_plain_auth_vectors() {
        let cfg = cfg();
        let prepared = cfg.prepare().unwrap();
        for both in [false, true] {
            let raw = fixture(both, false);
            let (key, digest) = if both {
                (
                    "1534fceb7376aa89c03f504338c7044d063d671f541f2da2028de9d790c8f32f",
                    "7684bf7aaa031e4394e4aab1a5fa077ec0a68c74b9ddb8e03a54b751b784c5cb",
                )
            } else {
                (
                    "eab528009dd0eb15599b9737fcba08cbd310942fc7dc99efaeb12cebbfe961f1",
                    "e56bf4dd0e8c93270eae3e732e54750d9a0b2dc73c60aad122abf29ba8b0cddc",
                )
            };
            assert_eq!(Sha256::digest(&raw).as_slice(), hex::<32>(digest));
            let h = parsed(raw.clone()).await;
            let auth = authenticate(&cfg, &prepared, &h, Duration::from_millis(CLIENT_MS))
                .unwrap()
                .unwrap();
            assert_eq!(auth.auth_key, hex::<32>(key));
            assert_eq!(
                auth.server_public,
                hex::<32>("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c")
            );
            assert_eq!(h.raw_ch, raw);
        }
    }

    #[tokio::test]
    async fn milliseconds_inclusive_both_directions_and_versions() {
        let mut cfg = cfg();
        cfg.max_time_diff_ms = 1234;
        cfg.min_client_version = Some([26, 10, 31]);
        cfg.max_client_version = Some([26, 10, 31]);
        let p = cfg.prepare().unwrap();
        let h = parsed(fixture(true, false)).await;
        for (delta, expected) in [(1234, true), (1235, false)] {
            for now in [CLIENT_MS - delta, CLIENT_MS + delta] {
                assert_eq!(
                    authenticate(&cfg, &p, &h, Duration::from_millis(now))
                        .unwrap()
                        .is_some(),
                    expected
                );
            }
        }
        cfg.min_client_version = Some([26, 11, 0]);
        assert!(
            authenticate(&cfg, &p, &h, Duration::from_millis(CLIENT_MS))
                .unwrap()
                .is_none()
        );
        cfg.min_client_version = None;
        cfg.max_client_version = Some([26, 10, 30]);
        assert!(
            authenticate(&cfg, &p, &h, Duration::from_millis(CLIENT_MS))
                .unwrap()
                .is_none()
        );
        cfg.max_client_version = None;
        cfg.max_time_diff_ms = 1;
        assert!(
            authenticate(&cfg, &p, &h, Duration::from_millis(CLIENT_MS + 1))
                .unwrap()
                .is_some()
        );
        assert!(
            authenticate(&cfg, &p, &h, Duration::from_millis(CLIENT_MS + 2))
                .unwrap()
                .is_none()
        );
        assert!(authenticate(&cfg, &p, &h, Duration::MAX).is_err());
        let edge = Duration::from_millis(CLIENT_MS + 1);
        assert!(
            authenticate(&cfg, &p, &h, edge + Duration::from_nanos(1))
                .unwrap()
                .is_none()
        );
        let edge = Duration::from_millis(CLIENT_MS - 1);
        assert!(
            authenticate(&cfg, &p, &h, edge - Duration::from_nanos(1))
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn independent_zero_max_timestamps_versions_and_explicit_short_ids() {
        let mut config = cfg();
        let p = config.prepare().unwrap();
        let cases = [
            (
                "f1732648b7a6fe50ed225e0b40122e21a7a1a4b3f47e36e11e9ba493f5599c06",
                "93b3bb740c179a86ffed703d7b7a7f4ed46cf84f7a4f8fc5de16e32f4c2b7f0a",
                0u32,
                [0, 0, 0],
            ),
            (
                "0e8cd948485901afed225e0b40122e21517cb81f5cf6ac1b87acb3099b0fa8bd",
                "4391bf20eeb5a150e62c9d986f70df0386d50f1ae33a9a7697f5a14a1a176aff",
                u32::MAX,
                [255, 255, 255],
            ),
        ];
        for (sid, digest, timestamp, version) in cases {
            let mut raw = fixture(true, false);
            raw[39..71].copy_from_slice(&hex::<32>(sid));
            assert_eq!(Sha256::digest(&raw).as_slice(), hex::<32>(digest));
            let h = parsed(raw).await;
            config.min_client_version = Some(version);
            config.max_client_version = Some(version);
            let now = Duration::from_secs(u64::from(timestamp));
            assert!(authenticate(&config, &p, &h, now).unwrap().is_some());
            assert!(
                authenticate(
                    &config,
                    &p,
                    &h,
                    now + Duration::from_millis(config.max_time_diff_ms)
                )
                .unwrap()
                .is_some()
            );
            assert!(
                authenticate(
                    &config,
                    &p,
                    &h,
                    now + Duration::from_millis(config.max_time_diff_ms + 1)
                )
                .unwrap()
                .is_none()
            );
        }
        config.min_client_version = None;
        config.max_client_version = None;
        for (sid, short_id) in [
            (
                "eb793948d2f50f50ff165e0b40122e21829560858eafaf2293be379c21332faf",
                "",
            ),
            (
                "eb793948d2f50f50ed220873daaef0d1e785583a3de85f5dcf5cf2b0a8807d05",
                "123456789abcdef0",
            ),
        ] {
            let mut raw = fixture(true, false);
            raw[39..71].copy_from_slice(&hex::<32>(sid));
            let h = parsed(raw).await;
            assert!(
                authenticate(&config, &p, &h, Duration::from_millis(CLIENT_MS))
                    .unwrap()
                    .is_none()
            );
            config.short_ids = vec![crate::config::Secret(short_id.to_owned())];
            let prepared = config.prepare().unwrap();
            assert!(
                authenticate(&config, &prepared, &h, Duration::from_millis(CLIENT_MS))
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn auth_policy_mismatch_and_low_order_are_only_fixed_fallback_candidates() {
        let config = cfg();
        let p = config.prepare().unwrap();
        let now = Duration::from_millis(CLIENT_MS);
        for index in [6, 37, 39, 55, 70, 100] {
            let mut raw = fixture(true, false);
            raw[index] ^= 1;
            let h = parsed(raw).await;
            assert!(
                authenticate(&config, &p, &h, now).unwrap().is_none(),
                "mutated {index}"
            );
        }
        for both in [false, true] {
            let h = parsed(fixture(both, true)).await;
            assert!(authenticate(&config, &p, &h, now).unwrap().is_none());
        }
        let h = parsed(fixture(true, false)).await;
        for name in ["Example.test", "other.test"] {
            let mut c = config.clone();
            c.server_names = vec![name.to_owned()];
            assert!(authenticate(&c, &p, &h, now).unwrap().is_none());
        }
        let mut c = config.clone();
        c.short_ids = vec![crate::config::Secret("".into())];
        let other = c.prepare().unwrap();
        assert!(authenticate(&c, &other, &h, now).unwrap().is_none());
        c = config.clone();
        c.private_key = crate::config::Secret(URL_SAFE_NO_PAD.encode([77; 32]));
        let other = c.prepare().unwrap();
        assert!(authenticate(&c, &other, &h, now).unwrap().is_none());
        for key in [[0; 32], {
            let mut a = [0; 32];
            a[0] = 1;
            a
        }] {
            let mut h = parsed(fixture(true, false)).await;
            h.x25519 = Some(key);
            assert!(authenticate(&config, &p, &h, now).unwrap().is_none());
        }
        let mut h = parsed(fixture(false, false)).await;
        h.hybrid.as_mut().unwrap()[1184..].fill(0);
        assert!(authenticate(&config, &p, &h, now).unwrap().is_none());
        let mut h = parsed(fixture(true, false)).await;
        h.hybrid = None;
        assert!(authenticate(&config, &p, &h, now).unwrap().is_none());
        let mut h = parsed(fixture(true, false)).await;
        h.session_id = 39..70;
        assert!(authenticate(&config, &p, &h, now).unwrap().is_none());
        let mut h = parsed(fixture(true, false)).await;
        h.supported_versions.clear();
        assert!(authenticate(&config, &p, &h, now).unwrap().is_none());
        let mut h = parsed(fixture(true, false)).await;
        h.session_id = 10000..10032;
        assert!(authenticate(&config, &p, &h, now).is_err());
    }
}
