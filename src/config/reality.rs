//! REALITY 的严格配置与纯本地密钥导入；此模块不执行 DNS 或网络 IO。
use std::{collections::HashSet, net::IpAddr};

use anyhow::{Result, anyhow, ensure};
use aws_lc_rs::agreement::{PrivateKey, X25519};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize};

use super::Secret;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RealityTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reality {
    pub target: RealityTarget,
    pub private_key: Secret,
    pub server_names: Vec<String>,
    pub short_ids: Vec<Secret>,
    #[serde(default = "default_window")]
    pub max_time_diff_ms: u64,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_client_version: Option<[u8; 3]>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_client_version: Option<[u8; 3]>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub mldsa65_seed: Option<Secret>,
    #[serde(default = "default_idle")]
    pub fallback_idle_timeout_ms: u64,
    #[serde(default = "default_duration")]
    pub fallback_max_duration_ms: u64,
}

const fn default_window() -> u64 {
    120_000
}
const fn default_idle() -> u64 {
    10_000
}
const fn default_duration() -> u64 {
    60_000
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

// 不派生 Debug，防止把导入密钥、shortID 或种子带入上层日志。
pub(crate) struct PreparedReality {
    pub static_private: PrivateKey,
    pub public_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub mldsa65_seed: Option<[u8; 32]>,
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    ensure!(value.len() == 43, "REALITY 密钥编码或长度无效");
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| anyhow!("REALITY 密钥编码或长度无效"))?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&decoded) == value,
        "REALITY 密钥编码或长度无效"
    );
    decoded
        .try_into()
        .map_err(|_| anyhow!("REALITY 密钥编码或长度无效"))
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value
            .strip_suffix('.')
            .unwrap_or(value)
            .split('.')
            .all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
}

fn short_id(value: &str) -> Result<[u8; 8]> {
    ensure!(
        value.len() <= 16 && value.len().is_multiple_of(2),
        "REALITY short_ids 格式无效"
    );
    let mut decoded = [0; 8];
    for (slot, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let hex = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        *slot = (hex(pair[0]).ok_or_else(|| anyhow!("REALITY short_ids 格式无效"))? << 4)
            | hex(pair[1]).ok_or_else(|| anyhow!("REALITY short_ids 格式无效"))?;
    }
    Ok(decoded)
}

impl Reality {
    pub(crate) fn prepare(&self) -> Result<PreparedReality> {
        ensure!(self.target.port != 0, "REALITY target.port 必须非零");
        ensure!(
            self.target.host.parse::<IpAddr>().is_ok() || dns_name(&self.target.host),
            "REALITY target.host 必须为 IP 或 ASCII 域名"
        );
        ensure!(
            (1..=64).contains(&self.server_names.len()),
            "REALITY server_names 数量必须在1到64之间"
        );
        let mut names = HashSet::new();
        for name in &self.server_names {
            ensure!(
                dns_name(name) && name.parse::<IpAddr>().is_err(),
                "REALITY server_names 必须为 ASCII DNS 名"
            );
            ensure!(names.insert(name), "REALITY server_names 重复");
        }
        ensure!(
            (1..=256).contains(&self.short_ids.len()),
            "REALITY short_ids 数量必须在1到256之间"
        );
        let mut unique_ids = HashSet::new();
        let mut short_ids = Vec::with_capacity(self.short_ids.len());
        for value in &self.short_ids {
            let id = short_id(&value.0)?;
            ensure!(unique_ids.insert(id), "REALITY short_ids 规范化后重复");
            short_ids.push(id);
        }
        ensure!(
            (1..=600_000).contains(&self.max_time_diff_ms),
            "REALITY max_time_diff_ms 必须在1到600000之间"
        );
        ensure!(
            (1..=60_000).contains(&self.fallback_idle_timeout_ms),
            "REALITY fallback_idle_timeout_ms 必须在1到60000之间"
        );
        ensure!(
            (1..=300_000).contains(&self.fallback_max_duration_ms)
                && self.fallback_max_duration_ms >= self.fallback_idle_timeout_ms,
            "REALITY fallback_max_duration_ms 必须不小于 idle 且在1到300000之间"
        );
        if let (Some(min), Some(max)) = (self.min_client_version, self.max_client_version) {
            ensure!(min <= max, "REALITY 客户端版本上下界顺序错误");
        }
        let private = decode_key(&self.private_key.0)?;
        ensure!(private != [0; 32], "REALITY 静态私钥无效");
        let static_private = PrivateKey::from_private_key(&X25519, &private)
            .map_err(|_| anyhow!("REALITY 静态私钥导入失败"))?;
        let public_key = static_private
            .compute_public_key()
            .map_err(|_| anyhow!("REALITY 静态公钥派生失败"))?
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("REALITY 静态公钥长度无效"))?;
        let mldsa65_seed = self
            .mldsa65_seed
            .as_ref()
            .map(|value| decode_key(&value.0))
            .transpose()?;
        Ok(PreparedReality {
            static_private,
            public_key,
            short_ids,
            mldsa65_seed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Inbound};
    use serde_json::{Value, json};

    fn reality() -> Value {
        json!({"target":{"host":"127.0.0.1","port":443},
            "private_key":URL_SAFE_NO_PAD.encode([7;32]),
            "server_names":["example.test"], "short_ids":["1234", ""]})
    }
    fn config(r: Value) -> Value {
        json!({"version":1,"inbounds":[{"type":"vless-reality","tag":"reality","listen":"127.0.0.1:0",
            "users":[{"name":"alice","uuid":"00112233-4455-6677-8899-aabbccddeeff","flow":"xtls-rprx-vision"}],"reality":r}],
            "outbounds":[{"tag":"direct","type":"direct"}],"route":{"default":"direct"}})
    }
    fn parse(v: &Value) -> Result<Config> {
        Config::from_json(&v.to_string())
    }

    #[test]
    fn defaults_local_import_and_roundtrip() {
        let cfg = parse(&config(reality())).unwrap();
        assert_eq!(cfg.limits.max_reality_replay_entries, 65536);
        let Inbound::VlessReality { reality, xudp, .. } = &cfg.inbounds[0] else {
            panic!()
        };
        assert!(*xudp);
        assert_eq!(
            (
                reality.max_time_diff_ms,
                reality.fallback_idle_timeout_ms,
                reality.fallback_max_duration_ms
            ),
            (120000, 10000, 60000)
        );
        assert_eq!(reality.min_client_version, None);
        let prepared = reality.prepare().unwrap();
        assert_ne!(prepared.public_key, [0; 32]);
        assert_eq!(
            prepared.short_ids,
            vec![[0x12, 0x34, 0, 0, 0, 0, 0, 0], [0; 8]]
        );
        assert!(prepared.mldsa65_seed.is_none());
        let roundtrip = serde_json::to_value(&cfg).unwrap();
        assert_eq!(roundtrip["inbounds"][0]["type"], "vless-reality");
        assert!(parse(&roundtrip).is_ok());
        let debug = format!("{cfg:?}");
        for secret in [&reality.private_key.0, &reality.short_ids[0].0] {
            assert!(!debug.contains(secret));
        }
        assert!(!debug.contains("00112233-4455-6677-8899-aabbccddeeff"));
    }

    #[test]
    fn strict_fields_null_types_and_secret_diagnostics() {
        let good = reality();
        let invalid = [
            ("target", Value::Null),
            ("target", json!({"host":"localhost","port":0})),
            (
                "target",
                json!({"host":"https://secret.test/path","port":443}),
            ),
            ("target", json!({"host":"localhost","port":443,"extra":1})),
            ("private_key", json!(URL_SAFE_NO_PAD.encode([0; 32]))),
            (
                "private_key",
                json!(format!("{}=", URL_SAFE_NO_PAD.encode([7; 32]))),
            ),
            ("private_key", json!("sensitive-key")),
            ("private_key", json!(URL_SAFE_NO_PAD.encode([1; 31]))),
            ("server_names", json!([])),
            ("server_names", json!(["*.test"])),
            ("server_names", json!(["a.test", "a.test"])),
            ("server_names", json!(["127.0.0.1"])),
            ("short_ids", json!([])),
            ("short_ids", json!(["a"])),
            ("short_ids", json!(["gg"])),
            ("short_ids", json!(["12", "1200"])),
            ("short_ids", json!(["aa", "AA"])),
            ("short_ids", json!(["", "00"])),
            ("short_ids", json!(["001122334455667788"])),
            ("max_time_diff_ms", json!(0)),
            ("max_time_diff_ms", json!(600001)),
            ("min_client_version", json!([1, 2])),
            ("min_client_version", json!([1, 2, 256])),
            ("max_client_version", json!("1.2.3")),
            ("mldsa65_seed", json!("")),
            ("fallback_idle_timeout_ms", json!(60001)),
            ("fallback_idle_timeout_ms", json!(0)),
            ("fallback_max_duration_ms", json!(9999)),
            ("fallback_max_duration_ms", json!(300001)),
            ("extra", json!("sensitive-value")),
        ];
        for (field, value) in invalid {
            let mut r = good.clone();
            r[field] = value;
            let e = parse(&config(r)).unwrap_err();
            assert!(!format!("{e:?}").contains("sensitive"), "{field}");
        }
        for field in [
            "target",
            "private_key",
            "server_names",
            "short_ids",
            "max_time_diff_ms",
            "min_client_version",
            "max_client_version",
            "mldsa65_seed",
            "fallback_idle_timeout_ms",
            "fallback_max_duration_ms",
        ] {
            let mut r = good.clone();
            r[field] = Value::Null;
            assert!(parse(&config(r)).is_err(), "{field}");
        }
        for field in ["certificate", "private_key"] {
            let mut c = config(good.clone());
            c["inbounds"][0][field] = json!("secret");
            assert!(parse(&c).is_err());
        }
    }

    #[test]
    fn bounds_versions_names_and_limits() {
        let mut r = reality();
        r["max_time_diff_ms"] = json!(1);
        r["fallback_idle_timeout_ms"] = json!(1);
        r["fallback_max_duration_ms"] = json!(1);
        r["min_client_version"] = json!([0, 0, 0]);
        r["max_client_version"] = json!([255, 255, 255]);
        r["mldsa65_seed"] = json!(URL_SAFE_NO_PAD.encode([0; 32]));
        assert!(parse(&config(r.clone())).is_ok());
        r["max_time_diff_ms"] = json!(600000);
        r["fallback_idle_timeout_ms"] = json!(60000);
        r["fallback_max_duration_ms"] = json!(300000);
        r["server_names"] = json!(["Example.test", "example.test"]);
        assert!(parse(&config(r.clone())).is_ok());
        r["min_client_version"] = json!([2, 0, 0]);
        r["max_client_version"] = json!([1, 255, 255]);
        assert!(parse(&config(r)).is_err());
        for (field, max) in [("server_names", 64), ("short_ids", 256)] {
            let mut r = reality();
            r[field] = Value::Array(
                (0..max)
                    .map(|n| {
                        if field == "server_names" {
                            json!(format!("n{n}.test"))
                        } else {
                            json!(format!("{n:016x}"))
                        }
                    })
                    .collect(),
            );
            assert!(parse(&config(r.clone())).is_ok());
            r[field].as_array_mut().unwrap().push(json!("extra"));
            assert!(parse(&config(r)).is_err());
        }
        for value in [json!(0), json!(1048577), Value::Null, json!("secret")] {
            let mut c = config(reality());
            c["limits"] = json!({"max_reality_replay_entries":value});
            assert!(parse(&c).is_err());
        }
        for value in [1, 1048576] {
            let mut c = config(reality());
            c["limits"] = json!({"max_reality_replay_entries":value});
            assert!(parse(&c).is_ok());
        }
    }

    #[test]
    fn users_boundaries_duplicates_and_old_vless_remains_required() {
        let mut c = config(reality());
        for count in [0, 1, 1024, 1025] {
            c["inbounds"][0]["users"]=Value::Array((0..count).map(|n| json!({"name":format!("u{n}"),"uuid":format!("{n:08x}-4455-6677-8899-aabbccddeeff")})).collect());
            assert_eq!(parse(&c).is_ok(), (1..=1024).contains(&count));
        }
        let mut c = config(reality());
        let user = c["inbounds"][0]["users"][0].clone();
        c["inbounds"][0]["users"].as_array_mut().unwrap().push(user);
        assert!(parse(&c).is_err());
        c = config(reality());
        c["inbounds"][0]["type"] = json!("vless");
        c["inbounds"][0].as_object_mut().unwrap().remove("reality");
        assert!(parse(&c).is_err());
        c["inbounds"][0]["certificate"] = json!("cert.pem");
        assert!(parse(&c).is_err());
        c["inbounds"][0]["private_key"] = json!("key.pem");
        assert!(parse(&c).is_ok());
    }

    #[test]
    fn dns_name_exact_length_trailing_dot_and_labels() {
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest.len(), 253);
        for name in [
            "example.test".to_owned(),
            "example.test.".to_owned(),
            longest.clone(),
        ] {
            let mut r = reality();
            r["server_names"] = json!([name]);
            assert!(parse(&config(r)).is_ok());
        }
        for name in [
            "example.test..".to_owned(),
            ".".to_owned(),
            "".to_owned(),
            "-x.test".to_owned(),
            "x-.test".to_owned(),
            "a_b.test".to_owned(),
            "é.test".to_owned(),
            format!("{}.test", "a".repeat(64)),
            format!("{longest}x"),
        ] {
            let mut r = reality();
            r["server_names"] = json!([name]);
            assert!(parse(&config(r.clone())).is_err());
            r["server_names"] = json!(["example.test"]);
            r["target"]["host"] = json!(name);
            assert!(parse(&config(r)).is_err());
        }
        for host in ["localhost", "::1", "127.0.0.1"] {
            let mut r = reality();
            r["target"]["host"] = json!(host);
            assert!(parse(&config(r)).is_ok());
        }
    }

    #[test]
    fn equivalent_x25519_private_representations_share_public_identity() {
        let r: Reality = serde_json::from_value(reality()).unwrap();
        let a = r.prepare().unwrap();
        let mut other = r.clone();
        let mut private = [7; 32];
        private[0] ^= 7;
        private[31] ^= 0x80;
        other.private_key = Secret(URL_SAFE_NO_PAD.encode(private));
        assert_eq!(a.public_key, other.prepare().unwrap().public_key);
    }
}
