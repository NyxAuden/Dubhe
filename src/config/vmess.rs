use std::{collections::HashSet, fmt, path::PathBuf};

use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Deserializer, Serialize};

use super::parse_uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmessUser {
    pub name: String,
    pub uuid: String,
}

impl fmt::Debug for VmessUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VmessUser")
            .field("name", &self.name)
            .field("uuid", &"[REDACTED]")
            .finish()
    }
}

// 缺省表示直承载；显式 null 不是路径，不能静默关闭 TLS。
pub(super) fn present_tls_path<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PathBuf>, D::Error> {
    PathBuf::deserialize(deserializer).map(Some)
}

pub(super) fn validate_users(users: &[VmessUser], inbound_index: usize) -> Result<()> {
    ensure!(
        (1..=1024).contains(&users.len()),
        "inbounds[{inbound_index}].users 数量必须在1到1024之间"
    );
    let mut names = HashSet::new();
    let mut uuids = HashSet::new();
    for (user_index, user) in users.iter().enumerate() {
        ensure!(
            !user.name.is_empty(),
            "inbounds[{inbound_index}].users[{user_index}] 用户名不得为空"
        );
        ensure!(
            names.insert(user.name.as_str()),
            "inbounds[{inbound_index}].users[{user_index}] 用户名重复"
        );
        let uuid = parse_uuid(&user.uuid).ok_or_else(|| {
            anyhow!("inbounds[{inbound_index}].users[{user_index}] UUID 必须为标准 36 字符格式")
        })?;
        ensure!(
            uuids.insert(uuid),
            "inbounds[{inbound_index}].users[{user_index}] UUID 重复"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::{Value, json};

    use super::*;
    use crate::config::{Config, Inbound, VlessFlow};

    const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const OTHER_UUID: &str = "f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f";
    const SECRET: &str = "vmess-config-secret-918";

    fn valid_value() -> Value {
        json!({
            "version": 1,
            "inbounds": [{
                "type": "vmess", "tag": "vmess", "listen": "127.0.0.1:0",
                "users": [{"name": "alice", "uuid": UUID}]
            }],
            "outbounds": [{"tag": "direct", "type": "direct"}],
            "route": {"default": "direct"}
        })
    }

    fn parse(value: &Value) -> Result<Config> {
        Config::from_json(&value.to_string())
    }

    fn assert_sanitized(error: &anyhow::Error) {
        assert_eq!(error.chain().count(), 1);
        for rendered in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            for secret in [
                UUID.to_owned(),
                UUID.to_uppercase(),
                OTHER_UUID.to_owned(),
                SECRET.into(),
            ] {
                assert!(!rendered.contains(&secret), "配置错误泄漏秘密");
            }
        }
    }

    #[test]
    fn vmess_direct_defaults_tls_omission_and_roundtrip() {
        let mut value = valid_value();
        value["inbounds"][0]["users"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "name": "用户".repeat(128), "uuid": OTHER_UUID.to_uppercase()
            }));
        let config = parse(&value).unwrap();
        let inbound = &config.inbounds[0];
        assert_eq!(inbound.tag(), "vmess");
        assert_eq!(inbound.listen(), "127.0.0.1:0".parse().unwrap());
        assert_eq!(inbound.tls_paths(), None);
        assert!(matches!(
            inbound,
            Inbound::Vmess {
                users,
                xudp: true,
                packetaddr: false,
                allow_insecure_body: false,
                allow_authenticated_length: false,
                certificate: None,
                private_key: None,
                ..
            } if users.len() == 2
        ));
        assert_eq!(config.limits.max_vmess_replay_entries, 65_536);
        assert_eq!(config.limits.max_replay_entries, 65_536);
        let serialized = serde_json::to_value(&config).unwrap();
        let inbound = &serialized["inbounds"][0];
        assert_eq!(inbound["type"], "vmess");
        assert_eq!(inbound["users"][0]["uuid"], UUID);
        assert_eq!(inbound["users"][1]["uuid"], OTHER_UUID.to_uppercase());
        assert!(inbound["users"][0].get("flow").is_none());
        assert_eq!(inbound["xudp"], true);
        for field in [
            "packetaddr",
            "allow_insecure_body",
            "allow_authenticated_length",
        ] {
            assert_eq!(inbound[field], false, "{field}");
        }
        for field in ["certificate", "private_key"] {
            assert!(inbound.get(field).is_none(), "{field}");
        }
        assert_eq!(
            serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
            serialized
        );
    }

    #[test]
    fn vmess_tls_pair_roundtrips_without_enabling_other_options() {
        let mut value = valid_value();
        value["inbounds"][0]["listen"] = json!("[::1]:8443");
        value["inbounds"][0]["certificate"] = json!("vmess-cert.pem");
        value["inbounds"][0]["private_key"] = json!("vmess-key.pem");
        let config = parse(&value).unwrap();
        assert_eq!(config.inbounds[0].listen(), "[::1]:8443".parse().unwrap());
        assert_eq!(
            config.inbounds[0].tls_paths(),
            Some((Path::new("vmess-cert.pem"), Path::new("vmess-key.pem")))
        );
        let serialized = serde_json::to_value(&config).unwrap();
        assert_eq!(serialized["inbounds"][0]["certificate"], "vmess-cert.pem");
        assert_eq!(serialized["inbounds"][0]["private_key"], "vmess-key.pem");
        assert_eq!(serialized["inbounds"][0]["allow_insecure_body"], false);
        assert_eq!(
            serialized["inbounds"][0]["allow_authenticated_length"],
            false
        );
        assert_eq!(
            serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
            serialized
        );
    }

    #[test]
    fn vmess_option_flags_are_independent_and_roundtrip() {
        for bits in 0..16 {
            let mut value = valid_value();
            for (bit, field) in [
                "xudp",
                "packetaddr",
                "allow_insecure_body",
                "allow_authenticated_length",
            ]
            .iter()
            .enumerate()
            {
                value["inbounds"][0][*field] = json!(bits & (1 << bit) != 0);
            }
            let config = parse(&value).unwrap();
            let Inbound::Vmess {
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            } = &config.inbounds[0]
            else {
                panic!()
            };
            assert_eq!(
                [
                    *xudp,
                    *packetaddr,
                    *allow_insecure_body,
                    *allow_authenticated_length
                ],
                [bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0]
            );
            let serialized = serde_json::to_value(&config).unwrap();
            assert_eq!(
                serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
                serialized
            );
        }
    }

    #[test]
    fn vmess_option_flags_reject_null_and_non_boolean_types() {
        for field in [
            "xudp",
            "packetaddr",
            "allow_insecure_body",
            "allow_authenticated_length",
        ] {
            for invalid in [
                json!(null),
                json!(0),
                json!(1),
                json!(-1),
                json!(1.5),
                json!("true"),
                json!(SECRET),
                json!([]),
                json!({SECRET: true}),
            ] {
                let mut value = valid_value();
                value["inbounds"][0][field] = invalid;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
    }

    #[test]
    fn vmess_tls_rejects_half_pairs_and_empty_paths() {
        for field in ["certificate", "private_key"] {
            let mut value = valid_value();
            value["inbounds"][0][field] = json!(SECRET);
            let error = parse(&value).unwrap_err();
            assert!(error.to_string().contains("必须成对配置"));
            assert_sanitized(&error);
            value["inbounds"][0]["certificate"] = json!("cert.pem");
            value["inbounds"][0]["private_key"] = json!("key.pem");
            value["inbounds"][0][field] = json!("");
            let error = parse(&value).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("inbounds[0].{field} 不得为空"))
            );
            assert_sanitized(&error);
        }
    }

    #[test]
    fn vmess_tls_rejects_explicit_null_and_non_path_types() {
        for field in ["certificate", "private_key"] {
            for paired in [false, true] {
                for invalid in [
                    json!(null),
                    json!(true),
                    json!(1),
                    json!(1.5),
                    json!([]),
                    json!([SECRET]),
                    json!({SECRET: "path"}),
                ] {
                    let mut value = valid_value();
                    if paired {
                        value["inbounds"][0]["certificate"] = json!("cert.pem");
                        value["inbounds"][0]["private_key"] = json!("key.pem");
                    }
                    value["inbounds"][0][field] = invalid;
                    assert_sanitized(&parse(&value).unwrap_err());
                }
            }
        }
        let mut value = valid_value();
        value["inbounds"][0]["certificate"] = Value::Null;
        value["inbounds"][0]["private_key"] = Value::Null;
        assert_sanitized(&parse(&value).unwrap_err());
    }

    #[test]
    fn vmess_user_count_has_a_fixed_nonempty_upper_bound() {
        for (count, valid) in [(0, false), (1, true), (1024, true), (1025, false)] {
            let mut value = valid_value();
            value["inbounds"][0]["users"] = json!((0..count).map(|index| {
                json!({"name": format!("user-{index}"), "uuid": format!("00000000-0000-0000-0000-{index:012x}")})
            }).collect::<Vec<_>>());
            match parse(&value) {
                Ok(config) => {
                    assert!(valid, "用户数 {count}");
                    let Inbound::Vmess { users, .. } = &config.inbounds[0] else {
                        panic!()
                    };
                    assert_eq!(users.len(), count);
                }
                Err(error) => {
                    assert!(!valid, "用户数 {count}");
                    assert!(
                        error
                            .to_string()
                            .contains("inbounds[0].users 数量必须在1到1024之间")
                    );
                    assert_sanitized(&error);
                }
            }
        }
    }

    #[test]
    fn vmess_usernames_and_parsed_uuid_identities_must_be_unique() {
        for (name, uuid, reason) in [
            ("", OTHER_UUID.to_owned(), "用户名不得为空"),
            ("alice", OTHER_UUID.to_owned(), "用户名重复"),
            ("bob", UUID.to_owned(), "UUID 重复"),
            ("bob", UUID.to_uppercase(), "UUID 重复"),
        ] {
            let mut value = valid_value();
            value["inbounds"][0]["users"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": name, "uuid": uuid}));
            let error = parse(&value).unwrap_err();
            assert!(error.to_string().contains("inbounds[0].users[1]"));
            assert!(error.to_string().contains(reason));
            assert_sanitized(&error);
        }
        let mut value = valid_value();
        value["inbounds"][0]["users"][0]["uuid"] = json!(UUID.to_uppercase());
        parse(&value).unwrap();
        // 身份唯一性是入口内约束；同一凭据跨入口的重放保护由运行器共享池负责。
        let mut second = value["inbounds"][0].clone();
        second["tag"] = json!("vmess-second");
        value["inbounds"].as_array_mut().unwrap().push(second);
        parse(&value).unwrap();
    }

    #[test]
    fn vmess_rejects_placeholders_nonstandard_and_malformed_uuid_text() {
        for invalid in [
            String::new(),
            SECRET.into(),
            "replace-with-uuid".into(),
            "YOUR_UUID".into(),
            "<uuid>".into(),
            UUID.replace('-', ""),
            format!("{{{UUID}}}"),
            format!("urn:uuid:{UUID}"),
            format!(" {UUID}"),
            format!("{UUID}\n"),
            UUID.replacen("00", "é", 1),
        ] {
            let mut value = valid_value();
            value["inbounds"][0]["users"][0]["uuid"] = json!(invalid);
            let error = parse(&value).unwrap_err();
            assert!(error.to_string().contains("UUID 必须为标准 36 字符格式"));
            assert_sanitized(&error);
        }
        for index in 0..36 {
            let mut bytes = UUID.as_bytes().to_vec();
            bytes[index] = if bytes[index] == b'-' { b'0' } else { b'g' };
            let mut value = valid_value();
            value["inbounds"][0]["users"][0]["uuid"] = json!(String::from_utf8(bytes).unwrap());
            assert_sanitized(&parse(&value).unwrap_err());
        }
        // 与 VLESS 的标准 UUID 解析规则一致，不额外强制版本或 variant 位。
        for uuid in [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ] {
            let mut value = valid_value();
            value["inbounds"][0]["users"][0]["uuid"] = json!(uuid);
            parse(&value).unwrap();
        }
    }

    #[test]
    fn vmess_rejects_missing_required_fields_nulls_and_wrong_types() {
        for (pointer, fields) in [
            ("/inbounds/0", &["type", "tag", "listen", "users"][..]),
            ("/inbounds/0/users/0", &["name", "uuid"][..]),
        ] {
            for field in fields {
                let mut value = valid_value();
                value
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(*field);
                assert_sanitized(&parse(&value).unwrap_err());
                let mut value = valid_value();
                value.pointer_mut(pointer).unwrap()[*field] = Value::Null;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
        for invalid in [
            json!(true),
            json!(1),
            json!(1.5),
            json!(SECRET),
            json!({SECRET: UUID}),
        ] {
            let mut value = valid_value();
            value["inbounds"][0]["users"] = invalid.clone();
            assert_sanitized(&parse(&value).unwrap_err());
            value["inbounds"][0]["users"] = json!([invalid]);
            assert_sanitized(&parse(&value).unwrap_err());
        }
        for field in ["name", "uuid"] {
            for invalid in [
                json!(true),
                json!(1),
                json!(1.5),
                json!([]),
                json!([UUID]),
                json!({SECRET: UUID}),
            ] {
                let mut value = valid_value();
                value["inbounds"][0]["users"][0][field] = invalid;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
    }

    #[test]
    fn vmess_rejects_historical_aliases_unknown_fields_and_vless_flow() {
        for pointer in ["/inbounds/0", "/inbounds/0/users/0"] {
            for field in [
                "alter_id",
                "alterId",
                "security",
                "flow",
                "transport",
                "mux",
                "multiplex",
                "reality",
                "encryption",
                "packet_encoding",
                "websocket",
                "grpc",
                "password",
                "allow_insecure",
                SECRET,
            ] {
                let mut value = valid_value();
                value.pointer_mut(pointer).unwrap()[field] = json!(SECRET);
                let error = parse(&value).unwrap_err();
                assert!(error.to_string().contains("未知字段"), "{pointer}/{field}");
                assert_sanitized(&error);
            }
            for field in ["alter_id", "alterId"] {
                for alter_id in [0, 1, 64] {
                    let mut value = valid_value();
                    value.pointer_mut(pointer).unwrap()[field] = json!(alter_id);
                    assert_sanitized(&parse(&value).unwrap_err());
                }
            }
            for flow in [json!(""), json!("xtls-rprx-vision"), json!(null)] {
                let mut value = valid_value();
                value.pointer_mut(pointer).unwrap()["flow"] = flow;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
        assert!(
            serde_json::from_value::<VmessUser>(json!({"name": "alice", "uuid": UUID, "flow": ""}))
                .is_err()
        );
        for alias in ["VMess", "VMESS", "vmess-aead"] {
            let mut value = valid_value();
            value["inbounds"][0]["type"] = json!(alias);
            assert_sanitized(&parse(&value).unwrap_err());
        }
    }

    #[test]
    fn vmess_duplicate_fields_are_rejected_without_echoing_values() {
        let mut value = valid_value();
        value["inbounds"][0]["certificate"] = json!("cert.pem");
        value["inbounds"][0]["private_key"] = json!("key.pem");
        for field in [
            "xudp",
            "packetaddr",
            "allow_insecure_body",
            "allow_authenticated_length",
        ] {
            value["inbounds"][0][field] = json!(false);
        }
        value["limits"] = json!({"max_vmess_replay_entries": 1});
        for (field, original) in [
            ("type", json!("vmess")),
            ("tag", json!("vmess")),
            ("listen", json!("127.0.0.1:0")),
            ("users", value["inbounds"][0]["users"].clone()),
            ("name", json!("alice")),
            ("uuid", json!(UUID)),
            ("xudp", json!(false)),
            ("packetaddr", json!(false)),
            ("allow_insecure_body", json!(false)),
            ("allow_authenticated_length", json!(false)),
            ("certificate", json!("cert.pem")),
            ("private_key", json!("key.pem")),
            ("max_vmess_replay_entries", json!(1)),
        ] {
            let needle = format!("\"{field}\":{original}");
            let duplicate = format!("{needle},\"{field}\":\"{SECRET}\"");
            let input = value.to_string().replacen(&needle, &duplicate, 1);
            let error = Config::from_json(&input).unwrap_err();
            assert!(error.to_string().contains("字段重复"), "{field}");
            assert_sanitized(&error);
        }
    }

    #[test]
    fn vmess_debug_redacts_uuid_at_user_inbound_and_config_levels() {
        let config = parse(&valid_value()).unwrap();
        let Inbound::Vmess { users, .. } = &config.inbounds[0] else {
            panic!()
        };
        for rendered in [
            format!("{:?}", users[0]),
            format!("{:#?}", users[0]),
            format!("{:?}", config.inbounds[0]),
            format!("{:#?}", config.inbounds[0]),
            format!("{config:?}"),
            format!("{config:#?}"),
        ] {
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains(UUID));
        }
    }

    #[test]
    fn vmess_direct_validation_preserves_all_configuration_guards() {
        let mut config = parse(&valid_value()).unwrap();
        let Inbound::Vmess { users, .. } = &mut config.inbounds[0] else {
            panic!()
        };
        users[0].uuid = SECRET.into();
        assert_sanitized(&config.validate().unwrap_err());
        let Inbound::Vmess { users, .. } = &mut config.inbounds[0] else {
            panic!()
        };
        users[0].uuid = UUID.into();
        users[0].name.clear();
        assert_sanitized(&config.validate().unwrap_err());
        let Inbound::Vmess { users, .. } = &mut config.inbounds[0] else {
            panic!()
        };
        users[0].name = "alice".into();
        users.push(VmessUser {
            name: "bob".into(),
            uuid: UUID.to_uppercase(),
        });
        assert_sanitized(&config.validate().unwrap_err());
        let Inbound::Vmess {
            users, certificate, ..
        } = &mut config.inbounds[0]
        else {
            panic!()
        };
        users.pop();
        *certificate = Some(SECRET.into());
        assert_sanitized(&config.validate().unwrap_err());
        let Inbound::Vmess {
            certificate,
            private_key,
            ..
        } = &mut config.inbounds[0]
        else {
            panic!()
        };
        *certificate = Some(PathBuf::new());
        *private_key = Some("key.pem".into());
        assert_sanitized(&config.validate().unwrap_err());
        let Inbound::Vmess {
            certificate,
            private_key,
            users,
            ..
        } = &mut config.inbounds[0]
        else {
            panic!()
        };
        *certificate = None;
        *private_key = None;
        users.clear();
        assert_sanitized(&config.validate().unwrap_err());
        let Inbound::Vmess { users, .. } = &mut config.inbounds[0] else {
            panic!()
        };
        *users = (0..1025)
            .map(|index| VmessUser {
                name: format!("user-{index}"),
                uuid: format!("00000000-0000-0000-0000-{index:012x}"),
            })
            .collect();
        assert_sanitized(&config.validate().unwrap_err());
    }

    #[test]
    fn vmess_replay_limit_is_independent_and_enforces_range_and_types() {
        for (vmess, shadowsocks) in [(1, 1_048_576), (1_048_576, 1)] {
            let mut value = valid_value();
            value["limits"] =
                json!({"max_vmess_replay_entries": vmess, "max_replay_entries": shadowsocks});
            let config = parse(&value).unwrap();
            assert_eq!(config.limits.max_vmess_replay_entries, vmess);
            assert_eq!(config.limits.max_replay_entries, shadowsocks);
            let serialized = serde_json::to_value(&config).unwrap();
            assert_eq!(
                serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
                serialized
            );
        }
        for (field, other) in [
            ("max_vmess_replay_entries", "max_replay_entries"),
            ("max_replay_entries", "max_vmess_replay_entries"),
        ] {
            let mut value = valid_value();
            value["limits"] = json!({field: 1});
            let serialized = serde_json::to_value(parse(&value).unwrap()).unwrap();
            assert_eq!(serialized["limits"][field], 1);
            assert_eq!(serialized["limits"][other], 65_536);
            for invalid in [
                json!(0),
                json!(1_048_577),
                json!(u64::MAX),
                json!(-1),
                json!(1.5),
                json!(null),
                json!(true),
                json!(SECRET),
                json!([]),
                json!({SECRET: 1}),
            ] {
                value["limits"] = json!({field: invalid});
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
        let mut config = parse(&valid_value()).unwrap();
        for invalid in [0, 1_048_577, usize::MAX] {
            config.limits.max_vmess_replay_entries = invalid;
            let error = config.validate().unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("limits.max_vmess_replay_entries")
            );
            assert_sanitized(&error);
        }
    }

    #[test]
    fn vmess_mixed_old_protocols_keep_tls_flow_and_safety_defaults() {
        let mut value = valid_value();
        value["inbounds"].as_array_mut().unwrap().extend([
            json!({"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}),
            json!({"type": "trojan", "tag": "trojan", "listen": "127.0.0.1:0", "users": [{"name": "alice", "password": SECRET}], "certificate": "cert.pem", "private_key": "key.pem"}),
            json!({"type": "vless", "tag": "vless", "listen": "127.0.0.1:0", "users": [{"name": "alice", "uuid": UUID}, {"name": "vision", "uuid": OTHER_UUID, "flow": "xtls-rprx-vision"}], "certificate": "cert.pem", "private_key": "key.pem"}),
            json!({"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1:0", "method": "aes-128-gcm", "password": SECRET}),
        ]);
        let config = parse(&value).unwrap();
        assert!(
            matches!(&config.inbounds[1], Inbound::Socks5 { users, allow_insecure: false, .. } if users.is_empty())
        );
        let Inbound::Vless { users, xudp, .. } = &config.inbounds[3] else {
            panic!()
        };
        assert!(*xudp);
        assert_eq!(users[0].flow, VlessFlow::None);
        assert_eq!(users[1].flow, VlessFlow::Vision);
        assert_eq!(config.inbounds[0].tls_paths(), None);
        assert_eq!(config.inbounds[1].tls_paths(), None);
        assert_eq!(config.inbounds[4].tls_paths(), None);
        for index in [2, 3] {
            assert_eq!(
                config.inbounds[index].tls_paths(),
                Some((Path::new("cert.pem"), Path::new("key.pem")))
            );
            for field in ["certificate", "private_key"] {
                let mut missing = value.clone();
                missing["inbounds"][index]
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
                assert_sanitized(&parse(&missing).unwrap_err());
                let mut null = value.clone();
                null["inbounds"][index][field] = Value::Null;
                assert_sanitized(&parse(&null).unwrap_err());
            }
        }
        for rendered in [format!("{config:?}"), format!("{config:#?}")] {
            assert!(!rendered.contains(UUID));
            assert!(!rendered.contains(OTHER_UUID));
            assert!(!rendered.contains(SECRET));
        }
        let serialized = serde_json::to_value(&config).unwrap();
        assert_eq!(
            serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
            serialized
        );
        let mut exposed = value;
        exposed["inbounds"][1]["listen"] = json!("0.0.0.0:0");
        assert_sanitized(&parse(&exposed).unwrap_err());
    }
}
