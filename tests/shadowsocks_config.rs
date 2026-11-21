use base64::{Engine, engine::general_purpose::STANDARD};
use dubhe::{Config, Server};
use serde_json::{Value, json};
use std::net::{TcpListener, UdpSocket};

const METHODS: [&str; 6] = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

fn key_length(method: &str) -> usize {
    if method == METHODS[3] { 16 } else { 32 }
}

fn psk(method: &str, byte: u8) -> String {
    STANDARD.encode(vec![byte; key_length(method)])
}

fn config(method: &str, multiple: bool) -> Value {
    let password = if method.starts_with("2022-") {
        psk(method, 0x73)
    } else {
        "test-only-secret".to_owned()
    };
    let mut inbound = json!({
        "type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1:0",
        "method": method, "password": password
    });
    if multiple {
        inbound["users"] = json!([
            {"name": "alice", "password": psk(method, 0x74)},
            {"name": "bob", "password": psk(method, 0x75)}
        ]);
    }
    json!({
        "version": 1, "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

fn parse(value: &Value) -> anyhow::Result<Config> {
    Config::from_json(&value.to_string())
}

#[test]
fn all_methods_and_aes_users_roundtrip_and_prepare_without_binding() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = UdpSocket::bind(tcp.local_addr().unwrap()).unwrap();
    tcp.set_nonblocking(true).unwrap();
    udp.set_nonblocking(true).unwrap();
    for method in METHODS {
        for multiple in [false, true] {
            if multiple && ![METHODS[3], METHODS[4]].contains(&method) {
                continue;
            }
            let mut value = config(method, multiple);
            value["inbounds"][0]["listen"] = json!(tcp.local_addr().unwrap());
            let parsed = parse(&value).unwrap();
            Server::check(&parsed).unwrap();
            let serialized = serde_json::to_value(&parsed).unwrap();
            assert_eq!(serialized["inbounds"], value["inbounds"]);
            assert_eq!(
                serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
                serialized
            );
            let debug = format!("{parsed:?}");
            for secret in [
                "test-only-secret".to_owned(),
                psk(method, 0x73),
                psk(method, 0x74),
                psk(method, 0x75),
            ] {
                assert!(!debug.contains(&secret));
            }
        }
    }
    assert_eq!(tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    assert_eq!(
        tcp.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        udp.recv_from(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn rejects_wrong_psk_forms_and_lengths_without_echoing_values() {
    for method in &METHODS[3..] {
        let mut bad_keys = vec![
            String::new(),
            "raw-key-not-base64".to_owned(),
            psk(method, 0x73).trim_end_matches('=').to_owned(),
            format!("{}\n", psk(method, 0x73)),
            format!("{}:{}", psk(method, 0x73), psk(method, 0x74)),
            psk(method, 0xff).replace('/', "_"),
        ];
        for length in [0, 15, 16, 17, 31, 32, 33] {
            if length != key_length(method) {
                bad_keys.push(STANDARD.encode(vec![0x73; length]));
            }
        }
        // 同一解码字节的非零尾部bits编码也不得作为另一个合法文本形式。
        let mut noncanonical = psk(method, 0);
        let last_symbol = noncanonical.find('=').unwrap() - 1;
        noncanonical.replace_range(last_symbol..=last_symbol, "B");
        bad_keys.push(noncanonical);
        for bad in bad_keys {
            let mut value = config(method, false);
            value["inbounds"][0]["password"] = json!(bad);
            let error = parse(&value).unwrap_err();
            if !bad.is_empty() {
                assert!(!format!("{error:?}").contains(&bad));
            }
        }
        let mut value = config(method, false);
        value["inbounds"][0]["password"] = Value::Null;
        assert!(parse(&value).is_err());
    }
}

#[test]
fn users_fields_are_strict_and_identities_unique() {
    for method in METHODS {
        for invalid in [Value::Null, json!([]), json!({}), json!("secret-users")] {
            let mut value = config(method, false);
            value["inbounds"][0]["users"] = invalid;
            assert!(parse(&value).is_err(), "{method}");
        }
        if ![METHODS[3], METHODS[4]].contains(&method) {
            assert!(parse(&config(method, true)).is_err());
        }
    }
    for method in [METHODS[3], METHODS[4]] {
        for property in ["name", "password"] {
            let mut value = config(method, true);
            value["inbounds"][0]["users"][1][property] =
                value["inbounds"][0]["users"][0][property].clone();
            assert!(parse(&value).is_err());
        }
        for (property, invalid) in [
            ("name", json!("")),
            ("password", json!("")),
            ("password", json!(psk(method, 0x73))),
            ("password", json!("user-secret-not-base64")),
            ("password", Value::Null),
        ] {
            let mut value = config(method, true);
            value["inbounds"][0]["users"][0][property] = invalid;
            let error = parse(&value).unwrap_err();
            assert!(!format!("{error:?}").contains("user-secret-not-base64"));
        }
    }
}

#[test]
fn rejects_legacy_methods_extensions_and_required_nulls() {
    for method in [
        "none",
        "plain",
        "aes-128-cfb",
        "rc4-md5",
        "aes-192-gcm",
        "2022-blake3-chacha8-poly1305",
        "method-secret-unknown",
    ] {
        let mut value = config(METHODS[0], false);
        value["inbounds"][0]["method"] = json!(method);
        let error = parse(&value).unwrap_err();
        assert!(!format!("{error:?}").contains(method));
    }
    for field in ["tag", "listen", "method", "password"] {
        let mut value = config(METHODS[0], false);
        value["inbounds"][0].as_object_mut().unwrap().remove(field);
        assert!(parse(&value).is_err());
        value["inbounds"][0][field] = Value::Null;
        assert!(parse(&value).is_err());
    }
    for field in [
        "plugin",
        "uot",
        "udp_over_tcp",
        "relay",
        "certificate",
        "private_key",
        "transport",
    ] {
        let mut value = config(METHODS[0], false);
        value["inbounds"][0][field] = json!("extension-secret");
        let error = parse(&value).unwrap_err();
        assert!(!format!("{error:?}").contains("extension-secret"));
    }
    let mut value = config(METHODS[0], false);
    value["inbounds"][0]["password"] = json!("");
    assert!(parse(&value).is_err());
}

#[test]
fn replay_capacity_defaults_bounds_and_old_limits_are_compatible() {
    let mut value = config(METHODS[3], true);
    assert_eq!(parse(&value).unwrap().limits.max_replay_entries, 65536);
    value["limits"] = json!({"max_connections": 16});
    assert_eq!(parse(&value).unwrap().limits.max_replay_entries, 65536);
    for capacity in [0, 1_048_577] {
        value["limits"] = json!({"max_replay_entries": capacity});
        assert!(parse(&value).is_err());
    }
    for capacity in [1, 1_048_576] {
        value["limits"] = json!({"max_replay_entries": capacity});
        assert!(parse(&value).is_ok());
    }
    for invalid in [Value::Null, json!(true), json!(-1), json!("65536")] {
        value["limits"] = json!({"max_replay_entries": invalid});
        assert!(parse(&value).is_err());
    }
}
