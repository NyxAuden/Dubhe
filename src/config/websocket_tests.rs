use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};

use super::{Config, EarlyData, Inbound, VlessFlow, WebSocket};

const KINDS: [&str; 3] = ["vless-ws", "vmess-ws", "trojan-ws"];
const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const OTHER_UUID: &str = "f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f";
const PASSWORD: &str = "ws-config-password-secret-918";
const SECRET: &str = "ws-config-sensitive-input-918";

fn valid_value(kind: &str) -> Value {
    let user = if kind == "trojan-ws" {
        json!({"name": "alice", "password": PASSWORD})
    } else {
        json!({"name": "alice", "uuid": UUID})
    };
    json!({
        "version": 1,
        "inbounds": [{
            "type": kind, "tag": kind, "listen": "127.0.0.1:0", "users": [user],
            "certificate": "cert.pem", "private_key": "key.pem",
            "websocket": {"path": "/proxy"}
        }],
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "route": {"default": "direct"}
    })
}

fn parse(value: &Value) -> Result<Config> {
    Config::from_json(&value.to_string())
}

fn remove_tls(value: &mut Value) {
    for field in ["certificate", "private_key"] {
        value["inbounds"][0].as_object_mut().unwrap().remove(field);
    }
}

fn websocket(inbound: &Inbound) -> &WebSocket {
    match inbound {
        Inbound::VlessWs { websocket, .. }
        | Inbound::VmessWs { websocket, .. }
        | Inbound::TrojanWs { websocket, .. } => websocket,
        _ => panic!("错误的测试入口"),
    }
}

fn assert_sanitized(error: &anyhow::Error) {
    assert_eq!(error.chain().count(), 1);
    for rendered in [
        format!("{error}"),
        format!("{error:#}"),
        format!("{error:?}"),
    ] {
        for secret in [UUID, OTHER_UUID, PASSWORD, SECRET] {
            assert!(!rendered.contains(secret), "配置错误泄漏秘密");
        }
        assert!(!rendered.contains(&UUID.to_uppercase()));
    }
}

#[test]
fn websocket_new_types_defaults_tls_accessors_and_roundtrip() {
    for kind in KINDS {
        let mut value = valid_value(kind);
        value["inbounds"][0]["listen"] = json!("[::1]:8443");
        let config = parse(&value).unwrap();
        let inbound = &config.inbounds[0];
        assert_eq!(inbound.tag(), kind);
        assert_eq!(inbound.listen(), "[::1]:8443".parse().unwrap());
        assert_eq!(
            inbound.tls_paths(),
            Some((Path::new("cert.pem"), Path::new("key.pem")))
        );
        match inbound {
            Inbound::VlessWs {
                users,
                xudp: true,
                allow_insecure_transport: false,
                ..
            } => {
                assert_eq!(users[0].flow, VlessFlow::None);
            }
            Inbound::VmessWs {
                xudp: true,
                packetaddr: false,
                allow_insecure_body: false,
                allow_authenticated_length: false,
                ..
            }
            | Inbound::TrojanWs {
                allow_insecure_transport: false,
                ..
            } => {}
            _ => panic!("新入口的缺省值发生变化"),
        }
        let ws = websocket(inbound);
        assert_eq!(ws.path, "/proxy");
        assert!(ws.host.is_none());
        assert!(ws.early_data.is_none());
        ws.validate().unwrap();
        let serialized = serde_json::to_value(&config).unwrap();
        assert_eq!(serialized["inbounds"][0]["type"], kind);
        assert!(serialized["inbounds"][0]["websocket"].get("host").is_none());
        assert!(
            serialized["inbounds"][0]["websocket"]
                .get("early_data")
                .is_none()
        );
        assert_eq!(
            serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
            serialized
        );
    }
}

#[test]
fn websocket_plaintext_security_is_explicit_even_on_loopback() {
    for kind in KINDS {
        for listen in ["127.0.0.1:0", "[::1]:0", "0.0.0.0:0", "[::]:0"] {
            let mut value = valid_value(kind);
            remove_tls(&mut value);
            value["inbounds"][0]["listen"] = json!(listen);
            if kind == "vmess-ws" {
                let config = parse(&value).unwrap();
                assert_eq!(config.inbounds[0].tls_paths(), None);
                assert!(matches!(
                    config.inbounds[0],
                    Inbound::VmessWs {
                        allow_insecure_body: false,
                        ..
                    }
                ));
                value["inbounds"][0]["allow_insecure_transport"] = json!(true);
                assert_sanitized(&parse(&value).unwrap_err());
                continue;
            }
            for option in [None, Some(false), Some(true)] {
                let mut candidate = value.clone();
                if let Some(option) = option {
                    candidate["inbounds"][0]["allow_insecure_transport"] = json!(option);
                }
                if option == Some(true) {
                    let config = parse(&candidate).unwrap();
                    assert_eq!(config.inbounds[0].tls_paths(), None);
                    let serialized = serde_json::to_value(config).unwrap();
                    assert!(serialized["inbounds"][0].get("certificate").is_none());
                    assert!(serialized["inbounds"][0].get("private_key").is_none());
                    parse(&serialized).unwrap();
                } else {
                    let error = parse(&candidate).unwrap_err();
                    assert!(error.to_string().contains("allow_insecure_transport=true"));
                    assert_sanitized(&error);
                }
            }
        }
    }
}

#[test]
fn websocket_tls_pair_null_empty_and_wrong_types_are_rejected() {
    for kind in KINDS {
        for field in ["certificate", "private_key"] {
            let mut half = valid_value(kind);
            half["inbounds"][0].as_object_mut().unwrap().remove(field);
            half["inbounds"][0]["allow_insecure_transport"] = json!(true);
            if kind == "vmess-ws" {
                half["inbounds"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("allow_insecure_transport");
            }
            let error = parse(&half).unwrap_err();
            assert!(error.to_string().contains("必须成对配置"));
            assert_sanitized(&error);
            for invalid in [
                json!(""),
                Value::Null,
                json!(true),
                json!(1),
                json!(1.5),
                json!([]),
                json!([SECRET]),
                json!({SECRET: "path"}),
            ] {
                let mut value = valid_value(kind);
                value["inbounds"][0][field] = invalid;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
        let mut value = valid_value(kind);
        value["inbounds"][0]["certificate"] = Value::Null;
        value["inbounds"][0]["private_key"] = Value::Null;
        assert_sanitized(&parse(&value).unwrap_err());
    }
}

#[test]
fn websocket_early_data_modes_defaults_accessors_and_full_bounds() {
    for kind in KINDS {
        for mode in ["header", "path"] {
            for max_bytes in [1, 8192] {
                let mut value = valid_value(kind);
                value["inbounds"][0]["websocket"]["early_data"] =
                    json!({"mode": mode, "max_bytes": max_bytes});
                let config = parse(&value).unwrap();
                let early = websocket(&config.inbounds[0]).early_data.as_ref().unwrap();
                assert_eq!(early.max_bytes(), max_bytes);
                assert_eq!(
                    early.header_name(),
                    (mode == "header").then_some("Sec-WebSocket-Protocol")
                );
                assert!(matches!(
                    (mode, early),
                    ("header", EarlyData::Header { .. }) | ("path", EarlyData::Path { .. })
                ));
                let serialized = serde_json::to_value(config).unwrap();
                if mode == "path" {
                    assert!(
                        serialized["inbounds"][0]["websocket"]["early_data"]
                            .get("header_name")
                            .is_none()
                    );
                } else {
                    assert_eq!(
                        serialized["inbounds"][0]["websocket"]["early_data"]["header_name"],
                        "Sec-WebSocket-Protocol"
                    );
                }
                assert_eq!(
                    serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
                    serialized
                );
            }
            for invalid in [
                json!(0),
                json!(8193),
                json!(u64::MAX),
                json!(-1),
                json!(1.5),
                Value::Null,
                json!(true),
                json!(SECRET),
                json!([]),
                json!({SECRET: 1}),
            ] {
                let mut value = valid_value(kind);
                value["inbounds"][0]["websocket"]["early_data"] =
                    json!({"mode": mode, "max_bytes": invalid});
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
    }
}

#[test]
fn websocket_path_preserves_case_slashes_plus_and_single_percent_decode() {
    for path in [
        "/".to_owned(),
        "/Ws/".to_owned(),
        "/a//../b+".to_owned(),
        "/%41/%2f/%25/%2520".to_owned(),
        "/!$&'()*+,;=:@-._~".to_owned(),
        format!("/{}", "a".repeat(1023)),
    ] {
        let mut value = valid_value("vmess-ws");
        value["inbounds"][0]["websocket"]["path"] = json!(path);
        let config = parse(&value).unwrap();
        assert_eq!(websocket(&config.inbounds[0]).path, path);
        value["inbounds"][0]["websocket"]["early_data"] =
            json!({"mode": "header", "max_bytes": 8192});
        parse(&value).unwrap();
        value["inbounds"][0]["websocket"]["early_data"] =
            json!({"mode": "path", "max_bytes": 8192});
        assert_eq!(parse(&value).is_ok(), !path.contains('%'));
    }
}

#[test]
fn websocket_rejects_malformed_raw_and_decoded_path_syntax() {
    for path in [
        "".to_owned(),
        "relative".to_owned(),
        "http://example.test/a".to_owned(),
        "/?ed=8192".to_owned(),
        "/#secret".to_owned(),
        "/a b".to_owned(),
        "/a\tb".to_owned(),
        "/a\r\nb".to_owned(),
        "/a\0b".to_owned(),
        "/é".to_owned(),
        "/\\evil".to_owned(),
        "/[a]".to_owned(),
        "/%".to_owned(),
        "/%a".to_owned(),
        "/%gg".to_owned(),
        "/%00".to_owned(),
        "/%09".to_owned(),
        "/%0d%0a".to_owned(),
        "/%20".to_owned(),
        "/%7f".to_owned(),
        "/%80".to_owned(),
        "/%3f".to_owned(),
        "/%23".to_owned(),
        "/%5c".to_owned(),
        format!("/{}", "a".repeat(1024)),
    ] {
        let mut value = valid_value("vmess-ws");
        value["inbounds"][0]["websocket"]["path"] = json!(path);
        assert_sanitized(&parse(&value).unwrap_err());
    }
}

#[test]
fn websocket_host_authority_is_finite_ascii_and_preserves_original_text() {
    for host in [
        "example.test",
        "EXAMPLE.test.",
        "localhost",
        "example.test:0",
        "example.test:65535",
        "127.0.0.1:443",
        "[::1]",
        "[2001:db8::1]:8443",
        "[::ffff:192.0.2.1]:00443",
    ] {
        let mut value = valid_value("vmess-ws");
        value["inbounds"][0]["websocket"]["host"] = json!(host);
        let config = parse(&value).unwrap();
        assert_eq!(websocket(&config.inbounds[0]).host.as_deref(), Some(host));
    }
    for host in [
        "",
        " ",
        "example.test ",
        " example.test",
        "é.test",
        "*.test",
        ".",
        ".test",
        "bad..test",
        "bad.test..",
        "user@example.test",
        "https://example.test",
        "example.test/path",
        "example.test?ed=1",
        "example.test#fragment",
        "bad%20.test",
        "bad\\test",
        "bad\r\ntest",
        "bad\0test",
        ":443",
        "example.test:",
        "example.test:+1",
        "example.test:-1",
        "example.test:65536",
        "example.test:999999999999999999999999999999999",
        "example.test:443:80",
        "::1",
        "[::1",
        "::1]",
        "[]",
        "[example.test]",
        "[::1]tail",
        "[::1]:",
        "[::1]:65536",
        "[::1]:+443",
        "[fe80::1%lo0]:443",
    ] {
        let mut value = valid_value("vmess-ws");
        value["inbounds"][0]["websocket"]["host"] = json!(host);
        assert_sanitized(&parse(&value).unwrap_err());
    }
}

#[test]
fn websocket_header_name_token_boundary_and_reserved_names() {
    for name in [
        "Sec-WebSocket-Protocol".to_owned(),
        "sEc-WeBsOcKeT-pRoToCoL".to_owned(),
        "X-Proxy-Early-Data".to_owned(),
        "Proxy-Early-Data".to_owned(),
        "X-!#$%&'*+-.^_`|~".to_owned(),
        "x".repeat(64),
    ] {
        let mut value = valid_value("vmess-ws");
        value["inbounds"][0]["websocket"]["early_data"] =
            json!({"mode": "header", "max_bytes": 8192, "header_name": name});
        let config = parse(&value).unwrap();
        assert_eq!(
            websocket(&config.inbounds[0])
                .early_data
                .as_ref()
                .unwrap()
                .header_name(),
            Some(name.as_str())
        );
    }
    for name in [
        "".to_owned(),
        "x".repeat(65),
        "X A".to_owned(),
        "X:A".to_owned(),
        "X,Other".to_owned(),
        "X\r\nA".to_owned(),
        "é".to_owned(),
        "Host".to_owned(),
        "Connection".to_owned(),
        "Upgrade".to_owned(),
        "Sec-WebSocket-Key".to_owned(),
        "Sec-WebSocket-Version".to_owned(),
        "Sec-WebSocket-Accept".to_owned(),
        "Sec-WebSocket-Extensions".to_owned(),
        "Content-Length".to_owned(),
        "Transfer-Encoding".to_owned(),
        "Authorization".to_owned(),
        "Cookie".to_owned(),
        "Set-Cookie".to_owned(),
        "Proxy-Authorization".to_owned(),
        "Proxy-Authenticate".to_owned(),
        "Proxy-Authentication-Info".to_owned(),
        "WWW-Authenticate".to_owned(),
        "Authentication-Info".to_owned(),
        "Forwarded".to_owned(),
        "X-Forwarded-For".to_owned(),
        "X-Forwarded-Proto".to_owned(),
        "X-Forwarded-Host".to_owned(),
        "X-Real-IP".to_owned(),
        "Via".to_owned(),
    ] {
        for name in [name.to_ascii_lowercase(), name.to_ascii_uppercase()] {
            let mut value = valid_value("vmess-ws");
            value["inbounds"][0]["websocket"]["early_data"] =
                json!({"mode": "header", "max_bytes": 1, "header_name": name});
            assert_sanitized(&parse(&value).unwrap_err());
        }
    }
}

#[test]
fn websocket_objects_require_fields_and_reject_null_wrong_types_and_unknown_fields() {
    for kind in KINDS {
        for (pointer, fields) in [
            (
                "/inbounds/0",
                &["type", "tag", "listen", "users", "websocket"][..],
            ),
            (
                "/inbounds/0/users/0",
                if kind == "trojan-ws" {
                    &["name", "password"][..]
                } else {
                    &["name", "uuid"][..]
                },
            ),
            ("/inbounds/0/websocket", &["path"][..]),
        ] {
            for field in fields {
                let mut value = valid_value(kind);
                value
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(*field);
                assert_sanitized(&parse(&value).unwrap_err());
                let mut value = valid_value(kind);
                value.pointer_mut(pointer).unwrap()[*field] = Value::Null;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
        for field in ["host", "early_data"] {
            let mut value = valid_value(kind);
            value["inbounds"][0]["websocket"][field] = Value::Null;
            assert_sanitized(&parse(&value).unwrap_err());
        }
        for pointer in [
            "/inbounds/0",
            "/inbounds/0/users/0",
            "/inbounds/0/websocket",
        ] {
            let mut value = valid_value(kind);
            value.pointer_mut(pointer).unwrap()[SECRET] = json!(SECRET);
            let error = parse(&value).unwrap_err();
            assert!(error.to_string().contains("未知字段"));
            assert_sanitized(&error);
        }
        for pointer in ["/inbounds/0/websocket", "/inbounds/0/websocket/early_data"] {
            for invalid in [
                json!(true),
                json!(1),
                json!(1.5),
                json!(SECRET),
                json!([]),
                json!([SECRET]),
                json!(["/proxy"]),
                json!(["/proxy", "example.test"]),
            ] {
                let mut value = valid_value(kind);
                value.pointer_mut("/inbounds/0/websocket").unwrap()["early_data"] =
                    json!({"mode": "header", "max_bytes": 1});
                *value.pointer_mut(pointer).unwrap() = invalid;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
        for field in ["path", "host"] {
            for invalid in [
                Value::Null,
                json!(true),
                json!(1),
                json!(1.5),
                json!([]),
                json!({SECRET: SECRET}),
            ] {
                let mut value = valid_value(kind);
                value["inbounds"][0]["websocket"][field] = invalid;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
        for early in [
            json!({}),
            json!({"mode": "header"}),
            json!({"max_bytes": 1}),
            json!({"mode": null, "max_bytes": 1}),
            json!({"mode": SECRET, "max_bytes": 1}),
            json!({"mode": {"header": null}, "max_bytes": 1}),
            json!(["header", 8192]),
            json!(["path", 8192]),
            json!(["header", 8192, "X-ED"]),
            json!({"mode": "header", "max_bytes": 1, "header_name": null}),
            json!({"mode": "header", "max_bytes": 1, "header_name": 1}),
            json!({"mode": "header", "max_bytes": 1, SECRET: SECRET}),
            json!({"mode": "path", "max_bytes": 1, SECRET: SECRET}),
            json!({"mode": "path", "max_bytes": 1, "header_name": "X-ED"}),
            json!({"mode": "path", "max_bytes": 1, "header_name": null}),
        ] {
            let mut value = valid_value(kind);
            value["inbounds"][0]["websocket"]["early_data"] = early;
            assert_sanitized(&parse(&value).unwrap_err());
        }
    }
}

#[test]
fn websocket_boolean_options_are_independent_and_strict() {
    for (kind, fields) in [
        ("vless-ws", &["xudp", "allow_insecure_transport"][..]),
        (
            "vmess-ws",
            &[
                "xudp",
                "packetaddr",
                "allow_insecure_body",
                "allow_authenticated_length",
            ][..],
        ),
        ("trojan-ws", &["allow_insecure_transport"][..]),
    ] {
        for bits in 0..(1 << fields.len()) {
            let mut value = valid_value(kind);
            for (index, field) in fields.iter().enumerate() {
                value["inbounds"][0][*field] = json!(bits & (1 << index) != 0);
            }
            let serialized = serde_json::to_value(parse(&value).unwrap()).unwrap();
            for field in fields {
                assert_eq!(
                    serialized["inbounds"][0][*field],
                    value["inbounds"][0][*field]
                );
            }
            assert_eq!(
                serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
                serialized
            );
        }
        for field in fields {
            for invalid in [
                Value::Null,
                json!(0),
                json!(1),
                json!(1.5),
                json!("true"),
                json!(SECRET),
                json!([]),
                json!({SECRET: true}),
            ] {
                let mut value = valid_value(kind);
                value["inbounds"][0][*field] = invalid;
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
    }
}

#[test]
fn websocket_user_count_boundaries_identity_uniqueness_and_placeholders() {
    for kind in KINDS {
        for (count, valid) in [(0, false), (1, true), (1024, true), (1025, false)] {
            let mut value = valid_value(kind);
            value["inbounds"][0]["users"] = json!((0..count).map(|index| {
                if kind == "trojan-ws" {
                    json!({"name": format!("user-{index}"), "password": format!("password-{index}")})
                } else {
                    json!({"name": format!("user-{index}"), "uuid": format!("00000000-0000-0000-0000-{index:012x}")})
                }
            }).collect::<Vec<_>>());
            assert_eq!(parse(&value).is_ok(), valid, "{kind}: 用户数 {count}");
        }
        let identity = if kind == "trojan-ws" {
            "password"
        } else {
            "uuid"
        };
        for duplicate_name in [false, true] {
            let mut value = valid_value(kind);
            let mut other = value["inbounds"][0]["users"][0].clone();
            if duplicate_name {
                other[identity] = json!(if kind == "trojan-ws" {
                    SECRET.to_owned()
                } else {
                    OTHER_UUID.to_owned()
                });
            } else {
                other["name"] = json!("bob");
                if kind != "trojan-ws" {
                    other[identity] = json!(UUID.to_uppercase());
                }
            }
            value["inbounds"][0]["users"]
                .as_array_mut()
                .unwrap()
                .push(other);
            assert_sanitized(&parse(&value).unwrap_err());
        }
        for field in ["name", identity] {
            let mut value = valid_value(kind);
            value["inbounds"][0]["users"][0][field] = json!("");
            assert_sanitized(&parse(&value).unwrap_err());
        }
        if kind != "trojan-ws" {
            for placeholder in ["replace-with-uuid", "YOUR_UUID", "<uuid>", SECRET] {
                let mut value = valid_value(kind);
                value["inbounds"][0]["users"][0]["uuid"] = json!(placeholder);
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
        // 与旧协议一致：名字和 Trojan 密码不新增 SOCKS5 的255字节限制。
        let mut value = valid_value(kind);
        value["inbounds"][0]["users"][0]["name"] = json!("用户".repeat(256));
        if kind == "trojan-ws" {
            value["inbounds"][0]["users"][0]["password"] = json!("密".repeat(256));
        }
        parse(&value).unwrap();
    }
}

#[test]
fn websocket_vless_requires_all_flows_none_and_other_protocols_reject_flow() {
    for flow in [
        json!(""),
        json!("xtls-rprx-vision"),
        Value::Null,
        json!(true),
        json!(1),
        json!({"": null}),
        json!(SECRET),
    ] {
        let mut value = valid_value("vless-ws");
        value["inbounds"][0]["users"][0]["flow"] = flow.clone();
        assert_eq!(parse(&value).is_ok(), flow == json!(""));
        if flow != json!("") {
            assert_sanitized(&parse(&value).unwrap_err());
        }
        for kind in ["vmess-ws", "trojan-ws"] {
            let mut value = valid_value(kind);
            value["inbounds"][0]["users"][0]["flow"] = flow.clone();
            assert_sanitized(&parse(&value).unwrap_err());
        }
    }
    let mut value = valid_value("vless-ws");
    value["inbounds"][0]["users"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "vision", "uuid": OTHER_UUID, "flow": "xtls-rprx-vision"}));
    assert_sanitized(&parse(&value).unwrap_err());
}

#[test]
fn websocket_rejects_illegal_layering_and_protocol_option_aliases() {
    for kind in KINDS {
        for field in [
            "flow",
            "vision",
            "reality",
            "mux",
            "multiplex",
            "transport",
            "grpc",
            "encryption",
            "fallback",
            "allow_insecure",
            "early_data",
        ] {
            let mut value = valid_value(kind);
            value["inbounds"][0][field] = json!(SECRET);
            assert_sanitized(&parse(&value).unwrap_err());
        }
        for alias in [
            kind.to_ascii_uppercase(),
            kind.replace('-', ""),
            kind.replace("-ws", "-websocket"),
        ] {
            let mut value = valid_value(kind);
            value["inbounds"][0]["type"] = json!(alias);
            assert_sanitized(&parse(&value).unwrap_err());
        }
        for field in [
            "allow_insecure_body",
            "allow_authenticated_length",
            "packetaddr",
            "allow_insecure_transport",
            "xudp",
        ] {
            let supported = match kind {
                "vless-ws" => matches!(field, "xudp" | "allow_insecure_transport"),
                "vmess-ws" => field != "allow_insecure_transport",
                "trojan-ws" => field == "allow_insecure_transport",
                _ => unreachable!(),
            };
            if !supported {
                let mut value = valid_value(kind);
                value["inbounds"][0][field] = json!(false);
                assert_sanitized(&parse(&value).unwrap_err());
            }
        }
    }
}

#[test]
fn websocket_duplicate_fields_are_rejected_with_sanitized_errors() {
    for kind in KINDS {
        let mut value = valid_value(kind);
        value["inbounds"][0]["websocket"]["host"] = json!("example.test");
        value["inbounds"][0]["websocket"]["early_data"] =
            json!({"mode": "header", "max_bytes": 8192, "header_name": "X-ED"});
        for (field, original) in [
            ("type", json!(kind)),
            ("tag", json!(kind)),
            ("listen", json!("127.0.0.1:0")),
            ("users", value["inbounds"][0]["users"].clone()),
            ("name", json!("alice")),
            ("websocket", value["inbounds"][0]["websocket"].clone()),
            ("certificate", json!("cert.pem")),
            ("private_key", json!("key.pem")),
            ("path", json!("/proxy")),
            ("host", json!("example.test")),
            (
                "early_data",
                value["inbounds"][0]["websocket"]["early_data"].clone(),
            ),
            ("mode", json!("header")),
            ("max_bytes", json!(8192)),
            ("header_name", json!("X-ED")),
        ] {
            let needle = format!("\"{field}\":{original}");
            let duplicate = format!("{needle},\"{field}\":\"{SECRET}\"");
            let input = value.to_string().replacen(&needle, &duplicate, 1);
            assert_ne!(input, value.to_string());
            assert_sanitized(&Config::from_json(&input).unwrap_err());
        }
    }
}

#[test]
fn websocket_debug_redacts_secrets_at_all_levels_including_paths() {
    for kind in KINDS {
        let mut value = valid_value(kind);
        value["inbounds"][0]["certificate"] = json!(format!("{SECRET}-certificate.pem"));
        value["inbounds"][0]["private_key"] = json!(format!("{SECRET}-private-key.pem"));
        value["inbounds"][0]["websocket"] = json!({
            "path": format!("/{SECRET}"), "host": format!("{SECRET}.example"),
            "early_data": {"mode": "header", "max_bytes": 8192, "header_name": format!("X-{SECRET}")}
        });
        let config = parse(&value).unwrap();
        let ws = websocket(&config.inbounds[0]);
        let early = ws.early_data.as_ref().unwrap();
        for rendered in [
            format!("{config:?}"),
            format!("{config:#?}"),
            format!("{:?}", config.inbounds[0]),
            format!("{:#?}", config.inbounds[0]),
            format!("{ws:?}"),
            format!("{ws:#?}"),
            format!("{early:?}"),
            format!("{early:#?}"),
        ] {
            assert!(rendered.contains("[REDACTED]"));
            for secret in [SECRET, UUID, PASSWORD] {
                assert!(!rendered.contains(secret), "Debug 泄漏秘密");
            }
        }
    }
}

#[test]
fn websocket_direct_validation_keeps_guards_and_is_purely_static() {
    let mut ws = WebSocket {
        path: "/proxy".into(),
        host: None,
        early_data: None,
    };
    ws.validate().unwrap();
    ws.host = Some(SECRET.into());
    ws.early_data = Some(EarlyData::Header {
        max_bytes: 8192,
        header_name: "Sec-WebSocket-Protocol".into(),
    });
    ws.validate().unwrap();
    ws.early_data = Some(EarlyData::Path { max_bytes: 0 });
    assert_sanitized(&ws.validate().unwrap_err());
    ws.early_data = Some(EarlyData::Path { max_bytes: 8193 });
    assert_sanitized(&ws.validate().unwrap_err());
    ws.early_data = Some(EarlyData::Path { max_bytes: 1 });
    ws.path = "/%41".into();
    assert_sanitized(&ws.validate().unwrap_err());
    ws.path = format!("/{SECRET}?ed=1");
    assert_sanitized(&ws.validate().unwrap_err());
    ws.path = "/proxy".into();
    ws.host = Some(format!("{SECRET}:65536"));
    assert_sanitized(&ws.validate().unwrap_err());
    ws.host = None;
    ws.early_data = Some(EarlyData::Header {
        max_bytes: 1,
        header_name: "Authorization".into(),
    });
    assert_sanitized(&ws.validate().unwrap_err());

    for kind in KINDS {
        let mut value = valid_value(kind);
        // 非本机地址、确定不存在的路径也不触发 bind、文件读取或 DNS。
        value["inbounds"][0]["listen"] = json!("192.0.2.123:8443");
        value["inbounds"][0]["certificate"] = json!(format!("/nonexistent-{SECRET}/cert.pem"));
        value["inbounds"][0]["private_key"] = json!(format!("/nonexistent-{SECRET}/key.pem"));
        value["inbounds"][0]["websocket"]["host"] = json!("does-not-exist.invalid");
        let mut config = parse(&value).unwrap();
        config.validate().unwrap();
        match &mut config.inbounds[0] {
            Inbound::VlessWs { users, .. } => users[0].flow = VlessFlow::Vision,
            Inbound::VmessWs { users, .. } => users[0].uuid = SECRET.into(),
            Inbound::TrojanWs { users, .. } => users.clear(),
            _ => panic!(),
        }
        assert_sanitized(&config.validate().unwrap_err());
    }
}

#[test]
fn websocket_old_protocols_keep_tls_flow_and_unknown_field_contracts() {
    let mut value = valid_value("vmess-ws");
    value["inbounds"].as_array_mut().unwrap().extend([
        json!({"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}),
        json!({"type": "trojan", "tag": "trojan", "listen": "127.0.0.1:0", "users": [{"name": "alice", "password": PASSWORD}], "certificate": "cert.pem", "private_key": "key.pem"}),
        json!({"type": "vless", "tag": "vless", "listen": "127.0.0.1:0", "users": [{"name": "alice", "uuid": UUID}, {"name": "vision", "uuid": OTHER_UUID, "flow": "xtls-rprx-vision"}], "certificate": "cert.pem", "private_key": "key.pem"}),
        json!({"type": "vmess", "tag": "vmess", "listen": "127.0.0.1:0", "users": [{"name": "alice", "uuid": UUID}]}),
        json!({"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1:0", "method": "aes-128-gcm", "password": PASSWORD}),
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
    assert!(matches!(
        config.inbounds[4],
        Inbound::Vmess {
            xudp: true,
            packetaddr: false,
            allow_insecure_body: false,
            allow_authenticated_length: false,
            ..
        }
    ));
    assert_eq!(config.inbounds[4].tls_paths(), None);
    for index in [2, 3] {
        for field in ["certificate", "private_key"] {
            let mut missing = value.clone();
            missing["inbounds"][index]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_sanitized(&parse(&missing).unwrap_err());
        }
    }
    for index in 1..=5 {
        let mut extended = value.clone();
        extended["inbounds"][index]["websocket"] = json!({"path": "/proxy"});
        assert_sanitized(&parse(&extended).unwrap_err());
    }
    let serialized = serde_json::to_value(config).unwrap();
    assert_eq!(
        serde_json::to_value(parse(&serialized).unwrap()).unwrap(),
        serialized
    );
    value["inbounds"][1]["listen"] = json!("0.0.0.0:0");
    assert_sanitized(&parse(&value).unwrap_err());
}
