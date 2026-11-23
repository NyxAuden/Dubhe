//! `config` 模块的单元测试。

use super::*;
use serde_json::{Value, json};

fn valid_value() -> Value {
    json!({
        "version": 1,
        "inbounds": [
            {"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"},
            {
                "type": "trojan", "tag": "tls", "listen": "[::1]:0",
                "users": [{"name": "alice", "password": "test-secret-password"}],
                "certificate": "test-cert.pem", "private_key": "test-key.pem"
            }
        ],
        "outbounds": [
            {"tag": "direct", "type": "direct"},
            {"tag": "blocked", "type": "reject"}
        ],
        "route": {"default": "direct"}
    })
}

/// 两个 TCP 入口抢占同一地址时，`check` 就该失败——否则要到 `run` 的
/// 绑定阶段才以 `AddrInUse` 整体退出。
#[test]
fn duplicate_tcp_listen_is_rejected() {
    let mut value = valid_value();
    value["inbounds"] = json!([
        {"type": "socks5", "tag": "a", "listen": "127.0.0.1:8080"},
        {"type": "http", "tag": "b", "listen": "127.0.0.1:8080"}
    ]);
    let error = parse_value(&value).unwrap_err().to_string();
    assert!(error.contains("在端口 8080 上冲突"), "{error}");
    assert!(error.contains("TCP 冲突"), "{error}");
}

/// 通配监听与具体地址在 macOS 上能同时绑定成功（SO_REUSEADDR），但连接
/// 由哪个套接字接收不确定；必须提前拦下。
#[test]
fn wildcard_and_specific_listen_overlap_is_rejected() {
    let mut value = valid_value();
    value["inbounds"] = json!([
        {"type": "socks5", "tag": "a", "listen": "0.0.0.0:8080", "allow_insecure": true},
        {"type": "http", "tag": "b", "listen": "127.0.0.1:8080", "allow_insecure": true}
    ]);
    let error = parse_value(&value).unwrap_err().to_string();
    assert!(error.contains("未指定地址"), "{error}");
}

/// `::` 在双栈模式下同时占用 IPv4 端口，因此与 IPv4 通配/具体地址冲突。
#[test]
fn ipv6_wildcard_conflicts_with_ipv4() {
    let mut value = valid_value();
    value["inbounds"] = json!([
        {"type": "socks5", "tag": "a", "listen": "[::]:8080", "allow_insecure": true},
        {"type": "http", "tag": "b", "listen": "0.0.0.0:8080", "allow_insecure": true}
    ]);
    let error = parse_value(&value).unwrap_err().to_string();
    assert!(error.contains("在端口 8080 上冲突"), "{error}");
}

/// NW3 Portal 同端口绑 TCP 与 UDP 两个 socket，必须与 Hysteria2 冲突。
/// 此前把它当成只占 TCP，导致 `check` 通过、`run` 报 `监听任务失败: Other`。
#[test]
fn nw3_occupies_both_tcp_and_udp() {
    let mut value = valid_value();
    value["inbounds"] = json!([
        {"type": "nw3", "tag": "portal", "listen": "127.0.0.1:8443",
         "key": "0123456789abcdef0123456789abcdef", "morph": true, "out": "direct"},
        {"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1:8443", "udp": true,
         "users": [{"name": "u", "password": "test-secret-password"}],
         "certificate": "test-cert.pem", "private_key": "test-key.pem"}
    ]);
    let error = parse_value(&value).unwrap_err().to_string();
    assert!(error.contains("UDP 冲突"), "{error}");
}

/// XHTTP/3 只绑 UDP（runtime 走 continue，不起 TCP），因此与 TCP 入口同端口
/// 不冲突。此前声明成 TCP+UDP，会误拒这个合法组合。
#[test]
fn xhttp_h3_occupies_udp_only() {
    let mut value = valid_value();
    value["inbounds"] = json!([
        {"type": "vless-xhttp", "tag": "h3", "listen": "127.0.0.1:8443",
         "xhttp": {"path": "/x", "h3": true},
         "users": [{"name": "u", "uuid": "11111111-1111-1111-1111-111111111111"}],
         "certificate": "test-cert.pem", "private_key": "test-key.pem"},
        {"type": "socks5", "tag": "sk", "listen": "127.0.0.1:8443"}
    ]);
    parse_value(&value).expect("XHTTP/3 与 TCP 入口可共用端口号");
}

/// 相同端口、不同具体地址不算冲突（Linux 与 macOS 都能正常绑定）。
#[test]
fn distinct_specific_addresses_on_same_port_are_allowed() {
    let mut value = valid_value();
    value["inbounds"] = json!([
        {"type": "socks5", "tag": "a", "listen": "127.0.0.1:8080"},
        {"type": "http", "tag": "b", "listen": "127.0.0.2:8080", "allow_insecure": true}
    ]);
    parse_value(&value).expect("不同具体地址可以共用端口");
}

/// TCP 与 UDP 占同一端口不冲突：Hysteria2 只监听 UDP，可以和 TCP 入口共存。
#[test]
fn tcp_and_udp_may_share_a_port() {
    let mut value = valid_value();
    value["inbounds"] = json!([
        {"type": "socks5", "tag": "a", "listen": "127.0.0.1:8080"},
        {"type": "hysteria2", "tag": "b", "listen": "127.0.0.1:8080", "udp": true,
         "users": [{"name": "u", "password": "test-secret-password"}],
         "certificate": "test-cert.pem", "private_key": "test-key.pem"}
    ]);
    parse_value(&value).expect("TCP 与 UDP 同端口应通过");
}

/// 两个只监听 UDP 的入口抢同一端口仍然冲突。
#[test]
fn duplicate_udp_listen_is_rejected() {
    let mut value = valid_value();
    value["inbounds"] = json!([
        {"type": "hysteria2", "tag": "a", "listen": "127.0.0.1:8080", "udp": true,
         "users": [{"name": "u", "password": "test-secret-password"}],
         "certificate": "test-cert.pem", "private_key": "test-key.pem"},
        {"type": "tuic", "tag": "b", "listen": "127.0.0.1:8080",
         "users": [{"name": "u", "uuid": "11111111-1111-1111-1111-111111111111", "password": "test-secret-password"}],
         "certificate": "test-cert.pem", "private_key": "test-key.pem"}
    ]);
    let error = parse_value(&value).unwrap_err().to_string();
    assert!(error.contains("UDP 冲突"), "{error}");
}

fn parse_value(value: &Value) -> Result<Config> {
    Config::from_json(&serde_json::to_string(value).unwrap())
}

fn set(value: &mut Value, pointer: &str, replacement: Value) {
    *value.pointer_mut(pointer).unwrap() = replacement;
}

#[test]
fn valid_dual_inbounds_defaults_and_serialization() {
    let config = parse_value(&valid_value()).unwrap();
    assert_eq!(config.inbounds[0].tag(), "socks");
    assert_eq!(config.inbounds[1].listen(), "[::1]:0".parse().unwrap());
    assert!(matches!(
        &config.inbounds[0],
        Inbound::Socks5 { users, allow_insecure: false, .. } if users.is_empty()
    ));
    assert!(config.route.rules.is_empty());
    let expected_limits = json!({
        "max_connections": 1024,
        "max_handshakes": 64,
        "max_grpc_streams": 256,
        "max_grpc_streams_per_connection": 16,
        "max_replay_entries": 65536,
        "max_vmess_replay_entries": 65536,
        "max_reality_replay_entries": 65536,
        "max_udp_associations": 256,
        "max_udp_targets": 64,
        "udp_queue_bytes": 262144,
        "udp_queue_packets": 64,
        "max_udp_payload": 65507,
        "max_xhttp_sessions": 256,
        "per_ip_handshakes": 8,
        "handshake_timeout_ms": 10000,
        "dial_timeout_ms": 10000,
        "dial_attempt_timeout_ms": 2000,
        "dns_timeout_ms": 5000,
        "max_dns_queries": 64,
        "udp_idle_timeout_ms": 60000,
        "idle_timeout_ms": 300000,
        "shutdown_timeout_ms": 5000,
        "stats_interval_ms": 30000
    });
    assert_eq!(
        serde_json::to_value(&config.limits).unwrap(),
        expected_limits
    );
    let serialized = serde_json::to_value(config.clone()).unwrap();
    assert_eq!(serialized["outbounds"][0]["type"], "direct");
    assert!(serialized["outbounds"][0].get("kind").is_none());
    let roundtrip = parse_value(&serialized).unwrap();
    assert_eq!(serde_json::to_value(roundtrip).unwrap(), serialized);
}

#[test]
fn partial_limits_and_rules_keep_defaults() {
    let mut value = valid_value();
    value["limits"] = json!({"max_connections": 2});
    value["route"]["rules"] = json!([{"outbound": "blocked"}]);
    let config = parse_value(&value).unwrap();
    assert_eq!(config.limits.max_connections, 2);
    assert_eq!(config.limits.max_dns_queries, 64);
    let rule = &config.route.rules[0];
    assert!(rule.inbounds.is_empty());
    assert!(rule.networks.is_empty());
    assert!(rule.domains.is_empty());
    assert!(rule.ip_cidrs.is_empty());
    assert!(rule.ports.is_empty());
}

#[test]
fn invalid_configurations_are_rejected_without_values() {
    let cases = [
        ("/version", json!(0)),
        ("/version", json!(2)),
        ("/version", json!(-1)),
        ("/version", json!("sensitive-input")),
        ("/inbounds", json!([])),
        ("/outbounds", json!([])),
        ("/inbounds/0/type", json!("sensitive-input")),
        ("/outbounds/0/type", json!("sensitive-input")),
        ("/inbounds/0/listen", json!("sensitive-input")),
        ("/inbounds/0/listen", json!("127.0.0.1:65536")),
        ("/inbounds/0/tag", json!("tls")),
        ("/outbounds/1/tag", json!("direct")),
        ("/inbounds/1/users", json!([])),
        ("/inbounds/1/users/0/name", json!("")),
        ("/inbounds/1/users/0/password", json!("")),
        (
            "/inbounds/1/users/0/password",
            json!({"sensitive-input": 1}),
        ),
        ("/inbounds/1/certificate", json!("")),
        ("/inbounds/1/private_key", json!("")),
        ("/route/default", json!("sensitive-input")),
        ("/route/default", json!("")),
        ("/route/default", json!(null)),
        ("/limits", json!(null)),
        ("/sniffing/timeout_ms", json!(9)),
        ("/sniffing/timeout_ms", json!(10_001)),
        ("/sniffing/dest_override", json!(["tls", "tls"])),
        ("/sniffing/inbounds", json!(["missing"])),
        ("/sniffing", json!({"enabled": false, "route_only": true})),
    ];
    let mut base = valid_value();
    base["limits"] = json!({});
    base["sniffing"] = json!({
        "enabled": true,
        "inbounds": [],
        "dest_override": [],
        "route_only": false,
        "timeout_ms": 300
    });
    for (pointer, replacement) in cases {
        let mut value = base.clone();
        set(&mut value, pointer, replacement);
        let error = parse_value(&value).unwrap_err();
        for rendered in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            assert!(!rendered.contains("sensitive-input"), "{pointer}");
            assert!(!rendered.contains("test-secret-password"), "{pointer}");
        }
    }
}

#[test]
fn all_nested_objects_reject_unknown_fields_and_extensions() {
    let mut base = valid_value();
    base["limits"] = json!({});
    base["route"]["rules"] = json!([{
        "outbound": "direct", "ports": [{"start": 1, "end": 65535}]
    }]);
    for pointer in [
        "",
        "/inbounds/0",
        "/inbounds/1",
        "/inbounds/1/users/0",
        "/outbounds/0",
        "/outbounds/1",
        "/route",
        "/route/rules/0",
        "/route/rules/0/ports/0",
        "/limits",
    ] {
        let mut value = base.clone();
        value.pointer_mut(pointer).unwrap()["secret-unknown-field"] = json!("secret-unknown-value");
        let error = parse_value(&value).unwrap_err();
        let rendered = format!("{error:?}");
        assert!(rendered.contains("未知字段"), "{pointer}: {rendered}");
        assert!(rendered.contains("line ") && rendered.contains("column "));
        assert!(!rendered.contains("secret-unknown"));
    }
    for field in ["fallback", "transport", "multiplex", "mux"] {
        let mut value = base.clone();
        value["inbounds"][1][field] = json!({"secret": "extension-secret"});
        let error = parse_value(&value).unwrap_err().to_string();
        assert!(error.contains("未实现"), "{field}");
        assert!(!error.contains("extension-secret"));
    }
    // 已实现的扩展字段按各自类型校验；无论错误类别如何都不得回显配置值。
    for field in ["fallbacks", "websocket", "grpc", "httpupgrade", "xhttp"] {
        let mut value = base.clone();
        value["inbounds"][1][field] = json!({"secret": "extension-secret"});
        let error = parse_value(&value).unwrap_err().to_string();
        assert!(!error.contains("extension-secret"), "{field}");
    }
    let mut value = base;
    value["outbounds"][0]["kind"] = json!("direct");
    assert!(parse_value(&value).is_err());
}

#[test]
fn required_fields_and_explicit_nulls_are_rejected() {
    for (pointer, field) in [
        ("", "version"),
        ("", "inbounds"),
        ("", "outbounds"),
        ("", "route"),
        ("/inbounds/0", "type"),
        ("/inbounds/0", "tag"),
        ("/inbounds/0", "listen"),
        ("/inbounds/1", "users"),
        ("/inbounds/1", "certificate"),
        ("/inbounds/1", "private_key"),
        ("/inbounds/1/users/0", "name"),
        ("/inbounds/1/users/0", "password"),
        ("/outbounds/0", "type"),
        ("/outbounds/0", "tag"),
        ("/route", "default"),
    ] {
        let mut value = valid_value();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        let error = parse_value(&value).unwrap_err().to_string();
        assert!(error.contains("缺少必填字段"), "{pointer}/{field}: {error}");
    }
    for field in ["users", "allow_insecure"] {
        let mut value = valid_value();
        value["inbounds"][0][field] = Value::Null;
        assert!(parse_value(&value).is_err(), "{field}");
    }
}

#[test]
fn malformed_json_and_duplicate_fields_have_sanitized_locations() {
    let valid = serde_json::to_string(&valid_value()).unwrap();
    let cases = [
        String::new(),
        "{\n\"version\": \"syntax-secret\"".to_owned(),
        format!("{valid} syntax-secret"),
        valid.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        valid.replacen(
            "\"type\":\"trojan\"",
            "\"type\":\"trojan\",\"type\":\"socks5\"",
            1,
        ),
        valid.replacen(
            "\"password\":\"test-secret-password\"",
            "\"password\":\"test-secret-password\",\"password\":\"syntax-secret\"",
            1,
        ),
    ];
    for input in cases {
        let error = Config::from_json(&input).unwrap_err();
        assert_eq!(error.chain().count(), 1);
        let rendered = format!("{error:?}");
        assert!(rendered.contains("line ") && rendered.contains("column "));
        assert!(!rendered.contains("syntax-secret"));
        assert!(!rendered.contains("test-secret-password"));
    }
}

#[test]
fn tags_are_safe_and_namespaces_are_independent() {
    for tag in [
        "".to_owned(),
        " ".to_owned(),
        "a b".to_owned(),
        "a\nb".to_owned(),
        "a/b".to_owned(),
        "a\"b".to_owned(),
        "入口".to_owned(),
        "a".repeat(129),
    ] {
        for pointer in ["/inbounds/0/tag", "/outbounds/1/tag"] {
            let mut value = valid_value();
            set(&mut value, pointer, json!(tag));
            assert!(parse_value(&value).is_err(), "{pointer}");
        }
    }
    for tag in ["A-z_0.1".to_owned(), "a".repeat(128), "direct".to_owned()] {
        let mut value = valid_value();
        value["inbounds"][0]["tag"] = json!(tag);
        parse_value(&value).unwrap();
    }
}

#[test]
fn no_auth_socks_exposure_requires_explicit_opt_in() {
    for (listen, allow_insecure, authenticated, valid) in [
        ("127.0.0.1:0", false, false, true),
        ("127.2.3.4:0", false, false, true),
        ("[::1]:0", false, false, true),
        ("0.0.0.0:0", false, false, false),
        ("[::]:0", false, false, false),
        ("192.0.2.1:1080", false, false, false),
        ("0.0.0.0:0", true, false, true),
        ("[::]:0", true, false, true),
        ("0.0.0.0:0", false, true, true),
    ] {
        let mut value = valid_value();
        value["inbounds"][0]["listen"] = json!(listen);
        value["inbounds"][0]["allow_insecure"] = json!(allow_insecure);
        if authenticated {
            value["inbounds"][0]["users"] = json!([{"name": "bob", "password": "password"}]);
        }
        assert_eq!(parse_value(&value).is_ok(), valid, "{listen}");
    }
}

#[test]
fn user_uniqueness_and_socks_byte_lengths() {
    for inbound in [0, 1] {
        for users in [
            json!([{"name": "alice", "password": "one"}, {"name": "alice", "password": "two"}]),
            json!([{"name": "alice", "password": "one"}, {"name": "bob", "password": "one"}]),
        ] {
            let mut value = valid_value();
            value["inbounds"][inbound]["users"] = users;
            assert!(parse_value(&value).is_err());
        }
    }
    for field in ["name", "password"] {
        for (credential, valid) in [
            ("a".repeat(255), true),
            ("a".repeat(256), false),
            ("密".repeat(85), true),
            ("密".repeat(86), false),
        ] {
            let mut value = valid_value();
            value["inbounds"][0]["users"] = json!([{"name": "bob", "password": "password"}]);
            value["inbounds"][0]["users"][0][field] = json!(credential);
            assert_eq!(parse_value(&value).is_ok(), valid, "{field}");
        }
    }
    let mut value = valid_value();
    value["inbounds"][1]["users"][0]["password"] = json!("a".repeat(256));
    parse_value(&value).unwrap();
}

#[test]
fn limit_fields_enforce_both_bounds() {
    let max_permits = tokio::sync::Semaphore::MAX_PERMITS.min(u32::MAX as usize) as u64;
    let bounds = [
        ("max_connections", max_permits),
        ("max_handshakes", max_permits),
        ("max_replay_entries", 1_048_576),
        ("max_vmess_replay_entries", 1_048_576),
        ("max_udp_associations", max_permits),
        ("max_udp_targets", max_permits),
        ("udp_queue_packets", max_permits),
        ("max_dns_queries", max_permits),
        ("udp_queue_bytes", (1 << 30).min(max_permits)),
        ("max_udp_payload", 65_507),
        ("handshake_timeout_ms", 86_400_000),
        ("dial_timeout_ms", 86_400_000),
        ("dial_attempt_timeout_ms", 86_400_000),
        ("dns_timeout_ms", 86_400_000),
        ("udp_idle_timeout_ms", 86_400_000),
        ("shutdown_timeout_ms", 86_400_000),
        ("stats_interval_ms", 86_400_000),
    ];
    for (field, max) in bounds {
        for (number, valid) in [
            (0, false),
            (1, true),
            (max, true),
            (max + 1, false),
            (u64::MAX, false),
        ] {
            let mut value = valid_value();
            value["limits"] = json!({field: number});
            assert_eq!(parse_value(&value).is_ok(), valid, "{field} = {number}");
        }
        for number in [json!(-1), json!(1.5), json!("limit-secret"), Value::Null] {
            let mut value = valid_value();
            value["limits"] = json!({field: number});
            let error = parse_value(&value).unwrap_err().to_string();
            assert!(!error.contains("limit-secret"));
        }
    }
}

#[test]
fn invalid_rules_and_missing_fields_are_rejected() {
    for rule in [
        json!({}),
        json!({"outbound": "unknown"}),
        json!({"outbound": "direct", "inbounds": ["unknown"]}),
        json!({"outbound": "direct", "networks": ["quic"]}),
        json!({"outbound": "direct", "ports": [{"start": 2, "end": 1}]}),
        json!({"outbound": "direct", "ports": [{"start": 1}]}),
        json!({"outbound": "direct", "ports": [{"end": 1}]}),
        json!({"outbound": "direct", "ports": [{"start": 0, "end": 65536}]}),
        json!({"outbound": "direct", "ip_cidrs": ["route-secret"]}),
        json!({"outbound": "direct", "ip_cidrs": ["127.0.0.1/33"]}),
        json!({"outbound": "direct", "ip_cidrs": ["::1/129"]}),
    ] {
        let mut value = valid_value();
        value["route"]["rules"] = json!([rule]);
        let error = parse_value(&value).unwrap_err().to_string();
        assert!(!error.contains("route-secret"));
    }
    for domain in [
        "",
        ".",
        "..",
        "bad..example",
        "has space.example",
        "*.example",
        "bad\n.example",
    ] {
        let mut value = valid_value();
        value["route"]["rules"] = json!([{"outbound": "direct", "domains": [domain]}]);
        assert!(parse_value(&value).is_err());
    }
    let mut value = valid_value();
    value["route"]["rules"] = json!([{
        "outbound": "blocked", "inbounds": ["socks", "tls"], "networks": ["tcp", "udp"],
        "domains": ["EXAMPLE.com.", "localhost"], "ip_cidrs": ["192.0.2.0/24", "2001:db8::/32"],
        "ports": [{"start": 0, "end": 65535}]
    }]);
    parse_value(&value).unwrap();
}

#[test]
fn direct_validation_and_debug_remain_safe() {
    let mut config = parse_value(&valid_value()).unwrap();
    for rendered in [format!("{config:?}"), format!("{config:#?}")] {
        assert!(!rendered.contains("test-secret-password"));
        assert!(rendered.contains("[REDACTED]"));
    }
    config.route.default = "validation-secret".to_owned();
    let error = config.validate().unwrap_err();
    assert!(!format!("{error:?}").contains("validation-secret"));
    config.route.default = "direct".to_owned();
    config.limits.max_connections = 0;
    assert!(config.validate().is_err());
}

const VLESS_UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const OTHER_VLESS_UUID: &str = "f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f";

fn valid_vless_value() -> Value {
    let mut value = valid_value();
    value["inbounds"].as_array_mut().unwrap().push(json!({
        "type": "vless", "tag": "vless-tls", "listen": "127.0.0.1:8443",
        "users": [{"name": "alice", "uuid": VLESS_UUID}],
        "certificate": "vless-cert.pem", "private_key": "vless-key.pem"
    }));
    value
}

#[test]
fn uuid_parser_requires_standard_text_and_accepts_both_hex_cases() {
    let expected = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    for uuid in [VLESS_UUID.to_owned(), VLESS_UUID.to_uppercase()] {
        assert_eq!(parse_uuid(&uuid), Some(expected));
    }
    assert_eq!(
        parse_uuid("00000000-0000-0000-0000-000000000000"),
        Some([0; 16])
    );
    assert_eq!(
        parse_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff"),
        Some([255; 16])
    );
    for invalid in [
        "".to_owned(),
        "non-uuid-identity".to_owned(),
        VLESS_UUID.replace('-', ""),
        format!("{{{VLESS_UUID}}}"),
        format!("urn:uuid:{VLESS_UUID}"),
        format!(" {VLESS_UUID}"),
        format!("{VLESS_UUID}\n"),
        VLESS_UUID.replacen("00", "é", 1),
    ] {
        assert_eq!(parse_uuid(&invalid), None);
    }
    for index in 0..36 {
        let mut bytes = VLESS_UUID.as_bytes().to_vec();
        bytes[index] = if bytes[index] == b'-' { b'0' } else { b'g' };
        assert!(parse_uuid(std::str::from_utf8(&bytes).unwrap()).is_none());
    }
}

#[test]
fn vless_config_roundtrip_tls_paths_and_debug_redaction() {
    let mut value = valid_vless_value();
    let uppercase = OTHER_VLESS_UUID.to_uppercase();
    // 用户名沿用现有 TLS 入口规则：非空且唯一，不施加 SOCKS5 字节长度限制。
    value["inbounds"][2]["users"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name": "用户".repeat(128), "uuid": uppercase
        }));
    let config = parse_value(&value).unwrap();
    assert_eq!(config.inbounds[2].tag(), "vless-tls");
    assert_eq!(
        config.inbounds[2].listen(),
        "127.0.0.1:8443".parse().unwrap()
    );
    assert_eq!(config.inbounds[0].tls_paths(), None);
    assert_eq!(
        config.inbounds[1].tls_paths(),
        Some((Path::new("test-cert.pem"), Path::new("test-key.pem")))
    );
    assert_eq!(
        config.inbounds[2].tls_paths(),
        Some((Path::new("vless-cert.pem"), Path::new("vless-key.pem")))
    );
    for rendered in [format!("{config:?}"), format!("{config:#?}")] {
        assert!(!rendered.contains(VLESS_UUID));
        assert!(!rendered.contains(&uppercase));
        assert!(!rendered.contains("test-secret-password"));
        assert!(rendered.contains("[REDACTED]"));
    }
    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["inbounds"][2]["type"], "vless");
    assert_eq!(serialized["inbounds"][2]["users"][0]["uuid"], VLESS_UUID);
    assert_eq!(serialized["inbounds"][2]["users"][1]["uuid"], uppercase);
    let roundtrip = parse_value(&serialized).unwrap();
    assert_eq!(serde_json::to_value(roundtrip).unwrap(), serialized);
}

#[test]
fn vless_flow_defaults_and_mixed_users_roundtrip() {
    let mut value = valid_vless_value();
    value["inbounds"][2]["users"] = json!([
        {"name": "legacy", "uuid": VLESS_UUID},
        {"name": "vision", "uuid": OTHER_VLESS_UUID, "flow": "xtls-rprx-vision"},
        {"name": "empty", "uuid": "00000000-0000-0000-0000-000000000000", "flow": ""}
    ]);
    let config = parse_value(&value).unwrap();
    let Inbound::Vless { users, .. } = &config.inbounds[2] else {
        panic!()
    };
    assert_eq!(VlessFlow::default(), VlessFlow::None);
    assert_eq!(
        users.iter().map(|user| user.flow).collect::<Vec<_>>(),
        [VlessFlow::None, VlessFlow::Vision, VlessFlow::None]
    );
    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["inbounds"][2]["users"][0]["flow"], "");
    assert_eq!(
        serialized["inbounds"][2]["users"][1]["flow"],
        "xtls-rprx-vision"
    );
    assert_eq!(serialized["inbounds"][2]["users"][2]["flow"], "");
    assert_eq!(
        serde_json::to_value(parse_value(&serialized).unwrap()).unwrap(),
        serialized
    );
    for rendered in [format!("{config:?}"), format!("{config:#?}")] {
        for user in users {
            assert!(!rendered.contains(&user.uuid));
        }
        assert!(rendered.contains("[REDACTED]"));
    }
}

#[test]
fn vless_flow_rejects_null_non_strings_unknown_and_duplicate_values_safely() {
    for flow in [
        json!(null),
        json!(true),
        json!(false),
        json!(0),
        json!(1.5),
        json!([]),
        json!(["xtls-rprx-vision"]),
        json!({"xtls-rprx-vision": null}),
        json!({"": null}),
        json!("flow-secret-918"),
        json!("xtls-rprx-vision-udp443"),
        json!("xtls-rprx-direct"),
        json!("xtls-rprx-origin"),
        json!("XTLS-RPRX-VISION"),
        json!("xtls-rprx-vision "),
        json!(" xtls-rprx-vision"),
        json!("xtls-rprx-vision\0"),
    ] {
        let mut value = valid_vless_value();
        value["inbounds"][2]["users"][0]["flow"] = flow.clone();
        let error = parse_value(&value).unwrap_err();
        assert_eq!(error.chain().count(), 1);
        for rendered in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            assert!(!rendered.contains("flow-secret-918"));
            assert!(!rendered.contains("xtls-rprx-"));
            assert!(!rendered.contains(VLESS_UUID));
            assert!(!rendered.contains("test-secret-password"));
        }
        assert!(serde_json::from_value::<VlessFlow>(flow).is_err());
    }
    let mut value = valid_vless_value();
    value["inbounds"][2]["users"][0]["flow"] = json!("");
    let duplicate = value.to_string().replace(
        "\"flow\":\"\"",
        "\"flow\":\"\",\"flow\":\"flow-secret-918\"",
    );
    let error = Config::from_json(&duplicate).unwrap_err();
    let rendered = format!("{error:?}");
    assert!(rendered.contains("字段重复"));
    assert!(!rendered.contains("flow-secret-918"));
    assert!(!rendered.contains(VLESS_UUID));
}

#[test]
fn vless_mixed_flow_users_keep_name_and_uuid_uniqueness() {
    for flow in ["", "xtls-rprx-vision"] {
        for (name, uuid, reason) in [
            ("alice", OTHER_VLESS_UUID.to_owned(), "用户名重复"),
            ("other", VLESS_UUID.to_uppercase(), "UUID 重复"),
        ] {
            let mut value = valid_vless_value();
            value["inbounds"][2]["users"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "name": name, "uuid": uuid, "flow": flow
                }));
            let error = parse_value(&value).unwrap_err();
            let rendered = format!("{error:?}");
            assert!(rendered.contains(reason));
            assert!(!rendered.contains(&uuid));
            assert!(!rendered.contains(VLESS_UUID));
        }
    }
}

#[test]
fn vless_invalid_credentials_and_paths_never_echo_input() {
    for (pointer, replacement) in [
        ("/inbounds/2/users", json!([])),
        ("/inbounds/2/users", json!(null)),
        ("/inbounds/2/users/0/name", json!("")),
        ("/inbounds/2/users/0/uuid", json!("")),
        ("/inbounds/2/users/0/uuid", json!("sensitive-uuid")),
        ("/inbounds/2/users/0/uuid", json!([VLESS_UUID])),
        (
            "/inbounds/2/users/0/uuid",
            json!({VLESS_UUID: "sensitive-uuid"}),
        ),
        ("/inbounds/2/users/0/uuid", json!(null)),
        ("/inbounds/2/certificate", json!("")),
        ("/inbounds/2/private_key", json!("")),
    ] {
        let mut value = valid_vless_value();
        set(&mut value, pointer, replacement);
        let error = parse_value(&value).unwrap_err();
        for rendered in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            assert!(!rendered.contains(VLESS_UUID), "{pointer}");
            assert!(!rendered.contains("sensitive-uuid"), "{pointer}");
            assert!(!rendered.contains("test-secret-password"), "{pointer}");
        }
    }
    let mut config = parse_value(&valid_vless_value()).unwrap();
    let Inbound::Vless { users, .. } = &mut config.inbounds[2] else {
        panic!()
    };
    users[0].uuid = "direct-validation-secret".into();
    let error = config.validate().unwrap_err();
    assert!(!format!("{error:?}").contains("direct-validation-secret"));
}

#[test]
fn vless_rejects_duplicate_names_and_uuid_bytes() {
    for (name, uuid, reason) in [
        ("alice", OTHER_VLESS_UUID.to_owned(), "用户名重复"),
        ("bob", VLESS_UUID.to_owned(), "UUID 重复"),
        ("bob", VLESS_UUID.to_uppercase(), "UUID 重复"),
    ] {
        let mut value = valid_vless_value();
        value["inbounds"][2]["users"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "name": name, "uuid": uuid
            }));
        let error = parse_value(&value).unwrap_err();
        let rendered = format!("{error:?}");
        assert!(rendered.contains(reason));
        assert!(!rendered.contains(&uuid));
        assert!(!rendered.contains(VLESS_UUID));
    }
}

#[test]
fn vless_xudp_defaults_true_and_requires_boolean() {
    let mut value = valid_vless_value();
    let config = parse_value(&value).unwrap();
    assert!(matches!(
        config.inbounds[2],
        Inbound::Vless { xudp: true, .. }
    ));
    value["inbounds"][2]["xudp"] = json!(false);
    assert!(matches!(
        parse_value(&value).unwrap().inbounds[2],
        Inbound::Vless { xudp: false, .. }
    ));
    for invalid in [json!(null), json!("true"), json!(1)] {
        value["inbounds"][2]["xudp"] = invalid;
        assert!(parse_value(&value).is_err());
    }
}

#[test]
fn vless_requires_fields_and_rejects_unknown_extensions() {
    for (pointer, fields) in [
        ("/inbounds/2", &["tag", "listen", "users"][..]),
        ("/inbounds/2/users/0", &["name", "uuid"][..]),
    ] {
        for field in fields {
            let mut value = valid_vless_value();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(*field);
            let error = parse_value(&value).unwrap_err().to_string();
            assert!(error.contains("缺少必填字段"), "{pointer}/{field}: {error}");
            let mut value = valid_vless_value();
            value.pointer_mut(pointer).unwrap()[*field] = Value::Null;
            assert!(parse_value(&value).is_err(), "{pointer}/{field}");
        }
    }
    // 省略证书/私钥即明文 VLESS；只给一半必须拒绝。
    let mut value = valid_vless_value();
    let inbound = value["inbounds"][2].as_object_mut().unwrap();
    inbound.remove("certificate");
    inbound.remove("private_key");
    assert!(matches!(
        parse_value(&value).unwrap().inbounds[2],
        Inbound::Vless {
            certificate: None,
            private_key: None,
            ..
        }
    ));
    let mut partial = valid_vless_value();
    partial["inbounds"][2]
        .as_object_mut()
        .unwrap()
        .remove("private_key");
    assert!(
        parse_value(&partial)
            .unwrap_err()
            .to_string()
            .contains("必须成对配置")
    );
    // flow 只属于用户；入口级 flow 仍是未知字段。
    let mut value = valid_vless_value();
    value["inbounds"][2]["flow"] = json!("xtls-rprx-vision");
    assert!(
        parse_value(&value)
            .unwrap_err()
            .to_string()
            .contains("未知字段")
    );
    for pointer in ["/inbounds/2", "/inbounds/2/users/0"] {
        for field in [
            "security",
            "transport",
            "mux",
            "multiplex",
            "reality",
            "vision",
            "encryption",
            "packet_encoding",
            "websocket",
            "grpc",
            "password",
            "allow_insecure",
        ] {
            let mut value = valid_vless_value();
            value.pointer_mut(pointer).unwrap()[field] = json!(VLESS_UUID);
            let error = parse_value(&value).unwrap_err();
            let rendered = format!("{error:?}");
            assert!(
                rendered.contains("未知字段"),
                "{pointer}/{field}: {rendered}"
            );
            assert!(!rendered.contains(VLESS_UUID));
        }
    }
}

#[test]
fn listen_conflicts_are_left_to_resource_preparation() {
    let mut value = valid_value();
    value["inbounds"][1]["listen"] = value["inbounds"][0]["listen"].clone();
    parse_value(&value).unwrap();
}

fn grpc_inbound(kind: &str, tls: bool) -> Value {
    let mut inbound = json!({
        "type": kind,
        "tag": "grpc",
        "listen": "127.0.0.1:0",
        "grpc": {"path": "/GunService/Tun", "multi_path": "/GunService/TunMulti"}
    });
    match kind {
        "vless-grpc" => {
            inbound["users"] = json!([{"name": "alice", "uuid": VLESS_UUID}]);
        }
        "vmess-grpc" => {
            inbound["users"] = json!([{"name": "alice", "uuid": VLESS_UUID}]);
        }
        "trojan-grpc" => {
            inbound["users"] = json!([{"name": "alice", "password": "test-secret-password"}]);
        }
        _ => unreachable!(),
    }
    if tls {
        inbound["certificate"] = json!("test-cert.pem");
        inbound["private_key"] = json!("test-key.pem");
    } else {
        inbound["allow_insecure_transport"] = json!(true);
    }
    inbound
}

#[test]
fn grpc_inbounds_parse_paths_and_redact_them_from_debug() {
    for kind in ["vless-grpc", "vmess-grpc", "trojan-grpc"] {
        let mut value = valid_value();
        value["inbounds"] = json!([grpc_inbound(kind, true)]);
        let config = parse_value(&value).unwrap();
        let (Inbound::VlessGrpc { grpc, .. }
        | Inbound::VmessGrpc { grpc, .. }
        | Inbound::TrojanGrpc { grpc, .. }) = &config.inbounds[0]
        else {
            panic!("入口类型错误")
        };
        assert_eq!(grpc.path, "/GunService/Tun");
        assert_eq!(grpc.mode("/GunService/Tun"), Some(false));
        assert_eq!(grpc.mode("/GunService/TunMulti"), Some(true));
        assert_eq!(grpc.mode("/GunService/Tun/"), None);
        let rendered = format!("{:?}", config.inbounds[0]);
        assert!(!rendered.contains("GunService"), "Debug泄露RPC路径");
        let serialized = serde_json::to_value(&config).unwrap();
        assert_eq!(serialized["inbounds"][0]["grpc"]["path"], "/GunService/Tun");
    }
}

#[test]
fn grpc_inbounds_require_consistent_tls_and_valid_paths() {
    for kind in ["vless-grpc", "trojan-grpc"] {
        let mut value = valid_value();
        let mut inbound = grpc_inbound(kind, false);
        inbound
            .as_object_mut()
            .unwrap()
            .remove("allow_insecure_transport");
        value["inbounds"] = json!([inbound]);
        assert!(parse_value(&value).is_err(), "{kind} 缺省明文必须拒绝");
    }

    let mut value = valid_value();
    let mut inbound = grpc_inbound("vmess-grpc", true);
    inbound.as_object_mut().unwrap().remove("certificate");
    value["inbounds"] = json!([inbound]);
    assert!(parse_value(&value).is_err(), "VMess gRPC必须要求TLS");

    for (field, replacement) in [
        ("path", json!("GunService/Tun")),
        ("path", json!("")),
        ("multi_path", json!("/GunService/Tun")),
        ("path", json!(format!("/{}", "a".repeat(1024)))),
        ("path", json!("/bad path")),
    ] {
        let mut value = valid_value();
        let mut inbound = grpc_inbound("vless-grpc", false);
        inbound["grpc"][field] = replacement;
        value["inbounds"] = json!([inbound]);
        assert!(parse_value(&value).is_err(), "{field}应被拒绝");
    }

    let mut value = valid_value();
    let mut inbound = grpc_inbound("vless-grpc", false);
    inbound["grpc"]["service_name"] = json!("GunService");
    value["inbounds"] = json!([inbound]);
    assert!(parse_value(&value).is_err(), "grpc未知字段必须拒绝");
}

#[test]
fn grpc_stream_limits_have_defaults_and_bounds() {
    let config = parse_value(&valid_value()).unwrap();
    assert_eq!(config.limits.max_grpc_streams, 256);
    assert_eq!(config.limits.max_grpc_streams_per_connection, 16);

    for (field, value) in [
        ("max_grpc_streams", 0usize),
        ("max_grpc_streams_per_connection", 0),
        ("max_grpc_streams_per_connection", 129),
    ] {
        let mut config = parse_value(&valid_value()).unwrap();
        match field {
            "max_grpc_streams" => config.limits.max_grpc_streams = value,
            _ => config.limits.max_grpc_streams_per_connection = value,
        }
        assert!(config.validate().is_err(), "{field}={value}应被拒绝");
    }

    let mut config = parse_value(&valid_value()).unwrap();
    config.limits.max_grpc_streams = 8;
    config.limits.max_grpc_streams_per_connection = 16;
    assert!(config.validate().is_err(), "每连接上限不得超过全局上限");
}

#[test]
fn nw3_egress_defaults_and_validation() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    let mut value = valid_value();
    value["nw3_egress"] = json!({
        "tag": "exit",
        "endpoint": "portal.example.com:443",
        "key": KEY
    });
    let config = parse_value(&value).unwrap();
    let egress = config.nw3_egress.as_ref().unwrap();
    assert_eq!(egress.tag, "exit");
    assert!(egress.morph);
    assert!(egress.sni.is_none() && egress.rate.is_none());

    for broken in [
        json!({"tag": "exit", "endpoint": "portal.example.com:443", "key": "0123"}),
        json!({"tag": "exit", "endpoint": "host:443?x=1", "key": KEY}),
        json!({"tag": "exit", "endpoint": "", "key": KEY}),
        json!({
            "tag": "exit", "endpoint": "host:443", "key": KEY,
            "dial": "auto", "dial6": "auto"
        }),
        json!({"tag": "exit", "endpoint": "host:443", "key": KEY, "morph": "yes"}),
        json!({
            "tag": "exit", "endpoint": "host:443", "key": KEY, "unknown": true
        }),
    ] {
        let mut bad = value.clone();
        bad["nw3_egress"] = broken;
        assert!(parse_value(&bad).is_err(), "{bad} 应被拒绝");
    }

    let text = serde_json::to_string(&parse_value(&valid_value()).unwrap()).unwrap();
    assert!(!text.contains("nw3_egress"), "未配置时不得序列化该字段");
}

#[test]
fn nw3_portal_out_defaults_to_direct() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    let mut value = valid_value();
    value["inbounds"] = json!([{
        "type": "nw3",
        "tag": "nw3-in",
        "listen": "127.0.0.1:2000",
        "key": KEY
    }]);
    let config = parse_value(&value).unwrap();
    config.validate().unwrap();
    let Inbound::Nw3 { out, .. } = &config.inbounds[0] else {
        panic!("应解析为 NW3 入站");
    };
    assert_eq!(out, &Nw3Out::Direct);

    for (raw, expected) in [("direct", Nw3Out::Direct), ("egress", Nw3Out::Egress)] {
        let mut value = value.clone();
        value["inbounds"][0]["out"] = json!(raw);
        let config = parse_value(&value).unwrap();
        config.validate().unwrap();
        let Inbound::Nw3 { out, .. } = &config.inbounds[0] else {
            panic!("应解析为 NW3 入站");
        };
        assert_eq!(out, &expected);
    }

    let mut socks = value.clone();
    socks["inbounds"][0]["out"] = json!("alice:s3cret@127.0.0.1:1080");
    socks["inbounds"][0]["dial4"] = json!("192.0.2.1");
    let config = parse_value(&socks).unwrap();
    config.validate().unwrap();
    let Inbound::Nw3 { out, dial4, .. } = &config.inbounds[0] else {
        panic!("应解析为 NW3 入站");
    };
    assert_eq!(out, &Nw3Out::Socks("alice:s3cret@127.0.0.1:1080".into()));
    assert_eq!(dial4.as_deref(), Some("192.0.2.1"));

    for invalid in [
        "socks5",
        "alice@127.0.0.1:1080",
        "alice:s3cret@127.0.0.1",
        "alice:s3cret@127.0.0.1:0",
        "alice:s3cret@127.0.0.1:70000",
        "a:b@[not-v6]:1080",
        "a:b@127.0.0.1:1080?x=1",
    ] {
        let mut bad = value.clone();
        bad["inbounds"][0]["out"] = json!(invalid);
        assert!(parse_value(&bad).is_err(), "{invalid} 应被拒绝");
    }

    let mut conflict = value.clone();
    conflict["inbounds"][0]["out"] = json!("egress");
    conflict["inbounds"][0]["dial"] = json!("auto");
    // `Config::from_json` 会立即校验，因此冲突组合应在解析阶段失败。
    let error = parse_value(&conflict).expect_err("out=egress 与 dial 互斥");
    assert!(format!("{error:#}").contains("互斥"), "{error:#}");
}

#[test]
fn proxy_outbounds_validate_and_redact_credentials() {
    let mut value = valid_value();
    value["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "socks5",
        "tag": "upstream",
        "endpoint": "[::1]:1080",
        "username": "alice",
        "password": "s3cret",
        "tls": {"ca_file": "/tmp/ca.pem", "server_name": "proxy.example"}
    }));
    value["route"]["rules"] = json!([{"outbound": "upstream", "networks": ["tcp"]}]);
    let config = parse_value(&value).unwrap();
    config.validate().unwrap();
    let outbound = config
        .outbounds
        .iter()
        .find(|outbound| outbound.tag == "upstream")
        .unwrap();
    assert_eq!(outbound.kind, OutboundKind::Socks5);
    assert_eq!(outbound.endpoint.as_deref(), Some("[::1]:1080"));
    assert!(outbound.tls.is_some(), "TLS 参数应被保留");
    let debug = format!("{outbound:?}");
    assert!(
        debug.contains("alice") && !debug.contains("s3cret"),
        "{debug}"
    );

    for (mutate, expected) in [
        (json!({"type": "socks5", "tag": "upstream"}), "endpoint"),
        (
            json!({"type": "http", "tag": "upstream", "endpoint": "::1:1080"}),
            "endpoint",
        ),
        (
            json!({
                "type": "socks5", "tag": "upstream",
                "endpoint": "127.0.0.1:1080", "username": "a"
            }),
            "username",
        ),
        (
            json!({"type": "direct", "tag": "upstream", "endpoint": "127.0.0.1:1080"}),
            "仅适用于",
        ),
        (
            json!({"type": "socks5", "tag": "upstream", "endpoint": "127.0.0.1:1080", "tls": {}}),
            "缺少必填字段",
        ),
        (
            json!({
                "type": "socks5", "tag": "upstream", "endpoint": "127.0.0.1:1080",
                "tls": {"ca_file": ""}
            }),
            "ca_file",
        ),
        (
            json!({
                "type": "socks5", "tag": "upstream", "endpoint": "127.0.0.1:1080",
                "tls": {"ca_file": "/etc/ssl/cert.pem", "server_name": "bad name"}
            }),
            "server_name",
        ),
        (
            json!({
                "type": "direct", "tag": "upstream",
                "tls": {"ca_file": "/etc/ssl/cert.pem"}
            }),
            "仅适用于",
        ),
    ] {
        let mut bad = value.clone();
        bad["outbounds"][2] = mutate;
        let error = parse_value(&bad)
            .and_then(|config| config.validate().map(|()| config))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "错误信息应提到 {expected}: {error:#}"
        );
    }
}

#[test]
fn shadowtls_outbound_is_via_only_and_matches_detour_endpoint() {
    const CA: &str = "/etc/ssl/cert.pem";
    let shadowtls = |endpoint: &str| {
        json!({
            "type": "shadowtls",
            "tag": "st",
            "endpoint": endpoint,
            "password": "secret",
            "tls": {"ca_file": CA, "server_name": "st.example"}
        })
    };

    // 最小合法配置：无 via、未参与路由。
    let mut value = valid_value();
    value["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(shadowtls("st.example:8443"));
    parse_value(&value).expect("最小 shadowtls 出站应通过校验");

    // 合法的 via detour：两端 endpoint 域名大小写按 Target 语义归一化。
    let mut value = valid_value();
    value["outbounds"].as_array_mut().unwrap().extend([
        shadowtls("ST.Example:8443"),
        json!({
            "type": "socks5", "tag": "inner",
            "endpoint": "st.example:8443", "via": "st"
        }),
    ]);
    value["route"]["default"] = json!("inner");
    parse_value(&value).expect("shadowtls 作为 via detour 应通过校验");

    // password 上限为 4096 字节，不受其他代理出站 255 字节限制。
    for (length, valid) in [(4096, true), (4097, false)] {
        let mut value = valid_value();
        let mut outbound = shadowtls("st.example:8443");
        outbound["password"] = json!("a".repeat(length));
        value["outbounds"].as_array_mut().unwrap().push(outbound);
        assert_eq!(parse_value(&value).is_ok(), valid, "password {length}");
    }

    // 缺失/非法字段与不允许的附加字段。
    for (mutate, expected) in [
        (
            json!({
                "type": "shadowtls", "tag": "st", "endpoint": "st.example:8443",
                "tls": {"ca_file": CA, "server_name": "st.example"}
            }),
            "password",
        ),
        (
            json!({
                "type": "shadowtls", "tag": "st", "endpoint": "st.example:8443",
                "password": "secret"
            }),
            "tls",
        ),
        (
            json!({
                "type": "shadowtls", "tag": "st", "endpoint": "st.example:8443",
                "password": "secret", "tls": {"ca_file": CA}
            }),
            "server_name",
        ),
        (
            json!({
                "type": "shadowtls", "tag": "st", "endpoint": "st.example:8443",
                "password": "secret",
                "tls": {"ca_file": CA, "server_name": "192.0.2.1"}
            }),
            "server_name",
        ),
        (
            json!({
                "type": "shadowtls", "tag": "st", "endpoint": "st.example:8443",
                "password": "secret",
                "tls": {"ca_file": CA, "server_name": "[::1]"}
            }),
            "server_name",
        ),
        (
            json!({
                "type": "shadowtls", "tag": "st", "endpoint": "st.example:8443",
                "password": "secret", "username": "u",
                "tls": {"ca_file": CA, "server_name": "st.example"}
            }),
            "username",
        ),
        (
            json!({
                "type": "shadowtls", "tag": "st", "endpoint": "st.example:8443",
                "password": "secret", "via": "direct",
                "tls": {"ca_file": CA, "server_name": "st.example"}
            }),
            "via",
        ),
        (
            json!({
                "type": "shadowtls", "tag": "st", "endpoint": "st.example:8443",
                "password": "secret", "version": 3,
                "tls": {"ca_file": CA, "server_name": "st.example"}
            }),
            "未知字段",
        ),
    ] {
        let mut bad = valid_value();
        bad["outbounds"].as_array_mut().unwrap().push(mutate);
        let error = parse_value(&bad).unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "错误信息应提到 {expected}: {error:#}"
        );
    }

    // via 两端 endpoint 不一致。
    let mut bad = valid_value();
    bad["outbounds"].as_array_mut().unwrap().extend([
        shadowtls("st.example:8443"),
        json!({
            "type": "socks5", "tag": "inner",
            "endpoint": "other.example:8443", "via": "st"
        }),
    ]);
    let error = parse_value(&bad).unwrap_err();
    assert!(format!("{error:#}").contains("相同 endpoint"), "{error:#}");

    // 不能作为终端路由目标或组员。
    for (mutate, expected) in [
        (json!({"route": {"default": "st"}}), "route.default"),
        (
            json!({"route": {"default": "direct", "rules": [{"outbound": "st"}]}}),
            "route.rules",
        ),
        (
            json!({
                "route": {"default": "direct"},
                "group": {"type": "selector", "tag": "group",
                          "outbounds": ["st"], "default": "st"}
            }),
            "selector",
        ),
        (
            json!({
                "route": {"default": "direct"},
                "group": {"type": "urltest", "tag": "group",
                          "outbounds": ["st"], "probe": "example.com:443"}
            }),
            "urltest",
        ),
    ] {
        let mut value = valid_value();
        value["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(shadowtls("st.example:8443"));
        if let Some(route) = mutate.get("route") {
            value["route"] = route.clone();
        }
        if let Some(group) = mutate.get("group").cloned() {
            value["outbounds"].as_array_mut().unwrap().push(group);
        }
        let error = parse_value(&value).unwrap_err();
        // 组用例的错误来自成员检查，仍应明确拒绝 shadowtls。
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(expected)
                || matches!(expected, "selector" | "urltest") && rendered.contains("shadowtls"),
            "错误信息应提到 {expected}: {rendered}"
        );
    }
}

#[test]
fn protocol_outbounds_require_their_own_credentials() {
    let validate = |outbound: serde_json::Value| {
        let mut value = valid_value();
        value["outbounds"].as_array_mut().unwrap().push(outbound);
        parse_value(&value).and_then(|config| config.validate().map(|()| config))
    };
    for good in [
        json!({
            "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "tls": {"ca_file": "/etc/ssl/cert.pem"}
        }),
        json!({
            "type": "trojan", "tag": "up", "endpoint": "127.0.0.1:443",
            "password": "secret",
            "tls": {"ca_file": "/etc/ssl/cert.pem"}
        }),
        json!({
            "type": "shadowsocks", "tag": "up", "endpoint": "127.0.0.1:8388",
            "method": "chacha20-ietf-poly1305", "password": "secret"
        }),
        json!({
            "type": "vmess", "tag": "up", "endpoint": "127.0.0.1:443",
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "security": 4,
            "tls": {"ca_file": "/etc/ssl/cert.pem"}
        }),
        json!({
            "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "transport": {"type": "ws", "path": "/proxy", "host": "cdn.example"}
        }),
        json!({
            "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "transport": {"type": "grpc", "path": "/GunService/Tun", "multi": true}
        }),
    ] {
        validate(good).expect("合法的协议出站应通过校验");
    }
    for (bad, expected) in [
        (
            json!({"type": "vless", "tag": "up", "endpoint": "127.0.0.1:443"}),
            "uuid",
        ),
        (
            json!({
                "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "x"
            }),
            "uuid",
        ),
        (
            json!({
                "type": "trojan", "tag": "up", "endpoint": "127.0.0.1:443",
                "password": "secret"
            }),
            "tls",
        ),
        (
            json!({
                "type": "trojan", "tag": "up", "endpoint": "127.0.0.1:443",
                "username": "u", "password": "secret",
                "tls": {"ca_file": "/etc/ssl/cert.pem"}
            }),
            "password",
        ),
        (
            json!({
                "type": "shadowsocks", "tag": "up", "endpoint": "127.0.0.1:8388",
                "method": "chacha20-ietf-poly1305", "password": "secret",
                "tls": {"ca_file": "/etc/ssl/cert.pem"}
            }),
            "tls",
        ),
        (
            json!({
                "type": "shadowsocks", "tag": "up", "endpoint": "127.0.0.1:8388",
                "password": "secret"
            }),
            "method",
        ),
        (
            json!({
                "type": "socks5", "tag": "up", "endpoint": "127.0.0.1:1080",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"
            }),
            "仅适用于 vless/vmess",
        ),
        (
            json!({"type": "vmess", "tag": "up", "endpoint": "127.0.0.1:443"}),
            "uuid",
        ),
        (
            json!({
                "type": "vmess", "tag": "up", "endpoint": "127.0.0.1:443",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": 5
            }),
            "security 只支持 3 或 4",
        ),
        (
            json!({
                "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": 3
            }),
            "仅适用于 vmess",
        ),
        (
            json!({
                "type": "socks5", "tag": "up", "endpoint": "127.0.0.1:1080",
                "transport": {"type": "ws", "path": "/proxy"}
            }),
            "transport 仅适用于",
        ),
        (
            json!({
                "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "transport": {"type": "ws", "path": "proxy"}
            }),
            "transport.path",
        ),
        (
            json!({
                "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "transport": {"type": "grpc"}
            }),
            "grpc 需要 path",
        ),
        (
            json!({
                "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "transport": {"type": "grpc", "path": "/x", "host": "h"}
            }),
            "不允许 host",
        ),
        (
            json!({
                "type": "vless", "tag": "up", "endpoint": "127.0.0.1:443",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "transport": {"type": "ws", "path": "/x", "multi": true}
            }),
            "仅适用于 grpc",
        ),
    ] {
        let error = validate(bad).unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "错误信息应提到 {expected}: {error:#}"
        );
    }
}

#[test]
fn snell_v6_accepts_default_shaped_and_rejects_unknown_modes() {
    let snell = |version: u8, psk: &str, mode: Option<&str>| {
        let mut value = valid_value();
        let mut inbound = json!({
            "type": "snell",
            "tag": "snell",
            "listen": "127.0.0.1:8443",
            "psk": psk,
            "version": version,
            "users": [{"name": "u", "userkey": "user-key"}]
        });
        if let Some(mode) = mode {
            inbound["mode"] = json!(mode);
        }
        value["inbounds"] = json!([inbound]);
        parse_value(&value).and_then(|config| config.validate().map(|()| config))
    };
    let psk = "0123456789abcdef";
    snell(6, psk, Some("unshaped")).unwrap();
    snell(6, psk, Some("unsafe-raw")).unwrap();
    snell(6, psk, None).unwrap();
    snell(6, psk, Some("default")).unwrap();
    snell(6, psk, Some("unknown")).unwrap_err();
    snell(4, psk, None).unwrap();
    snell(6, "short", Some("unshaped")).unwrap_err();
    snell(5, psk, Some("unshaped")).unwrap_err();
}

#[test]
fn reverse_outbound_requires_a_domain_and_cannot_join_groups() {
    let mut value = valid_value();
    value["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "reverse", "tag": "portal", "domain": "v1.rvs.cool"
    }));
    let config = parse_value(&value).unwrap();
    config.validate().unwrap();

    let mut missing = value.clone();
    missing["outbounds"][2] = json!({"type": "reverse", "tag": "portal"});
    assert!(
        parse_value(&missing)
            .and_then(|config| config.validate())
            .is_err()
    );

    let mut member = value.clone();
    member["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "selector", "tag": "group", "outbounds": ["portal"]
    }));
    assert!(
        parse_value(&member)
            .and_then(|config| config.validate())
            .is_err()
    );
}

#[test]
fn vless_outbound_encryption_is_validated() {
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]);
    let mut value = valid_value();
    value["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "vless",
        "tag": "vless-enc",
        "endpoint": "127.0.0.1:443",
        "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "encryption": format!("mlkem768x25519plus.native.1rtt.{key}")
    }));
    parse_value(&value)
        .and_then(|config| config.validate())
        .unwrap();

    let mut bad_time = value.clone();
    bad_time["outbounds"][2]["encryption"] = json!(format!("mlkem768x25519plus.native.600s.{key}"));
    assert!(
        parse_value(&bad_time)
            .and_then(|config| config.validate())
            .is_err()
    );

    let mut misplaced = value.clone();
    misplaced["outbounds"][2]["type"] = json!("direct");
    misplaced["outbounds"][2]
        .as_object_mut()
        .unwrap()
        .remove("endpoint");
    misplaced["outbounds"][2]
        .as_object_mut()
        .unwrap()
        .remove("uuid");
    assert!(
        parse_value(&misplaced)
            .and_then(|config| config.validate())
            .is_err()
    );
}

#[test]
fn wireguard_outbound_validates_keys_and_configuration() {
    let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let mut value = valid_value();
    value["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "wireguard",
        "tag": "wg",
        "endpoint": "127.0.0.1:51820",
        "wireguard": {
            "private_key": key,
            "peer_public_key": key,
            "address": ["10.66.0.2/32"],
            "mtu": 1420,
            "keepalive_secs": 25
        }
    }));
    parse_value(&value)
        .and_then(|config| config.validate())
        .unwrap();

    let mut grouped = value.clone();
    grouped["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "selector", "tag": "group", "outbounds": ["wg"], "default": "wg"
    }));
    parse_value(&grouped)
        .and_then(|config| config.validate())
        .unwrap();

    let mut missing = value.clone();
    missing["outbounds"][2]
        .as_object_mut()
        .unwrap()
        .remove("wireguard");
    assert!(
        parse_value(&missing)
            .and_then(|config| config.validate())
            .is_err()
    );

    let mut bad_key = value.clone();
    bad_key["outbounds"][2]["wireguard"]["private_key"] = json!("short");
    assert!(
        parse_value(&bad_key)
            .and_then(|config| config.validate())
            .is_err()
    );

    let mut misplaced = value.clone();
    misplaced["outbounds"][2]["type"] = json!("direct");
    assert!(
        parse_value(&misplaced)
            .and_then(|config| config.validate())
            .is_err()
    );
}

#[test]
fn hysteria2_gecko_obfs_bounds_are_validated() {
    let mut value = valid_value();
    value["inbounds"] = json!([{
        "type": "hysteria2",
        "tag": "hy",
        "listen": "127.0.0.1:8443",
        "users": [{"name": "u", "password": "secret"}],
        "certificate": "/tmp/cert.pem",
        "private_key": "/tmp/key.pem",
        "obfs": {
            "type": "gecko",
            "password": "obfs",
            "min_packet_size": 512,
            "max_packet_size": 1200
        }
    }]);
    let config = parse_value(&value).unwrap();
    config.validate().unwrap();

    value["inbounds"][0]["obfs"] =
        json!({"type": "salamander", "password": "obfs", "min_packet_size": 512});
    let error = parse_value(&value)
        .and_then(|config| config.validate().map(|()| config))
        .unwrap_err();
    assert!(format!("{error:#}").contains("gecko"), "{error:#}");

    value["inbounds"][0]["obfs"] = json!({"type": "gecko", "password": "obfs", "min_packet_size": 1200, "max_packet_size": 512});
    let error = parse_value(&value)
        .and_then(|config| config.validate().map(|()| config))
        .unwrap_err();
    assert!(format!("{error:#}").contains("gecko"), "{error:#}");
}

#[test]
fn hysteria2_client_bandwidth_bounds_are_validated() {
    let mut value = valid_value();
    value["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "hysteria2",
        "tag": "hy2-out",
        "endpoint": "127.0.0.1:8443",
        "password": "secret",
        "tls": {"ca_file": "/tmp/ca.pem", "server_name": "localhost"},
        "hysteria2": {"up_mbps": 100, "down_mbps": 0}
    }));
    parse_value(&value)
        .and_then(|config| config.validate())
        .expect("合法 Hysteria2 客户端上行/下行带宽");

    let mut overflow = value.clone();
    overflow["outbounds"][2]["hysteria2"]["up_mbps"] = json!(u64::MAX);
    let error = parse_value(&overflow)
        .and_then(|config| config.validate())
        .unwrap_err();
    assert!(format!("{error:#}").contains("up_mbps"), "{error:#}");

    let mut misplaced = value.clone();
    misplaced["outbounds"][2]["hysteria2"]["down_mbps"] = json!(1);
    // 1 Mbps 合法；用未知字段确认客户端对象保持严格解析。
    misplaced["outbounds"][2]["hysteria2"]["unknown"] = json!(true);
    assert!(
        parse_value(&misplaced)
            .and_then(|config| config.validate())
            .is_err()
    );
}

#[test]
fn hysteria2_masquerade_shapes_are_validated() {
    let value_with = |masquerade: serde_json::Value| {
        let mut value = valid_value();
        value["inbounds"] = json!([{
            "type": "hysteria2",
            "tag": "hy",
            "listen": "127.0.0.1:8443",
            "users": [{"name": "u", "password": "secret"}],
            "certificate": "/tmp/cert.pem",
            "private_key": "/tmp/key.pem",
            "masquerade": masquerade
        }]);
        parse_value(&value).and_then(|config| config.validate().map(|()| config))
    };
    value_with(json!({"type": "string", "content": "hello"})).unwrap();
    value_with(json!({"type": "file", "directory": "/srv/www"})).unwrap();
    for bad in [
        json!({"type": "file"}),
        json!({"type": "string"}),
        json!({"type": "string", "content": "x", "directory": "/srv/www"}),
        json!({"type": "file", "directory": "/srv/www", "status_code": 200}),
        json!({"type": "string", "content": "x", "status_code": 42}),
    ] {
        assert!(value_with(bad).is_err(), "非法 masquerade 应被拒绝");
    }
}

#[test]
fn dns_config_and_domain_rule_fields_validate() {
    let mut value = valid_value();
    value["dns"] = json!({
        "servers": ["1.1.1.1", "[2606:4700:4700::1111]:53"],
        "hosts": {"Example.Test": ["192.0.2.1", "2001:db8::1"]}
    });
    value["route"]["rules"] = json!([{
        "outbound": "blocked",
        "domain_suffix": [".example.com"],
        "domain_keyword": ["tracker"]
    }]);
    let config = parse_value(&value).unwrap();
    config.validate().unwrap();
    assert_eq!(
        config
            .dns
            .as_ref()
            .unwrap()
            .server_endpoints()
            .unwrap()
            .len(),
        2
    );

    let plain = value["dns"].clone();
    value["dns"] = json!({
        "servers": ["tls://1.1.1.1", "https://[2606:4700:4700::1111]/dns-query"],
        "ca_file": "/etc/ssl/cert.pem",
        "server_name": "cloudflare-dns.com"
    });
    parse_value(&value).unwrap().validate().unwrap();
    value["dns"] = plain;

    for (dns, expected) in [
        (json!({"servers": ["not-an-ip"]}), "dns.servers"),
        (json!({"servers": ["tls://1.1.1.1"]}), "dns.ca_file"),
        (
            json!({"servers": ["1.1.1.1", "tls://1.0.0.1"],
                   "ca_file": "/etc/ssl/cert.pem"}),
            "不能混用",
        ),
        (
            json!({"servers": ["https://dns.example/dns-query"],
                   "ca_file": "/etc/ssl/cert.pem"}),
            "dns.servers",
        ),
        (
            json!({"servers": ["1.1.1.1"], "ca_file": "/etc/ssl/cert.pem"}),
            "仅适用于",
        ),
        (
            json!({"hosts": {"127.0.0.1": ["1.1.1.1"]}}),
            "dns.hosts 的键",
        ),
        (
            json!({"hosts": {"example.test": ["not-an-ip"]}}),
            "dns.hosts 的值",
        ),
    ] {
        let mut bad = value.clone();
        bad["dns"] = dns;
        let error = parse_value(&bad)
            .and_then(|config| config.validate().map(|()| config))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "错误信息应提到 {expected}: {error:#}"
        );
    }
    for (rules, expected) in [
        (
            json!([{"outbound": "blocked", "domain_suffix": [""]}]),
            "domain_suffix",
        ),
        (
            json!([{"outbound": "blocked", "domain_keyword": ["a b"]}]),
            "domain_keyword",
        ),
    ] {
        let mut bad = value.clone();
        bad["route"]["rules"] = rules;
        let error = parse_value(&bad)
            .and_then(|config| config.validate().map(|()| config))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "错误信息应提到 {expected}: {error:#}"
        );
    }
}

#[test]
fn hysteria2_gecko_packet_size_matches_upstream_constraints() {
    // 官方 `WrapPacketConnGecko` 只在 min<=0 || min>max || max>2048 时拒绝。
    // 此前本地限制 256..=1400，会把 max=1401..2048 的合法官方配置拒绝启动。
    let base = |min: u64, max: u64| {
        json!({
            "version": 1,
            "inbounds": [{
                "type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1:443",
                "users": [{"name": "a", "password": "pw"}],
                "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem",
                "obfs": {"type": "gecko", "password": "o",
                         "min_packet_size": min, "max_packet_size": max}
            }],
            "outbounds": [{"tag": "direct", "type": "direct"}],
            "route": {"default": "direct"}
        })
    };

    for (min, max) in [(1u64, 1u64), (128, 2048), (512, 2000), (1401, 2048)] {
        let text = base(min, max).to_string();
        Config::from_json(&text).expect("官方允许的取值不应被拒绝");
    }
    for (min, max) in [(0u64, 1200u64), (1200, 512), (512, 2049)] {
        let text = base(min, max).to_string();
        Config::from_json(&text).expect_err("越界取值必须拒绝");
    }
}
