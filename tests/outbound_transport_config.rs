//! 传输出站配置边界；纯配置校验，不访问网络或证书文件。

use dubhe::Config;
use serde_json::{Value, json};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn config(transport: Value) -> Value {
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [{
            "type": "vless", "tag": "up", "endpoint": "127.0.0.1:24443", "uuid": UUID,
            "tls": {"ca_file": "/not-read-during-validation.pem", "server_name": "localhost"},
            "transport": transport
        }],
        "route": {"default": "up"}
    })
}

fn validate(value: Value) -> bool {
    Config::from_json(&value.to_string())
        .and_then(|config| config.validate().map(|()| config))
        .is_ok()
}

#[test]
fn xhttp_accepts_each_version_and_mode_without_implicit_downgrades() {
    for version in ["1.1", "2", "3"] {
        for mode in ["auto", "stream-one", "stream-up", "packet-up"] {
            let value = config(json!({
                "type": "xhttp", "path": "/proxy", "host": "localhost",
                "http_version": version, "mode": mode,
                "headers": {"x-test": "value"},
                "x_padding": {"from": 100, "to": 200}, "max_post_bytes": 1024
            }));
            assert!(validate(value), "version={version} mode={mode}");
        }
    }
    let mut plain_h2 = config(json!({"type": "xhttp"}));
    plain_h2["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("tls");
    assert!(validate(plain_h2));
    let mut plain_h3 = config(json!({"type": "xhttp", "http_version": "3"}));
    plain_h3["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("tls");
    assert!(!validate(plain_h3));
}

#[test]
fn xhttp_rejects_request_injection_and_unbounded_options() {
    for transport in [
        json!({"type": "xhttp", "path": "not-absolute"}),
        json!({"type": "xhttp", "path": "/proxy?query"}),
        json!({"type": "xhttp", "host": "host\r\ninjected: value"}),
        json!({"type": "xhttp", "headers": {"Content-Length": "10"}}),
        json!({"type": "xhttp", "headers": {"x-test": "bad\r\nvalue"}}),
        json!({"type": "xhttp", "headers": {"X-Session": "other-session"}}),
        json!({"type": "xhttp", "x_padding": {"from": 100, "to": 99}}),
        json!({"type": "xhttp", "x_padding": {"from": 0, "to": 16385}}),
        json!({"type": "xhttp", "max_post_bytes": 63}),
        json!({"type": "xhttp", "max_post_bytes": 65537}),
        json!({"type": "xhttp", "http_version": "auto"}),
        json!({"type": "xhttp", "http_version": "2", "quic": {}}),
    ] {
        assert!(!validate(config(transport)));
    }
}

#[test]
fn transport_specific_parameters_cannot_be_silently_ignored() {
    for kind in ["ws", "grpc", "httpupgrade", "kcp", "quic"] {
        for (field, value) in [
            ("mode", json!("packet-up")),
            ("http_version", json!("2")),
            ("headers", json!({"x-test": "value"})),
            ("x_padding", json!({"from": 0, "to": 100})),
            ("max_post_bytes", json!(1024)),
        ] {
            let mut transport = json!({"type": kind});
            if kind == "grpc" {
                transport["path"] = json!("/GunService/Tun");
            }
            transport[field] = value;
            assert!(!validate(config(transport)), "kind={kind} field={field}");
        }
    }
    assert!(!validate(config(json!({"type": "ws", "kcp": {}}))));
    assert!(!validate(config(json!({"type": "kcp", "path": "/proxy"}))));
    assert!(!validate(config(
        json!({"type": "quic", "host": "localhost"})
    )));
}

#[test]
fn kcp_and_quic_reuse_existing_parameter_bounds() {
    for transport in [
        json!({"type": "kcp"}),
        json!({"type": "kcp", "kcp": {"security": "none"}}),
        json!({"type": "quic", "quic": {"max_bidi_streams": 2}}),
        json!({"type": "xhttp", "http_version": "3", "quic": {"max_bidi_streams": 2}}),
    ] {
        assert!(validate(config(transport)));
    }
    for transport in [
        json!({"type": "kcp", "kcp": {"mtu": 0}}),
        json!({"type": "kcp", "kcp": {"tti": 0}}),
        json!({"type": "quic", "quic": {"max_bidi_streams": 0}}),
        json!({"type": "quic", "quic": {"idle_timeout_ms": 0}}),
    ] {
        assert!(!validate(config(transport)));
    }
}

#[test]
fn non_proxy_kinds_reject_flow_and_tuic_parameters() {
    for kind in ["direct", "reject", "reverse", "selector", "urltest"] {
        for field in ["flow", "tuic"] {
            let mut value = config(json!({"type": "ws"}));
            value["outbounds"][0] = json!({"type": kind, "tag": "up"});
            value["outbounds"][0][field] = if field == "flow" {
                json!("")
            } else {
                json!({})
            };
            assert!(!validate(value), "kind={kind} field={field}");
        }
    }
}

#[test]
fn debug_does_not_print_header_secrets_or_kcp_seed() {
    let value =
        config(json!({"type": "xhttp", "headers": {"authorization": "private-header-token"}}));
    let parsed = Config::from_json(&value.to_string()).unwrap();
    parsed.validate().unwrap();
    let debug = format!("{:?}", parsed.outbounds[0]);
    assert!(!debug.contains("private-header-token"));
    let value = config(json!({"type": "kcp", "kcp": {"seed": "private-seed"}}));
    let parsed = Config::from_json(&value.to_string()).unwrap();
    parsed.validate().unwrap();
    assert!(!format!("{:?}", parsed.outbounds[0]).contains("private-seed"));
}
