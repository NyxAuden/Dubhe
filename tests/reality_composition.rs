//! REALITY 承载组合校验：与上游一致，仅允许 RAW、XHTTP、gRPC。
#[path = "common/reality.rs"]
mod peer;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

fn inbound(kind: &str) -> Value {
    let users = if kind.starts_with("trojan") {
        json!([{"name": "test", "password": "reality-composition"}])
    } else {
        json!([{"name": "test", "uuid": peer::UUID}])
    };
    let mut value = json!({
        "type": kind,
        "tag": "reality",
        "listen": "127.0.0.1:0",
        "users": users,
        "reality": {
            "target": {"host": "127.0.0.1", "port": 443},
            "private_key": URL_SAFE_NO_PAD.encode(peer::SERVER_PRIVATE_KEY),
            "server_names": ["localhost"],
            "short_ids": ["8172635445362718"]
        }
    });
    if kind.ends_with("-grpc") {
        value["grpc"] = json!({"path": "/Svc/Tun", "multi_path": "/Svc/TunMulti"});
    } else if kind.ends_with("-xhttp") {
        value["xhttp"] = json!({"path": "/x"});
    } else if kind.ends_with("-ws") {
        value["websocket"] = json!({"path": "/proxy"});
    } else if kind.ends_with("-httpupgrade") {
        value["httpupgrade"] = json!({"path": "/up"});
    }
    value
}

fn config(kind: &str) -> Value {
    json!({
        "version": 1,
        "inbounds": [inbound(kind)],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

fn parse(value: &Value) -> anyhow::Result<()> {
    dubhe::Config::from_json(&value.to_string())
        .and_then(|config| config.validate().map(|()| config))
        .map(|_| ())
}

#[test]
fn reality_accepts_only_raw_xhttp_and_grpc_transports() {
    parse(&config("vless-reality")).unwrap();
    parse(&config("vmess-reality")).unwrap();
    parse(&config("trojan-reality")).unwrap();
    for protocol in ["vless", "vmess", "trojan"] {
        for transport in ["grpc", "xhttp"] {
            let kind = format!("{protocol}-{transport}");
            parse(&config(&kind)).unwrap_or_else(|error| panic!("{kind}: {error}"));
        }
        for transport in ["ws", "httpupgrade"] {
            let kind = format!("{protocol}-{transport}");
            assert!(
                parse(&config(&kind)).is_err(),
                "{kind} 不属于上游 REALITY 支持的承载，必须拒绝"
            );
        }
    }

    let mut h3 = config("vless-xhttp");
    h3["inbounds"][0]["xhttp"] = json!({"path": "/x", "h3": true});
    assert!(parse(&h3).is_err(), "REALITY 不支持 XHTTP/3（QUIC）");
}

#[test]
fn reality_rejects_certificates_and_insecure_transport() {
    let base = config("vless-grpc");

    let mut with_cert = base.clone();
    with_cert["inbounds"][0]["certificate"] = json!("/tmp/not-used.pem");
    with_cert["inbounds"][0]["private_key"] = json!("/tmp/not-used.key");
    assert!(parse(&with_cert).is_err(), "REALITY 不得与证书共存");

    let mut insecure = base;
    insecure["inbounds"][0]["allow_insecure_transport"] = json!(true);
    assert!(
        parse(&insecure).is_err(),
        "REALITY 下不得 allow_insecure_transport"
    );

    // 新 RAW REALITY 类型不接受证书字段，避免 REALITY 与 TLS 双安全层并存。
    for kind in ["vmess-reality", "trojan-reality"] {
        let mut with_cert = config(kind);
        with_cert["inbounds"][0]["certificate"] = json!("/tmp/not-used.pem");
        with_cert["inbounds"][0]["private_key"] = json!("/tmp/not-used.key");
        assert!(parse(&with_cert).is_err(), "{kind} 不得与证书共存");
    }
}
