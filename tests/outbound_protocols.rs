//! 上游代理出站（VLESS / Trojan / Shadowsocks）回环互通测试。
//!
//! 每个用例启动两个内核实例：上游实例提供对应协议入站，下游实例把
//! SOCKS5 入站的流量交给该协议出站，验证真实握手、认证与 TCP 转发。

mod common;

use common::{Echo, Running};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "outbound-loopback-password";

fn socks_inbound() -> Value {
    json!([{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}])
}

fn downstream(outbound: Value) -> Value {
    json!({
        "version": 1,
        "inbounds": socks_inbound(),
        "outbounds": [outbound],
        "route": {"default": "up"}
    })
}

fn tls(cert: &common::Certificate) -> Value {
    json!({
        "ca_file": cert.dir.path().join("cert.pem").to_string_lossy(),
        "server_name": "localhost"
    })
}

/// 经下游 SOCKS5 入站连接到回环 echo，验证上行与下行字节。
async fn assert_relayed(upstream: Running, outbound: Value) {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(downstream(outbound)).await;
    let (mut tunnel, _bound) =
        common::socks(1, common::address(echo.address), server.address).await;
    tunnel.write_all(b"outbound-proto").await.unwrap();
    let mut echoed = [0u8; 14];
    tunnel.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"outbound-proto");
    drop(tunnel);
    server.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn vless_outbound_relays_over_tls() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "vless-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "tls": tls(&cert)
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vless_vision_outbound_relays_over_tls13() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "vless-vision-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "flow": "xtls-rprx-vision",
        "tls": tls(&cert)
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn trojan_outbound_relays_over_tls() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "trojan",
            "tag": "trojan-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "trojan",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "password": PASSWORD,
        "tls": tls(&cert)
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn shadowsocks_outbound_relays_over_aead() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "shadowsocks",
            "tag": "ss-up",
            "listen": "127.0.0.1:0",
            "method": "chacha20-ietf-poly1305",
            "password": PASSWORD
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "shadowsocks",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "method": "chacha20-ietf-poly1305",
        "password": PASSWORD
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn shadowsocks_2022_eih_outbound_relays_over_tcp() {
    const IPSK: &str = "EREREREREREREREREREREQ==";
    const UPSK: &str = "IiIiIiIiIiIiIiIiIiIiIg==";
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "shadowsocks",
            "tag": "ss-eih-up",
            "listen": "127.0.0.1:0",
            "method": "2022-blake3-aes-128-gcm",
            "password": IPSK,
            "users": [{"name": "u", "password": UPSK}]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "shadowsocks",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "method": "2022-blake3-aes-128-gcm",
        "password": format!("{IPSK}:{UPSK}")
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn chained_vless_via_trojan_reaches_the_target() {
    let first_cert = common::Certificate::new();
    let second_cert = common::Certificate::new();
    // 最后一跳：Trojan/TLS。
    let final_hop = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "trojan",
            "tag": "final",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": second_cert.dir.path().join("cert.pem"),
            "private_key": second_cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    // 第一跳：VLESS/TLS，经它连接到最后一跳。
    let entry = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "entry",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "certificate": first_cert.dir.path().join("cert.pem"),
            "private_key": first_cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "trojan",
        "tag": "up",
        "endpoint": final_hop.address.to_string(),
        "password": PASSWORD,
        "tls": tls(&second_cert),
        "via": "entry-hop"
    });
    let mut value = downstream(outbound);
    value["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "vless",
        "tag": "entry-hop",
        "endpoint": entry.address.to_string(),
        "uuid": UUID,
        "tls": tls(&first_cert)
    }));

    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(value).await;
    let (mut tunnel, _bound) =
        common::socks(1, common::address(echo.address), server.address).await;
    tunnel.write_all(b"chain-ok").await.unwrap();
    let mut echoed = [0u8; 8];
    tunnel.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"chain-ok");
    drop(tunnel);
    server.shutdown().await;
    final_hop.shutdown().await;
    entry.shutdown().await;
}

#[tokio::test]
async fn vmess_outbound_relays_over_tls() {
    for security in [3, 4] {
        let cert = common::Certificate::new();
        let upstream = Running::start(json!({
            "version": 1,
            "inbounds": [{
                "type": "vmess",
                "tag": "vmess-up",
                "listen": "127.0.0.1:0",
                "users": [{"name": "u", "uuid": UUID}],
                "certificate": cert.dir.path().join("cert.pem"),
                "private_key": cert.dir.path().join("key.pem")
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"default": "direct"}
        }))
        .await;
        let outbound = json!({
            "type": "vmess",
            "tag": "up",
            "endpoint": upstream.address.to_string(),
            "uuid": UUID,
            "security": security,
            "tls": tls(&cert)
        });
        assert_relayed(upstream, outbound).await;
    }
}

#[tokio::test]
async fn vless_outbound_relays_over_plain_websocket() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-ws",
            "tag": "vless-ws-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "allow_insecure_transport": true,
            "websocket": {"path": "/proxy"}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "transport": {"type": "ws", "path": "/proxy"}
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn trojan_outbound_relays_over_wss() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "trojan-ws",
            "tag": "trojan-ws-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "websocket": {"path": "/proxy"},
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "trojan",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "password": PASSWORD,
        "tls": tls(&cert),
        "transport": {"type": "ws", "path": "/proxy"}
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vmess_outbound_relays_over_plain_websocket() {
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vmess-ws",
            "tag": "vmess-ws-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "allow_insecure_body": true,
            "websocket": {"path": "/proxy"}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "vmess",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "transport": {"type": "ws", "path": "/proxy"}
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vless_outbound_relays_over_grpc_single_and_multi() {
    for multi in [false, true] {
        let upstream = Running::start(json!({
            "version": 1,
            "inbounds": [{
                "type": "vless-grpc",
                "tag": "grpc-up",
                "listen": "127.0.0.1:0",
                "users": [{"name": "u", "uuid": UUID}],
                "allow_insecure_transport": true,
                "grpc": {"path": "/GunService/Tun", "multi_path": "/GunService/TunMulti"}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"default": "direct"}
        }))
        .await;
        let outbound = json!({
            "type": "vless",
            "tag": "up",
            "endpoint": upstream.address.to_string(),
            "uuid": UUID,
            "transport": {
                "type": "grpc",
                "path": if multi { "/GunService/TunMulti" } else { "/GunService/Tun" },
                "multi": multi
            }
        });
        assert_relayed(upstream, outbound).await;
    }
}

#[tokio::test]
async fn vless_outbound_relays_over_grpc_tls() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-grpc",
            "tag": "grpc-tls-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "allow_insecure_transport": false,
            "grpc": {"path": "/GunService/Tun"},
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "tls": tls(&cert),
        "transport": {"type": "grpc", "path": "/GunService/Tun"}
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vless_outbound_encryption_relays_tcp() {
    use aws_lc_rs::agreement::{PrivateKey, X25519};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let cert = common::Certificate::new();
    let seed = [0x42u8; 32];
    let private = PrivateKey::from_private_key(&X25519, &seed).unwrap();
    let public = private.compute_public_key().unwrap();
    let private = URL_SAFE_NO_PAD.encode(seed);
    let public = URL_SAFE_NO_PAD.encode(public.as_ref());
    for mode in ["native", "xorpub", "random"] {
        let upstream = Running::start(json!({
            "version": 1,
            "inbounds": [{
                "type": "vless",
                "tag": "vless-enc-up",
                "listen": "127.0.0.1:0",
                "users": [{"name": "u", "uuid": UUID}],
                "decryption": format!("mlkem768x25519plus.{mode}.0.{private}"),
                "certificate": cert.dir.path().join("cert.pem"),
                "private_key": cert.dir.path().join("key.pem")
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"default": "direct"}
        }))
        .await;
        let outbound = json!({
            "type": "vless",
            "tag": "up",
            "endpoint": upstream.address.to_string(),
            "uuid": UUID,
            "tls": tls(&cert),
            "encryption": format!("mlkem768x25519plus.{mode}.1rtt.{public}")
        });
        assert_relayed(upstream, outbound).await;
    }
}

#[tokio::test]
async fn vless_encryption_composes_with_vision() {
    use aws_lc_rs::agreement::{PrivateKey, X25519};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let cert = common::Certificate::new();
    let seed = [0x44u8; 32];
    let private = PrivateKey::from_private_key(&X25519, &seed).unwrap();
    let public = private.compute_public_key().unwrap();
    let private = URL_SAFE_NO_PAD.encode(seed);
    let public = URL_SAFE_NO_PAD.encode(public.as_ref());
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "vless-enc-vision",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}],
            "decryption": format!("mlkem768x25519plus.native.0.{private}"),
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "flow": "xtls-rprx-vision",
        "tls": tls(&cert),
        "encryption": format!("mlkem768x25519plus.native.1rtt.{public}")
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vless_encryption_relays_plaintext_without_tls() {
    use aws_lc_rs::agreement::{PrivateKey, X25519};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let seed = [0x43u8; 32];
    let private = PrivateKey::from_private_key(&X25519, &seed).unwrap();
    let public = private.compute_public_key().unwrap();
    let private = URL_SAFE_NO_PAD.encode(seed);
    let public = URL_SAFE_NO_PAD.encode(public.as_ref());
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "vless-enc-plain",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "decryption": format!("mlkem768x25519plus.native.0.{private}")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "encryption": format!("mlkem768x25519plus.native.1rtt.{public}")
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn vless_encryption_composes_with_ws_and_grpc() {
    use aws_lc_rs::agreement::{PrivateKey, X25519};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let cert = common::Certificate::new();
    let seed = [0x51u8; 32];
    let private = PrivateKey::from_private_key(&X25519, &seed).unwrap();
    let public = private.compute_public_key().unwrap();
    let private = URL_SAFE_NO_PAD.encode(seed);
    let public = URL_SAFE_NO_PAD.encode(public.as_ref());
    for (kind, transport) in [
        ("vless-ws", json!({"type": "ws", "path": "/proxy"})),
        (
            "vless-grpc",
            json!({"type": "grpc", "path": "/Svc/Tun", "multi": false}),
        ),
    ] {
        let mut inbound = json!({
            "type": kind,
            "tag": "vless-enc-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "decryption": format!("mlkem768x25519plus.native.0.{private}"),
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        });
        if kind == "vless-ws" {
            inbound["websocket"] = json!({"path": "/proxy"});
        } else {
            inbound["grpc"] = json!({"path": "/Svc/Tun", "multi_path": "/Svc/TunMulti"});
        }
        let upstream = Running::start(json!({
            "version": 1,
            "inbounds": [inbound],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"default": "direct"}
        }))
        .await;
        let outbound = json!({
            "type": "vless",
            "tag": "up",
            "endpoint": upstream.address.to_string(),
            "uuid": UUID,
            "tls": tls(&cert),
            "transport": transport,
            "encryption": format!("mlkem768x25519plus.native.1rtt.{public}")
        });
        assert_relayed(upstream, outbound).await;
    }
}

#[tokio::test]
async fn vless_outbound_relays_over_httpupgrade() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-httpupgrade",
            "tag": "vless-hu-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "httpupgrade": {"path": "/upgrade"},
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "vless",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "tls": tls(&cert),
        "transport": {"type": "httpupgrade", "path": "/upgrade"}
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn anytls_outbound_relays_tcp() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "anytls",
            "tag": "anytls-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "anytls",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "password": PASSWORD,
        "tls": tls(&cert)
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn hysteria2_outbound_relays_tcp() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hy2-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "hysteria2",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "password": PASSWORD,
        "tls": tls(&cert),
        "hysteria2": {"up_mbps": 100, "down_mbps": 100}
    });
    assert_relayed(upstream, outbound).await;
}

#[tokio::test]
async fn tuic_outbound_relays_tcp() {
    let cert = common::Certificate::new();
    let upstream = Running::start(json!({
        "version": 1,
        "inbounds": [{
            "type": "tuic",
            "tag": "tuic-up",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID, "password": PASSWORD}],
            "certificate": cert.dir.path().join("cert.pem"),
            "private_key": cert.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    }))
    .await;
    let outbound = json!({
        "type": "tuic",
        "tag": "up",
        "endpoint": upstream.address.to_string(),
        "uuid": UUID,
        "password": PASSWORD,
        "tls": tls(&cert)
    });
    assert_relayed(upstream, outbound).await;
}
