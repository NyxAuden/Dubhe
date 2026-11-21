mod common;
use common::*;
use serde_json::Value;

#[tokio::test]
async fn documented_examples_check_start_and_transfer() {
    let mut socks: Value = serde_json::from_str(include_str!("../examples/socks5.json")).unwrap();
    socks["inbounds"][0]["listen"] = "127.0.0.1:0".into();
    let config = dubhe::Config::from_json(&socks.to_string()).unwrap();
    dubhe::Server::check(&config).unwrap();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(socks).await;
    let (mut client, _) = common::socks(1, address(echo.address), server.address).await;
    exchange(&mut client, b"documented-socks").await;
    drop(client);
    server.shutdown().await;
    let cert = Certificate::new();
    let mut trojan: Value = serde_json::from_str(include_str!("../examples/trojan.json")).unwrap();
    trojan["inbounds"][0]["listen"] = "127.0.0.1:0".into();
    trojan["inbounds"][0]["certificate"] = cert
        .dir
        .path()
        .join("cert.pem")
        .to_string_lossy()
        .as_ref()
        .into();
    trojan["inbounds"][0]["private_key"] = cert
        .dir
        .path()
        .join("key.pem")
        .to_string_lossy()
        .as_ref()
        .into();
    trojan["inbounds"][0]["users"][0]["password"] = PASSWORD.into();
    let config = dubhe::Config::from_json(&trojan.to_string()).unwrap();
    dubhe::Server::check(&config).unwrap();
    let server = Running::start(trojan).await;
    let mut client = cert.connect(server.address).await;
    use tokio::io::AsyncWriteExt;
    client
        .write_all(&trojan_header(1, address(echo.address), PASSWORD))
        .await
        .unwrap();
    exchange(&mut client, b"documented-trojan").await;
    drop(client);
    server.shutdown().await;
}

const GRPC_TEMPLATES: [&str; 6] = [
    include_str!("../examples/vless-grpc.json"),
    include_str!("../examples/vless-grpc-tls.json"),
    include_str!("../examples/vless-grpc-multi.json"),
    include_str!("../examples/vmess-grpc-tls.json"),
    include_str!("../examples/trojan-grpc.json"),
    include_str!("../examples/trojan-grpc-tls.json"),
];

#[test]
fn grpc_example_templates_reject_placeholder_identities() {
    // Trojan密码只校验非空，占位密码本身可解析；UUID占位必须直接拒绝。
    for text in &GRPC_TEMPLATES[..4] {
        assert!(
            dubhe::Config::from_json(text).is_err(),
            "占位UUID模板不得在替换前可用"
        );
    }
    for text in &GRPC_TEMPLATES[4..] {
        assert!(text.contains("REPLACE_WITH_A_RANDOM_TROJAN_GRPC_PASSWORD"));
    }
}

#[test]
fn grpc_example_templates_parse_after_replacing_secrets() {
    for text in GRPC_TEMPLATES {
        let mut value: Value = serde_json::from_str(text).unwrap();
        let inbound = &mut value["inbounds"][0];
        if inbound["users"][0]["uuid"].is_string() {
            inbound["users"][0]["uuid"] = "11111111-1111-1111-1111-111111111111".into();
        } else {
            inbound["users"][0]["password"] = "replaced-secret-password".into();
        }
        if inbound["certificate"].is_string() {
            inbound["certificate"] = "/tmp/replaced-cert.pem".into();
            inbound["private_key"] = "/tmp/replaced-key.pem".into();
        }
        dubhe::Config::from_json(&value.to_string()).expect("替换占位值后应可解析");
    }
}

const NEW_ENTRY_TEMPLATES: [&str; 25] = [
    include_str!("../examples/http.json"),
    include_str!("../examples/mixed.json"),
    include_str!("../examples/naive.json"),
    include_str!("../examples/anytls.json"),
    include_str!("../examples/vless-fallback.json"),
    include_str!("../examples/trojan-fallback.json"),
    include_str!("../examples/vless-httpupgrade.json"),
    include_str!("../examples/vmess-httpupgrade-tls.json"),
    include_str!("../examples/trojan-httpupgrade.json"),
    include_str!("../examples/vless-xhttp.json"),
    include_str!("../examples/vless-xhttp-tls.json"),
    include_str!("../examples/vless-xhttp-headers.json"),
    include_str!("../examples/vmess-xhttp-tls.json"),
    include_str!("../examples/trojan-xhttp.json"),
    include_str!("../examples/trojan-xhttp-tls.json"),
    include_str!("../examples/vless-xhttp-h3.json"),
    include_str!("../examples/snell.json"),
    include_str!("../examples/hysteria2.json"),
    include_str!("../examples/tuic.json"),
    include_str!("../examples/shadowtls.json"),
    include_str!("../examples/nw3.json"),
    include_str!("../examples/vless-encryption.json"),
    include_str!("../examples/nw3-egress.json"),
    include_str!("../examples/socks5-upstream.json"),
    include_str!("../examples/dns-routing.json"),
];

#[test]
fn new_entry_templates_parse_after_replacing_placeholders() {
    for text in NEW_ENTRY_TEMPLATES {
        let mut value: Value = serde_json::from_str(text).unwrap();
        if value["inbounds"][0]["users"][0]["uuid"].is_string() {
            assert!(
                dubhe::Config::from_json(&value.to_string()).is_err(),
                "UUID 占位符不得在替换前可用"
            );
        }
        let inbound = &mut value["inbounds"][0];
        if inbound["users"][0]["uuid"].is_string() {
            inbound["users"][0]["uuid"] = "11111111-1111-1111-1111-111111111111".into();
        }
        if inbound["users"][0]["password"].is_string() {
            inbound["users"][0]["password"] = "replaced-secret-password".into();
        }
        if inbound["certificate"].is_string() {
            inbound["certificate"] = "/tmp/replaced-cert.pem".into();
            inbound["private_key"] = "/tmp/replaced-key.pem".into();
        }
        dubhe::Config::from_json(&value.to_string()).expect("替换占位值后应可解析");
    }
}

#[test]
fn routing_fields_example_is_valid() {
    // 该示例只用到本机入口与新路由字段，不需要替换占位凭据。
    let text = include_str!("../examples/routing-fields.json");
    dubhe::Config::from_json(text).expect("路由字段示例应可直接加载");
}

#[test]
fn routing_fields_example_rejects_bad_regex() {
    // 文件里是 JSON 转义（`\\\\.`），读进来后是单个反斜杠。
    // 源文件里是 JSON 转义的 `^stun\\..+`；直接替换整段正则更容易核对。
    let text = include_str!("../examples/routing-fields.json").replace("^stun\\\\..+", "(unclosed");
    let error = dubhe::Config::from_json(&text).expect_err("非法正则应被拒绝");
    assert!(format!("{error}").contains("domain_regex"), "{error}");
}
