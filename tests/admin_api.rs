//! 管理/统计 API 回环测试。

mod common;

use common::*;
use serde_json::json;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const TOKEN: &str = "0123456789abcdef";

fn config() -> serde_json::Value {
    let mut config = socks_config();
    config["api"] = json!({"listen":"127.0.0.1:0","token":TOKEN});
    config
}

async fn request(address: SocketAddr, request: &[u8]) -> (String, String) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.to_owned(), body.to_owned())
}

#[tokio::test]
async fn stats_require_the_configured_bearer_token() {
    let server = Running::start(config()).await;
    let address = server.api_address.expect("API 已绑定");

    let (head, body) = request(
        address,
        format!("GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let stats: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(stats["connections"], 0);
    assert!(stats.get("uplink").is_some(), "{stats}");

    let (head, body) = request(address, b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    assert!(body.is_empty());

    let (head, _) = request(
        address,
        b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");

    let (head, body) = request(
        address,
        format!(
            "GET /healthz HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, r#"{"status":"ok"}"#);

    let (head, _) = request(
        address,
        format!("POST /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 0\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 405"), "{head}");

    let (head, _) = request(
        address,
        format!(
            "GET /missing HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    server.shutdown().await;
}

#[tokio::test]
async fn metrics_are_exported_in_prometheus_format() {
    let server = Running::start(config()).await;
    let address = server.api_address.expect("API 已绑定");

    let (head, body) = request(
        address,
        format!(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
        "{head}"
    );
    assert!(body.contains("dubhe_connections 0\n"), "{body}");
    assert!(
        body.contains("# TYPE dubhe_uplink_bytes_total counter\n"),
        "{body}"
    );

    let (head, _) = request(
        address,
        format!(
            "DELETE /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 405"), "{head}");
    assert!(head.contains("Allow: GET"), "{head}");
    server.shutdown().await;
}

#[tokio::test]
async fn token_can_be_loaded_from_a_private_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("api.token");
    std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = socks_config();
    config["api"] = json!({"listen":"127.0.0.1:0","token_file":path});
    let server = Running::start(config).await;
    let address = server.api_address.expect("API 已绑定");

    let (head, _) = request(
        address,
        format!("GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    server.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn token_file_with_group_or_world_access_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("api.token");
    std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut config = socks_config();
    config["api"] = json!({"listen":"127.0.0.1:0","token_file":path});
    let config = dubhe::Config::from_json(&config.to_string()).unwrap();
    let error = match dubhe::Server::bind(config).await {
        Ok(_) => panic!("权限不安全的 token 文件必须拒绝"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("权限"), "{error}");
}

#[tokio::test]
async fn malformed_and_oversized_admin_headers_fail_closed() {
    let server = Running::start(config()).await;
    let address = server.api_address.expect("API 已绑定");

    let mut wire =
        format!("GET /healthz HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n");
    for index in 0..33 {
        wire.push_str(&format!("X-Test-{index}: value\r\n"));
    }
    wire.push_str("\r\n");
    let (head, _) = request(address, wire.as_bytes()).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");

    let (head, _) = request(
        address,
        format!(
            "GET /healthz HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    server.shutdown().await;
}

#[tokio::test]
async fn connections_are_listed_and_can_be_closed() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config()).await;
    let api = server.api_address.expect("API 已绑定");

    let (mut tunnel, _) = socks(1, address(echo.address), server.address).await;
    tunnel.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    tunnel.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    let (head, body) = request(
        api,
        format!(
            "GET /connections HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let entries = value["connections"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{value}");
    assert_eq!(entries[0]["inbound"], "socks");
    assert_eq!(entries[0]["outbound"], "direct");
    assert_eq!(entries[0]["network"], "tcp");
    assert_eq!(entries[0]["host"], "127.0.0.1");
    assert_eq!(entries[0]["port"], echo.address.port());
    assert_eq!(entries[0]["upload"], 4);
    assert_eq!(entries[0]["download"], 4);
    let id = entries[0]["id"].as_u64().unwrap();

    let (head, _) = request(
        api,
        format!(
            "DELETE /connections/{id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 204"), "{head}");

    // 关闭后转发循环应立即结束：客户端读到 EOF 或连接错误。
    let mut byte = [0u8; 1];
    let closed = timeout(Duration::from_secs(2), tunnel.read(&mut byte))
        .await
        .expect("关闭后读取不应挂起")
        .unwrap();
    assert_eq!(closed, 0);

    // 注销在 Upstream 丢弃时完成，允许极短的回收窗口。
    let mut remaining = None;
    for _ in 0..50 {
        let (_, body) = request(
            api,
            format!(
                "GET /connections HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        remaining = Some(value["connections"].as_array().unwrap().len());
        if remaining == Some(0) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(remaining, Some(0));

    let (head, _) = request(
        api,
        format!(
            "DELETE /connections/not-a-number HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");

    let (head, _) = request(
        api,
        format!(
            "DELETE /connections/999999 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    server.shutdown().await;
}

#[test]
fn api_configuration_is_validated() {
    let parse = |api: serde_json::Value| {
        let mut config = socks_config();
        config["api"] = api;
        dubhe::config::Config::from_json(&config.to_string())
            .and_then(|config| config.validate().map(|()| config))
    };
    assert!(
        parse(json!({"listen":"0.0.0.0:9090","token":TOKEN})).is_err(),
        "非回环监听必须拒绝"
    );
    assert!(
        parse(json!({"listen":"127.0.0.1:9090","token":"short"})).is_err(),
        "过短 token 必须拒绝"
    );
    assert!(
        parse(json!({"listen":"127.0.0.1:9090","token":"has space and is long enough"})).is_err(),
        "含空白的 token 必须拒绝"
    );
    assert!(
        parse(json!({"listen":"127.0.0.1:9090"})).is_err(),
        "缺少 token 与 token_file 必须拒绝"
    );
    assert!(
        parse(json!({
            "listen":"127.0.0.1:9090",
            "token":TOKEN,
            "token_file":"/tmp/api.token"
        }))
        .is_err(),
        "token 与 token_file 同时配置必须拒绝"
    );
    assert!(
        parse(json!({
            "listen":"127.0.0.1:9090",
            "token_file":"/tmp/api.token"
        }))
        .is_ok(),
        "静态校验只检查 token_file 路径，不读取文件"
    );
}

#[tokio::test]
async fn users_endpoint_returns_empty_list_without_traffic() {
    let server = Running::start(config()).await;
    let address = server.api_address.expect("API 已绑定");

    let (head, body) = request(
        address,
        format!(
            "GET /stats/users HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let users: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(users.as_array().expect("数组").len(), 0);

    let (head, _) = request(
        address,
        b"GET /stats/users HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
}

#[tokio::test]
async fn user_traffic_is_attributed_after_an_authenticated_socks_connection() {
    let mut config = socks_config();
    config["inbounds"][0] = json!({
        "type": "socks5",
        "tag": "socks",
        "listen": "127.0.0.1:0",
        "users": [{"name": "alice", "password": "secret-password"}]
    });
    config["api"] = json!({"listen":"127.0.0.1:0","token":TOKEN});
    let server = Running::start(config).await;
    let api = server.api_address.expect("API 已绑定");
    let echo = Echo::tcp("127.0.0.1", false).await;

    // SOCKS5 用户名/密码认证（RFC 1929）。
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let mut auth = vec![1, 5];
    auth.extend_from_slice(b"alice");
    auth.push(b"secret-password".len() as u8);
    auth.extend_from_slice(b"secret-password");
    stream.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0]);

    let mut connect_request = vec![5, 1, 0];
    connect_request.extend(domain("localhost", echo.address.port()));
    stream.write_all(&connect_request).await.unwrap();
    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head, [5, 0, 0]);
    read_address(&mut stream).await;

    stream.write_all(b"payload").await.unwrap();
    let mut echoed = [0u8; 7];
    timeout(Duration::from_secs(3), stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"payload");

    let (head, body) = request(
        api,
        format!(
            "GET /stats/users HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let users: serde_json::Value = serde_json::from_str(&body).unwrap();
    let entry = &users.as_array().expect("数组")[0];
    assert_eq!(entry["inbound"], "socks");
    assert_eq!(entry["user"], "alice");
    assert!(entry["uplink"].as_u64().unwrap() >= 7, "{entry}");
    assert!(entry["downlink"].as_u64().unwrap() >= 7, "{entry}");

    drop(stream);
    server.shutdown().await;
}
