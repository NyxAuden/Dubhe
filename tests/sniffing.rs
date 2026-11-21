mod common;

use common::{Echo, Running};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn uuid_bytes() -> Vec<u8> {
    UUID.split('-')
        .flat_map(|part| {
            (0..part.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&part[i..i + 2], 16).unwrap())
        })
        .collect()
}

/// SOCKS5 入站：嗅探出的 Host 命中规则时拒绝，证明路由使用了域名。
#[tokio::test]
async fn sniffed_http_host_selects_route_without_changing_dial_target() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let config = json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "proxy", "listen": "127.0.0.1:0"}],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "reject", "tag": "blocked"}
        ],
        "route": {
            "default": "direct",
            "rules": [{"domains": ["blocked.test"], "outbound": "blocked"}]
        },
        "sniffing": {"enabled": true, "inbounds": ["proxy"], "timeout_ms": 150}
    });
    let running = Running::start(config).await;
    let mut client = TcpStream::connect(running.address).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    client.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0]);

    // 目标仍是 IP；嗅探只影响路由，不改写拨号目标。
    let mut request = vec![5, 1, 0];
    request.extend(common::address(echo.address));
    client.write_all(&request).await.unwrap();
    // 首包与请求同批写入，服务端在应答前读取并回放。
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
        .await
        .unwrap();
    let mut reply = [0u8; 3];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 2, "嗅探域名命中拒绝规则时应返回 SOCKS5 拒绝");
}

/// VLESS 入站：`dest_override` 允许时用嗅探域名拨号，DNS hosts 直接映射到回环。
#[tokio::test]
async fn dest_override_dials_sniffed_domain() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let config = json!({
        "version": 1,
        "inbounds": [{
            "type": "vless",
            "tag": "proxy",
            "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "dns": {"hosts": {"sniffed.test": ["127.0.0.1"]}},
        "sniffing": {
            "enabled": true,
            "inbounds": ["proxy"],
            "dest_override": ["http"],
            "timeout_ms": 500
        }
    });
    let running = Running::start(config).await;
    let mut client = TcpStream::connect(running.address).await.unwrap();
    let mut bytes = vec![0u8];
    bytes.extend_from_slice(&uuid_bytes());
    bytes.push(0);
    bytes.push(1);
    bytes.extend_from_slice(&echo.address.port().to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&common::address(echo.address)[1..5]);
    let payload = b"GET /path HTTP/1.1\r\nHost: sniffed.test\r\n\r\n";
    bytes.extend_from_slice(payload);
    client.write_all(&bytes).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0, 0], "VLESS 应答应在嗅探/拨号后返回");
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload, "嗅探域名应以 hosts 映射拨号并回放首包");
}
