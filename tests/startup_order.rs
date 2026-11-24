//! 入口顺序不得影响启动。
//!
//! 回归背景：`reality_pending` 曾用**入口枚举下标**去索引 `listeners`，
//! 而 NW3 / WireGuard 等入口在加入 `listeners` 之前就 `continue`。
//! 于是 `NW3 + REALITY` 这种合法配置 `check` 通过、`run` 直接 panic
//! （`index out of bounds`）。多协议单进程是本项目的核心用途，不能要求
//! 用户靠调整入口顺序才能启动。

mod common;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::Running;
use serde_json::{Value, json};

fn reality_inbound(target_port: u16) -> Value {
    json!({
        "type": "vless-reality",
        "tag": "reality-in",
        "listen": "127.0.0.1:0",
        "users": [{"name": "u", "uuid": "11111111-1111-1111-1111-111111111111"}],
        "reality": {
            "target": {"host": "127.0.0.1", "port": target_port},
            "private_key": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "server_names": ["localhost"],
            "short_ids": ["8172635445362718"]
        }
    })
}

fn nw3_inbound() -> Value {
    // NW3 不接受端口 0（Nowhere 要求显式端点），因此用一个探到的具体端口。
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    json!({
        "type": "nw3",
        "tag": "nw3-in",
        "listen": format!("127.0.0.1:{port}"),
        "key": "0123456789abcdef0123456789abcdef",
        "morph": false,
        "out": "direct"
    })
}

async fn starts_with_order(inbounds: Vec<Value>) -> Running {
    let value = json!({
        "version": 1,
        "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 300, "handshake_timeout_ms": 3000}
    });
    // `Running::start` 内部会 `Server::bind`，panic 会直接暴露出来。
    Running::start(value).await
}

/// NW3 在前、REALITY 在后：NW3 不加入 `listeners`，REALITY 的下标必须仍对得上。
#[tokio::test]
async fn nw3_before_reality_starts() {
    let echo = common::Echo::tcp("127.0.0.1", false).await;
    let server = starts_with_order(vec![nw3_inbound(), reality_inbound(echo.address.port())]).await;
    assert_eq!(server.addresses.len(), 2, "两个入口都应就绪");
    server.shutdown().await;
}

/// 反过来：REALITY 在前、NW3 在后。两种排列都必须能启动。
#[tokio::test]
async fn reality_before_nw3_starts() {
    let echo = common::Echo::tcp("127.0.0.1", false).await;
    let server = starts_with_order(vec![reality_inbound(echo.address.port()), nw3_inbound()]).await;
    assert_eq!(server.addresses.len(), 2, "两个入口都应就绪");
    server.shutdown().await;
}
