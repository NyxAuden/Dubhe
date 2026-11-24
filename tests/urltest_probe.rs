//! `urltest` 探测的两个语义：
//! 1) `reject` 成员不能被真的拨号（否则拒绝语义与健康结果都不对）；
//! 2) 热重载后启动的探测任务必须能被实例停机取消。

mod common;

use dubhe::{Config, Server};
use serde_json::{Value, json};
use tokio::{
    net::TcpListener,
    time::{Duration, timeout},
};
use tokio_util::sync::CancellationToken;

fn config(outbounds: Value, default: &str) -> Config {
    Config::from_json(
        &json!({
            "version": 1,
            "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
            "outbounds": outbounds,
            "route": {"default": default}
        })
        .to_string(),
    )
    .unwrap()
}

fn group(member: &str, probe: std::net::SocketAddr) -> Value {
    json!({
        "type": "urltest", "tag": "auto", "outbounds": [member],
        "probe": probe.to_string(), "interval_ms": 1000, "probe_timeout_ms": 500
    })
}

/// 正例：`direct` 成员的探测必须真的发起连接。
#[tokio::test]
async fn direct_members_are_probed() {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let probe_address = probe.local_addr().unwrap();
    let server = Server::bind(config(
        json!([
            {"type": "direct", "tag": "ok"},
            group("ok", probe_address)
        ]),
        "auto",
    ))
    .await
    .unwrap();
    let stop = CancellationToken::new();
    let driver = tokio::spawn(server.run(stop.clone()));

    let accepted = timeout(Duration::from_secs(2), probe.accept()).await;
    stop.cancel();
    let _ = timeout(Duration::from_secs(2), driver).await;
    assert!(accepted.is_ok(), "direct 成员的探测应发起连接");
}

/// `reject` 成员不是「直连」：探测不得拨号。
#[tokio::test]
async fn reject_members_are_not_probed() {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let probe_address = probe.local_addr().unwrap();
    let server = Server::bind(config(
        json!([
            {"type": "reject", "tag": "bad"},
            group("bad", probe_address)
        ]),
        "auto",
    ))
    .await
    .unwrap();
    let stop = CancellationToken::new();
    let driver = tokio::spawn(server.run(stop.clone()));

    let accepted = timeout(Duration::from_millis(1200), probe.accept()).await;
    stop.cancel();
    let _ = timeout(Duration::from_secs(2), driver).await;
    assert!(accepted.is_err(), "reject 成员不应被探测拨号");
}

/// 热重载启动的探测任务也必须由实例停机取消。
#[tokio::test]
async fn hot_reload_probes_are_cancelled_at_shutdown() {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let probe_address = probe.local_addr().unwrap();

    let server = Server::bind(config(
        json!([{"type": "direct", "tag": "direct"}]),
        "direct",
    ))
    .await
    .unwrap();
    let hot = server.hot_reload_handle();
    let stop = CancellationToken::new();
    let driver = tokio::spawn(server.run(stop.clone()));

    let next = config(
        json!([
            {"type": "direct", "tag": "direct"},
            group("direct", probe_address)
        ]),
        "auto",
    );
    // `run` 在任务启动时才发布共享上下文；等它就绪再重载。
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if hot.reload(&next).unwrap() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "热重载一直未就绪");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let accepted = timeout(Duration::from_secs(2), probe.accept()).await;
    assert!(accepted.is_ok(), "热重载后的探测应已启动");

    stop.cancel();
    timeout(Duration::from_secs(2), driver)
        .await
        .expect("热重载后的探测任务必须能被停机取消")
        .unwrap()
        .unwrap();
}
