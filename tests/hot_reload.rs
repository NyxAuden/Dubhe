//! 零停机配置热重载回环测试。

mod common;

use common::Echo;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn config(default: &str) -> serde_json::Value {
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "reject", "tag": "reject"}
        ],
        "route": {"default": default}
    })
}

fn parse(value: &serde_json::Value) -> dubhe::Config {
    dubhe::Config::from_json(&value.to_string()).unwrap()
}

async fn connect_status(address: std::net::SocketAddr, echo: std::net::SocketAddr) -> u8 {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.unwrap();
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&common::address(echo));
    stream.write_all(&request).await.unwrap();
    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await.unwrap();
    head[1]
}

#[tokio::test]
async fn hot_reload_swaps_routing_without_dropping_existing_connections() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let start = config("direct");
    let server = dubhe::Server::bind(parse(&start)).await.unwrap();
    let address = server.local_addr("socks").unwrap();
    let hot = server.hot_reload_handle();
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.run(stop.clone()));

    let (mut existing, _) = common::socks(1, common::address(echo.address), address).await;
    existing.write_all(b"before").await.unwrap();
    let mut echoed = [0u8; 6];
    existing.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"before");

    let mut reject = config("reject");
    reject["route"]["default"] = json!("reject");
    assert!(
        hot.reload(&parse(&reject)).unwrap(),
        "仅路由变化的配置应可热重载"
    );

    // 新连接使用新路由；已建立连接继续使用握手时的快照。
    assert_eq!(connect_status(address, echo.address).await, 2);
    existing.write_all(b"after!").await.unwrap();
    let mut echoed = [0u8; 6];
    existing.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"after!");

    drop(existing);
    stop.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), task).await;
}

#[tokio::test]
async fn hot_reload_rejects_listener_affecting_changes() {
    let server = dubhe::Server::bind(parse(&config("direct"))).await.unwrap();
    let hot = server.hot_reload_handle();
    let mut changed = config("direct");
    changed["limits"] = json!({"max_connections": 16});
    assert!(!hot.reload(&parse(&changed)).unwrap());
}
