//! 停机契约：`Server::run` 返回时，所有流的字节计数与 gauge 必须已经释放。
//!
//! 流任务可能挂在连接任务内部的 `JoinSet` 里；只 abort 不等待、或者外层
//! `force` 直接丢掉连接 future，都会让 gauge 晚于停机返回才 drop。

mod common;

use common::{Certificate, Echo};
use dubhe::{Config, Server};
use serde_json::json;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn uuid_bytes() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    for part in UUID.split('-') {
        for chunk in part.as_bytes().chunks(2) {
            let text = std::str::from_utf8(chunk).unwrap();
            bytes.push(u8::from_str_radix(text, 16).unwrap());
        }
    }
    bytes
}

/// 单条 V2Ray HTTP/H2 流，客户端保持打开，停机返回后**不 sleep、不重试**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_waits_for_in_flight_h2_streams() {
    let certificate = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let config = json!({
        "version": 1,
        "inbounds": [{
            "type": "vless-http", "tag": "in", "listen": "127.0.0.1:0",
            "users": [{"name": "u", "uuid": UUID}],
            "http": {"path": "/flow", "host": ["localhost"]},
            "certificate": certificate.dir.path().join("cert.pem"),
            "private_key": certificate.dir.path().join("key.pem")
        }],
        "outbounds": [{"type": "direct", "tag": "d"}],
        "route": {"default": "d"},
        "limits": {"shutdown_timeout_ms": 300}
    });
    let server = Server::bind(Config::from_json(&config.to_string()).unwrap())
        .await
        .unwrap();
    let address = server.local_addr("in").unwrap();
    let stats = server.stats();
    let stop = CancellationToken::new();
    let driver = tokio::spawn(server.run(stop.clone()));

    let io = certificate.connect_alpn(address, &[b"h2"]).await;
    let (mut client, h2) = h2::client::handshake(io).await.unwrap();
    let h2 = tokio::spawn(h2);
    client = client.ready().await.unwrap();
    let request = http::Request::builder()
        .method("PUT")
        .uri("https://localhost/flow")
        .body(())
        .unwrap();
    let (response, mut body) = client.send_request(request, false).unwrap();
    let mut payload = vec![0u8];
    payload.extend_from_slice(&uuid_bytes());
    payload.extend_from_slice(&[0, 1]); // addons 长度 0、命令 1（TCP）
    payload.extend_from_slice(&echo.address.port().to_be_bytes());
    payload.extend_from_slice(&[1, 127, 0, 0, 1]);
    payload.extend_from_slice(b"OK!");
    body.send_data(payload.into(), false).unwrap();

    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut rx = response.into_body();
    let mut echoed = Vec::new();
    while !echoed.ends_with(b"OK!") {
        let chunk = timeout(Duration::from_secs(3), rx.data())
            .await
            .expect("回显超时")
            .unwrap()
            .unwrap();
        echoed.extend_from_slice(&chunk);
    }
    // 流仍然开着，必须已经计入。
    assert_eq!(stats.snapshot().tcp_flows, 1, "回显后应有一个活动流");

    stop.cancel();
    timeout(Duration::from_secs(3), driver)
        .await
        .expect("服务端未在期限内停止")
        .unwrap()
        .unwrap();

    // 关键断言：返回后立即读取，不 sleep、不重试。
    assert_eq!(
        stats.snapshot().tcp_flows,
        0,
        "Server::run 返回时流任务必须已经释放"
    );

    drop((body, rx, client));
    h2.abort();
    let _ = h2.await;
}
