//! `urltest` 出站组的回环行为：探测失败的首成员被可用成员替换。

mod common;

use common::{Echo, Running};
use serde_json::json;
use std::{
    net::{SocketAddr, TcpListener},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

/// 申请一个当前未监听的本地端口；连接它会得到拒绝，用于构造探测失败成员。
fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

/// 经 SOCKS5 入口 CONNECT 到回环目标并交换一个字节；失败返回 `Err` 以便重试。
async fn try_exchange(proxy: SocketAddr, target: SocketAddr) -> std::io::Result<()> {
    let mut stream = timeout(Duration::from_millis(500), TcpStream::connect(proxy)).await??;
    stream.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    timeout(Duration::from_millis(500), stream.read_exact(&mut reply)).await??;
    if reply != [5, 0] {
        return Err(std::io::Error::other("SOCKS5 方法协商失败"));
    }
    let ip = match target.ip() {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(_) => return Err(std::io::Error::other("测试目标应为 IPv4")),
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend(ip);
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 3];
    timeout(Duration::from_millis(500), stream.read_exact(&mut head)).await??;
    if head != [5, 0, 0] {
        return Err(std::io::Error::other("SOCKS5 CONNECT 失败"));
    }
    // 读取并丢弃 BND.ADDR/BND.PORT。
    let mut kind = [0u8; 1];
    timeout(Duration::from_millis(500), stream.read_exact(&mut kind)).await??;
    let rest = if kind[0] == 1 { 6 } else { 18 };
    let mut bound = vec![0u8; rest];
    timeout(Duration::from_millis(500), stream.read_exact(&mut bound)).await??;
    stream.write_all(b"ping").await?;
    let mut echoed = [0u8; 4];
    timeout(Duration::from_millis(500), stream.read_exact(&mut echoed)).await??;
    if &echoed != b"ping" {
        return Err(std::io::Error::other("回显不一致"));
    }
    Ok(())
}

#[tokio::test]
async fn urltest_switches_away_from_a_failing_member() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let dead = closed_port();
    let running = Running::start(json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
        "outbounds": [
            {"type": "socks5", "tag": "dead", "endpoint": dead.to_string()},
            {"type": "direct", "tag": "live"},
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": ["dead", "live"],
                "probe": echo.address.to_string(),
                "interval_ms": 1000,
                "tolerance_ms": 0,
                "probe_timeout_ms": 200
            }
        ],
        "route": {"default": "auto"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 300}
    }))
    .await;

    // 首个成员探测失败后应切换到 `live`；轮询避免依赖单次调度时序。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if try_exchange(running.address, echo.address).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "urltest 未在期限内切换离开失败成员"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    running.shutdown().await;
}
