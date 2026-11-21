//! XHTTP 出站受控回环：仅本地服务器，不使用公网或官方客户端。
//! 本文件仅补写；执行与编译由主线程统一处理。

mod common;

use std::{io, net::SocketAddr};

use common::{Certificate, Echo, Running};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
// 96 KiB 双跳传输在 CI 并发下可能超过 10 秒；放宽等待，断言不变。
const WAIT: Duration = Duration::from_secs(30);
const PATH: &str = "/GunService/Tun";

fn upstream(mode: &str, version: &str, cert: Option<&Certificate>) -> Value {
    let mut inbound = json!({
        "type": "vless-xhttp", "tag": "remote", "listen": "127.0.0.1:0",
        "users": [{"name": "u", "uuid": UUID}], "xudp": false,
        "allow_insecure_transport": cert.is_none(),
        "xhttp": {"path": PATH, "host": "localhost", "mode": mode,
            "h3": version == "3", "sc_max_each_post_bytes": 1024}
    });
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    }
    json!({
        "version": 1, "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"default": "direct"},
        "limits": {"handshake_timeout_ms": 2000, "shutdown_timeout_ms": 100}
    })
}

fn downstream(
    endpoint: SocketAddr,
    mode: &str,
    version: &str,
    cert: Option<&Certificate>,
) -> Value {
    let mut outbound = json!({
        "type": "vless", "tag": "up", "endpoint": endpoint.to_string(), "uuid": UUID,
        "transport": {"type": "xhttp", "path": PATH, "host": "localhost",
            "mode": mode, "http_version": version, "max_post_bytes": 1024,
            "headers": {"x-client-test": "bounded"}, "x_padding": {"from": 100, "to": 100}}
    });
    if let Some(cert) = cert {
        outbound["tls"] =
            json!({"ca_file": cert.dir.path().join("cert.pem"), "server_name": "localhost"});
    }
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [outbound], "route": {"default": "up"},
        "limits": {"handshake_timeout_ms": 2000, "dial_timeout_ms": 2000, "shutdown_timeout_ms": 100}
    })
}

async fn tunnel(local: SocketAddr, target: SocketAddr) -> TcpStream {
    timeout(WAIT, common::socks(1, common::address(target), local))
        .await
        .unwrap()
        .0
}

/// 双向交换。必须边写边读：`stream-one` 在单条 HTTP/2 流上双向承载，
/// 写满流控窗口后只有对端回显被读走才会释放窗口；先写完再读会互相等待。
async fn exchange(stream: &mut TcpStream, payload: &[u8]) {
    timeout(WAIT, async {
        let (mut reader, mut writer) = stream.split();
        let mut received = vec![0u8; payload.len()];
        let read = async {
            reader.read_exact(&mut received).await.unwrap();
        };
        let write = async {
            writer.write_all(payload).await.unwrap();
            writer.flush().await.unwrap();
        };
        tokio::join!(read, write);
        assert_eq!(received, payload);
    })
    .await
    .expect("XHTTP双向传输超时");
}

async fn relay_modes(version: &str) {
    let cert = (version == "3").then(Certificate::new);
    let echo = Echo::tcp("127.0.0.1", false).await;
    for mode in ["auto", "stream-one", "stream-up", "packet-up"] {
        eprintln!("MODE {version} {mode}");
        let remote = Running::start(upstream(mode, version, cert.as_ref())).await;
        let local = Running::start(downstream(remote.address, mode, version, cert.as_ref())).await;
        let mut first = tunnel(local.address, echo.address).await;
        exchange(&mut first, b"request response boundary").await;
        // 总量跨越H2初始65535窗口，且超过单POST预算；持续POST不能累计拒绝。
        let payload: Vec<u8> = (0..96 * 1024).map(|index| (index % 251) as u8).collect();
        exchange(&mut first, &payload).await;
        let mut second = tunnel(local.address, echo.address).await;
        drop(first);
        exchange(&mut second, b"one drop must not cancel another tunnel").await;
        drop(second);
        local.shutdown().await;
        remote.shutdown().await;
    }
}

#[tokio::test]
async fn h2_all_modes_cross_flow_window_and_preserve_sessions() {
    relay_modes("2").await;
}

#[tokio::test]
async fn h3_all_modes_cross_post_budget_and_preserve_sessions() {
    relay_modes("3").await;
}

#[tokio::test]
async fn h1_split_modes_use_independent_connections() {
    relay_modes("1.1").await;
}

#[tokio::test]
async fn stream_up_upload_eof_does_not_end_get_downlink() {
    for version in ["1.1", "2", "3"] {
        let cert = (version == "3").then(Certificate::new);
        let echo = Echo::tcp("127.0.0.1", true).await;
        let remote = Running::start(upstream("stream-up", version, cert.as_ref())).await;
        let local = Running::start(downstream(
            remote.address,
            "stream-up",
            version,
            cert.as_ref(),
        ))
        .await;
        let mut stream = tunnel(local.address, echo.address).await;
        let bytes = vec![0x5a; 96 * 1024];
        timeout(WAIT, async {
            stream.write_all(&bytes).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = vec![0; bytes.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, bytes);
        })
        .await
        .expect("上传FIN后GET仍应读取回声");
        drop(stream);
        local.shutdown().await;
        remote.shutdown().await;
    }
}

async fn read_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await?);
        if bytes.len() > 8192 {
            return Err(io::Error::other("测试请求头超限"));
        }
    }
    String::from_utf8(bytes).map_err(io::Error::other)
}

#[tokio::test]
async fn cancelling_pending_h1_handshake_releases_the_endpoint() {
    let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = Running::start(downstream(
        peer.local_addr().unwrap(),
        "stream-one",
        "1.1",
        None,
    ))
    .await;
    let mut socks = TcpStream::connect(local.address).await.unwrap();
    socks.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    socks.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&common::address("127.0.0.1:9".parse().unwrap()));
    socks.write_all(&request).await.unwrap();
    let (mut endpoint, _) = timeout(WAIT, peer.accept()).await.unwrap().unwrap();
    assert!(
        timeout(WAIT, read_head(&mut endpoint))
            .await
            .unwrap()
            .unwrap()
            .starts_with("POST ")
    );
    // 不回HTTP响应，取消本地服务；远端应看到连接被丢弃，不能残留后台握手任务。
    local.shutdown().await;
    timeout(WAIT, async {
        let mut buffer = [0u8; 1024];
        loop {
            match endpoint.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("取消后端点连接应释放");
}

#[tokio::test]
async fn h2_upload_reset_fails_the_tunnel_instead_of_hanging() {
    let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = peer.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = peer.accept().await.unwrap();
        let mut connection = h2::server::handshake(tcp).await.unwrap();
        let (_request, mut response) = connection.accept().await.unwrap().unwrap();
        response.send_reset(h2::Reason::INTERNAL_ERROR);
        while connection.accept().await.is_some() {}
    });
    let local = Running::start(downstream(address, "stream-one", "2", None)).await;
    timeout(WAIT, async {
        let mut socks = TcpStream::connect(local.address).await.unwrap();
        socks.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        socks.read_exact(&mut method).await.unwrap();
        let mut request = vec![5, 1, 0];
        request.extend_from_slice(&common::address("127.0.0.1:9".parse().unwrap()));
        socks.write_all(&request).await.unwrap();
        // CONNECT可在HTTP错误到达前先成功，但后续业务流必须失败/关闭，不能永远等待。
        let mut head = [0u8; 3];
        match socks.read_exact(&mut head).await {
            Ok(_) if head[1] == 0 => {
                common::read_address(&mut socks).await;
                let _ = socks.write_all(&vec![0x42; 96 * 1024]).await;
                let _ = socks.flush().await;
                let mut byte = [0u8; 1];
                assert!(matches!(socks.read(&mut byte).await, Ok(0) | Err(_)));
            }
            Ok(_) | Err(_) => {}
        }
    })
    .await
    .expect("上传RST必须终止隧道");
    local.shutdown().await;
    server.abort();
}
