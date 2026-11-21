mod common;
use common::*;
use std::{
    process::{Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

#[tokio::test]
async fn curl_uses_standard_socks5_connect() {
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = http.local_addr().unwrap();
    let server = Running::start(socks_config()).await;
    let response = tokio::spawn(async move {
        let (mut client, _) = http.accept().await.unwrap();
        let mut request = Vec::new();
        let mut b = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut b).await.unwrap();
            request.push(b[0]);
            assert!(request.len() < 8192);
        }
        client
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nstandard-curl",
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let proxy = server.address.to_string();
    let result = tokio::task::spawn_blocking(move || {
        Command::new("curl")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("NO_PROXY")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "3",
                "--noproxy",
                "",
                "--socks5-hostname",
                &proxy,
                &format!("http://{target}/"),
            ])
            .stdin(Stdio::null())
            .output()
            .expect("标准客户端 curl 必须已安装")
    })
    .await
    .unwrap();
    assert!(
        result.status.success(),
        "curl: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"standard-curl");
    timeout(Duration::from_secs(3), response)
        .await
        .unwrap()
        .unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn socks_refused_target_reports_rep_five() {
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = reservation.local_addr().unwrap();
    drop(reservation);
    let server = Running::start(socks_config()).await;
    let mut client = TcpStream::connect(server.address).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    read_exact(&mut client, &mut reply).await;
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0];
    request.extend(address(destination));
    client.write_all(&request).await.unwrap();
    read_exact(&mut client, &mut reply).await;
    assert_eq!(reply, [5, 5]);
    server.shutdown().await;
}
