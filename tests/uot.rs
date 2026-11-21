//! UoT（UDP over TCP，sing-box `sp.v2.udp-over-tcp.arpa` / legacy）黑盒测试。
//!
//! 本文件内的 UoT/VLESS 编码器完全独立于服务端 codec，只按本地 sing 源码的线格式
//! 逐字节构造；VMess 加密复用 `tests/common/vmess.rs` 的独立测试端，同样不调用内核实现。

#[path = "common/vmess.rs"]
mod client;
mod common;

use client::{Client, Request};
use common::*;
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const V2_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
const LEGACY_MAGIC: &str = "sp.udp-over-tcp.arpa";
// 与 tests/common/vmess.rs 相同的测试身份。
const UUID: &str = client::UUID;
const ID: [u8; 16] = client::ID;

fn vless_config(cert: &Certificate) -> Value {
    let mut value = socks_config();
    value["inbounds"] = json!([{
        "type":"vless","tag":"vless","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "certificate":cert.dir.path().join("cert.pem"),
        "private_key":cert.dir.path().join("key.pem")
    }]);
    value
}

fn vmess_config() -> Value {
    let mut value = socks_config();
    value["inbounds"] = json!([{
        "type":"vmess","tag":"vmess","listen":"127.0.0.1:0",
        "users":[{"name":"test","uuid":UUID}],
        "allow_insecure_body":true
    }]);
    value
}

/// VLESS 请求：版本 0、UUID、空 addons、TCP 命令、端口在前、域名地址。
fn vless_request(port: u16, domain: &str) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend(ID);
    bytes.push(0);
    bytes.push(1);
    bytes.extend(port.to_be_bytes());
    bytes.push(2);
    bytes.push(domain.len() as u8);
    bytes.extend(domain.as_bytes());
    bytes
}

/// 初始请求中的 SOCKS5 地址（类型 1/4 + 地址 + 端口）。
fn socks_address(address: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(address.port().to_be_bytes());
    bytes
}

/// 逐包 UoT 地址（类型 0x00 IPv4 / 0x01 IPv6 + 地址 + 端口）。
fn uot_address(address: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes.push(0x00);
            bytes.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(0x01);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(address.port().to_be_bytes());
    bytes
}

/// 逐包 UoT 域名地址（类型 0x02 + 长度 + ASCII 域名 + 端口）。
fn uot_domain(name: &str, port: u16) -> Vec<u8> {
    let mut bytes = vec![0x02, name.len() as u8];
    bytes.extend(name.as_bytes());
    bytes.extend(port.to_be_bytes());
    bytes
}

/// 版本 2 初始请求：1 字节 isConnect + SOCKS5 地址；legacy 不发送该请求。
fn uot_request(is_connect: bool, destination: Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![u8::from(is_connect)];
    bytes.extend(destination);
    bytes
}

/// 逐包帧：connect 无地址，非 connect 前置 UoT 地址；随后 u16 长度 + 载荷。
fn uot_frame(address: Option<&[u8]>, payload: &[u8]) -> Vec<u8> {
    let mut bytes = address.map(<[u8]>::to_vec).unwrap_or_default();
    bytes.extend((payload.len() as u16).to_be_bytes());
    bytes.extend(payload);
    bytes
}

async fn vless_reply<R: AsyncRead + Unpin>(stream: &mut R) {
    let mut head = [0xff; 2];
    read_exact(stream, &mut head).await;
    assert_eq!(head, [0, 0]);
}

async fn read_connect_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Vec<u8> {
    let length = stream.read_u16().await.unwrap() as usize;
    let mut payload = vec![0; length];
    read_exact(stream, &mut payload).await;
    payload
}

/// 非 connect 回包：读取 UoT 地址与载荷。测试中的回环 UDP 源均为 127.0.0.1。
async fn read_address_frame<R: AsyncRead + Unpin>(stream: &mut R) -> (SocketAddr, Vec<u8>) {
    assert_eq!(stream.read_u8().await.unwrap(), 0x00);
    let mut octets = [0; 4];
    read_exact(stream, &mut octets).await;
    let port = stream.read_u16().await.unwrap();
    let length = stream.read_u16().await.unwrap() as usize;
    let mut payload = vec![0; length];
    read_exact(stream, &mut payload).await;
    (
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port),
        payload,
    )
}

async fn expect_closed<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut byte = [0; 1];
    let result = timeout(Duration::from_secs(2), stream.read(&mut byte)).await;
    let closed = match result {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => true,
        Ok(Ok(_)) => false,
    };
    assert!(closed, "非法 UoT 请求后连接应立即关闭或不再返回载荷");
}

#[tokio::test]
async fn vless_v2_connect_round_trip_including_empty_payload() {
    let cert = Certificate::new();
    let echo = Echo::udp("127.0.0.1").await;
    let server = Running::start(vless_config(&cert)).await;
    let mut stream = cert.connect(server.address).await;

    stream.write_all(&vless_request(0, V2_MAGIC)).await.unwrap();
    vless_reply(&mut stream).await;
    stream
        .write_all(&uot_request(true, socks_address(echo.address)))
        .await
        .unwrap();

    // 上行无地址头，下行同样只有长度；空载荷必须作为合法数据报保留。
    stream
        .write_all(&uot_frame(None, b"vless-uot-connect"))
        .await
        .unwrap();
    assert_eq!(read_connect_frame(&mut stream).await, b"vless-uot-connect");
    stream.write_all(&uot_frame(None, b"")).await.unwrap();
    assert!(read_connect_frame(&mut stream).await.is_empty());

    stream.shutdown().await.unwrap();
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn vless_v2_non_connect_uses_per_packet_targets() {
    let cert = Certificate::new();
    let first = Echo::udp("127.0.0.1").await;
    let second = Echo::udp("127.0.0.1").await;
    let server = Running::start(vless_config(&cert)).await;
    let mut stream = cert.connect(server.address).await;

    stream.write_all(&vless_request(0, V2_MAGIC)).await.unwrap();
    vless_reply(&mut stream).await;
    // 非 connect 的初始目标只是元数据，端口 0 占位值必须被接受。
    stream
        .write_all(&uot_request(
            false,
            socks_address("0.0.0.0:0".parse().unwrap()),
        ))
        .await
        .unwrap();

    stream
        .write_all(&uot_frame(Some(&uot_address(first.address)), b"alpha"))
        .await
        .unwrap();
    stream
        .write_all(&uot_frame(Some(&uot_address(second.address)), b"beta"))
        .await
        .unwrap();

    let first_reply = read_address_frame(&mut stream).await;
    let second_reply = read_address_frame(&mut stream).await;
    let mut replies = [first_reply, second_reply];
    replies.sort_by(|left, right| left.1.cmp(&right.1));
    assert_eq!(replies[0], (first.address, b"alpha".to_vec()));
    assert_eq!(replies[1], (second.address, b"beta".to_vec()));

    stream.shutdown().await.unwrap();
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn vless_legacy_has_no_initial_request_and_accepts_domain_targets() {
    let cert = Certificate::new();
    let echo = Echo::udp("127.0.0.1").await;
    let server = Running::start(vless_config(&cert)).await;
    let mut stream = cert.connect(server.address).await;

    stream
        .write_all(&vless_request(0, LEGACY_MAGIC))
        .await
        .unwrap();
    vless_reply(&mut stream).await;

    // legacy 首字节即逐包地址；服务端不得再消费一个 isConnect 字节。
    stream
        // 使用 IP 字面量形式的域名，既覆盖 0x02 类型，又避免 localhost 的 A/AAAA 顺序歧义。
        .write_all(&uot_frame(
            Some(&uot_domain("127.0.0.1", echo.address.port())),
            b"legacy",
        ))
        .await
        .unwrap();
    let (target, payload) = read_address_frame(&mut stream).await;
    assert_eq!(target, echo.address);
    assert_eq!(payload, b"legacy");

    stream.shutdown().await.unwrap();
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn vmess_v2_connect_round_trip() {
    let echo = Echo::udp("127.0.0.1").await;
    let server = Running::start(vmess_config()).await;
    let io = TcpStream::connect(server.address).await.unwrap();
    // VMess 目标端口必须非 0（VMess 头部策略），UoT 只按域名识别魔数。
    let request = Request::new(1, client::domain(V2_MAGIC, 443), 5, 0);
    let initial = uot_request(true, socks_address(echo.address));
    let mut vmess = Client::start(io, request, Some(&initial)).await;

    vmess.send(&uot_frame(None, b"vmess-uot")).await;
    let length = u16::from_be_bytes(vmess.read(2).await.try_into().unwrap()) as usize;
    assert_eq!(vmess.read(length).await, b"vmess-uot");

    drop(vmess);
    server.shutdown().await;
}

#[tokio::test]
async fn invalid_and_truncated_requests_close_the_stream() {
    let cert = Certificate::new();
    let server = Running::start(vless_config(&cert)).await;

    // 初始地址类型 0x02 不是 SOCKS5 类型（只允许 1/4/3）。
    let mut stream = cert.connect(server.address).await;
    stream.write_all(&vless_request(0, V2_MAGIC)).await.unwrap();
    vless_reply(&mut stream).await;
    stream
        .write_all(&uot_request(true, vec![0x02, 0x01, 0xbb, 0x00, 0x35]))
        .await
        .unwrap();
    expect_closed(&mut stream).await;
    drop(stream);

    // isConnect 仅接受 0/1，2 必须被拒绝；后续字节构成完整地址也不能放行。
    let mut stream = cert.connect(server.address).await;
    stream.write_all(&vless_request(0, V2_MAGIC)).await.unwrap();
    vless_reply(&mut stream).await;
    let mut invalid = vec![2];
    invalid.extend(socks_address(echo_address()));
    stream.write_all(&invalid).await.unwrap();
    expect_closed(&mut stream).await;
    drop(stream);

    // 初始请求截断：声明 IPv4 但地址不足，半关闭后必须以错误结束。
    let mut stream = cert.connect(server.address).await;
    stream.write_all(&vless_request(0, V2_MAGIC)).await.unwrap();
    vless_reply(&mut stream).await;
    stream.write_all(&[1, 1, 127, 0]).await.unwrap();
    stream.shutdown().await.unwrap();
    expect_closed(&mut stream).await;
    drop(stream);

    // 非 connect 逐包地址类型 0x03 非法（只允许 0x00/0x01/0x02）。
    let mut stream = cert.connect(server.address).await;
    stream.write_all(&vless_request(0, V2_MAGIC)).await.unwrap();
    vless_reply(&mut stream).await;
    stream
        .write_all(&uot_request(
            false,
            socks_address("0.0.0.0:0".parse().unwrap()),
        ))
        .await
        .unwrap();
    stream
        .write_all(&[0x03, 0x00, 0x35, 0, 1, b'x'])
        .await
        .unwrap();
    expect_closed(&mut stream).await;
    drop(stream);

    // 帧长度声明 5 但只给 1 字节载荷，半关闭后必须报错。
    let mut stream = cert.connect(server.address).await;
    stream.write_all(&vless_request(0, V2_MAGIC)).await.unwrap();
    vless_reply(&mut stream).await;
    stream
        .write_all(&uot_request(true, socks_address(echo_address())))
        .await
        .unwrap();
    stream.write_all(&[0, 5, b'a']).await.unwrap();
    stream.shutdown().await.unwrap();
    expect_closed(&mut stream).await;
    drop(stream);

    server.shutdown().await;
}

/// 负向用例只关心格式，不建立真实 UDP 映射；用固定回环端口即可。
fn echo_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)
}
