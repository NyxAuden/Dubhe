mod common;
#[path = "common/vmess.rs"]
mod vmess_client;

use common::*;
use h2::{RecvStream, SendStream};
use prost::Message;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const WAIT: Duration = Duration::from_secs(5);
const UUID_ONE: &str = "11111111-1111-1111-1111-111111111111";
const UUID_TWO: &str = "22222222-2222-2222-2222-222222222222";

#[derive(Clone, PartialEq, Message)]
struct Hunk {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
}

fn config(cert: Option<&Certificate>, multi_path: Option<&str>) -> Value {
    let mut value = socks_config();
    let mut grpc = json!({"path":"/GunService/Tun"});
    if let Some(multi) = multi_path {
        grpc["multi_path"] = json!(multi);
    }
    let mut inbound = json!({
        "type":"vless-grpc", "tag":"grpc", "listen":"127.0.0.1:0",
        "grpc": grpc,
        "users":[{"name":"one","uuid":UUID_ONE}],
        "xudp": true
    });
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    } else {
        inbound["allow_insecure_transport"] = json!(true);
    }
    value["inbounds"] = json!([inbound]);
    value["limits"]["handshake_timeout_ms"] = json!(3000);
    value
}

fn request(path: &str) -> http::Request<()> {
    http::Request::builder()
        .method("POST")
        .uri(format!("https://localhost{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap()
}

fn uuid_of(text: &str) -> Vec<u8> {
    text.split('-')
        .flat_map(|part| {
            (0..part.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&part[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn uuid_bytes() -> Vec<u8> {
    uuid_of(UUID_ONE)
}

fn vless_request(target: SocketAddr) -> Vec<u8> {
    vless_command(1, target)
}

fn vless_command(command: u8, target: SocketAddr) -> Vec<u8> {
    vless_with_uuid(uuid_bytes(), command, target)
}

fn vless_with_uuid(uuid: Vec<u8>, command: u8, target: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend(uuid);
    bytes.push(0);
    bytes.push(command);
    bytes.extend(target.port().to_be_bytes());
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            bytes.push(3);
            bytes.extend(ip.octets());
        }
    }
    bytes
}

fn frame(data: &[u8]) -> prost::bytes::Bytes {
    let payload = Hunk {
        data: data.to_vec(),
    }
    .encode_to_vec();
    let mut wire = Vec::with_capacity(5 + payload.len());
    wire.push(0);
    wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    wire.extend_from_slice(&payload);
    prost::bytes::Bytes::from(wire)
}

struct FrameReader {
    body: RecvStream,
    buffer: Vec<u8>,
    pending: Vec<u8>,
}

impl FrameReader {
    fn new(body: RecvStream) -> Self {
        Self {
            body,
            buffer: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// 跨gRPC消息读取精确字节数；消息边界与业务字节流无关。
    async fn read_bytes(&mut self, length: usize) -> Vec<u8> {
        while self.pending.len() < length {
            let chunk = self.next().await.expect("业务流提前结束");
            self.pending.extend_from_slice(&chunk);
        }
        let out = self.pending[..length].to_vec();
        self.pending.drain(..length);
        out
    }

    async fn vless_udp_packet(&mut self) -> Vec<u8> {
        let header = self.read_bytes(2).await;
        let length = u16::from_be_bytes([header[0], header[1]]) as usize;
        self.read_bytes(length).await
    }

    async fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.buffer.len() >= 5 {
                assert_eq!(self.buffer[0], 0, "不支持压缩消息");
                let length = u32::from_be_bytes([
                    self.buffer[1],
                    self.buffer[2],
                    self.buffer[3],
                    self.buffer[4],
                ]) as usize;
                if self.buffer.len() >= 5 + length {
                    let payload = self.buffer[5..5 + length].to_vec();
                    self.buffer.drain(..5 + length);
                    return Some(Hunk::decode(&payload[..]).unwrap().data);
                }
            }
            match self.body.data().await {
                Some(Ok(chunk)) => {
                    let length = chunk.len();
                    self.buffer.extend_from_slice(&chunk);
                    self.body.flow_control().release_capacity(length).unwrap();
                }
                Some(Err(_)) | None => return None,
            }
        }
    }
}

async fn plain_client(
    address: SocketAddr,
    path: &str,
) -> (
    SendStream<prost::bytes::Bytes>,
    FrameReader,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let io = timeout(WAIT, TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let (mut send_request, connection) = h2::client::handshake(io).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, stream) = send_request.send_request(request(path), false).unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    (stream, FrameReader::new(response.into_body()), driver)
}

async fn vless_tcp_round_trip(
    stream: &mut SendStream<prost::bytes::Bytes>,
    body: &mut FrameReader,
    target: SocketAddr,
) {
    stream
        .send_data(frame(&vless_request(target)), false)
        .unwrap();
    assert_eq!(
        body.next().await.expect("VLESS应答"),
        vec![0, 0],
        "VLESS首响应"
    );
    stream.send_data(frame(b"hello-over-grpc"), false).unwrap();
    assert_eq!(body.next().await.expect("回显载荷"), b"hello-over-grpc");
    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let trailers = timeout(WAIT, body.body.trailers())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
}

#[tokio::test]
async fn plaintext_vless_grpc_relays_tcp_and_ends_with_trailers() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;
    timeout(
        WAIT,
        vless_tcp_round_trip(&mut stream, &mut body, echo.address),
    )
    .await
    .unwrap();
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn tls_vless_grpc_requires_and_negotiates_h2() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(Some(&cert), None)).await;
    // 标准证书辅助未声明ALPN；这里单独建立带h2 ALPN的客户端。
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(server.address).await.unwrap();
    let tls = TlsConnector::from(Arc::new(config))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut send_request, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, mut stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = FrameReader::new(response.into_body());
    timeout(
        WAIT,
        vless_tcp_round_trip(&mut stream, &mut body, echo.address),
    )
    .await
    .unwrap();
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn wrong_path_or_content_type_is_rejected_before_authentication() {
    let server = Running::start(config(None, None)).await;
    let io = TcpStream::connect(server.address).await.unwrap();
    let (mut send_request, connection) = h2::client::handshake(io).await.unwrap();
    let driver = tokio::spawn(connection);

    let (response, stream) = send_request
        .send_request(request("/GunService/TunMulti"), false)
        .unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 404);
    drop(stream);

    let mut wrong = request("/GunService/Tun");
    wrong.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/grpc-web"),
    );
    let (response, stream) = send_request.send_request(wrong, false).unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 415);
    drop(stream);

    drop(send_request);
    driver.abort();
    server.shutdown().await;
}

async fn rejected_status(
    send_request: &mut h2::client::SendRequest<prost::bytes::Bytes>,
    request: http::Request<()>,
) -> http::StatusCode {
    let (response, stream) = send_request.send_request(request, true).unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    drop(stream);
    response.status()
}

#[tokio::test]
async fn admission_rejects_ambiguous_headers_and_invalid_timeout() {
    let server = Running::start(config(None, None)).await;
    let io = TcpStream::connect(server.address).await.unwrap();
    let (mut send_request, connection) = h2::client::handshake(io).await.unwrap();
    let driver = tokio::spawn(connection);

    let mut with_length = request("/GunService/Tun");
    with_length
        .headers_mut()
        .insert("content-length", http::HeaderValue::from_static("0"));
    assert_eq!(
        rejected_status(&mut send_request, with_length).await,
        http::StatusCode::BAD_REQUEST
    );

    let mut compressed = request("/GunService/Tun");
    compressed
        .headers_mut()
        .insert("grpc-encoding", http::HeaderValue::from_static("gzip"));
    assert_eq!(
        rejected_status(&mut send_request, compressed).await,
        http::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let mut duplicated = request("/GunService/Tun");
    duplicated.headers_mut().append(
        "content-type",
        http::HeaderValue::from_static("application/grpc"),
    );
    assert_eq!(
        rejected_status(&mut send_request, duplicated).await,
        http::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let mut bad_timeout = request("/GunService/Tun");
    bad_timeout
        .headers_mut()
        .insert("grpc-timeout", http::HeaderValue::from_static("10X"));
    assert_eq!(
        rejected_status(&mut send_request, bad_timeout).await,
        http::StatusCode::BAD_REQUEST
    );

    let mut too_many = request("/GunService/Tun");
    for index in 0..64 {
        too_many.headers_mut().insert(
            http::HeaderName::from_bytes(format!("x-meta-{index}").as_bytes()).unwrap(),
            http::HeaderValue::from_static("v"),
        );
    }
    assert_eq!(
        rejected_status(&mut send_request, too_many).await,
        http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );

    drop(send_request);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn multi_hunk_path_is_accepted_when_configured() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(None, Some("/GunService/TunMulti"))).await;
    let (mut send_request, connection) =
        h2::client::handshake(TcpStream::connect(server.address).await.unwrap())
            .await
            .unwrap();
    let driver = tokio::spawn(connection);
    let (response, mut stream) = send_request
        .send_request(request("/GunService/TunMulti"), false)
        .unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = FrameReader::new(response.into_body());

    #[derive(Clone, PartialEq, Message)]
    struct MultiHunk {
        #[prost(bytes = "vec", repeated, tag = "1")]
        data: Vec<Vec<u8>>,
    }
    let request_bytes = vless_request(echo.address);
    let split = request_bytes.len() / 2;
    let payload = MultiHunk {
        data: vec![
            request_bytes[..split].to_vec(),
            request_bytes[split..].to_vec(),
        ],
    }
    .encode_to_vec();
    let mut wire = vec![0];
    wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    wire.extend_from_slice(&payload);
    stream
        .send_data(prost::bytes::Bytes::from(wire), false)
        .unwrap();
    assert_eq!(body.next().await.expect("VLESS应答"), vec![0, 0]);
    stream.send_data(frame(b"multi"), false).unwrap();
    assert_eq!(body.next().await.expect("回显"), b"multi");
    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

fn grpc_inbound(kind: &str, cert: Option<&Certificate>) -> Value {
    let mut inbound = json!({
        "type": kind,
        "tag": "grpc",
        "listen": "127.0.0.1:0",
        "grpc": {"path": "/GunService/Tun"}
    });
    match kind {
        "trojan-grpc" => {
            inbound["users"] = json!([{"name":"alice","password":"test-secret-password"}]);
        }
        "vmess-grpc" => {
            inbound["users"] = json!([{"name":"alice","uuid":vmess_client::UUID}]);
        }
        _ => unreachable!(),
    }
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    } else {
        inbound["allow_insecure_transport"] = json!(true);
    }
    inbound
}

fn with_inbound(inbound: Value) -> Value {
    let mut value = socks_config();
    value["inbounds"] = json!([inbound]);
    value["limits"]["handshake_timeout_ms"] = json!(3000);
    value
}

fn trojan_digest(password: &str) -> Vec<u8> {
    use sha2::Digest as ShaDigest;
    let digest = sha2::Sha224::digest(password.as_bytes());
    let mut encoded = Vec::with_capacity(56);
    for byte in digest {
        encoded.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    encoded
}

fn trojan_request(command: u8, password: &str, target: SocketAddr) -> Vec<u8> {
    let mut bytes = trojan_digest(password);
    bytes.extend_from_slice(b"\r\n");
    bytes.push(command);
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(target.port().to_be_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes
}

fn trojan_hello(password: &str, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = trojan_request(1, password, target);
    bytes.extend_from_slice(payload);
    bytes
}

async fn trojan_packet(body: &mut FrameReader) -> (SocketAddr, Vec<u8>) {
    let atyp = body.read_bytes(1).await[0];
    assert_eq!(atyp, 1, "测试对端为IPv4");
    let ip = body.read_bytes(4).await;
    let port = body.read_bytes(2).await;
    let length = body.read_bytes(2).await;
    let crlf = body.read_bytes(2).await;
    assert_eq!(crlf, b"\r\n");
    let payload = body
        .read_bytes(u16::from_be_bytes([length[0], length[1]]) as usize)
        .await;
    (
        SocketAddr::from((
            [ip[0], ip[1], ip[2], ip[3]],
            u16::from_be_bytes([port[0], port[1]]),
        )),
        payload,
    )
}

async fn tls_h2(
    cert: &Certificate,
    address: SocketAddr,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(address).await.unwrap();
    TlsConnector::from(Arc::new(config))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap()
}

/// 测试端把gRPC消息流适配成字节流，供独立VMess客户端复用。
fn client_bridge(
    response: h2::client::ResponseFuture,
    mut send: SendStream<prost::bytes::Bytes>,
) -> DuplexStream {
    let (app, bridge) = tokio::io::duplex(64 * 1024);
    let (mut pump_read, mut pump_write) = tokio::io::split(bridge);
    tokio::spawn(async move {
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let mut body = response.into_body();
        let mut buffer = Vec::new();
        loop {
            loop {
                if buffer.len() < 5 {
                    break;
                }
                let length =
                    u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
                if buffer.len() < 5 + length {
                    break;
                }
                let payload = buffer[5..5 + length].to_vec();
                buffer.drain(..5 + length);
                let data = Hunk::decode(&payload[..]).unwrap().data;
                if !data.is_empty() {
                    pump_write.write_all(&data).await.unwrap();
                }
            }
            match body.data().await {
                Some(Ok(chunk)) => {
                    let length = chunk.len();
                    buffer.extend_from_slice(&chunk);
                    body.flow_control().release_capacity(length).unwrap();
                }
                _ => break,
            }
        }
        let _ = pump_write.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = pump_read.read(&mut buffer).await.unwrap();
            if read == 0 {
                let _ = send.send_data(prost::bytes::Bytes::new(), true);
                break;
            }
            let _ = send.send_data(frame(&buffer[..read]), false);
        }
    });
    app
}

#[tokio::test]
async fn trojan_grpc_plaintext_relays_tcp() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(with_inbound(grpc_inbound("trojan-grpc", None))).await;
    let (mut send_request, connection) =
        h2::client::handshake(TcpStream::connect(server.address).await.unwrap())
            .await
            .unwrap();
    let driver = tokio::spawn(connection);
    let (response, mut stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = FrameReader::new(response.into_body());
    stream
        .send_data(
            frame(&trojan_hello(
                "test-secret-password",
                echo.address,
                b"trojan-over-grpc",
            )),
            false,
        )
        .unwrap();
    assert_eq!(body.next().await.expect("Trojan回显"), b"trojan-over-grpc");
    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let trailers = timeout(WAIT, body.body.trailers())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn trojan_grpc_tls_requires_and_negotiates_h2() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(with_inbound(grpc_inbound("trojan-grpc", Some(&cert)))).await;
    let tls = tls_h2(&cert, server.address).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut send_request, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, mut stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = FrameReader::new(response.into_body());
    stream
        .send_data(
            frame(&trojan_hello(
                "test-secret-password",
                echo.address,
                b"trojan-over-grpc-tls",
            )),
            false,
        )
        .unwrap();
    assert_eq!(
        body.next().await.expect("Trojan TLS 回显"),
        b"trojan-over-grpc-tls"
    );
    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let trailers = timeout(WAIT, body.body.trailers())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn vless_grpc_native_udp_preserves_packet_boundaries() {
    let target = Echo::udp("127.0.0.1").await;
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;

    let mut first = vless_command(2, target.address);
    first.extend_from_slice(&5u16.to_be_bytes());
    first.extend_from_slice(b"first");
    first.extend_from_slice(&6u16.to_be_bytes());
    first.extend_from_slice(b"second");
    stream.send_data(frame(&first), false).unwrap();
    assert_eq!(body.read_bytes(2).await, vec![0, 0]);
    assert_eq!(body.vless_udp_packet().await, b"first");
    assert_eq!(body.vless_udp_packet().await, b"second");

    let mut third = 5u16.to_be_bytes().to_vec();
    third.extend_from_slice(b"third");
    stream.send_data(frame(&third), false).unwrap();
    assert_eq!(body.vless_udp_packet().await, b"third");

    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let _ = timeout(WAIT, body.body.trailers()).await;
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn trojan_grpc_udp_round_trip_multiple_targets() {
    let one = Echo::udp("127.0.0.1").await;
    let two = Echo::udp("127.0.0.1").await;
    let server = Running::start(with_inbound(grpc_inbound("trojan-grpc", None))).await;
    let (mut send_request, connection) =
        h2::client::handshake(TcpStream::connect(server.address).await.unwrap())
            .await
            .unwrap();
    let driver = tokio::spawn(connection);
    let (response, mut stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = FrameReader::new(response.into_body());

    let mut first = trojan_request(3, "test-secret-password", one.address);
    first.extend(trojan_udp(one.address, b"first"));
    first.extend(trojan_udp(two.address, b"second"));
    stream.send_data(frame(&first), false).unwrap();
    let (address, payload) = trojan_packet(&mut body).await;
    assert_eq!(address, one.address);
    assert_eq!(payload, b"first");
    let (address, payload) = trojan_packet(&mut body).await;
    assert_eq!(address, two.address);
    assert_eq!(payload, b"second");

    stream
        .send_data(frame(&trojan_udp(two.address, b"third")), false)
        .unwrap();
    let (address, payload) = trojan_packet(&mut body).await;
    assert_eq!(address, two.address);
    assert_eq!(payload, b"third");

    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let _ = timeout(WAIT, body.body.trailers()).await;
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn vmess_grpc_tls_relays_tcp_and_preserves_half_close() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", true).await;
    let server = Running::start(with_inbound(grpc_inbound("vmess-grpc", Some(&cert)))).await;
    let tls = tls_h2(&cert, server.address).await;
    let (mut send_request, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let app = client_bridge(response, stream);
    let mut client = vmess_client::Client::start(
        app,
        vmess_client::Request::new(1, vmess_client::target(echo.address), 5, 0),
        Some(b"first"),
    )
    .await;
    let payload = vec![0x73u8; 20_001];
    client.send(&payload).await;
    client.finish().await;
    client.io.shutdown().await.unwrap();
    let mut expected = b"first".to_vec();
    expected.extend_from_slice(&payload);
    assert_eq!(client.read(expected.len()).await, expected);
    client.eof().await;
    client.io.shutdown().await.unwrap();
    driver.abort();
    server.shutdown().await;
}

/// 按对端capacity分块写一条完整gRPC消息；用于超过发送缓冲的大消息。
async fn send_wire(stream: &mut SendStream<prost::bytes::Bytes>, wire: prost::bytes::Bytes) {
    let mut offset = 0;
    while offset < wire.len() {
        let length = (wire.len() - offset).min(16 * 1024);
        stream.reserve_capacity(length);
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .expect("发送方向未关闭")
            .expect("发送容量可用");
        assert!(capacity > 0, "capacity必须为正");
        let chunk = wire.slice(offset..offset + length);
        stream.send_data(chunk, false).unwrap();
        offset += length;
    }
}

#[tokio::test]
async fn bad_identity_does_not_disturb_other_rpc_on_same_connection() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(None, None)).await;
    let (mut send_request, connection) =
        h2::client::handshake(TcpStream::connect(server.address).await.unwrap())
            .await
            .unwrap();
    let driver = tokio::spawn(connection);

    let (bad_response, mut bad) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let (good_response, mut good) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let bad_response = timeout(WAIT, bad_response).await.unwrap().unwrap();
    let good_response = timeout(WAIT, good_response).await.unwrap().unwrap();
    assert_eq!(bad_response.status(), 200);
    assert_eq!(good_response.status(), 200);
    let mut bad_body = FrameReader::new(bad_response.into_body());
    let mut good_body = FrameReader::new(good_response.into_body());

    bad.send_data(
        frame(&vless_with_uuid(vec![0xAB; 16], 1, echo.address)),
        false,
    )
    .unwrap();
    if let Ok(Some(_)) = timeout(Duration::from_secs(2), bad_body.next()).await {
        panic!("坏认证不得产生业务响应");
    }

    good.send_data(frame(&vless_request(echo.address)), false)
        .unwrap();
    assert_eq!(good_body.next().await.expect("良好RPC应答"), vec![0, 0]);
    good.send_data(frame(b"still-alive"), false).unwrap();
    assert_eq!(good_body.next().await.expect("良好RPC回显"), b"still-alive");

    drop(bad);
    drop(bad_body);
    good.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let _ = timeout(WAIT, good_body.body.trailers()).await;
    drop(good);
    drop(good_body);
    driver.abort();
    server.shutdown().await;
}

fn xudp_address(target: SocketAddr) -> Vec<u8> {
    let mut bytes = target.port().to_be_bytes().to_vec();
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            bytes.push(3);
            bytes.extend(ip.octets());
        }
    }
    bytes
}

fn xudp_new(id: u16, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([1, 1, 2]);
    metadata.extend(xudp_address(target));
    let mut bytes = (metadata.len() as u16).to_be_bytes().to_vec();
    bytes.extend(metadata);
    bytes.extend((payload.len() as u16).to_be_bytes());
    bytes.extend(payload);
    bytes
}

fn xudp_keep(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([2, 1]);
    let mut bytes = (metadata.len() as u16).to_be_bytes().to_vec();
    bytes.extend(metadata);
    bytes.extend((payload.len() as u16).to_be_bytes());
    bytes.extend(payload);
    bytes
}

fn xudp_end(id: u16) -> Vec<u8> {
    let [high, low] = id.to_be_bytes();
    vec![0, 4, high, low, 3, 0]
}

async fn xudp_recv(body: &mut FrameReader) -> (u16, u8, Vec<u8>) {
    let length = body.read_bytes(2).await;
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let metadata = body.read_bytes(length).await;
    let id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    assert_eq!(metadata[3] & 1, 1, "XUDP回包必须携带数据");
    let length = body.read_bytes(2).await;
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    (id, status, body.read_bytes(length).await)
}

#[tokio::test]
async fn vless_grpc_xudp_new_keep_and_end_round_trip() {
    let target = Echo::udp("127.0.0.1").await;
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;

    let mut header = vec![0];
    header.extend(uuid_bytes());
    header.extend([0, 3]);
    stream.send_data(frame(&header), false).unwrap();
    stream
        .send_data(frame(&xudp_new(7, target.address, b"new")), false)
        .unwrap();
    // VLESS 认证成功即发送唯一成功响应；Mux 帧在其后按序处理。
    assert_eq!(body.read_bytes(2).await, vec![0, 0]);
    assert_eq!(xudp_recv(&mut body).await, (7, 2, b"new".to_vec()));

    stream
        .send_data(frame(&xudp_keep(7, b"again")), false)
        .unwrap();
    assert_eq!(xudp_recv(&mut body).await, (7, 2, b"again".to_vec()));

    stream.send_data(frame(&xudp_end(7)), false).unwrap();
    timeout(WAIT, async {
        while server.stats.snapshot().udp_associations != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("End后必须回收UDP关联");

    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let _ = timeout(WAIT, body.body.trailers()).await;
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn xudp_association_is_joined_and_released_when_rpc_is_reset() {
    let target = Echo::udp("127.0.0.1").await;
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;

    let mut header = vec![0];
    header.extend(uuid_bytes());
    header.extend([0, 3]);
    stream.send_data(frame(&header), false).unwrap();
    stream
        .send_data(frame(&xudp_new(9, target.address, b"first")), false)
        .unwrap();
    assert_eq!(body.read_bytes(2).await, vec![0, 0]);
    assert_eq!(xudp_recv(&mut body).await, (9, 2, b"first".to_vec()));
    timeout(WAIT, async {
        while server.stats.snapshot().udp_associations != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("New后应存在UDP关联");

    // 不发送End，直接reset流，验证关联任务被真实join并归还额度。
    drop(stream);
    drop(body);
    timeout(WAIT, async {
        loop {
            let snapshot = server.stats.snapshot();
            if snapshot.udp_associations == 0 && snapshot.grpc_streams == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("RST后必须回收UDP关联与RPC额度");

    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn silent_client_is_closed_at_handshake_deadline() {
    let mut value = config(None, None);
    value["limits"]["handshake_timeout_ms"] = json!(200);
    let server = Running::start(value).await;
    let mut socket = TcpStream::connect(server.address).await.unwrap();
    let mut buffer = [0u8; 16];
    let closed = timeout(Duration::from_secs(2), async {
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "静默连接必须在握手绝对期限内关闭");
    server.shutdown().await;
}

#[tokio::test]
async fn truncated_authentication_message_never_dials() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;
    let request = vless_request(address);
    stream.send_data(frame(&request[..10]), false).unwrap();
    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    if let Ok(Some(_)) = timeout(Duration::from_millis(500), body.next()).await {
        panic!("截断认证不得产生业务响应");
    }
    assert!(
        timeout(Duration::from_millis(300), target.accept())
            .await
            .is_err(),
        "截断认证不得拨号目标"
    );
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn oversized_message_prefix_is_rejected_before_dial() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;
    let mut wire = vec![0u8];
    wire.extend_from_slice(&((1u32 << 20) + 1).to_be_bytes());
    wire.extend_from_slice(&vless_request(address));
    stream
        .send_data(prost::bytes::Bytes::from(wire), false)
        .unwrap();
    if let Ok(Some(_)) = timeout(Duration::from_millis(500), body.next()).await {
        panic!("超过1MiB的消息不得产生业务响应");
    }
    assert!(
        timeout(Duration::from_millis(300), target.accept())
            .await
            .is_err(),
        "超过1MiB的消息不得完成认证或拨号"
    );
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

/// 只读取并返回全部上行的目标；没有下行，避免测试端不并发读时形成回环背压。
async fn counting_sink() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await.unwrap();
        received
    });
    (address, task)
}

#[tokio::test]
async fn large_messages_cross_poll_budgets_and_flow_control() {
    let (address, sink) = counting_sink().await;
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;
    stream
        .send_data(frame(&vless_request(address)), false)
        .unwrap();
    assert_eq!(body.next().await.expect("VLESS应答"), vec![0, 0]);

    // 恰好1MiB的protobuf消息（Hunk开销4字节）必须跨多个65535窗完成。
    let payload: Vec<u8> = (0..(1 << 20) - 4)
        .map(|index| (index % 251) as u8)
        .collect();
    let mut expected = payload.clone();
    send_wire(&mut stream, frame(&payload)).await;
    // 1/7/17字节短写也必须保持完整消息边界。
    for small in [&b"x"[..], &b"1234567"[..], &[7u8; 17][..]] {
        stream.send_data(frame(small), false).unwrap();
        expected.extend_from_slice(small);
    }
    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();

    let received = timeout(WAIT, sink)
        .await
        .expect("目标应收到完整上行")
        .unwrap();
    assert_eq!(received, expected);
    let _ = timeout(WAIT, body.body.trailers()).await;
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn stop_drains_active_rpc_and_stops_admitting_new_ones() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config(None, None);
    value["limits"]["shutdown_timeout_ms"] = json!(1000);
    let server = Running::start(value).await;
    let (mut send_request, connection) =
        h2::client::handshake(TcpStream::connect(server.address).await.unwrap())
            .await
            .unwrap();
    let driver = tokio::spawn(connection);

    let (response, mut first) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = FrameReader::new(response.into_body());
    first
        .send_data(frame(&vless_request(echo.address)), false)
        .unwrap();
    assert_eq!(body.next().await.expect("VLESS应答"), vec![0, 0]);

    server.stop_now();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 已接受的RPC在stop后仍可继续业务。
    first.send_data(frame(b"after-stop"), false).unwrap();
    assert_eq!(body.next().await.expect("stop后回显"), b"after-stop");

    // 新RPC要么被客户端按GOAWAY拒绝，要么得到固定503，不能进入业务。
    let rejected = match send_request.send_request(request("/GunService/Tun"), false) {
        Ok((response, stream)) => {
            let status = timeout(Duration::from_millis(500), response).await;
            drop(stream);
            match status {
                Ok(Ok(response)) => response.status() == 503,
                // GOAWAY或连接关闭导致请求未完成，同样未进入业务。
                _ => true,
            }
        }
        Err(_) => true,
    };
    assert!(rejected, "stop后新RPC必须被拒绝");

    first.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let trailers = timeout(WAIT, body.body.trailers())
        .await
        .expect("stop后应完成尾帧")
        .expect("尾帧方向未重置")
        .expect("应有grpc-status");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    drop(first);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

/// 目标先发数据并关闭写方向，但仍继续读取上行。
async fn early_fin_target() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"early").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut rest = Vec::new();
        socket.read_to_end(&mut rest).await.unwrap();
        rest
    });
    (address, task)
}

#[tokio::test]
async fn target_half_close_allows_continued_uplink() {
    let (address, target) = early_fin_target().await;
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;
    stream
        .send_data(frame(&vless_request(address)), false)
        .unwrap();
    assert_eq!(body.next().await.expect("VLESS应答"), vec![0, 0]);
    assert_eq!(body.next().await.expect("目标先FIN的数据"), b"early");

    stream.send_data(frame(b"after-target-fin"), false).unwrap();
    stream.send_data(prost::bytes::Bytes::new(), true).unwrap();
    assert_eq!(
        timeout(WAIT, target).await.unwrap().unwrap(),
        b"after-target-fin"
    );
    let _ = timeout(WAIT, body.body.trailers()).await;
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn incomplete_frame_header_times_out_without_further_io() {
    let mut value = config(None, None);
    value["limits"]["handshake_timeout_ms"] = json!(300);
    let server = Running::start(value).await;
    let mut socket = TcpStream::connect(server.address).await.unwrap();
    let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    bytes.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    // 只发送HEADERS帧头的前4字节，之后不再产生IO。
    bytes.extend_from_slice(&[0, 0, 0x10, 1]);
    socket.write_all(&bytes).await.unwrap();

    let started = std::time::Instant::now();
    let mut buffer = [0u8; 64];
    let closed = timeout(Duration::from_secs(2), async {
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "不完整帧头必须在绝对期限内关闭连接");
    assert!(started.elapsed() >= Duration::from_millis(200));
    server.shutdown().await;
}

#[tokio::test]
async fn one_connection_muxes_multiple_identities_and_targets() {
    let one = Echo::tcp("127.0.0.1", false).await;
    let two = Echo::tcp("127.0.0.1", false).await;
    let mut value = config(None, None);
    value["inbounds"][0]["users"] = json!([
        {"name":"one","uuid":UUID_ONE},
        {"name":"two","uuid":UUID_TWO}
    ]);
    let server = Running::start(value).await;
    let (mut send_request, connection) =
        h2::client::handshake(TcpStream::connect(server.address).await.unwrap())
            .await
            .unwrap();
    let driver = tokio::spawn(connection);

    let (first_response, mut first) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let (second_response, mut second) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let first_response = timeout(WAIT, first_response).await.unwrap().unwrap();
    let second_response = timeout(WAIT, second_response).await.unwrap().unwrap();
    assert_eq!(first_response.status(), 200);
    assert_eq!(second_response.status(), 200);
    let mut first_body = FrameReader::new(first_response.into_body());
    let mut second_body = FrameReader::new(second_response.into_body());

    first
        .send_data(
            frame(&vless_with_uuid(uuid_of(UUID_ONE), 1, one.address)),
            false,
        )
        .unwrap();
    second
        .send_data(
            frame(&vless_with_uuid(uuid_of(UUID_TWO), 1, two.address)),
            false,
        )
        .unwrap();
    assert_eq!(first_body.next().await.expect("身份1应答"), vec![0, 0]);
    assert_eq!(second_body.next().await.expect("身份2应答"), vec![0, 0]);

    first.send_data(frame(b"one"), false).unwrap();
    second.send_data(frame(b"two"), false).unwrap();
    assert_eq!(first_body.next().await.expect("目标1回显"), b"one");
    assert_eq!(second_body.next().await.expect("目标2回显"), b"two");

    // 两条RPC可交替取得进展，互不串流。
    second.send_data(frame(b"progress"), false).unwrap();
    assert_eq!(second_body.next().await.expect("另一RPC进展"), b"progress");

    timeout(WAIT, async {
        while server.stats.snapshot().grpc_streams != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        server.stats.snapshot().connections,
        1,
        "同一物理TCP只计一次"
    );

    first.send_data(prost::bytes::Bytes::new(), true).unwrap();
    second.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let _ = timeout(WAIT, first_body.body.trailers()).await;
    let _ = timeout(WAIT, second_body.body.trailers()).await;
    drop(first);
    drop(second);
    drop(first_body);
    drop(second_body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn vmess_grpc_packetaddr_udp_over_tls() {
    let cert = Certificate::new();
    let target = Echo::udp("127.0.0.1").await;
    let mut inbound = grpc_inbound("vmess-grpc", Some(&cert));
    inbound["packetaddr"] = json!(true);
    let server = Running::start(with_inbound(inbound)).await;
    let tls = tls_h2(&cert, server.address).await;
    let (mut send_request, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let app = client_bridge(response, stream);
    let mut client = vmess_client::Client::start(
        app,
        vmess_client::Request::new(
            2,
            vmess_client::domain("sp.packet-addr.v2fly.arpa", 0),
            4,
            13,
        ),
        None,
    )
    .await;
    let packet = vmess_client::packetaddr(target.address, b"packet");
    client.send(&packet).await;
    assert_eq!(timeout(WAIT, client.recv()).await.unwrap(), packet);
    client.io.shutdown().await.unwrap();
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn vmess_grpc_native_udp_over_tls() {
    let cert = Certificate::new();
    let target = Echo::udp("127.0.0.1").await;
    let server = Running::start(with_inbound(grpc_inbound("vmess-grpc", Some(&cert)))).await;
    let tls = tls_h2(&cert, server.address).await;
    let (mut send_request, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, stream) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let app = client_bridge(response, stream);
    let mut client = vmess_client::Client::start(
        app,
        vmess_client::Request::new(2, vmess_client::target(target.address), 3, 1),
        None,
    )
    .await;
    client.send(b"native-udp").await;
    assert_eq!(timeout(WAIT, client.recv()).await.unwrap(), b"native-udp");
    client.io.shutdown().await.unwrap();
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn trojan_grpc_split_digest_and_second_user() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut inbound = grpc_inbound("trojan-grpc", None);
    inbound["users"] = json!([
        {"name":"alice","password":"test-secret-password"},
        {"name":"bob","password":"second-secret-password"}
    ]);
    let server = Running::start(with_inbound(inbound)).await;
    let (mut send_request, connection) =
        h2::client::handshake(TcpStream::connect(server.address).await.unwrap())
            .await
            .unwrap();
    let driver = tokio::spawn(connection);

    let (first_response, mut first) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let (second_response, mut second) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let first_response = timeout(WAIT, first_response).await.unwrap().unwrap();
    let second_response = timeout(WAIT, second_response).await.unwrap().unwrap();
    assert_eq!(first_response.status(), 200);
    assert_eq!(second_response.status(), 200);
    let mut first_body = FrameReader::new(first_response.into_body());
    let mut second_body = FrameReader::new(second_response.into_body());

    // 认证头在任意字节边界拆成两个gRPC消息。
    let hello = trojan_hello("test-secret-password", echo.address, b"split");
    let (head, tail) = hello.split_at(37);
    first.send_data(frame(head), false).unwrap();
    first.send_data(frame(tail), false).unwrap();
    assert_eq!(first_body.next().await.expect("拆分认证回显"), b"split");

    second
        .send_data(
            frame(&trojan_hello(
                "second-secret-password",
                echo.address,
                b"second-user",
            )),
            false,
        )
        .unwrap();
    assert_eq!(
        second_body.next().await.expect("第二用户回显"),
        b"second-user"
    );

    first.send_data(prost::bytes::Bytes::new(), true).unwrap();
    second.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let _ = timeout(WAIT, first_body.body.trailers()).await;
    let _ = timeout(WAIT, second_body.body.trailers()).await;
    drop(first);
    drop(second);
    drop(first_body);
    drop(second_body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn grpc_stream_gauge_and_per_connection_limit_are_enforced() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config(None, None);
    value["limits"]["max_grpc_streams_per_connection"] = json!(1);
    let server = Running::start(value).await;
    let (mut send_request, connection) =
        h2::client::handshake(TcpStream::connect(server.address).await.unwrap())
            .await
            .unwrap();
    let driver = tokio::spawn(connection);

    let (response, mut first) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = FrameReader::new(response.into_body());
    first
        .send_data(frame(&vless_request(echo.address)), false)
        .unwrap();
    assert_eq!(body.next().await.expect("VLESS应答"), vec![0, 0]);

    timeout(WAIT, async {
        while server.stats.snapshot().grpc_streams != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let snapshot = server.stats.snapshot();
    assert_eq!(snapshot.connections, 1, "物理TCP只计一次");
    assert_eq!(snapshot.grpc_streams, 1);

    // 每连接并发上限由h2 SETTINGS通告；第2个RPC在首RPC结束前不得被服务端接受。
    let (mut response, second) = send_request
        .send_request(request("/GunService/Tun"), false)
        .unwrap();
    assert!(
        timeout(Duration::from_millis(150), &mut response)
            .await
            .is_err(),
        "超过每连接上限的RPC不得提前完成"
    );

    first.send_data(prost::bytes::Bytes::new(), true).unwrap();
    let _ = timeout(WAIT, body.body.trailers()).await;
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut second = second;
    second.send_data(prost::bytes::Bytes::new(), true).unwrap();
    drop(second);
    drop(first);
    drop(body);
    timeout(WAIT, async {
        while server.stats.snapshot().grpc_streams != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn grpc_admission_accepts_missing_te_identity_and_custom_user_agent() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(config(None, None)).await;
    let io = TcpStream::connect(server.address).await.unwrap();
    let (mut send_request, connection) = h2::client::handshake(io).await.unwrap();
    let driver = tokio::spawn(connection);
    let mut request = request("/GunService/Tun");
    request.headers_mut().remove("te");
    request
        .headers_mut()
        .insert("grpc-encoding", http::HeaderValue::from_static("identity"));
    request.headers_mut().insert(
        "user-agent",
        http::HeaderValue::from_static("custom-ua/1.0"),
    );
    let (response, mut stream) = send_request.send_request(request, false).unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    let mut body = FrameReader::new(response.into_body());
    timeout(
        WAIT,
        vless_tcp_round_trip(&mut stream, &mut body, echo.address),
    )
    .await
    .unwrap();
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn grpc_authentication_failure_never_emits_ok_trailers() {
    let server = Running::start(config(None, None)).await;
    let (mut stream, mut body, driver) = plain_client(server.address, "/GunService/Tun").await;
    stream
        .send_data(
            frame(&vless_with_uuid(
                uuid_of(UUID_TWO),
                1,
                "127.0.0.1:9".parse().unwrap(),
            )),
            false,
        )
        .unwrap();
    let trailers = timeout(WAIT, body.body.trailers()).await.unwrap();
    assert!(
        !matches!(
            &trailers,
            Ok(Some(trailers))
                if trailers.get("grpc-status").is_some_and(|value| value == "0")
        ),
        "认证失败不得以grpc-status 0伪装成功: {trailers:?}"
    );
    drop(stream);
    drop(body);
    driver.abort();
    server.shutdown().await;
}

fn grpc_outbound_config(transport: Value) -> bool {
    let value = json!({
        "version": 1,
        "inbounds": [{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],
        "outbounds": [{
            "type":"vless","tag":"up","endpoint":"127.0.0.1:443","uuid":UUID_ONE,
            "transport": transport
        }],
        "route": {"default":"up"}
    });
    dubhe::Config::from_json(&value.to_string())
        .and_then(|config| config.validate().map(|()| config))
        .is_ok()
}

#[test]
fn grpc_transport_accepts_xray_client_tuning_fields() {
    for transport in [
        json!({"type":"grpc","path":"/GunService/Tun","authority":"front.example"}),
        json!({"type":"grpc","path":"/GunService/Tun","user_agent":"chrome"}),
        json!({"type":"grpc","path":"/GunService/Tun","user_agent":"custom-ua/1.0"}),
        json!({"type":"grpc","path":"/GunService/Tun","idle_timeout":30}),
        json!({"type":"grpc","path":"/GunService/Tun","health_check_timeout":10}),
        json!({"type":"grpc","path":"/GunService/Tun","permit_without_stream":true}),
        json!({"type":"grpc","path":"/GunService/Tun","initial_windows_size":1048576}),
        json!({"type":"grpc","path":"/GunService/Tun","initial_windows_size":0}),
    ] {
        assert!(grpc_outbound_config(transport.clone()), "{transport}");
    }
}

#[test]
fn grpc_transport_rejects_misplaced_or_invalid_tuning_fields() {
    for transport in [
        json!({"type":"ws","user_agent":"chrome"}),
        json!({"type":"httpupgrade","idle_timeout":30}),
        json!({"type":"grpc","path":"/GunService/Tun","authority":"bad\r\nvalue"}),
        json!({"type":"grpc","path":"/GunService/Tun","user_agent":"bad\r\nvalue"}),
        json!({"type":"grpc","path":"/GunService/Tun","idle_timeout":86401}),
        json!({"type":"grpc","path":"/GunService/Tun","health_check_timeout":86401}),
        json!({"type":"grpc","path":"/GunService/Tun","initial_windows_size":2147483648u32}),
    ] {
        assert!(!grpc_outbound_config(transport.clone()), "{transport}");
    }
}
