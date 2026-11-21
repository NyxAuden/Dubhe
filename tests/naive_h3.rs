//! Naive普通H3 CONNECT独立回环：不是扩展CONNECT。
mod common;
#[path = "common/h3_connect.rs"]
mod h3_connect;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Buf, Bytes};
use common::{Certificate, Echo, Running};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
type Quic = h3_connect::Connect;
type Bidi = <Quic as h3::quic::OpenStreams<Bytes>>::BidiStream;
type Stream = h3::client::RequestStream<Bidi, Bytes>;
const WAIT: Duration = Duration::from_secs(3);
fn config(cert: &Certificate) -> Value {
    json!({"version":1,
    "inbounds":[{"type":"naive","tag":"naive","listen":"127.0.0.1:0","h3":true,
        "users":[{"name":"u","password":"p"}],"certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],
    "outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],"route":{"default":"direct"},
    "limits":{"shutdown_timeout_ms":500,"handshake_timeout_ms":500}})
}
struct Client {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    driver: tokio::task::JoinHandle<()>,
    requests: h3::client::SendRequest<h3_connect::Opener, Bytes>,
    stream: Stream,
    status: http::StatusCode,
    headers: http::HeaderMap,
    stash: Vec<u8>,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"done");
        self.driver.abort();
    }
}
impl Client {
    async fn connect(
        cert: &Certificate,
        address: SocketAddr,
        target: SocketAddr,
        credentials: &str,
        padding: bool,
    ) -> Self {
        Self::connect_with_fields(cert, address, target, credentials, padding, &[]).await
    }
    async fn connect_with_fields(
        cert: &Certificate,
        address: SocketAddr,
        target: SocketAddr,
        credentials: &str,
        padding: bool,
        extra: &[(&str, &str)],
    ) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der.clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connection = timeout(WAIT, endpoint.connect(address, "localhost").unwrap())
            .await
            .unwrap()
            .unwrap();
        let authority = target.to_string();
        let authorization = format!("Basic {}", STANDARD.encode(credentials));
        let mut fields = vec![
            (":method", "CONNECT"),
            (":authority", authority.as_str()),
            ("proxy-authorization", authorization.as_str()),
        ];
        if padding {
            fields.push(("padding", "test-padding"));
        }
        fields.extend_from_slice(extra);
        let (mut h3, mut requests) = h3::client::builder()
            .build::<_, _, Bytes>(Quic::new(connection.clone(), &fields))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| h3.poll_close(cx)).await;
        });
        let mut request = http::Request::builder()
            .method("CONNECT")
            .uri(target.to_string())
            .header(
                "proxy-authorization",
                format!("Basic {}", STANDARD.encode(credentials)),
            );
        if padding {
            request = request.header("padding", "test-padding");
        }
        let mut stream = timeout(WAIT, requests.send_request(request.body(()).unwrap()))
            .await
            .unwrap()
            .unwrap();
        let response = timeout(WAIT, stream.recv_response())
            .await
            .unwrap()
            .unwrap();
        Self {
            endpoint,
            connection,
            driver,
            requests,
            stream,
            status: response.status(),
            headers: response.headers().clone(),
            stash: Vec::new(),
        }
    }
    async fn another(&mut self) -> Result<Stream, h3::error::StreamError> {
        let request = http::Request::builder()
            .method("CONNECT")
            .uri("127.0.0.1:1")
            .body(())
            .unwrap();
        // backend按同一组固定字段替换HEADERS，目标/认证与首流一致。
        self.requests.send_request(request).await
    }
    async fn fill(&mut self, needed: usize) {
        timeout(WAIT, async {
            while self.stash.len() < needed {
                let mut data = self.stream.recv_data().await.unwrap().expect("H3提早结束");
                while data.has_remaining() {
                    let chunk = data.chunk();
                    self.stash.extend_from_slice(chunk);
                    let length = chunk.len();
                    data.advance(length);
                }
            }
        })
        .await
        .unwrap();
    }
    async fn read_padded(&mut self) -> Vec<u8> {
        self.fill(3).await;
        let length = usize::from(u16::from_be_bytes([self.stash[0], self.stash[1]]));
        let padding = usize::from(self.stash[2]);
        self.fill(3 + length + padding).await;
        let payload = self.stash[3..3 + length].to_vec();
        self.stash.drain(..3 + length + padding);
        payload
    }
}
fn padded(payload: &[u8]) -> Vec<u8> {
    let mut bytes = (payload.len() as u16).to_be_bytes().to_vec();
    bytes.push(7);
    bytes.extend(payload);
    bytes.resize(3 + payload.len() + 7, 0);
    bytes
}
#[tokio::test]
async fn h3_padding_first_eight_then_raw_and_same_port_h1_h2() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config(&cert)).await;
    let address = running.address;
    let mut client = Client::connect(&cert, address, echo.address, "u:p", true).await;
    assert_eq!(client.status, http::StatusCode::OK);
    let header = client.headers.get("padding").unwrap().as_bytes();
    assert!((30..=61).contains(&header.len()));
    assert!(
        header[..16]
            .iter()
            .all(|byte| b"!#$()+<>?@[]^`{}".contains(byte))
    );
    assert!(header[16..].iter().all(|byte| *byte == b'~'));
    for value in 0u8..8 {
        client
            .stream
            .send_data(Bytes::from(padded(&[value])))
            .await
            .unwrap();
        assert_eq!(client.read_padded().await, vec![value]);
    }
    client
        .stream
        .send_data(Bytes::from_static(b"ninth-raw"))
        .await
        .unwrap();
    client.fill(9).await;
    assert_eq!(client.stash, b"ninth-raw");
    let mut h1 = cert.connect_alpn(address, &[b"http/1.1"]).await;
    h1.write_all(format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\nPadding: test\r\n\r\n",echo.address,echo.address,STANDARD.encode("u:p")).as_bytes()).await.unwrap();
    let mut head = Vec::new();
    loop {
        let byte = h1.read_u8().await.unwrap();
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    // 固定上游H1不启用payload padding，即使有Padding头也必须裸传。
    h1.write_all(b"h1-raw").await.unwrap();
    let mut reply = [0; 6];
    h1.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"h1-raw");
    let tls = cert.connect_alpn(address, &[b"h2"]).await;
    let (mut requests, driver) = h2::client::handshake(tls).await.unwrap();
    let h2_driver = tokio::spawn(driver);
    let request = http::Request::builder()
        .method("CONNECT")
        .uri(echo.address.to_string())
        .header(
            "proxy-authorization",
            format!("Basic {}", STANDARD.encode("u:p")),
        )
        .body(())
        .unwrap();
    let (response, mut send) = requests.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    send.send_data(Bytes::from_static(b"h2-raw"), false)
        .unwrap();
    let mut body = response.into_body();
    assert_eq!(&body.data().await.unwrap().unwrap()[..], b"h2-raw");
    drop(h1);
    h2_driver.abort();
    running.shutdown().await;
    drop(client);
    UdpSocket::bind(address).await.expect("H3停机释放UDP端口");
    TcpListener::bind(address).await.expect("H3停机释放TCP端口");
}
#[tokio::test]
async fn explicit_h1_padding_option_does_not_change_h3_padding_or_plain_modes() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config(&cert);
    value["inbounds"][0]["h1_padding"] = json!(true);
    let running = Running::start(value).await;
    for padding in [false, true] {
        let mut client =
            Client::connect(&cert, running.address, echo.address, "u:p", padding).await;
        assert_eq!(client.status, http::StatusCode::OK);
        assert_eq!(client.headers.contains_key("padding"), padding);
        let data = if padding {
            padded(b"h3-unchanged")
        } else {
            b"h3-unchanged".to_vec()
        };
        client.stream.send_data(Bytes::from(data)).await.unwrap();
        if padding {
            assert_eq!(client.read_padded().await, b"h3-unchanged");
        } else {
            client.fill(12).await;
            assert_eq!(client.stash, b"h3-unchanged");
        }
    }
    running.shutdown().await;
}

#[tokio::test]
async fn h3_without_padding_is_plain_connect() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let running = Running::start(config(&cert)).await;
    let mut client = Client::connect(&cert, running.address, echo.address, "u:p", false).await;
    assert_eq!(client.status, http::StatusCode::OK);
    assert!(!client.headers.contains_key("padding"));
    client
        .stream
        .send_data(Bytes::from_static(b"plain"))
        .await
        .unwrap();
    client.fill(5).await;
    assert_eq!(client.stash, b"plain");
    let stats = running.stats.snapshot();
    assert_eq!(stats.uplink, 5);
    assert_eq!(stats.downlink, 5);
    running.shutdown().await;
}
#[tokio::test]
async fn h3_wrong_auth_and_reject_route_are_zero_target_traffic() {
    let cert = Certificate::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let running = Running::start(config(&cert)).await;
    let client = Client::connect(&cert, running.address, address, "u:wrong", true).await;
    assert_eq!(
        client.status,
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    drop(client);
    running.shutdown().await;
    let mut value = config(&cert);
    value["route"]["default"] = json!("reject");
    let running = Running::start(value).await;
    let client = Client::connect(&cert, running.address, address, "u:p", true).await;
    assert_eq!(client.status, http::StatusCode::BAD_GATEWAY);
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    assert_eq!(running.stats.snapshot().uplink, 0);
    running.shutdown().await;
    drop(client);
}
#[tokio::test]
async fn h3_fin_keeps_reverse_direction_and_padding_bytes_intact() {
    for padding in [false, true] {
        let cert = Certificate::new();
        let echo = Echo::tcp("127.0.0.1", true).await;
        let running = Running::start(config(&cert)).await;
        let mut client =
            Client::connect(&cert, running.address, echo.address, "u:p", padding).await;
        assert_eq!(client.status, http::StatusCode::OK);
        let payload = b"reply-only-after-client-fin";
        client
            .stream
            .send_data(Bytes::from(if padding {
                padded(payload)
            } else {
                payload.to_vec()
            }))
            .await
            .unwrap();
        client.stream.finish().await.unwrap();
        if padding {
            assert_eq!(client.read_padded().await, payload);
        } else {
            client.fill(payload.len()).await;
            assert_eq!(client.stash, payload);
        }
        assert!(
            timeout(WAIT, client.stream.recv_data())
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        running.shutdown().await;
    }
}

#[tokio::test]
async fn h3_rejects_non_connect_pseudo_headers_and_duplicate_credentials() {
    let cert = Certificate::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let running = Running::start(config(&cert)).await;
    for (extra, status) in [
        (
            vec![(":scheme", "https"), (":path", "/")],
            http::StatusCode::BAD_REQUEST,
        ),
        (
            vec![(":protocol", "connect-udp")],
            http::StatusCode::BAD_REQUEST,
        ),
        (
            vec![("proxy-authorization", "Basic dTpw")],
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        ),
    ] {
        let client =
            Client::connect_with_fields(&cert, running.address, address, "u:p", false, &extra)
                .await;
        assert_eq!(client.status, status);
    }
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    assert_eq!(running.stats.snapshot().uplink, 0);
    running.shutdown().await;
}

#[tokio::test]
async fn h3_slow_headers_do_not_block_another_stream_and_stream_limit_recovers() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config(&cert);
    value["limits"]["max_grpc_streams_per_connection"] = json!(2);
    let running = Running::start(value).await;
    let mut client = Client::connect(&cert, running.address, echo.address, "u:p", false).await;
    assert_eq!(client.status, http::StatusCode::OK);
    let (mut slow_send, slow_recv) = client.connection.open_bi().await.unwrap();
    slow_send.write_all(&[1, 16, 0]).await.unwrap(); // 未完成 HEADERS：占一个流，但不能阻塞连接循环。
    client
        .stream
        .send_data(Bytes::from_static(b"alive"))
        .await
        .unwrap();
    client.fill(5).await;
    assert_eq!(client.stash, b"alive");
    let blocked = timeout(Duration::from_millis(100), client.another()).await;
    assert!(blocked.is_err(), "第三个流应受 QUIC 每连接并发上限阻塞");
    let _ = slow_send.reset(0u32.into());
    drop(slow_recv);
    let mut next = timeout(WAIT, client.another()).await.unwrap().unwrap();
    assert_eq!(
        timeout(WAIT, next.recv_response())
            .await
            .unwrap()
            .unwrap()
            .status(),
        http::StatusCode::OK
    );
    drop(next);
    drop(client);
    running.shutdown().await;
}

#[tokio::test]
async fn h2_h3_share_global_stream_and_connection_budgets() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut value = config(&cert);
    value["limits"]["max_grpc_streams"] = json!(1);
    value["limits"]["max_grpc_streams_per_connection"] = json!(1);
    let running = Running::start(value).await;
    let tls = cert.connect_alpn(running.address, &[b"h2"]).await;
    let (mut requests, driver) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(driver);
    let request = http::Request::builder()
        .method("CONNECT")
        .uri(echo.address.to_string())
        .header(
            "proxy-authorization",
            format!("Basic {}", STANDARD.encode("u:p")),
        )
        .body(())
        .unwrap();
    let (response, mut send) = requests.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    // 占满 H2 全局流预算后，H3 请求应被标准复位，不能拨目标或损坏已有连接。
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut tls = tls;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));
    let connection = endpoint
        .connect(running.address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let target = echo.address.to_string();
    let auth = format!("Basic {}", STANDARD.encode("u:p"));
    let (mut h3, mut h3_requests) = h3::client::builder()
        .build::<_, _, Bytes>(Quic::new(
            connection,
            &[
                (":method", "CONNECT"),
                (":authority", &target),
                ("proxy-authorization", &auth),
            ],
        ))
        .await
        .unwrap();
    let h3_driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3.poll_close(cx)).await;
    });
    let request = || {
        http::Request::builder()
            .method("CONNECT")
            .uri(target.as_str())
            .body(())
            .unwrap()
    };
    let mut stream = timeout(WAIT, h3_requests.send_request(request()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(WAIT, stream.recv_response())
            .await
            .unwrap()
            .is_err()
    );
    assert!(running.stats.snapshot().rejected > 0);
    assert_eq!(running.stats.snapshot().tcp_flows, 1);
    send.send_reset(h2::Reason::CANCEL);
    drop(response);
    drop(stream);
    // reset的处理由连接驱动异步完成，重试仍只允许标准失败，不允许绕过预算。
    timeout(WAIT, async {
        loop {
            let mut stream = h3_requests.send_request(request()).await.unwrap();
            if let Ok(response) = stream.recv_response().await {
                assert_eq!(response.status(), http::StatusCode::OK);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    endpoint.close(0u32.into(), b"done");
    h3_driver.abort();
    driver.abort();
    running.shutdown().await;

    // 连接预算也共享：已有H3连接占满时，同入口新的TCP握手不得另开预算。
    let mut value = config(&cert);
    value["limits"]["max_connections"] = json!(1);
    let running = Running::start(value).await;
    let client = Client::connect(&cert, running.address, echo.address, "u:p", false).await;
    assert_eq!(client.status, http::StatusCode::OK);
    assert!(
        cert.try_connect_alpn(running.address, &[b"h2"])
            .await
            .is_err()
    );
    assert_eq!(running.stats.snapshot().connections, 1);
    drop(client);
    running.shutdown().await;
}

#[tokio::test]
async fn h3_shutdown_reclaims_blocked_writes_and_partial_headers() {
    let cert = Certificate::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running::start(config(&cert)).await;
    let address = running.address;
    let client = Client::connect(&cert, address, target.local_addr().unwrap(), "u:p", false).await;
    assert_eq!(client.status, http::StatusCode::OK);
    let (mut peer, _) = target.accept().await.unwrap();
    let flood = tokio::spawn(async move {
        let bytes = [1; 65536];
        loop {
            if peer.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
    let (mut partial, _recv) = client.connection.open_bi().await.unwrap();
    partial.write_all(&[1, 16, 0]).await.unwrap();
    // 不消费H3 body，等待至少一个QUIC接收窗口的目标数据被接受，随后停机。
    timeout(WAIT, async {
        while running.stats.snapshot().downlink < 65536 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    running.shutdown().await;
    timeout(WAIT, flood).await.unwrap().unwrap();
    drop(client);
    drop(partial);
    let _udp = common::rebind_udp(address).await;
    TcpListener::bind(address).await.unwrap();
}

#[test]
fn h3_config_is_optional_and_roundtrips() {
    let cert = Certificate::new();
    let mut value = config(&cert);
    value["inbounds"][0].as_object_mut().unwrap().remove("h3");
    let config = dubhe::Config::from_json(&value.to_string()).unwrap();
    assert_eq!(
        serde_json::to_value(config).unwrap()["inbounds"][0]["h3"],
        false
    );
}
