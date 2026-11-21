//! ShadowTLS v3 出站回环：真实 TLS 外观 + 内层 Shadowsocks。
//!
//! 只使用回环地址、自签证书与临时端口；真实 TLS target 完成标准 TLS 握手，
//! ShadowTLS 服务器把认证后的内层流转给同进程 Shadowsocks detour。HRR 用例在
//! ShadowTLS 服务器与 TLS target 之间插入独立记录转发器，实际计数两个
//! ClientHello，避免仅凭配置推断 HRR。

mod common;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{Certificate, Echo, Running};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "shadowtls-outbound-loopback-secret";
const SS_SECRET: [u8; 16] = [0x5a; 16];

fn ss_password() -> String {
    STANDARD.encode(SS_SECRET)
}

async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut frame = vec![0u8; 5 + length];
    frame[..5].copy_from_slice(&header);
    stream.read_exact(&mut frame[5..]).await?;
    Ok(frame)
}

/// 真实标准 TLS target；TLS 1.3-only，握手后等待对端 EOF。
struct TlsTarget {
    address: SocketAddr,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TlsTarget {
    async fn start(certificate: &Certificate, force_hrr: bool) -> Self {
        let certificates = CertificateDer::pem_file_iter(certificate.dir.path().join("cert.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(certificate.dir.path().join("key.pem")).unwrap();
        let mut provider = rustls::crypto::ring::default_provider();
        if force_hrr {
            // 只保留 P-256，客户端默认 key share 不会命中，从而触发真实 HRR。
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
        }
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        config.send_tls13_tickets = 0;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { break };
                        let acceptor = acceptor.clone();
                        connections.spawn(async move {
                            let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                            let mut buffer = [0u8; 1024];
                            while let Ok(count) = tls.read(&mut buffer).await {
                                if count == 0 {
                                    break;
                                }
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
        });
        Self {
            address,
            stop,
            task: Some(task),
        }
    }
}

impl Drop for TlsTarget {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// 在 ShadowTLS 服务器与真实 TLS target 之间逐记录转发，并统计 ClientHello。
struct CountingProxy {
    address: SocketAddr,
    client_hellos: Arc<AtomicUsize>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl CountingProxy {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client_hellos = Arc::new(AtomicUsize::new(0));
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let count = client_hellos.clone();
        let task = tokio::spawn(async move {
            let Ok((mut inbound, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut outbound) = TcpStream::connect(target).await else {
                return;
            };
            let (mut inbound_read, mut inbound_write) = inbound.split();
            let (mut outbound_read, mut outbound_write) = outbound.split();
            let upstream = async {
                loop {
                    let Ok(frame) = read_record(&mut inbound_read).await else {
                        return;
                    };
                    if frame[0] == 22 && frame.get(5) == Some(&1) {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    if outbound_write.write_all(&frame).await.is_err() {
                        return;
                    }
                }
            };
            let downstream = async {
                loop {
                    let Ok(frame) = read_record(&mut outbound_read).await else {
                        return;
                    };
                    if inbound_write.write_all(&frame).await.is_err() {
                        return;
                    }
                }
            };
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = upstream => {}
                _ = downstream => {}
            }
        });
        Self {
            address,
            client_hellos,
            stop,
            task: Some(task),
        }
    }

    async fn wait_for_client_hellos(&self, expected: usize) {
        timeout(Duration::from_secs(5), async {
            while self.client_hellos.load(Ordering::SeqCst) < expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("未观察到预期 ClientHello 数量");
        assert_eq!(self.client_hellos.load(Ordering::SeqCst), expected);
    }
}

impl Drop for CountingProxy {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn stls_config(handshake: SocketAddr) -> Value {
    json!({
        "version": 1,
        "inbounds": [
            {
                "type": "shadowtls",
                "tag": "stls",
                "listen": "127.0.0.1:0",
                "version": 3,
                "users": [{"name": "u", "password": PASSWORD}],
                "handshake": {"server": "127.0.0.1", "server_port": handshake.port()},
                "strict_mode": true,
                "detour": "inner"
            },
            {
                "type": "shadowsocks",
                "tag": "inner",
                "listen": "127.0.0.1:0",
                "method": "2022-blake3-aes-128-gcm",
                "password": ss_password()
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "limits": {"handshake_timeout_ms": 5000, "shutdown_timeout_ms": 1000}
    })
}

fn downstream_config(stls: SocketAddr, certificate: &Certificate) -> Value {
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [
            {
                "type": "shadowtls",
                "tag": "stls-out",
                "endpoint": stls.to_string(),
                "password": PASSWORD,
                "tls": {
                    "ca_file": certificate.dir.path().join("cert.pem"),
                    "server_name": "localhost"
                }
            },
            {
                "type": "shadowsocks",
                "tag": "inner-out",
                "endpoint": stls.to_string(),
                "method": "2022-blake3-aes-128-gcm",
                "password": ss_password(),
                "via": "stls-out"
            }
        ],
        "route": {"default": "inner-out"},
        "limits": {"handshake_timeout_ms": 5000, "shutdown_timeout_ms": 1000}
    })
}

async fn udp_associate(server: SocketAddr) -> (TcpStream, UdpSocket) {
    let mut control = TcpStream::connect(server).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    control.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut head = [0u8; 3];
    control.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0, "UDP ASSOCIATE 应成功");
    let bound = common::read_address(&mut control).await;
    let relay = if bound.ip().is_unspecified() {
        SocketAddr::new(control.peer_addr().unwrap().ip(), bound.port())
    } else {
        bound
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    (control, socket)
}

async fn assert_echo(local: SocketAddr, echo: SocketAddr) {
    let (mut stream, _) = common::socks(1, common::address(echo), local).await;
    stream.write_all(b"shadowtls-v3-e2e").await.unwrap();
    let mut reply = [0u8; 16];
    timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
        .await
        .expect("等待 Shadowsocks 回环超时")
        .unwrap();
    assert_eq!(&reply, b"shadowtls-v3-e2e");
}

async fn run_roundtrip(force_hrr: bool) {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let certificate = Certificate::new();
    let target = TlsTarget::start(&certificate, force_hrr).await;
    let proxy = CountingProxy::start(target.address).await;
    let stls = Running::start(stls_config(proxy.address)).await;
    let downstream = Running::start(downstream_config(stls.addresses[0], &certificate)).await;

    assert_echo(downstream.address, echo.address).await;
    proxy
        .wait_for_client_hellos(if force_hrr { 2 } else { 1 })
        .await;

    downstream.shutdown().await;
    stls.shutdown().await;
}

#[tokio::test]
async fn shadowsocks_over_shadowtls_roundtrip() {
    run_roundtrip(false).await;
}

#[tokio::test]
async fn shadowsocks_over_shadowtls_with_real_hrr() {
    run_roundtrip(true).await;
}

#[tokio::test]
async fn udp_via_shadowtls_fails_closed_instead_of_direct() {
    let echo = Echo::udp("127.0.0.1").await;
    let certificate = Certificate::new();
    let target = TlsTarget::start(&certificate, false).await;
    let proxy = CountingProxy::start(target.address).await;
    let stls = Running::start(stls_config(proxy.address)).await;
    let downstream = Running::start(downstream_config(stls.addresses[0], &certificate)).await;

    let (control, socket) = udp_associate(downstream.address).await;
    let mut packet = vec![0, 0, 0];
    packet.extend(common::address(echo.address));
    packet.extend(b"udp-shadowtls");
    socket.send(&packet).await.unwrap();
    let mut reply = [0u8; 128];
    assert!(
        timeout(Duration::from_millis(500), socket.recv(&mut reply))
            .await
            .is_err(),
        "ShadowTLS via 链不得承载 UDP，也不得静默直连"
    );
    drop(socket);
    drop(control);
    downstream.shutdown().await;
    stls.shutdown().await;
}

#[tokio::test]
async fn wrong_password_fails_closed_without_inner_flow() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let certificate = Certificate::new();
    let target = TlsTarget::start(&certificate, false).await;
    let proxy = CountingProxy::start(target.address).await;
    let stls = Running::start(stls_config(proxy.address)).await;
    let mut config = downstream_config(stls.addresses[0], &certificate);
    config["outbounds"][0]["password"] = json!("wrong-password");
    let downstream = Running::start(config).await;

    let mut local = TcpStream::connect(downstream.address).await.unwrap();
    timeout(Duration::from_secs(3), async {
        local.write_all(&[5, 1, 0]).await.unwrap();
        let mut methods = [0u8; 2];
        local.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [5, 0]);
        let mut request = vec![5, 1, 0];
        request.extend(common::address(echo.address));
        local.write_all(&request).await.unwrap();
        let mut head = [0u8; 3];
        match local.read(&mut head).await {
            Ok(0) => {}
            Ok(count) => assert_ne!(
                &head[..count],
                &[5, 0, 0][..count],
                "错误密码不得建立内层流"
            ),
            Err(_) => {}
        }
    })
    .await
    .expect("错误密码用例不得挂起");

    drop(local);
    downstream.shutdown().await;
    stls.shutdown().await;
}

fn parse(value: &Value) -> anyhow::Result<dubhe::Config> {
    dubhe::Config::from_json(&value.to_string())
}

#[test]
fn rejects_invalid_shadowtls_outbound_shapes() {
    let certificate = Certificate::new();
    let address = "127.0.0.1:443".parse::<SocketAddr>().unwrap();
    let valid = downstream_config(address, &certificate);
    assert!(parse(&valid).is_ok(), "合法最小配置应解析成功");

    // 用例表：名称 + 对配置 JSON 的定点破坏。
    type Case<'a> = (&'a str, Box<dyn Fn(&mut Value)>);
    let cases: Vec<Case> = vec![
        (
            "missing password",
            Box::new(|value: &mut Value| {
                value["outbounds"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("password");
            }),
        ),
        (
            "missing tls",
            Box::new(|value: &mut Value| {
                value["outbounds"][0].as_object_mut().unwrap().remove("tls");
            }),
        ),
        (
            "missing server_name",
            Box::new(|value: &mut Value| {
                value["outbounds"][0]["tls"]
                    .as_object_mut()
                    .unwrap()
                    .remove("server_name");
            }),
        ),
        (
            "IP server_name",
            Box::new(|value: &mut Value| {
                value["outbounds"][0]["tls"]["server_name"] = json!("127.0.0.1");
            }),
        ),
        (
            "shadowtls with via",
            Box::new(|value: &mut Value| {
                value["outbounds"][0]["via"] = json!("inner-out");
            }),
        ),
        (
            "endpoint mismatch",
            Box::new(|value: &mut Value| {
                value["outbounds"][1]["endpoint"] = json!("127.0.0.1:444");
            }),
        ),
        (
            "terminal route",
            Box::new(|value: &mut Value| {
                value["route"]["default"] = json!("stls-out");
            }),
        ),
        (
            "selector member",
            Box::new(|value: &mut Value| {
                value["outbounds"].as_array_mut().unwrap().push(json!({
                    "type": "selector",
                    "tag": "group",
                    "outbounds": ["stls-out", "inner-out"],
                    "default": "stls-out"
                }));
                value["route"]["default"] = json!("group");
            }),
        ),
    ];
    for (name, mutate) in cases {
        let mut value = valid.clone();
        mutate(&mut value);
        assert!(parse(&value).is_err(), "应拒绝: {name}");
    }
}
