//! WS 私有运行器门禁：自持 DNS、真实监听/映射及结束屏障，不依赖公网或官方客户端。
//! 不把这些有限场景扩称为每个协议/UDP 扩展的完整资源或容量证明。
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_resolver::config::ResolverOpts;
use serde_json::{Value, json};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[path = "../tests/common/websocket.rs"]
mod ws;
use super::tests::vmess_client as vmess_peer;

const KINDS: [&str; 3] = ["vless-ws", "vmess-ws", "trojan-ws"];
const PASSWORD: &str = "runtime-ws-local-test-only";
const WAIT: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(25);

trait Wire: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Wire for T {}
type Peer = ws::Peer<Box<dyn Wire>>;

struct Certificate {
    dir: tempfile::TempDir,
    connector: tokio_rustls::TlsConnector,
}
impl Certificate {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(dir.path().join("cert.pem"), certificate.cert.pem()).unwrap();
        let key = dir.path().join("key.pem");
        std::fs::write(&key, certificate.key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        Self {
            dir,
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        }
    }
    fn apply(&self, inbound: &mut Value) {
        inbound
            .as_object_mut()
            .unwrap()
            .remove("allow_insecure_transport");
        inbound["certificate"] = json!(self.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(self.dir.path().join("key.pem"));
    }
}

fn inbound(kind: &str, tag: &str) -> Value {
    let user = if kind == "trojan-ws" {
        json!({"name":"test", "password":PASSWORD})
    } else {
        json!({"name":"test", "uuid":vmess_peer::UUID})
    };
    let mut value = json!({"type":kind, "tag":tag, "listen":"127.0.0.1:0", "users":[user], "websocket":{"path":"/proxy"}});
    if kind != "vmess-ws" {
        value["allow_insecure_transport"] = json!(true);
    }
    value
}
fn configuration(kind: &str, certificate: Option<&Certificate>) -> Value {
    let mut entry = inbound(kind, "ws");
    if let Some(certificate) = certificate {
        certificate.apply(&mut entry);
    }
    json!({"version":1, "inbounds":[entry],
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],
        "route":{"default":"direct"},
        "limits":{"max_connections":4,"max_handshakes":3,"max_udp_associations":1,
            "max_dns_queries":1,"udp_queue_bytes":4096,"udp_queue_packets":1,
            "handshake_timeout_ms":10000,"dial_timeout_ms":10000,"dns_timeout_ms":10000,
            "udp_idle_timeout_ms":30000,"shutdown_timeout_ms":20}})
}
fn parse(value: &Value) -> Config {
    Config::from_json(&value.to_string()).unwrap()
}
fn inject_dns(server: &mut Server, address: SocketAddr) {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(10);
    opts.attempts = 1;
    opts.cache_size = 0;
    Arc::get_mut(&mut server.context).unwrap().dns = crate::dns::Dns::new(
        crate::dns::udp_resolver(address, opts).unwrap(),
        1,
        Duration::from_secs(10),
    );
}
async fn wait(mut predicate: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("运行器状态应有限收敛");
}
async fn wire(address: SocketAddr, certificate: Option<&Certificate>) -> Box<dyn Wire> {
    let stream = TcpStream::connect(address).await.unwrap();
    stream.set_nodelay(true).unwrap();
    match certificate {
        Some(certificate) => Box::new(
            certificate
                .connector
                .connect("localhost".try_into().unwrap(), stream)
                .await
                .unwrap(),
        ),
        None => Box::new(stream),
    }
}
async fn connect(address: SocketAddr, certificate: Option<&Certificate>) -> Peer {
    ws::upgrade(wire(address, certificate).await, "/proxy", "", &[]).await
}
async fn send<S: AsyncWrite + Unpin>(io: &mut S, bytes: &[u8]) {
    io.write_all(bytes).await.unwrap();
    io.flush().await.unwrap();
}

// 仅复用独立客户端夹具；VLESS/Trojan 的窄 wire 编码不调用生产 parser/encoder。
fn domain_address(kind: &str, name: &str, port: u16) -> Vec<u8> {
    if kind == "trojan-ws" {
        let mut address = vec![3, u8::try_from(name.len()).unwrap()];
        address.extend(name.as_bytes());
        address.extend(port.to_be_bytes());
        address
    } else {
        vmess_peer::domain(name, port)
    }
}
fn request(kind: &str, command: u8, target: Vec<u8>, bad_identity: bool) -> Vec<u8> {
    match kind {
        "vless-ws" => {
            let mut bytes = vec![0];
            bytes.extend(if bad_identity {
                [0x44; 16]
            } else {
                vmess_peer::ID
            });
            bytes.extend([0, command]);
            bytes.extend(target);
            bytes
        }
        "trojan-ws" => {
            let password = if bad_identity {
                "wrong-test-password"
            } else {
                PASSWORD
            };
            let digest = Sha224::digest(password.as_bytes());
            let mut bytes = digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .into_bytes();
            bytes.extend(b"\r\n");
            bytes.push(if command == 2 { 3 } else { command });
            bytes.extend(target);
            bytes.extend(b"\r\n");
            bytes
        }
        "vmess-ws" => {
            let mut bytes = vmess_peer::Request::new(command, target, 3, 13).wire;
            if bad_identity {
                bytes[0] ^= 0x80; // AuthID 完整但认证错误，不靠截断等待超时。
            }
            bytes
        }
        _ => panic!("测试入口类型"),
    }
}
fn packet(kind: &str, target: Vec<u8>, payload: &[u8]) -> Vec<u8> {
    let mut bytes = if kind == "trojan-ws" {
        target
    } else {
        Vec::new()
    };
    bytes.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
    if kind == "trojan-ws" {
        bytes.extend(b"\r\n");
    }
    bytes.extend(payload);
    bytes
}
async fn assert_no_business(dns: &UdpSocket, tcp: &TcpListener, udp: &UdpSocket) {
    let mut bytes = [0; 2048];
    assert!(
        timeout(QUIET, dns.recv_from(&mut bytes)).await.is_err(),
        "失败不应触发自持DNS"
    );
    assert!(
        timeout(QUIET, tcp.accept()).await.is_err(),
        "失败不应拨业务TCP"
    );
    assert!(
        timeout(QUIET, udp.recv_from(&mut bytes)).await.is_err(),
        "失败不应发业务UDP"
    );
}
fn assert_finished(ctx: &Context, handshakes: &Arc<Semaphore>, expected: usize) {
    assert!(ctx.children.is_closed() && ctx.children.is_empty());
    assert_eq!(ctx.udp_slots.available_permits(), 1);
    assert_eq!(ctx.udp_bytes.available_permits(), 4096);
    assert_eq!(handshakes.available_permits(), expected);
    let snapshot = ctx.stats.snapshot();
    assert_eq!(
        (
            snapshot.connections,
            snapshot.tcp_flows,
            snapshot.udp_associations
        ),
        (0, 0, 0)
    );
}

#[tokio::test]
async fn websocket_http_auth_and_reject_failures_do_not_query_injected_dns() {
    timeout(Duration::from_secs(20), async {
        let certificate = Certificate::new();
        for kind in KINDS {
            for tls in [false,true] {
                let certificate = tls.then_some(&certificate);
                let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let mut value = configuration(kind, certificate);
                value["route"]["rules"] = json!([{"domains":["denied.test"],"outbound":"reject"}]);
                let mut server = Server::bind(parse(&value)).await.unwrap();
                inject_dns(&mut server, dns.local_addr().unwrap());
                let address = server.local_addr("ws").unwrap();
                let ctx = server.context.clone();
                let handshakes = server.listeners[0].handshakes.clone();
                let stop = CancellationToken::new();
                let stimulus = async {
                    // 无效HTTP后拼入一个合法代理帧也不得进入协议认证或DNS。
                    let mut raw = wire(address, certificate).await;
                    let mut http = b"GET /wrong HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n".to_vec();
                    http.extend(ws::masked(true, 2, &request(kind,1,domain_address(kind,"denied.test",tcp.local_addr().unwrap().port()),false)));
                    send(&mut raw,&http).await;
                    let mut response = Vec::new();
                    // 拒绝可以直接关闭TLS，不要求发送close_notify或保证小错误响应送达。
                    let _ = timeout(WAIT, raw.read_to_end(&mut response)).await.unwrap();
                    assert!(response.len() <= 1024,"HTTP错误响应应固定且有限");
                    assert!(!response.starts_with(b"HTTP/1.1 101"));
                    assert!(!String::from_utf8_lossy(&response).contains("denied.test"));
                    drop(raw);
                    wait(|| ctx.stats.snapshot().connections == 0).await;
                    assert_no_business(&dns,&tcp,&udp).await;
                    for command in [1,2] {
                        for bad_identity in [true,false] {
                            let mut peer = connect(address,certificate).await;
                            let mut bytes = request(kind,command,domain_address(kind,"denied.test",tcp.local_addr().unwrap().port()),bad_identity);
                            if kind == "trojan-ws" && command == 2 {
                                bytes.extend(packet(kind,domain_address(kind,"denied.test",udp.local_addr().unwrap().port()),b"denied"));
                            }
                            send(&mut peer,&bytes).await;
                            if kind == "trojan-ws" && command == 2 && !bad_identity {
                                // Trojan按UDP帧拒绝目标而不是关闭整个合法关联。
                                wait(|| ctx.stats.snapshot().rejected >= 5).await;
                                assert_no_business(&dns,&tcp,&udp).await;
                                peer.close().await;
                            }
                            if kind == "vmess-ws" && command == 1 && !bad_identity {
                                // VMess 应答必须先于正文加密流写出；路由拒绝
                                // 后可能已交付响应头，关键是不得产生业务数据。
                                ws::closed_after_optional_response(&mut peer).await;
                            } else {
                                ws::closed(&mut peer).await;
                            }
                            drop(peer);
                            wait(|| ctx.stats.snapshot().connections == 0).await;
                            assert_no_business(&dns,&tcp,&udp).await;
                        }
                    }
                    let snapshot = ctx.stats.snapshot();
                    assert_eq!(snapshot.rejected,5,"每次HTTP/认证/路由失败只分类一次");
                    assert_eq!((snapshot.uplink,snapshot.downlink,snapshot.tcp_flows),(0,0,0));
                    // 正对照：同一注入解析器收到已认证、未被Reject的真实请求。
                    let mut peer = connect(address,certificate).await;
                    send(&mut peer,&request(kind,1,domain_address(kind,"allowed.test",tcp.local_addr().unwrap().port()),false)).await;
                    let mut bytes = [0;2048];
                    timeout(WAIT,dns.recv_from(&mut bytes)).await.unwrap().unwrap();
                    stop.cancel();
                    peer
                };
                let (result, peer) = tokio::join!(server.run(stop.clone()),stimulus);
                result.unwrap();
                assert_finished(&ctx,&handshakes,3);
                drop(peer);
                drop(TcpListener::bind(address).await.unwrap());
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn websocket_tls_http_early_prefix_and_auth_use_one_absolute_deadline() {
    timeout(Duration::from_secs(12), async {
        let certificate = Certificate::new();
        for kind in KINDS {
            let mut value = configuration(kind, Some(&certificate));
            value["limits"]["handshake_timeout_ms"] = json!(1800);
            value["limits"]["max_handshakes"] = json!(1);
            value["inbounds"][0]["websocket"]["early_data"] =
                json!({"mode":"header","max_bytes":8192});
            let server = Server::bind(parse(&value)).await.unwrap();
            let address = server.local_addr("ws").unwrap();
            let ctx = server.context.clone();
            let handshakes = server.listeners[0].handshakes.clone();
            let stop = CancellationToken::new();
            let stimulus = async {
                let stream = TcpStream::connect(address).await.unwrap();
                wait(|| handshakes.available_permits() == 0).await;
                tokio::time::sleep(Duration::from_millis(600)).await;
                let tls = certificate
                    .connector
                    .connect("localhost".try_into().unwrap(), stream)
                    .await
                    .unwrap();
                assert_eq!(handshakes.available_permits(), 0, "TLS完成不得释放握手槽");
                tokio::time::sleep(Duration::from_millis(600)).await;
                let prefix = URL_SAFE_NO_PAD.encode([0]);
                let headers = format!("Sec-WebSocket-Protocol: {prefix}\r\n");
                let mut peer = ws::upgrade(tls, "/proxy", &headers, &[]).await;
                assert_eq!(
                    handshakes.available_permits(),
                    0,
                    "101/不完整early-data不得释放认证槽"
                );
                // 正确余量约600ms；即使只在TLS后刷新也至少还剩1200ms。
                timeout(Duration::from_millis(900), ws::closed(&mut peer))
                    .await
                    .expect("TLS/HTTP/认证不能逐层刷新1800ms");
                wait(|| {
                    handshakes.available_permits() == 1 && ctx.stats.snapshot().connections == 0
                })
                .await;
                assert_eq!(ctx.stats.snapshot().rejected, 1);
                assert_eq!(
                    (ctx.stats.snapshot().uplink, ctx.stats.snapshot().downlink),
                    (0, 0)
                );
                stop.cancel();
            };
            let (result, ()) = tokio::join!(server.run(stop.clone()), stimulus);
            result.unwrap();
            assert_finished(&ctx, &handshakes, 1);
            drop(TcpListener::bind(address).await.unwrap());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn websocket_and_legacy_connections_share_global_slots_but_keep_per_inbound_handshake_caps() {
    timeout(Duration::from_secs(8), async {
        for kind in KINDS {
            let mut value = configuration(kind, None);
            value["limits"]["max_connections"] = json!(2);
            value["limits"]["max_handshakes"] = json!(1);
            value["inbounds"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type":"socks5","tag":"legacy","listen":"127.0.0.1:0"}));
            let server = Server::bind(parse(&value)).await.unwrap();
            let address = server.local_addr("ws").unwrap();
            let legacy_address = server.local_addr("legacy").unwrap();
            let ctx = server.context.clone();
            let handshakes = server.listeners[0].handshakes.clone();
            let legacy_handshakes = server.listeners[1].handshakes.clone();
            let stop = CancellationToken::new();
            let stimulus = async {
                let legacy = TcpStream::connect(legacy_address).await.unwrap();
                wait(|| legacy_handshakes.available_permits() == 0).await;
                let mut slow = TcpStream::connect(address).await.unwrap();
                send(&mut slow, b"GET /proxy HTTP/1.1\r\nHost:").await;
                wait(|| ctx.stats.snapshot().connections == 2).await;
                assert_eq!(handshakes.available_permits(), 0);
                for occupied in [address, legacy_address] {
                    let mut extra = TcpStream::connect(occupied).await.unwrap();
                    ws::closed(&mut extra).await;
                }
                assert_eq!(ctx.stats.snapshot().connections, 2);
                drop(legacy);
                wait(|| {
                    ctx.stats.snapshot().connections == 1
                        && legacy_handshakes.available_permits() == 1
                })
                .await;
                // 此时全局仍有空槽，同入口第二握手应单独被max_handshakes拒绝。
                let mut extra = TcpStream::connect(address).await.unwrap();
                ws::closed(&mut extra).await;
                let legacy = TcpStream::connect(legacy_address).await.unwrap();
                wait(|| ctx.stats.snapshot().connections == 2).await;
                drop(slow);
                wait(|| {
                    handshakes.available_permits() == 1 && ctx.stats.snapshot().connections == 1
                })
                .await;
                let peer = connect(address, None).await;
                wait(|| ctx.stats.snapshot().connections == 2).await;
                assert_eq!(handshakes.available_permits(), 0, "HTTP101不是完整协议认证");
                stop.cancel();
                (legacy, peer)
            };
            let (result, clients) = tokio::join!(server.run(stop.clone()), stimulus);
            result.unwrap();
            assert_finished(&ctx, &handshakes, 1);
            assert_eq!(legacy_handshakes.available_permits(), 1);
            drop(clients);
            drop(TcpListener::bind(address).await.unwrap());
            drop(TcpListener::bind(legacy_address).await.unwrap());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn websocket_blocked_udp_dns_bounds_queue_and_force_returns_children_and_budgets() {
    timeout(Duration::from_secs(8), async {
        for kind in ["vless-ws", "trojan-ws"] {
            let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let business = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut server = Server::bind(parse(&configuration(kind, None)))
                .await
                .unwrap();
            inject_dns(&mut server, dns.local_addr().unwrap());
            let address = server.local_addr("ws").unwrap();
            let handshakes = server.listeners[0].handshakes.clone();
            let ctx = server.context.clone();
            let stop = CancellationToken::new();
            let stimulus = async {
                let mut peer = connect(address, None).await;
                let target = domain_address(
                    kind,
                    "blocked-gate.test",
                    business.local_addr().unwrap().port(),
                );
                let mut bytes = request(kind, 2, target.clone(), false);
                bytes.extend(packet(kind, target.clone(), &[0x71; 512]));
                send(&mut peer, &bytes).await;
                if kind == "vless-ws" {
                    let mut response = [0xff; 2];
                    peer.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, [0, 0]);
                }
                let mut buffer = [0; 2048];
                timeout(WAIT, dns.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                wait(|| ctx.stats.snapshot().udp_associations == 1).await;
                for _ in 0..16 {
                    send(&mut peer, &packet(kind, target.clone(), &[0x72; 512])).await;
                }
                wait(|| {
                    ctx.stats.snapshot().dropped > 0 && ctx.udp_bytes.available_permits() < 4096
                })
                .await;
                assert!(
                    (512..=1024).contains(&(4096 - ctx.udp_bytes.available_permits())),
                    "一个DNS处理中的包和一个队列包各保留512字节"
                );
                assert!(
                    ctx.children.len() <= 1,
                    "阻塞DNS前只有有限帧读取任务，不按包spawn"
                );
                assert_eq!(
                    handshakes.available_permits(),
                    3,
                    "已完整认证后才能归还握手槽"
                );
                assert_eq!(ctx.udp_slots.available_permits(), 0);
                assert_eq!(
                    (ctx.stats.snapshot().uplink, ctx.stats.snapshot().downlink),
                    (0, 0)
                );
                assert!(
                    timeout(QUIET, business.recv_from(&mut buffer))
                        .await
                        .is_err()
                );
                stop.cancel();
                peer
            };
            let (result, peer) = tokio::join!(server.run(stop.clone()), stimulus);
            result.unwrap();
            assert_finished(&ctx, &handshakes, 3);
            drop(peer);
            drop(TcpListener::bind(address).await.unwrap());
            // Dns的私有permit不暴露；通过取消后另一个不同名字能发出真实查询观察归还。
            let target = crate::session::Target {
                host: crate::session::Host::Domain("reclaimed-gate.test".into()),
                port: 80,
            };
            let query = timeout(Duration::from_millis(300), ctx.dns.resolve(&target));
            let observed = async {
                let mut buffer = [0; 2048];
                timeout(WAIT, async {
                    loop {
                        let (n, _) = dns.recv_from(&mut buffer).await.unwrap();
                        if buffer[..n]
                            .windows(b"reclaimed-gate".len())
                            .any(|part| part == b"reclaimed-gate")
                        {
                            break;
                        }
                    }
                })
                .await
                .unwrap();
            };
            let (result, ()) = tokio::join!(query, observed);
            assert!(
                result.is_err(),
                "自持DNS不答应保持Pending，不得因旧permit未还而立即WouldBlock"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn websocket_force_joins_active_udp_mapping_slow_http_and_half_frame_then_rebinds() {
    timeout(Duration::from_secs(8), async {
        let mut value = configuration("vless-ws", None);
        value["inbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"socks5","tag":"legacy","listen":"127.0.0.1:0"}));
        let server = Server::bind(parse(&value)).await.unwrap();
        let address = server.local_addr("ws").unwrap();
        let legacy_address = server.local_addr("legacy").unwrap();
        let ctx = server.context.clone();
        let handshakes = server.listeners[0].handshakes.clone();
        let legacy_handshakes = server.listeners[1].handshakes.clone();
        let business = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stop = CancellationToken::new();
        let stimulus = async {
            let mut peer = connect(address, None).await;
            let mut bytes = request(
                "vless-ws",
                2,
                vmess_peer::target(business.local_addr().unwrap()),
                false,
            );
            bytes.extend(packet("vless-ws", Vec::new(), b"active"));
            send(&mut peer, &bytes).await;
            let mut response = [0xff; 2];
            peer.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0, 0]);
            let mut buffer = [0; 2048];
            let (n, mapping) = business.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], b"active");
            business.send_to(b"reply", mapping).await.unwrap();
            let mut reply = [0; 7];
            peer.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"\0\x05reply");
            wait(|| ctx.stats.snapshot().uplink == 6 && ctx.stats.snapshot().downlink == 5).await;
            assert_eq!(ctx.udp_slots.available_permits(), 0);
            // 旧SOCKS也竞争同一UDP关联预算；拒绝回复不得另建关联。
            let mut legacy = TcpStream::connect(legacy_address).await.unwrap();
            send(&mut legacy, &[5, 1, 0]).await;
            let mut greeting = [0; 2];
            legacy.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            send(&mut legacy, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            let mut rejected = [0; 10];
            legacy.read_exact(&mut rejected).await.unwrap();
            assert_ne!(rejected[1], 0, "旧入口不得绕过新入口占用的UDP槽");
            drop(legacy);
            wait(|| ctx.stats.snapshot().connections == 1).await;
            let mut slow = TcpStream::connect(address).await.unwrap();
            send(&mut slow, b"GET /proxy HTTP/1.1\r\nHost:").await;
            let mut half = TcpStream::connect(address).await.unwrap();
            drop(ws::upgrade(&mut half, "/proxy", "", &[]).await);
            // 完整合法mask头声明20字节但仅送1字节，保持半帧/未认证状态。
            send(&mut half, &[0x82, 0x94, 0x13, 0x37, 0x59, 0x83, 0x13]).await;
            wait(|| ctx.stats.snapshot().connections == 3 && handshakes.available_permits() == 1)
                .await;
            assert!(
                ctx.children.len() <= 2,
                "一个UDP reader和一个mapping receiver"
            );
            assert_eq!(ctx.stats.snapshot().udp_associations, 1);
            stop.cancel();
            (peer, slow, half, mapping)
        };
        let (result, (peer, slow, half, mapping)) =
            tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        assert_finished(&ctx, &handshakes, 3);
        assert_eq!(legacy_handshakes.available_permits(), 3);
        assert_eq!(
            (ctx.stats.snapshot().uplink, ctx.stats.snapshot().downlink),
            (6, 5),
            "HTTP/认证/封装/控制不算业务载荷"
        );
        drop((peer, slow, half));
        drop(UdpSocket::bind(mapping).await.unwrap());
        drop(TcpListener::bind(address).await.unwrap());
        drop(TcpListener::bind(legacy_address).await.unwrap());
    })
    .await
    .unwrap();
}

// 扩展承载仍使用独立客户端；VMess 的每个 UDP/XUDP 包都经过认证正文 chunk。
#[derive(Clone, Copy, Debug)]
enum UdpPath {
    VmessNative,
    VlessXudp,
    VmessXudp,
}
enum UdpPeer {
    Vless(Peer),
    Vmess(Box<vmess_peer::Client<Peer>>),
}
impl UdpPeer {
    async fn send(&mut self, payload: &[u8]) {
        match self {
            Self::Vless(peer) => send(peer, payload).await,
            Self::Vmess(client) => client.send(payload).await,
        }
    }
    async fn xreply(&mut self) -> (Vec<u8>, Vec<u8>) {
        match self {
            Self::Vless(peer) => {
                let length = usize::from(peer.read_u16().await.unwrap());
                assert!((4..=512).contains(&length));
                let mut metadata = vec![0; length];
                peer.read_exact(&mut metadata).await.unwrap();
                let mut payload = Vec::new();
                if metadata[3] & 1 != 0 {
                    let length = usize::from(peer.read_u16().await.unwrap());
                    assert!(length <= 512);
                    payload.resize(length, 0);
                    peer.read_exact(&mut payload).await.unwrap();
                }
                (metadata, payload)
            }
            Self::Vmess(client) => vmess_peer::xrecv(client.as_mut()).await,
        }
    }
}

#[tokio::test]
async fn websocket_vmess_udp_and_vless_vmess_xudp_blocked_dns_bound_queues_and_force_join() {
    timeout(Duration::from_secs(8), async {
        let certificate = Certificate::new();
        for path in [UdpPath::VmessNative, UdpPath::VlessXudp, UdpPath::VmessXudp] {
            for tls in [false, true] {
                let certificate = tls.then_some(&certificate);
                let kind = if matches!(path, UdpPath::VlessXudp) {
                    "vless-ws"
                } else {
                    "vmess-ws"
                };
                let xudp = !matches!(path, UdpPath::VmessNative);
                let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let business = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let target = business.local_addr().unwrap();
                let mut value = configuration(kind, certificate);
                value["inbounds"][0]["xudp"] = json!(xudp);
                let mut server = Server::bind(parse(&value)).await.unwrap();
                inject_dns(&mut server, dns.local_addr().unwrap());
                let address = server.local_addr("ws").unwrap();
                let handshakes = server.listeners[0].handshakes.clone();
                let ctx = server.context.clone();
                let stop = CancellationToken::new();
                let stimulus = async {
                    let peer = connect(address, certificate).await;
                    let mut client = if matches!(path, UdpPath::VlessXudp) {
                        let mut peer = peer;
                        send(&mut peer, &request(kind, 3, Vec::new(), false)).await;
                        UdpPeer::Vless(peer)
                    } else {
                        let request = vmess_peer::Request::new(
                            if xudp { 3 } else { 2 },
                            if xudp {
                                Vec::new()
                            } else {
                                vmess_peer::domain("blocked-native-ws.test", target.port())
                            },
                            3,
                            13,
                        );
                        UdpPeer::Vmess(Box::new(
                            vmess_peer::Client::start(peer, request, None).await,
                        ))
                    };
                    let mapping = if xudp {
                        client
                            .send(&vmess_peer::xframe(
                                7,
                                1,
                                Some(vmess_peer::target(target)),
                                false,
                                Some(b"active"),
                            ))
                            .await;
                        if let UdpPeer::Vless(peer) = &mut client {
                            let mut response = [0xff; 2];
                            peer.read_exact(&mut response).await.unwrap();
                            assert_eq!(response, [0, 0]);
                        }
                        let mut buffer = [0; 1024];
                        let (n, mapping) = business.recv_from(&mut buffer).await.unwrap();
                        assert_eq!(&buffer[..n], b"active");
                        business.send_to(b"active", mapping).await.unwrap();
                        let (metadata, payload) = client.xreply().await;
                        let mut expected = vec![0, 7, 2, 1, 2];
                        expected.extend(vmess_peer::target(target));
                        assert_eq!(metadata, expected);
                        assert_eq!(payload, b"active");
                        Some(mapping)
                    } else {
                        None
                    };
                    let payload = [0x61; 512];
                    let blocked = if xudp {
                        vmess_peer::xframe(
                            7,
                            2,
                            Some(vmess_peer::domain("blocked-xudp-ws.test", target.port())),
                            false,
                            Some(&payload),
                        )
                    } else {
                        payload.to_vec()
                    };
                    client.send(&blocked).await;
                    let mut buffer = [0; 2048];
                    timeout(WAIT, dns.recv_from(&mut buffer))
                        .await
                        .unwrap()
                        .unwrap();
                    wait(|| ctx.stats.snapshot().udp_associations == 1).await;
                    assert_eq!(ctx.udp_slots.available_permits(), 0);
                    for _ in 0..16 {
                        client.send(&blocked).await;
                    }
                    if xudp {
                        // Mux 使用每条承载独立的 256 KiB 入站字节预算，
                        // 不占用全局 udp_queue_bytes；只断言任务数与业务计数有界。
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        assert_eq!(ctx.udp_bytes.available_permits(), 4096);
                        assert!(
                            ctx.children.len() <= 2,
                            "固定承载reader与既有映射，不按帧创建任务"
                        );
                    } else {
                        wait(|| {
                            ctx.stats.snapshot().dropped >= 15
                                && ctx.udp_bytes.available_permits() == 4096 - 2 * 512
                        })
                        .await;
                        assert_eq!(ctx.children.len(), 1, "原生VMess只保留一个正文reader");
                    }
                    let counted = if xudp { 6 } else { 0 };
                    assert_eq!(
                        (ctx.stats.snapshot().uplink, ctx.stats.snapshot().downlink),
                        (counted, counted)
                    );
                    assert!(
                        timeout(QUIET, business.recv_from(&mut buffer))
                            .await
                            .is_err()
                    );
                    assert_eq!(handshakes.available_permits(), 3);
                    // 占满共享slot后，同入口另一合法UDP请求在成功回应之前有限拒绝。
                    let mut excess = connect(address, certificate).await;
                    send(
                        &mut excess,
                        &request(kind, 2, vmess_peer::target(target), false),
                    )
                    .await;
                    ws::closed(&mut excess).await;
                    drop(excess);
                    wait(|| ctx.stats.snapshot().connections == 1).await;
                    assert_eq!(ctx.stats.snapshot().udp_associations, 1);
                    assert_eq!(ctx.stats.snapshot().rejected, 1);
                    stop.cancel();
                    (client, mapping)
                };
                let (result, (client, mapping)) = tokio::join!(server.run(stop.clone()), stimulus);
                result.unwrap();
                assert_finished(&ctx, &handshakes, 3);
                let counted = if xudp { 6 } else { 0 };
                assert_eq!(
                    (ctx.stats.snapshot().uplink, ctx.stats.snapshot().downlink),
                    (counted, counted)
                );
                drop(client);
                if let Some(mapping) = mapping {
                    drop(UdpSocket::bind(mapping).await.unwrap());
                }
                drop(TcpListener::bind(address).await.unwrap());
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn websocket_packetaddr_active_mapping_and_native_dns_share_slots_then_force_reclaim() {
    timeout(Duration::from_secs(8), async {
        let certificate = Certificate::new();
        for tls in [false, true] {
            let certificate = tls.then_some(&certificate);
            let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let business = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = business.local_addr().unwrap();
            let mut value = configuration("vmess-ws", certificate);
            value["inbounds"][0]["packetaddr"] = json!(true);
            value["limits"]["max_udp_associations"] = json!(2);
            let mut server = Server::bind(parse(&value)).await.unwrap();
            inject_dns(&mut server, dns.local_addr().unwrap());
            let address = server.local_addr("ws").unwrap();
            let handshakes = server.listeners[0].handshakes.clone();
            let ctx = server.context.clone();
            let stop = CancellationToken::new();
            let stimulus = async {
                let mut active = vmess_peer::Client::start(
                    connect(address, certificate).await,
                    vmess_peer::Request::new(
                        2,
                        vmess_peer::domain("sp.packet-addr.v2fly.arpa", 0),
                        4,
                        13,
                    ),
                    None,
                )
                .await;
                active
                    .send(&vmess_peer::packetaddr(target, b"active"))
                    .await;
                let mut buffer = [0; 2048];
                let (n, mapping) = business.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..n], b"active");
                business.send_to(b"reply", mapping).await.unwrap();
                assert_eq!(
                    active.recv().await,
                    vmess_peer::packetaddr(target, b"reply")
                );
                assert!(
                    timeout(QUIET, dns.recv_from(&mut buffer)).await.is_err(),
                    "packetaddr控制域名不应解析，数据报仅能携带IP"
                );
                let mut blocked = vmess_peer::Client::start(
                    connect(address, certificate).await,
                    vmess_peer::Request::new(
                        2,
                        vmess_peer::domain("blocked-packetaddr-peer.test", target.port()),
                        3,
                        13,
                    ),
                    None,
                )
                .await;
                blocked.send(&[0x62; 512]).await;
                timeout(WAIT, dns.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                for _ in 0..16 {
                    blocked.send(&[0x63; 512]).await;
                }
                wait(|| {
                    ctx.stats.snapshot().dropped >= 15
                        && ctx.udp_bytes.available_permits() == 4096 - 2 * 512
                })
                .await;
                assert_eq!(ctx.udp_slots.available_permits(), 0);
                assert_eq!(ctx.stats.snapshot().udp_associations, 2);
                assert_eq!(
                    ctx.children.len(),
                    3,
                    "packetaddr正文reader及映射receiver、原生正文reader"
                );
                assert_eq!(
                    (ctx.stats.snapshot().uplink, ctx.stats.snapshot().downlink),
                    (6, 5)
                );
                assert_eq!(handshakes.available_permits(), 3);
                assert!(
                    timeout(QUIET, business.recv_from(&mut buffer))
                        .await
                        .is_err()
                );
                let mut excess = connect(address, certificate).await;
                send(
                    &mut excess,
                    &vmess_peer::Request::new(2, vmess_peer::target(target), 3, 13).wire,
                )
                .await;
                ws::closed(&mut excess).await;
                wait(|| ctx.stats.snapshot().connections == 2).await;
                assert_eq!(ctx.stats.snapshot().udp_associations, 2);
                assert_eq!(ctx.stats.snapshot().rejected, 1);
                stop.cancel();
                (active, blocked, mapping)
            };
            let (result, (active, blocked, mapping)) =
                tokio::join!(server.run(stop.clone()), stimulus);
            result.unwrap();
            assert!(ctx.children.is_closed() && ctx.children.is_empty());
            assert_eq!(ctx.udp_slots.available_permits(), 2);
            assert_eq!(ctx.udp_bytes.available_permits(), 4096);
            assert_eq!(handshakes.available_permits(), 3);
            let snapshot = ctx.stats.snapshot();
            assert_eq!(
                (
                    snapshot.connections,
                    snapshot.tcp_flows,
                    snapshot.udp_associations
                ),
                (0, 0, 0)
            );
            assert_eq!((snapshot.uplink, snapshot.downlink), (6, 5));
            drop((active, blocked));
            drop(UdpSocket::bind(mapping).await.unwrap());
            drop(TcpListener::bind(address).await.unwrap());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn websocket_check_does_not_bind_and_later_bind_conflict_returns_earlier_ports() {
    timeout(Duration::from_secs(8), async {
        let certificate = Certificate::new();
        for kind in KINDS {
            for tls in [false,true] {
                let certificate = tls.then_some(&certificate);
                let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut value = configuration(kind,certificate);
                value["inbounds"][0]["listen"] = json!(occupied.local_addr().unwrap());
                Server::check(&parse(&value)).unwrap();
                assert!(timeout(QUIET,occupied.accept()).await.is_err());
                assert!(Server::bind(parse(&value)).await.is_err());
                let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let middle = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addresses = [first.local_addr().unwrap(),middle.local_addr().unwrap()];
                value["inbounds"][0]["listen"] = json!(addresses[0]);
                value["inbounds"].as_array_mut().unwrap().extend([
                    json!({"type":"socks5","tag":"middle","listen":addresses[1]}),
                    json!({"type":"socks5","tag":"conflict","listen":occupied.local_addr().unwrap()}),
                ]);
                drop((first,middle));
                let error = Server::bind(parse(&value)).await.err().unwrap();
                assert!(format!("{error:?}").contains("conflict"));
                assert!(!format!("{error:#?}").contains(PASSWORD));
                let _first = TcpListener::bind(addresses[0]).await.unwrap();
                let _middle = TcpListener::bind(addresses[1]).await.unwrap();
                assert!(timeout(QUIET,occupied.accept()).await.is_err());
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn websocket_later_invalid_tls_never_leaves_any_planned_listener_bound() {
    timeout(Duration::from_secs(8), async {
        let certificate = Certificate::new();
        let other = Certificate::new();
        let invalid = certificate.dir.path().join("invalid.pem");
        std::fs::write(&invalid, "ws-runtime-private-pem-secret").unwrap();
        for kind in KINDS {
            for (cert, key) in [
                (invalid.clone(), certificate.dir.path().join("key.pem")),
                (certificate.dir.path().join("cert.pem"), invalid.clone()),
                (
                    certificate.dir.path().join("cert.pem"),
                    other.dir.path().join("key.pem"),
                ),
                (
                    certificate.dir.path().join("missing.pem"),
                    certificate.dir.path().join("key.pem"),
                ),
            ] {
                let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addresses = [first.local_addr().unwrap(), second.local_addr().unwrap()];
                let mut value = configuration(kind, None);
                value["inbounds"][0]["listen"] = json!(addresses[0]);
                let mut bad = inbound(kind, "bad-tls");
                bad.as_object_mut()
                    .unwrap()
                    .remove("allow_insecure_transport");
                bad["listen"] = json!(addresses[1]);
                bad["certificate"] = json!(cert);
                bad["private_key"] = json!(key);
                value["inbounds"].as_array_mut().unwrap().push(bad);
                let config = parse(&value);
                let error = Server::check(&config).unwrap_err();
                for secret in [PASSWORD, vmess_peer::UUID, "ws-runtime-private-pem-secret"] {
                    assert!(!format!("{error:#?}").contains(secret));
                }
                drop((first, second));
                assert!(Server::bind(config).await.is_err());
                let _first = TcpListener::bind(addresses[0]).await.unwrap();
                let _second = TcpListener::bind(addresses[1]).await.unwrap();
            }
        }
    })
    .await
    .unwrap();
}
