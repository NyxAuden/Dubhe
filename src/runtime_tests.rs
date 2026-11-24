//! 联合准备及监听任务故障注入；不修改系统双栈设置或生产配置接口。
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

#[path = "../tests/common/vmess.rs"]
pub(super) mod vmess_client;

fn configuration() -> Value {
    json!({
        "version":1,
        "inbounds":[
            {"type":"shadowsocks","tag":"legacy","listen":"127.0.0.1:0","method":"aes-128-gcm","password":"local-test-only"},
            {"type":"shadowsocks","tag":"modern","listen":"127.0.0.1:0","method":"2022-blake3-aes-128-gcm","password":STANDARD.encode([0x11;16])},
            {"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}
        ],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":20,"handshake_timeout_ms":10000}
    })
}

fn parse(value: &Value) -> Config {
    Config::from_json(&value.to_string()).unwrap()
}

#[tokio::test]
async fn paired_ephemeral_binding_retries_only_udp_address_conflicts() {
    let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = attempts.clone();
    let (tcp, udp) = bind_tcp_udp_with("127.0.0.1:0".parse().unwrap(), move |address| {
        let mut attempts = seen.lock().unwrap();
        attempts.push(address);
        let fail = attempts.len() == 1;
        drop(attempts);
        async move {
            if fail {
                Err(io::Error::new(io::ErrorKind::AddrInUse, "注入UDP端口冲突"))
            } else {
                UdpSocket::bind(address).await
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(attempts.lock().unwrap().len(), 2);
    let address = tcp.local_addr().unwrap();
    assert_eq!(udp.local_addr().unwrap(), address);
    // 首次失败的TCP句柄已经回收，不把联合准备错误变成端口泄漏。
    let failed = attempts.lock().unwrap()[0];
    if failed != address {
        TcpListener::bind(failed).await.unwrap();
    }
    drop(tcp);
    drop(udp);
    TcpListener::bind(address).await.unwrap();
    UdpSocket::bind(address).await.unwrap();

    let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fixed = occupied.local_addr().unwrap();
    let error = bind_tcp_udp(fixed).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    TcpListener::bind(fixed)
        .await
        .expect("固定端口错误也须回收已准备的TCP");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let error = bind_tcp_udp_with("127.0.0.1:0".parse().unwrap(), move |_| {
        observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        async {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "注入非端口冲突错误",
            ))
        }
    })
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn vision_reject_precedes_local_dns_and_target_io() {
    use hickory_resolver::config::ResolverOpts;
    use tokio::io::AsyncReadExt;
    timeout(Duration::from_secs(3),async {
        let directory=tempfile::tempdir().unwrap();let cert=rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate=directory.path().join("cert.pem");let key=directory.path().join("key.pem");
        std::fs::write(&certificate,cert.cert.pem()).unwrap();std::fs::write(&key,cert.key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let value=json!({"version":1,"inbounds":[{"type":"vless","tag":"vision","listen":"127.0.0.1:0","users":[{"name":"test","uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision"}],"certificate":certificate,"private_key":key}],"outbounds":[{"type":"reject","tag":"reject"}],"route":{"default":"reject"}});
        let mut server=Server::bind(parse(&value)).await.unwrap();let address=server.local_addr("vision").unwrap();
        let dns=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Arc::get_mut(&mut server.context).unwrap().dns=crate::dns::Dns::new(crate::dns::udp_resolver(dns.local_addr().unwrap(),ResolverOpts::default()).unwrap(),1,Duration::from_secs(1));
        let stats=server.stats();let stop=CancellationToken::new();let run=tokio::spawn(server.run(stop.clone()));
        let mut roots=rustls::RootCertStore::empty();roots.add(cert.cert.der().clone()).unwrap();
        let config=rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        let mut stream=tokio_rustls::TlsConnector::from(Arc::new(config)).connect("localhost".try_into().unwrap(),TcpStream::connect(address).await.unwrap()).await.unwrap();
        let mut request=vec![0];request.extend([0x11;16]);request.extend([18,10,16]);request.extend(b"xtls-rprx-vision");request.extend([1,0,80,2,11]);request.extend(b"denied.test");
        stream.write_all(&request).await.unwrap();stream.flush().await.unwrap();
        // 与 Xray 一致，VLESS 应答先于出站拨号；拒绝后连接关闭。
        let mut response=Vec::new();
        let _=timeout(Duration::from_secs(2),stream.read_to_end(&mut response)).await;
        assert_eq!(response,vec![0,0]);
        assert!(timeout(Duration::from_millis(40),dns.recv_from(&mut [0;512])).await.is_err());
        // 既有统计分别记录路由拒绝和连接处理失败，故同请求会增加两次。
        assert_eq!(stats.snapshot().rejected,2);assert_eq!(stats.snapshot().uplink,0);assert_eq!(stats.snapshot().downlink,0);
        stop.cancel();run.await.unwrap().unwrap();assert_eq!(stats.snapshot().connections,0);
    }).await.unwrap();
}

const VMESS_UUID: &str = "f57196ec-a7a1-49bb-9445-e755ec418605";

fn vmess_inbound(address: SocketAddr, tag: &str) -> Value {
    json!({"type":"vmess", "tag":tag, "listen":address, "users":[{"name":"test", "uuid":VMESS_UUID}]})
}

fn vmess_certificate() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(directory.path().join("cert.pem"), certificate.cert.pem()).unwrap();
    let key = directory.path().join("key.pem");
    std::fs::write(&key, certificate.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    directory
}

#[tokio::test]
async fn vmess_check_avoids_bind_and_prepared_modes_drop_all_listeners() {
    timeout(Duration::from_secs(3), async {
        let certificate = vmess_certificate();
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for tls in [false, true] {
            let mut inbound = vmess_inbound(occupied.local_addr().unwrap(), "vmess");
            if tls {
                inbound["certificate"] = json!(certificate.path().join("cert.pem"));
                inbound["private_key"] = json!(certificate.path().join("key.pem"));
            }
            let mut value = configuration();
            value["inbounds"] = json!([inbound]);
            Server::check(&parse(&value)).unwrap();
            // check合法且地址已占用，随后真正bind必须失败，不能把check当监听。
            let error = Server::bind(parse(&value)).await.err().unwrap();
            assert!(!format!("{error:?}").contains(VMESS_UUID));
            assert!(
                timeout(Duration::from_millis(20), occupied.accept())
                    .await
                    .is_err()
            );
            value["inbounds"][0]["listen"] = json!("127.0.0.1:0");
            let server = Server::bind(parse(&value)).await.unwrap();
            let address = server.local_addr("vmess").unwrap();
            assert_eq!(server.listeners.len(), 1);
            assert_eq!(server.listeners[0].tls.is_some(), tls);
            assert!(server.listeners[0].vmess.is_some());
            let stats = server.stats();
            assert_eq!(stats.snapshot().connections, 0);
            drop(server);
            let _rebound = TcpListener::bind(address).await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vmess_later_listener_conflict_returns_all_prepared_ports() {
    timeout(Duration::from_secs(3), async {
        let certificate = vmess_certificate();
        for tls in [false, true] {
            let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let conflict = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addresses = [first.local_addr().unwrap(), second.local_addr().unwrap()];
            let mut vmess = vmess_inbound(addresses[0], "vmess");
            if tls {
                vmess["certificate"] = json!(certificate.path().join("cert.pem"));
                vmess["private_key"] = json!(certificate.path().join("key.pem"));
            }
            let mut value = configuration();
            value["inbounds"] = json!([
                vmess,
                {"type":"socks5", "tag":"middle", "listen":addresses[1]},
                {"type":"socks5", "tag":"conflict", "listen":conflict.local_addr().unwrap()}
            ]);
            drop((first, second));
            let error = Server::bind(parse(&value)).await.err().unwrap();
            let rendered = format!("{error:#?}");
            assert!(rendered.contains("conflict") && rendered.contains("绑定失败"));
            assert!(!rendered.contains(VMESS_UUID));
            let mut rebound = Vec::new();
            for address in addresses {
                rebound.push(TcpListener::bind(address).await.unwrap());
            }
            assert!(
                timeout(Duration::from_millis(20), conflict.accept())
                    .await
                    .is_err()
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vmess_later_tls_preparation_failure_leaves_prior_listeners_unbound() {
    timeout(Duration::from_secs(3), async {
        let certificate = vmess_certificate();
        let other = vmess_certificate();
        let invalid_certificate = certificate.path().join("bad-cert.pem");
        let invalid_key = certificate.path().join("bad-key.pem");
        std::fs::write(&invalid_certificate, "vmess-pem-secret-918").unwrap();
        std::fs::write(&invalid_key, "vmess-pem-secret-918").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&invalid_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        for (certificate_path, key_path) in [
            (invalid_certificate, certificate.path().join("key.pem")),
            (certificate.path().join("cert.pem"), invalid_key),
            (
                certificate.path().join("cert.pem"),
                other.path().join("key.pem"),
            ),
            (
                certificate.path().join("missing.pem"),
                certificate.path().join("key.pem"),
            ),
        ] {
            let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let last = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addresses = [
                first.local_addr().unwrap(),
                second.local_addr().unwrap(),
                last.local_addr().unwrap(),
            ];
            let mut bad = vmess_inbound(addresses[2], "bad-tls");
            bad["certificate"] = json!(certificate_path);
            bad["private_key"] = json!(key_path);
            let mut value = configuration();
            value["inbounds"] = json!([
                {"type":"socks5", "tag":"socks", "listen":addresses[0]},
                vmess_inbound(addresses[1], "vmess"),
                bad
            ]);
            let config = parse(&value);
            let error = Server::check(&config).unwrap_err();
            let rendered = format!("{error:#?}");
            assert!(!rendered.contains(VMESS_UUID));
            assert!(!rendered.contains("vmess-pem-secret-918"));
            drop((first, second, last));
            let error = Server::bind(config).await.err().unwrap();
            let rendered = format!("{error:#?}");
            assert!(!rendered.contains(VMESS_UUID));
            assert!(!rendered.contains("vmess-pem-secret-918"));
            let mut rebound = Vec::new();
            for address in addresses {
                rebound.push(TcpListener::bind(address).await.unwrap());
            }
        }
    })
    .await
    .unwrap();
}

fn vmess_runtime_configuration(packetaddr: bool) -> Value {
    let mut value = configuration();
    let mut inbound = vmess_inbound("127.0.0.1:0".parse().unwrap(), "vmess");
    inbound["users"][0]["uuid"] = json!(vmess_client::UUID);
    inbound["packetaddr"] = json!(packetaddr);
    value["inbounds"] = json!([inbound]);
    value["outbounds"] =
        json!([{"type":"direct", "tag":"direct"}, {"type":"reject", "tag":"reject"}]);
    value["limits"]["handshake_timeout_ms"] = json!(300);
    value["limits"]["udp_idle_timeout_ms"] = json!(1000);
    value
}

async fn vmess_local_dns(server: &mut Server) -> UdpSocket {
    vmess_local_dns_with_deadline(server, Duration::from_millis(200)).await
}

async fn vmess_local_dns_with_deadline(server: &mut Server, deadline: Duration) -> UdpSocket {
    use hickory_resolver::config::{ResolveHosts, ResolverOpts};
    let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut options = ResolverOpts::default();
    options.use_hosts_file = ResolveHosts::Never;
    options.attempts = 1;
    options.timeout = deadline;
    Arc::get_mut(&mut server.context).unwrap().dns = crate::dns::Dns::new(
        crate::dns::udp_resolver(dns.local_addr().unwrap(), options).unwrap(),
        1,
        deadline,
    );
    dns
}

async fn vmess_assert_no_dns_or_target(dns: &UdpSocket, tcp: &TcpListener, udp: &UdpSocket) {
    let mut dns_bytes = [0; 1024];
    let mut udp_bytes = [0; 1024];
    let (dns, tcp, udp) = tokio::join!(
        timeout(Duration::from_millis(30), dns.recv_from(&mut dns_bytes)),
        timeout(Duration::from_millis(30), tcp.accept()),
        timeout(Duration::from_millis(30), udp.recv_from(&mut udp_bytes)),
    );
    assert!(dns.is_err(), "拒绝请求触发了测试DNS");
    assert!(tcp.is_err(), "拒绝请求连接了TCP目标");
    assert!(udp.is_err(), "拒绝请求访问了UDP目标");
}

#[tokio::test]
async fn vmess_reject_route_precedes_local_dns_target_io_and_success_response() {
    timeout(Duration::from_secs(4), async {
        let mut value = vmess_runtime_configuration(false);
        value["route"]["default"] = json!("reject");
        let mut server = Server::bind(parse(&value)).await.unwrap();
        let address = server.local_addr("vmess").unwrap();
        let dns = vmess_local_dns(&mut server).await;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = server.stats();
        let stop = CancellationToken::new();
        let stimulus = async {
            for (command, target) in [
                (
                    1,
                    vmess_client::domain("denied.test", tcp.local_addr().unwrap().port()),
                ),
                (1, vmess_client::target(tcp.local_addr().unwrap())),
                (
                    2,
                    vmess_client::domain("denied.test", udp.local_addr().unwrap().port()),
                ),
                (2, vmess_client::target(udp.local_addr().unwrap())),
            ] {
                let request = vmess_client::Request::new(command, target, 3, 5);
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(&request.wire).await.unwrap();
                // VMess 应答必须在正文加密流之前写出，因此 TCP 拒绝路径可能先
                // 返回响应头；关键约束是拒绝发生在 DNS/目标 IO 之前。
                if command == 1 {
                    vmess_client::closed_after_optional_response(&mut stream).await;
                } else {
                    vmess_client::closed(&mut stream).await;
                }
                vmess_assert_no_dns_or_target(&dns, &tcp, &udp).await;
                assert_eq!(stats.snapshot().uplink, 0);
                assert_eq!(stats.snapshot().downlink, 0);
            }
            assert!(stats.snapshot().rejected >= 4);
            stop.cancel();
        };
        let (result, ()) = tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        assert_eq!(stats.snapshot().connections, 0);
        assert_eq!(stats.snapshot().udp_associations, 0);
        let _rebound = TcpListener::bind(address).await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vmess_bad_auth_time_and_security_policy_precede_local_dns_and_target_io() {
    timeout(Duration::from_secs(4), async {
        let value = vmess_runtime_configuration(false);
        let mut server = Server::bind(parse(&value)).await.unwrap();
        let address = server.local_addr("vmess").unwrap();
        let dns = vmess_local_dns(&mut server).await;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = server.stats();
        let stop = CancellationToken::new();
        let stimulus = async {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            for command in [1, 2] {
                for (uuid, timestamp, security, options) in [
                    ([0x73; 16], now, 3, 5),
                    (vmess_client::ID, now - 121, 3, 5),
                    (vmess_client::ID, now + 1000, 3, 5),
                    (vmess_client::ID, u64::MAX, 3, 5),
                    (vmess_client::ID, now, 5, 1), // 直承载默认不准许无正文加密。
                    (vmess_client::ID, now, 1, 1), // 历史正文算法。
                    (vmess_client::ID, now, 3, 0x15), // A 默认关闭。
                    (vmess_client::ID, now, 3, 2), // 连接复用位不得静默忽略。
                ] {
                    for target in [
                        vmess_client::domain("must-not-resolve.test", 80),
                        vmess_client::target(if command == 1 {
                            tcp.local_addr().unwrap()
                        } else {
                            udp.local_addr().unwrap()
                        }),
                    ] {
                        let request = vmess_client::Request::at(
                            command, target, security, options, uuid, timestamp, None,
                        );
                        let mut stream = TcpStream::connect(address).await.unwrap();
                        stream.write_all(&request.wire).await.unwrap();
                        vmess_client::closed(&mut stream).await;
                        vmess_assert_no_dns_or_target(&dns, &tcp, &udp).await;
                    }
                }
            }
            assert_eq!(stats.snapshot().uplink, 0);
            assert_eq!(stats.snapshot().downlink, 0);
            assert!(stats.snapshot().rejected >= 32);
            stop.cancel();
        };
        let (result, ()) = tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        assert_eq!(stats.snapshot().connections, 0);
        assert_eq!(stats.snapshot().udp_associations, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vmess_disabled_packetaddr_never_resolves_reserved_control_domain() {
    timeout(Duration::from_secs(3), async {
        let mut server = Server::bind(parse(&vmess_runtime_configuration(false)))
            .await
            .unwrap();
        let address = server.local_addr("vmess").unwrap();
        let dns = vmess_local_dns(&mut server).await;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = server.stats();
        let stop = CancellationToken::new();
        let stimulus = async {
            for (command, port) in [(1, 443), (2, 443), (2, 0)] {
                let request = vmess_client::Request::new(
                    command,
                    vmess_client::domain("sp.packet-addr.v2fly.arpa", port),
                    4,
                    13,
                );
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(&request.wire).await.unwrap();
                vmess_client::closed(&mut stream).await;
                vmess_assert_no_dns_or_target(&dns, &tcp, &udp).await;
            }
            assert_eq!(stats.snapshot().uplink, 0);
            assert_eq!(stats.snapshot().downlink, 0);
            stop.cancel();
        };
        let (result, ()) = tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        assert_eq!(stats.snapshot().connections, 0);
        assert_eq!(stats.snapshot().udp_associations, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vmess_packetaddr_reject_is_per_packet_and_never_contacts_rejected_target() {
    timeout(Duration::from_secs(4), async {
        let blocked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let allowed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut value = vmess_runtime_configuration(true);
        let blocked_port = blocked.local_addr().unwrap().port();
        value["route"]["rules"] = json!([{"networks":["udp"], "ports":[{"start":blocked_port,"end":blocked_port}], "outbound":"reject"}]);
        let mut server = Server::bind(parse(&value)).await.unwrap();
        let address = server.local_addr("vmess").unwrap();
        let dns = vmess_local_dns(&mut server).await;
        let stats = server.stats();
        let ctx = server.context.clone();
        let stop = CancellationToken::new();
        let stimulus = async {
            let stream = TcpStream::connect(address).await.unwrap();
            let request = vmess_client::Request::new(2, vmess_client::domain("sp.packet-addr.v2fly.arpa", 0), 3, 5);
            let mut client = vmess_client::Client::start(stream, request, None).await;
            for payload in [b"allowed-one".as_slice(), b"allowed-two".as_slice()] {
                client.send(&vmess_client::packetaddr(blocked.local_addr().unwrap(), b"must-not-arrive")).await;
                client.send(&vmess_client::packetaddr(allowed.local_addr().unwrap(), payload)).await;
                let mut packet = [0; 256];
                let (length, source) = allowed.recv_from(&mut packet).await.unwrap();
                assert_eq!(&packet[..length], payload);
                allowed.send_to(&packet[..length], source).await.unwrap();
                assert_eq!(client.recv().await, vmess_client::packetaddr(allowed.local_addr().unwrap(), payload));
                vmess_assert_no_dns_or_target(&dns, &tcp, &blocked).await;
            }
            let snapshot = stats.snapshot();
            assert!(snapshot.rejected >= 2);
            assert_eq!(snapshot.uplink, 22);
            assert_eq!(snapshot.downlink, 22);
            assert_eq!(snapshot.udp_associations, 1);
            stop.cancel();
            client
        };
        let (result, client) = tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        drop(client);
        assert_eq!(stats.snapshot().connections, 0);
        assert_eq!(stats.snapshot().udp_associations, 0);
        assert!(ctx.children.is_empty());
        assert_eq!(ctx.udp_slots.available_permits(), ctx.limits.max_udp_associations);
        assert_eq!(ctx.udp_bytes.available_permits(), ctx.limits.udp_queue_bytes);
    }).await.unwrap();
}

#[tokio::test]
async fn vmess_blocked_native_udp_dns_bounds_queue_and_force_joins_active_packetaddr() {
    timeout(Duration::from_secs(4), async {
        let mut value = vmess_runtime_configuration(true);
        value["limits"]["udp_queue_packets"] = json!(1);
        value["limits"]["udp_queue_bytes"] = json!(2048);
        value["limits"]["max_udp_associations"] = json!(2);
        value["limits"]["dial_timeout_ms"] = json!(10000);
        value["limits"]["udp_idle_timeout_ms"] = json!(10000);
        value["limits"]["shutdown_timeout_ms"] = json!(30);
        let mut server = Server::bind(parse(&value)).await.unwrap();
        let address = server.local_addr("vmess").unwrap();
        let handshakes = server.listeners[0].handshakes.clone();
        let dns = vmess_local_dns_with_deadline(&mut server, Duration::from_secs(10)).await;
        let ctx = server.context.clone();
        let stats = server.stats();
        let blocked_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let active_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stop = CancellationToken::new();
        let stimulus = async {
            let mut active = vmess_client::Client::start(
                TcpStream::connect(address).await.unwrap(),
                vmess_client::Request::new(
                    2,
                    vmess_client::domain("sp.packet-addr.v2fly.arpa", 0),
                    4,
                    13,
                ),
                None,
            )
            .await;
            active
                .send(&vmess_client::packetaddr(
                    active_target.local_addr().unwrap(),
                    b"active",
                ))
                .await;
            let mut buffer = [0; 1024];
            let (length, mapping) = active_target.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"active");
            active_target
                .send_to(&buffer[..length], mapping)
                .await
                .unwrap();
            assert_eq!(
                active.recv().await,
                vmess_client::packetaddr(active_target.local_addr().unwrap(), b"active")
            );

            let mut blocked = vmess_client::Client::start(
                TcpStream::connect(address).await.unwrap(),
                vmess_client::Request::new(
                    2,
                    vmess_client::domain(
                        "stall-vmess.example.com",
                        blocked_target.local_addr().unwrap().port(),
                    ),
                    3,
                    5,
                ),
                None,
            )
            .await;
            let payload = [0x73; 512];
            blocked.send(&payload).await;
            // 真实本机DNS收到查询但不回应，派发器持有一包并阻塞在目标解析。
            dns.recv_from(&mut buffer).await.unwrap();
            for _ in 0..32 {
                blocked.send(&payload).await;
            }
            while stats.snapshot().dropped < 30 {
                tokio::task::yield_now().await;
            }
            assert_eq!(stats.snapshot().connections, 2);
            assert_eq!(stats.snapshot().udp_associations, 2);
            assert_eq!(stats.snapshot().uplink, 6);
            assert_eq!(stats.snapshot().downlink, 6);
            assert_eq!(ctx.udp_slots.available_permits(), 0);
            // 固定一包在DNS中、一包在长度1队列，除此之外不积累完整业务包。
            assert_eq!(ctx.udp_bytes.available_permits(), 1024);
            assert_eq!(ctx.children.len(), 3); // 原生reader、packetaddr reader及其真实目标receiver。
            assert!(
                timeout(
                    Duration::from_millis(20),
                    blocked_target.recv_from(&mut buffer)
                )
                .await
                .is_err()
            );
            assert_eq!(handshakes.available_permits(), ctx.limits.max_handshakes);

            // 两个已认证UDP关联占满共享额度，第三个必须在成功响应前拒绝。
            let mut excess = TcpStream::connect(address).await.unwrap();
            excess
                .write_all(
                    &vmess_client::Request::new(
                        2,
                        vmess_client::target(active_target.local_addr().unwrap()),
                        3,
                        5,
                    )
                    .wire,
                )
                .await
                .unwrap();
            vmess_client::closed(&mut excess).await;
            assert!(stats.snapshot().rejected >= 1);
            assert_eq!(stats.snapshot().udp_associations, 2);
            let started = tokio::time::Instant::now();
            stop.cancel();
            (active, blocked, mapping, started)
        };
        let (result, (active, blocked, mapping, started)) =
            tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(20),
            "未经过排空期限即返回"
        );
        assert_eq!(stats.snapshot().connections, 0);
        assert_eq!(stats.snapshot().udp_associations, 0);
        assert_eq!(ctx.udp_slots.available_permits(), 2);
        assert_eq!(ctx.udp_bytes.available_permits(), 2048);
        assert_eq!(handshakes.available_permits(), ctx.limits.max_handshakes);
        assert!(ctx.children.is_closed() && ctx.children.is_empty());
        let _mapping = UdpSocket::bind(mapping).await.unwrap();
        let _listener = TcpListener::bind(address).await.unwrap();
        drop((active, blocked));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vmess_slow_tcp_reader_backpressure_force_joins_and_returns_shared_slots() {
    use tokio::io::AsyncReadExt;
    timeout(Duration::from_secs(4), async {
        let mut value = vmess_runtime_configuration(false);
        value["limits"]["max_connections"] = json!(1);
        value["limits"]["shutdown_timeout_ms"] = json!(30);
        let server = Server::bind(parse(&value)).await.unwrap();
        let address = server.local_addr("vmess").unwrap();
        let handshakes = server.listeners[0].handshakes.clone();
        let ctx = server.context.clone();
        let stats = server.stats();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stop = CancellationToken::new();
        let stimulus = async {
            let stream = TcpStream::connect(address).await.unwrap();
            socket2::SockRef::from(&stream)
                .set_recv_buffer_size(4096)
                .unwrap();
            let mut client = vmess_client::Client::start(
                stream,
                vmess_client::Request::new(
                    1,
                    vmess_client::target(target.local_addr().unwrap()),
                    3,
                    5,
                ),
                Some(b"first"),
            )
            .await;
            let (mut peer, _) = target.accept().await.unwrap();
            let mut first = [0; 5];
            peer.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"first");
            socket2::SockRef::from(&peer)
                .set_send_buffer_size(4096)
                .unwrap();
            let buffer = [0x73; 65536];
            let mut completed = 0usize;
            assert!(
                timeout(Duration::from_millis(500), async {
                    for _ in 0..1024 {
                        peer.write_all(&buffer).await.unwrap();
                        completed += 1;
                    }
                    panic!("64MiB仍未形成VMess TCP背压");
                })
                .await
                .is_err()
            );
            assert!(completed < 1024);
            assert_eq!(stats.snapshot().connections, 1);
            assert_eq!(stats.snapshot().tcp_flows, 1);
            assert_eq!(stats.snapshot().uplink, 5);
            assert!(stats.snapshot().downlink > 0);
            assert_eq!(handshakes.available_permits(), ctx.limits.max_handshakes);
            assert!(ctx.children.is_empty());
            // 已存在VMess流占满全局TCP额度，额外承载不得无限积累。
            let mut excess = TcpStream::connect(address).await.unwrap();
            vmess_client::closed(&mut excess).await;
            assert!(stats.snapshot().rejected >= 1);
            // 背压时读向仍可接受与下行无关的业务，不由无关写Pending阻塞。
            client.send(b"up-after-backpressure").await;
            let mut uplink = [0; 21];
            peer.read_exact(&mut uplink).await.unwrap();
            assert_eq!(&uplink, b"up-after-backpressure");
            let started = tokio::time::Instant::now();
            stop.cancel();
            (client, peer, started)
        };
        let (result, (client, mut peer, started)) =
            tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert_eq!(stats.snapshot().connections, 0);
        assert_eq!(stats.snapshot().tcp_flows, 0);
        assert_eq!(stats.snapshot().uplink, 26);
        assert_eq!(
            ctx.udp_slots.available_permits(),
            ctx.limits.max_udp_associations
        );
        assert_eq!(
            ctx.udp_bytes.available_permits(),
            ctx.limits.udp_queue_bytes
        );
        assert_eq!(handshakes.available_permits(), ctx.limits.max_handshakes);
        assert!(ctx.children.is_closed() && ctx.children.is_empty());
        vmess_client::closed(&mut peer).await;
        let _listener = TcpListener::bind(address).await.unwrap();
        drop(client);
    })
    .await
    .unwrap();
}

fn unavailable() -> io::Result<UdpSocket> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "injected"))
}

#[tokio::test]
async fn unavailable_dual_stack_fails_modern_preparation_and_releases_every_listener() {
    timeout(Duration::from_secs(3), async {
        let mut value = configuration();
        let mut addresses = Vec::new();
        let mut reserved = Vec::new();
        for inbound in value["inbounds"].as_array_mut().unwrap() {
            let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            inbound["listen"] = json!(address);
            addresses.push(address);
            reserved.push(socket);
        }
        drop(reserved);
        let error = Server::bind_with_udp_probe(parse(&value), unavailable)
            .await
            .err()
            .expect("2022必须在准备阶段失败");
        let message = error.to_string();
        assert!(message.contains("modern") && message.contains("双栈UDP能力不可用"));
        assert!(!message.contains("injected")); // 不直接发布底层错误材料。
        for address in addresses {
            let _tcp = TcpListener::bind(address).await.unwrap();
            let _udp = UdpSocket::bind(address).await.unwrap();
        }
        // 相同失败探针不应被2017调用，不能额外要求2017平台支持双栈出站。
        value["inbounds"].as_array_mut().unwrap().truncate(1);
        let server = Server::bind_with_udp_probe(parse(&value), unavailable)
            .await
            .unwrap();
        assert!(server.local_addr("legacy").is_some());
        drop(server);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn blocked_udp_dns_bounds_head_of_line_queue_and_force_joins_all_children() {
    use ::shadowsocks::{
        config::ServerType,
        context::Context as CryptoContext,
        crypto::CipherKind,
        relay::{
            Address,
            udprelay::{crypto_io::encrypt_client_payload, options::UdpSocketControlData},
        },
    };
    use hickory_resolver::config::ResolverOpts;
    timeout(Duration::from_secs(3), async {
        let mut value = configuration();
        value["limits"]["udp_queue_packets"] = json!(1);
        value["limits"]["udp_queue_bytes"] = json!(4096);
        value["limits"]["dial_timeout_ms"] = json!(10000);
        let mut server = Server::bind(parse(&value)).await.unwrap();
        let addresses = server.addresses.clone();
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let ctx = Arc::get_mut(&mut server.context).unwrap();
        ctx.dns = crate::dns::Dns::new(
            crate::dns::udp_resolver(dns.local_addr().unwrap(), ResolverOpts::default()).unwrap(),
            1,
            Duration::from_secs(10),
        );
        let ctx = server.context.clone();
        let stats = server.stats();
        let stop = CancellationToken::new();
        let stimulus = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let encode = |target: Address, packet_id| {
                let mut control = UdpSocketControlData::default();
                control.client_session_id = 7;
                control.packet_id = packet_id;
                let mut wire = Default::default();
                encrypt_client_payload(
                    &CryptoContext::new(ServerType::Local),
                    CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
                    &[0x11; 16],
                    &target,
                    &control,
                    &[],
                    b"blocked",
                    &mut wire,
                );
                wire.to_vec()
            };
            client
                .send_to(
                    &encode(
                        Address::DomainNameAddress("stall.example.com".into(), destination.port()),
                        1,
                    ),
                    addresses["modern"],
                )
                .await
                .unwrap();
            // DNS服务由本测试持有且不回包，证明分派器已真实阻塞，绝不查询公网。
            let mut buffer = [0; 1024];
            dns.recv_from(&mut buffer).await.unwrap();
            for packet in 2..18 {
                client
                    .send_to(
                        &encode(Address::SocketAddress(destination), packet),
                        addresses["modern"],
                    )
                    .await
                    .unwrap();
            }
            while stats.snapshot().dropped == 0 {
                tokio::task::yield_now().await;
            }
            assert_eq!(stats.snapshot().udp_associations, 1);
            assert_eq!(stats.snapshot().uplink, 0);
            assert!(ctx.udp_bytes.available_permits() >= 2048);
            assert_eq!(ctx.children.len(), 3); // 两个SS入口receiver + 一个已认证会话reader，无按包任务。
            assert!(
                timeout(Duration::from_millis(20), target.recv_from(&mut buffer))
                    .await
                    .is_err()
            );
            stop.cancel();
            client
        };
        let (result, client) = tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        assert!(ctx.children.is_empty() && ctx.children.is_closed());
        assert_eq!(stats.snapshot().udp_associations, 0);
        assert_eq!(
            ctx.udp_slots.available_permits(),
            ctx.limits.max_udp_associations
        );
        assert_eq!(ctx.udp_bytes.available_permits(), 4096);
        for address in addresses.values() {
            let _tcp = TcpListener::bind(address).await.unwrap();
            let _udp = UdpSocket::bind(address).await.unwrap();
        }
        drop(client);
    })
    .await
    .unwrap();
}

/// 有界重试绑定：只用于「刚停机、端口正在释放」的验证。
async fn bind_tcp_retrying(address: std::net::SocketAddr) -> TcpListener {
    for _ in 0..50 {
        if let Ok(listener) = TcpListener::bind(address).await {
            return listener;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("TCP 端口在期限内未释放: {address}");
}

async fn bind_udp_retrying(address: std::net::SocketAddr) -> UdpSocket {
    for _ in 0..50 {
        if let Ok(socket) = UdpSocket::bind(address).await {
            return socket;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("UDP 端口在期限内未释放: {address}");
}

#[tokio::test]
async fn stop_forces_live_tcp_slow_reader_and_native_udp_then_rebinds_session_socket() {
    use ::shadowsocks::{
        config::{ServerConfig, ServerType},
        context::Context as CryptoContext,
        crypto::CipherKind,
        relay::{
            Address,
            tcprelay::ProxyClientStream,
            udprelay::{crypto_io::encrypt_client_payload, options::UdpSocketControlData},
        },
    };
    use tokio::io::AsyncReadExt;
    timeout(Duration::from_secs(5), async {
        let server = Server::bind(parse(&configuration())).await.unwrap();
        let addresses = server.addresses.clone();
        let ctx = server.context.clone();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let datagram = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stop = CancellationToken::new();
        let stimulus = async {
            let stream = TcpStream::connect(addresses["legacy"]).await.unwrap();
            socket2::SockRef::from(&stream)
                .set_recv_buffer_size(4096)
                .unwrap();
            let key = ServerConfig::new(
                addresses["legacy"],
                "local-test-only",
                CipherKind::AES_128_GCM,
            )
            .unwrap();
            let mut tcp = ProxyClientStream::from_stream(
                Arc::new(CryptoContext::new(ServerType::Local)),
                stream,
                &key,
                Address::SocketAddress(target.local_addr().unwrap()),
            );
            tcp.write_all(b"first").await.unwrap();
            let (mut peer, _) = target.accept().await.unwrap();
            let mut first = [0; 5];
            peer.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"first");
            socket2::SockRef::from(&peer)
                .set_send_buffer_size(4096)
                .unwrap();
            // 客户端不消费响应。Linux允许的在途缓冲可能超过2MiB，不能用固定
            // 一次写入是否超时推定背压；固定64KiB缓冲、最多64MiB且500ms有界填充。
            let buffer = vec![7; 65536];
            assert!(
                timeout(Duration::from_millis(500), async {
                    for _ in 0..1024 {
                        peer.write_all(&buffer).await.unwrap();
                    }
                    panic!("64MiB仍未形成TCP背压");
                })
                .await
                .is_err()
            );
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut control = UdpSocketControlData::default();
            control.client_session_id = 7;
            control.packet_id = 1;
            let mut wire = Default::default();
            encrypt_client_payload(
                &CryptoContext::new(ServerType::Local),
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
                &[0x11; 16],
                &Address::SocketAddress(datagram.local_addr().unwrap()),
                &control,
                &[],
                b"datagram",
                &mut wire,
            );
            udp.send_to(&wire, addresses["modern"]).await.unwrap();
            let mut buffer = [0; 64];
            let (_, mapping) = datagram.recv_from(&mut buffer).await.unwrap();
            assert_eq!(ctx.stats.snapshot().tcp_flows, 1);
            assert_eq!(ctx.stats.snapshot().udp_associations, 1);
            stop.cancel();
            (tcp, peer, udp, mapping)
        };
        let (result, (tcp, peer, udp, mapping)) = tokio::join!(server.run(stop.clone()), stimulus);
        result.unwrap();
        assert_eq!(ctx.stats.snapshot().connections, 0);
        assert_eq!(ctx.stats.snapshot().tcp_flows, 0);
        assert_eq!(ctx.stats.snapshot().udp_associations, 0);
        assert_eq!(
            ctx.udp_slots.available_permits(),
            ctx.limits.max_udp_associations
        );
        assert_eq!(
            ctx.udp_bytes.available_permits(),
            ctx.limits.udp_queue_bytes
        );
        assert!(ctx.children.is_empty());
        // 停机返回后端口可能还被内核占着一小会儿（macOS 上实测到
        // `AddrInUse`）。这是「重新绑定同一地址」的时序，不是泄漏：
        // 给一个有界重试窗口，而不是把偶发失败当断言。
        let _mapping = bind_udp_retrying(mapping).await;
        for address in addresses.values() {
            let _tcp = bind_tcp_retrying(*address).await;
            let _udp = bind_udp_retrying(*address).await;
        }
        drop((tcp, peer, udp));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn one_listener_failure_cancels_all_inbounds_and_joins_half_frame_connections() {
    timeout(Duration::from_secs(3), async {
        let server = Server::bind(parse(&configuration())).await.unwrap();
        let addresses: Vec<_> = ["legacy", "modern", "socks"]
            .map(|tag| server.local_addr(tag).unwrap())
            .into();
        let stats = server.stats();
        let ctx = server.context.clone();
        let stop = CancellationToken::new();
        let observed_stop = stop.clone();
        let (fail, failure) = tokio::sync::oneshot::channel();
        let mut tasks = JoinSet::new();
        // 注入一个与真实监听任务相同的io::Result出口，覆盖统一错误/排空/force屏障。
        tasks.spawn(async move {
            failure.await.map_err(io::Error::other)?;
            Err(io::Error::other("injected-listener-failure"))
        });
        let running = server.run_with_tasks(stop, tasks);
        let stimulate = async {
            let mut peers = Vec::new();
            for (index, address) in addresses.iter().enumerate() {
                let mut peer = TcpStream::connect(address).await.unwrap();
                if index != 1 {
                    peer.write_all(&[if index == 2 { 5 } else { 1 }])
                        .await
                        .unwrap(); // SOCKS合法版本但缺后续字段；2022零字节等待首读。
                }
                peers.push(peer);
            }
            while stats.snapshot().connections != 3 {
                tokio::task::yield_now().await;
            }
            fail.send(()).unwrap();
            peers
        };
        let (result, peers) = tokio::join!(running, stimulate);
        assert!(result.is_err());
        assert!(observed_stop.is_cancelled());
        assert_eq!(stats.snapshot().connections, 0);
        assert_eq!(stats.snapshot().udp_associations, 0);
        assert_eq!(
            ctx.udp_slots.available_permits(),
            ctx.limits.max_udp_associations
        );
        assert_eq!(
            ctx.udp_bytes.available_permits(),
            ctx.limits.udp_queue_bytes
        );
        assert!(ctx.children.is_closed());
        assert!(ctx.children.is_empty());
        for address in addresses {
            let _tcp = TcpListener::bind(address).await.unwrap();
            let _udp = UdpSocket::bind(address).await.unwrap();
        }
        drop(peers);
    })
    .await
    .unwrap();
}
