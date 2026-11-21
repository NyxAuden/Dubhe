//! REALITY 的确定性受控 DNS/队列预算门禁；仅为 runtime 的私有测试子模块。
use super::*;
#[path = "../tests/common/reality.rs"]
mod peer;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_resolver::config::ResolverOpts;
use serde_json::json;
use std::sync::atomic::Ordering;
use tokio::{io::AsyncReadExt, time::timeout};

fn configuration(target: SocketAddr) -> serde_json::Value {
    json!({"version":1,"inbounds":[{"type":"vless-reality","tag":"reality","listen":"127.0.0.1:0","xudp":true,
        "users":[{"name":"alice","uuid":peer::UUID}],
        "reality":{"target":{"host":target.ip().to_string(),"port":target.port()},"private_key":URL_SAFE_NO_PAD.encode(peer::SERVER_PRIVATE_KEY),"server_names":["localhost"],"short_ids":["8172635445362718"]}}],
        "outbounds":[{"tag":"direct","type":"direct"}],"route":{"default":"direct"},
        "limits":{"max_connections":4,"max_handshakes":1,"max_udp_associations":1,"udp_queue_packets":1,"udp_queue_bytes":4096,
            "shutdown_timeout_ms":20,"handshake_timeout_ms":3000,"udp_idle_timeout_ms":30000,"dial_timeout_ms":10000,"dns_timeout_ms":10000,"max_dns_queries":1}})
}
fn xudp(id: u16, host: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([1, 1, 2]);
    metadata.extend(port.to_be_bytes());
    metadata.extend([2, host.len() as u8]);
    metadata.extend(host);
    let mut out = (metadata.len() as u16).to_be_bytes().to_vec();
    out.extend(metadata);
    out.extend((payload.len() as u16).to_be_bytes());
    out.extend(payload);
    out
}
async fn wait(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn uuid_and_route_rejections_precede_business_dns_and_count_once() {
    timeout(Duration::from_secs(8), async {
        for (command, bad_uuid, reject) in [
            (1, true, false),
            (2, true, false),
            (1, false, true),
            (2, false, true),
        ] {
            let target = peer::TargetPeer::start(Default::default()).await.unwrap();
            let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let business = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut value = configuration(target.address);
            if reject {
                value["outbounds"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"type":"reject","tag":"reject"}));
                value["route"]["default"] = json!("reject");
            }
            let mut server = Box::pin(Server::bind(Config::from_json(&value.to_string()).unwrap()))
                .await
                .unwrap();
            let address = server.local_addr("reality").unwrap();
            Arc::get_mut(&mut server.context).unwrap().dns = crate::dns::Dns::new(
                crate::dns::udp_resolver(dns.local_addr().unwrap(), ResolverOpts::default())
                    .unwrap(),
                1,
                Duration::from_secs(10),
            );
            let ctx = server.context.clone();
            let stats = server.stats();
            let stop = CancellationToken::new();
            let stimulus = async {
                let mut client = peer::PreparedClient::new(Default::default())
                    .unwrap()
                    .connect(address)
                    .await
                    .unwrap();
                let mut request = vec![0];
                request.extend(if bad_uuid { [0x22; 16] } else { peer::ID });
                request.extend([0, command]);
                request.extend(
                    (if command == 1 {
                        business.local_addr().unwrap()
                    } else {
                        udp.local_addr().unwrap()
                    })
                    .port()
                    .to_be_bytes(),
                );
                request.extend([2, 11]);
                request.extend(b"denied.test");
                client.send(&request).await.unwrap();
                assert!(client.plain(2).await.is_err(), "拒绝不应发送VLESS成功响应");
                wait(|| stats.snapshot().connections == 0).await;
                assert_eq!(
                    target.observation.accepted.load(Ordering::SeqCst),
                    1,
                    "辅助target已使用但不是业务连接"
                );
                assert_eq!(stats.snapshot().rejected, 1, "REALITY拒绝只能分类一次");
                let mut bytes = [0; 1024];
                assert!(
                    timeout(Duration::from_millis(20), dns.recv_from(&mut bytes))
                        .await
                        .is_err()
                );
                assert!(
                    timeout(Duration::from_millis(20), udp.recv_from(&mut bytes))
                        .await
                        .is_err()
                );
                assert!(
                    timeout(Duration::from_millis(20), business.accept())
                        .await
                        .is_err()
                );
                assert_eq!(
                    (
                        stats.snapshot().uplink,
                        stats.snapshot().downlink,
                        stats.snapshot().tcp_flows,
                        stats.snapshot().udp_associations
                    ),
                    (0, 0, 0, 0)
                );
                stop.cancel();
                client
            };
            let (result, client) = tokio::join!(server.run(stop.clone()), stimulus);
            result.unwrap();
            assert!(ctx.children.is_closed() && ctx.children.is_empty());
            drop(client);
            drop(TcpListener::bind(address).await.unwrap());
            target.shutdown().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[test]
fn blocked_reality_udp_dns_bounds_queue_bytes_packets_and_force_joins_children() {
    // 第三次迭代（VLESS Vision + REALITY）在 debug 构建下会让
    // `Server::run` 的 Vision 路径单次 poll 超过 Rust 测试线程默认 2 MiB
    // 栈（已在默认栈下确定性复现 SIGABRT）。生产代码不改，本用例改用
    // 独立 8 MiB 测试线程；这不表示默认 2 MiB 测试线程可通过。
    std::thread::Builder::new()
        .name("reality-udp-stack".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(Box::pin(async {
                timeout(Duration::from_secs(8), async {
                    for (command, vision) in [(2, false), (3, false), (3, true)] {
                        let target = peer::TargetPeer::start(Default::default()).await.unwrap();
                        let business = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                        let mut value = configuration(target.address);
                        value["inbounds"][0]["users"][0]["flow"] =
                            json!(if vision { "xtls-rprx-vision" } else { "" });
                        let mut server =
                            Box::pin(Server::bind(Config::from_json(&value.to_string()).unwrap()))
                                .await
                                .unwrap();
                        let address = server.local_addr("reality").unwrap();
                        let handshakes = server.listeners[0].handshakes.clone();
                        let mut opts = ResolverOpts::default();
                        opts.timeout = Duration::from_secs(10);
                        opts.attempts = 1;
                        Arc::get_mut(&mut server.context).unwrap().dns = crate::dns::Dns::new(
                            crate::dns::udp_resolver(dns.local_addr().unwrap(), opts).unwrap(),
                            1,
                            Duration::from_secs(10),
                        );
                        let ctx = server.context.clone();
                        let stats = server.stats();
                        let stop = CancellationToken::new();
                        let stimulus_ctx = ctx.clone();
                        let stimulus_stats = stats.clone();
                        let stimulus_handshakes = handshakes.clone();
                        let stimulus_stop = stop.clone();
                        let stimulus = tokio::spawn(async move {
                            let mut client = peer::PreparedClient::new(Default::default())
                                .unwrap()
                                .connect(address)
                                .await
                                .unwrap();
                            let payload = vec![0x71; 1024];
                            let mut request = if command == 2 {
                                let mut r = vec![0];
                                r.extend(peer::ID);
                                r.extend([0, 2]);
                                r.extend(business.local_addr().unwrap().port().to_be_bytes());
                                r.extend([2, 17]);
                                r.extend(b"stall.example.com");
                                r
                            } else {
                                peer::vless_request(
                                    3,
                                    vision.then_some("xtls-rprx-vision"),
                                    peer::ID,
                                    business.local_addr().unwrap(),
                                )
                            };
                            let packet = if command == 2 {
                                [
                                    (payload.len() as u16).to_be_bytes().to_vec(),
                                    payload.clone(),
                                ]
                                .concat()
                            } else {
                                xudp(
                                    1,
                                    b"stall.example.com",
                                    business.local_addr().unwrap().port(),
                                    &payload,
                                )
                            };
                            request.extend(if vision {
                                peer::vision_block(true, 1, &packet, 0)
                            } else {
                                packet
                            });
                            client.send(&request).await.unwrap();
                            assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
                            // 自持DNS收到真实查询但不回应；之后业务数据不得绕过队头到UDP target。
                            let mut bytes = [0; 2048];
                            dns.recv_from(&mut bytes).await.unwrap();
                            wait(|| stimulus_stats.snapshot().udp_associations == 1).await;
                            for id in 2..=16 {
                                let body = if command == 2 {
                                    [
                                        (payload.len() as u16).to_be_bytes().to_vec(),
                                        payload.clone(),
                                    ]
                                    .concat()
                                } else {
                                    xudp(
                                        id,
                                        b"other.example.com",
                                        business.local_addr().unwrap().port(),
                                        &payload,
                                    )
                                };
                                client.send(&body).await.unwrap();
                            }
                            if command == 2 {
                                wait(|| stimulus_ctx.udp_bytes.available_permits() < 4096).await;
                                wait(|| stimulus_stats.snapshot().dropped > 0).await;
                                let reserved = 4096 - stimulus_ctx.udp_bytes.available_permits();
                                assert!((1024..=4096).contains(&reserved));
                            } else {
                                // Mux 使用每条连接独立的 256 KiB 入站预算，不占用全局
                                // udp_queue_bytes；等待其停止增长并确认未绕过 DNS 阻塞。
                                tokio::time::sleep(Duration::from_millis(30)).await;
                                assert_eq!(stimulus_ctx.udp_bytes.available_permits(), 4096);
                                assert_eq!(stimulus_ctx.udp_slots.available_permits(), 0);
                            }
                            assert!(stimulus_ctx.children.len() <= 2, "不得按包创建任务");
                            assert_eq!(stimulus_stats.snapshot().uplink, 0);
                            assert_eq!(stimulus_handshakes.available_permits(), 1);
                            assert!(
                                timeout(Duration::from_millis(20), business.recv_from(&mut bytes))
                                    .await
                                    .is_err()
                            );
                            stimulus_stop.cancel();
                            client
                        });
                        let server_task = tokio::spawn(async move { server.run(stop).await });
                        let (result, client) = tokio::join!(server_task, stimulus);
                        result.unwrap().unwrap();
                        let mut client = client.unwrap();
                        assert!(ctx.children.is_closed() && ctx.children.is_empty());
                        assert_eq!(ctx.udp_bytes.available_permits(), 4096);
                        assert_eq!(ctx.udp_slots.available_permits(), 1);
                        assert_eq!(handshakes.available_permits(), 1);
                        assert_eq!(
                            (
                                stats.snapshot().connections,
                                stats.snapshot().udp_associations
                            ),
                            (0, 0)
                        );
                        let mut b = [0; 1];
                        let _ = timeout(Duration::from_secs(1), client.io.read(&mut b))
                            .await
                            .unwrap();
                        drop(TcpListener::bind(address).await.unwrap());
                        target.shutdown().await.unwrap();
                    }
                })
                .await
                .unwrap();
            }));
        })
        .unwrap()
        .join()
        .unwrap();
}
