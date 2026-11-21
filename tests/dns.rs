use dubhe::{
    Config,
    dns::Dns,
    forward::{Context, dial_addresses},
    session::{Host, Target},
};
use hickory_resolver::{
    Hosts, TokioResolver,
    config::{LookupIpStrategy, ResolveHosts, ResolverOpts},
    proto::{
        op::{Message, ResponseCode},
        rr::{RData, Record, RecordType, rdata::A},
    },
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Notify,
    time::timeout,
};

fn resolver(addr: SocketAddr, hosts: bool) -> TokioResolver {
    let mut opts = ResolverOpts::default();
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    opts.attempts = 1;
    opts.timeout = Duration::from_millis(100);
    opts.use_hosts_file = if hosts {
        ResolveHosts::Always
    } else {
        ResolveHosts::Never
    };
    dubhe::dns::udp_resolver(addr, opts).expect("测试 DNS 解析器初始化失败")
}
fn target(name: &str) -> Target {
    Target {
        host: Host::Domain(name.into()),
        port: 80,
    }
}

#[tokio::test]
async fn controlled_dns_answers_nxdomain_and_no_ip_lookup() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut b = [0; 4096];
        let mut count = 0;
        while let Ok((n, peer)) = socket.recv_from(&mut b).await {
            let request = Message::from_vec(&b[..n]).unwrap();
            let q = request.queries[0].clone();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.metadata.recursion_desired = true;
            response.metadata.recursion_available = true;
            response.add_query(q.clone());
            if q.name().to_ascii() == "found.test." {
                response.add_answer(Record::from_rdata(
                    q.name().clone(),
                    0,
                    RData::A(A(Ipv4Addr::new(127, 0, 0, 2))),
                ));
                response.add_answer(Record::from_rdata(
                    q.name().clone(),
                    0,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
            } else {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
            count += 1;
            if count == 2 {
                break;
            }
        }
        count
    });
    let dns = Dns::new(resolver(addr, false), 2, Duration::from_millis(500));
    assert_eq!(
        dns.resolve(&Target::from("127.0.0.1:9".parse::<SocketAddr>().unwrap()))
            .await
            .unwrap(),
        vec!["127.0.0.1:9".parse::<SocketAddr>().unwrap()]
    );
    let found = dns.resolve(&target("found.test.")).await.unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].ip(), Ipv4Addr::new(127, 0, 0, 2));
    assert_eq!(
        dns.resolve(&target("missing.test."))
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn hosts_mapping_works_without_dns_network() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut resolver = resolver(socket.local_addr().unwrap(), true);
    let mut hosts = Hosts::default();
    hosts
        .read_hosts_conf("127.0.0.9 custom.test\n".as_bytes())
        .unwrap();
    resolver.set_hosts(Arc::new(hosts));
    let dns = Dns::new(resolver, 1, Duration::from_millis(100));
    assert_eq!(
        dns.resolve(&target("custom.test")).await.unwrap()[0].ip(),
        Ipv4Addr::new(127, 0, 0, 9)
    );
    let mut b = [0; 64];
    assert!(
        timeout(Duration::from_millis(20), socket.recv_from(&mut b))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dns_limits_timeout_and_cancel_return_slots() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns = Arc::new(Dns::new(
        resolver(socket.local_addr().unwrap(), false),
        1,
        Duration::from_millis(40),
    ));
    let observed = Arc::new(Notify::new());
    let notify = observed.clone();
    let drain = tokio::spawn(async move {
        let mut b = [0; 4096];
        while socket.recv_from(&mut b).await.is_ok() {
            notify.notify_one();
        }
    });
    let copy = dns.clone();
    let first = tokio::spawn(async move { copy.resolve(&target("slow-one.test")).await });
    timeout(Duration::from_secs(1), observed.notified())
        .await
        .unwrap();
    assert_eq!(
        dns.resolve(&target("slow-two.test"))
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let error = dns.resolve(&target("slow-three.test")).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let copy = dns.clone();
    let next = tokio::spawn(async move { copy.resolve(&target("slow-four.test")).await });
    tokio::task::yield_now().await;
    next.abort();
    let _ = next.await;
    drain.abort();
    let _ = drain.await;
}

#[tokio::test]
async fn total_dial_timeout_cancels_slow_dns_and_returns_budget() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let value = serde_json::json!({"version":1,"inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"dial_timeout_ms":40,"dial_attempt_timeout_ms":20,"dns_timeout_ms":500}});
    let config = dubhe::Config::from_json(&value.to_string()).unwrap();
    let mut ctx = dubhe::forward::Context::new(&config).unwrap();
    ctx.dns = Dns::new(
        resolver(socket.local_addr().unwrap(), false),
        1,
        Duration::from_millis(500),
    );
    let start = std::time::Instant::now();
    let error = ctx
        .connect("socks", &target("dial-timeout.test."))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_millis(400));
    let pending_target = target("budget-returned.test.");
    let mut lookup = Box::pin(ctx.dns.resolve(&pending_target));
    tokio::select! {
        result = &mut lookup => panic!("解析名额应已归还，不能立即失败: {result:?}"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
    }
}

async fn answer_with(ip: Ipv4Addr) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut b).await {
            let request = Message::from_vec(&b[..n]).unwrap();
            let q = request.queries[0].clone();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.metadata.recursion_desired = true;
            response.metadata.recursion_available = true;
            response.add_query(q.clone());
            if q.query_type() == RecordType::A {
                response.add_answer(Record::from_rdata(q.name().clone(), 30, RData::A(A(ip))));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    addr
}

fn routed_config(primary: SocketAddr, secondary: SocketAddr) -> Config {
    let value = serde_json::json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"},
        "dns": {
            "servers": [primary.to_string()],
            "rules": [
                {"domain_suffix": ["corp.test"], "servers": [secondary.to_string()]},
                {"domains": ["exact.test"], "servers": [secondary.to_string()]}
            ]
        }
    });
    Config::from_json(&value.to_string()).unwrap()
}

#[tokio::test]
async fn dns_rules_select_servers_by_exact_and_suffix_match() {
    let primary = answer_with(Ipv4Addr::new(127, 0, 0, 1)).await;
    let secondary = answer_with(Ipv4Addr::new(127, 0, 0, 2)).await;
    let ctx = Context::new(&routed_config(primary, secondary)).unwrap();
    for (name, expected) in [
        ("www.corp.test", Ipv4Addr::new(127, 0, 0, 2)),
        ("corp.test", Ipv4Addr::new(127, 0, 0, 2)),
        ("exact.test", Ipv4Addr::new(127, 0, 0, 2)),
        ("www.public.test", Ipv4Addr::new(127, 0, 0, 1)),
        ("notcorp.test", Ipv4Addr::new(127, 0, 0, 1)),
    ] {
        let addresses = ctx.dns.resolve(&target(name)).await.unwrap();
        assert_eq!(addresses[0].ip(), expected, "{name}");
    }
}

#[test]
fn dns_rule_configuration_is_validated() {
    let parse = |dns: serde_json::Value| {
        let value = serde_json::json!({
            "version": 1,
            "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"default": "direct"},
            "dns": dns
        });
        Config::from_json(&value.to_string())
    };
    assert!(
        parse(serde_json::json!({"rules": [{"domain_suffix": ["x.test"], "servers": []}]}))
            .is_err()
    );
    assert!(parse(serde_json::json!({"rules": [{"servers": ["127.0.0.1"]}]})).is_err());
    assert!(
        parse(serde_json::json!({"rules": [{
            "domain_suffix": ["x.test"], "servers": ["tls://127.0.0.1"]
        }]}))
        .is_err(),
        "加密服务器缺少 ca_file 必须拒绝"
    );
    assert!(
        parse(serde_json::json!({"rules": [{
            "domain_suffix": ["x.test"], "servers": ["127.0.0.1", "tls://127.0.0.1"]
        }]}))
        .is_err(),
        "同一列表混用明文与加密必须拒绝"
    );
    assert!(
        parse(serde_json::json!({"rules": [{
            "domain_suffix": ["x.test"], "servers": ["127.0.0.1"]
        }]}))
        .is_ok()
    );
}

#[tokio::test]
async fn tcp_dial_retries_next_address() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stream = dial_addresses(
        &[
            SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), address.port()),
            address,
        ],
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), address);
    let _ = listener.accept().await.unwrap();
}

/// 启动一个可延迟应答的 UDP DNS 服务器，只对 `race.test.` 的 A 查询返回答案。
async fn delayed_dns(
    answer: Ipv4Addr,
    delay: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let Ok(request) = Message::from_vec(&buffer[..length]) else {
                continue;
            };
            let query = request.queries[0].clone();
            let should_answer =
                query.name().to_ascii() == "race.test." && query.query_type() == RecordType::A;
            let socket = std::sync::Arc::clone(&socket);
            let delay = delay;
            let answer = answer;
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let mut response = Message::response(request.metadata.id, request.metadata.op_code);
                response.metadata.recursion_desired = true;
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                if should_answer {
                    response.add_answer(Record::from_rdata(
                        query.name().clone(),
                        30,
                        RData::A(A(answer)),
                    ));
                }
                let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn race_rule_returns_the_first_successful_server() {
    let (slow, slow_task) =
        delayed_dns(Ipv4Addr::new(127, 0, 0, 2), Duration::from_millis(1000)).await;
    let (fast, fast_task) =
        delayed_dns(Ipv4Addr::new(127, 0, 0, 3), Duration::from_millis(0)).await;
    let config = Config::from_json(&format!(
        r#"{{
            "version": 1,
            "inbounds": [{{"type":"socks5","tag":"s","listen":"127.0.0.1:0"}}],
            "outbounds": [{{"type":"direct","tag":"d"}}],
            "route": {{"default":"d"}},
            "dns": {{
                "servers": ["{slow}"],
                "rules": [{{
                    "domain_suffix": ["race.test"],
                    "servers": ["{slow}", "{fast}"],
                    "race": true
                }}]
            }}
        }}"#
    ))
    .unwrap();
    let dns = Dns::from_config(config.dns.as_ref(), 4, Duration::from_secs(3)).unwrap();
    let started = std::time::Instant::now();
    let addresses = dns.resolve(&target("race.test")).await.unwrap();
    assert_eq!(addresses[0].ip(), Ipv4Addr::new(127, 0, 0, 3));
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "并发查询不应等待慢服务器"
    );
    slow_task.abort();
    fast_task.abort();
}
