//! AnyTLS正式空闲池的运行时/原路径/TCP-UoT共享与热替换回环；非官方客户端验收。
mod common;
use common::{Certificate, Echo, Running};
use dubhe::{Config, Server};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
const WAIT: Duration = Duration::from_secs(4);
const PASSWORD: &str = "test-only-anytls-pool-password";
fn upstream(cert: &Certificate) -> Value {
    json!({"version":1,"inbounds":[{"type":"anytls","tag":"in","listen":"127.0.0.1:0","users":[{"name":"u","password":PASSWORD}],
        "certificate":cert.dir.path().join("cert.pem"),"private_key":cert.dir.path().join("key.pem")}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],
        "route":{"default":"direct"},"limits":{"shutdown_timeout_ms":300,"handshake_timeout_ms":800}})
}
fn proxy(cert: &Certificate, address: SocketAddr) -> Value {
    json!({"type":"anytls","tag":"up","endpoint":address.to_string(),"password":PASSWORD,
        "tls":{"ca_file":cert.dir.path().join("cert.pem"),"server_name":"localhost"}})
}
fn downstream(proxy: Value) -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[proxy,{"type":"reject","tag":"reject"}],"route":{"default":"up"},
        "limits":{"shutdown_timeout_ms":400,"handshake_timeout_ms":1000,"dial_timeout_ms":1000}})
}
struct Front {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Front {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let stop = CancellationToken::new();
        let token = stop.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {biased;
                    _=token.cancelled()=>break,
                    _=tasks.join_next(),if !tasks.is_empty()=>{},
                    accepted=listener.accept()=>{let(mut client,_)=accepted.unwrap();seen.fetch_add(1,Ordering::SeqCst);tasks.spawn(async move{
                        let mut server=TcpStream::connect(target).await.unwrap();let _=tokio::io::copy_bidirectional(&mut client,&mut server).await;});}
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        Self {
            address,
            count,
            stop,
            task,
        }
    }
    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
    async fn close(self) {
        self.stop.cancel();
        timeout(WAIT, self.task).await.unwrap().unwrap();
    }
}
async fn echo_open(local: SocketAddr, target: SocketAddr, payload: &[u8]) -> TcpStream {
    let (mut stream, _) = common::socks(1, common::address(target), local).await;
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = vec![0; payload.len()];
    timeout(WAIT, stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, payload);
    stream
}
async fn wait_no_business(running: &Running) {
    timeout(WAIT, async {
        while running.stats.snapshot().tcp_flows != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn associate(local: SocketAddr) -> (TcpStream, UdpSocket) {
    let (control, mut relay) =
        common::socks(3, common::address("0.0.0.0:0".parse().unwrap()), local).await;
    if relay.ip().is_unspecified() {
        relay.set_ip(local.ip());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(relay).await.unwrap();
    (control, socket)
}
fn packet(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend(common::address(target));
    bytes.extend_from_slice(data);
    bytes
}
async fn datagram(socket: &UdpSocket, target: SocketAddr, data: &[u8]) {
    socket.send(&packet(target, data)).await.unwrap();
    let mut bytes = vec![0; 65536];
    let n = timeout(WAIT, socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], packet(target, data));
}
#[test]
fn example_roundtrip_default_and_explicit_pool_configuration() {
    let config = Config::from_json(include_str!("../examples/anytls-pool-outbound.json")).unwrap();
    assert!(!config.outbounds[0].anytls.as_ref().unwrap().disable_reuse);
    Config::from_json(&serde_json::to_string(&config).unwrap()).unwrap();
}
#[tokio::test]
async fn sequential_tcp_and_uot_share_one_tls_session_but_disabled_reuse_redials() {
    for disabled in [false, true] {
        let cert = Certificate::new();
        let up = Running::start(upstream(&cert)).await;
        let front = Front::start(up.address).await;
        let mut out = proxy(&cert, front.address);
        out["anytls"] = json!({"disable_reuse":disabled});
        let down = Running::start(downstream(out)).await;
        for _ in 0..2 {
            let echo = Echo::tcp("127.0.0.1", false).await;
            let mut stream = echo_open(down.address, echo.address, &vec![0x55; 96 * 1024]).await;
            stream.shutdown().await.unwrap();
            drop(stream);
            wait_no_business(&down).await;
        }
        let udp = Echo::udp("127.0.0.1").await;
        let (control, socket) = associate(down.address).await;
        datagram(&socket, udp.address, b"uot").await;
        datagram(&socket, udp.address, b"").await;
        assert_eq!(
            front.count(),
            if disabled { 3 } else { 1 },
            "TCP/UoT必须共用池，禁用时不复用"
        );
        drop(socket);
        drop(control);
        down.shutdown().await;
        front.close().await;
        up.shutdown().await;
    }
}
#[tokio::test]
async fn concurrent_busy_sessions_are_isolated_and_peer_fin_does_not_terminate_others() {
    let cert = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    let front = Front::start(up.address).await;
    let down = Running::start(downstream(proxy(&cert, front.address))).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut first = echo_open(down.address, echo.address, b"first").await;
    let mut second = echo_open(down.address, echo.address, b"second").await;
    assert_eq!(front.count(), 2, "忙会话不被新的普通拨号窃用");
    first.shutdown().await.unwrap();
    drop(first);
    second.write_all(b"still-live").await.unwrap();
    let mut reply = [0; 10];
    second.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"still-live");
    second.shutdown().await.unwrap();
    drop(second);
    wait_no_business(&down).await;
    let mut third = echo_open(down.address, echo.address, b"third").await;
    assert_eq!(front.count(), 2);
    third.shutdown().await.unwrap();
    drop(third);
    down.shutdown().await;
    front.close().await;
    up.shutdown().await;
}
#[tokio::test]
async fn root_and_intermediate_chain_take_pool_before_tcp_tls_redial() {
    let cert = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    let socks=Running::start(json!({"version":1,"inbounds":[{"type":"socks5","tag":"hop","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":300}})).await;
    for last in [false, true] {
        let front = Front::start(up.address).await;
        let mut out = proxy(&cert, front.address);
        out["tag"] = json!(if last { "up" } else { "first" });
        let mut hop = json!({"type":"socks5","tag":if last{"first"}else{"up"},"endpoint":socks.address.to_string()});
        if last {
            out["via"] = json!("first");
        } else {
            hop["via"] = json!("first");
        }
        let mut value = downstream(out.clone());
        value["outbounds"] = json!([out, hop]);
        let down = Running::start(value).await;
        for _ in 0..2 {
            let echo = Echo::tcp("127.0.0.1", false).await;
            let mut stream = echo_open(down.address, echo.address, b"chain").await;
            stream.shutdown().await.unwrap();
            drop(stream);
            wait_no_business(&down).await;
        }
        assert_eq!(front.count(), 1, "AnyTLS在链两侧均先取池而非先拨号后丢弃");
        down.shutdown().await;
        front.close().await;
    }
    socks.shutdown().await;
    up.shutdown().await;
}
#[tokio::test]
async fn wrong_password_ca_and_target_reject_fail_without_business_or_session_poisoning() {
    let cert = Certificate::new();
    let other = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    for wrong_ca in [false, true] {
        let mut out = proxy(&cert, up.address);
        if wrong_ca {
            out["tls"]["ca_file"] = json!(other.dir.path().join("cert.pem"));
        } else {
            out["password"] = json!("wrong");
        }
        let down = Running::start(downstream(out)).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut stream = TcpStream::connect(down.address).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        stream.read_exact(&mut [0; 2]).await.unwrap();
        let mut request = vec![5, 1, 0];
        request.extend(common::address(target.local_addr().unwrap()));
        stream.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        let _ = timeout(WAIT, stream.read(&mut reply)).await.unwrap();
        let _ = stream.write_all(b"unauthorized").await;
        assert!(
            timeout(Duration::from_millis(120), target.accept())
                .await
                .is_err()
        );
        assert_eq!(down.stats.snapshot().downlink, 0);
        drop(stream);
        down.shutdown().await;
    }
    let denied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut value = upstream(&cert);
    let port = denied.local_addr().unwrap().port();
    value["route"]["rules"] = json!([{"ports":[{"start":port,"end":port}],"outbound":"reject"}]);
    let reject = Running::start(value).await;
    let down = Running::start(downstream(proxy(&cert, reject.address))).await;
    let (mut stream, _) = common::socks(
        1,
        common::address(denied.local_addr().unwrap()),
        down.address,
    )
    .await;
    let _ = stream.write_all(b"denied").await;
    assert!(matches!(
        timeout(WAIT, stream.read(&mut [0; 16])).await.unwrap(),
        Ok(0) | Err(_)
    ));
    assert!(
        timeout(Duration::from_millis(100), denied.accept())
            .await
            .is_err()
    );
    drop(stream);
    wait_no_business(&down).await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let live = echo_open(down.address, echo.address, b"not-poisoned").await;
    drop(live);
    down.shutdown().await;
    reject.shutdown().await;
    up.shutdown().await;
}
#[tokio::test]
async fn blocked_downlink_partial_client_frame_and_active_pool_are_reclaimed_on_force_stop() {
    let cert = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    let down = Running::start(downstream(proxy(&cert, up.address))).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stream, _) = common::socks(
        1,
        common::address(target.local_addr().unwrap()),
        down.address,
    )
    .await;
    let (mut remote, _) = target.accept().await.unwrap();
    stream.write_all(b"request").await.unwrap();
    remote.read_exact(&mut [0; 7]).await.unwrap();
    let blocked = tokio::spawn(async move {
        let bytes = vec![0x55; 256 * 1024];
        loop {
            if remote.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
    // 下游不读，允许会话4块读队列形成背压，再停止；不能留read/writer自持Arc任务。
    tokio::task::yield_now().await;
    let address = down.address;
    down.shutdown().await;
    drop(stream);
    timeout(WAIT, blocked).await.unwrap().unwrap();
    TcpListener::bind(address).await.unwrap();
    let mut partial = TcpStream::connect(up.address).await.unwrap();
    // 已有TLS池与这个未完成TLS头的客户端都必须在同一停机期限内回收。
    partial.write_all(&[0x16, 3, 1]).await.unwrap();
    let address = up.address;
    up.shutdown().await;
    drop(partial);
    TcpListener::bind(address).await.unwrap();
}

#[tokio::test]
async fn compiled_outbounds_with_same_endpoint_have_distinct_pool_and_scheme_instances() {
    let cert = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    let front = Front::start(up.address).await;
    let first = proxy(&cert, front.address);
    let mut other = first.clone();
    other["tag"] = json!("other");
    let first_target = Echo::tcp("127.0.0.1", false).await;
    let other_target = Echo::tcp("127.0.0.1", false).await;
    let mut value = downstream(first.clone());
    value["outbounds"] = json!([first, other]);
    let port = other_target.address.port();
    value["route"]["rules"] = json!([{"ports":[{"start":port,"end":port}],"outbound":"other"}]);
    let down = Running::start(value).await;
    let mut first = echo_open(down.address, first_target.address, b"first-pool").await;
    first.shutdown().await.unwrap();
    drop(first);
    wait_no_business(&down).await;
    let mut other = echo_open(down.address, other_target.address, b"other-pool").await;
    assert_eq!(front.count(), 2, "同端点不同出站不串池");
    other.shutdown().await.unwrap();
    drop(other);
    wait_no_business(&down).await;
    let mut first = echo_open(down.address, first_target.address, b"same-first-pool").await;
    assert_eq!(front.count(), 2);
    first.shutdown().await.unwrap();
    drop(first);
    down.shutdown().await;
    front.close().await;
    up.shutdown().await;
}

#[tokio::test]
async fn review_ready_intermediate_session_skips_dns_while_miss_still_uses_resolver() {
    use dubhe::{dns::Dns, forward::Context};
    use hickory_resolver::config::{ResolveHosts, ResolverOpts};
    use hickory_resolver::proto::op::{Message, ResponseCode};
    let cert = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    let front = Front::start(up.address).await;
    let socks = Running::start(json!({"version":1,"inbounds":[{"type":"socks5","tag":"hop","listen":"127.0.0.1:0"}],
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":300}})).await;
    let mut out = proxy(&cert, front.address);
    out["tag"] = json!("first");
    out["endpoint"] = json!(format!("pool-endpoint.test:{}", front.address.port()));
    let mut value = downstream(out.clone());
    value["outbounds"] = json!([out, {"type":"socks5","tag":"up","endpoint":socks.address.to_string(),"via":"first"}]);
    value["dns"] = json!({"hosts":{"pool-endpoint.test":["127.0.0.1"]}});
    let config = Config::from_json(&value.to_string()).unwrap();
    let mut ctx = Context::new(&config).unwrap();
    let tracker = ctx.children.clone();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let destination = echo.address.into();
    let mut first = ctx.connect("local", &destination).await.unwrap();
    first.write_all(b"before").await.unwrap();
    first.flush().await.unwrap();
    first.read_exact(&mut [0; 6]).await.unwrap();
    first.shutdown().await.unwrap();
    drop(first);
    // 同一已编译池不变，只替换解析器快照：确定性模拟缓存失效后的NXDOMAIN，不靠真实DNS/时间等待。
    let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = dns.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let observed = queries.clone();
    let dns_task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        while let Ok((n, peer)) = dns.recv_from(&mut bytes).await {
            observed.fetch_add(1, Ordering::SeqCst);
            let request = Message::from_vec(&bytes[..n]).unwrap();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.metadata.recursion_desired = true;
            response.metadata.recursion_available = true;
            response.metadata.response_code = ResponseCode::NXDomain;
            for query in &request.queries {
                response.add_query(query.clone());
            }
            dns.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut options = ResolverOpts::default();
    options.use_hosts_file = ResolveHosts::Never;
    options.attempts = 1;
    options.cache_size = 0;
    ctx.dns = Dns::new(
        dubhe::dns::udp_resolver(address, options).unwrap(),
        1,
        Duration::from_millis(300),
    );
    let mut next = ctx
        .connect("local", &destination)
        .await
        .expect("健康中间会话先取池，不应被DNS失败阻断");
    next.write_all(b"after").await.unwrap();
    next.flush().await.unwrap();
    let mut bytes = [0; 5];
    next.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"after");
    assert_eq!(queries.load(Ordering::SeqCst), 0);
    assert_eq!(front.count(), 1);
    next.shutdown().await.unwrap();
    drop(next);
    // 新Context无缓存会话，必须查询同一受控DNS并明确失败，不能绕过resolver直连。
    value["dns"] = json!({"servers":[address.to_string()]});
    let miss = Context::new(&Config::from_json(&value.to_string()).unwrap()).unwrap();
    assert!(miss.connect("local", &destination).await.is_err());
    assert!(queries.load(Ordering::SeqCst) > 0);
    assert_eq!(front.count(), 1);
    drop(miss);
    drop(ctx);
    tracker.close();
    timeout(WAIT, tracker.wait()).await.unwrap();
    dns_task.abort();
    let _ = dns_task.await;
    front.close().await;
    socks.shutdown().await;
    up.shutdown().await;
}

#[tokio::test]
async fn hot_reload_retires_idle_pool_preserves_active_stream_and_final_shutdown_releases_ports() {
    let cert = Certificate::new();
    let up = Running::start(upstream(&cert)).await;
    let front = Front::start(up.address).await;
    let value = downstream(proxy(&cert, front.address));
    let config = Config::from_json(&value.to_string()).unwrap();
    let server = Server::bind(config).await.unwrap();
    let address = server.local_addr("local").unwrap();
    let hot = server.hot_reload_handle();
    let stop = CancellationToken::new();
    let task = tokio::spawn(server.run(stop.clone()));
    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut old = echo_open(address, echo.address, b"old-active").await;
    let mut idle = echo_open(address, echo.address, b"old-idle").await;
    idle.shutdown().await.unwrap();
    drop(idle);
    assert!(
        hot.reload(&Config::from_json(&value.to_string()).unwrap())
            .unwrap()
    );
    old.write_all(b"after-reload").await.unwrap();
    let mut reply = [0; 12];
    old.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"after-reload");
    let new = echo_open(address, echo.address, b"new-pool").await;
    assert_eq!(front.count(), 3);
    timeout(WAIT, async {
        while up.stats.snapshot().connections != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(old);
    drop(new);
    stop.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    TcpListener::bind(address).await.unwrap();
    front.close().await;
    up.shutdown().await;
}
