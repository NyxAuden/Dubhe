//! Snell顺序池的完整运行时/路由/链式回环；不是官方客户端兼容证据。
mod common;
use common::{Echo, Running};
use dubhe::{Config, Server, forward::Context};
use serde_json::{Value, json};
use std::{
    io,
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

const PSK: &str = "test-only-snell-reuse-psk";
const KEY: &str = "test-only-snell-reuse-user";
const WAIT: Duration = Duration::from_secs(3);
fn server_options(version: u8, mode: Option<&str>, obfs: Option<&str>) -> Value {
    let mut inbound = json!({"type":"snell","tag":"snell","listen":"127.0.0.1:0","psk":PSK,"version":version,"users":[{"name":"test","userkey":KEY}]});
    if let Some(mode) = mode {
        inbound["mode"] = json!(mode);
    }
    if let Some(obfs) = obfs {
        inbound["obfs_mode"] = json!(obfs);
    }
    json!({"version":1,"inbounds":[inbound],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},
        "limits":{"shutdown_timeout_ms":300,"handshake_timeout_ms":800}})
}
fn outbound(address: SocketAddr, version: u8, mode: Option<&str>, obfs: Option<&str>) -> Value {
    let mut options = json!({"psk":PSK,"version":version,"userkey":KEY,"reuse":true});
    if let Some(mode) = mode {
        options["mode"] = json!(mode);
    }
    if let Some(obfs) = obfs {
        options["obfs_mode"] = json!(obfs);
    }
    json!({"type":"snell","tag":"up","endpoint":address.to_string(),"snell":options})
}
fn downstream(proxy: Value) -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[proxy,{"type":"reject","tag":"reject"}],"route":{"default":"up"},
        "limits":{"shutdown_timeout_ms":300,"handshake_timeout_ms":1000,"dial_timeout_ms":1000}})
}
fn context(value: Value) -> Context {
    Context::new(&Config::from_json(&value.to_string()).unwrap()).unwrap()
}
async fn business(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    message: &[u8],
) {
    stream.write_all(message).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, message);
}

/// 原始TCP前置计数桥，只转发字节，独立观察物理承载拨号次数。
struct Front {
    address: SocketAddr,
    accepts: Arc<AtomicUsize>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Front {
    async fn start(up: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let count = accepts.clone();
        let stop = CancellationToken::new();
        let token = stop.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = listener.accept() => {
                        let (mut from, _) = accepted.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        tasks.spawn(async move {
                            let mut to = TcpStream::connect(up).await.unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut from, &mut to).await;
                        });
                    }
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        Self {
            address,
            accepts,
            stop,
            task,
        }
    }
    fn count(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
    async fn close(self) {
        self.stop.cancel();
        timeout(WAIT, self.task).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn all_versions_modes_and_obfs_reuse_same_wire_across_two_targets_then_shutdown() {
    for (version, mode, obfs) in [
        (4, None, None),
        (5, None, None),
        (6, None, None),
        (6, Some("unshaped"), None),
        (6, Some("unsafe-raw"), None),
        (4, None, Some("http")),
        (4, None, Some("tls")),
        (5, None, Some("http")),
        (5, None, Some("tls")),
    ] {
        let up = Running::start(server_options(version, mode, obfs)).await;
        let front = Front::start(up.address).await;
        let down = Running::start(downstream(outbound(front.address, version, mode, obfs))).await;
        for _ in 0..2 {
            let echo = Echo::tcp("127.0.0.1", true).await;
            let (stream, _) = common::socks(1, common::address(echo.address), down.address).await;
            business(stream, &vec![0x55; 96 * 1024]).await;
            // 最后业务EOF已经收到，给根relay处理本地关闭并将流回池的调度机会。
            timeout(WAIT, async {
                while down.stats.snapshot().tcp_flows != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(
            front.count(),
            1,
            "{version}/{mode:?}/{obfs:?}必须真实减少物理拨号"
        );
        down.shutdown().await;
        front.close().await;
        up.shutdown().await;
    }
}

#[tokio::test]
async fn concurrent_streams_use_separate_leases_and_default_false_never_pools() {
    for reuse in [true, false] {
        let up = Running::start(server_options(5, None, Some("tls"))).await;
        let front = Front::start(up.address).await;
        let mut proxy = outbound(front.address, 5, None, Some("tls"));
        if !reuse {
            proxy["snell"].as_object_mut().unwrap().remove("reuse");
        }
        let down = Running::start(downstream(proxy)).await;
        let echo = Echo::tcp("127.0.0.1", false).await;
        let (mut first, _) = common::socks(1, common::address(echo.address), down.address).await;
        first.write_all(b"first").await.unwrap();
        first.read_exact(&mut [0; 5]).await.unwrap();
        let (mut second, _) = common::socks(1, common::address(echo.address), down.address).await;
        second.write_all(b"second").await.unwrap();
        let mut bytes = [0; 6];
        second.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"second");
        first.write_all(b"again").await.unwrap();
        let mut bytes = [0; 5];
        first.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"again");
        assert_eq!(front.count(), 2);
        drop(first);
        drop(second);
        timeout(WAIT, async {
            while down.stats.snapshot().tcp_flows != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let echo = Echo::tcp("127.0.0.1", true).await;
        let (stream, _) = common::socks(1, common::address(echo.address), down.address).await;
        business(stream, b"next").await;
        if !reuse {
            assert_eq!(front.count(), 3);
        }
        down.shutdown().await;
        front.close().await;
        up.shutdown().await;
    }
}

#[tokio::test]
async fn runtime_root_and_intermediate_chain_take_pool_before_redialing() {
    let socks = Running::start(json!({"version":1,"inbounds":[{"type":"socks5","tag":"hop","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":300}})).await;
    for last in [true, false] {
        let up = Running::start(server_options(5, None, Some("http"))).await;
        let front = Front::start(up.address).await;
        let mut snell = outbound(front.address, 5, None, Some("http"));
        snell["tag"] = json!(if last { "up" } else { "first" });
        let mut hop = json!({"type":"socks5","tag":if last {"first"} else {"up"},"endpoint":socks.address.to_string()});
        if last {
            snell["via"] = json!("first");
        } else {
            hop["via"] = json!("first");
        }
        let mut value = downstream(snell.clone());
        value["outbounds"] = json!([snell, hop]);
        let down = Running::start(value).await;
        for _ in 0..2 {
            let echo = Echo::tcp("127.0.0.1", true).await;
            let (stream, _) = common::socks(1, common::address(echo.address), down.address).await;
            business(stream, b"original-chain").await;
            timeout(WAIT, async {
                while down.stats.snapshot().tcp_flows != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(
            front.count(),
            1,
            "Snell位于链{last}仍须真实取池而非先拨号后丢弃"
        );
        down.shutdown().await;
        front.close().await;
        up.shutdown().await;
    }
    socks.shutdown().await;
}

#[tokio::test]
async fn reuse_does_not_share_udp_and_wrong_identity_or_reject_never_reaches_target() {
    let up = Running::start(server_options(5, None, None)).await;
    let front = Front::start(up.address).await;
    let down = Running::start(downstream(outbound(front.address, 5, None, None))).await;
    let tcp = Echo::tcp("127.0.0.1", true).await;
    let (stream, _) = common::socks(1, common::address(tcp.address), down.address).await;
    business(stream, b"tcp").await;
    let udp = Echo::udp("127.0.0.1").await;
    let (control, mut relay) = common::socks(
        3,
        common::address("0.0.0.0:0".parse().unwrap()),
        down.address,
    )
    .await;
    relay.set_ip(down.address.ip());
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0];
    packet.extend(common::address(udp.address));
    packet.extend_from_slice(b"udp");
    socket.send_to(&packet, relay).await.unwrap();
    let mut bytes = [0; 128];
    let (count, _) = timeout(WAIT, socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..count], packet);
    assert_eq!(front.count(), 2, "UDP不可复用TCP的ready会话");
    drop(control);
    drop(socket);
    down.shutdown().await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = outbound(front.address, 5, None, None);
    proxy["snell"]["userkey"] = json!("wrong-identity");
    let down = Running::start(downstream(proxy)).await;
    let (mut stream, _) = common::socks(
        1,
        common::address(target.local_addr().unwrap()),
        down.address,
    )
    .await;
    stream.write_all(b"denied").await.unwrap();
    assert!(matches!(
        timeout(WAIT, stream.read(&mut bytes)).await.unwrap(),
        Ok(0) | Err(_)
    ));
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    assert_eq!(down.stats.snapshot().downlink, 0);
    drop(stream);
    down.shutdown().await;
    let before = front.count();
    let mut value = downstream(outbound(front.address, 5, None, None));
    value["route"]["default"] = json!("reject");
    let down = Running::start(value).await;
    let mut stream = TcpStream::connect(down.address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    stream.read_exact(&mut [0; 2]).await.unwrap();
    let mut request = vec![5, 1, 0];
    request.extend(common::address(target.local_addr().unwrap()));
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 3];
    stream.read_exact(&mut reply).await.unwrap();
    assert_ne!(reply[1], 0);
    assert_eq!(front.count(), before);
    drop(stream);
    down.shutdown().await;
    front.close().await;
    up.shutdown().await;
}

#[tokio::test]
async fn hot_reload_preserves_old_live_flow_new_pool_isolated_and_shutdown_releases_ports() {
    let up = Running::start(server_options(5, None, Some("tls"))).await;
    let front = Front::start(up.address).await;
    let value = downstream(outbound(front.address, 5, None, Some("tls")));
    let config = Config::from_json(&value.to_string()).unwrap();
    let server = Server::bind(config).await.unwrap();
    let address = server.local_addr("local").unwrap();
    let reload = server.hot_reload_handle();
    let stop = CancellationToken::new();
    let task = tokio::spawn(server.run(stop.clone()));
    let echo = Echo::tcp("127.0.0.1", false).await;
    let (mut old, _) = common::socks(1, common::address(echo.address), address).await;
    old.write_all(b"before").await.unwrap();
    old.read_exact(&mut [0; 6]).await.unwrap();
    let idle_target = Echo::tcp("127.0.0.1", true).await;
    let (idle, _) = common::socks(1, common::address(idle_target.address), address).await;
    business(idle, b"pooled-before-reload").await;
    assert_eq!(front.count(), 2);
    assert!(
        reload
            .reload(&Config::from_json(&value.to_string()).unwrap())
            .unwrap()
    );
    old.write_all(b"after!").await.unwrap();
    let mut bytes = [0; 6];
    old.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"after!");
    let (mut new, _) = common::socks(1, common::address(echo.address), address).await;
    new.write_all(b"new-pool").await.unwrap();
    new.read_exact(&mut [0; 8]).await.unwrap();
    assert_eq!(front.count(), 3);
    timeout(WAIT, async {
        while up.stats.snapshot().connections != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap(); // 旧池空闲承载已关，原活流和新池活流仍在。
    // 活流/等待/空闲均不得让最终停机等待180秒；reload句柄仍持共享Context。
    drop(old);
    drop(new);
    stop.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    TcpListener::bind(address).await.unwrap();
    front.close().await;
    up.shutdown().await;
}

#[tokio::test]
async fn low_level_connect_rejects_reuse_without_runtime_instead_of_ignoring_it() {
    let config = downstream(outbound("127.0.0.1:9".parse().unwrap(), 5, None, None));
    let ctx = context(config);
    let proxy = ctx
        .router
        .select_outbound(
            "local",
            dubhe::session::Network::Tcp,
            &"127.0.0.1:443".parse::<SocketAddr>().unwrap().into(),
        )
        .proxy
        .unwrap();
    // 已提供普通流也不能把reuse静默当false；通过Context的路径由上面完整用例覆盖。
    // 不需要构造私有Upstream；公开Context先直连取得回环流。
    let direct = context(
        json!({"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default":"direct"}}),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap().into();
    let stream = direct.connect("local", &target).await.unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    let result = dubhe::outbound::connect(stream, &proxy, &target).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    let tracker = ctx.children.clone();
    drop(proxy);
    drop(ctx);
    tracker.close();
    timeout(WAIT, tracker.wait()).await.unwrap();
}
