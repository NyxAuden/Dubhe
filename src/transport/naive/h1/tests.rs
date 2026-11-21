use super::*;
use std::sync::atomic::Ordering;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
const WAIT: Duration = Duration::from_secs(3);
fn context() -> Arc<Context> {
    let config = crate::Config::from_json(r#"{"version":1,"inbounds":[{"type":"socks5","tag":"local","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],"route":{"default":"direct"},"limits":{"udp_queue_bytes":4,"udp_queue_packets":1,"max_udp_associations":1,"handshake_timeout_ms":300}}"#).unwrap();
    Arc::new(Context::new(&config).unwrap())
}
fn request(target: &str) -> Vec<u8> {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nPadding: yes\r\nProxy-Authorization: Basic dTpw\r\n\r\n").into_bytes()
}
async fn head<S: AsyncRead + Unpin>(client: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        bytes.push(client.read_u8().await.unwrap());
        if bytes.ends_with(b"\r\n\r\n") {
            return bytes;
        }
        assert!(bytes.len() <= 8192);
    }
}
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u16).to_be_bytes().to_vec();
    frame.push(0);
    frame.extend_from_slice(payload);
    frame
}
async fn response_frame<S: AsyncRead + Unpin>(client: &mut S) -> Vec<u8> {
    let size = client.read_u16().await.unwrap() as usize;
    let padding = client.read_u8().await.unwrap() as usize;
    let mut bytes = vec![0; size];
    client.read_exact(&mut bytes).await.unwrap();
    let mut waste = vec![0; padding];
    client.read_exact(&mut waste).await.unwrap();
    assert!(waste.iter().all(|byte| *byte == 0));
    bytes
}
fn spawn(
    wire: tokio::io::DuplexStream,
    ctx: Arc<Context>,
    permit: OwnedSemaphorePermit,
    deadline: Instant,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        serve(
            wire,
            "local",
            &[crate::config::User {
                name: "u".into(),
                password: "p".into(),
            }],
            ctx,
            deadline,
            permit,
        )
        .await
    })
}
async fn idle(ctx: &Context) {
    timeout(WAIT, async {
        while !ctx.children.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn slow_partial_head_deadline_returns_handshake_permit_without_dial_or_children() {
    let ctx = context();
    let slots = Arc::new(Semaphore::new(1));
    let (wire, mut client) = tokio::io::duplex(8192);
    let permit = slots.clone().acquire_owned().await.unwrap();
    let task = spawn(
        wire,
        ctx.clone(),
        permit,
        Instant::now() + Duration::from_millis(30),
    );
    client
        .write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nPadding: par")
        .await
        .unwrap();
    let error = timeout(WAIT, task).await.unwrap().unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(slots.available_permits(), 1);
    assert!(ctx.children.is_empty());
    assert_eq!(ctx.stats.snapshot().uplink, 0);
    assert_eq!(ctx.stats.snapshot().tcp_flows, 0);
    let mut rest = Vec::new();
    timeout(WAIT, client.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn h1_uot_shared_bytes_and_slot_limits_release_after_cancel_without_instance_stop() {
    let ctx = context();
    let slots = Arc::new(Semaphore::new(1));
    let (wire, mut client) = tokio::io::duplex(8192);
    let task = spawn(
        wire,
        ctx.clone(),
        slots.clone().acquire_owned().await.unwrap(),
        Instant::now() + WAIT,
    );
    client
        .write_all(&request("sp.v2.udp-over-tcp.arpa:0"))
        .await
        .unwrap();
    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    assert_eq!(slots.available_permits(), 1, "认证后不继续占握手槽");
    // v2 isConnect=true + IPv4目标；首包只握手，不在魔数上拨TCP/DNS。
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut initial = vec![1, 1, 127, 0, 0, 1];
    initial.extend_from_slice(&port.to_be_bytes());
    client.write_all(&frame(&initial)).await.unwrap();
    timeout(WAIT, async {
        while ctx.udp_slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // 第二关联共享同一限额；200之后正式请求阶段失败，不能占另一个socket/任务。
    let (other_wire, mut other) = tokio::io::duplex(8192);
    let other_task = spawn(
        other_wire,
        ctx.clone(),
        slots.clone().acquire_owned().await.unwrap(),
        Instant::now() + WAIT,
    );
    other
        .write_all(&request("sp.v2.udp-over-tcp.arpa:0"))
        .await
        .unwrap();
    head(&mut other).await;
    other.write_all(&frame(&initial)).await.unwrap();
    assert_eq!(
        timeout(WAIT, other_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let held = ctx.udp_bytes.clone().acquire_many_owned(4).await.unwrap();
    client.write_all(&frame(b"\0\x02no")).await.unwrap();
    timeout(WAIT, async {
        while ctx.stats.dropped.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_millis(30), socket.recv_from(&mut [0; 8]))
            .await
            .is_err()
    );
    drop(held);
    client.write_all(&frame(b"\0\x02ok")).await.unwrap();
    let mut bytes = [0; 16];
    let (n, peer) = timeout(WAIT, socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], b"ok");
    socket.send_to(b"ok", peer).await.unwrap();
    assert_eq!(
        timeout(WAIT, response_frame(&mut client)).await.unwrap(),
        b"\0\x02ok"
    );
    client.write_all(&frame(b"\0\0")).await.unwrap();
    let (n, peer) = timeout(WAIT, socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
    socket.send_to(b"", peer).await.unwrap();
    assert_eq!(
        timeout(WAIT, response_frame(&mut client)).await.unwrap(),
        b"\0\0"
    );
    // 取消拥有future等同force路径；必须等其析构与children回收，不先cancel全实例。
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    idle(&ctx).await;
    assert_eq!(ctx.udp_bytes.available_permits(), 4);
    assert_eq!(ctx.udp_slots.available_permits(), 1);
    assert_eq!(ctx.stats.snapshot().udp_associations, 0);
    assert!(!ctx.outbound_stop.is_cancelled());
    // 接收映射任务确实释放其真实socket。
    tokio::net::UdpSocket::bind(peer).await.unwrap();
}

#[tokio::test]
async fn aborting_partial_uot_or_truncated_padding_does_not_leave_reader_or_udp_budget() {
    for partial in [b"\0".as_slice(), b"\0\x05\0x", b"\0\x02\0\x01\x03"] {
        let ctx = context();
        let slots = Arc::new(Semaphore::new(1));
        let (wire, mut client) = tokio::io::duplex(8192);
        let task = spawn(
            wire,
            ctx.clone(),
            slots.clone().acquire_owned().await.unwrap(),
            Instant::now() + WAIT,
        );
        client
            .write_all(&request("sp.v2.udp-over-tcp.arpa:0"))
            .await
            .unwrap();
        head(&mut client).await;
        client.write_all(partial).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(timeout(WAIT, task).await.unwrap().unwrap().is_err());
        idle(&ctx).await;
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(ctx.udp_bytes.available_permits(), 4);
        assert_eq!(ctx.udp_slots.available_permits(), 1);
        assert_eq!(ctx.stats.snapshot().uplink, 0);
    }
}
