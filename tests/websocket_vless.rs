mod common;
#[path = "common/websocket.rs"]
mod ws;

use common::*;
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(3);
const UUID_ONE: &str = "11111111-1111-1111-1111-111111111111";
const UUID_TWO: &str = "22222222-2222-2222-2222-222222222222";
const VISION_ADDONS: &[u8] = b"\x0a\x10xtls-rprx-vision";

// 只统一测试端真实 TCP/TLS IO，不使用生产承载或协议编解码。
trait Wire: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Wire for T {}
type Peer = ws::Peer<Box<dyn Wire>>;

fn config(cert: Option<&Certificate>, xudp: Option<bool>) -> Value {
    let mut value = socks_config();
    let mut inbound = json!({
        "type":"vless-ws", "tag":"vless-ws", "listen":"127.0.0.1:0",
        "websocket":{"path":"/proxy"},
        "users":[{"name":"one","uuid":UUID_ONE},{"name":"two","uuid":UUID_TWO}]
    });
    if let Some(cert) = cert {
        inbound["certificate"] = json!(cert.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(cert.dir.path().join("key.pem"));
    } else {
        inbound["allow_insecure_transport"] = json!(true);
    }
    if let Some(enabled) = xudp {
        inbound["xudp"] = json!(enabled);
    }
    value["inbounds"] = json!([inbound]);
    value["limits"]["handshake_timeout_ms"] = json!(2000);
    value["limits"]["udp_idle_timeout_ms"] = json!(10000);
    value
}

async fn connect(cert: Option<&Certificate>, server: &Running, raw_prefix: &[u8]) -> Peer {
    let io: Box<dyn Wire> = match cert {
        Some(cert) => {
            let io = cert.connect(server.address).await;
            io.get_ref().0.set_nodelay(true).unwrap();
            Box::new(io)
        }
        None => {
            let io = timeout(WAIT, TcpStream::connect(server.address))
                .await
                .unwrap()
                .unwrap();
            io.set_nodelay(true).unwrap();
            Box::new(io)
        }
    };
    ws::upgrade(io, "/proxy", "", raw_prefix).await
}

// VLESS 地址为端口在前，IPv6 类型为 3，不能借用 SOCKS 地址 helper。
fn target(addr: SocketAddr) -> Vec<u8> {
    let mut bytes = addr.port().to_be_bytes().to_vec();
    match addr.ip() {
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

fn localhost(port: u16) -> Vec<u8> {
    let mut bytes = port.to_be_bytes().to_vec();
    bytes.extend(b"\x02\x09localhost");
    bytes
}

fn header(identity: u8, command: u8, address: &[u8], addons: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend([identity; 16]);
    bytes.push(u8::try_from(addons.len()).unwrap());
    bytes.extend(addons);
    bytes.push(command);
    bytes.extend(address);
    bytes
}

fn request(command: u8, addr: SocketAddr) -> Vec<u8> {
    header(0x11, command, &target(addr), &[])
}

fn datagram(payload: &[u8]) -> Vec<u8> {
    let mut bytes = u16::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend(payload);
    bytes
}

// XUDP 元数据和数据长度独立编码；同一测试内复用固定 GlobalID 以观察接管，
// 不同并行测试使用不同值，避免进程级 GlobalID 表相互串扰。
fn xframe(
    id: u16,
    status: u8,
    address: Option<Vec<u8>>,
    global: bool,
    payload: Option<&[u8]>,
) -> Vec<u8> {
    xframe_global(id, status, address, global.then_some([0x77; 8]), payload)
}
// GlobalID 是进程级键；并行测试必须使用互不相同的值，避免相互接管。
fn xframe_gid(
    id: u16,
    status: u8,
    address: Option<Vec<u8>>,
    global: [u8; 8],
    payload: Option<&[u8]>,
) -> Vec<u8> {
    xframe_global(id, status, address, Some(global), payload)
}
fn xframe_global(
    id: u16,
    status: u8,
    address: Option<Vec<u8>>,
    global: Option<[u8; 8]>,
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([status, u8::from(payload.is_some())]);
    if let Some(address) = address {
        metadata.push(2); // UDP；TCP 负向用例会明确改成 1。
        metadata.extend(address);
    }
    if let Some(global) = global {
        metadata.extend(global);
    }
    let mut bytes = u16::try_from(metadata.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    bytes.extend(metadata);
    if let Some(payload) = payload {
        bytes.extend(datagram(payload));
    }
    bytes
}

fn xmetadata(id: u16, addr: SocketAddr) -> Vec<u8> {
    let mut bytes = id.to_be_bytes().to_vec();
    bytes.extend([2, 1, 2]);
    bytes.extend(target(addr));
    bytes
}

async fn send<S: AsyncWrite + Unpin>(peer: &mut S, bytes: &[u8]) {
    timeout(WAIT, async {
        peer.write_all(bytes).await.unwrap();
        peer.flush().await.unwrap();
    })
    .await
    .unwrap();
}

async fn message(peer: &mut Peer, opcode: u8, payload: &[u8]) {
    timeout(WAIT, peer.send_message(opcode, payload))
        .await
        .unwrap();
}

async fn fragment(peer: &mut Peer, fin: bool, opcode: u8, payload: &[u8]) {
    timeout(WAIT, peer.send_fragment(fin, opcode, payload))
        .await
        .unwrap();
}

async fn response<S: AsyncRead + Unpin>(peer: &mut S) {
    let mut bytes = [0xff; 2];
    read_exact(peer, &mut bytes).await;
    assert_eq!(bytes, [0, 0], "必须且仅应出现所属 VLESS 响应");
}

async fn payload<S: AsyncRead + Unpin>(peer: &mut S, expected: &[u8]) {
    let mut bytes = vec![0; expected.len()];
    read_exact(peer, &mut bytes).await;
    assert_eq!(bytes, expected);
}

async fn packet<S: AsyncRead + Unpin>(peer: &mut S, expected: &[u8]) {
    let mut length = [0; 2];
    read_exact(peer, &mut length).await;
    assert_eq!(usize::from(u16::from_be_bytes(length)), expected.len());
    payload(peer, expected).await;
}

async fn xrecv<S: AsyncRead + Unpin>(peer: &mut S) -> (Vec<u8>, Vec<u8>) {
    timeout(WAIT, async {
        let length = usize::from(peer.read_u16().await.unwrap());
        assert!((4..=512).contains(&length));
        let mut metadata = vec![0; length];
        peer.read_exact(&mut metadata).await.unwrap();
        let mut data = Vec::new();
        if metadata[3] & 1 != 0 {
            let length = usize::from(peer.read_u16().await.unwrap());
            assert!(length <= 512);
            data.resize(length, 0);
            peer.read_exact(&mut data).await.unwrap();
        }
        (metadata, data)
    })
    .await
    .unwrap()
}

async fn xexpect<S: AsyncRead + Unpin>(peer: &mut S, id: u16, addr: SocketAddr, data: &[u8]) {
    let (metadata, received) = xrecv(peer).await;
    assert_eq!(metadata, xmetadata(id, addr));
    assert_eq!(received, data);
}

async fn xerror<S: AsyncRead + Unpin>(peer: &mut S, id: u16) {
    let (metadata, data) = xrecv(peer).await;
    let [hi, lo] = id.to_be_bytes();
    assert_eq!(metadata, [hi, lo, 3, 2]);
    assert!(data.is_empty());
}
async fn xend<S: AsyncRead + Unpin>(peer: &mut S, id: u16) {
    let (metadata, data) = xrecv(peer).await;
    let [hi, lo] = id.to_be_bytes();
    assert_eq!(metadata, [hi, lo, 3, 0]);
    assert!(data.is_empty());
}

async fn recv_udp(socket: &UdpSocket, expected: &[u8]) -> SocketAddr {
    let mut bytes = vec![0; 65536];
    let (n, peer) = timeout(WAIT, socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], expected);
    peer
}

async fn no_udp(socket: &UdpSocket) {
    let mut bytes = [0; 1024];
    assert!(
        timeout(Duration::from_millis(40), socket.recv_from(&mut bytes))
            .await
            .is_err(),
        "受控 UDP 目标不应收到数据报"
    );
}

async fn target_pair() -> (TcpListener, UdpSocket) {
    // TCP 的临时端口可能已被其他测试的 UDP 占用，只重试本测试自己的绑定。
    for _ in 0..32 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        match UdpSocket::bind(tcp.local_addr().unwrap()).await {
            Ok(udp) => return (tcp, udp),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("绑定受控 UDP 目标失败: {error}"),
        }
    }
    panic!("未能准备同端口 TCP/UDP 受控目标");
}

async fn no_target(tcp: &TcpListener, udp: &UdpSocket) {
    assert!(
        timeout(Duration::from_millis(40), tcp.accept())
            .await
            .is_err(),
        "受控 TCP 目标不应被拨号"
    );
    no_udp(udp).await;
}

async fn associations(server: &Running, expected: usize) {
    let converged = timeout(WAIT, async {
        while server.stats.snapshot().udp_associations != expected {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "UDP 关联数未收敛到 {expected}: {:?}",
        server.stats.snapshot()
    );
}

async fn finish(peer: &mut Peer) {
    // Close 终止整个 WS 会话；绝不借此声称存在透明的客户端单向 FIN。
    timeout(WAIT, peer.close()).await.unwrap();
    ws::closed(peer).await;
}

async fn stop(server: Running, uplink: u64, downlink: u64) {
    let stats = server.stats.clone();
    server.shutdown().await;
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.uplink, uplink);
    assert_eq!(snapshot.downlink, downlink);
}

#[tokio::test]
async fn tcp_ws_and_wss_preserve_prefetch_split_messages_fragments_and_counts() {
    let cert = Certificate::new();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let first = b"first-payload-not-a-response-header";
    let second = b"second-exchange";
    let large: Vec<_> = (0..70000).map(|n| (n % 251) as u8).collect();
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        let server = Running::start(config(cert, None)).await;
        let mut transferred = 0u64;
        for layout in 0..3 {
            let address = if layout == 1 {
                localhost(echo.address.port())
            } else {
                target(echo.address)
            };
            let mut bytes = header(0x11, 1, &address, &[]);
            bytes.extend(first);
            let prefix = if layout == 0 {
                ws::masked(true, 2, &bytes)
            } else {
                Vec::new()
            };
            let mut peer = connect(cert, &server, &prefix).await;
            match layout {
                0 => {} // HTTP 头、完整首帧、VLESS 头和首载荷一次提交。
                1 => {
                    message(&mut peer, 2, b"").await;
                    for byte in &bytes {
                        message(&mut peer, 2, &[*byte]).await;
                    }
                }
                _ => {
                    message(&mut peer, 2, &bytes[..7]).await;
                    message(&mut peer, 2, b"").await;
                    fragment(&mut peer, false, 2, &bytes[7..19]).await;
                    message(&mut peer, 9, b"not-business-ping").await;
                    fragment(&mut peer, false, 0, &bytes[19..27]).await;
                    fragment(&mut peer, false, 0, b"").await;
                    message(&mut peer, 10, b"not-business-pong").await;
                    fragment(&mut peer, true, 0, &bytes[27..]).await;
                }
            }
            response(&mut peer).await;
            payload(&mut peer, first).await;
            send(&mut peer, second).await;
            payload(&mut peer, second).await;
            transferred += (first.len() + second.len()) as u64;
            if layout == 2 {
                send(&mut peer, &large).await;
                payload(&mut peer, &large).await;
                transferred += large.len() as u64;
            }
            // 第二次交换和关闭前无额外字节也会捕获重复的 [0,0] 应答。
            finish(&mut peer).await;
        }
        stop(server, transferred, transferred).await;
    }
}

#[tokio::test]
async fn tcp_ws_and_wss_server_first_needs_no_client_payload_or_fin() {
    let cert = Certificate::new();
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Running::start(config(cert, None)).await;
        let backend = async {
            let (mut io, _) = listener.accept().await.unwrap();
            io.write_all(b"server-first").await.unwrap();
            io.flush().await.unwrap();
            payload(&mut io, b"client-after-greeting").await;
            io.write_all(b"server-second").await.unwrap();
            io.flush().await.unwrap();
            let mut byte = [0];
            assert_eq!(io.read(&mut byte).await.unwrap(), 0);
        };
        let client = async {
            let prefix = ws::masked(true, 2, &request(1, addr));
            let mut peer = connect(cert, &server, &prefix).await;
            response(&mut peer).await;
            payload(&mut peer, b"server-first").await;
            send(&mut peer, b"client-after-greeting").await;
            payload(&mut peer, b"server-second").await;
            finish(&mut peer).await;
        };
        timeout(WAIT, async { tokio::join!(backend, client) })
            .await
            .unwrap();
        stop(
            server,
            b"client-after-greeting".len() as u64,
            (b"server-first".len() + b"server-second".len()) as u64,
        )
        .await;
    }
}

async fn native_udp_policy(cert: Option<&Certificate>, bind: &str) {
    let destination = UdpSocket::bind(bind).await.unwrap();
    let attacker = UdpSocket::bind(bind).await.unwrap();
    let addr = destination.local_addr().unwrap();
    let mut value = config(cert, None);
    value["limits"]["max_udp_payload"] = json!(512);
    let server = Running::start(value).await;
    let stats = server.stats.clone();
    let header = request(2, addr);
    let mut peer = connect(cert, &server, &ws::masked(true, 2, &header[..5])).await;
    let first = b"native-first";
    let second = b"native-second";
    let mut bytes = header[5..].to_vec();
    bytes.extend(datagram(first));
    bytes.extend(datagram(b""));
    bytes.extend(datagram(second));
    // 跨消息切在数据报长度的中间；一个后续消息又承载多个数据报。
    let split = header.len() - 5 + 1;
    message(&mut peer, 2, &bytes[..split]).await;
    fragment(&mut peer, false, 2, &bytes[split..split + 2]).await;
    message(&mut peer, 9, b"udp-ping").await;
    fragment(&mut peer, true, 0, &bytes[split + 2..]).await;
    response(&mut peer).await;
    let mapping = recv_udp(&destination, first).await;
    assert_eq!(recv_udp(&destination, second).await, mapping);
    attacker.send_to(b"spoofed", mapping).await.unwrap();
    destination.send_to(b"", mapping).await.unwrap();
    destination.send_to(&[0x6b; 513], mapping).await.unwrap();
    destination.send_to(b"reply-one", mapping).await.unwrap();
    packet(&mut peer, b"reply-one").await;
    destination.send_to(b"reply-two", mapping).await.unwrap();
    packet(&mut peer, b"reply-two").await;

    let large = vec![0x5a; 512];
    let bytes = datagram(&large);
    message(&mut peer, 2, &bytes[..1]).await;
    message(&mut peer, 2, &bytes[1..]).await;
    assert_eq!(recv_udp(&destination, &large).await, mapping);
    destination.send_to(&large, mapping).await.unwrap();
    packet(&mut peer, &large).await;
    no_udp(&destination).await; // 空包不得传给目标。

    // 只给出 max+1 长度，不提供正文；应及时终止而非等待正文补齐。
    message(&mut peer, 2, &513u16.to_be_bytes()).await;
    ws::closed(&mut peer).await;
    associations(&server, 0).await;
    let _released = rebind_udp(mapping).await;

    let mut truncated = connect(cert, &server, &ws::masked(true, 2, &header)).await;
    response(&mut truncated).await;
    send(&mut truncated, &[0, 4, 0xab]).await;
    finish(&mut truncated).await;
    no_udp(&destination).await;
    stop(
        server,
        (first.len() + second.len() + large.len()) as u64,
        (b"reply-one".len() + b"reply-two".len() + large.len()) as u64,
    )
    .await;
    assert!(stats.snapshot().dropped >= 1);
}

#[tokio::test]
async fn native_udp_ws_and_wss_preserve_boundaries_source_empty_and_size_policy() {
    let cert = Certificate::new();
    for tls in [false, true] {
        native_udp_policy(tls.then_some(&cert), "127.0.0.1:0").await;
    }
}

#[tokio::test]
async fn xudp_ws_and_wss_keep_targets_sessions_sources_and_payload_sizes() {
    let cert = Certificate::new();
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();
        let mut value = config(cert, Some(true));
        value["limits"]["max_udp_payload"] = json!(512);
        let server = Running::start(value).await;
        let stats = server.stats.clone();
        let mut bytes = header(0x11, 3, &[], &[]);
        bytes.extend(xframe_gid(
            7,
            1,
            Some(target(addr_a)),
            [0x11; 8],
            Some(b"first"),
        ));
        bytes.extend(xframe(9, 1, Some(target(addr_b)), false, Some(b"other")));
        let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes[..8])).await;
        send(&mut peer, &bytes[8..]).await;
        // 命令 3 认证成功后立即返回唯一 VLESS 响应；先合并发送 header 与首帧再读取。
        response(&mut peer).await;
        let map_a = recv_udp(&a, b"first").await;
        let map_b = recv_udp(&b, b"other").await;
        attacker.send_to(b"spoofed", map_a).await.unwrap();
        a.send_to(b"", map_a).await.unwrap();
        a.send_to(&[0x6b; 513], map_a).await.unwrap();
        b.send_to(b"other", map_b).await.unwrap();
        a.send_to(b"first", map_a).await.unwrap();
        // 空数据报保留边界；超限回包丢弃。
        let mut received = vec![
            xrecv(&mut peer).await,
            xrecv(&mut peer).await,
            xrecv(&mut peer).await,
        ];
        received.sort();
        let mut expected = vec![
            (xmetadata(7, addr_a), Vec::new()),
            (xmetadata(7, addr_a), b"first".to_vec()),
            (xmetadata(9, addr_b), b"other".to_vec()),
        ];
        expected.sort();
        assert_eq!(received, expected);

        send(
            &mut peer,
            &xframe(7, 2, Some(target(addr_b)), false, Some(b"switch")),
        )
        .await;
        let switched = recv_udp(&b, b"switch").await;
        assert_ne!(switched, map_b, "不同会话不能共用目标映射");
        b.send_to(b"switch", switched).await.unwrap();
        xexpect(&mut peer, 7, addr_b, b"switch").await;

        let large = vec![0x5a; 512];
        let bytes = xframe(7, 2, None, false, Some(&large));
        for chunk in bytes.chunks(17) {
            message(&mut peer, 2, chunk).await;
        }
        // 不带目标的 Keep 回到最初 A，而不是最近一次显式切换的 B。
        assert_eq!(recv_udp(&a, &large).await, map_a);
        a.send_to(&large, map_a).await.unwrap();
        xexpect(&mut peer, 7, addr_a, &large).await;
        let mut bytes = xframe(7, 2, None, false, Some(b""));
        bytes.extend(xframe(7, 2, None, false, Some(b"last")));
        send(&mut peer, &bytes).await;
        // 空请求保留为独立数据报，目标端也必须先看到它，再看到非空包。
        assert_eq!(recv_udp(&a, b"").await, map_a);
        assert_eq!(recv_udp(&a, b"last").await, map_a);
        a.send_to(b"last", map_a).await.unwrap();
        xexpect(&mut peer, 7, addr_a, b"last").await;
        no_udp(&a).await;
        no_udp(&b).await;

        // 超限声明必须连同正文读取后按会话拒绝；整条 Mux 连接仍存活。
        let oversized = xframe(7, 2, None, false, Some(&[0x6b; 513]));
        send(&mut peer, &oversized).await;
        xerror(&mut peer, 7).await;
        // 只结束出错会话；会话 9 仍持有自己的关联。
        associations(&server, 1).await;
        no_udp(&a).await;
        no_udp(&b).await;
        finish(&mut peer).await;
        associations(&server, 0).await;
        stop(server, 532, 532).await;
        assert!(stats.snapshot().dropped >= 1);
    }
}

#[tokio::test]
async fn xudp_ws_and_wss_global_id_takeover_moves_sink_and_ends_old_session() {
    let cert = Certificate::new();
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = destination.local_addr().unwrap();
        let server = Running::start(config(cert, Some(true))).await;
        let mut bytes = header(0x11, 3, &[], &[]);
        bytes.extend(xframe_gid(
            0,
            1,
            Some(target(addr)),
            [0x22; 8],
            Some(b"one"),
        ));
        let mut one = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
        response(&mut one).await;
        let shared = recv_udp(&destination, b"one").await;

        // 同一 GlobalID（不同用户/连接）复用关联并把回程 sink 迁到后到连接。
        let mut bytes = header(0x22, 3, &[], &[]);
        bytes.extend(xframe_gid(
            0,
            1,
            Some(target(addr)),
            [0x22; 8],
            Some(b"two"),
        ));
        let mut two = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
        response(&mut two).await;
        let second = recv_udp(&destination, b"two").await;
        assert_eq!(second, shared);
        xerror(&mut one, 0).await;
        destination.send_to(b"reply-two", shared).await.unwrap();
        xexpect(&mut two, 0, addr, b"reply-two").await;

        // 旧连接只丢失被接管的会话，仍可承载其他会话。
        send(
            &mut one,
            &xframe(7, 1, Some(target(addr)), false, Some(b"other")),
        )
        .await;
        let other = recv_udp(&destination, b"other").await;
        assert_ne!(other, shared);
        destination.send_to(b"reply-other", other).await.unwrap();
        xexpect(&mut one, 7, addr, b"reply-other").await;

        send(&mut two, &xframe(0, 3, None, false, None)).await;
        associations(&server, 1).await;
        // 宽限期内映射与源端口仍由全局关联持有，不能被重新绑定。
        assert!(
            UdpSocket::bind(shared).await.is_err(),
            "宽限期内不应释放源端口"
        );
        send(
            &mut two,
            &xframe_gid(0, 1, Some(target(addr)), [0x22; 8], Some(b"new")),
        )
        .await;
        let fresh = recv_udp(&destination, b"new").await;
        assert_eq!(fresh, shared, "宽限期内必须复用同一 UDP 关联");
        destination.send_to(b"fresh", fresh).await.unwrap();
        xexpect(&mut two, 0, addr, b"fresh").await;

        send(&mut one, &xframe(7, 3, None, false, None)).await;
        send(&mut two, &xframe(0, 3, None, false, None)).await;
        associations(&server, 0).await;
        finish(&mut one).await;
        finish(&mut two).await;
        stop(server, 14, 25).await;
        let _fresh_rebound = rebind_udp(fresh).await;
        let _second_rebound = rebind_udp(other).await;
    }
}

#[tokio::test]
async fn ipv6_ws_and_wss_tcp_native_udp_and_xudp_when_available() {
    let Ok(tcp_probe) = TcpListener::bind("[::1]:0").await else {
        eprintln!("SKIP VLESS WS/WSS IPv6：当前环境没有 IPv6 TCP 回环");
        return;
    };
    let Ok(udp_probe) = UdpSocket::bind("[::1]:0").await else {
        eprintln!("SKIP VLESS WS/WSS IPv6：当前环境没有 IPv6 UDP 回环");
        return;
    };
    drop(tcp_probe);
    drop(udp_probe);
    let cert = Certificate::new();
    let echo = Echo::tcp("[::1]", false).await;
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        native_udp_policy(cert, "[::1]:0").await;
        let destination = UdpSocket::bind("[::1]:0").await.unwrap();
        let addr = destination.local_addr().unwrap();
        let server = Running::start(config(cert, Some(true))).await;
        let mut tcp = connect(
            cert,
            &server,
            &ws::masked(true, 2, &request(1, echo.address)),
        )
        .await;
        response(&mut tcp).await;
        send(&mut tcp, b"ipv6-tcp").await;
        payload(&mut tcp, b"ipv6-tcp").await;
        finish(&mut tcp).await;

        let mut bytes = header(0x11, 3, &[], &[]);
        bytes.extend(xframe(
            65535,
            1,
            Some(target(addr)),
            false,
            Some(b"ipv6-xudp"),
        ));
        let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
        response(&mut peer).await;
        let mapping = recv_udp(&destination, b"ipv6-xudp").await;
        destination.send_to(b"ipv6-reply", mapping).await.unwrap();
        xexpect(&mut peer, 65535, addr, b"ipv6-reply").await;
        finish(&mut peer).await;
        stop(server, 17, 18).await;
    }
}

#[tokio::test]
async fn bad_uuid_flow_commands_and_disabled_xudp_gate_udp_sessions() {
    let cert = Certificate::new();
    let (tcp, udp) = target_pair().await;
    let addr = tcp.local_addr().unwrap();
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        let server = Running::start(config(cert, Some(true))).await;
        let mut invalid = Vec::new();
        for command in [1, 2, 3] {
            let address = if command == 3 {
                Vec::new()
            } else {
                target(addr)
            };
            let mut wrong_uuid = header(0x44, command, &address, &[]);
            let mut flow = header(0x11, command, &address, VISION_ADDONS);
            if command == 3 {
                let first = xframe(7, 1, Some(target(addr)), true, Some(b"must-not-forward"));
                wrong_uuid.extend(&first);
                flow.extend(first);
            } else {
                wrong_uuid.extend(datagram(b"must-not-forward"));
                flow.extend(datagram(b"must-not-forward"));
            }
            invalid.extend([wrong_uuid, flow]);
        }
        let mut bad_version = request(1, addr);
        bad_version[0] = 1;
        // 命令 4 现为合法 REVERSE 注册，不再作为非法命令样例。
        invalid.extend([
            bad_version,
            request(0, addr),
            header(0x11, 1, &target(addr), b"\x0a\x00"),
        ]);
        for bytes in invalid {
            let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
            ws::closed(&mut peer).await;
        }
        no_target(&tcp, &udp).await;
        stop(server, 0, 0).await;

        // 显式 false 时命令 3 仍进入 Mux，仅 UDP 会话被门控；默认 true 由配置单测覆盖。
        for xudp in [Some(false)] {
            let server = Running::start(config(cert, xudp)).await;
            let mut bytes = header(0x11, 3, &[], &[]);
            bytes.extend(xframe(7, 1, Some(target(addr)), true, Some(b"disabled")));
            let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
            response(&mut peer).await;
            xerror(&mut peer, 7).await;
            no_target(&tcp, &udp).await;
            finish(&mut peer).await;
            stop(server, 0, 0).await;
        }
    }
}

#[tokio::test]
async fn reject_ws_and_wss_deny_session_targets_after_mux_auth() {
    let cert = Certificate::new();
    let (tcp, udp) = target_pair().await;
    let addr = tcp.local_addr().unwrap();
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        let mut value = config(cert, Some(true));
        value["route"]["default"] = json!("reject");
        let server = Running::start(value).await;
        for address in [target(addr), localhost(addr.port())] {
            for command in [1, 2] {
                let mut bytes = header(0x11, command, &address, &[]);
                bytes.extend(datagram(b"rejected"));
                let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
                ws::closed(&mut peer).await;
            }
            let mut bytes = header(0x11, 3, &[], &[]);
            bytes.extend(xframe(7, 1, Some(address), true, Some(b"rejected-xudp")));
            let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
            // VLESS 认证成功即应答；Reject 只结束该 Mux UDP 会话。
            response(&mut peer).await;
            xerror(&mut peer, 7).await;
            finish(&mut peer).await;
        }
        // 本文件观察 TCP/UDP 目标与业务计量；DNS 调用由专门资源测试观测。
        no_target(&tcp, &udp).await;
        stop(server, 0, 0).await;
    }
}

#[tokio::test]
async fn xudp_ws_and_wss_per_session_errors_and_tcp_mux_keep_carry_usable() {
    let cert = Certificate::new();
    let (tcp, udp) = target_pair().await;
    let addr = tcp.local_addr().unwrap();
    let echo = Echo::tcp("127.0.0.1", false).await;
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        let mut value = config(cert, Some(true));
        value["limits"]["max_udp_payload"] = json!(16);
        let server = Running::start(value).await;
        let too_large = xframe(7, 1, Some(target(addr)), false, Some(&[0x6b; 17]));

        // 超限 UDP 载荷只结束该会话。
        let mut bytes = header(0x11, 3, &[], &[]);
        bytes.extend(too_large);
        let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
        response(&mut peer).await;
        xerror(&mut peer, 7).await;
        finish(&mut peer).await;
        associations(&server, 0).await;

        // 未知会话回无 Error 的 End，连接继续。
        let mut bytes = header(0x11, 3, &[], &[]);
        bytes.extend(xframe(7, 2, None, false, Some(b"unknown-session")));
        let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
        response(&mut peer).await;
        xend(&mut peer, 7).await;
        finish(&mut peer).await;

        // 同一命令 3 承载上，TCP New 是合法会话。
        let mut tcp_new = xframe(5, 1, Some(target(echo.address)), false, Some(b"tcp"));
        tcp_new[6] = 1;
        let mut bytes = header(0x11, 3, &[], &[]);
        bytes.extend(tcp_new);
        let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
        response(&mut peer).await;
        assert_eq!(xrecv(&mut peer).await, (vec![0, 5, 2, 1], b"tcp".to_vec()));
        send(&mut peer, &xframe(5, 2, None, false, Some(b"more"))).await;
        assert_eq!(xrecv(&mut peer).await, (vec![0, 5, 2, 1], b"more".to_vec()));
        finish(&mut peer).await;

        // 缺目标 New 与超长 metaLen 仍是整条承载的致命错误。
        for invalid in [
            xframe(7, 1, None, false, None),
            513u16.to_be_bytes().to_vec(),
        ] {
            let mut bytes = header(0x11, 3, &[], &[]);
            bytes.extend(invalid);
            let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
            // 命令 3 认证成功后必须先回 VLESS 响应，随后 Mux 解析错误才关闭承载。
            response(&mut peer).await;
            ws::closed(&mut peer).await;
            associations(&server, 0).await;
        }
        no_target(&tcp, &udp).await;
        stop(server, 7, 7).await;
    }
}

#[tokio::test]
async fn xudp_ws_and_wss_later_reject_and_tcp_mux_target_tracking() {
    let cert = Certificate::new();
    let (rejected_tcp, rejected_udp) = target_pair().await;
    let rejected_addr = rejected_tcp.local_addr().unwrap();
    let allowed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let allowed_addr = allowed.local_addr().unwrap();
    assert_ne!(allowed_addr.port(), rejected_addr.port());
    for tls in [false, true] {
        let cert = tls.then_some(&cert);
        let mut value = config(cert, Some(true));
        value["route"]["rules"] = json!([{
            "ports":[{"start":rejected_addr.port(),"end":rejected_addr.port()}],
            "outbound":"reject"
        }]);
        let server = Running::start(value).await;
        let mut bytes = header(0x11, 3, &[], &[]);
        bytes.extend(xframe_gid(
            7,
            1,
            Some(target(allowed_addr)),
            [0x33; 8],
            Some(b"ok"),
        ));
        let mut peer = connect(cert, &server, &ws::masked(true, 2, &bytes)).await;
        response(&mut peer).await;
        let mapping = recv_udp(&allowed, b"ok").await;
        allowed.send_to(b"ok", mapping).await.unwrap();
        xexpect(&mut peer, 7, allowed_addr, b"ok").await;

        send(
            &mut peer,
            &xframe(
                7,
                2,
                Some(target(rejected_addr)),
                false,
                Some(b"reject-keep"),
            ),
        )
        .await;
        xerror(&mut peer, 7).await;
        associations(&server, 0).await;
        send(
            &mut peer,
            &xframe(
                9,
                1,
                Some(target(rejected_addr)),
                false,
                Some(b"reject-new"),
            ),
        )
        .await;
        xerror(&mut peer, 9).await;
        send(
            &mut peer,
            &xframe_gid(7, 1, Some(target(allowed_addr)), [0x33; 8], Some(b"again")),
        )
        .await;
        let mapping = recv_udp(&allowed, b"again").await;
        allowed.send_to(b"again", mapping).await.unwrap();
        // 新 session 也不允许重复承载级 VLESS 响应。
        xexpect(&mut peer, 7, allowed_addr, b"again").await;
        // TCP New 是合法 Mux 会话，但 Reject 路由只结束该会话。
        let mut tcp_frame = xframe(10, 1, Some(target(rejected_addr)), false, Some(b"tcp"));
        tcp_frame[6] = 1;
        send(&mut peer, &tcp_frame).await;
        xerror(&mut peer, 10).await;
        send(&mut peer, &xframe(7, 2, None, false, Some(b"again"))).await;
        let mapping = recv_udp(&allowed, b"again").await;
        allowed.send_to(b"again", mapping).await.unwrap();
        xexpect(&mut peer, 7, allowed_addr, b"again").await;
        finish(&mut peer).await;
        associations(&server, 0).await;
        no_target(&rejected_tcp, &rejected_udp).await;
        no_udp(&allowed).await;
        // 只统计成功送达目标的载荷：2+5+5。
        stop(server, 12, 12).await;
    }
}
