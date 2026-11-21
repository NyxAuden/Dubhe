mod common;
#[path = "common/reality.rs"]
mod peer;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Running, socks_config};
use peer::{Outer, PreparedClient, TargetPeer};
use serde_json::{Value, json};
use std::{collections::VecDeque, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

const WAIT: Duration = Duration::from_secs(4);
const GLOBAL_ID: [u8; 8] = [0x77; 8];

fn config(target: SocketAddr, vision: bool) -> Value {
    let mut value = socks_config();
    value["limits"]["handshake_timeout_ms"] = json!(3000);
    value["limits"]["udp_idle_timeout_ms"] = json!(5000);
    value["inbounds"] = json!([{"type":"vless-reality","tag":"reality","listen":"127.0.0.1:0",
        "xudp":true,"users":[{"name":"alice","uuid":peer::UUID,
            "flow":if vision {"xtls-rprx-vision"} else {""}}],
        "reality":{"target":{"host":target.ip().to_string(),"port":target.port()},
            "private_key":URL_SAFE_NO_PAD.encode(peer::SERVER_PRIVATE_KEY),
            "server_names":["localhost"],"short_ids":["8172635445362718"]}}]);
    value
}

async fn until(mut predicate: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("UDP 状态未在期限内收敛");
}

async fn associations(server: &Running, count: usize) {
    until(|| server.stats.snapshot().udp_associations == count).await;
}

async fn idle(server: &Running) {
    until(|| server.stats.snapshot().connections == 0).await;
    associations(server, 0).await;
}

async fn socket(ip: &str) -> UdpSocket {
    let ip: std::net::IpAddr = ip.parse().unwrap();
    UdpSocket::bind(SocketAddr::new(ip, 0)).await.unwrap()
}

async fn receive(socket: &UdpSocket, expected: &[u8]) -> SocketAddr {
    let mut bytes = [0; 2048];
    let (length, source) = timeout(WAIT, socket.recv_from(&mut bytes))
        .await
        .expect("目标未收到 UDP")
        .unwrap();
    assert_eq!(&bytes[..length], expected);
    source
}

async fn no_datagram(socket: &UdpSocket) {
    let mut bytes = [0; 2048];
    assert!(
        timeout(Duration::from_millis(40), socket.recv_from(&mut bytes))
            .await
            .is_err(),
        "拒绝或空包不应到达 UDP 目标"
    );
}

fn address(target: SocketAddr) -> Vec<u8> {
    let mut bytes = target.port().to_be_bytes().to_vec();
    match target.ip() {
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

// 独立测试端帧编码，不调用生产 XUDP parser/encoder。
fn frame(
    id: u16,
    status: u8,
    target: Option<Vec<u8>>,
    global: bool,
    data: Option<&[u8]>,
) -> Vec<u8> {
    frame_global(id, status, target, global.then_some(GLOBAL_ID), data)
}
// GlobalID 只在同一服务实例内复用；不同测试各自启动独立实例，互不接管。
fn frame_gid(
    id: u16,
    status: u8,
    target: Option<Vec<u8>>,
    global: [u8; 8],
    data: Option<&[u8]>,
) -> Vec<u8> {
    frame_global(id, status, target, Some(global), data)
}
fn frame_global(
    id: u16,
    status: u8,
    target: Option<Vec<u8>>,
    global: Option<[u8; 8]>,
    data: Option<&[u8]>,
) -> Vec<u8> {
    let mut metadata = id.to_be_bytes().to_vec();
    metadata.extend([status, u8::from(data.is_some())]);
    if let Some(target) = target {
        metadata.push(2);
        metadata.extend(target);
    }
    if let Some(global) = global {
        metadata.extend(global);
    }
    let mut bytes = (metadata.len() as u16).to_be_bytes().to_vec();
    bytes.extend(metadata);
    if let Some(data) = data {
        bytes.extend((data.len() as u16).to_be_bytes());
        bytes.extend(data);
    }
    bytes
}

struct Xudp {
    outer: Outer,
    vision: bool,
    sent_first: bool,
    read_first: bool,
    buffered: VecDeque<u8>,
}
impl Xudp {
    async fn connect(server: &Running, vision: bool) -> Self {
        let mut outer = PreparedClient::new(Default::default())
            .unwrap()
            .connect(server.address)
            .await
            .unwrap();
        outer
            .send(&peer::vless_request(
                3,
                vision.then_some("xtls-rprx-vision"),
                peer::ID,
                "127.0.0.1:1".parse().unwrap(), // cmd3 不编码此占位目标。
            ))
            .await
            .unwrap();
        assert_eq!(outer.plain(2).await.unwrap(), [0, 0]);
        Self {
            outer,
            vision,
            sent_first: false,
            read_first: false,
            buffered: VecDeque::new(),
        }
    }
    async fn send(&mut self, bytes: &[u8]) {
        // 首个 End 的正文/padding 完成后，所有后续帧直接作为外层 TLS 明文。
        let wire = if self.vision && !self.sent_first {
            peer::vision_block(true, 1, bytes, 13)
        } else {
            bytes.to_vec()
        };
        self.sent_first = true;
        self.outer.send(&wire).await.unwrap();
    }
    async fn read(&mut self, length: usize) -> Vec<u8> {
        if self.vision && !self.read_first {
            assert_eq!(self.outer.plain(16).await.unwrap(), peer::ID);
            let header = self.outer.plain(5).await.unwrap();
            assert_eq!(header[0], 1, "XUDP 回程首块应以 End 退出 padding");
            let content = usize::from(u16::from_be_bytes([header[1], header[2]]));
            let padding = usize::from(u16::from_be_bytes([header[3], header[4]]));
            self.buffered
                .extend(self.outer.plain(content).await.unwrap());
            self.outer.plain(padding).await.unwrap();
            self.read_first = true;
        }
        let buffered = self.buffered.len().min(length);
        let mut bytes: Vec<_> = self.buffered.drain(..buffered).collect();
        if bytes.len() < length {
            bytes.extend(self.outer.plain(length - bytes.len()).await.unwrap());
        }
        bytes
    }
    async fn recv(&mut self) -> (Vec<u8>, Vec<u8>) {
        let length = self.read(2).await;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        assert!((4..=512).contains(&length));
        let metadata = self.read(length).await;
        let payload = if metadata[3] & 1 != 0 {
            let length = self.read(2).await;
            self.read(usize::from(u16::from_be_bytes([length[0], length[1]])))
                .await
        } else {
            Vec::new()
        };
        (metadata, payload)
    }
    async fn expect(&mut self, id: u16, source: SocketAddr, body: &[u8]) {
        let (metadata, payload) = self.recv().await;
        let mut expected = id.to_be_bytes().to_vec();
        expected.extend([2, 1, 2]);
        expected.extend(address(source));
        assert_eq!(
            metadata, expected,
            "回程必须编码实际 IP 来源，不是默认/声明目标"
        );
        assert_eq!(payload, body);
    }
    async fn end(&mut self, id: u16, error: bool) {
        let (metadata, payload) = self.recv().await;
        let [hi, lo] = id.to_be_bytes();
        assert_eq!(metadata, [hi, lo, 3, if error { 2 } else { 0 }]);
        assert!(payload.is_empty());
    }
    async fn closed(&mut self) {
        assert!(
            timeout(Duration::from_millis(700), self.outer.plain(1))
                .await
                .expect("应立即拒绝而不是等待 UDP idle/声明载荷")
                .is_err()
        );
    }
}

async fn native_recv(client: &mut Outer, expected: &[u8]) {
    assert_eq!(
        client.plain(2).await.unwrap(),
        (expected.len() as u16).to_be_bytes()
    );
    assert_eq!(client.plain(expected.len()).await.unwrap(), expected);
}

#[tokio::test]
async fn native_udp_filters_forged_sources_and_rejects_oversized_declaration_without_body() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let mut value = config(target.address, false);
    value["limits"]["max_udp_payload"] = json!(8);
    let server = Running::start(value).await;
    for ip in ["127.0.0.1", "::1"] {
        let destination = socket(ip).await;
        let attacker = socket(ip).await;
        let mut client = PreparedClient::new(Default::default())
            .unwrap()
            .connect(server.address)
            .await
            .unwrap();
        let mut request = peer::vless_request(2, None, peer::ID, destination.local_addr().unwrap());
        request.extend([0, 0, 0, 5]); // 空包被丢弃，后续 start 保持流对齐。
        request.extend(b"start");
        client.send(&request).await.unwrap();
        assert_eq!(client.plain(2).await.unwrap(), [0, 0]);
        let mapping = receive(&destination, b"start").await;
        attacker.send_to(b"spoof", mapping).await.unwrap();
        destination.send_to(b"oversized", mapping).await.unwrap();
        destination.send_to(b"", mapping).await.unwrap();
        destination.send_to(b"valid", mapping).await.unwrap();
        native_recv(&mut client, b"valid").await;
        // 只给出大于上限的声明，不给正文；必须当场拒绝并释放映射。
        client.send(&[0, 9]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(700), client.plain(1))
                .await
                .expect("超限声明不应等待正文或 idle")
                .is_err()
        );
        associations(&server, 0).await;
        no_datagram(&destination).await;
        drop(common::rebind_udp(mapping).await);
        drop(client);
    }
    idle(&server).await;
    let stats = server.stats.snapshot();
    assert_eq!((stats.uplink, stats.downlink), (10, 10));
    assert!(stats.dropped >= 6); // 两方向空包、超限回包；伪造来源由内核过滤。
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn xudp_same_session_switches_ipv4_ipv6_then_uses_initial_target_and_preserves_empty() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    for vision in [false, true] {
        let server = Running::start(config(target.address, vision)).await;
        let a = socket("127.0.0.1").await;
        let b = socket("::1").await;
        let attacker = socket("127.0.0.1").await;
        let mut client = Xudp::connect(&server, vision).await;
        client
            .send(&frame_gid(
                7,
                1,
                Some(address(a.local_addr().unwrap())),
                [0x11; 8],
                Some(b"first"),
            ))
            .await;
        let mapping_a = receive(&a, b"first").await;
        attacker.send_to(b"spoof", mapping_a).await.unwrap();
        a.send_to(b"one", mapping_a).await.unwrap();
        client.expect(7, a.local_addr().unwrap(), b"one").await;
        client
            .send(&frame(
                7,
                2,
                Some(address(b.local_addr().unwrap())),
                false,
                Some(b"switch"),
            ))
            .await;
        let mapping_b = receive(&b, b"switch").await;
        b.send_to(b"two", mapping_b).await.unwrap();
        client.expect(7, b.local_addr().unwrap(), b"two").await;
        // Keep 未携带目标恢复 New 的初始目标，不沿用上一次显式目标。
        client
            .send(&frame(7, 2, None, false, Some(b"default")))
            .await;
        assert_eq!(receive(&a, b"default").await, mapping_a);
        a.send_to(b"three", mapping_a).await.unwrap();
        client.expect(7, a.local_addr().unwrap(), b"three").await;
        let mut merged = frame(7, 2, None, false, Some(b""));
        merged.extend(frame(7, 2, None, false, Some(b"last")));
        client.send(&merged).await;
        // 空载荷保留边界并发送到目标，随后才是非空包。
        assert_eq!(receive(&a, b"").await, mapping_a);
        assert_eq!(receive(&a, b"last").await, mapping_a);
        a.send_to(b"four", mapping_a).await.unwrap();
        client.expect(7, a.local_addr().unwrap(), b"four").await;
        assert_eq!(server.stats.snapshot().uplink, 22);
        assert_eq!(server.stats.snapshot().downlink, 15);
        // 伪造来源由已连接 UDP 套接字在核内过滤，不进入应用层丢弃计数；
        // 若未过滤，上面的 expect 会先收到 "spoof"。
        drop(client);
        idle(&server).await;
        // GlobalID 关联按 Xray 语义保留映射与源端口进入宽限期，
        // 供同一 GlobalID 的新会话续接（见 tests/xudp.rs）。
        let _ = (mapping_a, mapping_b);
        server.shutdown().await;
    }
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn global_id_takeover_migrates_sink_and_ends_old_reality_session() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    for vision in [false, true] {
        let server = Running::start(config(target.address, vision)).await;
        let destination = socket("127.0.0.1").await;
        let source = destination.local_addr().unwrap();
        let address = address(source);
        // 同一用户、SessionID、GlobalID 的两条 REALITY 承载复用实例内关联。
        let mut one = Xudp::connect(&server, vision).await;
        let mut two = Xudp::connect(&server, vision).await;
        one.send(&frame_gid(
            0,
            1,
            Some(address.clone()),
            [0x22; 8],
            Some(b"one"),
        ))
        .await;
        let old_mapping = receive(&destination, b"one").await;
        two.send(&frame_gid(
            0,
            1,
            Some(address.clone()),
            [0x22; 8],
            Some(b"two"),
        ))
        .await;
        let other_mapping = receive(&destination, b"two").await;
        assert_eq!(other_mapping, old_mapping);
        one.end(0, true).await;
        destination
            .send_to(b"reply-two", old_mapping)
            .await
            .unwrap();
        two.expect(0, source, b"reply-two").await;

        // 旧承载只失去被接管会话，仍可创建新会话。
        one.send(&frame(7, 1, Some(address.clone()), false, Some(b"other")))
            .await;
        let other = receive(&destination, b"other").await;
        assert_ne!(other, old_mapping);
        destination.send_to(b"reply-other", other).await.unwrap();
        one.expect(7, source, b"reply-other").await;

        two.send(&frame(0, 3, None, false, None)).await;
        associations(&server, 1).await;
        // 宽限期内映射与源端口仍由全局关联持有，不能被重新绑定。
        assert!(
            UdpSocket::bind(old_mapping).await.is_err(),
            "宽限期内不应释放源端口"
        );
        two.send(&frame_gid(0, 1, Some(address), [0x22; 8], Some(b"new")))
            .await;
        let fresh = receive(&destination, b"new").await;
        assert_eq!(fresh, old_mapping, "宽限期内必须复用同一 UDP 关联");
        destination.send_to(b"fresh", fresh).await.unwrap();
        two.expect(0, source, b"fresh").await;

        one.send(&frame(7, 3, None, false, None)).await;
        two.send(&frame(0, 3, None, false, None)).await;
        associations(&server, 0).await;
        drop((one, two));
        idle(&server).await;
        drop(common::rebind_udp(other).await);
        // 实例停机主动释放宽限期关联后，源端口才可用。
        server.shutdown().await;
        drop(common::rebind_udp(fresh).await);
    }
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn xudp_is_opt_in_for_udp_and_command_three_remains_mux() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    let destination = socket("127.0.0.1").await;
    // 命令 3 与 xudp 无关：普通与 Vision 都先得到 VLESS 成功响应，
    // 关闭 xudp 时仅 UDP New 收到 End+Error。
    for vision in [false, true] {
        let mut value = config(target.address, vision);
        value["inbounds"][0]["xudp"] = json!(false);
        let server = Running::start(value).await;
        let mut client = Xudp::connect(&server, vision).await;
        client
            .send(&frame(
                1,
                1,
                Some(address(destination.local_addr().unwrap())),
                false,
                Some(b"denied"),
            ))
            .await;
        client.end(1, true).await;
        drop(client);
        idle(&server).await;
        no_datagram(&destination).await;
        let stats = server.stats.snapshot();
        assert_eq!((stats.tcp_flows, stats.uplink, stats.downlink), (0, 0, 0));
        server.shutdown().await;
    }
    // Vision 与原生 UDP 命令 2 的既有组合仍拒绝。
    let server = Running::start(config(target.address, true)).await;
    let mut client = PreparedClient::new(Default::default())
        .unwrap()
        .connect(server.address)
        .await
        .unwrap();
    let mut request = peer::vless_request(
        2,
        Some("xtls-rprx-vision"),
        peer::ID,
        destination.local_addr().unwrap(),
    );
    request.extend(b"\0\x06denied");
    client.send(&request).await.unwrap();
    assert!(
        client.plain(2).await.is_err(),
        "非法承载不能输出 VLESS 成功响应"
    );
    drop(client);
    idle(&server).await;
    no_datagram(&destination).await;
    let stats = server.stats.snapshot();
    assert_eq!((stats.tcp_flows, stats.uplink, stats.downlink), (0, 0, 0));
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn mux_accepts_tcp_and_rechecks_udp_session_and_payload_limits() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    for vision in [false, true] {
        let mut value = config(target.address, vision);
        value["limits"]["max_udp_payload"] = json!(4);
        let server = Running::start(value).await;
        let destination = socket("127.0.0.1").await;
        let addr = destination.local_addr().unwrap();
        let tcp = common::Echo::tcp("127.0.0.1", false).await;
        let mut client = Xudp::connect(&server, vision).await;

        client
            .send(&frame(7, 1, Some(address(addr)), false, Some(b"ok")))
            .await;
        let mapping = receive(&destination, b"ok").await;
        destination.send_to(b"ok", mapping).await.unwrap();
        client.expect(7, addr, b"ok").await;
        associations(&server, 1).await;

        // TCP New/Keep 是合法 Mux 会话，不能按旧 XUDP 语义拒绝整条承载。
        let mut tcp_new = frame(9, 1, Some(address(tcp.address)), false, Some(b"no"));
        tcp_new[6] = 1;
        client.send(&tcp_new).await;
        assert_eq!(client.recv().await, (vec![0, 9, 2, 1], b"no".to_vec()));
        client.send(&frame(9, 2, None, false, Some(b"hi"))).await;
        assert_eq!(client.recv().await, (vec![0, 9, 2, 1], b"hi".to_vec()));
        client.send(&frame(9, 3, None, false, None)).await;

        // 未知会话回 End 且连接继续。
        client.send(&frame(99, 2, None, false, Some(b"x"))).await;
        client.end(99, false).await;

        // 重复 New 替换旧会话；旧映射释放，新映射独立。
        client
            .send(&frame(7, 1, Some(address(addr)), false, Some(b"dup")))
            .await;
        let replacement = receive(&destination, b"dup").await;
        assert_ne!(replacement, mapping);
        drop(common::rebind_udp(mapping).await);
        // 下行同样受 max_udp_payload=4 限制，故使用不超过上限的载荷。
        destination.send_to(b"rep", replacement).await.unwrap();
        client.expect(7, addr, b"rep").await;

        // 超限载荷只结束该 UDP 会话。
        client.send(&frame(7, 2, None, false, Some(b"12345"))).await;
        client.end(7, true).await;
        associations(&server, 0).await;
        no_datagram(&destination).await;

        // 畸形 metaLen 仍是整条承载的致命错误。
        client.send(&[2, 1]).await;
        client.closed().await;
        associations(&server, 0).await;
        drop(client);
        idle(&server).await;
        server.shutdown().await;
    }
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn xudp_route_switch_and_target_limit_end_sessions_and_return_association_slot() {
    let target = TargetPeer::start(Default::default()).await.unwrap();
    for vision in [false, true] {
        let a = socket("127.0.0.1").await;
        let b = socket("127.0.0.1").await;
        let denied = socket("127.0.0.1").await;
        let mut value = config(target.address, vision);
        value["limits"]["max_udp_associations"] = json!(1);
        value["limits"]["max_udp_targets"] = json!(1);
        let denied_port = denied.local_addr().unwrap().port();
        value["route"]["rules"] =
            json!([{"ports":[{"start":denied_port,"end":denied_port}],"outbound":"reject"}]);
        let server = Running::start(value).await;
        let mut client = Xudp::connect(&server, vision).await;
        client
            .send(&frame(
                1,
                1,
                Some(address(a.local_addr().unwrap())),
                false,
                Some(b"one"),
            ))
            .await;
        let first_mapping = receive(&a, b"one").await;
        a.send_to(b"one", first_mapping).await.unwrap();
        client.expect(1, a.local_addr().unwrap(), b"one").await;
        client
            .send(&frame(
                2,
                1,
                Some(address(a.local_addr().unwrap())),
                false,
                Some(b"limit"),
            ))
            .await;
        client.end(2, true).await;
        associations(&server, 1).await;
        client
            .send(&frame(
                1,
                2,
                Some(address(denied.local_addr().unwrap())),
                false,
                Some(b"reject"),
            ))
            .await;
        client.end(1, true).await;
        associations(&server, 0).await;
        let _first_port = common::rebind_udp(first_mapping).await;
        no_datagram(&denied).await;
        no_datagram(&a).await;
        client
            .send(&frame(
                3,
                1,
                Some(address(a.local_addr().unwrap())),
                false,
                Some(b"new"),
            ))
            .await;
        let second_mapping = receive(&a, b"new").await;
        a.send_to(b"new", second_mapping).await.unwrap();
        client.expect(3, a.local_addr().unwrap(), b"new").await;
        client
            .send(&frame(
                3,
                2,
                Some(address(b.local_addr().unwrap())),
                false,
                Some(b"target-limit"),
            ))
            .await;
        client.end(3, true).await;
        associations(&server, 0).await;
        let _second_port = common::rebind_udp(second_mapping).await;
        no_datagram(&b).await;
        client
            .send(&frame(
                4,
                1,
                Some(address(b.local_addr().unwrap())),
                false,
                Some(b"released"),
            ))
            .await;
        let last_mapping = receive(&b, b"released").await;
        b.send_to(b"released", last_mapping).await.unwrap();
        client.expect(4, b.local_addr().unwrap(), b"released").await;
        client.send(&frame(4, 3, None, false, None)).await;
        associations(&server, 0).await;
        drop(common::rebind_udp(last_mapping).await);
        drop(client);
        idle(&server).await;
        assert_eq!(
            (
                server.stats.snapshot().uplink,
                server.stats.snapshot().downlink
            ),
            (14, 14)
        );
        server.shutdown().await;
    }
    target.shutdown().await.unwrap();
}
