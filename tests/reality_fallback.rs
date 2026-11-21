mod common;
#[path = "common/reality.rs"]
mod peer;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Running, socks_config};
use peer::{PreparedClient, TargetBehavior, TargetOptions, TargetPeer};
use serde_json::{Value, json};
use std::{io, net::SocketAddr, sync::atomic::Ordering, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(4);
const TAIL: &[u8] = b"same-target-after-template\0\xff";

fn config(target: SocketAddr, mldsa: bool) -> Value {
    let mut value = socks_config();
    value["limits"]["handshake_timeout_ms"] = json!(1000);
    value["inbounds"] = json!([{"type":"vless-reality","tag":"reality","listen":"127.0.0.1:0",
        "users":[{"name":"alice","uuid":peer::UUID}],
        "reality":{"target":{"host":target.ip().to_string(),"port":target.port()},
            "private_key":URL_SAFE_NO_PAD.encode(peer::SERVER_PRIVATE_KEY),
            "server_names":["localhost"],"short_ids":["8172635445362718"],
            "fallback_idle_timeout_ms":1000,"fallback_max_duration_ms":3000}}]);
    if mldsa {
        value["inbounds"][0]["reality"]["mldsa65_seed"] = json!(URL_SAFE_NO_PAD.encode([0x42; 32]));
    }
    value
}

async fn until(mut predicate: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("测试状态未在期限内收敛");
}

async fn idle(server: &Running) {
    until(|| server.stats.snapshot().connections == 0).await;
}

fn zero_business(server: &Running) {
    let stats = server.stats.snapshot();
    assert_eq!(
        (
            stats.tcp_flows,
            stats.udp_associations,
            stats.uplink,
            stats.downlink,
        ),
        (0, 0, 0, 0),
        "辅助目标、回落和拒绝请求不能计入业务流量"
    );
}

async fn read_exact(stream: &mut TcpStream, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    timeout(WAIT, stream.read_exact(&mut bytes))
        .await
        .expect("读取原文超时")
        .unwrap();
    bytes
}

async fn read_to_eof(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut bytes))
        .await
        .expect("等待原目标半关闭超时")
        .unwrap();
    assert!(bytes.len() <= 131072);
    bytes
}

// 本地握手出错可以输出加密 alert；这里只要求有限数据后真正关闭。
async fn drain_closed(stream: &mut TcpStream) {
    timeout(WAIT, async {
        let mut total = 0;
        let mut bytes = [0; 4096];
        loop {
            match stream.read(&mut bytes).await {
                Ok(0) => return,
                Ok(n) => {
                    total += n;
                    assert!(total <= 131072, "关闭前输出无界数据");
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    return;
                }
                Err(error) => panic!("非预期关闭错误: {error}"),
            }
        }
    })
    .await
    .expect("提交后连接未关闭");
}

async fn only_original_target(target: &TargetPeer, original: &[u8], raw_ch: &[u8]) {
    until(|| target.observation.active.load(Ordering::SeqCst) == 0).await;
    assert_eq!(target.observation.accepted.load(Ordering::SeqCst), 1);
    let connections = target.observation.connections.lock().unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].received_wire, original);
    assert_eq!(connections[0].raw_ch, raw_ch);
    assert!(!connections[0].handshake_complete);
    assert!(connections[0].plaintext.is_empty());
}

fn record(typ: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() <= 18432);
    [
        vec![typ, 3, 3],
        (body.len() as u16).to_be_bytes().to_vec(),
        body.to_vec(),
    ]
    .concat()
}

fn extension(typ: u16, body: &[u8]) -> Vec<u8> {
    [
        typ.to_be_bytes().to_vec(),
        (body.len() as u16).to_be_bytes().to_vec(),
        body.to_vec(),
    ]
    .concat()
}

#[derive(Clone, Copy, Debug)]
enum TemplateCase {
    InsufficientAggregate,
    WrongHandshakeType,
    HelloRetryRequest,
    WrongSessionId,
    UnknownExtension,
    UnsupportedSuite,
    UnofferedSuite,
    UnsupportedGroup,
}

// 独立 wire 构造：加密槽是 opaque 字节，只供布局观察，不伪称普通 TLS 有效密文。
fn target_flight(raw_ch: &[u8], case: TemplateCase) -> Vec<u8> {
    let sid = peer::session_id_range(raw_ch).unwrap();
    let mut session_id = raw_ch[sid].to_vec();
    if matches!(case, TemplateCase::WrongSessionId) {
        session_id[0] ^= 1;
    }
    let random = if matches!(case, TemplateCase::HelloRetryRequest) {
        [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ]
    } else {
        [0x73; 32]
    };
    let suite: u16 = match case {
        TemplateCase::UnsupportedSuite => 0xc02f,
        TemplateCase::UnofferedSuite => 0x1302,
        _ => 0x1301,
    };
    let (group, share): (u16, Vec<u8>) = if matches!(case, TemplateCase::UnsupportedGroup) {
        (0x0017, vec![4; 65])
    } else {
        (0x001d, peer::public_key(&[0x61; 32]).to_vec())
    };
    let key_share = [
        group.to_be_bytes().to_vec(),
        (share.len() as u16).to_be_bytes().to_vec(),
        share,
    ]
    .concat();
    let mut extensions = extension(43, &[3, 4]);
    extensions.extend(extension(51, &key_share));
    if matches!(case, TemplateCase::UnknownExtension) {
        extensions.extend(extension(0xaaaa, &[0x55]));
    }
    let body = [
        vec![3, 3],
        random.to_vec(),
        vec![32],
        session_id,
        suite.to_be_bytes().to_vec(),
        vec![0],
        (extensions.len() as u16).to_be_bytes().to_vec(),
        extensions,
    ]
    .concat();
    assert!(body.len() < 65536);
    let mut sh = vec![
        if matches!(case, TemplateCase::WrongHandshakeType) {
            3
        } else {
            2
        },
        0,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ];
    sh.extend(body);
    [
        record(22, &sh),
        record(20, &[1]),
        record(23, &vec![0x65; 1024]),
    ]
    .concat()
}

#[tokio::test]
async fn small_ordinary_certificate_replays_exact_target_flight_on_original_connection() {
    let target = TargetPeer::start(TargetOptions {
        certificate_padding: 0,
        ..Default::default()
    })
    .await
    .unwrap();
    // ML-DSA 证书至少有 3309 字节签名，普通小证书目标无法提供足够的初始布局。
    let mut value = config(target.address, true);
    value["limits"]["handshake_timeout_ms"] = json!(250);
    let server = Running::start(value).await;
    let prepared = PreparedClient::new(Default::default()).unwrap();
    let original = prepared.initial_wire.clone();
    let raw_ch = prepared.raw_ch.clone();
    let mut client = prepared.begin(server.address).await.unwrap();
    // 回落是原目标普通 TLS；不将它交给 REALITY certificate verifier。
    let first = peer::raw_record(&mut client.io).await.unwrap();
    assert_eq!(first[0], 22);
    client.io.shutdown().await.unwrap();
    let mut received = first.clone();
    received.extend(read_to_eof(&mut client.io).await);
    idle(&server).await;
    only_original_target(&target, &original, &raw_ch).await;
    {
        let connections = target.observation.connections.lock().unwrap();
        let connection = &connections[0];
        assert_eq!(&first[5..], connection.raw_sh);
        assert_eq!(received, connection.sent_wire, "目标下行必须恰一次原样回放");
        let lengths = peer::record_lengths(&connection.sent_wire).unwrap();
        assert!(lengths.iter().skip(1).all(|length| *length < 3309));
    }
    zero_business(&server);
    drop(client);
    server.shutdown().await;
    target.shutdown().await.unwrap();
}

#[tokio::test]
async fn incompatible_server_hellos_use_same_raw_target() {
    // InsufficientAggregate 现在改走本地自然长度 flight，由 lib 测试单独覆盖；
    // 本测试只保留必须回落的模板不兼容形态。
    for case in [
        TemplateCase::WrongHandshakeType,
        TemplateCase::HelloRetryRequest,
        TemplateCase::WrongSessionId,
        TemplateCase::UnknownExtension,
        TemplateCase::UnsupportedSuite,
        TemplateCase::UnofferedSuite,
        TemplateCase::UnsupportedGroup,
    ] {
        let prepared = PreparedClient::new(Default::default()).unwrap();
        let original = prepared.initial_wire.clone();
        let raw_ch = prepared.raw_ch.clone();
        let flight = target_flight(&raw_ch, case);
        let target = TargetPeer::start(TargetOptions {
            behavior: TargetBehavior::Raw(flight.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        let server = Running::start(config(target.address, false)).await;
        let mut client = prepared.begin(server.address).await.unwrap();
        let first = peer::raw_record(&mut client.io).await.unwrap();
        assert_eq!(first, flight[..first.len()], "{case:?}");
        let mut received = first;
        received.extend(read_exact(&mut client.io, flight.len() - received.len()).await);
        assert_eq!(received, flight, "{case:?}: 本地 SH 不得提前泄漏");
        client.io.write_all(TAIL).await.unwrap();
        client.io.shutdown().await.unwrap();
        let echo = read_to_eof(&mut client.io).await;
        assert_eq!(echo, TAIL, "{case:?}: 已读下行或后续原文重复");
        received.extend(echo);
        idle(&server).await;
        let mut expected_up = original;
        expected_up.extend(TAIL);
        only_original_target(&target, &expected_up, &raw_ch).await;
        assert_eq!(
            received,
            target.observation.connections.lock().unwrap()[0].sent_wire,
            "{case:?}"
        );
        zero_business(&server);
        drop(client);
        server.shutdown().await;
        target.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn template_timeout_preserves_partial_record_header_and_body_before_live_relay() {
    for partial_header in [true, false] {
        let prepared = PreparedClient::new(Default::default()).unwrap();
        let original = prepared.initial_wire.clone();
        let flight = target_flight(&prepared.raw_ch, TemplateCase::InsufficientAggregate);
        let sh_length = 5 + usize::from(u16::from_be_bytes([flight[3], flight[4]]));
        let cut = if partial_header {
            2
        } else {
            sh_length + 6 + 5 + 37
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = listener.local_addr().unwrap();
        let (sent_tx, sent_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (observed_tx, observed_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let target_wire = flight.clone();
        let expected_prefix = original.clone();
        let worker = tokio::spawn(async move {
            let (mut stream, address) = listener.accept().await.unwrap();
            assert!(address.ip().is_loopback());
            let exchange = async {
                let prefix = read_exact(&mut stream, expected_prefix.len()).await;
                assert_eq!(prefix, expected_prefix, "CH 必须只转交一次");
                stream.write_all(&target_wire[..cut]).await.unwrap();
                sent_tx.send(()).unwrap();
                // 直到客户端实际收到回放前缀才补齐 record，排除目标先完成或 EOF。
                release_rx.await.unwrap();
                stream.write_all(&target_wire[cut..]).await.unwrap();
                let rest = read_to_eof(&mut stream).await;
                stream.write_all(&rest).await.unwrap();
                stream.shutdown().await.unwrap();
                observed_tx.send([prefix, rest].concat()).unwrap();
                // Server 的连接清零前始终监视 listener，不能隐藏第二次拨号。
                stop_rx.await.unwrap();
            };
            tokio::select! {
                _ = exchange => {},
                second = listener.accept() => panic!("回落重新拨了目标: {second:?}"),
            }
        });
        let mut value = config(target_address, false);
        value["limits"]["handshake_timeout_ms"] = json!(250);
        let server = Running::start(value).await;
        let mut client = prepared.begin(server.address).await.unwrap();
        timeout(WAIT, sent_rx).await.unwrap().unwrap();
        let mut received = read_exact(&mut client.io, cut).await;
        assert_eq!(received, flight[..cut], "取消不能丢掉已读半 record");
        release_tx.send(()).unwrap();
        received.extend(read_exact(&mut client.io, flight.len() - cut).await);
        assert_eq!(
            received, flight,
            "回放前缀和原 socket 余下数据必须连续且恰一次"
        );
        client.io.write_all(TAIL).await.unwrap();
        client.io.shutdown().await.unwrap();
        assert_eq!(read_to_eof(&mut client.io).await, TAIL);
        let observed = timeout(WAIT, observed_rx).await.unwrap().unwrap();
        assert_eq!(observed, [original, TAIL.to_vec()].concat());
        idle(&server).await;
        zero_business(&server);
        stop_tx.send(()).unwrap();
        timeout(WAIT, worker).await.unwrap().unwrap();
        drop(client);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn damaged_client_finished_or_eof_after_local_flight_never_falls_back() {
    for damage_finished in [true, false] {
        let target = TargetPeer::start(Default::default()).await.unwrap();
        let server = Running::start(config(target.address, false)).await;
        let prepared = PreparedClient::new(Default::default()).unwrap();
        let original = prepared.initial_wire.clone();
        let raw_ch = prepared.raw_ch.clone();
        let mut client = prepared.begin(server.address).await.unwrap();
        // 验证本地服务端整个 flight，但刻意不 flush 客户端 Finished。
        timeout(WAIT, async {
            while client.tls.is_handshaking() {
                client.record().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(client.tls.wants_write());
        until(|| target.observation.active.load(Ordering::SeqCst) == 0).await;
        assert_ne!(
            client.log.lock().unwrap().raw_sh,
            target.observation.connections.lock().unwrap()[0].raw_sh,
            "已输出的应为替换了临时 key_share 的本地 SH"
        );
        if damage_finished {
            let mut finished = Vec::new();
            while client.tls.wants_write() {
                client.tls.write_tls(&mut finished).unwrap();
            }
            let lengths = peer::record_lengths(&finished).unwrap();
            let mut offset = 0;
            let mut damaged = false;
            for length in lengths {
                if finished[offset] == 23 {
                    finished[offset + length - 1] ^= 1;
                    damaged = true;
                    break;
                }
                offset += length;
            }
            assert!(damaged, "必须实际损坏 ClientFinished 所在的加密 record");
            client.io.write_all(&finished).await.unwrap();
        }
        client.io.shutdown().await.unwrap();
        drain_closed(&mut client.io).await;
        idle(&server).await;
        only_original_target(&target, &original, &raw_ch).await;
        zero_business(&server);
        drop(client);
        server.shutdown().await;
        target.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn wrong_uuid_or_flow_after_local_server_hello_cannot_dial_business_or_fall_back() {
    for wrong_uuid in [true, false] {
        let target = TargetPeer::start(Default::default()).await.unwrap();
        let server = Running::start(config(target.address, false)).await;
        let business = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let prepared = PreparedClient::new(Default::default()).unwrap();
        let original = prepared.initial_wire.clone();
        let raw_ch = prepared.raw_ch.clone();
        let mut client = prepared.connect(server.address).await.unwrap();
        until(|| target.observation.active.load(Ordering::SeqCst) == 0).await;
        assert_ne!(
            client.log.lock().unwrap().raw_sh,
            target.observation.connections.lock().unwrap()[0].raw_sh
        );
        let mut request = peer::vless_request(
            1,
            (!wrong_uuid).then_some("xtls-rprx-vision"),
            if wrong_uuid { [0x22; 16] } else { peer::ID },
            business.local_addr().unwrap(),
        );
        request.extend(b"must-not-be-business");
        client.send(&request).await.unwrap();
        assert!(
            client.plain(2).await.is_err(),
            "拒绝前不能输出 VLESS 成功响应"
        );
        drain_closed(&mut client.io).await;
        idle(&server).await;
        assert!(
            timeout(Duration::from_millis(50), business.accept())
                .await
                .is_err()
        );
        only_original_target(&target, &original, &raw_ch).await;
        zero_business(&server);
        drop(client);
        server.shutdown().await;
        target.shutdown().await.unwrap();
    }
}
