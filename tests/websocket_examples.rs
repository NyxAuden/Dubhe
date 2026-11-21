//! 原模板必须保留不可用占位；只将测试副本替换成临时凭据、证书与回环端口。
//! 业务端独立编码 WS 和代理 wire；不将 WS Close 当成 TCP 单向 FIN。
mod common;
#[path = "common/vmess.rs"]
mod vmess;
#[path = "common/websocket.rs"]
mod ws;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Certificate, Echo, Running};
use serde_json::{Value, json};
use std::{
    fs,
    net::{SocketAddr, TcpListener as StdListener},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::{sleep, timeout},
};

const BINARY: &str = env!("CARGO_BIN_EXE_dubhe");
const WAIT: Duration = Duration::from_secs(5);
const EXAMPLES: [(&str, &str); 6] = [
    ("vless-ws", include_str!("../examples/vless-ws.json")),
    ("vless-wss", include_str!("../examples/vless-wss.json")),
    ("vmess-ws", include_str!("../examples/vmess-ws.json")),
    ("vmess-wss", include_str!("../examples/vmess-wss.json")),
    ("trojan-ws", include_str!("../examples/trojan-ws.json")),
    ("trojan-wss", include_str!("../examples/trojan-wss.json")),
];

struct Check {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
    _directory: tempfile::TempDir,
}
impl Check {
    fn spawn(configuration: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let stdout = directory.path().join("stdout.log");
        let stderr = directory.path().join("stderr.log");
        fs::write(&path, configuration).unwrap();
        let child = Command::new(BINARY)
            .arg("check")
            .arg("-c")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        Self {
            child,
            stdout,
            stderr,
            _directory: directory,
        }
    }
    async fn wait(&mut self) -> ExitStatus {
        timeout(WAIT, async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("示例 CLI check 未及时退出：{}", self.output()))
    }
    fn output(&self) -> String {
        format!(
            "{}{}",
            fs::read_to_string(&self.stdout).unwrap(),
            fs::read_to_string(&self.stderr).unwrap()
        )
    }
    fn assert_no_ready(&self) {
        for line in fs::read_to_string(&self.stderr).unwrap().lines() {
            if let Ok(event) = serde_json::from_str::<Value>(line) {
                assert!(
                    !matches!(
                        event["fields"]["event"].as_str(),
                        Some("ready" | "inbound_ready")
                    ),
                    "check 不应启动监听"
                );
            }
        }
    }
}
impl Drop for Check {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn identity(index: usize) -> (String, [u8; 16]) {
    let mut bytes = vmess::ID;
    bytes[15] += index as u8;
    (
        format!("11111111-1111-4111-8111-1111111111{:02x}", bytes[15]),
        bytes,
    )
}

fn password(index: usize) -> String {
    format!("test-only-websocket-example-{index}-not-for-deployment")
}

fn prepared(index: usize, certificate: &Certificate, listen: SocketAddr) -> Value {
    let (name, source) = EXAMPLES[index];
    let mut value: Value = serde_json::from_str(source).unwrap();
    let inbound = &mut value["inbounds"][0];
    inbound["listen"] = json!(listen);
    inbound["users"][0]["name"] = json!(format!("test-{name}"));
    if name.starts_with("trojan") {
        inbound["users"][0]["password"] = json!(password(index));
    } else {
        inbound["users"][0]["uuid"] = json!(identity(index).0);
    }
    if name.ends_with("wss") {
        inbound["certificate"] = json!(certificate.dir.path().join("cert.pem"));
        inbound["private_key"] = json!(certificate.dir.path().join("key.pem"));
    }
    value["limits"] = json!({"handshake_timeout_ms":3000, "shutdown_timeout_ms":100});
    value
}

#[test]
fn templates_have_independent_placeholders_loopback_and_explicit_transport_policy() {
    let mut users = std::collections::HashSet::new();
    let mut tags = std::collections::HashSet::new();
    let mut addresses = std::collections::HashSet::new();
    let mut early_modes = std::collections::HashSet::new();
    for (name, source) in EXAMPLES {
        let value: Value = serde_json::from_str(source).unwrap();
        let inbounds = value["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 1, "{name}");
        let inbound = &inbounds[0];
        let address: SocketAddr = inbound["listen"].as_str().unwrap().parse().unwrap();
        assert!(address.ip().is_loopback(), "{name}");
        assert_ne!(address.port(), 0, "示例端口应是明确的回环模板");
        assert!(addresses.insert(address), "示例应有独立监听地址");
        assert!(tags.insert(inbound["tag"].as_str().unwrap().to_owned()));
        assert_eq!(inbound["users"].as_array().unwrap().len(), 1);
        assert!(users.insert(inbound["users"][0]["name"].as_str().unwrap().to_owned()));
        let protocol = name.split('-').next().unwrap();
        assert_eq!(inbound["type"], format!("{protocol}-ws"));
        let tls = name.ends_with("wss");
        assert_eq!(inbound.get("certificate").is_some(), tls);
        assert_eq!(inbound.get("private_key").is_some(), tls);
        if !tls && matches!(protocol, "vless" | "trojan") {
            assert_eq!(inbound["allow_insecure_transport"], true);
        } else {
            assert!(inbound.get("allow_insecure_transport").is_none());
        }
        if protocol == "vmess" {
            for flag in [
                "xudp",
                "packetaddr",
                "allow_insecure_body",
                "allow_authenticated_length",
            ] {
                assert_eq!(inbound[flag], false, "{name}:{flag}");
            }
        }
        let user = &inbound["users"][0];
        if protocol == "trojan" {
            // 非空 REPLACE 文本是合法 Trojan 密码，故使用显式空占位强制 check 失败。
            assert_eq!(user["password"], "");
            assert!(user["name"].as_str().unwrap().contains("REPLACE_WITH_"));
        } else {
            assert!(user["uuid"].as_str().unwrap().contains("REPLACE_WITH_"));
        }
        assert!(dubhe::Config::from_json(source).is_err(), "{name}");
        early_modes.insert(
            inbound["websocket"]["early_data"]["mode"]
                .as_str()
                .unwrap_or("disabled")
                .to_owned(),
        );
    }
    assert_eq!(
        early_modes,
        ["disabled", "header", "path"]
            .into_iter()
            .map(str::to_owned)
            .collect::<std::collections::HashSet<_>>()
    );
}

#[tokio::test]
async fn original_placeholder_templates_fail_real_cli_check_without_secret_output() {
    for (name, source) in EXAMPLES {
        let mut check = Check::spawn(source);
        assert_eq!(check.wait().await.code(), Some(1), "{name}");
        let output = check.output();
        assert!(!output.contains("配置检查通过"), "{name}");
        let value: Value = serde_json::from_str(source).unwrap();
        let user = &value["inbounds"][0]["users"][0];
        for marker in [user["uuid"].as_str(), user["name"].as_str()]
            .into_iter()
            .flatten()
        {
            if marker.contains("REPLACE_WITH_") {
                assert!(!output.contains(marker), "CLI 不应反射占位身份：{name}");
            }
        }
        check.assert_no_ready();
    }
}

#[tokio::test]
async fn prepared_templates_pass_real_cli_check_without_binding_or_accepting() {
    let certificate = Certificate::new();
    let occupied = StdListener::bind("127.0.0.1:0").unwrap();
    occupied.set_nonblocking(true).unwrap();
    let address = occupied.local_addr().unwrap();
    for (index, (name, _)) in EXAMPLES.iter().enumerate() {
        let value = prepared(index, &certificate, address);
        let mut check = Check::spawn(&value.to_string());
        assert!(check.wait().await.success(), "{name}: {}", check.output());
        let output = check.output();
        assert!(output.contains("配置检查通过"), "{name}");
        for secret in [password(index), identity(index).0] {
            assert!(!output.contains(&secret), "CLI 不应输出测试凭据：{name}");
        }
        check.assert_no_ready();
        assert_eq!(
            occupied.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(occupied.local_addr().unwrap(), address);
    }
    drop(occupied);
    let _rebound = StdListener::bind(address).unwrap();
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Peer = ws::Peer<Box<dyn Io>>;

async fn upgrade(
    address: SocketAddr,
    certificate: Option<&Certificate>,
    websocket: &Value,
    wire: &[u8],
) -> Peer {
    assert!(!wire.is_empty());
    let mut path = websocket["path"].as_str().unwrap().to_owned();
    let mut headers = String::new();
    let early = websocket.get("early_data");
    let prefix = if let Some(early) = early {
        let limit = usize::try_from(early["max_bytes"].as_u64().unwrap()).unwrap();
        let n = limit.min(wire.len().div_ceil(2));
        assert_ne!(n, 0);
        let encoded = URL_SAFE_NO_PAD.encode(&wire[..n]);
        match early["mode"].as_str().unwrap() {
            "header" => {
                let header = early["header_name"]
                    .as_str()
                    .unwrap_or("Sec-WebSocket-Protocol");
                headers = format!("{header}: {encoded}\r\n");
            }
            "path" => path.push_str(&encoded),
            _ => panic!("示例中未知 early-data 模式"),
        }
        n
    } else {
        0
    };
    // early-data 是首个代理头的真实前缀，其余字节是紧随 HTTP 的原始掩码帧。
    let raw = ws::masked(true, 2, &wire[prefix..]);
    let io: Box<dyn Io> = match certificate {
        Some(cert) => Box::new(cert.connect(address).await),
        None => Box::new(TcpStream::connect(address).await.unwrap()),
    };
    ws::upgrade(io, &path, &headers, &raw).await
}

fn vless_header(index: usize, destination: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend(identity(index).1);
    bytes.extend([0, 1]);
    bytes.extend(destination.port().to_be_bytes());
    match destination.ip() {
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

async fn finish(peer: &mut Peer) {
    peer.close().await;
    ws::closed(peer).await;
}

async fn settled(server: &Running, payload: usize) {
    timeout(WAIT, async {
        loop {
            let stats = server.stats.snapshot();
            if stats.connections == 0 && stats.tcp_flows == 0 && stats.udp_associations == 0 {
                assert_eq!(stats.uplink, payload as u64);
                assert_eq!(stats.downlink, payload as u64);
                break;
            }
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("示例业务或子任务未结束");
}

async fn transfer(index: usize) {
    let (name, _) = EXAMPLES[index];
    let certificate = Certificate::new();
    let value = prepared(index, &certificate, "127.0.0.1:0".parse().unwrap());
    let websocket = value["inbounds"][0]["websocket"].clone();
    let echo = Echo::tcp("127.0.0.1", false).await;
    let server = Running::start(value).await;
    let cert = name.ends_with("wss").then_some(&certificate);
    let first = b"example-first\0\xff";
    let second = b"example-second-exchange";
    if name.starts_with("vmess") {
        for security in [3, 4] {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut request = vmess::Request::at(
                1,
                vmess::target(echo.address),
                security,
                1,
                identity(index).1,
                timestamp,
                None,
            );
            let peer = upgrade(server.address, cert, &websocket, &request.wire).await;
            // 整个 AEAD 认证头已恰一次发送；保留密钥状态供独立客户端解响应/正文。
            request.wire.clear();
            let mut client = vmess::Client::start(peer, request, Some(first)).await;
            assert_eq!(client.read(first.len()).await, first);
            client.send(second).await;
            assert_eq!(client.read(second.len()).await, second);
            finish(&mut client.io).await;
        }
        settled(&server, 2 * (first.len() + second.len())).await;
    } else {
        let vless = name.starts_with("vless");
        let mut wire = if vless {
            vless_header(index, echo.address)
        } else {
            common::trojan_header(1, common::address(echo.address), &password(index))
        };
        wire.extend(first);
        let mut peer = upgrade(server.address, cert, &websocket, &wire).await;
        if vless {
            let mut response = [0xff; 2];
            common::read_exact(&mut peer, &mut response).await;
            assert_eq!(response, [0, 0]);
        }
        // Trojan 没有成功应答，第一个字节必须就是真实回显业务字节。
        let mut echoed = vec![0; first.len()];
        common::read_exact(&mut peer, &mut echoed).await;
        assert_eq!(echoed, first);
        peer.send_message(2, second).await;
        let mut echoed = vec![0; second.len()];
        common::read_exact(&mut peer, &mut echoed).await;
        assert_eq!(echoed, second);
        finish(&mut peer).await;
        settled(&server, first.len() + second.len()).await;
    }
    server.shutdown().await;
}

#[tokio::test]
async fn vless_ws_example_starts_and_transfers_with_its_configured_transport() {
    transfer(0).await;
}

#[tokio::test]
async fn vless_wss_example_starts_and_transfers_with_its_configured_transport() {
    transfer(1).await;
}

#[tokio::test]
async fn vmess_ws_example_starts_and_transfers_with_its_configured_transport() {
    transfer(2).await;
}

#[tokio::test]
async fn vmess_wss_example_starts_and_transfers_with_its_configured_transport() {
    transfer(3).await;
}

#[tokio::test]
async fn trojan_ws_example_starts_and_transfers_with_its_configured_transport() {
    transfer(4).await;
}

#[tokio::test]
async fn trojan_wss_example_starts_and_transfers_with_its_configured_transport() {
    transfer(5).await;
}
