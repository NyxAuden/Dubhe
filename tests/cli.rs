mod common;

use std::{
    fs,
    net::TcpListener as StdListener,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};

use common::*;
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};

const BINARY: &str = env!("CARGO_BIN_EXE_dubhe");
// CLI 子进程启动 + 证书轮换在 2 核 CI runner 上可能超过 5 秒；
// 这里是等待上限，不是性能断言，放宽不放松正确性要求。
const WAIT: Duration = Duration::from_secs(20);
const CONFIG_PASSWORD: &str = "configured-password-do-not-log-317";

struct CliProcess {
    child: Child,
    _directory: tempfile::TempDir,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl CliProcess {
    fn spawn(command: &str, configuration: Option<&str>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let stdout = directory.path().join("stdout.log");
        let stderr = directory.path().join("stderr.log");
        let mut process = Command::new(BINARY);
        process.arg(command);
        if let Some(configuration) = configuration {
            let path = directory.path().join("config.json");
            fs::write(&path, configuration).unwrap();
            process.args(["-c", path.to_str().unwrap()]);
        }
        let child = process
            .stdin(Stdio::null())
            .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        Self {
            child,
            _directory: directory,
            stdout,
            stderr,
        }
    }

    fn output(&self) -> String {
        format!(
            "{}{}",
            fs::read_to_string(&self.stdout).unwrap(),
            fs::read_to_string(&self.stderr).unwrap()
        )
    }

    fn events(&self) -> Vec<Value> {
        fs::read_to_string(&self.stderr)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    async fn wait_exit(&mut self) -> ExitStatus {
        timeout(WAIT, async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("CLI 未在期限内退出：{}", self.output()))
    }

    #[cfg(unix)]
    async fn wait_event(&mut self, predicate: impl Fn(&Value) -> bool) -> Value {
        timeout(WAIT, async {
            loop {
                if let Some(event) = self.events().into_iter().find(|event| predicate(event)) {
                    return event;
                }
                assert!(
                    self.child.try_wait().unwrap().is_none(),
                    "CLI 在预期事件出现前退出：{}",
                    self.output()
                );
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("CLI 未输出预期事件：{}", self.output()))
    }
}

/// 选一个子进程启动前必须释放的端口。
///
/// 并行测试各自“绑定 :0 → 释放 → 子进程绑定”时，内核可能把刚释放的端口
/// 再发给另一个测试；全局记录已发出的端口，避免两次分配落到同一端口。
/// 预留一个测试专用端口。
///
/// 不能直接用 `bind("127.0.0.1:0")` 的返回值：Linux 的临时端口范围是
/// 32768–60999，`bind(0)` 恰好从这个范围里取，而同一时刻其它测试建立的
/// TCP 连接会把这些端口当作**源端口**占用。于是「释放 → 稍后再 bind」
/// 会间歇性拿到 `AddrInUse`（2026-11-22 在 CI x86_64 上实测复现）。
///
/// 这里改为在临时端口范围之外顺序探测，并保证进程内不重复发放。
/// 子进程退出后立刻重绑端口，证明监听确实被释放。
///
/// 并行跑全套测试时实测出现过一次 `AddrInUse`：端口刚被释放、或被并发的
/// 客户端连接占成 TIME_WAIT。这里只重试一小段时间，**退出码与非 ready 断言
/// 不变**，监听泄漏仍会让测试失败。
fn bind_released(address: std::net::SocketAddr) -> StdListener {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match StdListener::bind(address) {
            Ok(listener) => return listener,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "端口 {address} 未被释放：{error}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// 导出与转换结果里有密码/私钥，文件必须是 0600。
#[cfg(unix)]
#[tokio::test]
async fn export_and_convert_outputs_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("server.json");
    let mut configuration = socks_config();
    configuration["inbounds"] = json!([{
        "type": "shadowsocks", "tag": "s", "listen": "127.0.0.1:0",
        "method": "aes-128-gcm", "password": "test-password"
    }]);
    fs::write(&config_path, configuration.to_string()).unwrap();

    let export_dir = directory.path().join("export");
    let status = Command::new(BINARY)
        .args([
            "export",
            "-c",
            config_path.to_str().unwrap(),
            "--host",
            "example.com",
            "-o",
            export_dir.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "export 应成功");

    let convert_input = directory.path().join("xray.json");
    fs::write(
        &convert_input,
        json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        })
        .to_string(),
    )
    .unwrap();
    let convert_output = directory.path().join("converted.json");
    let status = Command::new(BINARY)
        .args([
            "convert",
            "-i",
            convert_input.to_str().unwrap(),
            "-o",
            convert_output.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "convert 应成功");

    for path in [
        export_dir.join("xray-client.json"),
        export_dir.join("sing-box-client.json"),
        convert_output,
    ] {
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o600,
            "{} 权限应为 0600，实际 {mode:o}",
            path.display()
        );
    }
}

fn reserve_port() -> std::net::SocketAddr {
    static ISSUED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    let issued = ISSUED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    // 20000–29999 低于临时端口下界 32768，避开内核自动分配的源端口。
    // 本文件独占 20000–22499 段。`reserve_port` 的 HashSet 只能在**当前测试二进制**
    // 内去重，cargo 并行跑多个测试二进制时互相看不见；此前四个文件共用
    // 20000–29999，实测出现过 `入口 X 绑定失败: AddrInUse`。
    for port in 20000u16..22500 {
        if issued.lock().unwrap().contains(&port) {
            continue;
        }
        let Ok(listener) = StdListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        drop(listener);
        if issued.lock().unwrap().insert(port) {
            return std::net::SocketAddr::from(([127, 0, 0, 1], port));
        }
    }
    panic!("没有可用测试端口");
}

impl Drop for CliProcess {
    fn drop(&mut self) {
        // 断言失败也清理被测进程，日志目录在进程退出后才删除。
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn check_validates_both_inbounds_without_binding_or_accepting_connections() {
    let certificate = Certificate::new();
    let occupied = StdListener::bind("127.0.0.1:0").unwrap();
    occupied.set_nonblocking(true).unwrap();
    let address = occupied.local_addr().unwrap();
    let mut configuration = socks_config();
    configuration["inbounds"][0]["listen"] = json!(address);
    configuration["inbounds"][0]["users"] = json!([{"name":"tester", "password":CONFIG_PASSWORD}]);
    // 两个入口必须用不同端口：同 (地址, 端口, TCP) 现在会被 check 拒绝。
    // 测的是「check 不实际绑定」——端口由本测试自己占着，check 仍应通过。
    let mut trojan = certificate.inbound();
    let trojan_address = std::net::SocketAddr::from(([127, 0, 0, 1], address.port() + 1));
    trojan["listen"] = json!(trojan_address);
    configuration["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(trojan);
    let mut process = CliProcess::spawn("check", Some(&configuration.to_string()));
    assert!(process.wait_exit().await.success());
    assert!(process.output().contains("配置检查通过"));
    assert!(!process.output().contains(CONFIG_PASSWORD));
    assert!(!process.output().contains(PASSWORD));
    assert!(
        !process
            .events()
            .iter()
            .any(|event| event["fields"]["event"] == "ready")
    );
    assert_eq!(
        occupied.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(occupied.local_addr().unwrap(), address);
}

#[tokio::test]
async fn shadowsocks_check_prepares_keys_without_binding_and_redacts_failures() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use shadowsocks::config::ServerUser;

    let occupied = StdListener::bind("127.0.0.1:0").unwrap();
    occupied.set_nonblocking(true).unwrap();
    let udp = std::net::UdpSocket::bind(occupied.local_addr().unwrap()).unwrap();
    udp.set_nonblocking(true).unwrap();
    for method in [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ] {
        let length = if method == "2022-blake3-aes-128-gcm" {
            16
        } else {
            32
        };
        let identity = STANDARD.encode(vec![0x73; length]);
        let user_key = vec![0x74; length];
        let user_password = STANDARD.encode(&user_key);
        let user = ServerUser::new("tester".to_owned(), user_key);
        let hash_hex: String = user
            .identity_hash()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let hash_debug = format!("{:?}", user.identity_hash());
        let mut configuration = socks_config();
        configuration["inbounds"] = json!([{
            "type": "shadowsocks", "tag": "ss", "listen": occupied.local_addr().unwrap(),
            "method": method,
            "password": if method.starts_with("2022-") { identity.as_str() } else { CONFIG_PASSWORD }
        }]);
        if method.starts_with("2022-blake3-aes-") {
            configuration["inbounds"][0]["users"] = json!([
                {"name": "tester", "password": user_password}
            ]);
        }
        let mut valid = CliProcess::spawn("check", Some(&configuration.to_string()));
        assert!(valid.wait_exit().await.success());
        assert!(valid.output().contains("配置检查通过"));

        configuration["inbounds"][0]["password"] = json!("psk-secret-invalid-921");
        if !method.starts_with("2022-") {
            configuration["inbounds"][0]["password"] = json!("");
        }
        let mut invalid = CliProcess::spawn("check", Some(&configuration.to_string()));
        assert_eq!(invalid.wait_exit().await.code(), Some(1));
        assert!(!invalid.output().contains("配置检查通过"));
        for process in [&valid, &invalid] {
            let output = process.output();
            for secret in [
                CONFIG_PASSWORD,
                &identity,
                &user_password,
                &hash_hex,
                &hash_debug,
                "psk-secret-invalid-921",
            ] {
                assert!(!output.contains(secret), "Shadowsocks CLI 输出包含敏感材料");
            }
            assert!(
                !process
                    .events()
                    .iter()
                    .any(|event| event["fields"]["event"] == "ready")
            );
        }
    }
    assert_eq!(
        occupied.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        udp.recv_from(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(unix)]
#[tokio::test]
async fn shadowsocks_failed_joint_start_has_no_ready_and_releases_earlier_ports() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let first_address = reserve_port();
    let mut configuration = socks_config();
    configuration["inbounds"] = json!([
        {"type":"shadowsocks", "tag":"first", "listen":first_address, "method":"aes-128-gcm", "password":CONFIG_PASSWORD},
        {"type":"shadowsocks", "tag":"second", "listen":occupied.local_addr().unwrap(), "method":"2022-blake3-aes-128-gcm", "password":STANDARD.encode([0x73; 16])}
    ]);
    let mut process = CliProcess::spawn("run", Some(&configuration.to_string()));
    assert_eq!(process.wait_exit().await.code(), Some(1));
    assert!(!process.events().iter().any(|event| matches!(
        event["fields"]["event"].as_str(),
        Some("ready" | "inbound_ready")
    )));
    assert!(!process.output().contains(CONFIG_PASSWORD));
    let _tcp = bind_released(first_address);
    let _udp = std::net::UdpSocket::bind(first_address).unwrap();
    let _second_tcp = StdListener::bind(occupied.local_addr().unwrap()).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn shadowsocks_protocol_library_identity_logs_are_not_published() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use shadowsocks::{
        config::{ServerConfig, ServerType},
        context::Context,
        crypto::CipherKind,
        relay::{
            Address,
            udprelay::{crypto_io::encrypt_client_payload, options::UdpSocketControlData},
        },
    };
    use tokio::net::UdpSocket;
    let address = reserve_port();
    let identity = STANDARD.encode([0x73; 16]);
    let configured = STANDARD.encode([0x74; 16]);
    let unknown = STANDARD.encode([0x75; 16]);
    let mut configuration = socks_config();
    configuration["inbounds"] = json!([{
        "type":"shadowsocks", "tag":"ss", "listen":address,
        "method":"2022-blake3-aes-128-gcm", "password":identity,
        "users":[{"name":"tester", "password":configured}]
    }]);
    configuration["limits"]["stats_interval_ms"] = json!(50);
    let mut process = CliProcess::spawn("run", Some(&configuration.to_string()));
    process
        .wait_event(|event| event["fields"]["event"] == "ready")
        .await;
    let client = ServerConfig::new(
        address,
        format!("{identity}:{unknown}"),
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    )
    .unwrap();
    let mut wire = Default::default();
    encrypt_client_payload(
        &Context::new(ServerType::Local),
        client.method(),
        client.key(),
        &Address::SocketAddress("127.0.0.1:1".parse().unwrap()),
        &UdpSocketControlData::default(),
        client.identity_keys(),
        b"payload-secret-823",
        &mut wire,
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&wire, address).await.unwrap();
    // SS-UDP 的认证失败计入 rejected（与 TCP 侧一致）；此前计入 dropped，
    // 会让口令猜测混在「队列拥塞丢包」里。两种都算「被内核拒绝」。
    process
        .wait_event(|event| {
            event["fields"]["event"] == "stats"
                && ["dropped", "rejected"]
                    .iter()
                    .any(|field| event["fields"][field].as_u64().is_some_and(|n| n >= 1))
        })
        .await;
    let output = process.output();
    for secret in [
        &identity,
        &configured,
        &unknown,
        "payload-secret-823",
        "user with identity",
        "shadowsocks::",
    ] {
        assert!(!output.contains(secret));
    }
    // 正常的内核统计仍在输出，而协议库含身份材料的ERROR事件被目标过滤器阻止。
    assert!(
        process
            .events()
            .iter()
            .any(|event| event["fields"]["event"] == "stats")
    );
}

#[tokio::test]
async fn shadowsocks_examples_check_after_replacing_every_secret_with_random_material() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rustls::crypto::SecureRandom;
    let random = rustls::crypto::ring::default_provider().secure_random;
    fn fresh(random: &dyn SecureRandom, length: usize) -> String {
        let mut bytes = vec![0; length];
        random.fill(&mut bytes).unwrap();
        STANDARD.encode(bytes)
    }
    for (template, length) in [
        (include_str!("../examples/shadowsocks-2017.json"), 32),
        (include_str!("../examples/shadowsocks-2022.json"), 16),
        (include_str!("../examples/shadowsocks-eih.json"), 32),
    ] {
        let mut configuration: Value = serde_json::from_str(template).unwrap();
        let inbound = &mut configuration["inbounds"][0];
        assert!(
            inbound["password"]
                .as_str()
                .unwrap()
                .starts_with("REPLACE_WITH_")
        );
        let mut secrets = vec![fresh(random, length)];
        inbound["password"] = json!(secrets[0]);
        if let Some(users) = inbound.get_mut("users").and_then(Value::as_array_mut) {
            for user in users {
                assert!(
                    user["password"]
                        .as_str()
                        .unwrap()
                        .starts_with("REPLACE_WITH_")
                );
                let key = fresh(random, length);
                assert!(!secrets.contains(&key));
                user["password"] = json!(key);
                secrets.push(key);
            }
        }
        let mut process = CliProcess::spawn("check", Some(&configuration.to_string()));
        assert!(process.wait_exit().await.success());
        let output = process.output();
        assert!(!output.contains("ready"));
        for secret in secrets {
            assert!(!output.contains(&secret));
        }
    }
}

#[tokio::test]
async fn invalid_checks_exit_nonzero_emit_errors_and_redact_configuration() {
    let mut invalid = socks_config();
    invalid["inbounds"][0]["users"] = json!([{"name":"tester", "password":CONFIG_PASSWORD}]);
    invalid["unexpected-secret-field-918"] = json!("untrusted-value-do-not-log-629");
    let malformed = format!("{{\"password\":\"{CONFIG_PASSWORD}\", invalid-json");
    let certificate = Certificate::new();
    let other = Certificate::new();
    let mut mismatched = socks_config();
    let mut inbound = certificate.inbound();
    inbound["private_key"] = json!(other.dir.path().join("key.pem"));
    mismatched["inbounds"] = json!([inbound]);
    for configuration in [invalid.to_string(), malformed, mismatched.to_string()] {
        let mut process = CliProcess::spawn("check", Some(&configuration));
        let status = process.wait_exit().await;
        assert_eq!(status.code(), Some(1));
        let output = process.output();
        for secret in [
            CONFIG_PASSWORD,
            PASSWORD,
            "unexpected-secret-field-918",
            "untrusted-value-do-not-log-629",
        ] {
            assert!(!output.contains(secret), "错误输出包含敏感配置");
        }
        assert!(
            process
                .events()
                .iter()
                .any(|event| event["level"] == "ERROR" && event["fields"]["event"] == "fatal"),
            "失败退出必须保留结构化错误日志"
        );
        assert!(!output.contains("配置检查通过"));
        assert!(!output.contains("BEGIN PRIVATE KEY"));
    }
}

#[tokio::test]
async fn vless_check_validates_tls_and_redacts_uuid_without_binding() {
    let cert = Certificate::new();
    let other = Certificate::new();
    let occupied = StdListener::bind("127.0.0.1:0").unwrap();
    occupied.set_nonblocking(true).unwrap();
    let uuid = "f57196ec-a7a1-49bb-9445-e755ec418605";
    let mut configuration = socks_config();
    configuration["inbounds"] = json!([{
        "type":"vless","tag":"vless","listen":occupied.local_addr().unwrap(),
        "users":[{"name":"test","uuid":uuid}],
        "certificate":cert.dir.path().join("cert.pem"),
        "private_key":cert.dir.path().join("key.pem")
    }]);
    let mut valid = CliProcess::spawn("check", Some(&configuration.to_string()));
    assert!(valid.wait_exit().await.success());
    assert!(!valid.output().contains(uuid));
    assert_eq!(
        occupied.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    configuration["inbounds"][0]["private_key"] = json!(other.dir.path().join("key.pem"));
    let mut mismatched = CliProcess::spawn("check", Some(&configuration.to_string()));
    assert_eq!(mismatched.wait_exit().await.code(), Some(1));
    assert!(!mismatched.output().contains(uuid));
    configuration["inbounds"][0]["users"][0]["uuid"] = json!("invalid-secret-uuid");
    let mut invalid = CliProcess::spawn("run", Some(&configuration.to_string()));
    assert_eq!(invalid.wait_exit().await.code(), Some(1));
    assert!(!invalid.output().contains("invalid-secret-uuid"));
    assert!(
        !invalid
            .events()
            .iter()
            .any(|e| e["fields"]["event"] == "ready")
    );
}

#[tokio::test]
async fn vless_vision_check_accepts_mixed_flows_and_rejects_invalid_flows_without_binding() {
    let cert = Certificate::new();
    let occupied = StdListener::bind("127.0.0.1:0").unwrap();
    occupied.set_nonblocking(true).unwrap();
    let uuids = [
        "f57196ec-a7a1-49bb-9445-e755ec418605",
        "00112233-4455-6677-8899-aabbccddeeff",
        "f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f",
    ];
    let mut configuration = socks_config();
    configuration["inbounds"] = json!([{
        "type":"vless", "tag":"vless", "listen":occupied.local_addr().unwrap(),
        "users":[
            {"name":"legacy", "uuid":uuids[0]},
            {"name":"vision", "uuid":uuids[1], "flow":"xtls-rprx-vision"},
            {"name":"empty", "uuid":uuids[2], "flow":""}
        ],
        "certificate":cert.dir.path().join("cert.pem"),
        "private_key":cert.dir.path().join("key.pem")
    }]);
    for xudp in [false, true] {
        configuration["inbounds"][0]["xudp"] = json!(xudp);
        let mut process = CliProcess::spawn("check", Some(&configuration.to_string()));
        assert!(process.wait_exit().await.success());
        let output = process.output();
        assert!(output.contains("配置检查通过"));
        for uuid in uuids {
            assert!(!output.contains(uuid));
        }
        assert!(!process.events().iter().any(|event| matches!(
            event["fields"]["event"].as_str(),
            Some("ready" | "inbound_ready")
        )));
    }
    for flow in [
        json!(null),
        json!(true),
        json!(1),
        json!([]),
        json!({"xtls-rprx-vision": null}),
        json!("flow-secret-918"),
        json!("xtls-rprx-vision-udp443"),
        json!("xtls-rprx-direct"),
        json!("xtls-rprx-vision "),
    ] {
        let mut invalid = configuration.clone();
        invalid["inbounds"][0]["users"][1]["flow"] = flow;
        let mut process = CliProcess::spawn("check", Some(&invalid.to_string()));
        assert_eq!(process.wait_exit().await.code(), Some(1));
        let output = process.output();
        assert!(!output.contains("配置检查通过"));
        assert!(!output.contains("flow-secret-918"));
        assert!(!output.contains("xtls-rprx-"));
        for uuid in uuids {
            assert!(!output.contains(uuid));
        }
        assert!(!process.events().iter().any(|event| matches!(
            event["fields"]["event"].as_str(),
            Some("ready" | "inbound_ready")
        )));
    }
    configuration["inbounds"][0]["flow"] = json!("xtls-rprx-vision");
    let mut entry_flow = CliProcess::spawn("check", Some(&configuration.to_string()));
    assert_eq!(entry_flow.wait_exit().await.code(), Some(1));
    let output = entry_flow.output();
    assert!(output.contains("未知字段"));
    assert!(!output.contains("xtls-rprx-"));
    for uuid in uuids {
        assert!(!output.contains(uuid));
    }
    assert_eq!(
        occupied.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

const VMESS_UUID: &str = "f57196ec-a7a1-49bb-9445-e755ec418605";

fn vmess_inbound(address: std::net::SocketAddr) -> Value {
    json!({
        "type": "vmess", "tag": "vmess", "listen": address,
        "users": [{"name": "test", "uuid": VMESS_UUID}]
    })
}

fn assert_vmess_cli_redacted_and_not_ready(process: &CliProcess) {
    let output = process.output();
    for secret in [
        VMESS_UUID,
        "invalid-secret-vmess-uuid",
        "vmess-pem-secret-918",
        "BEGIN PRIVATE KEY",
    ] {
        assert!(!output.contains(secret), "VMess CLI 输出泄漏敏感配置");
    }
    assert!(!process.events().iter().any(|event| matches!(
        event["fields"]["event"].as_str(),
        Some("ready" | "inbound_ready")
    )));
}

#[tokio::test]
async fn vmess_check_accepts_direct_and_tls_without_binding_or_connecting() {
    let certificate = Certificate::new();
    let occupied = StdListener::bind("127.0.0.1:0").unwrap();
    occupied.set_nonblocking(true).unwrap();
    let address = occupied.local_addr().unwrap();
    let mut configuration = socks_config();
    let direct = vmess_inbound(address);
    let mut tls = direct.clone();
    tls["tag"] = json!("vmess-tls");
    tls["certificate"] = json!(certificate.dir.path().join("cert.pem"));
    tls["private_key"] = json!(certificate.dir.path().join("key.pem"));
    let mut tls_other_port = tls.clone();
    tls_other_port["listen"] = json!(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        address.port() + 1
    )));
    // 两个入口必须用不同端口：同一 (地址, 端口, TCP) 现在由 check 静态拒绝。
    // 这里验证的是「check 不真实 bind」——地址由本测试占着，check 仍应通过。
    for inbounds in [
        json!([direct.clone()]),
        json!([tls.clone()]),
        json!([direct, tls_other_port]),
    ] {
        configuration["inbounds"] = inbounds;
        let mut process = CliProcess::spawn("check", Some(&configuration.to_string()));
        assert!(process.wait_exit().await.success());
        assert!(process.output().contains("配置检查通过"));
        assert_vmess_cli_redacted_and_not_ready(&process);
        assert_eq!(
            occupied.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(occupied.local_addr().unwrap(), address);
    }
}

#[tokio::test]
async fn vmess_check_rejects_partial_null_empty_invalid_tls_and_redacts_uuid() {
    let certificate = Certificate::new();
    let other = Certificate::new();
    let occupied = StdListener::bind("127.0.0.1:0").unwrap();
    occupied.set_nonblocking(true).unwrap();
    let address = occupied.local_addr().unwrap();
    let mut tls = vmess_inbound(address);
    tls["certificate"] = json!(certificate.dir.path().join("cert.pem"));
    tls["private_key"] = json!(certificate.dir.path().join("key.pem"));
    let invalid_certificate = certificate.dir.path().join("bad-cert.pem");
    let invalid_key = certificate.dir.path().join("bad-key.pem");
    fs::write(&invalid_certificate, "vmess-pem-secret-918").unwrap();
    fs::write(&invalid_key, "vmess-pem-secret-918").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&invalid_key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut cases = Vec::new();
    for field in ["certificate", "private_key"] {
        let mut missing = tls.clone();
        missing.as_object_mut().unwrap().remove(field);
        cases.push(missing);
        for invalid in [json!(null), json!(""), json!(true)] {
            let mut value = tls.clone();
            value[field] = invalid;
            cases.push(value);
        }
    }
    let mut null_pair = tls.clone();
    null_pair["certificate"] = Value::Null;
    null_pair["private_key"] = Value::Null;
    cases.push(null_pair);
    for (field, path) in [
        ("certificate", invalid_certificate),
        ("private_key", invalid_key),
        (
            "certificate",
            certificate.dir.path().join("missing-cert.pem"),
        ),
        (
            "private_key",
            certificate.dir.path().join("missing-key.pem"),
        ),
        ("private_key", other.dir.path().join("key.pem")),
    ] {
        let mut value = tls.clone();
        value[field] = json!(path);
        cases.push(value);
    }
    let mut malformed_uuid = tls;
    malformed_uuid["users"][0]["uuid"] = json!("invalid-secret-vmess-uuid");
    cases.push(malformed_uuid);
    for inbound in cases {
        let mut configuration = socks_config();
        configuration["inbounds"] = json!([inbound]);
        let mut process = CliProcess::spawn("check", Some(&configuration.to_string()));
        assert_eq!(process.wait_exit().await.code(), Some(1));
        assert!(!process.output().contains("配置检查通过"));
        assert_vmess_cli_redacted_and_not_ready(&process);
        assert!(
            process
                .events()
                .iter()
                .any(|event| event["level"] == "ERROR" && event["fields"]["event"] == "fatal")
        );
        assert_eq!(
            occupied.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn vmess_failed_joint_run_releases_earlier_listener_and_never_reports_ready() {
    let certificate = Certificate::new();
    for tls in [false, true] {
        let occupied = StdListener::bind("127.0.0.1:0").unwrap();
        occupied.set_nonblocking(true).unwrap();
        let address = reserve_port();
        let mut first = vmess_inbound(address);
        if tls {
            first["certificate"] = json!(certificate.dir.path().join("cert.pem"));
            first["private_key"] = json!(certificate.dir.path().join("key.pem"));
        }
        let mut configuration = socks_config();
        configuration["inbounds"] = json!([
            first,
            {"type":"socks5", "tag":"conflict", "listen":occupied.local_addr().unwrap()}
        ]);
        let mut process = CliProcess::spawn("run", Some(&configuration.to_string()));
        assert_eq!(process.wait_exit().await.code(), Some(1));
        assert_vmess_cli_redacted_and_not_ready(&process);
        let _rebound = bind_released(address);
        assert_eq!(
            occupied.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn vmess_later_invalid_tls_run_leaves_all_prior_ports_available() {
    let certificate = Certificate::new();
    let addresses = [reserve_port(), reserve_port(), reserve_port()];
    let invalid_certificate = certificate.dir.path().join("bad-cert.pem");
    fs::write(&invalid_certificate, "vmess-pem-secret-918").unwrap();
    let mut bad_tls = vmess_inbound(addresses[2]);
    bad_tls["tag"] = json!("bad-tls");
    bad_tls["certificate"] = json!(invalid_certificate);
    bad_tls["private_key"] = json!(certificate.dir.path().join("key.pem"));
    let mut configuration = socks_config();
    configuration["inbounds"] = json!([
        {"type":"socks5", "tag":"first", "listen":addresses[0]},
        vmess_inbound(addresses[1]),
        bad_tls
    ]);
    let mut process = CliProcess::spawn("run", Some(&configuration.to_string()));
    assert_eq!(process.wait_exit().await.code(), Some(1));
    assert_vmess_cli_redacted_and_not_ready(&process);
    let _rebound: Vec<_> = addresses.into_iter().map(bind_released).collect();
}

#[tokio::test]
async fn version_and_invalid_usage_have_distinct_exit_codes() {
    let mut version = CliProcess::spawn("version", None);
    assert!(version.wait_exit().await.success());
    assert!(
        version
            .output()
            .contains(concat!("dubhe ", env!("CARGO_PKG_VERSION")))
    );
    let mut unknown = CliProcess::spawn("unsupported-command", None);
    assert_eq!(unknown.wait_exit().await.code(), Some(2));
    let mut missing = CliProcess::spawn("check", None);
    assert_eq!(missing.wait_exit().await.code(), Some(2));
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::{net::SocketAddr, sync::Arc};
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        time::Instant,
    };

    async fn login(inbound: SocketAddr, password: &str) -> (TcpStream, [u8; 2]) {
        let mut stream = TcpStream::connect(inbound).await.unwrap();
        stream.write_all(&[5, 1, 2]).await.unwrap();
        let mut method = [0; 2];
        read_exact(&mut stream, &mut method).await;
        assert_eq!(method, [5, 2]);
        let mut authentication = b"\x01\x06tester".to_vec();
        authentication.push(password.len() as u8);
        authentication.extend(password.as_bytes());
        stream.write_all(&authentication).await.unwrap();
        let mut status = [0; 2];
        read_exact(&mut stream, &mut status).await;
        (stream, status)
    }

    async fn request(stream: &mut TcpStream, command: u8, target: SocketAddr) -> SocketAddr {
        let mut bytes = vec![5, command, 0];
        bytes.extend(address(target));
        stream.write_all(&bytes).await.unwrap();
        let mut status = [0; 3];
        read_exact(stream, &mut status).await;
        assert_eq!(status, [5, 0, 0]);
        read_address(stream).await
    }

    async fn closed<R: AsyncRead + Unpin>(stream: &mut R) {
        assert!(matches!(
            timeout(WAIT, stream.read(&mut [0])).await.unwrap(),
            Ok(0) | Err(_)
        ));
    }

    fn tls_client(der: rustls::pki_types::CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    async fn tls_connect(
        config: &Arc<rustls::ClientConfig>,
        address: SocketAddr,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(address).await?;
        let connector = tokio_rustls::TlsConnector::from(config.clone());
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        timeout(WAIT, connector.connect(name, tcp))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS 握手超时"))?
    }

    #[tokio::test]
    async fn sighup_rotates_certificate_without_restarting_listeners() {
        let certificate = Certificate::new();
        let listen = reserve_port();
        let mut inbound = certificate.inbound();
        inbound["listen"] = json!(listen);
        let mut configuration = socks_config();
        configuration["inbounds"] = json!([inbound]);
        let mut process = CliProcess::spawn("run", Some(&configuration.to_string()));
        process
            .wait_event(|event| event["fields"]["event"] == "ready")
            .await;

        let old_client = tls_client(certificate.der.clone());
        let _existing = tls_connect(&old_client, listen).await.unwrap();

        let rotated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(certificate.dir.path().join("cert.pem"), rotated.cert.pem()).unwrap();
        let key = certificate.dir.path().join("key.pem");
        fs::write(&key, rotated.key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Command::new("/bin/kill")
            .args(["-HUP", &process.child.id().to_string()])
            .status()
            .unwrap();
        process
            .wait_event(|event| event["fields"]["event"] == "reload_tls")
            .await;
        assert!(
            process.child.try_wait().unwrap().is_none(),
            "证书轮换不应重启进程：{}",
            process.output()
        );

        assert!(
            tls_connect(&old_client, listen).await.is_err(),
            "轮换后旧信任锚不应再通过校验"
        );
        let new_client = tls_client(rotated.cert.der().clone());
        let _fresh = tls_connect(&new_client, listen).await.unwrap();

        Command::new("/bin/kill")
            .args(["-TERM", &process.child.id().to_string()])
            .status()
            .unwrap();
        assert!(process.wait_exit().await.success());
    }

    #[tokio::test]
    async fn sigint_and_sigterm_drain_then_force_live_sessions_without_leaking_secrets() {
        for signal in ["-INT", "-TERM"] {
            let certificate = Certificate::new();
            let tcp = Echo::tcp("127.0.0.1", false).await;
            let udp = Echo::udp("127.0.0.1").await;
            let socks_address = reserve_port();
            let trojan_address = reserve_port();
            let mut configuration = socks_config();
            configuration["inbounds"][0]["listen"] = json!(socks_address);
            configuration["inbounds"][0]["users"] =
                json!([{"name":"tester", "password":CONFIG_PASSWORD}]);
            let mut trojan = certificate.inbound();
            trojan["listen"] = json!(trojan_address);
            configuration["inbounds"]
                .as_array_mut()
                .unwrap()
                .push(trojan);
            configuration["limits"]["stats_interval_ms"] = 20.into();
            configuration["limits"]["shutdown_timeout_ms"] = 120.into();
            configuration["limits"]["udp_idle_timeout_ms"] = 30000.into();
            let mut process = CliProcess::spawn("run", Some(&configuration.to_string()));
            process
                .wait_event(|event| event["fields"]["event"] == "ready")
                .await;

            let wrong_password = "wire-password-do-not-log-852";
            let (mut rejected, status) = login(socks_address, wrong_password).await;
            assert_eq!(status, [1, 1]);
            closed(&mut rejected).await;
            drop(rejected);
            let bad_header = trojan_header(1, address(tcp.address), "wrong-trojan-password-514");
            let bad_digest = String::from_utf8(bad_header[..56].to_vec()).unwrap();
            let mut rejected_tls = certificate.connect(trojan_address).await;
            rejected_tls.write_all(&bad_header).await.unwrap();
            closed(&mut rejected_tls).await;
            drop(rejected_tls);

            let (mut stream, status) = login(socks_address, CONFIG_PASSWORD).await;
            assert_eq!(status, [1, 0]);
            request(&mut stream, 1, tcp.address).await;
            let payload = b"private-business-payload-do-not-log-963";
            exchange(&mut stream, payload).await;
            let (mut control, status) = login(socks_address, CONFIG_PASSWORD).await;
            assert_eq!(status, [1, 0]);
            let relay = request(&mut control, 3, "0.0.0.0:0".parse().unwrap()).await;
            let datagrams = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = vec![0, 0, 0];
            packet.extend(address(udp.address));
            packet.extend(payload);
            datagrams.send_to(&packet, relay).await.unwrap();
            let mut buffer = [0; 256];
            let (length, _) = timeout(WAIT, datagrams.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..length], packet);
            process
                .wait_event(|event| {
                    let fields = &event["fields"];
                    fields["event"] == "stats"
                        && fields["tcp_flows"] == 1
                        && fields["udp_associations"] == 1
                        && fields["uplink"] == json!(payload.len() * 2)
                        && fields["downlink"] == json!(payload.len() * 2)
                        && fields["rejected"].as_u64().is_some_and(|count| count >= 2)
                })
                .await;

            let started = Instant::now();
            assert!(
                Command::new("/bin/kill")
                    .args([signal, &process.child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(process.wait_exit().await.success());
            assert!(
                started.elapsed() >= Duration::from_millis(100),
                "信号停机未等待排空期限"
            );
            let stopped = process
                .events()
                .into_iter()
                .find(|event| event["fields"]["event"] == "stopped")
                .unwrap();
            assert_eq!(stopped["fields"]["forced_connections"], 2);
            closed(&mut stream).await;
            closed(&mut control).await;
            drop(TcpListener::bind(socks_address).await.unwrap());
            drop(TcpListener::bind(trojan_address).await.unwrap());
            drop(UdpSocket::bind(relay).await.unwrap());

            let output = process.output();
            for secret in [
                CONFIG_PASSWORD,
                PASSWORD,
                wrong_password,
                "wrong-trojan-password-514",
                &bad_digest,
                std::str::from_utf8(payload).unwrap(),
            ] {
                assert!(!output.contains(secret), "运行日志泄漏凭据、摘要或业务载荷");
            }
            for target in [tcp.address, udp.address] {
                assert!(
                    !output.contains(&target.to_string()),
                    "默认日志包含目标端点"
                );
            }
            let private_key = fs::read_to_string(certificate.dir.path().join("key.pem")).unwrap();
            for line in private_key
                .lines()
                .filter(|line| !line.starts_with("-----"))
            {
                assert!(!output.contains(line), "运行日志泄漏私钥内容");
            }
        }
    }
}
