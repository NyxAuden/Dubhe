//! `GET /status` 的真实进程回归：四条应用路径必须能被区分。
//!
//! 这些用例走真实二进制 + `/bin/kill -HUP`，因为状态句柄的传递链是
//! `main → 新 Server → 新 admin`；只测 handler 会漏掉句柄丢失。

mod common;

use std::{fs, net::SocketAddr, path::PathBuf, process::Child, time::Duration};

use common::*;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

const TOKEN: &str = "0123456789abcdef";
fn binary() -> std::path::PathBuf {
    std::env::var_os("DUBHE_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_dubhe").into())
}
const WAIT: Duration = Duration::from_secs(20);

/// 独立端口段：`tests/cli.rs` 独占 20000–22499，这里用 24000–25999。
///
/// 不同测试二进制之间无法共享去重集，只能靠互不重叠的区间避免 AddrInUse。
fn reserve_port() -> u16 {
    use std::sync::{Mutex, OnceLock};
    static ISSUED: OnceLock<Mutex<std::collections::HashSet<u16>>> = OnceLock::new();
    let issued = ISSUED.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    for port in 24000u16..26000 {
        if issued.lock().unwrap().contains(&port) {
            continue;
        }
        let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        drop(listener);
        if issued.lock().unwrap().insert(port) {
            return port;
        }
    }
    panic!("没有可用测试端口");
}

fn deployment_id(seed: u8) -> String {
    format!("{seed:02x}").repeat(16)
}

/// 真实 CLI 进程 + 可远程读取的 stderr 日志目录。
struct Cli {
    child: Child,
    _directory: tempfile::TempDir,
    config: PathBuf,
    stderr: PathBuf,
}

impl Cli {
    fn spawn(configuration: &Value) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.json");
        fs::write(&config, configuration.to_string()).unwrap();
        let stderr = directory.path().join("stderr.log");
        let stdout = directory.path().join("stdout.log");
        let child = std::process::Command::new(binary())
            .args(["run", "-c", config.to_str().unwrap()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(
                fs::File::create(&stdout).unwrap(),
            ))
            .stderr(std::process::Stdio::from(
                fs::File::create(&stderr).unwrap(),
            ))
            .spawn()
            .unwrap();
        Self {
            child,
            _directory: directory,
            config,
            stderr,
        }
    }

    fn write_config(&self, configuration: &Value) {
        // 与生产部署一致：同目录临时文件 + rename，避免读到半份 JSON。
        let temporary = self.config.with_extension("tmp");
        fs::write(&temporary, configuration.to_string()).unwrap();
        fs::rename(&temporary, &self.config).unwrap();
    }

    fn hangup(&self) {
        let status = std::process::Command::new("/bin/kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    async fn wait_ready(&mut self, port: u16) {
        timeout(WAIT, async {
            loop {
                if self.log().contains("\"event\":\"ready\"") {
                    return;
                }
                assert!(self.alive(), "进程提前退出：{}", self.log());
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        // ready 之后再确认端口真的可连，避免把「打过日志」当成「已监听」。
        timeout(WAIT, async {
            loop {
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    /// 轮询到基线之后的新 attempt 且已进入终态。
    async fn wait_apply(&mut self, api: u16, after: u64) -> Value {
        timeout(WAIT, async {
            loop {
                if let Some(status) = status(api).await
                    && status["last_apply"]["attempt"].as_u64().unwrap_or(0) > after
                    && status["last_apply"]["result"] != "pending"
                {
                    return status;
                }
                assert!(self.alive(), "进程提前退出：{}", self.log());
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn fetch(api: u16, request: &str) -> (String, String) {
    try_fetch(api, request).await.unwrap_or_default()
}

/// 重绑期间管理口会短暂不可达（旧实例已停、新实例尚未 ready）。
/// 返回 `None` 而不是 panic，轮询据此继续等待。
async fn try_fetch(api: u16, request: &str) -> Option<(String, String)> {
    let api = SocketAddr::from(([127, 0, 0, 1], api));
    let mut stream = TcpStream::connect(api).await.ok()?;
    if stream.write_all(request.as_bytes()).await.is_err() {
        return None;
    }
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .ok()?
        .ok()?;
    let response = String::from_utf8(response).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    Some((head.to_owned(), body.to_owned()))
}

async fn status(api: u16) -> Option<Value> {
    let (head, body) = fetch(
        api,
        &format!(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        ),
    )
    .await;
    if !head.starts_with("HTTP/1.1 200") {
        return None;
    }
    serde_json::from_str(&body).ok()
}

fn config(proxy: u16, api: u16, id: Option<&str>) -> Value {
    let mut value = socks_config();
    value["inbounds"][0]["listen"] = json!(format!("127.0.0.1:{proxy}"));
    value["api"] = json!({"listen": format!("127.0.0.1:{api}"), "token": TOKEN});
    if let Some(id) = id {
        value["deployment_id"] = json!(id);
    }
    value
}

/// 热替换：改默认路由，不换监听。
#[tokio::test]
async fn hot_apply_reports_same_instance_and_new_revision() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x01))));
    cli.wait_ready(proxy).await;

    let baseline = status(api).await.expect("状态可读");
    assert_eq!(baseline["active_revision"], 1, "{baseline}");
    assert_eq!(baseline["last_apply"], Value::Null, "{baseline}");

    let mut next = config(proxy, api, Some(&deployment_id(0x02)));
    next["route"]["default"] = json!("reject");
    cli.write_config(&next);
    cli.hangup();

    let applied = cli.wait_apply(api, 0).await;
    assert_eq!(applied["last_apply"]["mode"], "hot", "{applied}");
    assert_eq!(applied["last_apply"]["result"], "applied", "{applied}");
    assert_eq!(applied["active_revision"], 2, "{applied}");
    assert_eq!(
        applied["instance_id"], baseline["instance_id"],
        "热替换不换进程"
    );
    assert_eq!(
        applied["active_deployment_id"],
        deployment_id(0x02),
        "必须回显本次提交的标签"
    );

    // 业务结果：新连接被拒，而不是只看状态码。
    assert_eq!(connect_status(proxy, echo.address).await, 2);
    cli.terminate().await;
}

/// 需要重建：监听端口变化。
#[tokio::test]
async fn rebind_apply_reports_same_instance_and_new_revision() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x03))));
    cli.wait_ready(proxy).await;
    let baseline = status(api).await.expect("状态可读");

    let next_proxy = reserve_port();
    let next = config(next_proxy, api, Some(&deployment_id(0x04)));
    cli.write_config(&next);
    cli.hangup();

    let applied = cli.wait_apply(api, 0).await;
    assert_eq!(applied["last_apply"]["mode"], "rebind", "{applied}");
    assert_eq!(applied["last_apply"]["result"], "applied", "{applied}");
    assert_eq!(applied["active_revision"], 2, "{applied}");
    assert_eq!(
        applied["instance_id"], baseline["instance_id"],
        "重建后必须复用同一状态句柄"
    );
    assert_eq!(
        applied["active_deployment_id"],
        deployment_id(0x04),
        "重建后生效的必须是候选标签"
    );

    // 新端口可用，旧端口不再接受连接。
    assert_eq!(connect_status(next_proxy, echo.address).await, 0);
    assert!(
        TcpStream::connect(("127.0.0.1", proxy)).await.is_err()
            || connect_status(proxy, echo.address).await != 0,
        "旧监听必须已释放"
    );
    cli.terminate().await;
}

/// 校验拒绝：损坏 JSON 与静态校验失败都不推进版本。
#[tokio::test]
async fn rejected_candidates_keep_previous_revision() {
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x05))));
    cli.wait_ready(proxy).await;
    let baseline = status(api).await.expect("状态可读");
    assert_eq!(baseline["active_deployment_id"], deployment_id(0x05));

    // 1) 文件不可读/JSON 损坏：不猜标签。
    fs::write(&cli.config, b"{ not json").unwrap();
    cli.hangup();
    let broken = cli.wait_apply(api, 0).await;
    assert_eq!(broken["last_apply"]["result"], "rejected", "{broken}");
    assert_eq!(broken["last_apply"]["mode"], "validate", "{broken}");
    assert_eq!(
        broken["last_apply"]["error_code"], "config_invalid",
        "{broken}"
    );
    assert_eq!(
        broken["last_apply"]["requested_deployment_id"],
        Value::Null,
        "坏 JSON 不得给出候选标签: {broken}"
    );
    assert_eq!(broken["active_revision"], 1, "{broken}");

    // 2) 合法 JSON、反序列化成功，但运行前校验失败（证书文件不存在）。
    //    与 1) 的区别：这里 `requested_deployment_id` 必须有值，说明内核确实
    //    「读到了你提交的那一版」并在校验阶段拒绝。
    let mut invalid = config(proxy, api, Some(&deployment_id(0x06)));
    invalid["inbounds"][0] = json!({
        "type": "vless",
        "tag": "socks",
        "listen": format!("127.0.0.1:{proxy}"),
        "users": [{"name": "u", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
        "certificate": "/nonexistent/cert.pem",
        "private_key": "/nonexistent/key.pem"
    });
    cli.write_config(&invalid);
    cli.hangup();
    let rejected = cli.wait_apply(api, 1).await;
    assert_eq!(rejected["last_apply"]["result"], "rejected", "{rejected}");
    assert_eq!(rejected["last_apply"]["mode"], "validate", "{rejected}");
    assert_eq!(
        rejected["last_apply"]["error_code"], "config_invalid",
        "{rejected}"
    );
    assert_eq!(rejected["active_revision"], 1, "{rejected}");
    assert_eq!(
        rejected["last_apply"]["requested_deployment_id"],
        deployment_id(0x06),
        "解析成功的候选应带上自己的标签"
    );
    // 旧业务仍然可用。
    let echo = Echo::tcp("127.0.0.1", false).await;
    assert_eq!(connect_status(proxy, echo.address).await, 0);
    cli.terminate().await;
}

/// 新配置绑定失败、旧配置恢复：必须报 `rolled_back`，不是成功。
#[tokio::test]
async fn bind_failure_reports_rolled_back_and_keeps_old_revision() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x07))));
    cli.wait_ready(proxy).await;
    let baseline = status(api).await.expect("状态可读");

    // 始终占住一个端口，让候选配置无法绑定。
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = occupied.local_addr().unwrap().port();
    let next = config(taken, api, Some(&deployment_id(0x08)));
    cli.write_config(&next);
    cli.hangup();

    let rolled_back = cli.wait_apply(api, 0).await;
    assert_eq!(rolled_back["last_apply"]["mode"], "rebind", "{rolled_back}");
    assert_eq!(
        rolled_back["last_apply"]["result"], "rolled_back",
        "{rolled_back}"
    );
    assert_eq!(
        rolled_back["last_apply"]["error_code"], "candidate_bind_failed",
        "{rolled_back}"
    );
    assert_eq!(
        rolled_back["instance_id"], baseline["instance_id"],
        "回退后仍是同一进程"
    );
    assert_eq!(rolled_back["active_revision"], 1, "回退不得推进版本");
    assert_eq!(
        rolled_back["active_deployment_id"],
        deployment_id(0x07),
        "回退后生效的仍是旧标签"
    );
    // 旧配置确实重新服务，且能真实回显（不只是握手成功）。
    let (mut tunnel, _) = timeout(
        Duration::from_secs(5),
        common::socks(
            1,
            address(echo.address),
            SocketAddr::from(([127, 0, 0, 1], proxy)),
        ),
    )
    .await
    .expect("回退后 SOCKS 建连超时");
    tunnel.write_all(b"after-rollback").await.unwrap();
    let mut echoed = [0u8; 14];
    tunnel.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"after-rollback");
    drop(occupied);
    cli.terminate().await;
}

/// 只换标签：接受新标签，但不做重绑定。
#[tokio::test]
async fn metadata_only_change_is_applied_without_rebind() {
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x09))));
    cli.wait_ready(proxy).await;

    cli.write_config(&config(proxy, api, Some(&deployment_id(0x0a))));
    cli.hangup();
    let applied = cli.wait_apply(api, 0).await;
    assert_eq!(applied["last_apply"]["mode"], "metadata", "{applied}");
    assert_eq!(applied["last_apply"]["result"], "applied", "{applied}");
    assert_eq!(applied["active_revision"], 2, "{applied}");
    assert_eq!(applied["active_deployment_id"], deployment_id(0x0a));
    cli.terminate().await;
}

/// 复用当前标签却改业务内容：拒绝，避免一个标签指向两份配置。
#[tokio::test]
async fn reused_deployment_id_is_rejected() {
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x0b))));
    cli.wait_ready(proxy).await;

    let mut reuse = config(proxy, api, Some(&deployment_id(0x0b)));
    reuse["route"]["default"] = json!("reject");
    cli.write_config(&reuse);
    cli.hangup();
    let rejected = cli.wait_apply(api, 0).await;
    assert_eq!(rejected["last_apply"]["result"], "rejected", "{rejected}");
    assert_eq!(
        rejected["last_apply"]["error_code"], "deployment_id_reused",
        "{rejected}"
    );
    assert_eq!(rejected["active_revision"], 1, "{rejected}");
    cli.terminate().await;
}

/// 鉴权、方法与脱敏。
#[tokio::test]
async fn status_requires_bearer_and_rejects_writes() {
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x0c))));
    cli.wait_ready(proxy).await;

    let (head, body) = fetch(api, "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    assert!(body.is_empty(), "未授权不得泄露任何状态");

    let (head, _) = fetch(
        api,
        "POST /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer 0123456789abcdef\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 405"), "{head}");
    assert!(head.contains("Allow: GET"), "{head}");

    let (head, body) = fetch(
        api,
        &format!(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("Cache-Control: no-store"), "{head}");
    // 白名单：只允许契约字段，不得出现配置内容或路径。
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let keys: Vec<&str> = parsed
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for key in &keys {
        assert!(
            [
                "api_version",
                "instance_id",
                "active_revision",
                "active_deployment_id",
                "last_apply"
            ]
            .contains(key),
            "响应包含契约外字段 {key}: {body}"
        );
    }
    assert!(!body.contains("token"), "{body}");
    cli.terminate().await;
}

async fn connect_status(proxy: u16, echo: SocketAddr) -> u8 {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.unwrap();
    let mut request = vec![5, 1, 0];
    request.extend(address(echo));
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    reply[1]
}

/// 嵌入式库实例没有重载协调器：`/status` 必须明确不可用，
/// 不能编一个「永远第 1 代」的假版本号。
#[tokio::test]
async fn library_instance_reports_status_unavailable() {
    use dubhe::{Config, Server};

    let proxy = reserve_port();
    let api = reserve_port();
    let mut value = socks_config();
    value["inbounds"][0]["listen"] = json!(format!("127.0.0.1:{proxy}"));
    value["api"] = json!({"listen": format!("127.0.0.1:{api}"), "token": TOKEN});
    let config = Config::from_json(&value.to_string()).unwrap();
    let server = Server::bind(config).await.unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.run(stop.clone()));

    timeout(WAIT, async {
        while TcpStream::connect(("127.0.0.1", api)).await.is_err() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let (head, body) = fetch(
        api,
        &format!(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert!(
        body.contains("apply_status_unavailable"),
        "必须给出稳定错误码: {body}"
    );
    stop.cancel();
    let _ = timeout(WAIT, task).await;
}

/// 正常证书续期不能推进配置代数，也不能清空部署标签。
///
/// 真实运维最常见的一次 HUP 就是这个：配置没变、只是换了证书。若它被算作
/// 一代，面板会看到 `active_deployment_id` 变成 `null`，误以为部署身份丢失。
#[tokio::test]
async fn tls_rotation_keeps_revision_and_deployment_id() {
    let certificate = Certificate::new();
    let proxy = reserve_port();
    let api = reserve_port();
    let mut inbound = certificate.inbound();
    inbound["listen"] = json!(format!("127.0.0.1:{proxy}"));
    let mut value = config(proxy, api, Some(&deployment_id(0x0d)));
    value["inbounds"] = json!([inbound]);
    let mut cli = Cli::spawn(&value);
    cli.wait_ready(proxy).await;
    let baseline = status(api).await.expect("状态可读");
    assert_eq!(baseline["active_deployment_id"], deployment_id(0x0d));

    let rotated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    fs::write(certificate.dir.path().join("cert.pem"), rotated.cert.pem()).unwrap();
    let key = certificate.dir.path().join("key.pem");
    fs::write(&key, rotated.key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    cli.hangup();

    let rotated_status = cli.wait_apply(api, 0).await;
    assert_eq!(
        rotated_status["last_apply"]["mode"], "tls",
        "{rotated_status}"
    );
    assert_eq!(
        rotated_status["last_apply"]["result"], "applied",
        "{rotated_status}"
    );
    assert_eq!(
        rotated_status["active_revision"], 1,
        "证书轮换不是一代: {rotated_status}"
    );
    assert_eq!(
        rotated_status["active_deployment_id"],
        deployment_id(0x0d),
        "轮换不得清空部署标签: {rotated_status}"
    );
    assert_eq!(rotated_status["instance_id"], baseline["instance_id"]);
    cli.terminate().await;
}

/// 重建之后立刻再来一次 HUP，第二次尝试不能改变第一次已经提交的结果。
///
/// **边界**：这条用例只断言不变量，不断言重绑一定成功——端口竞争时重绑可能
/// 回退成 `rolled_back`，那是合法结果。真正要保证的是：第二次尝试若为
/// `rejected`，`active_*` 必须与第一次终态完全一致，说明它是在第一次提交
/// **之后**才被处理的。竞态窗口本身由协调器的 ready 屏障保证，底层不变量由
/// `apply::tests::stale_attempt_cannot_overwrite_newer_record` 覆盖。
#[tokio::test]
async fn second_hangup_after_rebind_does_not_lose_the_applied_revision() {
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x0e))));
    cli.wait_ready(proxy).await;

    let next_proxy = reserve_port();
    cli.write_config(&config(next_proxy, api, Some(&deployment_id(0x0f))));
    cli.hangup();
    // 等第一次尝试进入终态。
    let first = cli.wait_apply(api, 0).await;

    // 再发一次，候选无效：它只能被拒，不能动第一次的结果。
    cli.write_config(&json!({"version": 1, "inbounds": []}));
    cli.hangup();
    let second = cli.wait_apply(api, 1).await;

    assert_eq!(second["last_apply"]["attempt"], 2, "{second}");
    assert_eq!(second["last_apply"]["result"], "rejected", "{second}");
    assert_eq!(
        second["active_revision"], first["active_revision"],
        "第二次尝试不得改变已提交的代数: {first} -> {second}"
    );
    assert_eq!(
        second["active_deployment_id"], first["active_deployment_id"],
        "第二次尝试不得改变已提交的版本: {first} -> {second}"
    );
    assert_eq!(second["instance_id"], first["instance_id"]);
    cli.terminate().await;
}

/// 重绑等待 ready 的屏障不能吞掉退出信号。
///
/// 之前的实现里，屏障内的 `interrupt`/`terminate` 分支是空块再 `continue`，
/// 会跳过统一的取消与排空；一次 SIGTERM 不足以让进程退出。
#[tokio::test]
async fn sigterm_during_rebind_exits_on_first_signal() {
    let echo = Echo::tcp("127.0.0.1", false).await;
    let proxy = reserve_port();
    let api = reserve_port();
    let mut cli = Cli::spawn(&config(proxy, api, Some(&deployment_id(0x10))));
    cli.wait_ready(proxy).await;

    // 保持一条活连接，让旧实例的排空确实花时间，从而稳定落在屏障内。
    let (mut live, _) = common::socks(
        1,
        address(echo.address),
        SocketAddr::from(([127, 0, 0, 1], proxy)),
    )
    .await;
    live.write_all(b"hold").await.unwrap();
    let mut echoed = [0u8; 4];
    live.read_exact(&mut echoed).await.unwrap();

    let next_proxy = reserve_port();
    cli.write_config(&config(next_proxy, api, Some(&deployment_id(0x11))));
    cli.hangup();
    // 立刻发一次 TERM：此时重绑正在进行，可能停在等待 ready 的分支。
    let status = std::process::Command::new("/bin/kill")
        .args(["-TERM", &cli.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let code = timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = cli.child.try_wait().unwrap() {
                return status;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("一次 SIGTERM 必须让进程退出，不能被重绑屏障吞掉");
    assert!(code.success(), "退出码应为 0：{code:?}");
    drop(live);
}
