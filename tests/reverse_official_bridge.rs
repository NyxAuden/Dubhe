//! 官方 Xray 作为反向 Bridge 主动拨入本内核 Portal 的真实互通。
//!
//! 本机闭环（`tests/reverse_bridge.rs`）是内核连内核，双方的命令 4 实现
//! 错误会互相抵消。本文件改用官方 Xray v26.10.31 作为 Bridge，验证
//! `users[].reverse.tag` 与命令 4 的 Portal 侧实现真的对得上上游。
//!
//! `#[ignore]`：需要已下载并校验官方二进制。

mod common;

use anyhow::{Context, Result, bail, ensure};
use common::Echo;
use serde_json::{Value, json};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const WAIT: Duration = Duration::from_secs(10);

fn project() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn xray_binary() -> Result<PathBuf> {
    let manifest_path = project().join(".test-artifacts/reference-clients.json");
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).with_context(|| {
            format!(
                "缺少客户端 manifest: {}；先运行 tools/fetch_reference_clients.py",
                manifest_path.display()
            )
        })?)?;
    manifest["clients"]
        .as_array()
        .and_then(|clients| {
            clients
                .iter()
                .find(|client| client["name"] == "xray")
                .and_then(|client| client["path"].as_str())
        })
        .map(PathBuf::from)
        .context("manifest 里没有 xray")
}

struct Xray {
    child: Child,
    log: PathBuf,
}

impl Xray {
    fn start(binary: &Path, config: &Value, directory: &Path) -> Result<Self> {
        let config_path = directory.join("xray-bridge.json");
        let log = directory.join("xray-bridge.log");
        fs::write(&config_path, serde_json::to_vec_pretty(config)?)?;
        let output = fs::File::create(&log)?;
        let child = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()
            .context("启动 Xray 失败")?;
        Ok(Self { child, log })
    }

    fn assert_running(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            bail!(
                "Xray 提前退出（{status}）：{}",
                fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
        Ok(())
    }
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 取一个测试专用端口。
///
/// 与 tests/nw3.rs、tests/cli.rs 同样的做法：走临时端口范围（32768–60999）
/// 之外，并做进程内去重——否则同一测试里两次调用会拿到同一个端口。
fn pick_port() -> SocketAddr {
    static ISSUED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    let issued = ISSUED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    // 本文件独占 27500–29999 段。`reserve_port` 的 HashSet 只能在**当前测试二进制**
    // 内去重，cargo 并行跑多个测试二进制时互相看不见；此前四个文件共用
    // 20000–29999，实测出现过 `入口 X 绑定失败: AddrInUse`。
    for port in 27500u16..30000 {
        if issued.lock().unwrap().contains(&port) {
            continue;
        }
        if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            if issued.lock().unwrap().insert(port) {
                return SocketAddr::from(([127, 0, 0, 1], port));
            }
        }
    }
    panic!("没有可用测试端口");
}

/// Portal：VLESS + TLS 入站，用户在 `users[].reverse.tag` 里声明归属。
///
/// **默认路由故意指向 `direct`，且不给 `v1.rvs.cool` 配任何规则**：
/// 归属必须来自 Xray 写法的 `reverse.tag`，而不是域名匹配。
fn portal_config(certificate: &common::Certificate, listen: SocketAddr) -> Value {
    json!({
        "version": 1,
        "inbounds": [
            {
                "type": "vless",
                "tag": "portal-in",
                "listen": listen.to_string(),
                "users": [{"name": "u", "uuid": UUID, "reverse": {"tag": "portal"}}],
                "certificate": certificate.dir.path().join("cert.pem"),
                "private_key": certificate.dir.path().join("key.pem")
            },
            {"type": "socks5", "tag": "users", "listen": "127.0.0.1:0"}
        ],
        "outbounds": [
            {"type": "reverse", "tag": "portal", "domain": "v1.rvs.cool"},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {"default": "direct"},
        "limits": {"shutdown_timeout_ms": 100, "handshake_timeout_ms": 5000}
    })
}

/// 官方 Xray 作为 Bridge：出站带 `settings.reverse.tag` 主动拨入 Portal。
fn xray_bridge(portal: SocketAddr, certificate: &common::Certificate, socks: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "local",
            "listen": "127.0.0.1",
            "port": socks,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": true}
        }],
        "outbounds": [
            {
                "tag": "portal-link",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": portal.port(),
                    "id": UUID,
                    "encryption": "none",
                    "reverse": {"tag": "reverse-in"}
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "allowInsecure": false,
                        "certificates": [{
                            "usage": "verify",
                            "certificateFile": certificate.dir.path().join("cert.pem")
                                .to_string_lossy()
                        }]
                    }
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                // Xray 对 vless 入站默认屏蔽私有地址，本机回环必须放行。
                "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}
            }
        ]
    })
}

async fn wait_listening(address: SocketAddr) -> Result<()> {
    timeout(WAIT, async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("服务端未在期限内监听")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn official_xray_bridge_reaches_dubhe_portal() -> Result<()> {
    let binary = xray_binary()?;
    let certificate = common::Certificate::new();
    // 用固定目录而非 tempdir：失败后配置与日志要能被检查。
    let directory = project().join(".test-artifacts/interop-reverse-bridge");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory)?;

    let portal_address = pick_port();
    let socks_port = pick_port().port();

    let portal = common::Running::start(portal_config(&certificate, portal_address)).await;
    wait_listening(portal_address).await?;

    let mut bridge = Xray::start(
        &binary,
        &xray_bridge(portal_address, &certificate, socks_port),
        &directory,
    )?;
    // 不探测 Xray 的 SOCKS 端口：探测会建立一条空连接，可能干扰它的状态。
    // 改为直接重试业务流程。
    bridge.assert_running()?;

    // 命令 4 的隧道是异步注册的，给 Bridge 拨入留出时间。
    tokio::time::sleep(Duration::from_millis(800)).await;

    let echo = Echo::tcp("127.0.0.1", false).await;
    let proxy = SocketAddr::from(([127, 0, 0, 1], socks_port));

    // 多次请求，确认隧道稳定而不是偶发成功。
    for trial in 0..3u8 {
        // Xray 启动与命令 4 注册都是异步的：这里轮询到 SOCKS 可用为止。
        let mut stream = timeout(WAIT, async {
            loop {
                if let Ok(mut stream) = TcpStream::connect(proxy).await
                    && stream.write_all(&[5, 1, 0]).await.is_ok()
                {
                    let mut greeting = [0; 2];
                    if tokio::io::AsyncReadExt::read_exact(&mut stream, &mut greeting)
                        .await
                        .is_ok()
                        && greeting == [5, 0]
                    {
                        return stream;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("SOCKS 入口始终不可用")?;

        let mut request = vec![5, 1, 0, 1];
        request.extend(match echo.address.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(_) => bail!("本测试只用 IPv4"),
        });
        request.extend(echo.address.port().to_be_bytes());
        stream.write_all(&request).await?;

        let mut reply = [0; 10];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply).await?;
        ensure!(reply[1] == 0, "SOCKS 拒绝：code={}", reply[1]);

        let payload = [trial; 512];
        stream.write_all(&payload).await?;
        let mut echoed = vec![0; payload.len()];
        timeout(
            WAIT,
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed),
        )
        .await
        .with_context(|| format!("第 {trial} 次请求未回显"))??;
        ensure!(echoed == payload, "第 {trial} 次回显内容不一致");
        drop(stream);
    }

    bridge.assert_running()?;
    drop(bridge);
    portal.shutdown().await;
    Ok(())
}
