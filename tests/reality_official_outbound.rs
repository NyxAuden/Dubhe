//! 本内核 REALITY **出站** → 官方 Xray REALITY **服务端** 的真实互通。
//!
//! 其余 REALITY 出站测试（`tests/reality_outbound.rs`）是内核连内核，
//! 双方的实现错误会互相抵消。本文件改用官方 Xray v26.10.31 作为服务端，
//! 验证 `src/tls/reality_client.rs` 的客户端实现真的能对上上游。
//!
//! `#[ignore]`：需要已下载并校验官方二进制（`.test-artifacts/reference-clients.json`）。

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
/// 由 `xray x25519` 生成；`xray x25519 -i "<私钥>"` 可确定性复现公钥。
const REALITY_PRIVATE: &str = "aAz6xlX1zFLJbdvh_eO-eL5Ap2ez06m5iPh1ZamRGVM";
const REALITY_PUBLIC: &str = "WgEqf-ahV6J6uGy6Uy8fMPH3uMhmQ8JFw9vkwpKypEQ";
const SHORT_ID: &str = "8172635445362718";
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
    let path = manifest["clients"]
        .as_array()
        .and_then(|clients| {
            clients
                .iter()
                .find(|client| client["name"] == "xray")
                .and_then(|client| client["path"].as_str())
        })
        .context("manifest 里没有 xray")?;
    Ok(PathBuf::from(path))
}

/// 用给定配置启动官方 Xray；进程在 `Drop` 时终止。
struct Xray {
    child: Child,
    log: PathBuf,
}

impl Xray {
    fn start(binary: &Path, config: &Value, directory: &Path, name: &str) -> Result<Self> {
        let config_path = directory.join(format!("{name}.json"));
        let log = directory.join(format!("{name}.log"));
        fs::write(&config_path, serde_json::to_vec_pretty(config)?)?;
        let output = fs::File::create(&log)?;
        let child = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()
            .with_context(|| format!("启动 Xray {name} 失败"))?;
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

/// 等待端口可连接，最多 `WAIT`。
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

/// 取一个端口交给 Xray 子进程监听。
///
/// 不使用 `bind(0)` 的返回值：Linux 临时端口范围（32768–60999）会被
/// 并发测试的 TCP 连接当作源端口占用，造成「释放后再绑定」的 `AddrInUse`。
/// 这里在范围之外顺序探测，并由调用方保证进程内不重复。
fn pick_port() -> SocketAddr {
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(20000);
    // 本文件独占 25000–27499 段。`reserve_port` 的 HashSet 只能在**当前测试二进制**
    // 内去重，cargo 并行跑多个测试二进制时互相看不见；此前四个文件共用
    // 20000–29999，实测出现过 `入口 X 绑定失败: AddrInUse`。
    for _ in 25000u16..27500 {
        let port = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            return SocketAddr::from(([127, 0, 0, 1], port));
        }
    }
    panic!("没有可用测试端口");
}

fn reality_server(target: SocketAddr, port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "reality-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": UUID}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "target": format!("{}:{}", target.ip(), target.port()),
                    "xver": 0,
                    "serverNames": ["localhost"],
                    "privateKey": REALITY_PRIVATE,
                    "shortIds": [SHORT_ID]
                }
            }
        }],
        "outbounds": [{
            "protocol": "freedom",
            "tag": "direct",
            // Xray 的 freedom 对 vless 入站默认屏蔽私有地址
            // （`defaultBlockPrivateRule`）。本机回环测试必须显式放行，
            // 否则会出现「REALITY 认证成功但数据为零」的假象。
            "settings": {
                "domainStrategy": "AsIs",
                "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]
            }
        }]
    })
}

/// 一个真实 TLS 1.3 站点，充当 REALITY 的 target。
fn tls_site(certificate: &Path, key: &Path, port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "tls-site",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": "11111111-1111-1111-1111-111111111111"}],
                "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"certificates": [{
                    "certificateFile": certificate.display().to_string(),
                    "keyFile": key.display().to_string()
                }]}
            }
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    })
}

/// 本内核的出站配置：SOCKS 入口 + VLESS/REALITY 出站。
fn dubhe_client(upstream: SocketAddr) -> Value {
    json!({
        "version": 1,
        "inbounds": [{"type": "socks5", "tag": "local", "listen": "127.0.0.1:0"}],
        "outbounds": [{
            "type": "vless",
            "tag": "up",
            "endpoint": upstream.to_string(),
            "uuid": UUID,
            "reality": {
                "public_key": REALITY_PUBLIC,
                "short_id": SHORT_ID,
                "server_name": "localhost"
            }
        }],
        "route": {"default": "up"}
    })
}

async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut greeting).await?;
    ensure!(greeting == [5, 0], "SOCKS 入口不可用");

    let mut request = vec![5, 1, 0, 1];
    request.extend(match target.ip() {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => bail!("本测试只用 IPv4：{ip}"),
    });
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0; 10];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply).await?;
    ensure!(reply[0] == 5, "无效 SOCKS 回复");
    ensure!(reply[1] == 0, "SOCKS 拒绝：code={}", reply[1]);
    Ok(stream)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn dubhe_reality_outbound_reaches_official_xray_server() -> Result<()> {
    let binary = xray_binary()?;
    let certificate = common::Certificate::new();
    let directory = tempfile::tempdir()?;
    let root = directory.path();

    let site_port = pick_port().port();
    let reality_port = pick_port().port();
    let site_address: SocketAddr = format!("127.0.0.1:{site_port}").parse()?;
    let reality_address: SocketAddr = format!("127.0.0.1:{reality_port}").parse()?;

    let mut site = Xray::start(
        &binary,
        &tls_site(
            &certificate.dir.path().join("cert.pem"),
            &certificate.dir.path().join("key.pem"),
            site_port,
        ),
        root,
        "tls-site",
    )?;
    wait_listening(site_address).await?;
    site.assert_running()?;

    let mut server = Xray::start(
        &binary,
        &reality_server(site_address, reality_port),
        root,
        "reality-server",
    )?;
    wait_listening(reality_address).await?;
    server.assert_running()?;

    // 本内核作为客户端：走 REALITY 出站访问官方 Xray 服务端。
    let client = common::Running::start(dubhe_client(reality_address)).await;
    let echo = Echo::tcp("127.0.0.1", false).await;

    let mut stream = socks_connect(client.address, echo.address).await?;
    let payload = b"dubhe-reality-outbound\0\xff";
    stream.write_all(payload).await?;
    let mut echoed = vec![0; payload.len()];
    timeout(
        Duration::from_secs(10),
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed),
    )
    .await
    .context("官方 Xray REALITY 服务端未回显")??;
    ensure!(echoed == payload, "回显内容不一致");
    drop(stream);

    server.assert_running()?;
    site.assert_running()?;
    client.shutdown().await;
    Ok(())
}
