//! 7.1 配置生成及显式 ignored 入口：三家固定客户端 × 六单密钥/两 AES EIH 模式。
//! 普通测试不读取下载产物、不启动客户端；ignored 路径复用父模块核验与进程守卫。
//!
//! 字段依据固定源码，不沿用其他协议的 TLS/packet_encoding 默认值：
//! - Mihomo 3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8：
//!   adapter/outbound/shadowsocks.go、adapter/parser.go（smux.enabled）。
//!   go.mod 固定 sing-shadowsocks v0.2.13 / 028e27cf15b05d39a96ae78c5b21e6d7c3b4b740。
//! - sing-box c005f35300ce76427dc285481ec5695f5b179cd2：option/shadowsocks.go、
//!   option/types.go（空 network=TCP+UDP）、option/udp_over_tcp.go、
//!   protocol/shadowsocks/outbound.go；EIH 依据 sing-shadowsocks
//!   65740e0f0e3ea0d78beb9f3972ba42a75a6cd160 / shadowaead_2022/protocol.go。
//! - Xray a4a3dff5b20c2faae567b742c172c7b95e75c083：infra/conf/shadowsocks.go、
//!   infra/conf/transport_internet.go、proxy/shadowsocks_2022/{outbound,kdf}.go。

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use dubhe::{Config, Server, config::ShadowsocksMethod, telemetry::Stats};
use serde_json::{Value, json};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use super::{
    ClientProcess, DEADLINE, PASSWORD, ReferenceClient, WRONG_PASSWORD,
    common::{Echo, address, socks},
    positive_udp_targets, private_write, project, reference_client, relay_address, socks_config,
    tcp_denied,
};

pub(super) const CLIENTS: [&str; 3] = ["mihomo", "sing-box", "xray"];
const IDENTITY: u8 = 0x31;
const USERS: [u8; 2] = [0x42, 0x53];
const WRONG: u8 = 0x64;
const UNKNOWN: u8 = 0x75;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Mode {
    pub method: ShadowsocksMethod,
    pub eih: bool,
}

pub(super) const MODES: [Mode; 8] = [
    Mode {
        method: ShadowsocksMethod::Aes128Gcm,
        eih: false,
    },
    Mode {
        method: ShadowsocksMethod::Aes256Gcm,
        eih: false,
    },
    Mode {
        method: ShadowsocksMethod::Chacha20Poly1305,
        eih: false,
    },
    Mode {
        method: ShadowsocksMethod::Aead2022Aes128Gcm,
        eih: false,
    },
    Mode {
        method: ShadowsocksMethod::Aead2022Aes256Gcm,
        eih: false,
    },
    Mode {
        method: ShadowsocksMethod::Aead2022Chacha20Poly1305,
        eih: false,
    },
    Mode {
        method: ShadowsocksMethod::Aead2022Aes128Gcm,
        eih: true,
    },
    Mode {
        method: ShadowsocksMethod::Aead2022Aes256Gcm,
        eih: true,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scenario {
    Valid,
    SecondUser,
    WrongCredential,
    WrongIdentity,
    UnknownUser,
}

impl Scenario {
    pub fn name(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::SecondUser => "second-user",
            Self::WrongCredential => "wrong-password-or-psk",
            Self::WrongIdentity => "wrong-identity-psk",
            Self::UnknownUser => "unknown-user-psk",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Valid | Self::SecondUser)
    }
}

impl Mode {
    pub fn name(self) -> String {
        format!(
            "{}-{}",
            self.method.cipher(),
            if self.eih { "eih" } else { "single" }
        )
    }

    fn validate(self) -> Result<()> {
        ensure!(
            !self.eih || self.method.supports_users(),
            "该参考模式不支持 EIH"
        );
        Ok(())
    }

    pub fn scenarios(self) -> &'static [Scenario] {
        if self.eih {
            &[
                Scenario::Valid,
                Scenario::SecondUser,
                Scenario::WrongIdentity,
                Scenario::UnknownUser,
            ]
        } else {
            &[Scenario::Valid, Scenario::WrongCredential]
        }
    }

    fn psk(self, byte: u8) -> String {
        STANDARD.encode(vec![byte; self.method.cipher().key_len()])
    }

    // 不派生/截短/自动纠正负向 PSK；所有错误 2022 密钥仍保持合法标准 Base64/长度。
    pub fn credential(self, scenario: Scenario) -> Result<String> {
        self.validate()?;
        ensure!(
            self.scenarios().contains(&scenario),
            "场景与参考身份模式不匹配"
        );
        if self.eih {
            let identity = if scenario == Scenario::WrongIdentity {
                WRONG
            } else {
                IDENTITY
            };
            let user = match scenario {
                Scenario::SecondUser => USERS[1],
                Scenario::UnknownUser => UNKNOWN,
                _ => USERS[0],
            };
            Ok(format!("{}:{}", self.psk(identity), self.psk(user)))
        } else if self.method.is_2022() {
            Ok(self.psk(if scenario == Scenario::WrongCredential {
                WRONG
            } else {
                IDENTITY
            }))
        } else {
            Ok(if scenario == Scenario::WrongCredential {
                WRONG_PASSWORD
            } else {
                PASSWORD
            }
            .to_owned())
        }
    }

    pub fn server_config(self) -> Result<Value> {
        self.validate()?;
        let mut inbound = json!({
            "type":"shadowsocks", "tag":"ss", "listen":"127.0.0.1:0",
            "method":self.method, "password":if self.method.is_2022() { self.psk(IDENTITY) } else { PASSWORD.to_owned() }
        });
        if self.eih {
            inbound["users"] = json!([
                {"name":"alice", "password":self.psk(USERS[0])},
                {"name":"bob", "password":self.psk(USERS[1])}
            ]);
        }
        let mut config = socks_config();
        config["inbounds"] = json!([inbound]);
        config["limits"]["handshake_timeout_ms"] = json!(3000);
        config["limits"]["udp_idle_timeout_ms"] = json!(3000);
        config["limits"]["shutdown_timeout_ms"] = json!(300);
        // 纯静态校验，不绑定 socket，也不读取证书。
        Config::from_json(&config.to_string())?;
        Ok(config)
    }
}

pub(super) fn client_config(
    name: &str,
    mode: Mode,
    scenario: Scenario,
    listen: SocketAddr,
    server: SocketAddr,
) -> Result<Value> {
    ensure!(
        listen.ip() == Ipv4Addr::LOCALHOST
            && server.ip() == Ipv4Addr::LOCALHOST
            && listen.port() >= 1024
            && server.port() >= 1024
            && listen != server,
        "参考配置仅允许独立 IPv4 回环高端口"
    );
    let method = mode.method.cipher().to_string();
    let credential = mode.credential(scenario)?;
    Ok(match name {
        "mihomo" => json!({
            "socks-port":listen.port(), "bind-address":"127.0.0.1", "allow-lan":false,
            "mode":"rule", "log-level":"warning", "ipv6":false,
            "find-process-mode":"off", "geo-auto-update":false, "geodata-mode":false,
            "geox-url":{
                "geoip":"http://127.0.0.1:9/download-disabled",
                "geosite":"http://127.0.0.1:9/download-disabled",
                "mmdb":"http://127.0.0.1:9/download-disabled",
                "asn":"http://127.0.0.1:9/download-disabled"
            },
            "external-controller":"", "external-ui":"", "external-ui-url":"",
            "dns":{"enable":false}, "tun":{"enable":false},
            "sniffer":{"enable":false}, "ntp":{"enable":false},
            "profile":{"store-selected":false, "store-fake-ip":false},
            "proxies":[{
                "name":"kernel", "type":"ss", "server":"127.0.0.1", "port":server.port(),
                "cipher":method, "password":credential, "udp":true, "udp-over-tcp":false,
                "smux":{"enabled":false}
            }], "rules":["MATCH,kernel"]
        }),
        "sing-box" => json!({
            "log":{"level":"warn", "timestamp":false},
            "inbounds":[{"type":"socks", "tag":"local", "listen":"127.0.0.1", "listen_port":listen.port()}],
            "outbounds":[{
                "type":"shadowsocks", "tag":"kernel", "server":"127.0.0.1", "server_port":server.port(),
                "method":method, "password":credential,
                "network":["tcp", "udp"], "udp_over_tcp":false, "multiplex":{"enabled":false}
            }], "route":{"final":"kernel"}
        }),
        "xray" => json!({
            "log":{"loglevel":"warning", "access":"none"},
            "inbounds":[{"tag":"local", "listen":"127.0.0.1", "port":listen.port(),
                "protocol":"socks", "settings":{"auth":"noauth", "udp":true, "ip":"127.0.0.1"}}],
            "outbounds":[{
                "tag":"kernel", "protocol":"shadowsocks",
                "settings":{"address":"127.0.0.1", "port":server.port(), "method":method, "password":credential},
                // TCP streamSettings 不会把 Shadowsocks 原生 UDP 改成 UoT。
                "streamSettings":{"network":"tcp", "security":"none"},
                "mux":{"enabled":false}
            }]
        }),
        _ => bail!("未知参考客户端"),
    })
}

// SS 的保护期至少60秒，停机只能由 runtime 排空/force 处理，不能缩短会话TTL。
// 保持 handle 在守卫中跨 shutdown await，外层60秒取消时仍能 abort 而不 detach。
struct Running {
    address: SocketAddr,
    stats: Arc<Stats>,
    stop: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Running {
    async fn start(config: Value) -> Result<Self> {
        let server = Server::bind(Config::from_json(&config.to_string())?).await?;
        let address = server.local_addr("ss").context("SS 入口未准备")?;
        ensure!(address.ip().is_loopback(), "SS 服务端入口不是回环地址");
        let stats = server.stats();
        let stop = CancellationToken::new();
        let task = tokio::spawn(server.run(stop.clone()));
        Ok(Self {
            address,
            stats,
            stop,
            task,
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.stop.cancel();
        timeout(DEADLINE, &mut self.task)
            .await
            .context("SS 服务端未按期限停机")???;
        let stats = self.stats.snapshot();
        ensure!(
            stats.connections == 0 && stats.tcp_flows == 0 && stats.udp_associations == 0,
            "SS 停机后统计未归零"
        );
        let _tcp = super::PortReservation::bind(self.address).context("SS TCP 监听未释放")?;
        let _udp = super::UdpReservation::bind(self.address).context("SS UDP 监听未释放")?;
        Ok(())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

async fn positive_traffic(proxy: SocketAddr, server: &Running) -> Result<Value> {
    let target = Echo::tcp("127.0.0.1", false).await;
    let first = b"official-shadowsocks-first-payload\0\xff\x80";
    // 按标准SOCKS阶段先完成CONNECT再发送应用首载荷；不能把本地SOCKS
    // 请求流水线预读是否保留，混同于远端Shadowsocks首个应用载荷的完整性。
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    timeout(DEADLINE, stream.read_exact(&mut greeting))
        .await
        .context("SS 正向 SOCKS greeting 超时")??;
    ensure!(greeting == [5, 0], "SS 正向 SOCKS 入口不可用");
    let mut request = vec![5, 1, 0];
    request.extend(address(target.address));
    stream.write_all(&request).await?;
    let mut header = [0; 4];
    timeout(DEADLINE, stream.read_exact(&mut header))
        .await
        .with_context(|| {
            format!(
                "SS 正向 SOCKS CONNECT 超时，内核统计 {:?}",
                server.stats.snapshot()
            )
        })??;
    ensure!(header[..3] == [5, 0, 0], "SS 正向 SOCKS CONNECT 被拒绝");
    let length = match header[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => bail!("SS 正向 SOCKS 回复地址无效"),
    };
    let mut bound = vec![0; length + 2];
    timeout(DEADLINE, stream.read_exact(&mut bound))
        .await
        .context("SS 正向 SOCKS BND 超时")??;
    stream.write_all(first).await?;
    let mut reply = vec![0; first.len()];
    timeout(DEADLINE, stream.read_exact(&mut reply))
        .await
        .with_context(|| {
            format!(
                "SS 正向 TCP 首载荷回显超时，内核统计 {:?}",
                server.stats.snapshot()
            )
        })??;
    ensure!(reply == first, "SS TCP 首载荷改变");
    drop(stream);

    let first_udp = Echo::udp("127.0.0.1").await;
    let second_udp = Echo::udp("127.0.0.1").await;
    let mut result = positive_udp_targets(proxy, &first_udp, &second_udp, 1).await?;
    let stats = server.stats.snapshot();
    ensure!(
        stats.uplink > 0 && stats.downlink > 0,
        "SS 正向未计量到真实转发载荷"
    );
    result["tcp"] = json!("passed");
    result["tcp_first_binary_payload"] = json!(true);
    result["server_stats"] = json!(stats);
    Ok(result)
}

async fn negative_traffic(proxy: SocketAddr, server: &Running) -> Result<Value> {
    let tcp_target = TcpListener::bind("127.0.0.1:0").await?;
    let before = server.stats.snapshot().rejected;
    tcp_denied(proxy, tcp_target.local_addr()?).await?;
    timeout(DEADLINE, async {
        while server.stats.snapshot().rejected <= before {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("SS TCP 未观察到内核 rejected，不能仅凭客户端关闭判断负向通过")?;
    ensure!(
        timeout(Duration::from_millis(150), tcp_target.accept())
            .await
            .is_err(),
        "SS 错误身份仍连接到 TCP 目标"
    );
    let udp_target = UdpSocket::bind("127.0.0.1:0").await?;
    let local = UdpSocket::bind("127.0.0.1:0").await?;
    let (control, relay) = socks(3, address("0.0.0.0:0".parse()?), proxy).await;
    let relay = relay_address(relay)?;
    let before = server.stats.snapshot().dropped;
    let mut packet = vec![0, 0, 0];
    packet.extend(address(udp_target.local_addr()?));
    packet.extend_from_slice(b"negative-ss-udp\0\xff");
    local.send_to(&packet, relay).await?;
    timeout(DEADLINE, async {
        while server.stats.snapshot().dropped <= before {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("SS UDP 未观察到内核 dropped，不能仅凭客户端超时判断负向通过")?;
    let mut target_buffer = [0; 256];
    let mut client_buffer = [0; 256];
    ensure!(
        timeout(Duration::from_millis(300), async {
            tokio::select! {
                result = udp_target.recv_from(&mut target_buffer) => result,
                result = local.recv_from(&mut client_buffer) => result,
            }
        })
        .await
        .is_err(),
        "SS 错误身份产生 UDP 目标流量或客户端回包"
    );
    drop(control);
    let stats = server.stats.snapshot();
    ensure!(
        stats.uplink == 0 && stats.downlink == 0,
        "SS 负向产生明文业务计量"
    );
    Ok(
        json!({"tcp_rejected":true, "udp_dropped":true, "target_untouched":true, "server_stats":stats}),
    )
}

async fn run_scenarios(client: &ReferenceClient, mode: Mode, artifacts: &Path) -> Result<Value> {
    let mut results = serde_json::Map::new();
    for &scenario in mode.scenarios() {
        let directory = artifacts.join(scenario.name());
        fs::create_dir(&directory)?;
        let config = mode.server_config()?;
        private_write(
            &directory.join("server.json"),
            &serde_json::to_vec_pretty(&config)?,
        )?;
        let mut server = Running::start(config).await?;
        let mut process =
            ClientProcess::start_shadowsocks(client, mode, scenario, &directory, server.address)
                .await?;
        let traffic = if scenario.accepted() {
            positive_traffic(process.address, &server).await
        } else {
            negative_traffic(process.address, &server).await
        };
        // 即使流量断言失败也显式停止进程并等待内核停机；更早错误仍由 Drop 回收。
        let alive = process.assert_running();
        let stopped = process.stop();
        let shutdown = server.shutdown().await;
        let result = traffic.and_then(|value| {
            alive?;
            stopped?;
            shutdown?;
            Ok(value)
        });
        let report = match &result {
            Ok(value) => json!({"status":"passed", "scenario":scenario.name(), "traffic":value}),
            Err(error) => {
                json!({"status":"failed", "scenario":scenario.name(), "error":format!("{error:#}")})
            }
        };
        private_write(
            &directory.join("result.json"),
            &serde_json::to_vec_pretty(&report)?,
        )?;
        results.insert(
            scenario.name().to_owned(),
            result.with_context(|| {
                format!(
                    "{} {} {}；日志 {}",
                    client.name,
                    mode.name(),
                    scenario.name(),
                    directory.display()
                )
            })?,
        );
    }
    Ok(Value::Object(results))
}

pub(super) async fn real_interop(name: &str, mode: Mode) -> Result<()> {
    // 唯一外部入口先经过既有版本/平台/官方摘要/普通文件/SHA256门禁。
    let client = reference_client(name)?;
    let root = project().join(".test-artifacts");
    fs::create_dir_all(&root)?;
    let artifacts = tempfile::Builder::new()
        .prefix(&format!("interop-{name}-shadowsocks-{}-", mode.name()))
        .tempdir_in(&root)?
        .keep();
    eprintln!(
        "{} {} artifacts: {}",
        client.name,
        mode.name(),
        artifacts.display()
    );
    let result = timeout(
        Duration::from_secs(60),
        run_scenarios(&client, mode, &artifacts),
    )
    .await
    .context("SS 官方客户端互通超过60秒")
    .and_then(|result| result);
    let mut report = json!({
        "client":name, "version":client.version, "platform":client.platform,
        "client_sha256":client.sha256, "upstream_checksum_verified":client.upstream_checksum_verified,
        "protocol":"shadowsocks", "method":mode.method, "mode":mode.name(),
        "udp_transport":"native", "tls":"not_applicable"
    });
    match &result {
        Ok(scenarios) => {
            report["status"] = json!("passed");
            report["scenarios"] = scenarios.clone();
        }
        Err(error) => {
            report["status"] = json!("failed");
            report["error"] = json!(format!("{error:#}"));
        }
    }
    private_write(
        &artifacts.join("result.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    result.map(|_| ())
}
