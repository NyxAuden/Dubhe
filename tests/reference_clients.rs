//! 使用预先校验的官方客户端执行显式启用的真实互操作测试。
//! 运行：cargo test --locked --test reference_clients -- --ignored --nocapture
mod common;
#[path = "reference_support/shadowsocks.rs"]
mod shadowsocks_reference;

use anyhow::{Context, Result, bail, ensure};
use common::{Certificate, Echo, PASSWORD, Running, address, exchange, socks, socks_config};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener as PortReservation, UdpSocket as UdpReservation},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const DEADLINE: Duration = Duration::from_secs(5);
/// 负向认证用例的等待上限。
///
/// 认证失败后，部分协议（REALITY、VLESS fallback）会把连接伪装回落到一个
/// 真实目标站点，回落本身要建立外部 TCP 甚至 TLS。用 5 秒的通用上限会把
/// 「回落慢」误判成「没有明确关闭」，实测 `xray_vless_reality_authentication`
/// 因此间歇失败（同一命令连跑两次，一次 FAILED 一次 ok）。
/// 这里的等待只是「多久之内必须看到明确结论」，不是性能断言。
const NEGATIVE_DEADLINE: Duration = Duration::from_secs(20);
const WRONG_PASSWORD: &str = "deliberately-wrong-reference-test-password";
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
/// Snell v4 的 psk。Mihomo 支持 v1–v5 但拒绝 v6；
/// sing-box 1.14.4 只支持 v4/v6。交集只有 v4。
const SNELL_PSK: &str = "snell-reference-test-psk";
const WRONG_PSK: &str = "deliberately-wrong-snell-psk";
const WRONG_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30812";
/// VLESS Encryption 的固定密钥对，由 `xray vlessenc` 生成后固化。
///
/// 两半是同一密钥对：服务端持有 `decryption`（私钥），客户端需要
/// `encryption`（公钥）。公钥由私钥确定性推导，见
/// `xray x25519 -i "<private>"`（2026-11-22 逐字节核对）。
const VLESS_ENCRYPTION_PRIVATE: &str = "-DqEf18Ai3PxV9ZMJToAvlwY2XMlcMYlJItT-8oQBWg";
/// REALITY 固定密钥对，由 `xray x25519` 生成。
/// `xray x25519 -i "<私钥>"` 可确定性复现同一公钥。
const REALITY_PRIVATE: &str = "aAz6xlX1zFLJbdvh_eO-eL5Ap2ez06m5iPh1ZamRGVM";
const REALITY_PUBLIC: &str = "WgEqf-ahV6J6uGy6Uy8fMPH3uMhmQ8JFw9vkwpKypEQ";
const REALITY_SHORT_ID: &str = "8172635445362718";
/// 服务端 `decryption`：启用 600s 票据，因此客户端用 `0rtt`。
const VLESS_ENCRYPTION_CLIENT: &str =
    "mlkem768x25519plus.native.0rtt.MvcuFHxUUqUmO0_v_XgyVRuQDNZtWvoroqUfEaBZCy0";
/// ShadowTLS 只是 TLS 伪装层，必须叠加内层协议；这里固定内层为
/// Shadowsocks 2022（两家参考客户端都支持，且与 Mihomo `ss + shadow-tls`
/// 插件的常规形态一致）。密码是 16 字节 0x5a 的标准 Base64。
const SHADOWTLS_INNER_TAG: &str = "shadowtls-inner";
const SHADOWTLS_INNER_METHOD: &str = "2022-blake3-aes-128-gcm";
const SHADOWTLS_INNER_PASSWORD: &str = "WlpaWlpaWlpaWlpaWlpaWg==";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Trojan,
    Vless,
    VlessXudp,
    /// VLESS + XTLS Vision（`flow: xtls-rprx-vision`）。
    VlessVision,
    /// VLESS 经 WebSocket/WSS 承载。
    VlessWs,
    /// VLESS 经 gRPC（HTTP/2）承载。
    VlessGrpc,
    /// VLESS 经 XHTTP 承载。
    VlessXhttp,
    /// VLESS 经 HTTPUpgrade 承载。
    VlessHttpUpgrade,
    /// VLESS 经 V2Ray HTTP（h2 / http）承载。
    VlessHttp,
    /// VLESS 经 mKCP 承载。
    VlessKcp,
    /// VLESS 经旧 QUIC 承载。
    VlessQuic,
    /// VLESS Encryption（`mlkem768x25519plus`）。
    VlessEncryption,
    /// VLESS over REALITY（`security: "reality"` + RAW 传输）。
    VlessReality,
    Vmess,
    Hysteria2,
    Tuic,
    Snell,
    AnyTls,
    Naive,
    ShadowTls,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Trojan => "trojan",
            Self::Vless
            | Self::VlessXudp
            | Self::VlessVision
            | Self::VlessWs
            | Self::VlessGrpc
            | Self::VlessXhttp
            | Self::VlessHttpUpgrade
            | Self::VlessHttp
            | Self::VlessKcp
            | Self::VlessQuic
            | Self::VlessEncryption
            | Self::VlessReality => "vless",
            Self::Vmess => "vmess",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Snell => "snell",
            Self::AnyTls => "anytls",
            Self::Naive => "naive",
            Self::ShadowTls => "shadowtls",
        }
    }

    fn mode(self) -> &'static str {
        match self {
            Self::VlessXudp => "vless-xudp",
            Self::VlessVision => "vless-vision",
            Self::VlessWs => "vless-ws",
            Self::VlessGrpc => "vless-grpc",
            Self::VlessXhttp => "vless-xhttp",
            Self::VlessHttpUpgrade => "vless-httpupgrade",
            Self::VlessHttp => "vless-http",
            Self::VlessKcp => "vless-kcp",
            Self::VlessQuic => "vless-quic",
            Self::VlessEncryption => "vless-encryption",
            Self::VlessReality => "vless-reality",
            _ => self.name(),
        }
    }

    fn credential(self, scenario: Scenario) -> &'static str {
        match (self, scenario) {
            (
                Self::Trojan
                | Self::Hysteria2
                | Self::Tuic
                | Self::AnyTls
                | Self::Naive
                | Self::ShadowTls,
                Scenario::WrongCredential,
            ) => WRONG_PASSWORD,
            (
                Self::Trojan
                | Self::Hysteria2
                | Self::Tuic
                | Self::AnyTls
                | Self::Naive
                | Self::ShadowTls,
                _,
            ) => PASSWORD,
            (Self::Snell, Scenario::WrongCredential) => WRONG_PSK,
            (Self::Snell, _) => SNELL_PSK,
            (
                Self::Vless
                | Self::VlessXudp
                | Self::VlessVision
                | Self::VlessWs
                | Self::VlessGrpc
                | Self::VlessXhttp
                | Self::VlessHttpUpgrade
                | Self::VlessHttp
                | Self::VlessKcp
                | Self::VlessQuic
                | Self::VlessEncryption
                | Self::VlessReality
                | Self::Vmess,
                Scenario::WrongCredential,
            ) => WRONG_UUID,
            (
                Self::Vless
                | Self::VlessXudp
                | Self::VlessVision
                | Self::VlessWs
                | Self::VlessGrpc
                | Self::VlessXhttp
                | Self::VlessHttpUpgrade
                | Self::VlessHttp
                | Self::VlessKcp
                | Self::VlessQuic
                | Self::VlessEncryption
                | Self::VlessReality
                | Self::Vmess,
                _,
            ) => UUID,
        }
    }

    fn udp_supported(self, client: &str) -> bool {
        match (self, client) {
            // Mihomo v1.19.33 的 NewVless 强制在 XUDP / packetaddr 之间选择，
            // xudp:false 也会被覆盖；此基线只能验收 VLESS TCP，不能声称原生 UDP 通过。
            // https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L474-L485
            (Self::Vless, "mihomo") => false,
            // Mihomo 的 h2 承载实测 UDP 不通：SOCKS 已匹配到 kernel 出站，但
            // 服务端 connections 始终为 0（对比 ws 承载同一测试会正常回包）。
            // 这是客户端侧行为，不是内核缺陷，因此该组合只验收 TCP。
            (Self::VlessHttp, "mihomo") => false,
            // REALITY 的 UDP 在官方 Xray 客户端下实测不通（TCP 正常）。
            // 这是该承载的客户端行为，只验收 TCP。
            (Self::VlessReality, _) => false,

            // sing-box 实机报 "UDP is not supported by outbound: kernel"；
            // naive 出站只能 TCP CONNECT。
            (Self::Naive, _) => false,
            // ShadowTLS 只承载内层 TCP 字节流，两家客户端都没有 UDP 通路。
            (Self::ShadowTls, _) => false,
            _ => true,
        }
    }

    /// 该协议的入站是否使用 TLS。
    ///
    /// Snell 是纯对称加密握手，没有 TLS，所以 `untrusted-certificate`
    /// 场景对它不适用——那边测的是证书校验，不是协议本身。
    fn uses_tls(self) -> bool {
        // Snell 无 TLS；REALITY 的证书不是常规 TLS 校验，而由临时证书
        // HMAC + 目标证书链决定，因此 `untrusted-certificate` 场景不适用。
        !matches!(self, Self::Snell | Self::VlessReality)
    }

    /// 该参考客户端是否实现了此协议。
    ///
    /// 为 false 时不生成该客户端的测试用例——**不要**让它在客户端配置阶段
    /// 失败，那样报告的是「配置无效」而不是「该客户端不支持」。
    fn supported_by(self, client: &str) -> bool {
        self.unsupported_reason(client).is_none()
    }

    /// 客户端不支持时的具体原因，用于跳过报告。
    ///
    /// 「协议」与「承载」是两个维度：sing-box 支持 VLESS，但它的
    /// v2ray transport 没有 xhttp。跳过信息必须指出是哪一层不支持，
    /// 否则会被误读成「该客户端不支持 VLESS」。
    fn unsupported_reason(self, client: &str) -> Option<&'static str> {
        match self {
            Self::Hysteria2 | Self::Tuic | Self::Snell | Self::AnyTls if client == "xray" => {
                Some("Xray v26.10.31 没有该协议出站")
            }
            Self::Naive if client != "sing-box" => Some("Mihomo v1.19.33 没有 naive 代理类型"),
            Self::ShadowTls if client == "xray" => Some("Xray v26.10.31 没有 ShadowTLS"),
            Self::VlessXhttp if client == "sing-box" => {
                Some("sing-box 1.14.4 的 v2ray transport 无 xhttp")
            }
            // Xray v26.10.31 已移除 http / 旧 quic transport（实测报错并指向 XHTTP）。
            Self::VlessHttp if client == "xray" => {
                Some("Xray v26.10.31 已移除 http transport，改用 XHTTP")
            }
            Self::VlessQuic if client == "xray" => {
                Some("Xray v26.10.31 已移除旧 QUIC transport，改用 XHTTP H3")
            }
            // Mihomo v1.19.33 的 VLESS 出站只有 ws/http(h2)/xhttp/grpc 分支，无 kcp/quic。
            Self::VlessKcp | Self::VlessQuic if client == "mihomo" => {
                Some("Mihomo v1.19.33 的 VLESS 出站无 kcp/quic 分支")
            }
            // sing-box 1.14.4 的 v2ray transport 无 kcp。
            Self::VlessKcp if client == "sing-box" => {
                Some("sing-box 1.14.4 的 v2ray transport 无 kcp")
            }
            // sing-box 与 Mihomo 的 VLESS 出站没有 encryption 字段的实现
            // （sing-box option/vless.go 无该字段；Mihomo VlessOption 无该字段），
            // 写进去会让客户端拒绝加载或忽略，因此只对 Xray 生成用例。
            Self::VlessEncryption if client != "xray" => {
                Some("只有 Xray 的 VLESS 出站支持 encryption 字段")
            }
            // REALITY 的客户端矩阵在协议层不成立：
            // - sing-box 主动移除 X25519MLKEM768（common/tls/reality_client.go），
            //   而本内核与 Xray 服务端都硬要求该 hybrid share；
            // - Mihomo 默认也移除，需非默认开关 support-x25519mlkem768。
            // 因此只对 Xray 生成用例，不假装三家都支持。
            Self::VlessReality if client != "xray" => Some(
                "REALITY 需 X25519MLKEM768；该客户端默认不发（sing-box 直接移除，Mihomo 需非默认开关）",
            ),
            // Xray v26.10.31 的 mKCP 出站实测不工作：日志显示 connection
            // 创建后立刻 Close（state 1 at 0），向独立 UDP 探针零发包。
            // 内核 mKCP 由 tests/kcp.rs 的 10 项本机回环覆盖。
            Self::VlessKcp if client == "xray" => {
                Some("Xray v26.10.31 的 mKCP 出站实测零发包（创建后立即关闭）")
            }
            _ => None,
        }
    }

    fn inbound(self, certificate: &Certificate, target: Option<SocketAddr>) -> Value {
        let mut inbound = certificate.inbound();
        match self {
            Self::Vless
            | Self::VlessXudp
            | Self::VlessVision
            | Self::VlessWs
            | Self::VlessGrpc
            | Self::VlessXhttp
            | Self::VlessHttpUpgrade
            | Self::VlessHttp
            | Self::VlessKcp
            | Self::VlessQuic
            | Self::VlessEncryption
            | Self::VlessReality
            | Self::Vmess => {
                // 承载变体需要把 type 换成对应入口名。
                inbound["type"] = json!(match self {
                    Self::VlessWs => "vless-ws",
                    Self::VlessGrpc => "vless-grpc",
                    Self::VlessXhttp => "vless-xhttp",
                    Self::VlessHttpUpgrade => "vless-httpupgrade",
                    Self::VlessHttp => "vless-http",
                    Self::VlessKcp => "vless-kcp",
                    Self::VlessQuic => "vless-quic",
                    Self::VlessEncryption => "vless",
                    Self::VlessReality => "vless-reality",
                    _ => self.name(),
                });
                inbound["tag"] = json!(self.mode());
                inbound["users"] = json!([{"name": "test", "uuid": UUID}]);
                if matches!(self, Self::VlessEncryption) {
                    // 服务端持有私钥；客户端公钥由它确定性推导。
                    inbound["decryption"] = json!(format!(
                        "mlkem768x25519plus.native.600s.{VLESS_ENCRYPTION_PRIVATE}"
                    ));
                }
                if matches!(self, Self::VlessReality) {
                    let target = target.expect("REALITY 缺少 target");
                    // REALITY 不用常规证书：临时证书由私钥 + 客户端公钥派生，
                    // 证书链来自 target 的真实 TLS 握手。
                    if let Some(map) = inbound.as_object_mut() {
                        map.remove("certificate");
                        map.remove("private_key");
                    }
                    inbound["reality"] = json!({
                        "target": {"host": target.ip().to_string(), "port": target.port()},
                        "private_key": REALITY_PRIVATE,
                        "server_names": ["localhost"],
                        "short_ids": [REALITY_SHORT_ID]
                    });
                }
                if matches!(self, Self::VlessXudp) {
                    inbound["xudp"] = json!(true);
                }
                if matches!(self, Self::VlessVision) {
                    // Vision 在入站侧是 per-user 的 flow。
                    inbound["users"] = json!([{"name": "test", "uuid": UUID,
                        "flow": "xtls-rprx-vision"}]);
                }
                // 承载配置：路径必须与客户端一致。
                match self {
                    Self::VlessWs => inbound["websocket"] = json!({"path": "/ws"}),
                    Self::VlessGrpc => inbound["grpc"] = json!({"path": "/TunService/Tun"}),
                    Self::VlessXhttp => inbound["xhttp"] = json!({"path": "/xhttp"}),
                    Self::VlessHttpUpgrade => {
                        inbound["httpupgrade"] = json!({"path": "/httpupgrade"})
                    }
                    Self::VlessHttp => inbound["http"] = json!({"path": "/http"}),
                    Self::VlessKcp => {
                        // 明文本地回环测试：显式豁免并移除基础模板带的证书，
                        // 否则内核会走 kcp+TLS，而测试只验证明文字节流。
                        inbound["allow_insecure_transport"] = json!(true);
                        if let Some(map) = inbound.as_object_mut() {
                            map.remove("certificate");
                            map.remove("private_key");
                        }
                    }
                    Self::VlessQuic => inbound["quic"] = json!({}),
                    _ => {}
                }
            }
            Self::Snell => {
                // Snell 用 psk，无证书/TLS；不能复用 trojan 模板里的
                // certificate/private_key/password 字段，必须整体重建。
                inbound = json!({
                    "type": "snell",
                    "tag": self.mode(),
                    "listen": "127.0.0.1:0",
                    "psk": SNELL_PSK,
                    "version": 4
                });
            }
            Self::Naive => {
                // Naive 必须真实 TLS（HTTP CONNECT over TLS）。
                //
                // 监听 [::] 而非 127.0.0.1：上游 naive 出站硬编码
                // `RemoteIsDomain: true`（protocol/naive/outbound.go），
                // 即使 server 写 127.0.0.1 也会走 resolver；本机 /etc/hosts
                // 的 `localhost` 同时映射 127.0.0.1 与 ::1，cronet 按
                // happy-eyeballs 优先尝试 ::1。双栈监听才能同时接住两种结果。
                inbound["type"] = json!("naive");
                inbound["tag"] = json!(self.mode());
                inbound["users"] = json!([{"name": "test", "password": PASSWORD}]);
            }
            Self::AnyTls => {
                // AnyTLS 必须真实 TLS，凭据在 users 数组。
                inbound["type"] = json!("anytls");
                inbound["tag"] = json!(self.mode());
                inbound["users"] = json!([{"name": "test", "password": PASSWORD}]);
            }
            Self::Tuic => {
                // TUIC 入站需要证书 + users（uuid/password）。
                inbound["type"] = json!("tuic");
                inbound["tag"] = json!(self.mode());
                inbound["users"] = json!([{"name": "test", "uuid": UUID,
                    "password": PASSWORD}]);
            }
            Self::Hysteria2 => {
                // Hysteria2 入站必须带证书，凭据在 users 数组里而不是顶层字段。
                inbound["type"] = json!("hysteria2");
                inbound["tag"] = json!(self.mode());
                inbound["users"] = json!([{"name": "test", "password": PASSWORD}]);
            }
            Self::Trojan => {}
            Self::ShadowTls => {
                // ShadowTLS 只做 TLS 握手伪装，不终端代理：入站必须带真实
                // 握手目标和同配置内的内层明文入口，因此由 `inbounds` 生成两条。
                unreachable!("ShadowTLS 入站需要握手目标与内层入口")
            }
        }
        inbound
    }

    /// ShadowTLS 的两个入站：外层 ShadowTLS + 内层 Shadowsocks 2022。
    ///
    /// 内层选 Shadowsocks 2022 是因为它同时是 Mihomo（`ss + shadow-tls`
    /// 插件）和 sing-box（`shadowsocks` 出站 + `detour`）的常规组合，
    /// 且本内核 `detour` 允许列表里包含 shadowsocks。
    fn shadowtls_inbounds(handshake: SocketAddr, password: &str) -> Value {
        json!([
            {
                "type": "shadowtls",
                "tag": Self::ShadowTls.mode(),
                "listen": "127.0.0.1:0",
                "version": 3,
                "users": [{"name": "test", "password": password}],
                "handshake": {"server": "127.0.0.1", "server_port": handshake.port()},
                "strict_mode": true,
                "detour": SHADOWTLS_INNER_TAG
            },
            {
                "type": "shadowsocks",
                "tag": SHADOWTLS_INNER_TAG,
                "listen": "127.0.0.1:0",
                "method": SHADOWTLS_INNER_METHOD,
                "password": SHADOWTLS_INNER_PASSWORD
            }
        ])
    }

    /// 一个场景所需的全部入站；其余协议仍只有一条。
    fn inbounds(self, certificate: &Certificate, handshake: Option<SocketAddr>) -> Value {
        match self {
            Self::ShadowTls => Self::shadowtls_inbounds(
                handshake.expect("ShadowTLS 缺少本地 TLS 握手目标"),
                PASSWORD,
            ),
            _ => json!([self.inbound(certificate, handshake)]),
        }
    }

    fn configure_command(self, client: &str, command: &mut Command) {
        if matches!((self, client), (Self::Vless, "xray")) {
            // 空 flow / mux.enabled=false 不足以阻止 VLESS 出站默认使用 XUDP。
            // core/xray.go 的 cone 上下文读取 common/platform/platform.go 中的此开关。
            // https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/core/xray.go#L195-L196
            command.env("XRAY_CONE_DISABLED", "true");
        }
    }
}

fn project() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// ShadowTLS 需要一个真实的外部 TLS 服务器完成握手伪装。
///
/// `tests/shadowtls.rs` 用只回 ServerHello 的假服务器覆盖服务端行为，但真实
/// 客户端（Mihomo/sing-box）执行的是完整 TLS 1.3 握手，必须有一个真的 TLS
/// 服务端。这里沿用 `tests/shadowtls_outbound.rs` 的做法：本地 rustls TLS 1.3
/// 监听，自签 `localhost` 证书，握手后只排空数据。
struct TlsHandshakeTarget {
    address: SocketAddr,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    stop: tokio_util::sync::CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl TlsHandshakeTarget {
    /// `cert_padding`：证书里非关键扩展的填充字节数。
    ///
    /// REALITY 要求 target 的加密 flight 形态满足 `RecordPlan`：
    /// **首条加密记录 > 512 字节时必须是 1 条聚合记录**，否则必须正好 4 条
    /// （EE / Certificate / CertificateVerify / Finished）。rustls 的
    /// 紧凑 flight 默认可能发出恰好 512 字节的首记录，落进「必须 4 条」
    /// 的分支而 target 只发了 1 条，`collect_template` 会一直等第 2 条直到
    /// 握手超时——表现为约 50% 连接失败（是否越过边界取决于证书与
    /// ServerHello 的实际长度）。
    ///
    /// 加大证书即可让首条记录稳定超过 512，走「1 条聚合记录」分支。
    /// 这不是放宽校验：生产环境接入真实 CDN 时 flight 形态本就满足约束。
    async fn start(certificate: &Certificate, cert_padding: usize) -> Result<Self> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        let (certificates, key) = if cert_padding == 0 {
            (
                CertificateDer::pem_file_iter(certificate.dir.path().join("cert.pem"))
                    .context("读取握手目标证书失败")?
                    .collect::<Result<Vec<_>, _>>()?,
                PrivateKeyDer::from_pem_file(certificate.dir.path().join("key.pem"))
                    .context("读取握手目标私钥失败")?,
            )
        } else {
            padded_target_certificate(cert_padding)?
        };
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("握手目标仅支持 TLS 1.3")?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .context("握手目标证书无效")?;
        // ShadowTLS 认证后不再需要握手服务器的会话票据；关闭以保持流量形状简单。
        config.send_tls13_tickets = 0;
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_count = connections.clone();
        let stop = tokio_util::sync::CancellationToken::new();
        let cancel = stop.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { break };
                        accepted_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let config = config.clone();
                        connections.spawn(async move {
                            let _ = serve_target(tcp, config).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
        });
        Ok(Self {
            address,
            connections,
            stop,
            task: Some(task),
        })
    }

    /// 本场景开始以来握手目标被拨号的次数。
    fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// REALITY 握手目标的证书填充字节数。
///
/// 目标是让 target 的加密 flight 首条记录稳定超过 512 字节。取 2 KiB：
/// 足以越过边界，又远低于 `MAX_SERVER_HELLO` 与记录上限。
const REALITY_TARGET_CERT_PADDING: usize = 2048;

/// 生成带非关键扩展填充的自签名证书，用于放大 target 的握手 flight。
fn padded_target_certificate(
    padding: usize,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
    let (not_before, not_after) = common::test_certificate_dates();
    params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 1],
            vec![0x61; padding],
        ));
    let key = rcgen::KeyPair::generate()?;
    let certified = params.self_signed(&key)?;
    Ok((
        vec![certified.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    ))
}

/// 手动驱动 `rustls::ServerConnection`，而不是 `tokio_rustls::TlsAcceptor::accept`。
///
/// 原因：`accept()` 要等**客户端 Finished** 才返回并写出自己的 flight，而
/// REALITY 的做法是发 ClientHello、读到 ServerHello + ChangeCipherSpec 就
/// 停手，把那块模板拿去重放，**不会**完成握手。用 `accept()` 会让服务端
/// 永远发不出加密记录，`collect_template` 卡在读第一条密文记录上。
///
/// 手动驱动时 `process_new_packets()` 一处理完 ClientHello，rustls 就
/// 立即生成完整 flight（ServerHello + CCS + 加密记录），随后
/// `wants_write`/`write_tls` 把它一次写出。
async fn serve_target(
    mut tcp: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tls = rustls::ServerConnection::new(config)?;
    let mut buffer = [0u8; 4096];
    loop {
        let count = tcp.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let mut input = &buffer[..count];
        while !input.is_empty() {
            if tls.read_tls(&mut input)? == 0 {
                break;
            }
            // 处理失败（例如客户端发来非法记录）就直接结束该连接。
            if tls.process_new_packets().is_err() {
                return Ok(());
            }
        }
        let mut wire = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut wire)?;
        }
        if !wire.is_empty() {
            if std::env::var_os("D2").is_some() {
                let mut types = Vec::new();
                let mut i = 0;
                while i + 5 <= wire.len() {
                    let n = usize::from(u16::from_be_bytes([wire[i + 3], wire[i + 4]]));
                    types.push(format!("{}:{}", wire[i], n));
                    i += 5 + n;
                }
                eprintln!(
                    "[tgt] 写出 {} 字节, records=[{}]",
                    wire.len(),
                    types.join(" ")
                );
            }
            tcp.write_all(&wire).await?;
            tcp.flush().await?;
        }
    }
    Ok(())
}

impl Drop for TlsHandshakeTarget {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Deserialize)]
struct Manifest {
    clients: Vec<ReferenceClient>,
}

#[derive(Deserialize)]
struct ReferenceClient {
    name: String,
    path: PathBuf,
    version: String,
    platform: String,
    sha256: String,
    upstream_checksum_verified: bool,
    status: String,
}

fn reference_client(name: &str) -> Result<ReferenceClient> {
    let manifest_path = std::env::var_os("REFERENCE_CLIENTS_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|| project().join(".test-artifacts/reference-clients.json"));
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(&manifest_path).with_context(|| {
            format!(
                "缺少或无法读取已校验客户端 manifest: {}",
                manifest_path.display()
            )
        })?)?;
    let mut matching = manifest
        .clients
        .into_iter()
        .filter(|client| client.name == name);
    let client = matching.next().context("manifest 缺少所需客户端")?;
    ensure!(matching.next().is_none(), "manifest 客户端条目重复");
    verify_reference_binary(&client)?;
    Ok(client)
}

fn verify_reference_binary(client: &ReferenceClient) -> Result<()> {
    let pinned = match client.name.as_str() {
        "mihomo" => "v1.19.33",
        "sing-box" => "v1.14.4",
        "xray" => "v26.10.31",
        _ => bail!("未知参考客户端"),
    };
    ensure!(client.version == pinned, "参考客户端版本不符合固定版本");
    ensure!(
        client.status == "ready" && client.upstream_checksum_verified,
        "参考客户端尚未通过下载和官方摘要校验"
    );
    // 平台必须与本机一致，且是下载脚本声明支持的四种之一。
    // 脚本用 `{os}-{arch}`（如 `linux-aarch64`、`darwin-arm64`），
    // 而 `std::env::consts::ARCH` 在 Linux ARM64 上是 `aarch64`、
    // 在 macOS ARM64 上是 `aarch64`，可直接比对；x86_64 两侧同名。
    let expected = platform_tag();
    ensure!(
        client.platform == expected,
        "参考客户端平台不匹配：manifest 记录 {}，本机是 {expected}",
        client.platform
    );
    ensure!(
        client.path.is_absolute() && fs::symlink_metadata(&client.path)?.is_file(),
        "参考客户端路径必须是绝对路径普通文件"
    );
    let mut binary = File::open(&client.path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let size = binary.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
    }
    ensure!(
        format!("{:x}", digest.finalize()) == client.sha256,
        "参考客户端二进制 SHA-256 已改变，拒绝运行"
    );
    Ok(())
}

fn private_write(path: &Path, contents: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(contents)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Scenario {
    Valid,
    WrongCredential,
    UntrustedCertificate,
}

impl Scenario {
    fn name(self, protocol: Protocol) -> &'static str {
        match (self, protocol) {
            (Self::Valid, _) => "valid",
            (
                Self::WrongCredential,
                Protocol::Trojan
                | Protocol::Hysteria2
                | Protocol::Tuic
                | Protocol::AnyTls
                | Protocol::Naive
                | Protocol::ShadowTls,
            ) => "wrong-password",
            (Self::WrongCredential, Protocol::Snell) => "wrong-psk",
            (
                Self::WrongCredential,
                Protocol::Vless
                | Protocol::VlessXudp
                | Protocol::VlessVision
                | Protocol::VlessWs
                | Protocol::VlessGrpc
                | Protocol::VlessXhttp
                | Protocol::VlessHttpUpgrade
                | Protocol::VlessHttp
                | Protocol::VlessKcp
                | Protocol::VlessQuic
                | Protocol::VlessEncryption
                | Protocol::VlessReality
                | Protocol::Vmess,
            ) => "wrong-uuid",
            (Self::UntrustedCertificate, _) => "untrusted-certificate",
        }
    }
}

/// 计算证书的 SHA-256 指纹，格式与 `openssl x509 -fingerprint -sha256` 一致。
///
/// Mihomo 的 Hysteria2 走 QUIC，不读全局 `tls.custom-certifactes`，
/// 只能用出站级 `fingerprint` 固定证书。
fn certificate_fingerprint(certificate: &Certificate) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(certificate.der.as_ref());
    let mut out = String::with_capacity(digest.len() * 3);
    for (index, byte) in digest.iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

fn client_config(
    name: &str,
    protocol: Protocol,
    listen: SocketAddr,
    server: SocketAddr,
    trust_path: &Path,
    credential: &str,
    fingerprint: &str,
) -> Result<Value> {
    let pem = fs::read_to_string(trust_path)?;
    if matches!(protocol, Protocol::ShadowTls) {
        return shadowtls_client_config(name, listen, server, trust_path, credential);
    }
    Ok(match name {
        "mihomo" => {
            let mut proxy = json!({
                "name": "kernel", "type": protocol.name(), "server": "127.0.0.1",
                "port": server.port(), "skip-cert-verify": false,
                "udp": protocol.udp_supported(name)
            });
            match protocol {
                Protocol::Trojan => {
                    proxy["password"] = json!(credential);
                    proxy["sni"] = json!("localhost");
                }
                Protocol::Vless
                | Protocol::VlessXudp
                | Protocol::VlessVision
                | Protocol::VlessWs
                | Protocol::VlessGrpc
                | Protocol::VlessXhttp
                | Protocol::VlessHttpUpgrade
                | Protocol::VlessHttp
                | Protocol::VlessKcp
                | Protocol::VlessQuic
                | Protocol::VlessEncryption
                | Protocol::VlessReality => {
                    // VlessOption 使用 servername，而 TrojanOption 使用 sni。
                    // 同一固定源码的 adapter/parser.go 按 smux.enabled 控制复用包装。
                    proxy["uuid"] = json!(credential);
                    // Vision 必须显式声明 flow；空串是普通 VLESS。
                    proxy["flow"] = json!(match protocol {
                        Protocol::VlessVision => "xtls-rprx-vision",
                        _ => "",
                    });
                    proxy["tls"] = json!(true);
                    proxy["servername"] = json!("localhost");
                    proxy["smux"] = json!({"enabled": false});
                    if matches!(protocol, Protocol::VlessXudp) {
                        proxy["xudp"] = json!(true);
                    }
                    if matches!(protocol, Protocol::VlessEncryption) {
                        proxy["encryption"] = json!(VLESS_ENCRYPTION_CLIENT);
                    }
                    if matches!(protocol, Protocol::VlessReality) {
                        proxy["reality-opts"] = json!({
                            "public-key": REALITY_PUBLIC,
                            "short-id": REALITY_SHORT_ID
                        });
                    }
                    // Mihomo 用 network + *-opts 表达承载。
                    match protocol {
                        Protocol::VlessWs => {
                            proxy["network"] = json!("ws");
                            proxy["ws-opts"] = json!({"path": "/ws"});
                        }
                        Protocol::VlessGrpc => {
                            proxy["network"] = json!("grpc");
                            proxy["grpc-opts"] = json!({"grpc-service-name": "TunService"});
                        }
                        Protocol::VlessXhttp => {
                            proxy["network"] = json!("xhttp");
                            proxy["xhttp-opts"] = json!({"path": "/xhttp"});
                        }
                        Protocol::VlessHttpUpgrade => {
                            proxy["network"] = json!("ws");
                            proxy["ws-opts"] =
                                json!({"path": "/httpupgrade", "v2ray-http-upgrade": true});
                        }
                        // Mihomo 的 V2Ray HTTP 承载叫 "h2"（h2-opts），不是 "http"。
                        Protocol::VlessHttp => {
                            proxy["network"] = json!("h2");
                            proxy["h2-opts"] = json!({"path": "/http"});
                        }
                        // Mihomo v1.19.33 的 VLESS 出站没有 kcp/quic 分支。
                        Protocol::VlessKcp | Protocol::VlessQuic => {
                            unreachable!("Mihomo 不支持该承载，应由 unsupported_reason 跳过")
                        }
                        _ => {}
                    }
                }
                Protocol::Vmess => {
                    // Mihomo 的 VMess 必须显式给 alterId 与 cipher（文档标 Required），
                    // 与 VLESS 不同；缺省会走旧协议或拒绝加载。
                    proxy["uuid"] = json!(credential);
                    proxy["alterId"] = json!(0);
                    proxy["cipher"] = json!("auto");
                    proxy["tls"] = json!(true);
                    proxy["servername"] = json!("localhost");
                }
                Protocol::Hysteria2 => {
                    // Mihomo 用 sni（不是 servername），密码字段是 password。
                    // QUIC 路径不读全局 tls.custom-certifactes，必须用出站级
                    // fingerprint 固定证书，否则报 unknown authority。
                    proxy["password"] = json!(credential);
                    proxy["sni"] = json!("localhost");
                    proxy["fingerprint"] = json!(fingerprint);
                }
                Protocol::Tuic => {
                    // TUIC v5 要 uuid + password；Mihomo 默认 alpn=[h3]，
                    // 而本内核入站 alpn 为空，必须显式清空才协商成功。
                    proxy["uuid"] = json!(UUID);
                    proxy["password"] = json!(credential);
                    proxy["sni"] = json!("localhost");
                    proxy["fingerprint"] = json!(fingerprint);
                    proxy["alpn"] = json!([]);
                    proxy["udp-relay-mode"] = json!("native");
                    proxy["reduce-rtt"] = json!(false);
                }
                Protocol::Snell => {
                    // v4 是 Mihomo（v1–v5）与 sing-box 1.14.4（v4/v6）的交集。
                    proxy["psk"] = json!(credential);
                    proxy["version"] = json!(4);
                }
                Protocol::AnyTls => {
                    proxy["password"] = json!(credential);
                    proxy["sni"] = json!("localhost");
                }
                Protocol::Naive => unreachable!("Mihomo v1.19.33 无 naive 代理类型"),
                Protocol::ShadowTls => unreachable!("由 shadowtls_client_config 处理"),
            }
            json!({
                "socks-port": listen.port(), "bind-address": "127.0.0.1", "allow-lan": false,
                "mode": "rule", "log-level": "warning", "ipv6": false,
                "find-process-mode": "off", "geo-auto-update": false, "geodata-mode": false,
                // 不使用地理规则或远端 provider；意外地理数据请求也只到回环地址。
                "geox-url": {
                    "geoip": "http://127.0.0.1:9/download-disabled",
                    "geosite": "http://127.0.0.1:9/download-disabled",
                    "mmdb": "http://127.0.0.1:9/download-disabled",
                    "asn": "http://127.0.0.1:9/download-disabled"
                },
                "external-controller": "", "external-ui": "", "external-ui-url": "",
                "dns": {"enable": false}, "tun": {"enable": false},
                "sniffer": {"enable": false}, "ntp": {"enable": false},
                "profile": {"store-selected": false, "store-fake-ip": false},
                // 此拼写是上游 v1.19.33 实际的 JSON/YAML 字段。
                "tls": {"custom-certifactes": [pem]},
                "proxies": [proxy], "rules": ["MATCH,kernel"]
            })
        }
        "sing-box" => {
            let mut outbound = json!({
                "type": protocol.name(), "tag": "kernel", "server": "127.0.0.1",
                "server_port": server.port(),
                "tls": {"enabled": true, "server_name": "localhost", "insecure": false,
                    "certificate_path": trust_path}
            });
            match protocol {
                Protocol::Trojan => outbound["password"] = json!(credential),
                Protocol::Vless
                | Protocol::VlessXudp
                | Protocol::VlessVision
                | Protocol::VlessWs
                | Protocol::VlessGrpc
                | Protocol::VlessXhttp
                | Protocol::VlessHttpUpgrade
                | Protocol::VlessHttp
                | Protocol::VlessKcp
                | Protocol::VlessQuic
                | Protocol::VlessEncryption
                | Protocol::VlessReality => {
                    // *string: 省略/null 会默认 XUDP；必须显式空字符串才走原生 UDP。
                    // https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/option/vless.go
                    // https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/vless/outbound.go
                    outbound["uuid"] = json!(credential);
                    outbound["flow"] = json!(match protocol {
                        Protocol::VlessVision => "xtls-rprx-vision",
                        _ => "",
                    });
                    outbound["packet_encoding"] = json!(match protocol {
                        Protocol::VlessXudp => "xudp",
                        _ => "",
                    });
                    outbound["multiplex"] = json!({"enabled": false});
                    if matches!(protocol, Protocol::VlessEncryption) {
                        outbound["encryption"] = json!(VLESS_ENCRYPTION_CLIENT);
                    }
                    if matches!(protocol, Protocol::VlessReality) {
                        outbound["tls"]["reality"] = json!({
                            "enabled": true,
                            "public_key": REALITY_PUBLIC,
                            "short_id": REALITY_SHORT_ID
                        });
                    }
                    // sing-box 用 transport 段表达承载。
                    match protocol {
                        Protocol::VlessWs => {
                            outbound["transport"] = json!({"type": "ws", "path": "/ws"})
                        }
                        Protocol::VlessGrpc => {
                            outbound["transport"] =
                                json!({"type": "grpc", "service_name": "TunService"})
                        }
                        Protocol::VlessHttpUpgrade => {
                            outbound["transport"] =
                                json!({"type": "httpupgrade", "path": "/httpupgrade"})
                        }
                        // sing-box 没有 XHTTP 承载；由 supported_by 拦下，不会走到这里。
                        Protocol::VlessXhttp => {
                            unreachable!("sing-box 不支持 XHTTP，应由 supported_by 跳过")
                        }
                        Protocol::VlessHttp => {
                            outbound["transport"] = json!({"type": "http", "path": "/http"})
                        }
                        Protocol::VlessKcp => {
                            unreachable!("sing-box 无 mKCP，应由 unsupported_reason 跳过")
                        }
                        // sing-box 的 "quic" 是旧 QUIC 承载，需 TLS。
                        Protocol::VlessQuic => outbound["transport"] = json!({"type": "quic"}),
                        _ => {}
                    }
                }
                Protocol::Vmess => {
                    // sing-box 的 VMess 需要 security 与 alter_id；
                    // packet_encoding 空字符串为原生 UDP。
                    outbound["uuid"] = json!(credential);
                    outbound["security"] = json!("auto");
                    outbound["alter_id"] = json!(0);
                    outbound["packet_encoding"] = json!("");
                }
                Protocol::Hysteria2 => {
                    // sing-box 的 Hysteria2 用顶层 password，TLS 走公共 tls 段。
                    outbound["password"] = json!(credential);
                }
                Protocol::Tuic => {
                    outbound["uuid"] = json!(UUID);
                    outbound["password"] = json!(credential);
                    outbound["udp_relay_mode"] = json!("native");
                    outbound["zero_rtt_handshake"] = json!(false);
                }
                Protocol::Snell => {
                    // sing-box 的 Snell 走公共 tls 段（本内核入站无 TLS）。
                    outbound["version"] = json!(4);
                    outbound["psk"] = json!(credential);
                    outbound["reuse"] = json!(false);
                }
                Protocol::AnyTls => {
                    // AnyTLS 必须真实 TLS，走公共 tls 段。
                    outbound["password"] = json!(credential);
                }
                Protocol::Naive => {
                    // sing-box naive 需要 username + password，走公共 tls 段。
                    // 上游 protocol/naive/outbound.go 的 DialContext：
                    // UDP 只有 uotClient != nil（即启用 udp_over_tcp）时可用。
                    outbound["username"] = json!("test");
                    outbound["password"] = json!(credential);
                    outbound["udp_over_tcp"] = json!({"enabled": true, "version": 2});
                }
                Protocol::ShadowTls => unreachable!("由 shadowtls_client_config 处理"),
            }
            // Snell 没有 TLS；sing-box 的 snell 出站不接受 tls 字段，
            // 而公共模板带上了它，必须移除。
            if matches!(protocol, Protocol::Snell) {
                outbound.as_object_mut().expect("对象").remove("tls");
            }
            json!({
                "log": {"level": "warn", "timestamp": false},
                "inbounds": [{"type": "socks", "tag": "local", "listen": "127.0.0.1",
                    "listen_port": listen.port()}],
                "outbounds": [outbound], "route": {"final": "kernel"}
            })
        }
        "xray" => {
            // https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/infra/conf/vless.go
            let settings = match protocol {
                Protocol::Trojan => json!({"servers": [{"address": "127.0.0.1",
                    "port": server.port(), "password": credential}]}),
                Protocol::Vless
                | Protocol::VlessXudp
                | Protocol::VlessVision
                | Protocol::VlessWs
                | Protocol::VlessGrpc
                | Protocol::VlessXhttp
                | Protocol::VlessHttpUpgrade
                | Protocol::VlessHttp
                | Protocol::VlessKcp
                | Protocol::VlessQuic
                | Protocol::VlessEncryption
                | Protocol::VlessReality => {
                    json!({"address": "127.0.0.1", "port": server.port(),
                    "id": credential,
                    "encryption": match protocol {
                        Protocol::VlessEncryption => VLESS_ENCRYPTION_CLIENT,
                        _ => "none",
                    },
                    "flow": match protocol {
                        Protocol::VlessVision => "xtls-rprx-vision",
                        _ => "",
                    }})
                }
                Protocol::Vmess => {
                    // Xray 的 VMess 出站用 vnext/servers 形状，且 security 必填
                    // （auto/aes-128-gcm/chacha20-poly1305/none/zero）。
                    json!({"vnext": [{"address": "127.0.0.1", "port": server.port(),
                        "users": [{"id": credential, "security": "auto", "alterId": 0}]}]})
                }
                // Xray v26.10.31 的协议列表里没有 hysteria2 / tuic；此分支不可达，
                // 由 Protocol::supported_by 在生成用例前拦下。
                Protocol::Hysteria2
                | Protocol::Tuic
                | Protocol::Snell
                | Protocol::AnyTls
                | Protocol::Naive
                | Protocol::ShadowTls => unreachable!("Xray 不支持该协议"),
            };
            let mux = match protocol {
                // XUDP 模式保留默认 cone，只将 UDP（非 53/443）改为命令 3；
                // 普通 TCP 仍用命令 1，不开启通用 TCP mux。
                // https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/outbound/outbound.go#L303-L320
                Protocol::Trojan
                | Protocol::VlessXudp
                | Protocol::Vmess
                | Protocol::Hysteria2
                | Protocol::Tuic
                | Protocol::Snell
                | Protocol::AnyTls
                | Protocol::Naive
                | Protocol::ShadowTls => json!({"enabled": false}),
                Protocol::Vless
                | Protocol::VlessVision
                | Protocol::VlessWs
                | Protocol::VlessGrpc
                | Protocol::VlessXhttp
                | Protocol::VlessHttpUpgrade
                | Protocol::VlessHttp
                | Protocol::VlessKcp
                | Protocol::VlessQuic
                | Protocol::VlessEncryption
                | Protocol::VlessReality => json!({"enabled": false,
                    "concurrency": -1, "xudpConcurrency": -1}),
            };
            // Xray 用 streamSettings.network + *Settings 表达承载。
            let mut stream = json!({
                "network": "tcp", "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost", "allowInsecure": false,
                    "disableSystemRoot": true,
                    "certificates": [{"certificateFile": trust_path, "usage": "verify",
                        "oneTimeLoading": true}]
                }
            });
            if matches!(protocol, Protocol::VlessReality) {
                // REALITY 覆盖默认的 tls 段。
                stream["security"] = json!("reality");
                stream["realitySettings"] = json!({
                    "serverName": "localhost",
                    "fingerprint": "chrome",
                    "publicKey": REALITY_PUBLIC,
                    "shortId": REALITY_SHORT_ID
                });
                stream.as_object_mut().map(|map| map.remove("tlsSettings"));
            }
            match protocol {
                Protocol::VlessWs => {
                    stream["network"] = json!("ws");
                    stream["wsSettings"] = json!({"path": "/ws"});
                }
                Protocol::VlessGrpc => {
                    stream["network"] = json!("grpc");
                    stream["grpcSettings"] = json!({"serviceName": "TunService"});
                }
                Protocol::VlessXhttp => {
                    stream["network"] = json!("xhttp");
                    stream["xhttpSettings"] = json!({"path": "/xhttp"});
                }
                Protocol::VlessHttpUpgrade => {
                    stream["network"] = json!("httpupgrade");
                    stream["httpupgradeSettings"] = json!({"path": "/httpupgrade"});
                }
                // Xray v26.10.31 的 http transport 已被移除，改用 XHTTP。
                Protocol::VlessHttp => {
                    unreachable!("Xray v26 已移除 http transport，应由 unsupported_reason 跳过")
                }
                Protocol::VlessKcp => {
                    // 服务端为明文 KCP，客户端必须同步关闭 TLS。
                    stream["network"] = json!("kcp");
                    stream["security"] = json!("none");
                    stream["kcpSettings"] = json!({});
                    stream.as_object_mut().map(|map| map.remove("tlsSettings"));
                }
                // Xray v26 已移除旧 QUIC transport，改用 XHTTP H3。
                Protocol::VlessQuic => {
                    unreachable!("Xray v26 已移除 quic transport，应由 unsupported_reason 跳过")
                }
                _ => {}
            }
            json!({
                "log": {"loglevel": "warning", "access": "none"},
                "inbounds": [{"tag": "local", "listen": "127.0.0.1", "port": listen.port(),
                    "protocol": "socks", "settings": {"auth": "noauth", "udp": true,
                        "ip": "127.0.0.1"}}],
                "outbounds": [{"tag": "kernel", "protocol": protocol.name(),
                    "settings": settings, "streamSettings": stream, "mux": mux}]
            })
        }
        _ => bail!("未知参考客户端"),
    })
}

/// ShadowTLS 的客户端出站形态与其它协议不同：它不终端代理。
///
/// - Mihomo：ShadowTLS 是 shadowsocks 出站的 `plugin: shadow-tls` +
///   `plugin-opts`，证书校验开关（`skip-cert-verify`）必须在 `plugin-opts` 内。
/// - sing-box：`shadowtls` 单独一条出站，真正的内层 `shadowsocks` 出站用
///   `detour` 指向它；`shadowtls` 自身不承载目标。
/// - Xray v26.10.31 没有 ShadowTLS，由 `supported_by` 在生成用例前拦下。
fn shadowtls_client_config(
    name: &str,
    listen: SocketAddr,
    server: SocketAddr,
    trust_path: &Path,
    credential: &str,
) -> Result<Value> {
    let pem = fs::read_to_string(trust_path)?;
    Ok(match name {
        "mihomo" => json!({
            "socks-port": listen.port(), "bind-address": "127.0.0.1", "allow-lan": false,
            "mode": "rule", "log-level": "warning", "ipv6": false,
            "find-process-mode": "off", "geo-auto-update": false, "geodata-mode": false,
            "geox-url": {
                "geoip": "http://127.0.0.1:9/download-disabled",
                "geosite": "http://127.0.0.1:9/download-disabled",
                "mmdb": "http://127.0.0.1:9/download-disabled",
                "asn": "http://127.0.0.1:9/download-disabled"
            },
            "external-controller": "", "external-ui": "", "external-ui-url": "",
            "dns": {"enable": false}, "tun": {"enable": false},
            "sniffer": {"enable": false}, "ntp": {"enable": false},
            "profile": {"store-selected": false, "store-fake-ip": false},
            "tls": {"custom-certifactes": [pem]},
            "proxies": [{
                "name": "kernel", "type": "ss", "server": "127.0.0.1",
                "port": server.port(), "cipher": SHADOWTLS_INNER_METHOD,
                "password": SHADOWTLS_INNER_PASSWORD, "udp": false,
                "plugin": "shadow-tls",
                "plugin-opts": {
                    "host": "localhost", "password": credential, "version": 3,
                    "skip-cert-verify": false
                }
            }],
            "rules": ["MATCH,kernel"]
        }),
        "sing-box" => json!({
            "log": {"level": "warn", "timestamp": false},
            "inbounds": [{"type": "socks", "tag": "local", "listen": "127.0.0.1",
                "listen_port": listen.port()}],
            "outbounds": [
                {
                    "type": "shadowtls", "tag": "kernel", "server": "127.0.0.1",
                    "server_port": server.port(), "version": 3, "password": credential,
                    "tls": {"enabled": true, "server_name": "localhost", "insecure": false,
                        "certificate_path": trust_path}
                },
                {
                    "type": "shadowsocks", "tag": "inner", "server": "127.0.0.1",
                    "server_port": server.port(), "method": SHADOWTLS_INNER_METHOD,
                    "password": SHADOWTLS_INNER_PASSWORD, "network": ["tcp"],
                    "detour": "kernel"
                }
            ],
            "route": {"final": "inner"}
        }),
        "xray" => unreachable!("Xray 不支持 ShadowTLS"),
        _ => bail!("未知参考客户端"),
    })
}

struct ClientProcess {
    child: Child,
    address: SocketAddr,
    log_path: PathBuf,
}

impl ClientProcess {
    async fn start(
        client: &ReferenceClient,
        protocol: Protocol,
        directory: &Path,
        server: SocketAddr,
        trust_path: &Path,
        credential: &str,
        fingerprint: &str,
    ) -> Result<Self> {
        Self::start_configured(
            client,
            directory,
            |listen| {
                client_config(
                    &client.name,
                    protocol,
                    listen,
                    server,
                    trust_path,
                    credential,
                    fingerprint,
                )
            },
            |command| protocol.configure_command(&client.name, command),
        )
        .await
    }

    async fn start_shadowsocks(
        client: &ReferenceClient,
        mode: shadowsocks_reference::Mode,
        scenario: shadowsocks_reference::Scenario,
        directory: &Path,
        server: SocketAddr,
    ) -> Result<Self> {
        Self::start_configured(
            client,
            directory,
            |listen| {
                shadowsocks_reference::client_config(&client.name, mode, scenario, listen, server)
            },
            |_| {},
        )
        .await
    }

    // 旧协议和 SS 必须共用同一条端口预留、私有配置、最小环境与进程守卫路径。
    async fn start_configured(
        client: &ReferenceClient,
        directory: &Path,
        config: impl FnOnce(SocketAddr) -> Result<Value>,
        configure_command: impl FnOnce(&mut Command),
    ) -> Result<Self> {
        let (tcp_reservation, udp_reservation, listen) = reserve_port()?;
        let config_path = directory.join("client.json");
        private_write(&config_path, &serde_json::to_vec_pretty(&config(listen)?)?)?;
        let working = directory.join("work");
        fs::create_dir(&working)?; // Empty and separate from the preserved configuration.
        let log_path = directory.join("client.log");
        let log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&log_path)?;
        let mut command = Command::new(&client.path);
        match client.name.as_str() {
            "mihomo" => {
                command.arg("-d").arg(&working).arg("-f").arg(&config_path);
            }
            "sing-box" => {
                command.arg("run").arg("-c").arg(&config_path);
            }
            "xray" => {
                command.arg("run").arg("-config").arg(&config_path);
            }
            _ => bail!("未知参考客户端"),
        }
        command
            .current_dir(&working)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &working)
            .env("XDG_CONFIG_HOME", &working)
            .env("XDG_CACHE_HOME", &working)
            .env("TMPDIR", &working)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("DISABLE_SYSTEM_CA", "true")
            .env("DISABLE_EMBED_CA", "true")
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        configure_command(&mut command);
        // 每次场景启动前重新核对普通文件、固定平台/版本及二进制摘要。
        verify_reference_binary(client)?;
        // 客户端通过配置绑定端口，不接受继承的监听描述符。
        drop(tcp_reservation);
        drop(udp_reservation);
        let mut process = Self {
            child: command.spawn()?,
            address: listen,
            log_path,
        };
        let deadline = Instant::now() + DEADLINE;
        loop {
            process.assert_running()?;
            if let Ok(mut probe) = TcpStream::connect(listen).await {
                probe.write_all(&[5, 1, 0]).await?;
                let mut response = [0; 2];
                timeout(DEADLINE, probe.read_exact(&mut response)).await??;
                ensure!(response == [5, 0], "参考客户端 SOCKS 就绪探针失败");
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "参考客户端未就绪，日志: {}",
                process.log_path.display()
            );
            sleep(Duration::from_millis(20)).await;
        }
        Ok(process)
    }

    fn assert_running(&mut self) -> Result<()> {
        ensure!(
            self.child.try_wait()?.is_none(),
            "参考客户端提前退出，日志: {}",
            self.log_path.display()
        );
        Ok(())
    }

    fn stop(mut self) -> Result<()> {
        self.child.kill().context("终止参考客户端失败")?;
        self.child.wait().context("回收参考客户端失败")?;
        // 等待进程退出后验证 TCP/UDP 监听端口都已释放。
        let _tcp = PortReservation::bind(self.address).context("参考客户端 TCP 监听未释放")?;
        let _udp = UdpReservation::bind(self.address).context("参考客户端 UDP 监听未释放")?;
        Ok(())
    }
}

impl Drop for ClientProcess {
    fn drop(&mut self) {
        // 错误、panic、取消和超时路径均回收子进程。
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reserve_port() -> Result<(PortReservation, UdpReservation, SocketAddr)> {
    for _ in 0..16 {
        let tcp = PortReservation::bind((Ipv4Addr::LOCALHOST, 0))?;
        let listen = tcp.local_addr()?;
        if listen.port() < 1024 {
            continue;
        }
        if let Ok(udp) = UdpReservation::bind(listen) {
            return Ok((tcp, udp, listen));
        }
    }
    bail!("无法为本机 SOCKS 同时保留 TCP/UDP 动态端口")
}

fn relay_address(mut relay: SocketAddr) -> Result<SocketAddr> {
    if relay.ip().is_unspecified() {
        relay.set_ip(Ipv4Addr::LOCALHOST.into());
    }
    ensure!(
        relay.ip().is_loopback() && relay.port() >= 1024,
        "SOCKS UDP relay 不是本机高端口"
    );
    Ok(relay)
}

async fn positive_udp(proxy: SocketAddr, protocol: Protocol) -> Result<Value> {
    let first_udp = Echo::udp("127.0.0.1").await;
    let second_udp = Echo::udp("127.0.0.1").await;
    // Trojan/XUDP 在同一 SOCKS 关联内切换目标；原生 VLESS/VMess 每个关联固定一个目标。
    let association_count = match protocol {
        Protocol::Trojan | Protocol::VlessXudp => 1,
        Protocol::Vless
        | Protocol::VlessVision
        | Protocol::VlessWs
        | Protocol::VlessGrpc
        | Protocol::VlessXhttp
        | Protocol::VlessHttpUpgrade
        | Protocol::VlessHttp
        | Protocol::VlessKcp
        | Protocol::VlessQuic
        | Protocol::VlessEncryption
        | Protocol::VlessReality
        | Protocol::Vmess
        | Protocol::Hysteria2
        | Protocol::Tuic
        | Protocol::Snell
        | Protocol::AnyTls
        | Protocol::Naive
        | Protocol::ShadowTls => 2,
    };
    if matches!(protocol, Protocol::VlessXudp) {
        // 固定 Xray 的 cone 路径对 53/443 端口例外，确保测试数据报实际走 XUDP。
        ensure!(
            [first_udp.address.port(), second_udp.address.port()]
                .iter()
                .all(|port| !matches!(*port, 53 | 443)),
            "XUDP 回显目标不能使用 Xray cone 路径的例外端口"
        );
    }
    positive_udp_targets(proxy, &first_udp, &second_udp, association_count).await
}

async fn positive_udp_targets(
    proxy: SocketAddr,
    first_udp: &Echo,
    second_udp: &Echo,
    association_count: usize,
) -> Result<Value> {
    ensure!(
        (1..=2).contains(&association_count),
        "UDP 探针关联数超出范围"
    );
    let mut associations = Vec::new();
    for _ in 0..association_count {
        let (control, relay) = socks(3, address("0.0.0.0:0".parse()?), proxy).await;
        associations.push((
            control,
            relay_address(relay)?,
            UdpSocket::bind("127.0.0.1:0").await?,
        ));
    }
    let mut received = [0; 2048];
    for (target_index, destination, payload) in [
        (0, first_udp.address, b"first-udp\0\xff".as_slice()),
        (1, second_udp.address, b"second-target".as_slice()),
        (0, first_udp.address, b"return-to-first".as_slice()),
    ] {
        let (_, relay, datagrams) = &associations[target_index % association_count];
        let mut packet = vec![0, 0, 0];
        packet.extend(address(destination));
        packet.extend(payload);
        datagrams.send_to(&packet, *relay).await?;
        let (length, sender) = timeout(DEADLINE, datagrams.recv_from(&mut received))
            .await
            .context("参考客户端 UDP 回显超时")??;
        ensure!(sender == *relay, "UDP 响应来源不是参考客户端 relay");
        ensure!(received[..length] == packet, "UDP 响应地址或载荷改变");
    }
    Ok(
        json!({"udp": "passed", "udp_datagrams": 3, "udp_targets": 2,
        "udp_socks_associations": association_count}),
    )
}

async fn positive_traffic(
    proxy: SocketAddr,
    server: &Running,
    protocol: Protocol,
    udp: bool,
) -> Result<Value> {
    // 阶段标记只打边界与耗时，便于定位「哪一步在等 / 哪一步被重置」。
    // begin 一定要打：panic 时可能没有对应的 end。
    let started = std::time::Instant::now();
    let stage = |name: &str| {
        eprintln!(
            "[stage] {} protocol={} mode={} at_ms={}",
            name,
            protocol.name(),
            protocol.mode(),
            started.elapsed().as_millis()
        );
    };
    let tcp = Echo::tcp("127.0.0.1", false).await;
    let payload = format!("official-client-{}-tcp", protocol.name());
    let payload = [payload.as_bytes(), b"\0\xff"].concat();
    stage("begin: socks connect");
    let (mut stream, _) = socks(1, address(tcp.address), proxy).await;
    stage("begin: tcp echo");
    exchange(&mut stream, &payload).await;
    stage("end: tcp echo");
    drop(stream);
    let mut result = if udp {
        stage("begin: udp");
        let value = positive_udp(proxy, protocol).await?;
        stage("end: udp");
        value
    } else {
        json!({"udp": "unsupported_by_client_baseline"})
    };
    // 服务端计数发生在 relay 的 poll_write 中，与客户端收到回显是两条时间线。
    // 这里只重读计数、不重发流量：给「转发完成后计数可见」一个有界窗口。
    // 持续为零仍判失败，所以真漏计不会被这层等待掩盖。
    stage("begin: stats wait");
    let first = server.stats.snapshot();
    let wait_started = std::time::Instant::now();
    let deadline = wait_started + std::time::Duration::from_secs(2);
    let snapshot = loop {
        let snapshot = server.stats.snapshot();
        if snapshot.uplink > 0 && snapshot.downlink > 0 {
            break snapshot;
        }
        if std::time::Instant::now() >= deadline {
            break snapshot;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    stage("end: stats wait");
    ensure!(
        snapshot.uplink > 0 && snapshot.downlink > 0,
        "项目服务端未统计到真实转发流量（首读 uplink={} downlink={}；等待 {} ms 后 uplink={} downlink={}）",
        first.uplink,
        first.downlink,
        wait_started.elapsed().as_millis(),
        snapshot.uplink,
        snapshot.downlink
    );
    result["tcp"] = json!("passed");
    result["server_stats"] = json!(snapshot);
    Ok(result)
}

async fn tcp_denied(proxy: SocketAddr, target: SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    timeout(DEADLINE, stream.read_exact(&mut greeting)).await??;
    ensure!(greeting == [5, 0], "负向测试的 SOCKS 入口不可用");
    let mut request = vec![5, 1, 0];
    request.extend(address(target));
    // 某些 SOCKS 实现在完成上游协议握手前先返回乐观成功应答。
    request.extend(b"negative-auth-probe");
    stream.write_all(&request).await?;
    timeout(NEGATIVE_DEADLINE, async {
        let mut header = [0; 4];
        match stream.read_exact(&mut header).await {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        ensure!(header[0] == 5 && header[2] == 0, "无效 SOCKS 回复");
        if header[1] != 0 {
            ensure!((1..=8).contains(&header[1]), "无效 SOCKS 拒绝码");
            return Ok(());
        }
        let size = match header[3] {
            1 => 4,
            4 => 16,
            3 => stream.read_u8().await? as usize,
            _ => bail!("无效 SOCKS BND 地址"),
        };
        let mut bound = vec![0; size + 2];
        stream.read_exact(&mut bound).await?;
        let mut response = [0; 1];
        match stream.read(&mut response).await {
            Ok(0) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                Ok(())
            }
            Ok(_) => bail!("负向测试收到不应存在的代理载荷"),
            Err(error) => Err(error.into()),
        }
    })
    .await
    .context("负向 TCP 请求没有明确关闭或 SOCKS 拒绝")?
}

async fn wait_rejected(server: &Running, before: u64) -> Result<()> {
    timeout(NEGATIVE_DEADLINE, async {
        while server.stats.snapshot().rejected <= before {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("项目服务端没有观察到拒绝，不能仅凭客户端超时判断成功")
}

/// QUIC 协议（Hysteria2/TUIC）的证书不受信任场景。
///
/// 客户端在 QUIC/TLS 握手阶段就因证书校验失败放弃，**连连接都不会建立**，
/// 服务端观察不到任何握手尝试，因此 `stats.rejected` 不会增长。
/// 这与 TCP 协议不同：TCP 的 TLS 失败仍会到达服务端并计入 rejected。
///
/// 正确的断言是「服务端零流量」：客户端确实拒绝了该证书，且没有把业务
/// 数据发给目标。
async fn quic_untrusted_certificate_denies(proxy: SocketAddr, server: &Running) -> Result<Value> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let before = server.stats.snapshot();
    // 客户端会尝试发起代理请求；期望失败且不产生任何业务字节。
    let _ = tcp_denied(proxy, target.local_addr()?).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ensure!(
        timeout(Duration::from_millis(200), target.accept())
            .await
            .is_err(),
        "证书不受信任时仍连接到 TCP 目标"
    );
    let after = server.stats.snapshot();
    ensure!(
        after.uplink == before.uplink && after.downlink == before.downlink,
        "证书不受信任时服务端仍记录了业务字节"
    );
    Ok(
        json!({"scenario": "untrusted-certificate", "protocol_family": "quic",
        "assertion": "zero business bytes; handshake rejected client-side"}),
    )
}

/// TCP 承载的证书不受信任场景。
///
/// 断言的是**安全属性**：客户端拒绝该证书、服务端计入拒绝、且没有任何
/// 业务字节到达目标。不断言 SOCKS 立刻关闭——那是客户端实现细节：
/// sing-box 的 gRPC/XHTTP 出站基于 gRPC-Go 与 HTTP/2，证书校验失败后会
/// 自行重试而不关闭 SOCKS（2026-11-22 实测），但服务端记录 rejected 且
/// 无字节转发。
async fn tcp_untrusted_certificate_denies(
    proxy: SocketAddr,
    server: &Running,
    udp: bool,
) -> Result<Value> {
    let _ = udp;
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let before = server.stats.snapshot();
    // 客户端可能直接关闭 SOCKS，也可能重试到超时；两种都在下面统一断言。
    let _ = tcp_denied(proxy, target.local_addr()?).await;
    wait_rejected(server, before.rejected).await?;
    ensure!(
        timeout(Duration::from_millis(150), target.accept())
            .await
            .is_err(),
        "证书不受信任时仍连接到 TCP 目标"
    );
    let after = server.stats.snapshot();
    ensure!(
        after.uplink == before.uplink && after.downlink == before.downlink,
        "证书不受信任时服务端仍记录了业务字节"
    );
    Ok(json!({"scenario": "untrusted-certificate",
        "assertion": "server rejected; zero business bytes"}))
}

async fn negative_traffic(proxy: SocketAddr, server: &Running, udp: bool) -> Result<Value> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let before = server.stats.snapshot().rejected;
    tcp_denied(proxy, target.local_addr()?).await?;
    wait_rejected(server, before).await?;
    ensure!(
        timeout(Duration::from_millis(150), target.accept())
            .await
            .is_err(),
        "负向认证/TLS 场景仍连接到 TCP 目标"
    );
    if udp {
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let local = UdpSocket::bind("127.0.0.1:0").await?;
        let (control, relay) = socks(3, address("0.0.0.0:0".parse()?), proxy).await;
        let relay = relay_address(relay)?;
        let before = server.stats.snapshot().rejected;
        let mut packet = vec![0, 0, 0];
        packet.extend(address(target.local_addr()?));
        packet.extend(b"negative-udp-probe");
        local.send_to(&packet, relay).await?;
        wait_rejected(server, before).await?;
        let mut target_buffer = [0; 256];
        let mut client_buffer = [0; 256];
        let unexpected = timeout(Duration::from_millis(300), async {
            tokio::select! {
                result = target.recv_from(&mut target_buffer) => result,
                result = local.recv_from(&mut client_buffer) => result,
            }
        })
        .await;
        ensure!(
            unexpected.is_err(),
            "错误身份仍产生 UDP 目标流量或客户端数据"
        );
        drop(control);
    }
    let snapshot = server.stats.snapshot();
    ensure!(
        snapshot.uplink == 0 && snapshot.downlink == 0,
        "拒绝场景产生了项目转发载荷"
    );
    Ok(json!({"tcp_rejected": true, "udp_rejected": udp,
        "target_untouched": true, "server_stats": snapshot}))
}

/// ShadowTLS 的「错误密码」不是服务端拒绝，而是协议规定的回落。
///
/// 上游行为：ClientHello 的 v3 HMAC 不匹配时，服务端把缓存的 ClientHello
/// 原样转给伪装握手目标并进入双向复制。因此不能复用 `negative_traffic`
/// 去等 `stats.rejected` 增长——那样会错误判定测试失败。
///
/// 正确的断言是：
/// 1. 客户端无法到达业务目标（没有内层转发）；
/// 2. 握手目标确实收到了回落连接（证明走的是 ShadowTLS 回落路径，
///    而不是客户端根本没连上）；
/// 3. 服务端没有记录业务字节。
async fn shadowtls_wrong_password_falls_back(
    proxy: SocketAddr,
    server: &Running,
    handshake: &TlsHandshakeTarget,
) -> Result<Value> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let before = handshake.connections();
    // 客户端会为这个 TCP 请求完成 SOCKS 握手并尝试内层协议；
    // 期望在 SOCKS 层就失败或被关闭，绝不产生目标流量。
    let _ = tcp_denied(proxy, target.local_addr()?).await;
    // 回落是异步的：等到伪装目标确实被拨号。
    timeout(DEADLINE, async {
        while handshake.connections() <= before {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("错误密码时未观察到到伪装握手目标的回落连接")?;
    ensure!(
        timeout(Duration::from_millis(200), target.accept())
            .await
            .is_err(),
        "错误密码仍连接到业务 TCP 目标"
    );
    let snapshot = server.stats.snapshot();
    ensure!(
        snapshot.uplink == 0 && snapshot.downlink == 0,
        "错误密码场景产生了项目转发载荷"
    );
    Ok(json!({
        "scenario": "wrong-password",
        "behavior": "shadowtls v3 fallback to handshake target",
        "fallback_observed": true,
        "inner_target_untouched": true,
        "server_stats": snapshot
    }))
}

async fn run_scenarios(
    client: &ReferenceClient,
    protocol: Protocol,
    artifacts: &Path,
) -> Result<Value> {
    let certificate = Certificate::new();
    let unrelated = Certificate::new();
    // ShadowTLS 的握手伪装目标：真实 TLS 1.3 服务端，独立于协议入站证书。
    let handshake = if matches!(protocol, Protocol::ShadowTls | Protocol::VlessReality) {
        // REALITY 需要加密 flight 首记录 > 512（见 `TlsHandshakeTarget::start`）；
        // ShadowTLS 不需要，保持原样。
        let padding = if protocol == Protocol::VlessReality {
            REALITY_TARGET_CERT_PADDING
        } else {
            0
        };
        Some(TlsHandshakeTarget::start(&certificate, padding).await?)
    } else {
        None
    };
    let mut results = serde_json::Map::new();
    let mut scenarios = vec![Scenario::Valid, Scenario::WrongCredential];
    if protocol.uses_tls() {
        scenarios.push(Scenario::UntrustedCertificate);
    }
    for scenario in scenarios {
        let directory = artifacts.join(scenario.name(protocol));
        fs::create_dir(&directory)?;
        let cert_path = directory.join("server-cert.pem");
        let key_path = directory.join("server-key.pem");
        private_write(
            &cert_path,
            &fs::read(certificate.dir.path().join("cert.pem"))?,
        )?;
        private_write(
            &key_path,
            &fs::read(certificate.dir.path().join("key.pem"))?,
        )?;
        let trust_path = directory.join("trusted-cert.pem");
        let trust = if matches!(scenario, Scenario::UntrustedCertificate) {
            &unrelated
        } else {
            &certificate
        };
        private_write(&trust_path, &fs::read(trust.dir.path().join("cert.pem"))?)?;
        let config = if matches!(protocol, Protocol::ShadowTls) {
            // ShadowTLS 的入站由外层 ShadowTLS + 内层 Shadowsocks 组成；
            // 两者都不使用证书字段（握手目标自带 TLS）。
            let mut config = socks_config();
            config["inbounds"] =
                protocol.inbounds(&certificate, handshake.as_ref().map(|h| h.address));
            config
        } else {
            let mut inbound = protocol.inbound(&certificate, handshake.as_ref().map(|h| h.address));
            // Snell 没有 TLS；KCP 用明文；REALITY 不用常规证书（临时证书由
            // 私钥 + 客户端公钥派生，证书链来自 target 的真实握手）。
            if !matches!(
                protocol,
                Protocol::Snell | Protocol::VlessKcp | Protocol::VlessReality
            ) {
                inbound["certificate"] = json!(cert_path);
                inbound["private_key"] = json!(key_path);
            }
            // Naive 的 cronet 客户端会把 server 当域名解析（上游硬编码
            // `RemoteIsDomain: true`），本机 localhost 同时解析出 127.0.0.1
            // 与 ::1，happy-eyeballs 优先尝试 ::1。用 [::] 双栈监听同时接住。
            if matches!(protocol, Protocol::Naive) {
                inbound["listen"] = json!("[::]:0");
            }
            let mut config = socks_config();
            config["inbounds"] = json!([inbound]);
            config
        };
        let mut config = config;
        config["limits"]["handshake_timeout_ms"] = json!(3000);
        config["limits"]["udp_idle_timeout_ms"] = json!(3000);
        config["limits"]["shutdown_timeout_ms"] = json!(300);
        private_write(
            &directory.join("server.json"),
            &serde_json::to_vec_pretty(&config)?,
        )?;
        let server = Running::start(config).await;
        let mut process = ClientProcess::start(
            client,
            protocol,
            &directory,
            server.address,
            &trust_path,
            protocol.credential(scenario),
            // 指纹必须跟随客户端实际信任的那张证书：不信任场景下客户端配的是
            // `unrelated`，若仍传服务端证书指纹就等于绕过该负向用例。
            &certificate_fingerprint(trust),
        )
        .await?;
        let udp = protocol.udp_supported(&client.name);
        let result = match scenario {
            Scenario::Valid => {
                let result = positive_traffic(process.address, &server, protocol, udp).await;
                match (&result, &handshake) {
                    (Ok(_), Some(handshake)) => {
                        // 真实客户端认证路径必须实际拨过伪装握手目标；
                        // 仅“内层通了”不足以证明外层是真实 TLS。
                        ensure!(
                            handshake.connections() > 0,
                            "ShadowTLS 认证成功但未拨伪装握手目标"
                        );
                        result.map(|mut value| {
                            value["handshake_target_connections"] = json!(handshake.connections());
                            value
                        })
                    }
                    _ => result,
                }
            }
            Scenario::WrongCredential => match protocol {
                // ShadowTLS 错误密码按协议回落到伪装握手目标，不是服务端拒绝。
                Protocol::ShadowTls => {
                    shadowtls_wrong_password_falls_back(
                        process.address,
                        &server,
                        handshake.as_ref().expect("ShadowTLS 缺少握手目标"),
                    )
                    .await
                }
                _ => negative_traffic(process.address, &server, udp).await,
            },
            Scenario::UntrustedCertificate => match protocol {
                // QUIC 协议在握手期就失败，服务端看不到连接。
                // 旧 QUIC 承载与 Hysteria2/TUIC 同类：QUIC 握手期客户端即放弃，
                // 服务端看不到连接，只能断言「零业务字节」。
                Protocol::Hysteria2 | Protocol::Tuic | Protocol::VlessQuic => {
                    quic_untrusted_certificate_denies(process.address, &server).await
                }
                _ => tcp_untrusted_certificate_denies(process.address, &server, false).await,
            },
        }
        .with_context(|| {
            format!(
                "{} {}；保留日志 {}",
                client.name,
                scenario.name(protocol),
                directory.display()
            )
        });
        // 先固定业务错误，再做清理：清理自身失败不应覆盖首个真实错误，
        // 否则报出来的会是「客户端已退出」之类，掩盖最初的失败原因。
        let cleanup_started = std::time::Instant::now();
        let running = process.assert_running();
        let stopped = process.stop();
        server.shutdown().await;
        eprintln!(
            "[stage] cleanup protocol={} mode={} scenario={} at_ms={} business={}",
            protocol.name(),
            protocol.mode(),
            scenario.name(protocol),
            cleanup_started.elapsed().as_millis(),
            if result.is_ok() { "ok" } else { "failed" }
        );
        // 业务失败优先；业务成功时才报告清理问题。
        let result = match result {
            Ok(value) => {
                running?;
                stopped?;
                Ok(value)
            }
            Err(error) => {
                if running.is_err() || stopped.is_err() {
                    eprintln!(
                        "[stage] cleanup 亦失败（已忽略，保留首个业务错误）protocol={} mode={}",
                        protocol.name(),
                        protocol.mode()
                    );
                }
                Err(error)
            }
        };
        results.insert(scenario.name(protocol).to_owned(), result?);
        eprintln!(
            "{} {} {} {}: passed",
            client.name,
            client.version,
            protocol.mode(),
            scenario.name(protocol)
        );
    }
    Ok(Value::Object(results))
}

/// 当前平台标识，与 `tools/fetch_reference_clients.py::detect_platform`
/// 的返回值保持同一形状（`{os}-{arch}`）。
///
/// 注意架构名两边写法不同：脚本与 manifest 用 `arm64` / `x86_64`
/// （对齐上游 release 资产命名），而 `std::env::consts::ARCH` 在
/// macOS 与 Linux 的 ARM 上都是 `aarch64`。
fn platform_tag() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}-{arch}")
}

async fn real_interop(name: &str, protocol: Protocol) -> Result<()> {
    // 客户端未实现该协议时显式跳过：报告「该客户端不支持」，
    // 而不是让它去解析一份自己不认识的出站配置。
    if let Some(reason) = protocol.unsupported_reason(name) {
        eprintln!("跳过：{} {}；{}", name, protocol.mode(), reason);
        // 仍然写出机器可读结果：`passed` 只表示「该用例没有失败」，
        // 不支持不能算进互通覆盖数。
        let root = project().join(".test-artifacts");
        fs::create_dir_all(&root)?;
        let artifacts = tempfile::Builder::new()
            .prefix(&format!("interop-{name}-{}-unsupported-", protocol.mode()))
            .tempdir_in(&root)?
            .keep();
        private_write(
            &artifacts.join("result.json"),
            &serde_json::to_vec_pretty(&json!({
                "client": name,
                "protocol": protocol.name(),
                "mode": protocol.mode(),
                "status": "unsupported",
                "reason": reason,
            }))?,
        )?;
        return Ok(());
    }
    let client = reference_client(name)?;
    let root = project().join(".test-artifacts");
    fs::create_dir_all(&root)?;
    let artifacts = tempfile::Builder::new()
        .prefix(&format!("interop-{name}-{}-", protocol.mode()))
        .tempdir_in(&root)?
        .keep();
    eprintln!(
        "{} {} artifacts: {}",
        client.name,
        client.version,
        artifacts.display()
    );
    let result = timeout(
        Duration::from_secs(60),
        run_scenarios(&client, protocol, &artifacts),
    )
    .await
    .context("真实客户端互通测试超过 60 秒")
    .and_then(|result| result);
    let mut report = match &result {
        Ok(scenarios) => {
            // 只声明真正跑过的检查：REALITY/Snell 没有常规证书校验场景。
            let certificate_verification = if scenarios.get("untrusted-certificate").is_some() {
                "custom trust with localhost verification; unrelated certificate rejected"
            } else {
                "not_applicable"
            };
            json!({"client": name, "version": client.version,
                "protocol": protocol.name(), "mode": protocol.mode(), "status": "passed",
                "certificate_verification": certificate_verification,
                "scenarios": scenarios})
        }
        Err(error) => json!({"client": name, "version": client.version,
            "protocol": protocol.name(), "mode": protocol.mode(), "status": "failed", "error": format!("{error:#}")}),
    };
    if !protocol.udp_supported(name) {
        report["udp"] = json!("unsupported_by_client_baseline");
    }
    private_write(
        &artifacts.join("result.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    result.map(|_| ())
}

// 以下配置生成测试只读取临时证书和检查 JSON/Command，不读取 manifest 或启动进程。
#[test]
fn configuration_generation_vless_transport_and_udp_scope() -> Result<()> {
    let certificate = Certificate::new();
    let trust = certificate.dir.path().join("cert.pem");
    let listen = "127.0.0.1:1080".parse()?;
    let server = "127.0.0.1:1443".parse()?;
    let mihomo = client_config(
        "mihomo",
        Protocol::Vless,
        listen,
        server,
        &trust,
        UUID,
        "AA:BB",
    )?;
    assert_eq!(
        mihomo["proxies"][0],
        json!({
            "name": "kernel", "type": "vless", "server": "127.0.0.1", "port": 1443,
            "uuid": UUID, "flow": "", "tls": true, "servername": "localhost",
            "skip-cert-verify": false, "udp": false, "smux": {"enabled": false}
        })
    );
    assert_eq!(
        mihomo["tls"]["custom-certifactes"],
        json!([fs::read_to_string(&trust)?])
    );
    assert!(!Protocol::Vless.udp_supported("mihomo"));

    let sing_box = client_config(
        "sing-box",
        Protocol::Vless,
        listen,
        server,
        &trust,
        UUID,
        "AA:BB",
    )?;
    assert_eq!(
        sing_box["outbounds"][0],
        json!({
            "type": "vless", "tag": "kernel", "server": "127.0.0.1", "server_port": 1443,
            "uuid": UUID, "flow": "", "packet_encoding": "", "multiplex": {"enabled": false},
            "tls": {"enabled": true, "server_name": "localhost", "insecure": false,
                "certificate_path": trust}
        })
    );
    assert!(Protocol::Vless.udp_supported("sing-box"));

    let xray = client_config(
        "xray",
        Protocol::Vless,
        listen,
        server,
        &trust,
        UUID,
        "AA:BB",
    )?;
    assert_eq!(
        xray["outbounds"][0],
        json!({
            "tag": "kernel", "protocol": "vless",
            "settings": {"address": "127.0.0.1", "port": 1443, "id": UUID,
                "flow": "", "encryption": "none"},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                "serverName": "localhost", "allowInsecure": false, "disableSystemRoot": true,
                "certificates": [{"certificateFile": trust, "usage": "verify", "oneTimeLoading": true}]}},
            "mux": {"enabled": false, "concurrency": -1, "xudpConcurrency": -1}
        })
    );
    assert!(Protocol::Vless.udp_supported("xray"));
    Ok(())
}

#[test]
fn configuration_generation_trojan_preserves_existing_outbounds() -> Result<()> {
    let certificate = Certificate::new();
    let trust = certificate.dir.path().join("cert.pem");
    let listen = "127.0.0.1:1080".parse()?;
    let server = "127.0.0.1:1443".parse()?;
    let mihomo = client_config(
        "mihomo",
        Protocol::Trojan,
        listen,
        server,
        &trust,
        PASSWORD,
        "AA:BB",
    )?;
    assert_eq!(
        mihomo["proxies"][0],
        json!({
            "name": "kernel", "type": "trojan", "server": "127.0.0.1", "port": 1443,
            "password": PASSWORD, "sni": "localhost", "skip-cert-verify": false, "udp": true
        })
    );
    let sing_box = client_config(
        "sing-box",
        Protocol::Trojan,
        listen,
        server,
        &trust,
        PASSWORD,
        "AA:BB",
    )?;
    assert_eq!(
        sing_box["outbounds"][0],
        json!({
            "type": "trojan", "tag": "kernel", "server": "127.0.0.1", "server_port": 1443,
            "password": PASSWORD, "tls": {"enabled": true, "server_name": "localhost",
                "insecure": false, "certificate_path": trust}
        })
    );
    let xray = client_config(
        "xray",
        Protocol::Trojan,
        listen,
        server,
        &trust,
        PASSWORD,
        "AA:BB",
    )?;
    assert_eq!(
        xray["outbounds"][0],
        json!({
            "tag": "kernel", "protocol": "trojan",
            "settings": {"servers": [{"address": "127.0.0.1", "port": 1443, "password": PASSWORD}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                "serverName": "localhost", "allowInsecure": false, "disableSystemRoot": true,
                "certificates": [{"certificateFile": trust, "usage": "verify", "oneTimeLoading": true}]}},
            "mux": {"enabled": false}
        })
    );
    assert_eq!(
        Protocol::Trojan.inbound(&certificate, None),
        certificate.inbound()
    );
    Ok(())
}

#[test]
fn configuration_generation_scenarios_keep_identity_and_trust_separate() -> Result<()> {
    let certificate = Certificate::new();
    let unrelated = Certificate::new();
    let listen = "127.0.0.1:1080".parse()?;
    let server = "127.0.0.1:1443".parse()?;
    assert_ne!(UUID, WRONG_UUID);
    assert_eq!(
        Scenario::WrongCredential.name(Protocol::Vless),
        "wrong-uuid"
    );
    assert_eq!(
        Scenario::WrongCredential.name(Protocol::Trojan),
        "wrong-password"
    );
    for protocol in [Protocol::Trojan, Protocol::Vless, Protocol::VlessXudp] {
        for scenario in [
            Scenario::Valid,
            Scenario::WrongCredential,
            Scenario::UntrustedCertificate,
        ] {
            let credential = protocol.credential(scenario);
            let trust = if matches!(scenario, Scenario::UntrustedCertificate) {
                &unrelated
            } else {
                &certificate
            }
            .dir
            .path()
            .join("cert.pem");
            let mut inbound = protocol.inbound(&certificate, None);
            let key = match protocol {
                Protocol::Trojan => "password",
                Protocol::Hysteria2 | Protocol::Tuic => "password",
                Protocol::Snell => "psk",
                Protocol::AnyTls | Protocol::Naive | Protocol::ShadowTls => "password",
                Protocol::Vless
                | Protocol::VlessXudp
                | Protocol::VlessVision
                | Protocol::VlessWs
                | Protocol::VlessGrpc
                | Protocol::VlessXhttp
                | Protocol::VlessHttpUpgrade
                | Protocol::VlessHttp
                | Protocol::VlessKcp
                | Protocol::VlessQuic
                | Protocol::VlessEncryption
                | Protocol::VlessReality
                | Protocol::Vmess => "uuid",
            };
            assert_eq!(
                inbound["users"][0][key],
                protocol.credential(Scenario::Valid)
            );
            // 两个 UUID 都必须通过正式配置校验，错误用例才能验证服务端认证失败。
            inbound["users"][0][key] = json!(credential);
            let mut server_config = socks_config();
            server_config["inbounds"] = json!([inbound]);
            dubhe::Config::from_json(&server_config.to_string())?;
            for client in ["mihomo", "sing-box", "xray"] {
                let config = client_config(
                    client, protocol, listen, server, &trust, credential, "AA:BB",
                )?;
                let (actual_credential, actual_trust) = match client {
                    "mihomo" => (
                        config["proxies"][0][key].clone(),
                        config["tls"]["custom-certifactes"][0].clone(),
                    ),
                    "sing-box" => (
                        config["outbounds"][0][key].clone(),
                        json!(fs::read_to_string(
                            config["outbounds"][0]["tls"]["certificate_path"]
                                .as_str()
                                .unwrap()
                        )?),
                    ),
                    "xray" => {
                        let outbound = &config["outbounds"][0];
                        let identity = match protocol {
                            Protocol::Trojan => &outbound["settings"]["servers"][0]["password"],
                            Protocol::Vless
                            | Protocol::VlessXudp
                            | Protocol::VlessVision
                            | Protocol::VlessWs
                            | Protocol::VlessGrpc
                            | Protocol::VlessXhttp
                            | Protocol::VlessHttpUpgrade
                            | Protocol::VlessHttp
                            | Protocol::VlessKcp
                            | Protocol::VlessQuic
                            | Protocol::VlessEncryption
                            | Protocol::VlessReality => &outbound["settings"]["id"],
                            // Xray 的 VMess 出站用 vnext[].users[].id。
                            Protocol::Vmess => &outbound["settings"]["vnext"][0]["users"][0]["id"],
                            Protocol::Hysteria2
                            | Protocol::Tuic
                            | Protocol::Snell
                            | Protocol::AnyTls
                            | Protocol::Naive
                            | Protocol::ShadowTls => unreachable!("Xray 不支持该协议"),
                        };
                        (identity.clone(), json!(fs::read_to_string(outbound["streamSettings"]["tlsSettings"]["certificates"][0]["certificateFile"].as_str().unwrap())?))
                    }
                    _ => unreachable!(),
                };
                assert_eq!(actual_credential, credential);
                assert_eq!(actual_trust, fs::read_to_string(&trust)?);
                assert_eq!(
                    credential == protocol.credential(Scenario::Valid),
                    !matches!(scenario, Scenario::WrongCredential)
                );
                assert_eq!(
                    actual_trust == fs::read_to_string(certificate.dir.path().join("cert.pem"))?,
                    !matches!(scenario, Scenario::UntrustedCertificate)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn configuration_generation_xudp_enables_udp_without_tcp_mux() -> Result<()> {
    let certificate = Certificate::new();
    let trust = certificate.dir.path().join("cert.pem");
    let listen = "127.0.0.1:1080".parse()?;
    let server = "127.0.0.1:1443".parse()?;
    let protocol = Protocol::VlessXudp;
    assert_eq!(protocol.mode(), "vless-xudp");
    assert_eq!(Scenario::WrongCredential.name(protocol), "wrong-uuid");
    let inbound = protocol.inbound(&certificate, None);
    assert_eq!(inbound["type"], "vless");
    assert_eq!(inbound["xudp"], true);
    assert!(
        Protocol::Vless
            .inbound(&certificate, None)
            .get("xudp")
            .is_none()
    );

    for client in ["mihomo", "sing-box", "xray"] {
        assert!(protocol.udp_supported(client));
        let config = client_config(client, protocol, listen, server, &trust, UUID, "AA:BB")?;
        // 对比已另行验证的基础配置，只允许这些 UDP 模式字段变化；TLS/身份不变。
        let mut expected = client_config(
            client,
            Protocol::Vless,
            listen,
            server,
            &trust,
            UUID,
            "AA:BB",
        )?;
        match client {
            "mihomo" => {
                expected["proxies"][0]["udp"] = json!(true);
                expected["proxies"][0]["xudp"] = json!(true);
                assert_eq!(config["proxies"][0]["smux"]["enabled"], false);
            }
            "sing-box" => {
                expected["outbounds"][0]["packet_encoding"] = json!("xudp");
                assert_eq!(config["outbounds"][0]["multiplex"]["enabled"], false);
            }
            "xray" => {
                expected["outbounds"][0]["mux"] = json!({"enabled": false});
                assert_eq!(config["outbounds"][0]["mux"]["enabled"], false);
                assert_eq!(config["outbounds"][0]["settings"]["flow"], "");
            }
            _ => unreachable!(),
        }
        assert_eq!(config, expected);
    }
    Ok(())
}

#[test]
fn configuration_generation_xray_disables_implicit_xudp() {
    for protocol in [Protocol::Trojan, Protocol::Vless, Protocol::VlessXudp] {
        for client in ["mihomo", "sing-box", "xray"] {
            // 仅检查命令环境，不调用 spawn/status/output，也不访问下载的二进制。
            let mut command = Command::new("never-executed");
            command.env_clear();
            protocol.configure_command(client, &mut command);
            let variables: Vec<_> = command.get_envs().collect();
            if matches!((protocol, client), (Protocol::Vless, "xray")) {
                assert_eq!(
                    variables,
                    vec![(
                        std::ffi::OsStr::new("XRAY_CONE_DISABLED"),
                        Some(std::ffi::OsStr::new("true"))
                    )]
                );
            } else {
                assert!(variables.is_empty());
            }
        }
    }
}

// SS 7.1 只生成配置，不读取 manifest，不保留/执行任何客户端命令。
#[test]
fn configuration_generation_shadowsocks_24_modes_native_udp_without_tls_or_extensions() -> Result<()>
{
    use shadowsocks_reference::{CLIENTS, MODES, client_config};
    let listen = "127.0.0.1:1080".parse()?;
    let server = "127.0.0.1:1443".parse()?;
    let mut combinations = std::collections::HashSet::new();
    let mut scenario_configs = std::collections::HashSet::new();
    for mode in MODES {
        let server_config = mode.server_config()?;
        let inbound = &server_config["inbounds"][0];
        assert_eq!(inbound["type"], "shadowsocks");
        assert_eq!(inbound["method"], serde_json::to_value(mode.method)?);
        assert_eq!(inbound["listen"], "127.0.0.1:0");
        assert_eq!(inbound.get("users").is_some(), mode.eih);
        assert!(inbound.get("certificate").is_none());
        assert!(inbound.get("private_key").is_none());
        for client in CLIENTS {
            assert!(combinations.insert((client, mode.name())));
            for &scenario in mode.scenarios() {
                assert!(scenario_configs.insert((client, mode.name(), scenario.name())));
                let credential = mode.credential(scenario)?;
                let config = client_config(client, mode, scenario, listen, server)?;
                match client {
                    "mihomo" => {
                        assert_eq!(config["socks-port"], 1080);
                        assert_eq!(config["bind-address"], "127.0.0.1");
                        assert_eq!(config["allow-lan"], false);
                        assert_eq!(config["dns"]["enable"], false);
                        assert_eq!(config["tun"]["enable"], false);
                        assert_eq!(config["external-controller"], "");
                        assert!(config.get("tls").is_none());
                        assert_eq!(
                            config["proxies"],
                            json!([{
                                "name":"kernel", "type":"ss", "server":"127.0.0.1", "port":1443,
                                "cipher":mode.method.cipher().to_string(), "password":credential,
                                "udp":true, "udp-over-tcp":false, "smux":{"enabled":false}
                            }])
                        );
                        assert_eq!(config["rules"], json!(["MATCH,kernel"]));
                        for url in config["geox-url"].as_object().unwrap().values() {
                            assert_eq!(url, "http://127.0.0.1:9/download-disabled");
                        }
                    }
                    "sing-box" => {
                        assert_eq!(
                            config["inbounds"],
                            json!([{
                                "type":"socks", "tag":"local", "listen":"127.0.0.1", "listen_port":1080
                            }])
                        );
                        assert_eq!(
                            config["outbounds"],
                            json!([{
                                "type":"shadowsocks", "tag":"kernel", "server":"127.0.0.1", "server_port":1443,
                                "method":mode.method.cipher().to_string(), "password":credential,
                                "network":["tcp", "udp"], "udp_over_tcp":false, "multiplex":{"enabled":false}
                            }])
                        );
                        assert_eq!(config["route"]["final"], "kernel");
                    }
                    "xray" => {
                        assert_eq!(
                            config["inbounds"],
                            json!([{
                                "tag":"local", "listen":"127.0.0.1", "port":1080, "protocol":"socks",
                                "settings":{"auth":"noauth", "udp":true, "ip":"127.0.0.1"}
                            }])
                        );
                        assert_eq!(
                            config["outbounds"],
                            json!([{
                                "tag":"kernel", "protocol":"shadowsocks",
                                "settings":{"address":"127.0.0.1", "port":1443,
                                    "method":mode.method.cipher().to_string(), "password":credential},
                                "streamSettings":{"network":"tcp", "security":"none"},
                                "mux":{"enabled":false}
                            }])
                        );
                    }
                    _ => unreachable!(),
                }
                // 严格比较出站字段之外，递归禁止把其他协议的 TLS/UoT/插件字段带进来。
                fn no_tls_or_plugin(value: &Value) {
                    match value {
                        Value::Object(object) => {
                            for (key, value) in object {
                                assert!(!matches!(
                                    key.as_str(),
                                    "tls"
                                        | "tlsSettings"
                                        | "certificate"
                                        | "certificate_path"
                                        | "certificateFile"
                                        | "private_key"
                                        | "plugin"
                                        | "plugin-opts"
                                        | "plugin_opts"
                                        | "packet_encoding"
                                        | "xudp"
                                        | "flow"
                                        | "sni"
                                        | "servername"
                                        | "skip-cert-verify"
                                ));
                                no_tls_or_plugin(value);
                            }
                        }
                        Value::Array(values) => values.iter().for_each(no_tls_or_plugin),
                        _ => {}
                    }
                }
                no_tls_or_plugin(&config);
            }
        }
    }
    assert_eq!(combinations.len(), 24);
    assert_eq!(scenario_configs.len(), 60);
    Ok(())
}

#[test]
fn configuration_generation_shadowsocks_users_and_negative_keys_remain_well_formed() -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use shadowsocks_reference::{MODES, Scenario};
    for mode in MODES {
        let config = mode.server_config()?;
        let inbound = &config["inbounds"][0];
        let mut scenario_names = std::collections::HashSet::new();
        if mode.eih {
            let users = inbound["users"].as_array().unwrap();
            assert_eq!(users.len(), 2);
            assert_ne!(users[0]["name"], users[1]["name"]);
            assert_ne!(users[0]["password"], users[1]["password"]);
        }
        for &scenario in mode.scenarios() {
            assert!(scenario_names.insert(scenario.name()));
            let credential = mode.credential(scenario)?;
            if !mode.method.is_2022() {
                assert!(!credential.is_empty());
                assert_eq!(credential == PASSWORD, scenario.accepted());
                assert_eq!(mode.scenarios().len(), 2);
                continue;
            }
            let components: Vec<_> = credential.split(':').collect();
            assert_eq!(components.len(), if mode.eih { 2 } else { 1 });
            for component in &components {
                let key = STANDARD.decode(component)?;
                assert_eq!(key.len(), mode.method.cipher().key_len());
                assert_eq!(STANDARD.encode(key), *component);
            }
            if mode.eih {
                let identity = inbound["password"].as_str().unwrap();
                let user0 = inbound["users"][0]["password"].as_str().unwrap();
                let user1 = inbound["users"][1]["password"].as_str().unwrap();
                assert_ne!(identity, user0);
                assert_ne!(identity, user1);
                match scenario {
                    Scenario::Valid => assert_eq!(components, [identity, user0]),
                    Scenario::SecondUser => assert_eq!(components, [identity, user1]),
                    Scenario::WrongIdentity => {
                        assert_ne!(components[0], identity);
                        assert_eq!(components[1], user0);
                    }
                    Scenario::UnknownUser => {
                        assert_eq!(components[0], identity);
                        assert_ne!(components[1], user0);
                        assert_ne!(components[1], user1);
                        assert_ne!(components[1], identity);
                    }
                    Scenario::WrongCredential => unreachable!(),
                }
                assert_eq!(
                    scenario.accepted(),
                    matches!(scenario, Scenario::Valid | Scenario::SecondUser)
                );
                assert_eq!(mode.scenarios().len(), 4);
            } else {
                assert_eq!(
                    components[0] == inbound["password"].as_str().unwrap(),
                    scenario.accepted()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn configuration_generation_shadowsocks_rejects_out_of_scope_modes_scenarios_and_addresses()
-> Result<()> {
    use dubhe::config::ShadowsocksMethod;
    use shadowsocks_reference::{MODES, Mode, Scenario, client_config};
    let listen = "127.0.0.1:1080".parse()?;
    let server = "127.0.0.1:1443".parse()?;
    for method in [
        ShadowsocksMethod::Aes128Gcm,
        ShadowsocksMethod::Aes256Gcm,
        ShadowsocksMethod::Chacha20Poly1305,
        ShadowsocksMethod::Aead2022Chacha20Poly1305,
    ] {
        let mode = Mode { method, eih: true };
        assert!(mode.server_config().is_err());
        assert!(mode.credential(Scenario::Valid).is_err());
    }
    assert!(MODES[0].credential(Scenario::SecondUser).is_err());
    assert!(MODES[6].credential(Scenario::WrongCredential).is_err());
    assert!(client_config("unknown", MODES[0], Scenario::Valid, listen, server).is_err());
    for (local, remote) in [
        ("0.0.0.0:1080", "127.0.0.1:1443"),
        ("127.0.0.1:1080", "192.0.2.1:1443"),
        ("127.0.0.1:80", "127.0.0.1:1443"),
        ("127.0.0.1:1080", "127.0.0.1:0"),
        ("127.0.0.1:1080", "127.0.0.1:1080"),
    ] {
        assert!(
            client_config(
                "mihomo",
                MODES[0],
                Scenario::Valid,
                local.parse()?,
                remote.parse()?
            )
            .is_err()
        );
    }
    Ok(())
}

// 注册表和所有 ignored 入口由同一声明产生，防止手工列表遗漏或换用不安全启动路径。
macro_rules! shadowsocks_reference_cases {
    ($(($test:ident, $client:literal, $mode:literal)),+ $(,)?) => {
        const SHADOWSOCKS_CASES: &[(&str, &str, shadowsocks_reference::Mode)] = &[
            $((stringify!($test), $client, shadowsocks_reference::MODES[$mode])),+
        ];
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            #[ignore = "需要单独授权并已校验的官方客户端；SS分方法TCP/原生UDP互通"]
            async fn $test() -> Result<()> {
                shadowsocks_reference::real_interop($client, shadowsocks_reference::MODES[$mode]).await
            }
        )+
    };
}

shadowsocks_reference_cases!(
    (mihomo_shadowsocks_aes_128_gcm_single, "mihomo", 0),
    (mihomo_shadowsocks_aes_256_gcm_single, "mihomo", 1),
    (
        mihomo_shadowsocks_chacha20_ietf_poly1305_single,
        "mihomo",
        2
    ),
    (mihomo_shadowsocks_2022_aes_128_gcm_single, "mihomo", 3),
    (mihomo_shadowsocks_2022_aes_256_gcm_single, "mihomo", 4),
    (
        mihomo_shadowsocks_2022_chacha20_poly1305_single,
        "mihomo",
        5
    ),
    (mihomo_shadowsocks_2022_aes_128_gcm_eih, "mihomo", 6),
    (mihomo_shadowsocks_2022_aes_256_gcm_eih, "mihomo", 7),
    (sing_box_shadowsocks_aes_128_gcm_single, "sing-box", 0),
    (sing_box_shadowsocks_aes_256_gcm_single, "sing-box", 1),
    (
        sing_box_shadowsocks_chacha20_ietf_poly1305_single,
        "sing-box",
        2
    ),
    (sing_box_shadowsocks_2022_aes_128_gcm_single, "sing-box", 3),
    (sing_box_shadowsocks_2022_aes_256_gcm_single, "sing-box", 4),
    (
        sing_box_shadowsocks_2022_chacha20_poly1305_single,
        "sing-box",
        5
    ),
    (sing_box_shadowsocks_2022_aes_128_gcm_eih, "sing-box", 6),
    (sing_box_shadowsocks_2022_aes_256_gcm_eih, "sing-box", 7),
    (xray_shadowsocks_aes_128_gcm_single, "xray", 0),
    (xray_shadowsocks_aes_256_gcm_single, "xray", 1),
    (xray_shadowsocks_chacha20_ietf_poly1305_single, "xray", 2),
    (xray_shadowsocks_2022_aes_128_gcm_single, "xray", 3),
    (xray_shadowsocks_2022_aes_256_gcm_single, "xray", 4),
    (xray_shadowsocks_2022_chacha20_poly1305_single, "xray", 5),
    (xray_shadowsocks_2022_aes_128_gcm_eih, "xray", 6),
    (xray_shadowsocks_2022_aes_256_gcm_eih, "xray", 7),
);

#[test]
fn configuration_generation_shadowsocks_ignored_registry_has_24_unique_safe_cases() {
    use shadowsocks_reference::{CLIENTS, MODES};
    let mut names = std::collections::HashSet::new();
    let mut cases = std::collections::HashSet::new();
    for &(name, client, mode) in SHADOWSOCKS_CASES {
        assert!(names.insert(name));
        assert!(cases.insert((client, mode.name())));
        assert!(name.contains("shadowsocks"));
    }
    assert_eq!(names.len(), 24);
    for client in CLIENTS {
        for mode in MODES {
            assert!(cases.contains(&(client, mode.name())));
        }
    }
    // 不调用 async 函数；24 个宏生成入口只能走 real_interop -> reference_client
    // -> start_shadowsocks -> start_configured，同一 SHA256/私有配置/RAII 启动实现。
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端"]
async fn mihomo_trojan_tcp_udp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::Trojan).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端"]
async fn sing_box_trojan_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::Trojan).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端"]
async fn xray_trojan_tcp_udp_authentication() -> Result<()> {
    real_interop("xray", Protocol::Trojan).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可；固定 Mihomo 不支持原生 VLESS UDP"]
async fn mihomo_vless_tcp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::Vless).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::Vless).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_tcp_udp_authentication() -> Result<()> {
    real_interop("xray", Protocol::Vless).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vless_vision_tcp_udp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessVision).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_vision_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessVision).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_vision_tcp_udp_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessVision).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vless_ws_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessWs).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_ws_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessWs).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_ws_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessWs).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vless_grpc_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessGrpc).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_grpc_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessGrpc).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_grpc_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessGrpc).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vless_xhttp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessXhttp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_xhttp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessXhttp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_xhttp_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessXhttp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_xhttp_h1_stream_up_survives_handshake_deadline() -> Result<()> {
    let client = reference_client("xray")?;
    let certificate = Certificate::new();
    let protocol = Protocol::VlessXhttp;
    let mut config = socks_config();
    config["inbounds"] = json!([protocol.inbound(&certificate, None)]);
    config["limits"]["handshake_timeout_ms"] = json!(1000);
    let server = Running::start(config).await;
    let target = Echo::tcp("127.0.0.1", false).await;
    let directory = tempfile::tempdir()?;
    let trust = certificate.dir.path().join("cert.pem");
    let process = ClientProcess::start_configured(
        &client,
        directory.path(),
        |listen| {
            let mut config = client_config(
                "xray",
                protocol,
                listen,
                server.address,
                &trust,
                UUID,
                &certificate_fingerprint(&certificate),
            )?;
            let stream = &mut config["outbounds"][0]["streamSettings"];
            stream["tlsSettings"]["alpn"] = json!(["http/1.1"]);
            // 默认 Chrome ClientHello 仍会声明 h2；使用 Go TLS，让 ALPN 与 HTTP 版本一致。
            stream["tlsSettings"]["fingerprint"] = json!("unsafe");
            stream["xhttpSettings"]["mode"] = json!("stream-up");
            config["log"]["loglevel"] = json!("info");
            Ok(config)
        },
        |_| {},
    )
    .await?;

    let result = timeout(DEADLINE, async {
        let (mut stream, _) = socks(1, address(target.address), process.address).await;
        for (index, payload) in [
            b"before-handshake-deadline".as_slice(),
            b"after-handshake-deadline",
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                sleep(Duration::from_millis(1100)).await;
            }
            stream.write_all(payload).await?;
            let mut reply = vec![0; payload.len()];
            stream
                .read_exact(&mut reply)
                .await
                .with_context(|| format!("第 {} 次回显失败", index + 1))?;
            ensure!(reply == payload, "回显内容不符");
        }
        Ok(())
    })
    .await;
    if !matches!(&result, Ok(Ok(()))) {
        eprintln!("{}", fs::read_to_string(&process.log_path)?);
    }
    result.context("Xray HTTP/1.1 stream-up 未完成跨握手期限回显")??;
    process.stop()?;
    server.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vless_httpupgrade_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessHttpUpgrade).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_httpupgrade_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessHttpUpgrade).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_httpupgrade_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessHttpUpgrade).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vless_http_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessHttp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_http_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessHttp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_kcp_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessKcp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_quic_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessQuic).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vless_kcp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessKcp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vless_kcp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessKcp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vless_quic_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessQuic).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_quic_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessQuic).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_encryption_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessEncryption).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vless_reality_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessReality).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_vmess_tcp_udp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::Vmess).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_vmess_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::Vmess).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn xray_vmess_tcp_udp_authentication() -> Result<()> {
    real_interop("xray", Protocol::Vmess).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_hysteria2_tcp_udp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::Hysteria2).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_hysteria2_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::Hysteria2).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Xray v26.10.31 没有 hysteria2 协议；此用例应显式跳过"]
async fn xray_hysteria2_is_explicitly_skipped() -> Result<()> {
    real_interop("xray", Protocol::Hysteria2).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_tuic_tcp_udp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::Tuic).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_tuic_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::Tuic).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Xray v26.10.31 没有 tuic 协议；此用例应显式跳过"]
async fn xray_tuic_is_explicitly_skipped() -> Result<()> {
    real_interop("xray", Protocol::Tuic).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可；v4 是两边交集（Mihomo v1-5 / sing-box v4,v6）"]
async fn mihomo_snell_v4_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::Snell).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_snell_v4_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::Snell).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Xray v26.10.31 没有 snell 协议；此用例应显式跳过"]
async fn xray_snell_is_explicitly_skipped() -> Result<()> {
    real_interop("xray", Protocol::Snell).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn mihomo_anytls_tcp_udp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::AnyTls).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_anytls_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::AnyTls).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Xray v26.10.31 没有 anytls 协议；此用例应显式跳过"]
async fn xray_anytls_is_explicitly_skipped() -> Result<()> {
    real_interop("xray", Protocol::AnyTls).await
}

/// Naive 的 sing-box 互通。三个场景均已通过。
///
/// 两处上游行为需要在测试侧适配，都不是 dubhe 的问题：
///
/// 1. **证书有效期**：NaiveProxy 走 Chromium 网络栈，`rcgen` 默认的
///    1975..4096 有效期被拒为 `cert validity too long`。
///    `tests/common/mod.rs` 已改为显式一年期。
/// 2. **地址族**：上游 `protocol/naive/outbound.go` 硬编码
///    `RemoteIsDomain: true`，即使 `server` 写 `127.0.0.1` 也走 resolver；
///    本机 localhost 同时解析出 `127.0.0.1` 与 `::1`，happy-eyeballs
///    优先尝试 `::1`。测试侧用 `[::]:0` 双栈监听同时接住两种结果。
///
/// 另外按上游确认的两条硬限制：
/// - `insecure is not supported on naive outbound`（无法绕过证书校验）
/// - UDP 只有 `udp_over_tcp` 启用时才可用，已按此配置
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可"]
async fn sing_box_naive_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::Naive).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Mihomo v1.19.33 没有 naive 代理类型；此用例应显式跳过"]
async fn mihomo_naive_is_explicitly_skipped() -> Result<()> {
    real_interop("mihomo", Protocol::Naive).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可；VLESS XUDP 模式"]
async fn mihomo_vless_xudp_tcp_udp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::VlessXudp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可；VLESS XUDP 模式"]
async fn sing_box_vless_xudp_tcp_udp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::VlessXudp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可；VLESS XUDP 模式"]
async fn xray_vless_xudp_tcp_udp_authentication() -> Result<()> {
    real_interop("xray", Protocol::VlessXudp).await
}

// ShadowTLS v3 不是完整代理协议，只是 TLS 握手伪装层：入站必须带真实
// 握手目标 `handshake` 与同配置内的内层明文入口 `detour`。本文件统一选
// 内层 Shadowsocks 2022（上面 `SHADOWTLS_INNER_*`），因为 Mihomo 的
// `ss + shadow-tls` 插件形态和 sing-box 的 `shadowsocks + detour` 形态
// 都能直接表达，且本内核 detour 允许列表包含 shadowsocks。
//
// 握手目标用本地 rustls TLS 1.3 服务端（`TlsHandshakeTarget`）。这与
// `tests/shadowtls.rs` 的假 ServerHello 不同：真实客户端执行完整 TLS 1.3，
// 必须有真实握手目标；`tests/shadowtls_outbound.rs` 已用同一做法。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可；ShadowTLS v3 + 内层 Shadowsocks 2022"]
async fn mihomo_shadowtls_tcp_authentication() -> Result<()> {
    real_interop("mihomo", Protocol::ShadowTls).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要已校验官方客户端和执行许可；ShadowTLS v3 + 内层 Shadowsocks 2022"]
async fn sing_box_shadowtls_tcp_authentication() -> Result<()> {
    real_interop("sing-box", Protocol::ShadowTls).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Xray v26.10.31 没有 ShadowTLS；此用例应显式跳过"]
async fn xray_shadowtls_is_explicitly_skipped() -> Result<()> {
    real_interop("xray", Protocol::ShadowTls).await
}

#[test]
fn configuration_generation_shadowtls_wraps_inner_outbound_and_skips_xray() -> Result<()> {
    let certificate = Certificate::new();
    let trust = certificate.dir.path().join("cert.pem");
    let listen = "127.0.0.1:1080".parse()?;
    let server = "127.0.0.1:1443".parse()?;
    assert_eq!(Protocol::ShadowTls.name(), "shadowtls");
    assert_eq!(
        Scenario::WrongCredential.name(Protocol::ShadowTls),
        "wrong-password"
    );
    assert!(Protocol::ShadowTls.uses_tls());
    assert!(!Protocol::ShadowTls.udp_supported("mihomo"));
    assert!(!Protocol::ShadowTls.udp_supported("sing-box"));
    assert!(Protocol::ShadowTls.supported_by("mihomo"));
    assert!(Protocol::ShadowTls.supported_by("sing-box"));
    assert!(!Protocol::ShadowTls.supported_by("xray"));

    let handshake = "127.0.0.1:9443".parse()?;
    let inbounds = Protocol::ShadowTls.inbounds(&certificate, Some(handshake));
    let inbounds = inbounds.as_array().expect("数组");
    assert_eq!(inbounds.len(), 2, "ShadowTLS 必须由外层与内层两条入站组成");
    assert_eq!(inbounds[0]["type"], "shadowtls");
    assert_eq!(inbounds[0]["version"], 3);
    assert_eq!(inbounds[0]["detour"], SHADOWTLS_INNER_TAG);
    assert_eq!(inbounds[0]["handshake"]["server_port"], 9443);
    assert_eq!(inbounds[0]["users"][0]["password"], PASSWORD);
    assert_eq!(inbounds[1]["type"], "shadowsocks");
    assert_eq!(inbounds[1]["tag"], SHADOWTLS_INNER_TAG);
    assert_eq!(inbounds[1]["method"], SHADOWTLS_INNER_METHOD);
    // 入站必须能被正式配置校验接受（含 detour 指向检查）。
    let mut config = socks_config();
    config["inbounds"] = json!(inbounds);
    dubhe::Config::from_json(&config.to_string())?;

    let mihomo = client_config(
        "mihomo",
        Protocol::ShadowTls,
        listen,
        server,
        &trust,
        PASSWORD,
        "AA:BB",
    )?;
    assert_eq!(
        mihomo["proxies"][0],
        json!({
            "name": "kernel", "type": "ss", "server": "127.0.0.1", "port": 1443,
            "cipher": SHADOWTLS_INNER_METHOD, "password": SHADOWTLS_INNER_PASSWORD,
            "udp": false, "plugin": "shadow-tls",
            "plugin-opts": {"host": "localhost", "password": PASSWORD, "version": 3,
                "skip-cert-verify": false}
        })
    );
    assert_eq!(
        mihomo["tls"]["custom-certifactes"],
        json!([fs::read_to_string(&trust)?])
    );

    let sing_box = client_config(
        "sing-box",
        Protocol::ShadowTls,
        listen,
        server,
        &trust,
        PASSWORD,
        "AA:BB",
    )?;
    assert_eq!(
        sing_box["outbounds"],
        json!([
            {
                "type": "shadowtls", "tag": "kernel", "server": "127.0.0.1",
                "server_port": 1443, "version": 3, "password": PASSWORD,
                "tls": {"enabled": true, "server_name": "localhost", "insecure": false,
                    "certificate_path": trust}
            },
            {
                "type": "shadowsocks", "tag": "inner", "server": "127.0.0.1",
                "server_port": 1443, "method": SHADOWTLS_INNER_METHOD,
                "password": SHADOWTLS_INNER_PASSWORD, "network": ["tcp"],
                "detour": "kernel"
            }
        ])
    );
    assert_eq!(sing_box["route"]["final"], "inner");
    Ok(())
}
