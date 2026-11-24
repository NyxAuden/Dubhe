//! 从 dubhe 配置导出客户端配置。
//!
//! 方向与 `convert` 相反：服务端跑 dubhe，客户端用 Xray / sing-box / Mihomo /
//! Anywhere。只导出「客户端能直接导入」的字段；协议能力有差异时跳过并在报告里
//! 说明，不生成半可用的配置。

use std::net::SocketAddr;

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use crate::config::{Config, Inbound, VlessFlow};

/// 一个可导出的客户端节点。
#[derive(Debug, Clone)]
pub struct Node {
    /// 展示名，取自入口 tag。
    pub tag: String,
    /// 客户端连接的服务器地址（来自 `--host`，因为配置里通常是 0.0.0.0）。
    pub host: String,
    pub port: u16,
    /// 协议族；决定各目标格式能导出哪些字段。
    pub protocol: Protocol,
    pub security: Security,
    pub transport: Transport,
    pub credential: Credential,
    /// VLESS Encryption 的客户端 `encryption` 串；由服务端 `decryption` 推导。
    pub vless_encryption: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
    AnyTls,
    Snell,
    Nw3,
    Naive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    None,
    Tls {
        server_name: Option<String>,
    },
    Reality {
        public_key: String,
        short_id: String,
        server_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Ws {
        path: String,
        host: Option<String>,
    },
    Grpc {
        path: String,
        multi: bool,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    Xhttp {
        path: String,
        host: Option<String>,
        mode: String,
    },
    /// mKCP 自带加密层，没有 TLS/REALITY。
    Kcp,
    /// V2Ray HTTP 传输（h1/h2）。
    Http {
        path: String,
        host: Option<String>,
    },
    /// V2Ray QUIC 传输（sing-box 形状）。
    Quic,
}

#[derive(Debug, Clone)]
pub enum Credential {
    Uuid {
        uuid: String,
        flow: Option<String>,
    },
    Password {
        password: String,
    },
    /// Naive 的代理认证是 `用户名:密码`，空用户名会被服务端 407 拒绝。
    Naive {
        username: String,
        password: String,
    },
    Shadowsocks {
        method: String,
        password: String,
    },
    Tuic {
        uuid: String,
        password: String,
        congestion_control: Option<String>,
        /// 服务端非空时客户端必须发送其中至少一个值，否则 TLS 握手失败。
        alpn: Vec<String>,
    },
    Hysteria2 {
        password: String,
        obfs: Option<ObfsOptions>,
        /// Brutal 拥塞控制的声明带宽（Mbps）；只影响性能，不影响连通性。
        up_mbps: Option<u64>,
        down_mbps: Option<u64>,
    },
    Snell {
        psk: String,
        version: u8,
        userkey: Option<String>,
        /// v6 记录模式：default / unshaped / unsafe-raw。
        mode: Option<String>,
        /// v4/v5 的 http/tls 混淆。
        obfs_mode: Option<String>,
    },
    Nw3 {
        key: String,
        morph: bool,
    },
}

/// Hysteria2 的混淆参数；只在客户端支持时导出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfsOptions {
    pub kind: String,
    pub password: String,
    pub min_packet_size: Option<u64>,
    pub max_packet_size: Option<u64>,
}

/// 导出报告：目标格式不支持的节点与原因。
#[derive(Debug, Default)]
pub struct ExportReport {
    pub notes: Vec<String>,
}

impl ExportReport {
    /// 某个目标被跳过的节点数；`skip` 的记录都带 `[target]` 前缀。
    fn skipped(&self, target: Target) -> usize {
        let prefix = format!("[{}] 跳过 ", target.name());
        self.notes
            .iter()
            .filter(|note| note.starts_with(&prefix))
            .count()
    }

    fn skip(&mut self, target: &str, tag: &str, reason: &str) {
        self.notes.push(format!("[{target}] 跳过 {tag}：{reason}"));
    }
}

/// 支持的目标格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Xray,
    SingBox,
    Mihomo,
    Anywhere,
}

impl Target {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "xray" => Ok(Self::Xray),
            "sing-box" => Ok(Self::SingBox),
            "mihomo" => Ok(Self::Mihomo),
            "anywhere" => Ok(Self::Anywhere),
            other => {
                bail!("暂不支持的导出目标 {other}（支持 xray / sing-box / mihomo / anywhere）")
            }
        }
    }

    /// 输出文件名（不含扩展名）。
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Xray => "xray-client",
            Self::SingBox => "sing-box-client",
            Self::Mihomo => "mihomo-client",
            Self::Anywhere => "anywhere-ajson",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
            Self::Mihomo => "mihomo",
            Self::Anywhere => "anywhere",
        }
    }
}

/// 从服务端配置里提取可导出的节点。
///
/// `host` 是客户端实际连接的地址；配置里的 `listen` 通常是 `0.0.0.0`，不能直接用。
pub fn nodes(config: &Config, host: &str, report: &mut ExportReport) -> Vec<Node> {
    let mut nodes = Vec::new();
    for inbound in &config.inbounds {
        // 每个入口只导出第一个用户；多用户必须显式提示，否则会静默少人。
        let count = user_count(inbound);
        if count > 1 {
            report.notes.push(format!(
                "[all] {} 有 {count} 个用户，只导出第一个；其余请手工复制成多条",
                inbound.tag()
            ));
        }
        // Shadowsocks 多用户导出的是身份密钥，不是任何一个用户的密钥。
        if let Some(users) = shadowsocks_users(inbound)
            && !users.is_empty()
        {
            report.notes.push(format!(
                "[all] {} 是多用户 Shadowsocks，导出的是身份密钥；每个用户需手工替换 password",
                inbound.tag()
            ));
        }
        match node_from(inbound, host) {
            Ok(Some(node)) => nodes.push(node),
            // 走到这里只剩「没有用户」一种情况（其余入口都会返回错误）。
            Ok(None) => report.skip("all", inbound.tag(), "没有用户，无法生成客户端凭据"),
            Err(error) => report.skip("all", inbound.tag(), &format!("{error}")),
        }
    }
    nodes
}

/// Shadowsocks 多用户列表；其它入站返回 `None`。
fn shadowsocks_users(inbound: &Inbound) -> Option<&[crate::config::User]> {
    match inbound {
        Inbound::Shadowsocks { users, .. } => users.as_deref(),
        _ => None,
    }
}

/// 入站的用户数量；单密钥协议返回 0。
fn user_count(inbound: &Inbound) -> usize {
    match inbound {
        // VLESS 家族的 users 是 Vec<VlessUser>。
        Inbound::Vless { users, .. }
        | Inbound::VlessReality { users, .. }
        | Inbound::VlessWs { users, .. }
        | Inbound::VlessGrpc { users, .. }
        | Inbound::VlessXhttp { users, .. }
        | Inbound::VlessHttpUpgrade { users, .. }
        | Inbound::VlessKcp { users, .. } => users.len(),
        // VMess 家族是 Vec<VmessUser>。
        Inbound::Vmess { users, .. }
        | Inbound::VmessReality { users, .. }
        | Inbound::VmessWs { users, .. }
        | Inbound::VmessGrpc { users, .. }
        | Inbound::VmessXhttp { users, .. }
        | Inbound::VmessHttpUpgrade { users, .. }
        | Inbound::VmessKcp { users, .. } => users.len(),
        // Trojan/Hysteria2/AnyTLS 是 Vec<User>。
        Inbound::Trojan { users, .. }
        | Inbound::TrojanReality { users, .. }
        | Inbound::TrojanWs { users, .. }
        | Inbound::TrojanGrpc { users, .. }
        | Inbound::TrojanXhttp { users, .. }
        | Inbound::TrojanHttpUpgrade { users, .. }
        | Inbound::TrojanKcp { users, .. }
        | Inbound::Hysteria2 { users, .. }
        | Inbound::AnyTls { users, .. } => users.len(),
        // TUIC 是 Vec<TuicUser>。
        Inbound::Tuic { users, .. } => users.len(),
        _ => 0,
    }
}

fn port_of(address: &SocketAddr) -> u16 {
    address.port()
}

/// 由服务端 `decryption` 推导客户端 `encryption`。
///
/// 两侧是同一密钥对的两半：X25519 私钥 → 公钥是标量乘，ML-KEM-768 种子 →
/// 封装公钥是确定性展开。因此导出不需要用户再跑一次 `xray vlessenc`。
/// 2026-11-22 用 `xray v25519 -i` / `xray mlkem768 -i` 的官方输出逐字节核对过。
fn vless_encryption_of(decryption: &Option<String>) -> Result<Option<String>> {
    let Some(value) = decryption.as_deref() else {
        return Ok(None);
    };
    crate::config::vless_encryption::client_from_decryption(value)
}

fn node_from(inbound: &Inbound, host: &str) -> Result<Option<Node>> {
    let tag = inbound.tag().to_owned();
    let port = port_of(&inbound.listen());
    let base = |protocol, security, transport, credential, vless_encryption: Option<String>| Node {
        tag: tag.clone(),
        host: host.to_owned(),
        port,
        protocol,
        security,
        transport,
        credential,
        vless_encryption,
    };

    let node = match inbound {
        Inbound::VlessKcp {
            users, decryption, ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                Security::None,
                Transport::Kcp,
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                vless_encryption,
            )
        }
        Inbound::VmessKcp { users, .. } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                Security::None,
                Transport::Kcp,
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::TrojanKcp { users, .. } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                Security::None,
                Transport::Kcp,
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::Vless {
            users,
            decryption,
            certificate,
            ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                tls_or_reality(&None, certificate)?,
                Transport::Tcp,
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: flow(&user.flow),
                },
                vless_encryption,
            )
        }
        Inbound::VlessReality {
            users,
            decryption,
            reality,
            ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                reality_security(reality)?,
                Transport::Tcp,
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: flow(&user.flow),
                },
                vless_encryption,
            )
        }
        Inbound::VlessWs {
            users,
            decryption,
            websocket,
            reality,
            certificate,
            ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                tls_or_reality(reality, certificate)?,
                Transport::Ws {
                    path: websocket.path.clone(),
                    host: websocket.host.clone(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                vless_encryption,
            )
        }
        Inbound::VlessGrpc {
            users,
            decryption,
            grpc,
            reality,
            certificate,
            ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                tls_or_reality(reality, certificate)?,
                Transport::Grpc {
                    path: grpc.path.clone(),
                    multi: grpc.multi_path.is_some(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                vless_encryption,
            )
        }
        Inbound::VlessXhttp {
            users,
            decryption,
            xhttp,
            reality,
            certificate,
            ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                tls_or_reality(reality, certificate)?,
                Transport::Xhttp {
                    path: xhttp.path.clone(),
                    host: xhttp.host.clone(),
                    mode: xhttp_mode(xhttp.mode).to_owned(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                vless_encryption,
            )
        }
        Inbound::VlessHttpUpgrade {
            users,
            decryption,
            httpupgrade,
            reality,
            certificate,
            ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                tls_or_reality(reality, certificate)?,
                Transport::HttpUpgrade {
                    path: httpupgrade.path.clone(),
                    host: httpupgrade.host.clone(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                vless_encryption,
            )
        }
        Inbound::Vmess {
            users, certificate, ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                tls_or_reality(&None, certificate)?,
                Transport::Tcp,
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::VmessWs {
            users,
            websocket,
            reality,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                tls_or_reality(reality, certificate)?,
                Transport::Ws {
                    path: websocket.path.clone(),
                    host: websocket.host.clone(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::VmessGrpc {
            users,
            grpc,
            reality,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                tls_or_reality(reality, certificate)?,
                Transport::Grpc {
                    path: grpc.path.clone(),
                    multi: grpc.multi_path.is_some(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::VmessXhttp {
            users,
            xhttp,
            reality,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                tls_or_reality(reality, certificate)?,
                Transport::Xhttp {
                    path: xhttp.path.clone(),
                    host: xhttp.host.clone(),
                    mode: xhttp_mode(xhttp.mode).to_owned(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::VmessHttpUpgrade {
            users,
            httpupgrade,
            reality,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                tls_or_reality(reality, certificate)?,
                Transport::HttpUpgrade {
                    path: httpupgrade.path.clone(),
                    host: httpupgrade.host.clone(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::Trojan { users, .. } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                Security::Tls { server_name: None },
                Transport::Tcp,
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::TrojanReality { users, reality, .. } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                reality_security(reality)?,
                Transport::Tcp,
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::TrojanWs {
            users,
            websocket,
            reality,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                tls_or_reality(reality, certificate)?,
                Transport::Ws {
                    path: websocket.path.clone(),
                    host: websocket.host.clone(),
                },
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::Shadowsocks {
            method, password, ..
        } => base(
            Protocol::Shadowsocks,
            Security::None,
            Transport::Tcp,
            Credential::Shadowsocks {
                method: method_name(*method),
                password: password.0.clone(),
            },
            None,
        ),
        Inbound::Hysteria2 {
            users,
            obfs,
            up_mbps,
            down_mbps,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Hysteria2,
                Security::Tls { server_name: None },
                Transport::Tcp,
                Credential::Hysteria2 {
                    password: user.password.clone(),
                    up_mbps: *up_mbps,
                    down_mbps: *down_mbps,
                    obfs: obfs.as_ref().map(|obfs| ObfsOptions {
                        kind: match obfs.kind {
                            crate::config::Hysteria2ObfsType::Salamander => "salamander",
                            crate::config::Hysteria2ObfsType::Gecko => "gecko",
                        }
                        .to_owned(),
                        password: obfs.password.0.clone(),
                        min_packet_size: obfs.min_packet_size,
                        max_packet_size: obfs.max_packet_size,
                    }),
                },
                None,
            )
        }
        Inbound::Tuic {
            users,
            congestion_control,
            alpn,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Tuic,
                Security::Tls { server_name: None },
                Transport::Tcp,
                Credential::Tuic {
                    uuid: user.uuid.clone(),
                    password: user.password.0.clone(),
                    congestion_control: congestion_control.clone(),
                    alpn: alpn.clone(),
                },
                None,
            )
        }
        Inbound::AnyTls { users, .. } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::AnyTls,
                Security::Tls { server_name: None },
                Transport::Tcp,
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::Snell {
            psk,
            version,
            users,
            obfs_mode,
            mode,
            ..
        } => base(
            Protocol::Snell,
            Security::None,
            Transport::Tcp,
            Credential::Snell {
                psk: psk.0.clone(),
                version: *version,
                // v6 的 userkey 是客户端身份，必须带出，否则服务端分不清用户。
                userkey: users.first().map(|user| user.userkey.0.clone()),
                mode: mode.clone(),
                obfs_mode: obfs_mode.clone(),
            },
            None,
        ),
        Inbound::VlessHttp {
            users,
            decryption,
            http,
            certificate,
            ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                tls_or_reality(&None, certificate)?,
                Transport::Http {
                    path: http.path.clone(),
                    host: http.host.first().cloned(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                vless_encryption,
            )
        }
        Inbound::VmessHttp {
            users,
            http,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                tls_or_reality(&None, certificate)?,
                Transport::Http {
                    path: http.path.clone(),
                    host: http.host.first().cloned(),
                },
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::TrojanHttp {
            users,
            http,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                tls_or_reality(&None, certificate)?,
                Transport::Http {
                    path: http.path.clone(),
                    host: http.host.first().cloned(),
                },
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::VlessQuic {
            users,
            decryption,
            certificate,
            ..
        } => {
            let vless_encryption = vless_encryption_of(decryption)?;
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vless,
                tls_or_reality(&None, &Some(certificate.clone()))?,
                Transport::Quic,
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                vless_encryption,
            )
        }
        Inbound::VmessQuic {
            users, certificate, ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                tls_or_reality(&None, &Some(certificate.clone()))?,
                Transport::Quic,
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::TrojanQuic {
            users, certificate, ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                tls_or_reality(&None, &Some(certificate.clone()))?,
                Transport::Quic,
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::Naive {
            users,
            h3,
            h1_padding,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            // Naive 必须 TLS；H2 是默认形态，h3 只影响 UDP 承载。
            let _ = (h3, h1_padding);
            base(
                Protocol::Naive,
                Security::Tls { server_name: None },
                Transport::Tcp,
                Credential::Naive {
                    username: user.name.clone(),
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::Nw3 {
            key,
            morph,
            certificate,
            ..
        } => base(
            Protocol::Nw3,
            if certificate.is_some() {
                Security::Tls { server_name: None }
            } else {
                // Nowhere 的 tls=1 是 Portal 自签名；客户端不做 CA 校验。
                Security::Reality {
                    public_key: String::new(),
                    short_id: String::new(),
                    server_name: String::new(),
                }
            },
            Transport::Tcp,
            Credential::Nw3 {
                key: key.clone(),
                morph: *morph,
            },
            None,
        ),
        Inbound::VmessReality { users, reality, .. } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Vmess,
                reality_security(reality)?,
                Transport::Tcp,
                Credential::Uuid {
                    uuid: user.uuid.clone(),
                    flow: None,
                },
                None,
            )
        }
        Inbound::TrojanGrpc {
            users,
            grpc,
            reality,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                tls_or_reality(reality, certificate)?,
                Transport::Grpc {
                    path: grpc.path.clone(),
                    multi: grpc.multi_path.is_some(),
                },
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::TrojanHttpUpgrade {
            users,
            httpupgrade,
            reality,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                tls_or_reality(reality, certificate)?,
                Transport::HttpUpgrade {
                    path: httpupgrade.path.clone(),
                    host: httpupgrade.host.clone(),
                },
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        Inbound::TrojanXhttp {
            users,
            xhttp,
            reality,
            certificate,
            ..
        } => {
            let Some(user) = users.first() else {
                return Ok(None);
            };
            base(
                Protocol::Trojan,
                tls_or_reality(reality, certificate)?,
                Transport::Xhttp {
                    path: xhttp.path.clone(),
                    host: xhttp.host.clone(),
                    mode: xhttp_mode(xhttp.mode).to_owned(),
                },
                Credential::Password {
                    password: user.password.clone(),
                },
                None,
            )
        }
        // 本地代理入口：用户连的是本机端口，导出成远端节点没有意义。
        Inbound::Socks5 { .. } | Inbound::Http { .. } | Inbound::Mixed { .. } => {
            anyhow::bail!("本地代理入口（socks/http/mixed），不是远端节点");
        }
        Inbound::DokodemoDoor { .. } => {
            anyhow::bail!("dokodemo-door 是透明代理入口，没有对应的客户端协议");
        }
        // 客户端必须持有自己的私钥，服务端配置里只有客户端的公钥。
        Inbound::Wireguard { .. } => {
            anyhow::bail!("WireGuard 客户端需要客户端私钥，服务端配置中不存在，无法生成");
        }
        // 客户端侧 ShadowTLS 要与内层协议组成两条出站，且 Mihomo 无此类型。
        Inbound::ShadowTls { .. } => {
            anyhow::bail!("ShadowTLS 需与内层协议组合成两条出站，暂不自动生成");
        }
    };
    Ok(Some(node))
}

fn flow(value: &VlessFlow) -> Option<String> {
    match value {
        VlessFlow::None => None,
        VlessFlow::Vision => Some("xtls-rprx-vision".to_owned()),
    }
}

fn reality_security(reality: &crate::config::Reality) -> Result<Security> {
    let prepared = reality.prepare()?;
    let public_key = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        prepared.public_key,
    );
    Ok(Security::Reality {
        public_key,
        short_id: reality
            .short_ids
            .first()
            .map(|value| value.0.clone())
            .unwrap_or_default(),
        server_name: reality.server_names.first().cloned().unwrap_or_default(),
    })
}

fn tls_or_reality(
    reality: &Option<crate::config::Reality>,
    certificate: &Option<std::path::PathBuf>,
) -> Result<Security> {
    Ok(match reality {
        Some(reality) => reality_security(reality)?,
        None if certificate.is_some() => Security::Tls { server_name: None },
        None => Security::None,
    })
}

fn method_name(method: crate::config::ShadowsocksMethod) -> String {
    use crate::config::ShadowsocksMethod as M;
    match method {
        M::Aes128Gcm => "aes-128-gcm",
        M::Aes256Gcm => "aes-256-gcm",
        M::Chacha20Poly1305 => "chacha20-ietf-poly1305",
        M::Aead2022Aes128Gcm => "2022-blake3-aes-128-gcm",
        M::Aead2022Aes256Gcm => "2022-blake3-aes-256-gcm",
        M::Aead2022Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
    }
    .to_owned()
}

/// 生成目标格式的配置。
pub fn export(target: Target, nodes: &[Node], report: &mut ExportReport) -> Result<Value> {
    let skipped_before = report.skipped(target);
    let value = match target {
        Target::Xray => export_xray(nodes, report),
        Target::SingBox => export_sing_box(nodes, report),
        Target::Mihomo => export_mihomo(nodes, report),
        Target::Anywhere => export_anywhere(nodes, report),
    };
    // 某个目标把所有节点都跳过时，继续输出只会得到一份「纯直连」的客户端
    // 配置：用户看到加载成功、目标也能访问，实际上流量根本没走服务器。
    anyhow::ensure!(
        report.skipped(target) - skipped_before < nodes.len(),
        "{} 没有可用节点；拒绝生成纯直连的客户端配置",
        target.name()
    );
    Ok(value)
}

/// 辅助出站/代理组的名字不能与节点 tag 或固定入站 tag 冲突。
///
/// Xray 的 tag 是全局的：入站叫 `socks-in`，用户节点也叫 `direct` 时，
/// 固定出站 `direct` 会撞名，`xray run -test` 直接失败。
fn free_name<'a>(base: &str, taken: impl IntoIterator<Item = &'a str>) -> String {
    let taken: Vec<&str> = taken.into_iter().collect();
    if !taken.contains(&base) {
        return base.to_owned();
    }
    for index in 1.. {
        let candidate = format!("{base}-{index}");
        if !taken.contains(&candidate.as_str()) {
            return candidate;
        }
    }
    unreachable!("候选名字无限递增，必然会空闲")
}

/// Xray 客户端配置：`outbounds` 里每个节点一个 vnext/server。
fn export_xray(nodes: &[Node], report: &mut ExportReport) -> Value {
    // Xray 用**第一个出站**作为默认路由。此前的实现把 `freedom` 放在首位，
    // 于是导出配置名义上带着节点、实际全部直连——实测客户端启动成功、
    // 目标也访问成功，反而最难察觉流量没走服务器。
    let mut converted = Vec::new();
    for node in nodes {
        match xray_outbound(node) {
            Ok(value) => converted.push(value),
            Err(reason) => report.skip(Target::Xray.name(), &node.tag, &reason),
        }
    }
    let primary = converted
        .first()
        .and_then(|value| value.get("tag"))
        .cloned()
        .unwrap_or_else(|| json!("direct"));
    let direct = free_name(
        "direct",
        nodes
            .iter()
            .map(|node| node.tag.as_str())
            .chain(std::iter::once("socks-in")),
    );
    let mut outbounds = converted;
    outbounds.push(json!({"tag": direct, "protocol": "freedom"}));
    let mut route = json!({"domainStrategy": "AsIs"});
    if primary != json!("direct") {
        route["rules"] = json!([]);
    }
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": 1080,
            "protocol": "socks",
            "settings": {"udp": true}
        }],
        "outbounds": outbounds,
        "routing": route
    })
}

fn xray_outbound(node: &Node) -> std::result::Result<Value, String> {
    // Xray 文档：REALITY 只能与 RAW、XHTTP、gRPC 组合。
    if matches!(node.security, Security::Reality { .. })
        && matches!(
            node.transport,
            Transport::Ws { .. } | Transport::HttpUpgrade { .. }
        )
    {
        return Err("Xray 的 REALITY 只支持 RAW/XHTTP/gRPC，不支持该承载".to_owned());
    }
    // Xray v26 拒绝「无 TLS/REALITY 且目标是公网地址」的 VLESS/Trojan 出站。
    // 导出到公网时提前跳过，避免生成加载不了的配置。
    if node.security == Security::None
        && matches!(node.protocol, Protocol::Vless | Protocol::Trojan)
        && !is_private_host(&node.host)
    {
        return Err(
            "Xray 禁止无 TLS/REALITY 的 VLESS/Trojan 出站指向公网地址；请改用 TLS/REALITY 或私有地址"
                .to_owned(),
        );
    }
    let mut out = Map::new();
    out.insert("tag".into(), json!(node.tag));
    let mut stream = Map::new();
    match node.transport {
        Transport::Tcp => {
            // Xray 把 Hysteria2 的承载协商放在 network 上，不是普通 TCP。
            let network = if node.protocol == Protocol::Hysteria2 {
                "hysteria"
            } else {
                "tcp"
            };
            stream.insert("network".into(), json!(network));
        }
        Transport::Ws { ref path, ref host } => {
            stream.insert("network".into(), json!("ws"));
            let mut ws = Map::new();
            ws.insert("path".into(), json!(path));
            if let Some(host) = host {
                // 客户端发送 host 的优先级：host > headers > address。
                ws.insert("host".into(), json!(host));
            }
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        Transport::Grpc { ref path, .. } => {
            stream.insert("network".into(), json!("grpc"));
            let mut grpc = Map::new();
            // 单流客户端对两条路径都可用；导出只写完整路径，不启用 multiMode。
            grpc.insert("serviceName".into(), json!(xray_grpc_name(path)?));
            stream.insert("grpcSettings".into(), Value::Object(grpc));
        }
        Transport::HttpUpgrade { ref path, ref host } => {
            stream.insert("network".into(), json!("httpupgrade"));
            let mut up = Map::new();
            up.insert("path".into(), json!(path));
            if let Some(host) = host {
                up.insert("host".into(), json!(host));
            }
            stream.insert("httpupgradeSettings".into(), Value::Object(up));
        }
        Transport::Xhttp {
            ref path,
            ref host,
            ref mode,
        } => {
            stream.insert("network".into(), json!("xhttp"));
            let mut xhttp = Map::new();
            xhttp.insert("path".into(), json!(path));
            if let Some(host) = host {
                xhttp.insert("host".into(), json!(host));
            }
            xhttp.insert("mode".into(), json!(mode));
            stream.insert("xhttpSettings".into(), Value::Object(xhttp));
        }
        Transport::Kcp => {
            // 具体的 mtu/tti 由服务端 kcp 配置决定；导出时只声明承载类型。
            stream.insert("network".into(), json!("kcp"));
        }
        Transport::Http { .. } => {
            // Xray v26 已移除 HTTP transport（文档仍列 `httpSettings`，实机拒绝）；
            // 官方建议改用 XHTTP stream-one。这里明确跳过，不生成加载不了的配置。
            return Err("Xray v26 已移除 HTTP transport，请改用 XHTTP stream-one".to_owned());
        }
        Transport::Quic => {
            return Err("Xray v26 已移除旧 QUIC 传输，请改用 XHTTP/3".to_owned());
        }
    }

    match &node.security {
        Security::None => {
            stream.insert("security".into(), json!("none"));
        }
        Security::Tls { server_name } => {
            stream.insert("security".into(), json!("tls"));
            let mut tls = Map::new();
            if let Some(name) = server_name {
                tls.insert("serverName".into(), json!(name));
            }
            stream.insert("tlsSettings".into(), Value::Object(tls));
        }
        Security::Reality {
            public_key,
            short_id,
            server_name,
        } => {
            stream.insert("security".into(), json!("reality"));
            stream.insert(
                "realitySettings".into(),
                json!({
                    "serverName": server_name,
                    // 新版字段名是 password（旧名 publicKey 仍作为别名保留）。
                    "password": public_key,
                    "shortId": short_id,
                    "fingerprint": "chrome",
                }),
            );
        }
    }
    out.insert("streamSettings".into(), Value::Object(stream));

    // Xray v26 起 outbound settings 是扁平结构：不再有 vnext/servers 数组。
    match (&node.protocol, &node.credential) {
        (Protocol::Vless, Credential::Uuid { uuid, flow }) => {
            out.insert("protocol".into(), json!("vless"));
            let mut settings = json!({
                "address": node.host,
                "port": node.port,
                "id": uuid,
                // 该字段不能留空；关闭时必须显式写 "none"。
                "encryption": "none",
            });
            if let Some(flow) = flow {
                settings["flow"] = json!(flow);
            }
            // 由服务端 decryption 推导出的客户端 encryption；
            // 未启用时保持上面的 "none"。
            if let Some(encryption) = &node.vless_encryption {
                settings["encryption"] = json!(encryption);
            }
            out.insert("settings".into(), settings);
        }
        (Protocol::Vmess, Credential::Uuid { uuid, .. }) => {
            out.insert("protocol".into(), json!("vmess"));
            out.insert(
                "settings".into(),
                json!({
                    "address": node.host,
                    "port": node.port,
                    "id": uuid,
                    "security": "auto",
                }),
            );
        }
        (Protocol::Trojan, Credential::Password { password }) => {
            out.insert("protocol".into(), json!("trojan"));
            out.insert(
                "settings".into(),
                json!({
                    "address": node.host,
                    "port": node.port,
                    "password": password,
                }),
            );
        }
        (Protocol::Shadowsocks, Credential::Shadowsocks { method, password }) => {
            out.insert("protocol".into(), json!("shadowsocks"));
            out.insert(
                "settings".into(),
                json!({
                    "address": node.host,
                    "port": node.port,
                    "method": method,
                    "password": password,
                }),
            );
        }
        (
            Protocol::Hysteria2,
            Credential::Hysteria2 {
                password,
                obfs,
                up_mbps,
                down_mbps,
            },
        ) => {
            out.insert("protocol".into(), json!("hysteria"));
            out.insert(
                "settings".into(),
                json!({
                    "version": 2,
                    "address": node.host,
                    "port": node.port,
                }),
            );
            // streamSettings 已提前写入；Xray 的 Hysteria2 认证/混淆都在其中。
            let stream = out
                .get_mut("streamSettings")
                .and_then(Value::as_object_mut)
                .expect("streamSettings 已写入");
            let mut hysteria = json!({"version": 2, "auth": password});
            if let Some(mbps) = up_mbps {
                hysteria["up_mbps"] = json!(mbps);
            }
            if let Some(mbps) = down_mbps {
                hysteria["down_mbps"] = json!(mbps);
            }
            stream.insert("hysteriaSettings".into(), hysteria);
            // Xray 用 FinalMask 的 UDP 层表达 obfs；不写就无法与带混淆的服务端握手。
            if let Some(obfs) = obfs {
                let mut settings = json!({"password": obfs.password});
                if obfs.kind == "gecko" {
                    settings["packetSize"] = json!(format!(
                        "{}-{}",
                        obfs.min_packet_size.unwrap_or(512),
                        obfs.max_packet_size.unwrap_or(1200)
                    ));
                }
                stream.insert(
                    "finalmask".into(),
                    json!({"udp": [{"type": "salamander", "settings": settings}]}),
                );
            }
        }
        _ => {
            return Err(format!("{:?} 不是 Xray 支持的出站协议", node.protocol));
        }
    }
    Ok(Value::Object(out))
}

/// sing-box 客户端配置。
fn export_sing_box(nodes: &[Node], report: &mut ExportReport) -> Value {
    // `route.final` 决定默认出站。此前写死 `"direct"`，客户端因此绕过代理
    // ——与 Xray 侧同一个缺陷。改为指向第一个可用节点。
    let mut converted = Vec::new();
    for node in nodes {
        match sing_box_outbound(node) {
            Ok(value) => converted.push(value),
            Err(reason) => report.skip(Target::SingBox.name(), &node.tag, &reason),
        }
    }
    let final_tag = converted
        .first()
        .and_then(|value| value.get("tag"))
        .cloned()
        .unwrap_or_else(|| json!("direct"));
    let direct = free_name(
        "direct",
        nodes
            .iter()
            .map(|node| node.tag.as_str())
            .chain(std::iter::once("mixed-in")),
    );
    let mut outbounds = converted;
    outbounds.push(json!({"type": "direct", "tag": direct}));
    json!({
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 1080
        }],
        "outbounds": outbounds,
        "route": {"final": final_tag}
    })
}

fn sing_box_outbound(node: &Node) -> std::result::Result<Value, String> {
    let mut out = Map::new();
    out.insert("tag".into(), json!(node.tag));
    out.insert("server".into(), json!(node.host));
    out.insert("server_port".into(), json!(node.port));
    match (&node.protocol, &node.credential) {
        (Protocol::Vless, Credential::Uuid { uuid, flow }) => {
            out.insert("type".into(), json!("vless"));
            out.insert("uuid".into(), json!(uuid));
            if let Some(flow) = flow {
                out.insert("flow".into(), json!(flow));
            }
            if let Some(encryption) = &node.vless_encryption {
                out.insert("encryption".into(), json!(encryption));
            }
        }
        (Protocol::Vmess, Credential::Uuid { uuid, .. }) => {
            out.insert("type".into(), json!("vmess"));
            out.insert("uuid".into(), json!(uuid));
            out.insert("security".into(), json!("auto"));
        }
        (Protocol::Trojan, Credential::Password { password }) => {
            out.insert("type".into(), json!("trojan"));
            out.insert("password".into(), json!(password));
        }
        (Protocol::Shadowsocks, Credential::Shadowsocks { method, password }) => {
            out.insert("type".into(), json!("shadowsocks"));
            out.insert("method".into(), json!(method));
            out.insert("password".into(), json!(password));
        }
        (
            Protocol::Snell,
            Credential::Snell {
                psk,
                version,
                userkey,
                mode,
                obfs_mode,
            },
        ) => {
            // sing-box 没有 v5 客户端；官方文档称 v5 线格式与 v4 相同，按 4 发送。
            let wire = if (4..=5).contains(version) { 4 } else { 6 };
            if wire == 4 && obfs_mode.as_deref() == Some("tls") {
                return Err("sing-box 的 Snell obfs 只有 none/http，没有 tls".to_owned());
            }
            out.insert("type".into(), json!("snell"));
            out.insert("version".into(), json!(wire));
            out.insert("psk".into(), json!(psk));
            if let Some(userkey) = userkey {
                out.insert("userkey".into(), json!(userkey));
            }
            if wire == 4 {
                if let Some(obfs) = obfs_mode {
                    out.insert("obfs_mode".into(), json!(obfs));
                }
            } else if let Some(mode) = mode {
                out.insert("mode".into(), json!(mode));
            }
        }
        (
            Protocol::Hysteria2,
            Credential::Hysteria2 {
                password,
                obfs,
                up_mbps,
                down_mbps,
            },
        ) => {
            out.insert("type".into(), json!("hysteria2"));
            out.insert("password".into(), json!(password));
            if let Some(obfs) = obfs {
                out.insert(
                    "obfs".into(),
                    json!({"type": obfs.kind, "password": obfs.password}),
                );
            }
            if let Some(up) = up_mbps {
                out.insert("up_mbps".into(), json!(up));
            }
            if let Some(down) = down_mbps {
                out.insert("down_mbps".into(), json!(down));
            }
        }
        (
            Protocol::Tuic,
            Credential::Tuic {
                uuid,
                password,
                congestion_control,
                ..
            },
        ) => {
            out.insert("type".into(), json!("tuic"));
            out.insert("uuid".into(), json!(uuid));
            out.insert("password".into(), json!(password));
            if let Some(control) = congestion_control {
                out.insert("congestion_control".into(), json!(control));
            }
        }
        (Protocol::AnyTls, Credential::Password { password }) => {
            out.insert("type".into(), json!("anytls"));
            out.insert("password".into(), json!(password));
        }
        (Protocol::Naive, Credential::Naive { username, password }) => {
            out.insert("type".into(), json!("naive"));
            out.insert("username".into(), json!(username));
            out.insert("password".into(), json!(password));
        }
        _ => {
            return Err(format!("{:?} 不是 sing-box 支持的出站协议", node.protocol));
        }
    }

    // 传输层只对 vless/vmess/trojan 有意义。
    let stream = match node.transport {
        Transport::Tcp => None,
        Transport::Ws { ref path, ref host } => Some(json!({
            "type": "ws",
            "path": path,
            "headers": host.as_ref().map(|host| json!({"Host": host})).unwrap_or(Value::Null)
        })),
        Transport::Grpc { ref path, .. } => Some(json!({
            "type": "grpc",
            // sing-box 固定拼 `/<service>/Tun`；单流客户端对双路径服务同样可用。
            "service_name": sing_box_grpc_name(path)?
        })),
        Transport::HttpUpgrade { ref path, ref host } => Some(json!({
            "type": "httpupgrade",
            "path": path,
            "host": host
        })),
        Transport::Xhttp { .. } => {
            return Err("sing-box 没有 XHTTP 承载（Xray/Mihomo 才有）".to_owned());
        }
        Transport::Kcp => {
            return Err("sing-box 没有 mKCP 承载".to_owned());
        }
        Transport::Http { ref path, ref host } => Some(json!({
            "type": "http",
            "path": path,
            "host": host.as_ref().map(|host| json!([host])).unwrap_or(Value::Null)
        })),
        Transport::Quic => Some(json!({"type": "quic"})),
    };
    if let Some(mut stream) = stream {
        if stream.get("headers").is_some_and(Value::is_null) {
            stream.as_object_mut().expect("对象").remove("headers");
        }
        out.insert("transport".into(), stream);
    }

    match &node.security {
        Security::None => {}
        Security::Tls { server_name } => {
            let mut tls = json!({"enabled": true});
            if let Some(name) = server_name {
                tls["server_name"] = json!(name);
            }
            // TUIC 服务端配了 alpn 时客户端必须匹配。
            if let Credential::Tuic { alpn, .. } = &node.credential
                && !alpn.is_empty()
            {
                tls["alpn"] = json!(alpn);
            }
            out.insert("tls".into(), tls);
        }
        Security::Reality {
            public_key,
            short_id,
            server_name,
        } => {
            out.insert(
                "tls".into(),
                json!({
                    "enabled": true,
                    "server_name": server_name,
                    "reality": {"enabled": true, "public_key": public_key, "short_id": short_id},
                    "utls": {"enabled": true, "fingerprint": "chrome"}
                }),
            );
        }
    }
    Ok(Value::Object(out))
}

/// Mihomo（Clash.Meta）客户端配置：只导 proxies，规则交给用户。
fn export_mihomo(nodes: &[Node], report: &mut ExportReport) -> Value {
    let mut proxies = Vec::new();
    for node in nodes {
        match mihomo_proxy(node) {
            Ok(value) => proxies.push(value),
            Err(reason) => report.skip(Target::Mihomo.name(), &node.tag, &reason),
        }
    }
    let names: Vec<Value> = proxies
        .iter()
        .filter_map(|proxy| proxy.get("name").cloned())
        .collect();
    // 代理组名不能与任一代理同名，否则 Mihomo 报代理组循环。
    let group = free_name("PROXY", nodes.iter().map(|node| node.tag.as_str()));
    json!({
        "mixed-port": 7890,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [{
            "name": group,
            "type": "select",
            "proxies": names
        }],
        "rules": [format!("MATCH,{group}")]
    })
}

fn mihomo_proxy(node: &Node) -> std::result::Result<Value, String> {
    let mut out = Map::new();
    out.insert("name".into(), json!(node.tag));
    out.insert("server".into(), json!(node.host));
    out.insert("port".into(), json!(node.port));
    match (&node.protocol, &node.credential) {
        (Protocol::Vless, Credential::Uuid { uuid, flow }) => {
            out.insert("type".into(), json!("vless"));
            out.insert("uuid".into(), json!(uuid));
            if let Some(flow) = flow {
                out.insert("flow".into(), json!(flow));
            }
            if let Some(encryption) = &node.vless_encryption {
                out.insert("encryption".into(), json!(encryption));
            }
        }
        (Protocol::Vmess, Credential::Uuid { uuid, .. }) => {
            out.insert("type".into(), json!("vmess"));
            out.insert("uuid".into(), json!(uuid));
            out.insert("alterId".into(), json!(0));
            out.insert("cipher".into(), json!("auto"));
        }
        (Protocol::Trojan, Credential::Password { password }) => {
            // Mihomo 的 trojan 实现无条件 TLS（TrojanOption 没有 tls 开关），
            // 明文 trojan 只会得到 "first record does not look like a TLS handshake"。
            if node.security == Security::None {
                return Err("Mihomo 的 trojan 强制 TLS，无法连接明文 trojan".to_owned());
            }
            out.insert("type".into(), json!("trojan"));
            out.insert("password".into(), json!(password));
        }
        (Protocol::Shadowsocks, Credential::Shadowsocks { method, password }) => {
            out.insert("type".into(), json!("ss"));
            out.insert("cipher".into(), json!(method));
            out.insert("password".into(), json!(password));
        }
        (
            Protocol::Hysteria2,
            Credential::Hysteria2 {
                password,
                obfs,
                up_mbps,
                down_mbps,
            },
        ) => {
            out.insert("type".into(), json!("hysteria2"));
            out.insert("password".into(), json!(password));
            // Mihomo 的 up/down 是带单位的字符串，未指定单位时按 Mbps。
            if let Some(up) = up_mbps {
                out.insert("up".into(), json!(format!("{up} Mbps")));
            }
            if let Some(down) = down_mbps {
                out.insert("down".into(), json!(format!("{down} Mbps")));
            }
            if let Some(obfs) = obfs {
                out.insert("obfs".into(), json!(obfs.kind));
                out.insert("obfs-password".into(), json!(obfs.password));
                if let Some(min) = obfs.min_packet_size {
                    out.insert("obfs-min-packet-size".into(), json!(min));
                }
                if let Some(max) = obfs.max_packet_size {
                    out.insert("obfs-max-packet-size".into(), json!(max));
                }
            }
        }
        (
            Protocol::Tuic,
            Credential::Tuic {
                uuid,
                password,
                congestion_control,
                ..
            },
        ) => {
            out.insert("type".into(), json!("tuic"));
            out.insert("uuid".into(), json!(uuid));
            out.insert("password".into(), json!(password));
            if let Some(control) = congestion_control {
                out.insert("congestion-controller".into(), json!(control));
            }
        }
        (Protocol::AnyTls, Credential::Password { password }) => {
            out.insert("type".into(), json!("anytls"));
            out.insert("password".into(), json!(password));
        }
        (
            Protocol::Snell,
            Credential::Snell {
                psk,
                version,
                userkey,
                mode,
                obfs_mode,
            },
        ) => {
            // Mihomo v1.19.33 的 Snell 只到 v5；v6 会被内核拒绝
            // （文档写的是 1-6，与实测不符）。
            if *version > 5 {
                return Err(format!("Mihomo 不支持 Snell v{version}（最高 v5）"));
            }
            out.insert("type".into(), json!("snell"));
            out.insert("psk".into(), json!(psk));
            out.insert("version".into(), json!(version));
            if let Some(userkey) = userkey {
                out.insert("userkey".into(), json!(userkey));
            }
            if let Some(mode) = mode {
                out.insert("mode".into(), json!(mode));
            }
            if let Some(obfs) = obfs_mode {
                out.insert("obfs-opts".into(), json!({"mode": obfs}));
            }
        }
        _ => {
            return Err(format!("{:?} 不是 Mihomo 支持的协议", node.protocol));
        }
    }

    match node.transport {
        Transport::Tcp => {}
        Transport::Ws { ref path, ref host } => {
            out.insert("network".into(), json!("ws"));
            let mut opts = json!({"path": path});
            if let Some(host) = host {
                opts["headers"] = json!({"Host": host});
            }
            out.insert("ws-opts".into(), opts);
        }
        Transport::Grpc { ref path, .. } => {
            out.insert("network".into(), json!("grpc"));
            // Mihomo 对以 `/` 开头的 service name 原样作为请求路径。
            out.insert(
                "grpc-opts".into(),
                json!({"grpc-service-name": xray_grpc_name(path)?}),
            );
        }
        Transport::HttpUpgrade { ref path, ref host } => {
            // Mihomo 把 HTTPUpgrade 表达为 ws 的一个选项。
            out.insert("network".into(), json!("ws"));
            let mut opts = json!({"path": path, "v2ray-http-upgrade": true});
            if let Some(host) = host {
                opts["headers"] = json!({"Host": host});
            }
            out.insert("ws-opts".into(), opts);
        }
        Transport::Xhttp {
            ref path,
            ref host,
            ref mode,
        } => {
            out.insert("network".into(), json!("xhttp"));
            let mut opts = json!({"path": path, "mode": mode});
            if let Some(host) = host {
                opts["host"] = json!(host);
            }
            out.insert("xhttp-opts".into(), opts);
        }
        Transport::Kcp => {
            out.insert("network".into(), json!("mkcp"));
        }
        Transport::Http { ref path, ref host } => {
            out.insert("network".into(), json!("http"));
            let mut opts = json!({"path": [path]});
            if let Some(host) = host {
                opts["headers"] = json!({"Host": [host]});
            }
            out.insert("http-opts".into(), opts);
        }
        Transport::Quic => {
            return Err("Mihomo 不支持 V2Ray QUIC 传输".to_owned());
        }
    }

    match &node.security {
        Security::None => {}
        Security::Tls { server_name } => {
            out.insert("tls".into(), json!(true));
            if let Some(name) = server_name {
                out.insert("servername".into(), json!(name));
            }
            // TUIC 服务端配了 alpn 时客户端必须匹配（Mihomo 放在顶层）。
            if let Credential::Tuic { alpn, .. } = &node.credential
                && !alpn.is_empty()
            {
                out.insert("alpn".into(), json!(alpn));
            }
        }
        Security::Reality {
            public_key,
            short_id,
            server_name,
        } => {
            out.insert("tls".into(), json!(true));
            out.insert("servername".into(), json!(server_name));
            out.insert(
                "reality-opts".into(),
                json!({
                    "public-key": public_key,
                    "short-id": short_id
                }),
            );
            out.insert("client-fingerprint".into(), json!("chrome"));
        }
    }
    Ok(Value::Object(out))
}

/// Anywhere 订阅（AJSON）：一个文档带全部代理，客户端整份订阅。
///
/// 比逐条 `portal://` 深链更好用：支持全部协议、TLS/REALITY/传输层，
/// 且带稳定 `id`，重命名后客户端仍能保持选中项。
fn export_anywhere(nodes: &[Node], report: &mut ExportReport) -> Value {
    let mut proxies = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        match anywhere_proxy(node, index) {
            Ok(value) => proxies.push(value),
            Err(reason) => report.skip(Target::Anywhere.name(), &node.tag, &reason),
        }
    }
    json!({
        "anywhere": 1,
        "name": "dubhe",
        "proxies": proxies,
    })
}

fn anywhere_proxy(node: &Node, index: usize) -> std::result::Result<Value, String> {
    let mut out = Map::new();
    out.insert("id".into(), json!(format!("n{index}")));
    out.insert("name".into(), json!(node.tag));
    out.insert("server".into(), json!(node.host));
    out.insert("port".into(), json!(node.port));

    match (&node.protocol, &node.credential) {
        (Protocol::Vless, Credential::Uuid { uuid, flow }) => {
            out.insert("protocol".into(), json!("vless"));
            out.insert("uuid".into(), json!(uuid));
            if let Some(flow) = flow {
                out.insert("flow".into(), json!(flow));
            }
            if let Some(encryption) = &node.vless_encryption {
                out.insert("encryption".into(), json!(encryption));
            }
        }
        (Protocol::Trojan, Credential::Password { password }) => {
            out.insert("protocol".into(), json!("trojan"));
            out.insert("password".into(), json!(password));
        }
        (Protocol::Shadowsocks, Credential::Shadowsocks { method, password }) => {
            out.insert("protocol".into(), json!("shadowsocks"));
            out.insert("method".into(), json!(method));
            out.insert("password".into(), json!(password));
        }
        (
            Protocol::Hysteria2,
            Credential::Hysteria2 {
                password,
                obfs,
                up_mbps,
                down_mbps,
            },
        ) => {
            out.insert("protocol".into(), json!("hysteria"));
            out.insert("password".into(), json!(password));
            if let Some(up) = up_mbps {
                out.insert("upMbps".into(), json!(up));
            }
            if let Some(down) = down_mbps {
                out.insert("downMbps".into(), json!(down));
            }
            if let Some(obfs) = obfs {
                let mut opts = json!({"type": obfs.kind, "password": obfs.password});
                if let Some(min) = obfs.min_packet_size {
                    opts["minPacketSize"] = json!(min);
                }
                if let Some(max) = obfs.max_packet_size {
                    opts["maxPacketSize"] = json!(max);
                }
                out.insert("obfs".into(), opts);
            }
        }
        (Protocol::AnyTls, Credential::Password { password }) => {
            out.insert("protocol".into(), json!("anytls"));
            out.insert("password".into(), json!(password));
        }
        (Protocol::Nw3, Credential::Nw3 { key, morph }) => {
            out.insert("protocol".into(), json!("nowhere"));
            out.insert("key".into(), json!(key));
            out.insert("morph".into(), json!(morph));
        }
        _ => {
            return Err(format!(
                "Anywhere 不支持 {} 协议",
                protocol_name(&node.protocol)
            ));
        }
    }

    // AJSON 的 transport 只属于 VLESS；其它协议的承载字段不会被读取。
    // 不在这里拒绝，客户端会按 RAW TCP 连接一个 WS/gRPC 端口，静默不通。
    if node.protocol == Protocol::Vless {
        let transport = match &node.transport {
            Transport::Tcp => None,
            Transport::Ws { path, host } => {
                let mut ws = json!({"type": "ws", "path": path});
                if let Some(host) = host {
                    ws["host"] = json!(host);
                }
                Some(ws)
            }
            Transport::Grpc { path, .. } => Some(json!({
                "type": "grpc",
                "serviceName": xray_grpc_name(path)?,
                "multiMode": false
            })),
            Transport::HttpUpgrade { path, host } => {
                let mut up = json!({"type": "httpupgrade", "path": path});
                if let Some(host) = host {
                    up["host"] = json!(host);
                }
                Some(up)
            }
            Transport::Xhttp { path, host, mode } => {
                let mut xhttp = json!({"type": "xhttp", "path": path, "mode": mode});
                if let Some(host) = host {
                    xhttp["host"] = json!(host);
                }
                Some(xhttp)
            }
            Transport::Kcp => {
                return Err("Anywhere 的 AJSON 没有 mKCP 承载".to_owned());
            }
            Transport::Http { .. } => {
                return Err("Anywhere 的 AJSON 没有 v2ray-http 承载".to_owned());
            }
            Transport::Quic => {
                return Err("Anywhere 的 AJSON 没有 V2Ray QUIC 承载".to_owned());
            }
        };
        if let Some(transport) = transport {
            out.insert("transport".into(), transport);
        }
    } else if !matches!(node.transport, Transport::Tcp) {
        return Err("Anywhere 的 AJSON 只为 VLESS 读取 transport，其它协议只能 RAW TCP".to_owned());
    }

    // nowhere 固定 TLS 1.3，AJSON 里不接受 security 字段。
    if node.protocol == Protocol::Nw3 {
        return Ok(Value::Object(out));
    }
    match &node.security {
        Security::None => {
            // trojan/anytls 默认 tls；明文必须显式声明。
            if matches!(node.protocol, Protocol::Trojan | Protocol::AnyTls) {
                out.insert("security".into(), json!("none"));
            }
        }
        Security::Tls { server_name } => {
            let mut tls = json!({"type": "tls"});
            if let Some(name) = server_name {
                tls["sni"] = json!(name);
            }
            out.insert("security".into(), tls);
        }
        Security::Reality {
            public_key,
            short_id,
            server_name,
        } => {
            out.insert(
                "security".into(),
                json!({
                    "type": "reality",
                    "sni": server_name,
                    "publicKey": public_key,
                    "shortId": short_id,
                    "fingerprint": "chrome"
                }),
            );
        }
    }
    Ok(Value::Object(out))
}

/// XHTTP 模式的线上写法；`Debug` 的小写化会得到 `packetup`，客户端不认。
fn xhttp_mode(mode: crate::config::Mode) -> &'static str {
    use crate::config::Mode;
    match mode {
        Mode::Auto => "auto",
        Mode::StreamOne => "stream-one",
        Mode::StreamUp => "stream-up",
        Mode::PacketUp => "packet-up",
    }
}

/// 判断导出目标是私有地址或私有域名（Xray 允许这类明文出站）。
/// 本仓库的 `grpc.path` 存**完整 HTTP/2 路径**（`/GunService/Tun`）。
///
/// Xray 与 Mihomo 对以 `/` 开头的 `serviceName` 使用原样路径：Xray 在最后一个
/// `/` 处切出服务前缀、把最后一段当流名，拼回来仍是同一路径；Mihomo 直接当作
/// 请求路径。因此两者都可以写完整路径，不必猜 `/<service>/Tun` 结构。
///
/// 需要 `/<service>/<stream>` 至少两段；含 `%` 时 Xray 会重新转义，路径会变。
fn xray_grpc_name(path: &str) -> Result<String, String> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segments.len() < 2 || segments[0].is_empty() {
        return Err(format!(
            "gRPC 路径 {path} 至少需要 `/<service>/<stream>` 两段，无法导出到这个目标"
        ));
    }
    if path.contains('%') {
        return Err(format!(
            "gRPC 路径 {path} 含 `%`，Xray 会重新转义导致路径不同"
        ));
    }
    Ok(path.to_owned())
}

/// sing-box 固定把 `service_name` 拼成 `/<service>/Tun`，只能表达以 `/Tun` 结尾
/// 的路径。双路径服务仍然可以用单流客户端。
fn sing_box_grpc_name(path: &str) -> Result<&str, String> {
    let service = path
        .strip_prefix('/')
        .and_then(|rest| rest.strip_suffix("/Tun"))
        .filter(|service| !service.is_empty())
        .ok_or_else(|| format!("sing-box 只能请求 `/<service>/Tun`，gRPC 路径 {path} 无法导出"))?;
    if service.contains('%') {
        return Err(format!("gRPC 路径 {path} 含 `%`，无法导出到 sing-box"));
    }
    Ok(service)
}

fn is_private_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        };
    }
    let lower = host.to_ascii_lowercase();
    !lower.contains('.')
        || lower.ends_with(".local")
        || lower.ends_with(".lan")
        || lower.ends_with(".internal")
        || lower.ends_with(".home.arpa")
}

fn protocol_name(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::Vless => "VLESS",
        Protocol::Vmess => "VMess",
        Protocol::Trojan => "Trojan",
        Protocol::Shadowsocks => "Shadowsocks",
        Protocol::Hysteria2 => "Hysteria2",
        Protocol::Tuic => "TUIC",
        Protocol::AnyTls => "AnyTLS",
        Protocol::Snell => "Snell",
        Protocol::Nw3 => "NW3",
        Protocol::Naive => "Naive",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config() -> Config {
        let value = json!({
            "version": 1,
            "inbounds": [
                {
                    "type": "vless-reality", "tag": "reality", "listen": "0.0.0.0:8443",
                    "users": [{"name": "alice",
                        "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "flow": "xtls-rprx-vision"}],
                    "reality": {
                        "target": {"host": "www.example.com", "port": 443},
                        "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                        "server_names": ["www.example.com"],
                        "short_ids": ["ab"]
                    }
                },
                {
                    "type": "shadowsocks", "tag": "ss", "listen": "0.0.0.0:8388",
                    "method": "aes-256-gcm", "password": "ss-password"
                },
                {
                    "type": "nw3", "tag": "nw3", "listen": "0.0.0.0:10451",
                    "key": "0123456789abcdef0123456789abcdef"
                }
            ],
            "outbounds": [{"tag": "direct", "type": "direct"}],
            "route": {"default": "direct"}
        });
        Config::from_json(&value.to_string()).expect("配置应合法")
    }

    fn collect() -> (Config, Vec<Node>) {
        let config = config();
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);
        (config, nodes)
    }

    #[test]
    fn nodes_derive_reality_public_key_from_private_key() {
        let (_, nodes) = collect();
        let reality = nodes
            .iter()
            .find(|node| node.tag == "reality")
            .expect("应有 REALITY 节点");
        assert_eq!(reality.port, 8443);
        assert_eq!(reality.host, "example.com");
        match &reality.security {
            Security::Reality {
                public_key,
                short_id,
                ..
            } => {
                // 由固定私钥派生出的稳定公钥；换实现会立刻失败。
                assert_eq!(public_key, "pOCSkrZRwni5dyxWn1-puxPZBrRqtoyd-dwrRAn4ogk");
                assert_eq!(short_id, "ab");
            }
            other => panic!("应为 REALITY：{other:?}"),
        }
    }

    #[test]
    fn xray_export_skips_unsupported_and_keeps_reality() {
        let (_, nodes) = collect();
        let mut report = ExportReport::default();
        let value = export(Target::Xray, &nodes, &mut report).unwrap();
        let outbounds = value["outbounds"].as_array().unwrap();
        let reality = outbounds
            .iter()
            .find(|item| item["tag"] == "reality")
            .expect("应导出 REALITY 出站");
        assert_eq!(reality["streamSettings"]["security"], "reality");
        assert_eq!(reality["streamSettings"]["network"], "tcp");
        // Xray v26 起 settings 是扁平结构，没有 vnext 数组。
        assert_eq!(reality["settings"]["address"], "example.com");
        assert_eq!(reality["settings"]["port"], 8443);
        assert_eq!(reality["settings"]["flow"], "xtls-rprx-vision");
        assert_eq!(reality["settings"]["encryption"], "none");
        assert!(reality["settings"].get("vnext").is_none());
        assert_eq!(
            reality["streamSettings"]["realitySettings"]["password"],
            "pOCSkrZRwni5dyxWn1-puxPZBrRqtoyd-dwrRAn4ogk"
        );
        assert_eq!(
            reality["streamSettings"]["realitySettings"]["shortId"],
            "ab"
        );
        // NW3 不是 Xray 出站协议，必须进报告而不是静默丢弃。
        assert!(report.notes.iter().any(|note| note.contains("nw3")));
    }

    #[test]
    fn sing_box_export_maps_reality_and_skips_nw3() {
        let (_, nodes) = collect();
        let mut report = ExportReport::default();
        let value = export(Target::SingBox, &nodes, &mut report).unwrap();
        let outbounds = value["outbounds"].as_array().unwrap();
        let reality = outbounds
            .iter()
            .find(|item| item["tag"] == "reality")
            .expect("应导出 REALITY 出站");
        assert_eq!(reality["type"], "vless");
        assert_eq!(reality["tls"]["reality"]["enabled"], true);
        assert_eq!(reality["tls"]["utls"]["fingerprint"], "chrome");
        assert!(report.notes.iter().any(|note| note.contains("nw3")));
    }

    #[test]
    fn mihomo_export_fills_proxy_group() {
        let (_, nodes) = collect();
        let mut report = ExportReport::default();
        let value = export(Target::Mihomo, &nodes, &mut report).unwrap();
        let proxies = value["proxies"].as_array().unwrap();
        assert_eq!(proxies.len(), 2, "REALITY 与 SS 都应导出");
        let group = &value["proxy-groups"][0]["proxies"];
        assert_eq!(group.as_array().unwrap().len(), 2);
        assert_eq!(value["rules"][0], "MATCH,PROXY");
    }

    #[test]
    fn anywhere_export_uses_ajson_with_stable_ids() {
        let (_, nodes) = collect();
        let mut report = ExportReport::default();
        let value = export(Target::Anywhere, &nodes, &mut report).unwrap();
        assert_eq!(value["anywhere"], 1);
        let proxies = value["proxies"].as_array().unwrap();
        // REALITY / SS / NW3 都应导出，三者在 Anywhere 里分别是 vless / shadowsocks / nowhere。
        assert_eq!(proxies.len(), 3);
        for (index, proxy) in proxies.iter().enumerate() {
            assert_eq!(proxy["id"], format!("n{index}"));
            assert!(proxy["name"].is_string());
        }
        let reality = proxies
            .iter()
            .find(|proxy| proxy["name"] == "reality")
            .expect("应有 REALITY");
        assert_eq!(reality["protocol"], "vless");
        assert_eq!(reality["security"]["type"], "reality");
        assert_eq!(
            reality["security"]["publicKey"],
            "pOCSkrZRwni5dyxWn1-puxPZBrRqtoyd-dwrRAn4ogk"
        );
        let nw3 = proxies
            .iter()
            .find(|proxy| proxy["name"] == "nw3")
            .expect("应有 NW3");
        assert_eq!(nw3["protocol"], "nowhere");
        assert_eq!(nw3["morph"], true);
        assert!(report.notes.is_empty(), "{}", report.notes.join("; "));
    }

    #[test]
    fn anywhere_export_skips_unsupported_protocols() {
        // Snell 与 TUIC 不在 Anywhere 的协议表里，必须进报告。
        let value = json!({
            "version": 1,
            "inbounds": [
                {"type": "snell", "tag": "snell", "listen": "0.0.0.0:6160",
                 "psk": "psk", "version": 5},
                {"type": "tuic", "tag": "tuic", "listen": "0.0.0.0:443",
                 "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                            "password": "pw"}],
                 "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"}
            ],
            "outbounds": [{"tag": "direct", "type": "direct"}],
            "route": {"default": "direct"}
        });
        let config = Config::from_json(&value.to_string()).unwrap();
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);
        let mut report = ExportReport::default();
        let error = export(Target::Anywhere, &nodes, &mut report)
            .unwrap_err()
            .to_string();
        assert!(error.contains("没有可用节点"), "{error}");
        assert_eq!(report.notes.len(), 2);
    }

    fn rename_test_node(tag: &str) -> Node {
        let value = json!({
            "version": 1,
            "inbounds": [{
                "type": "shadowsocks", "tag": tag, "listen": "0.0.0.0:8388",
                "method": "aes-128-gcm", "password": "rename-password"
            }],
            "outbounds": [{"tag": "direct", "type": "direct"}],
            "route": {"default": "direct"}
        });
        let config = Config::from_json(&value.to_string()).expect("配置应合法");
        let mut report = ExportReport::default();
        nodes(&config, "example.com", &mut report)
            .into_iter()
            .next()
            .expect("应生成一个节点")
    }

    /// 用户节点叫 `direct` / `PROXY` 时，辅助出站与代理组必须改名。
    #[test]
    fn reserved_names_do_not_collide_with_node_tags() {
        let node = rename_test_node("direct");
        let mut report = ExportReport::default();
        let xray = export(Target::Xray, std::slice::from_ref(&node), &mut report).unwrap();
        let tags: Vec<&str> = xray["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["tag"].as_str())
            .collect();
        assert!(tags.contains(&"direct"), "节点名应保留：{tags:?}");
        assert!(
            tags.iter().filter(|tag| **tag == "direct").count() == 1,
            "辅助出站不能与节点同名：{tags:?}"
        );

        let sing = export(Target::SingBox, std::slice::from_ref(&node), &mut report).unwrap();
        let tags: Vec<&str> = sing["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["tag"].as_str())
            .collect();
        assert_eq!(
            tags.iter().filter(|tag| **tag == "direct").count(),
            1,
            "{tags:?}"
        );
        assert_eq!(sing["route"]["final"], "direct");

        let proxy_named = rename_test_node("PROXY");
        let mut report = ExportReport::default();
        let mihomo = export(
            Target::Mihomo,
            std::slice::from_ref(&proxy_named),
            &mut report,
        )
        .unwrap();
        let group = mihomo["proxy-groups"][0]["name"].as_str().unwrap();
        assert_ne!(group, "PROXY", "代理组不能与代理同名");
        assert_eq!(mihomo["rules"][0], format!("MATCH,{group}"));
        assert_eq!(mihomo["proxies"][0]["name"], "PROXY");
    }

    /// 第一个节点不可导出、第二个可用时，默认出口必须指向第二个。
    ///
    /// 只验证「全空」不够：`primary` 取的是**首个成功转换**的节点，
    /// 取错会让客户端默认用一个被跳过的 tag。
    #[test]
    fn first_skipped_node_does_not_become_the_default() {
        let value = json!({
            "version": 1,
            "inbounds": [
                // Xray 拒绝无 TLS 且指向公网地址的 VLESS 出站。
                {"type": "vless", "tag": "plaintext", "listen": "0.0.0.0:443",
                 "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}]},
                {"type": "shadowsocks", "tag": "usable", "listen": "0.0.0.0:8388",
                 "method": "aes-128-gcm", "password": "usable-password"}
            ],
            "outbounds": [{"tag": "direct", "type": "direct"}],
            "route": {"default": "direct"}
        });
        let config = Config::from_json(&value.to_string()).expect("配置应合法");
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);
        assert_eq!(nodes.len(), 2);

        let xray = export(Target::Xray, &nodes, &mut report).expect("应有一个可用节点");
        let outbounds = xray["outbounds"].as_array().unwrap();
        assert_eq!(
            outbounds[0]["tag"], "usable",
            "默认出口必须是可用的那个：{xray}"
        );
        assert!(
            outbounds.iter().all(|item| item["tag"] != "plaintext"),
            "不可用节点不应出现：{xray}"
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("跳过 plaintext")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn unknown_target_is_an_error() {
        let error = Target::parse("clash").unwrap_err();
        assert!(error.to_string().contains("clash"), "{error}");
    }
}

#[cfg(test)]
mod transport_matrix_tests {
    use super::*;
    use crate::config::Config;

    /// 按承载构造最小合法的 VLESS 入站。
    fn node_for(kind: &str) -> Node {
        const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let value = match kind {
            "ws" => json!({
                "type": "vless-ws", "tag": "n", "listen": "0.0.0.0:443",
                "users": [{"name": "a", "uuid": UUID}],
                "websocket": {"path": "/ws"},
                "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
            }),
            "grpc" => json!({
                "type": "vless-grpc", "tag": "n", "listen": "0.0.0.0:443",
                "users": [{"name": "a", "uuid": UUID}],
                "grpc": {"path": "/TunService/Tun"},
                "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
            }),
            "httpupgrade" => json!({
                "type": "vless-httpupgrade", "tag": "n", "listen": "0.0.0.0:443",
                "users": [{"name": "a", "uuid": UUID}],
                "httpupgrade": {"path": "/up"},
                "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
            }),
            "xhttp" => json!({
                "type": "vless-xhttp", "tag": "n", "listen": "0.0.0.0:443",
                "users": [{"name": "a", "uuid": UUID}],
                "xhttp": {"path": "/x", "mode": "packet-up"},
                "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
            }),
            "kcp" => json!({
                "type": "vless-kcp", "tag": "n", "listen": "0.0.0.0:443",
                "users": [{"name": "a", "uuid": UUID}],
                "kcp": {}
            }),
            other => panic!("未覆盖的承载 {other}"),
        };
        node_from(value)
    }

    fn node_from(value: serde_json::Value) -> Node {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [value],
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法");
        let mut report = ExportReport::default();
        nodes(&config, "example.com", &mut report)
            .into_iter()
            .next()
            .expect("应有节点")
    }

    fn get(target: Target, node: &Node) -> (Value, ExportReport) {
        let mut report = ExportReport::default();
        let value = export(target, std::slice::from_ref(node), &mut report).unwrap();
        (value, report)
    }

    /// 该目标把所有节点都跳过时，`export` 必须拒绝生成纯直连配置。
    fn rejected(target: Target, node: &Node) -> ExportReport {
        let mut report = ExportReport::default();
        let error = export(target, std::slice::from_ref(node), &mut report).unwrap_err();
        assert!(
            error.to_string().contains("没有可用节点"),
            "{target:?} 应拒绝导出：{error}"
        );
        report
    }

    #[test]
    fn mihomo_supports_xhttp() {
        let (value, _) = get(Target::Mihomo, &node_for("xhttp"));
        let proxy = &value["proxies"][0];
        assert_eq!(proxy["network"], "xhttp");
        assert_eq!(proxy["xhttp-opts"]["path"], "/x");
        assert_eq!(proxy["xhttp-opts"]["mode"], "packet-up");
    }

    #[test]
    fn mihomo_expresses_httpupgrade_as_ws_option() {
        let (value, _) = get(Target::Mihomo, &node_for("httpupgrade"));
        let proxy = &value["proxies"][0];
        assert_eq!(proxy["network"], "ws");
        assert_eq!(proxy["ws-opts"]["v2ray-http-upgrade"], true);
        assert_eq!(proxy["ws-opts"]["path"], "/up");
    }

    #[test]
    fn anywhere_supports_httpupgrade_and_xhttp() {
        for kind in ["httpupgrade", "xhttp"] {
            let (value, _) = get(Target::Anywhere, &node_for(kind));
            assert_eq!(value["proxies"][0]["transport"]["type"], kind);
        }
    }

    #[test]
    fn grpc_and_ws_convert_to_all_three_text_formats() {
        for kind in ["ws", "grpc"] {
            let node = node_for(kind);
            let (xray, _) = get(Target::Xray, &node);
            assert_eq!(xray["outbounds"][0]["streamSettings"]["network"], kind);
            let (sing, _) = get(Target::SingBox, &node);
            assert_eq!(sing["outbounds"][0]["transport"]["type"], kind);
            let (mihomo, _) = get(Target::Mihomo, &node);
            assert_eq!(mihomo["proxies"][0]["network"], kind);
            let (anywhere, _) = get(Target::Anywhere, &node);
            assert_eq!(anywhere["proxies"][0]["transport"]["type"], kind);
        }
    }

    /// 本仓库的 `grpc.path` 是完整 HTTP/2 路径（`/TunService/Tun`）：
    /// Xray/Mihomo 原样写完整路径（已用真客户端验证可连通），sing-box 只能写
    /// `/<service>/Tun` 里的服务名。此前导出 `TunService/Tun`，三家都会请求
    /// 一个不存在的路径。
    #[test]
    fn grpc_service_name_is_written_the_way_each_client_needs() {
        let node = node_for("grpc");
        let (xray, _) = get(Target::Xray, &node);
        assert_eq!(
            xray["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"],
            "/TunService/Tun"
        );
        let (sing, _) = get(Target::SingBox, &node);
        assert_eq!(
            sing["outbounds"][0]["transport"]["service_name"],
            "TunService"
        );
        let (mihomo, _) = get(Target::Mihomo, &node);
        assert_eq!(
            mihomo["proxies"][0]["grpc-opts"]["grpc-service-name"],
            "/TunService/Tun"
        );
        let (anywhere, _) = get(Target::Anywhere, &node);
        assert_eq!(
            anywhere["proxies"][0]["transport"]["serviceName"],
            "/TunService/Tun"
        );
    }

    /// 双路径服务：单流客户端仍然可用，三家都应导出单流配置。
    #[test]
    fn dual_path_grpc_still_exports_as_a_single_stream_client() {
        let node = node_from(json!({
            "type": "vless-grpc", "tag": "n", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "grpc": {"path": "/TunService/Tun", "multi_path": "/TunService/TunMulti"},
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let (xray, _) = get(Target::Xray, &node);
        let grpc = &xray["outbounds"][0]["streamSettings"]["grpcSettings"];
        assert_eq!(grpc["serviceName"], "/TunService/Tun");
        assert!(
            grpc.get("multiMode").is_none(),
            "单流客户端不启用 multiMode"
        );
        let (sing, _) = get(Target::SingBox, &node);
        assert_eq!(
            sing["outbounds"][0]["transport"]["service_name"],
            "TunService"
        );
        let (mihomo, _) = get(Target::Mihomo, &node);
        assert_eq!(
            mihomo["proxies"][0]["grpc-opts"]["grpc-service-name"],
            "/TunService/Tun"
        );
    }

    /// 自定义路径：Xray/Mihomo 写完整路径，sing-box 只能拼 `/Tun` 必须报错。
    #[test]
    fn custom_grpc_path_is_rejected_only_where_it_cannot_be_expressed() {
        let node = node_from(json!({
            "type": "vless-grpc", "tag": "n", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "grpc": {"path": "/svc/custom"},
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let (xray, _) = get(Target::Xray, &node);
        assert_eq!(
            xray["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"],
            "/svc/custom"
        );
        let (mihomo, _) = get(Target::Mihomo, &node);
        assert_eq!(
            mihomo["proxies"][0]["grpc-opts"]["grpc-service-name"],
            "/svc/custom"
        );
        let report = rejected(Target::SingBox, &node);
        assert!(
            report.notes.iter().any(|note| note.contains("gRPC")),
            "{:?}",
            report.notes
        );
    }

    /// 单段路径（没有流名）无法用 Xray 的 `/<service>/<stream>` 表达。
    #[test]
    fn single_segment_grpc_path_is_rejected_for_xray() {
        let node = node_from(json!({
            "type": "vless-grpc", "tag": "n", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "grpc": {"path": "/T"},
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let report = rejected(Target::Xray, &node);
        assert!(
            report.notes.iter().any(|note| note.contains("两段")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn kcp_only_exports_to_xray_and_mihomo() {
        let mut node = node_for("kcp");
        // mKCP 无 TLS；Xray 只允许明文出站指向私有地址。
        node.host = "192.168.1.10".to_owned();

        let (xray, _) = get(Target::Xray, &node);
        assert_eq!(xray["outbounds"][0]["streamSettings"]["network"], "kcp");

        let (mihomo, _) = get(Target::Mihomo, &node);
        assert_eq!(mihomo["proxies"][0]["network"], "mkcp");

        for target in [Target::SingBox, Target::Anywhere] {
            let report = rejected(target, &node);
            assert!(
                report.notes.iter().any(|note| note.contains("mKCP")),
                "{target:?} 应报告不支持 mKCP：{:?}",
                report.notes
            );
        }
    }
}

#[cfg(test)]
mod xray_shape_tests {
    use super::*;
    use crate::config::Config;

    fn node(json_inbound: Value) -> Node {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [json_inbound],
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法");
        let mut report = ExportReport::default();
        nodes(&config, "example.com", &mut report)
            .into_iter()
            .next()
            .expect("应有节点")
    }

    #[test]
    fn xray_vless_uses_flat_settings_without_vnext() {
        // Vision 只在有 TLS/REALITY 时合法；用 REALITY 承载。
        let node = node(json!({
            "type": "vless-reality", "tag": "v", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                       "flow": "xtls-rprx-vision"}],
            "reality": {
                "target": {"host": "www.example.com", "port": 443},
                "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                "server_names": ["www.example.com"],
                "short_ids": ["ab"]
            }
        }));
        let mut report = ExportReport::default();
        let value = export(Target::Xray, std::slice::from_ref(&node), &mut report).unwrap();
        let outbound = &value["outbounds"][0];
        let settings = &outbound["settings"];
        assert_eq!(settings["address"], "example.com");
        assert_eq!(settings["port"], 443);
        assert_eq!(settings["id"], "b831381d-6324-4d53-ad4f-8cda48b30811");
        assert_eq!(settings["encryption"], "none");
        assert_eq!(settings["flow"], "xtls-rprx-vision");
        // v26 起不再有 vnext 数组。
        assert!(settings.get("vnext").is_none());
    }

    #[test]
    fn xray_trojan_and_shadowsocks_use_flat_settings() {
        let trojan = node(json!({
            "type": "trojan", "tag": "t", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let ss = node(json!({
            "type": "shadowsocks", "tag": "s", "listen": "0.0.0.0:8388",
            "method": "aes-256-gcm", "password": "ss"
        }));
        let mut report = ExportReport::default();
        let value = export(Target::Xray, &[trojan, ss], &mut report).unwrap();
        let outbounds = value["outbounds"].as_array().unwrap();
        // 两个节点依次在 [0]、[1]；`direct` 在最后。
        assert!(outbounds[0]["settings"].get("servers").is_none());
        assert_eq!(outbounds[0]["settings"]["password"], "pw");
        assert!(outbounds[1]["settings"].get("servers").is_none());
        assert_eq!(outbounds[1]["settings"]["method"], "aes-256-gcm");
    }

    #[test]
    fn xray_ws_uses_host_field_not_headers() {
        let node = node(json!({
            "type": "vless-ws", "tag": "w", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "websocket": {"path": "/ws", "host": "cdn.example"},
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let mut report = ExportReport::default();
        let value = export(Target::Xray, std::slice::from_ref(&node), &mut report).unwrap();
        let ws = &value["outbounds"][0]["streamSettings"]["wsSettings"];
        assert_eq!(ws["path"], "/ws");
        assert_eq!(ws["host"], "cdn.example");
        assert!(ws.get("headers").is_none(), "{ws}");
    }

    #[test]
    fn xray_reality_uses_password_field_name() {
        let node = node(json!({
            "type": "vless-reality", "tag": "r", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "reality": {
                "target": {"host": "www.example.com", "port": 443},
                "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                "server_names": ["www.example.com"],
                "short_ids": ["ab"]
            }
        }));
        let mut report = ExportReport::default();
        let value = export(Target::Xray, std::slice::from_ref(&node), &mut report).unwrap();
        let reality = &value["outbounds"][0]["streamSettings"]["realitySettings"];
        // 新版字段名是 password；publicKey 是旧名别名。
        assert!(reality.get("password").is_some(), "{reality}");
        assert_eq!(reality["fingerprint"], "chrome");
    }

    #[test]
    fn xray_reality_with_ws_is_reported_not_emitted() {
        // 构造一个 REALITY + WS 的节点（服务端允许，但 Xray 客户端不支持该组合）。
        let node = Node {
            tag: "bad".into(),
            host: "example.com".into(),
            port: 443,
            protocol: Protocol::Vless,
            security: Security::Reality {
                public_key: "k".into(),
                short_id: "ab".into(),
                server_name: "s".into(),
            },
            transport: Transport::Ws {
                path: "/ws".into(),
                host: None,
            },
            credential: Credential::Uuid {
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                flow: None,
            },
            vless_encryption: None,
        };
        let mut report = ExportReport::default();
        let error = export(Target::Xray, std::slice::from_ref(&node), &mut report)
            .unwrap_err()
            .to_string();
        assert!(error.contains("没有可用节点"), "{error}");
        assert!(
            report.notes.iter().any(|note| note.contains("REALITY")),
            "{:?}",
            report.notes
        );
    }
}

#[cfg(test)]
mod tls_detection_tests {
    use super::*;
    use crate::config::Config;

    fn single(json_inbound: Value) -> Node {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [json_inbound],
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法");
        let mut report = ExportReport::default();
        nodes(&config, "example.com", &mut report)
            .into_iter()
            .next()
            .expect("应有节点")
    }

    #[test]
    fn vless_with_certificate_is_tls_not_plaintext() {
        let node = single(json!({
            "type": "vless", "tag": "v", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        assert!(
            matches!(node.security, Security::Tls { .. }),
            "带证书的 VLESS 必须识别为 TLS，实际是 {:?}",
            node.security
        );
    }

    #[test]
    fn vless_without_certificate_is_plaintext_and_skipped_for_xray_public_host() {
        let node = single(json!({
            "type": "vless", "tag": "v", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}]
        }));
        assert_eq!(node.security, Security::None);
        let mut report = ExportReport::default();
        let error = export(Target::Xray, std::slice::from_ref(&node), &mut report)
            .unwrap_err()
            .to_string();
        assert!(error.contains("没有可用节点"), "{error}");
        assert!(
            report.notes.iter().any(|note| note.contains("禁止无 TLS")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn private_host_allows_plaintext_vless_export() {
        assert!(is_private_host("192.168.1.10"));
        assert!(is_private_host("10.0.0.5"));
        assert!(is_private_host("127.0.0.1"));
        assert!(is_private_host("localhost"));
        assert!(is_private_host("router.lan"));
        assert!(!is_private_host("example.com"));
        assert!(!is_private_host("8.8.8.8"));
    }
}

#[cfg(test)]
mod data_loss_tests {
    use super::*;
    use crate::config::Config;

    fn nodes_for(json_inbounds: Value) -> (Vec<Node>, ExportReport) {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": json_inbounds,
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法");
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);
        (nodes, report)
    }

    #[test]
    fn hysteria2_obfs_is_preserved_for_sing_box() {
        let (nodes, _) = nodes_for(json!([{
            "type": "hysteria2", "tag": "hy2", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem",
            "obfs": {"type": "salamander", "password": "obfs-pw"}
        }]));
        assert_eq!(nodes.len(), 1);
        let mut report = ExportReport::default();
        let value = export(Target::SingBox, &nodes, &mut report).unwrap();
        let outbound = &value["outbounds"][0];
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["obfs"]["password"], "obfs-pw");
    }

    #[test]
    fn hysteria2_obfs_uses_flat_fields_for_mihomo() {
        let (nodes, _) = nodes_for(json!([{
            "type": "hysteria2", "tag": "hy2", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem",
            "obfs": {"type": "gecko", "password": "g", "min_packet_size": 512,
                     "max_packet_size": 1200}
        }]));
        let mut report = ExportReport::default();
        let value = export(Target::Mihomo, &nodes, &mut report).unwrap();
        let proxy = &value["proxies"][0];
        assert_eq!(proxy["obfs"], "gecko");
        assert_eq!(proxy["obfs-password"], "g");
        assert_eq!(proxy["obfs-min-packet-size"], 512);
        assert_eq!(proxy["obfs-max-packet-size"], 1200);
    }

    #[test]
    fn hysteria2_obfs_uses_nested_object_for_anywhere() {
        let (nodes, _) = nodes_for(json!([{
            "type": "hysteria2", "tag": "hy2", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem",
            "obfs": {"type": "salamander", "password": "obfs-pw"}
        }]));
        let mut report = ExportReport::default();
        let value = export(Target::Anywhere, &nodes, &mut report).unwrap();
        let proxy = &value["proxies"][0];
        assert_eq!(proxy["obfs"]["type"], "salamander");
        assert_eq!(proxy["obfs"]["password"], "obfs-pw");
    }

    #[test]
    fn tuic_congestion_control_is_exported_with_each_clients_spelling() {
        let (nodes, _) = nodes_for(json!([{
            "type": "tuic", "tag": "tuic", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                       "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem",
            "congestion_control": "bbr"
        }]));
        let mut report = ExportReport::default();
        let sing = export(Target::SingBox, &nodes, &mut report).unwrap();
        assert_eq!(sing["outbounds"][0]["congestion_control"], "bbr");
        let mut report = ExportReport::default();
        let mihomo = export(Target::Mihomo, &nodes, &mut report).unwrap();
        assert_eq!(mihomo["proxies"][0]["congestion-controller"], "bbr");
    }

    #[test]
    fn multiple_users_are_reported_not_silently_dropped() {
        let (nodes, report) = nodes_for(json!([{
            "type": "trojan", "tag": "tr", "listen": "0.0.0.0:443",
            "users": [
                {"name": "a", "password": "pw1"},
                {"name": "b", "password": "pw2"},
                {"name": "c", "password": "pw3"}
            ],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }]));
        assert_eq!(nodes.len(), 1, "只导出一个节点");
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("3 个用户") && note.contains("只导出第一个")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn single_user_does_not_emit_a_multi_user_note() {
        let (_, report) = nodes_for(json!([{
            "type": "trojan", "tag": "tr", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }]));
        assert!(report.notes.is_empty(), "{:?}", report.notes);
    }
}

#[cfg(test)]
mod remaining_fields_tests {
    use super::*;
    use crate::config::Config;

    fn one(json_inbound: Value) -> Node {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [json_inbound],
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法");
        let mut report = ExportReport::default();
        nodes(&config, "example.com", &mut report)
            .into_iter()
            .next()
            .expect("应有节点")
    }

    fn get(target: Target, node: &Node) -> Value {
        let mut report = ExportReport::default();
        export(target, std::slice::from_ref(node), &mut report).unwrap()
    }

    #[test]
    fn hysteria2_bandwidth_is_exported_per_client_syntax() {
        let node = one(json!({
            "type": "hysteria2", "tag": "hy2", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem",
            "up_mbps": 50, "down_mbps": 200
        }));
        let sing = get(Target::SingBox, &node);
        assert_eq!(sing["outbounds"][0]["up_mbps"], 50);
        assert_eq!(sing["outbounds"][0]["down_mbps"], 200);

        let mihomo = get(Target::Mihomo, &node);
        assert_eq!(mihomo["proxies"][0]["up"], "50 Mbps");
        assert_eq!(mihomo["proxies"][0]["down"], "200 Mbps");

        let anywhere = get(Target::Anywhere, &node);
        assert_eq!(anywhere["proxies"][0]["upMbps"], 50);
        assert_eq!(anywhere["proxies"][0]["downMbps"], 200);
    }

    #[test]
    fn snell_userkey_mode_and_obfs_are_exported() {
        let node = one(json!({
            "type": "snell", "tag": "snell", "listen": "0.0.0.0:6160",
            "psk": "snell-psk-v5", "version": 5,
            "users": [{"name": "a", "userkey": "client-id-1"}]
        }));
        let mihomo = get(Target::Mihomo, &node);
        let proxy = &mihomo["proxies"][0];
        assert_eq!(proxy["psk"], "snell-psk-v5");
        assert_eq!(proxy["version"], 5);
        assert_eq!(proxy["userkey"], "client-id-1");
    }

    #[test]
    fn snell_v4_obfs_mode_becomes_obfs_opts() {
        let node = one(json!({
            "type": "snell", "tag": "snell", "listen": "0.0.0.0:6160",
            "psk": "psk", "version": 4, "obfs_mode": "http"
        }));
        let mihomo = get(Target::Mihomo, &node);
        assert_eq!(mihomo["proxies"][0]["obfs-opts"]["mode"], "http");
    }
}

#[cfg(test)]
mod version_limit_tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn mihomo_rejects_snell_v6_because_the_binary_does_not_accept_it() {
        // 文档写 1-6，但 mihomo v1.19.33 实测拒绝 v6，这里按实测行为处理。
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{
                    "type": "snell", "tag": "snell", "listen": "0.0.0.0:6160",
                    "psk": "snell-psk-v6-long-enough", "version": 6
                }],
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .unwrap();
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);
        let mut report = ExportReport::default();
        let error = export(Target::Mihomo, &nodes, &mut report)
            .unwrap_err()
            .to_string();
        assert!(error.contains("没有可用节点"), "{error}");
        assert!(
            report.notes.iter().any(|note| note.contains("Snell v6")),
            "{:?}",
            report.notes
        );
    }
}

#[cfg(test)]
mod coverage_gap_tests {
    use super::*;
    use crate::config::Config;

    fn one(json_inbound: Value) -> Node {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [json_inbound],
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法");
        let mut report = ExportReport::default();
        nodes(&config, "example.com", &mut report)
            .into_iter()
            .next()
            .expect("应有节点")
    }

    fn get(target: Target, node: &Node) -> (Value, ExportReport) {
        let mut report = ExportReport::default();
        let value = export(target, std::slice::from_ref(node), &mut report).unwrap();
        (value, report)
    }

    /// 该目标把所有节点都跳过时，`export` 必须拒绝生成纯直连配置。
    fn rejected(target: Target, node: &Node) -> ExportReport {
        let mut report = ExportReport::default();
        let error = export(target, std::slice::from_ref(node), &mut report).unwrap_err();
        assert!(
            error.to_string().contains("没有可用节点"),
            "{target:?} 应拒绝导出：{error}"
        );
        report
    }

    #[test]
    fn naive_exports_to_sing_box_only() {
        let node = one(json!({
            "type": "naive", "tag": "naive", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let (sing, _) = get(Target::SingBox, &node);
        assert_eq!(sing["outbounds"][0]["type"], "naive");
        assert_eq!(sing["outbounds"][0]["password"], "pw");
        // 服务端按 `用户名:密码` 校验；空用户名会被自己的 407 拒绝。
        assert_eq!(sing["outbounds"][0]["username"], "a");
        // Mihomo v1.19.33 没有 naive 代理类型，必须报告并拒绝生成。
        let report = rejected(Target::Mihomo, &node);
        assert!(report.notes.iter().any(|note| note.contains("Naive")));
    }

    #[test]
    fn v2ray_http_transport_maps_to_each_client() {
        let node = one(json!({
            "type": "vless-http", "tag": "vh", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "http": {"path": "/h", "host": ["cdn.example.com"]},
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        // Xray v26 已移除 HTTP transport（文档仍列，实机拒绝）。
        let report = rejected(Target::Xray, &node);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("HTTP transport"))
        );

        let (sing, _) = get(Target::SingBox, &node);
        assert_eq!(sing["outbounds"][0]["transport"]["type"], "http");

        let (mihomo, _) = get(Target::Mihomo, &node);
        assert_eq!(mihomo["proxies"][0]["network"], "http");
        assert_eq!(mihomo["proxies"][0]["http-opts"]["path"][0], "/h");
    }

    #[test]
    fn quic_transport_is_reported_for_xray_and_mihomo() {
        let node = one(json!({
            "type": "vless-quic", "tag": "vq", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "quic": {},
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        // sing-box 有这个形状。
        let (sing, _) = get(Target::SingBox, &node);
        assert_eq!(sing["outbounds"][0]["transport"]["type"], "quic");

        // Xray v26 已移除旧 QUIC；Mihomo 也没有。两者都必须拒绝生成。
        for target in [Target::Xray, Target::Mihomo] {
            let report = rejected(target, &node);
            assert!(
                report.notes.iter().any(|note| note.contains("QUIC")),
                "{target:?} 应报告：{:?}",
                report.notes
            );
        }
    }

    #[test]
    fn snell_v5_exports_as_wire_v4_to_sing_box() {
        let node = one(json!({
            "type": "snell", "tag": "sn", "listen": "0.0.0.0:6160",
            "psk": "snell-psk-v5", "version": 5,
            "users": [{"name": "a", "userkey": "userkey-1"}]
        }));
        let (sing, _) = get(Target::SingBox, &node);
        // sing-box 没有 v5 客户端；官方文档称 v5 线格式与 v4 相同。
        assert_eq!(sing["outbounds"][0]["type"], "snell");
        assert_eq!(sing["outbounds"][0]["version"], 4);
        assert_eq!(sing["outbounds"][0]["userkey"], "userkey-1");
    }

    #[test]
    fn hysteria2_exports_to_xray_with_finalmask_obfs() {
        let node = one(json!({
            "type": "hysteria2", "tag": "hy", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem",
            "up_mbps": 50, "down_mbps": 200,
            "obfs": {"type": "salamander", "password": "obfs-pw"}
        }));
        let (xray, _) = get(Target::Xray, &node);
        let outbound = &xray["outbounds"][0];
        assert_eq!(outbound["protocol"], "hysteria");
        assert_eq!(outbound["streamSettings"]["network"], "hysteria");
        assert_eq!(outbound["streamSettings"]["hysteriaSettings"]["auth"], "pw");
        assert_eq!(
            outbound["streamSettings"]["hysteriaSettings"]["up_mbps"],
            50
        );
        assert_eq!(
            outbound["streamSettings"]["finalmask"]["udp"][0]["type"],
            "salamander"
        );
        assert_eq!(
            outbound["streamSettings"]["finalmask"]["udp"][0]["settings"]["password"],
            "obfs-pw"
        );
    }

    #[test]
    fn mihomo_rejects_a_config_with_no_usable_proxies() {
        // 唯一的入口是 Mihomo 不支持的协议：不能退化成 `MATCH,DIRECT`
        // 的纯直连配置，必须拒绝。
        let node = one(json!({
            "type": "naive", "tag": "naive", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "password": "pw"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let report = rejected(Target::Mihomo, &node);
        assert!(report.notes.iter().any(|note| note.contains("Naive")));
    }
}

#[cfg(test)]
mod exhaustive_audit_tests {
    use super::*;
    use crate::config::Config;

    fn build(inbounds: Value) -> Config {
        Config::from_json(
            &json!({
                "version": 1,
                "inbounds": inbounds,
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法")
    }

    #[test]
    fn vmess_reality_and_trojan_stream_variants_are_exported() {
        // 这四个变体在 2026-11 的字段核对里被 grep 漏掉过，之前是静默丢弃。
        let config = build(json!([
            {"type": "vmess-reality", "tag": "vm-reality", "listen": "0.0.0.0:443",
             "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
             "reality": {"target": {"host": "www.example.com", "port": 443},
                         "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                         "server_names": ["www.example.com"], "short_ids": ["ab"]}},
            // 每个入口独占一个端口：同 (地址, 端口, TCP) 会被 check 拒绝。
            {"type": "trojan-grpc", "tag": "tr-grpc", "listen": "0.0.0.0:8443",
             "users": [{"name": "a", "password": "pw"}], "grpc": {"path": "/TunService/Tun"},
             "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"},
            {"type": "trojan-httpupgrade", "tag": "tr-hu", "listen": "0.0.0.0:8444",
             "users": [{"name": "a", "password": "pw"}], "httpupgrade": {"path": "/u"},
             "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"},
            {"type": "trojan-xhttp", "tag": "tr-xhttp", "listen": "0.0.0.0:8445",
             "users": [{"name": "a", "password": "pw"}], "xhttp": {"path": "/x"},
             "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"}
        ]));
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);
        let tags: Vec<&str> = nodes.iter().map(|node| node.tag.as_str()).collect();
        assert_eq!(tags, ["vm-reality", "tr-grpc", "tr-hu", "tr-xhttp"]);

        let xray = export(Target::Xray, &nodes, &mut report).unwrap();
        let outbounds = xray["outbounds"].as_array().unwrap();
        assert!(outbounds.iter().any(|outbound| {
            outbound["tag"] == "vm-reality" && outbound["streamSettings"]["security"] == "reality"
        }));
        for tag in ["tr-grpc", "tr-hu", "tr-xhttp"] {
            assert!(
                outbounds.iter().any(|outbound| outbound["tag"] == tag),
                "{tag} 未导出：{xray}"
            );
        }
    }

    #[test]
    fn entries_without_a_client_protocol_are_reported_by_name() {
        let config = build(json!([
            {"type": "socks5", "tag": "local-socks", "listen": "127.0.0.1:1080"},
            {"type": "dokodemo-door", "tag": "tproxy", "listen": "127.0.0.1:1081",
             "address": "1.1.1.1", "port": 53},
            {"type": "wireguard", "tag": "wg", "listen": "0.0.0.0:51820",
             "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
             "address": ["10.88.0.1/24"],
             "peers": [{"public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                        "allowed_ips": ["10.88.0.2/32"]}]},
            {"type": "shadowtls", "tag": "stls", "listen": "0.0.0.0:8443",
             "users": [{"name": "u", "password": "stls-password-1"}],
             "handshake": {"server": "www.apple.com", "server_port": 443},
             "detour": "inner"},
            {"type": "socks5", "tag": "inner", "listen": "127.0.0.1:1082"}
        ]));
        let mut report = ExportReport::default();
        assert!(nodes(&config, "example.com", &mut report).is_empty());
        for tag in ["local-socks", "tproxy", "wg", "stls", "inner"] {
            assert!(
                report.notes.iter().any(|note| note.contains(tag)),
                "{tag} 没有报告原因：{:?}",
                report.notes
            );
        }
    }
}

#[cfg(test)]
mod unrepresentable_field_tests {
    use super::*;
    use crate::config::Config;

    fn build(inbounds: Value) -> Config {
        Config::from_json(
            &json!({
                "version": 1,
                "inbounds": inbounds,
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法")
    }

    #[test]
    fn vless_encryption_is_derived_into_all_targets() {
        let config = build(json!([
            {"type": "vless", "tag": "enc", "listen": "0.0.0.0:443",
             "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
             "decryption": "mlkem768x25519plus.native.600s.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
             "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"},
            // 显式 none 是明文，必须照常导出。端口与上面区分，避免 check 拒绝。
            {"type": "vless", "tag": "plain", "listen": "0.0.0.0:8443",
             "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
             "decryption": "none",
             "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"}
        ]));
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);
        let tags: Vec<&str> = nodes.iter().map(|node| node.tag.as_str()).collect();
        // 两个节点都必须导出：服务端 decryption 可以推导出客户端 encryption。
        assert_eq!(tags, ["enc", "plain"], "{:?}", report.notes);

        let enc = nodes.iter().find(|node| node.tag == "enc").unwrap();
        let encryption = enc
            .vless_encryption
            .as_deref()
            .expect("必须推导出 encryption");
        // time 语义不同：服务端 600s（有票据）→ 客户端 0rtt。
        assert!(
            encryption.starts_with("mlkem768x25519plus.native.0rtt."),
            "{encryption}"
        );
        // 推导出的公钥不能与私钥相同（那不是公钥）。
        assert!(!encryption.contains("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"));

        // 明文节点的 encryption 必须保持 None（导出时写 "none"）。
        let plain = nodes.iter().find(|node| node.tag == "plain").unwrap();
        assert!(plain.vless_encryption.is_none());

        // 三个能表达该字段的目标都要写进去。
        let xray = export(
            Target::Xray,
            std::slice::from_ref(enc),
            &mut ExportReport::default(),
        )
        .unwrap();
        // 节点在 outbounds[0]（作为默认出站），direct 在最后。
        assert_eq!(xray["outbounds"][0]["settings"]["encryption"], encryption);
        let sing = export(
            Target::SingBox,
            std::slice::from_ref(enc),
            &mut ExportReport::default(),
        )
        .unwrap();
        assert_eq!(sing["outbounds"][0]["encryption"], encryption);
        let mihomo = export(
            Target::Mihomo,
            std::slice::from_ref(enc),
            &mut ExportReport::default(),
        )
        .unwrap();
        assert_eq!(mihomo["proxies"][0]["encryption"], encryption);
        let anywhere = export(
            Target::Anywhere,
            std::slice::from_ref(enc),
            &mut ExportReport::default(),
        )
        .unwrap();
        assert_eq!(anywhere["proxies"][0]["encryption"], encryption);
    }

    #[test]
    fn tuic_alpn_is_exported_because_clients_must_match_it() {
        let config = build(json!([
            {"type": "tuic", "tag": "tuic", "listen": "0.0.0.0:443",
             "users": [{"name": "a",
                        "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "password": "pw"}],
             "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem",
             "alpn": ["custom", "h3"]}
        ]));
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);

        let sing = export(Target::SingBox, &nodes, &mut report).unwrap();
        assert_eq!(sing["outbounds"][0]["tls"]["alpn"], json!(["custom", "h3"]));

        let mihomo = export(Target::Mihomo, &nodes, &mut report).unwrap();
        assert_eq!(mihomo["proxies"][0]["alpn"], json!(["custom", "h3"]));
    }
}

#[cfg(test)]
mod shadowsocks_multiuser_tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn multiuser_shadowsocks_says_the_exported_key_is_the_identity_key() {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{
                    "type": "shadowsocks", "tag": "ss", "listen": "0.0.0.0:8388",
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "EREREREREREREREREREREQ==",
                    "users": [{"name": "u", "password": "IiIiIiIiIiIiIiIiIiIiIg=="}]
                }],
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法");
        let mut report = ExportReport::default();
        let nodes = nodes(&config, "example.com", &mut report);
        // 身份密钥本身仍可用，因此照常导出单条。
        assert_eq!(nodes.len(), 1);
        assert!(
            report.notes.iter().any(|note| note.contains("身份密钥")),
            "{:?}",
            report.notes
        );
    }
}

#[cfg(test)]
mod default_route_tests {
    use super::*;

    fn one(value: serde_json::Value) -> Node {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "version": 1,
                "inbounds": [value],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"default": "direct"}
            })
            .to_string(),
        )
        .unwrap();
        nodes(&config, "example.com", &mut ExportReport::default())
            .into_iter()
            .next()
            .expect("应生成一个节点")
    }

    /// 导出的客户端配置必须**默认走节点**。
    ///
    /// 此前的实现把 `freedom`/`direct` 放在首位（Xray 用第一个出站当默认），
    /// sing-box 则写死 `route.final = "direct"`。实测结果是：节点离线时，
    /// 用导出的配置仍能访问目标——因为客户端在直连，用户看不出区别。
    #[test]
    fn xray_defaults_to_the_node_not_direct() {
        let node = one(serde_json::json!({
            "type": "vless", "tag": "n", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let value = export(
            Target::Xray,
            std::slice::from_ref(&node),
            &mut ExportReport::default(),
        )
        .unwrap();
        let outbounds = value["outbounds"].as_array().unwrap();
        // Xray 的默认出站是第一个。
        assert_eq!(outbounds[0]["tag"], "n", "首个出站必须是节点");
        assert!(
            outbounds.iter().any(|item| item["protocol"] == "freedom"),
            "仍需保留 freedom 供显式规则使用"
        );
    }

    #[test]
    fn sing_box_final_targets_the_node_not_direct() {
        let node = one(serde_json::json!({
            "type": "vless", "tag": "n", "listen": "0.0.0.0:443",
            "users": [{"name": "a", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "certificate": "/tmp/c.pem", "private_key": "/tmp/k.pem"
        }));
        let value = export(
            Target::SingBox,
            std::slice::from_ref(&node),
            &mut ExportReport::default(),
        )
        .unwrap();
        assert_eq!(value["route"]["final"], "n", "route.final 必须指向节点");
    }

    /// 没有可用节点时必须显式提示：生成的客户端会直连。
    /// 没有可用节点时必须**拒绝导出**，而不是生成一份能直连的配置。
    #[test]
    fn no_nodes_is_rejected_instead_of_producing_a_direct_client() {
        let mut report = ExportReport::default();
        let error = export(Target::Xray, &[], &mut report)
            .unwrap_err()
            .to_string();
        assert!(error.contains("没有可用节点"), "{error}");
    }
}
