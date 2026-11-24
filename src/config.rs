use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use base64::Engine;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::session::Network;

mod anytls;
mod dokodemo;
mod fallback;
mod grpc;
mod httpupgrade;
mod inbound;
mod kcp;
mod naive;
mod reality;
mod shadowsocks;
mod v2ray_http;
mod v2ray_quic;
mod validate;
pub(crate) mod vless_encryption;
mod vmess;
mod websocket;
#[cfg(test)]
mod websocket_tests;
mod xhttp;
pub use anytls::AnyTlsClientOptions;
pub(crate) use dokodemo::networks as dokodemo_networks;
pub use dokodemo::{DokodemoDoor, SniffKind, Sniffing};
pub use fallback::{Dest, Endpoint, Fallback};
pub use grpc::Grpc;
pub use httpupgrade::HttpUpgrade;
pub use inbound::*;
pub use kcp::{Kcp, KcpHeader, KcpSecurity};
pub use naive::{NaiveClientOptions, NaiveHttpVersion};
pub(crate) use reality::PreparedReality;
pub use reality::{Reality, RealityTarget};
pub use shadowsocks::{Secret, ShadowsocksMethod};
pub(crate) use shadowsocks::{ShadowsocksKeys, prepare as prepare_shadowsocks};
pub use v2ray_http::V2rayHttp;
pub use v2ray_quic::V2rayQuic;
pub use vmess::VmessUser;
pub use websocket::{EarlyData, WebSocket};
pub use xhttp::{Mode, Padding as XhttpPadding, Xhttp};

/// 入站/出站共用的布尔默认值。
pub(crate) fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub route: RouteConfig,
    #[serde(default)]
    pub limits: Limits,
    /// 可选 DNS 配置；省略时沿用系统解析器。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    /// NW3 Egress 出口服务：无本地监听，主动连接远端 Portal 并注册为出口。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nw3_egress: Option<Nw3Egress>,
    /// 外部地理数据集；省略时不支持 `geosite:` / `geoip:` / `mmdb:` 规则。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoConfig>,
    /// 管理/统计 API；只允许回环监听，必须提供 Bearer token。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiConfig>,
    /// 流式入站的首包嗅探策略；dokodemo-door 使用自己的 `sniffing` 字段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<SniffingPolicy>,
    /// Xray 反向 Mux 的 Bridge 角色：主动连接 Portal，并在隧道上运行 Mux 服务端。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reverse_bridges: Vec<ReverseBridge>,
    /// 允许未声明 `users[].reverse.tag` 的账户按路由匹配成为 Portal 载体。
    ///
    /// 默认关闭：Xray 语义下只有显式声明的账户才能建立反向隧道。旧配置若
    /// 依赖「命令 4 的固定域名被路由到 reverse 出站」，需要显式打开此开关；
    /// 打开后任何已认证账户都能注册为载体，只适合受控部署。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reverse_route_fallback: bool,
    /// 部署标识：面板每次提交生成新的 32 位小写十六进制 ID。
    ///
    /// 内核只是把它当**公开关联标记**回显在 `GET /status` 里，用于确认「跑的
    /// 是不是我提交的那一版」。它不是配置哈希、不是认证凭据，也不参与选路；
    /// 手写配置可以省略。复用同一个非空 ID 却改业务内容会被拒绝，避免一个
    /// 标签指向两份不同配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
}

/// 反向 Mux Bridge：引用一个已配置的 VLESS 出站作为到 Portal 的连接。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseBridge {
    /// Bridge 的本地标识，作为 Mux 服务端的 inbound tag 参与路由。
    pub tag: String,
    /// 已配置的 `vless` 出站 tag；其 endpoint/TLS/transport/flow 全部复用。
    pub outbound: String,
    /// 断线重连间隔（毫秒），默认 5000。
    #[serde(default = "default_bridge_reconnect_ms")]
    pub reconnect_ms: u64,
}

const fn default_bridge_reconnect_ms() -> u64 {
    5_000
}

fn default_sniff_timeout() -> u64 {
    300
}

/// 全站首包嗅探策略。
///
/// 语义对齐 Xray/sing-box：嗅探出的域名默认只参与路由选择；只有协议出现在
/// `dest_override` 且未设置 `route_only` 时，才用域名替换拨号目标。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SniffingPolicy {
    #[serde(default)]
    pub enabled: bool,
    /// 生效的入口 tag；空表示所有支持流式嗅探的入口。
    #[serde(default)]
    pub inbounds: Vec<String>,
    /// 允许改写拨号目标的协议；空表示只影响路由。
    #[serde(default)]
    pub dest_override: Vec<SniffKind>,
    /// 即使列出 `dest_override` 也只影响路由。
    #[serde(default)]
    pub route_only: bool,
    /// 首包读取期限（毫秒），默认 300。
    #[serde(default = "default_sniff_timeout")]
    pub timeout_ms: u64,
}

/// 管理/统计 API 配置。
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// 只允许回环地址，避免明文 Bearer token 暴露到网络。
    pub listen: SocketAddr,
    /// 至少 16 字节的可见 ASCII token；与 `token_file` 二选一。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// 从文件读取 token；文件在启动和 `check` 时读取，权限必须为 0600。
    /// 与 `token` 二选一，且修改文件内容后需要重启服务。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
}

impl std::fmt::Debug for ApiConfig {
    /// token 是写权限凭据，诊断输出里只保留是否配置。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfig")
            .field("listen", &self.listen)
            .field(
                "token",
                &if self.token.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .field("token_file", &self.token_file)
            .finish()
    }
}

impl ApiConfig {
    /// 解析并校验最终 token。`token_file` 只在启动/检查时读取一次。
    pub fn load_token(&self) -> Result<String> {
        let token = match &self.token_file {
            Some(path) => {
                ensure!(
                    self.token.is_empty(),
                    "api.token 与 api.token_file 只能配置一个"
                );
                let input = std::fs::read_to_string(path)
                    .map_err(|_| anyhow!("api.token_file 不可读取"))?;
                let token = input.trim_end_matches(['\r', '\n']).to_owned();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = std::fs::metadata(path)
                        .map_err(|_| anyhow!("api.token_file 不可读取"))?
                        .permissions()
                        .mode();
                    ensure!(
                        mode & 0o077 == 0,
                        "api.token_file 权限必须为 0600（不得允许组或其他用户读取）"
                    );
                }
                token
            }
            None => self.token.clone(),
        };
        validate_api_token(&token)?;
        Ok(token)
    }
}

fn validate_api_token(token: &str) -> Result<()> {
    ensure!(
        (16..=512).contains(&token.len()),
        "api.token 长度必须在 16-512 字节"
    );
    ensure!(
        token.bytes().all(|byte| byte.is_ascii_graphic()),
        "api.token 必须是可见 ASCII"
    );
    Ok(())
}

/// 可选 DNS 配置。
///
/// 显式配置时不再读取系统 DNS；`hosts` 先于服务器查询，精确匹配域名
/// （忽略 ASCII 大小写与尾点）。
///
/// `servers` 支持三种写法，并禁止在同一列表中混用明文与加密服务器：
/// - `IP` 或 `IP:PORT`：明文 UDP，端口缺省 53；
/// - `tls://IP:PORT`：DNS over TLS，端口缺省 853；
/// - `https://IP:PORT/PATH`：DNS over HTTPS，端口缺省 443、路径缺省
///   `/dns-query`。加密服务器的主机必须是 IP 字面量，避免引导解析递归。
///
/// 加密服务器必须显式提供 `ca_file`，与上游代理一致，不读取系统根证书；
/// `server_name` 用于证书校验与 SNI，省略时按服务器 IP 地址校验。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// DNS 服务器：明文 UDP 或加密的 DoT/DoH。
    #[serde(default)]
    pub servers: Vec<String>,
    /// 静态 hosts：域名 → IP 列表。
    #[serde(default)]
    pub hosts: BTreeMap<String, Vec<String>>,
    /// DoT/DoH 的 PEM CA 文件；存在加密服务器时必填。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    /// DoT/DoH 的证书校验名与 SNI；省略时使用服务器 IP。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// 按域名选择服务器；首条命中后只使用该条目的服务器列表。
    #[serde(default)]
    pub rules: Vec<DnsRule>,
}

/// DNS 分流规则：字段间 AND、同字段多值 OR，与路由规则一致。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRule {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    pub servers: Vec<String>,
    /// 并发查询该规则的多个服务器，首个成功结果生效；缺省顺序回退。
    #[serde(default)]
    pub race: bool,
}

/// 解析后的 DNS 服务器端点。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DnsServer {
    Udp(SocketAddr),
    Tls(SocketAddr),
    Https(SocketAddr, String),
}

impl DnsConfig {
    /// 解析服务器列表；重复地址去重，保持配置顺序。
    ///
    /// 同一列表内明文与加密服务器不能混用：加密查询走独立的 DoT/DoH
    /// 实现，明文查询走既有 hickory UDP 解析器，混用会产生两种超时与
    /// 重试语义。
    pub(crate) fn server_endpoints(&self) -> Result<Vec<DnsServer>> {
        parse_dns_servers(&self.servers, "dns.servers")
    }
}

/// 解析一个 DNS 服务器列表；同一列表内不能混用明文与加密服务器。
pub(crate) fn parse_dns_servers(servers: &[String], label: &str) -> Result<Vec<DnsServer>> {
    let mut endpoints: Vec<DnsServer> = Vec::new();
    for server in servers {
        let endpoint = if let Some(rest) = server.strip_prefix("tls://") {
            DnsServer::Tls(parse_dns_address(rest, 853, server, label)?)
        } else if let Some(rest) = server.strip_prefix("https://") {
            let (authority, path) = match rest.split_once('/') {
                Some((authority, path)) => (authority, format!("/{path}")),
                None => (rest, "/dns-query".to_owned()),
            };
            ensure!(
                path.len() <= 256 && path.is_ascii() && !path.contains(['?', '#']),
                "{label} 的 HTTPS 路径无效"
            );
            ensure!(
                path.bytes().all(|byte| byte.is_ascii_graphic()),
                "{label} 的 HTTPS 路径必须是可见 ASCII"
            );
            DnsServer::Https(parse_dns_address(authority, 443, server, label)?, path)
        } else {
            DnsServer::Udp(parse_dns_address(server, 53, server, label)?)
        };
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    let encrypted = endpoints
        .iter()
        .filter(|endpoint| !matches!(endpoint, DnsServer::Udp(_)))
        .count();
    ensure!(
        encrypted == 0 || encrypted == endpoints.len(),
        "{label} 不能混用明文与 tls://、https:// 服务器"
    );
    Ok(endpoints)
}

/// 解析 `HOST[:PORT]`；主机只接受 IP 字面量，端口缺省为 `default_port`。
fn parse_dns_address(
    raw: &str,
    default_port: u16,
    server: &str,
    label: &str,
) -> Result<SocketAddr> {
    let address = match raw.parse::<SocketAddr>() {
        Ok(address) => address,
        Err(_) => {
            let ip =
                if let Some(inner) = raw.strip_prefix('[').and_then(|raw| raw.strip_suffix(']')) {
                    inner
                        .parse::<std::net::Ipv6Addr>()
                        .map(std::net::IpAddr::V6)
                } else {
                    raw.parse::<std::net::IpAddr>()
                };
            let ip = ip.map_err(|_| {
                anyhow!("{label} 项 {server:?} 必须是 IP 或 IP:PORT（加密服务器只接受 IP 字面量）")
            })?;
            SocketAddr::new(ip, default_port)
        }
    };
    ensure!(address.port() != 0, "{label} 端口不得为 0");
    Ok(address)
}

/// NW3 Egress 独立服务配置。
///
/// 出口服务不读取本内核的 route/outbounds，也不计入本内核统计；它把 Portal
/// 分配的目标连接直接拨出，与 NW3 Portal 入站的既有边界一致。
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Nw3Egress {
    pub tag: String,
    /// 远端 Portal 端点。支持 `host:port`、`host/tcp:port`、`host/udp:port`；
    /// 省略路径时使用 QUIC（与 Nowhere CLI 一致）。
    pub endpoint: String,
    /// 32 个小写十六进制字符的共享密钥。
    pub key: String,
    /// TLS 校验名；`none` 关闭 SNI。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// 证书 SHA-256 指纹；`none` 交回系统 CA 校验。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Morph 线格式伪装；默认开启，必须与 Portal 一致。
    #[serde(default = "default_true")]
    pub morph: bool,
    /// 出站源地址绑定：`auto` 或具体 IP。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial: Option<String>,
    /// 仅 IPv4 源地址；与 `dial`/`dial6` 互斥。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial4: Option<String>,
    /// 仅 IPv6 源地址；与 `dial`/`dial4` 互斥。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial6: Option<String>,
    /// 源到目标限速（Mbps）；0 或省略表示不限制。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<u32>,
    /// 目标到源限速（Mbps）；0 或省略表示不限制。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etar: Option<u32>,
}
impl std::fmt::Debug for Nw3Egress {
    /// `key` 是出口共享密钥，诊断输出里必须脱敏。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nw3Egress")
            .field("tag", &self.tag)
            .field("endpoint", &self.endpoint)
            .field("key", &"<redacted>")
            .field("sni", &self.sni)
            .field("pin", &self.pin)
            .field("morph", &self.morph)
            .field("dial", &self.dial)
            .field("dial4", &self.dial4)
            .field("dial6", &self.dial6)
            .field("rate", &self.rate)
            .field("etar", &self.etar)
            .finish()
    }
}

/// NW3 Portal 的出口选择。
///
/// `Direct` 由 Portal 自行解析并连接目标；`Egress` 把目标连接交给通过共享密钥
/// 注册到同一 Portal 的 Egress 服务；`Socks` 是 `[USER:PASS@]HOST:PORT` 形式的
/// SOCKS5 上游。三者都不经过本内核的 route/outbounds。
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Nw3Out {
    #[default]
    Direct,
    Egress,
    /// 原始 SOCKS5 端点；可能包含认证信息，因此 Debug/Serialize 之外的输出必须脱敏。
    Socks(String),
}

impl Nw3Out {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Direct => "direct",
            Self::Egress => "egress",
            Self::Socks(raw) => raw,
        }
    }

    /// 脱敏描述：SOCKS 上游只显示类别，不输出用户名或密码。
    fn describe(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Egress => "egress",
            Self::Socks(_) => "socks",
        }
    }
}

impl fmt::Debug for Nw3Out {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.describe())
    }
}

impl<'de> Deserialize<'de> for Nw3Out {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "direct" => Ok(Self::Direct),
            "egress" => Ok(Self::Egress),
            _ => {
                validate_socks_out(&raw).map_err(serde::de::Error::custom)?;
                Ok(Self::Socks(raw))
            }
        }
    }
}

impl Serialize for Nw3Out {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// 校验 Nowhere Portal 的 `out` SOCKS5 端点写法：`[USER:PASS@]HOST:PORT`。
///
/// 这里只做本地早期校验；端点的最终语义由 Nowhere 的 `SocksConfig` 在
/// `Server::check` 构造 Portal 时再次确认。
fn validate_socks_out(raw: &str) -> std::result::Result<(), String> {
    if raw.is_empty() {
        return Err("out 不得为空".into());
    }
    if !raw.is_ascii() {
        return Err("out 必须是 ASCII".into());
    }
    if raw
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '?' | '#'))
    {
        return Err("out 不得包含空白、? 或 #".into());
    }
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("out 中的 % 必须构成合法的 %XX 转义".into());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let (credentials, endpoint) = match raw.split_once('@') {
        Some((credentials, endpoint)) => {
            if endpoint.contains('@') {
                return Err("out 至多包含一个 @".into());
            }
            (Some(credentials), endpoint)
        }
        None => (None, raw),
    };
    if let Some(credentials) = credentials {
        let Some((user, password)) = credentials.split_once(':') else {
            return Err("SOCKS5 认证必须写成 USER:PASS".into());
        };
        if user.is_empty() || password.is_empty() || password.contains(':') {
            return Err("SOCKS5 认证必须是非空且不含额外冒号的 USER:PASS".into());
        }
    }
    validate_socks_endpoint(endpoint)
}

fn validate_socks_endpoint(endpoint: &str) -> std::result::Result<(), String> {
    let (host, raw_port) = if let Some(rest) = endpoint.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err("IPv6 端点缺少 ]".into());
        };
        if rest[..end].parse::<std::net::Ipv6Addr>().is_err() {
            return Err("[] 内必须是 IPv6 地址".into());
        }
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| "IPv6 端点缺少端口".to_string())?;
        (&rest[..end], port)
    } else {
        let (host, port) = endpoint
            .rsplit_once(':')
            .ok_or_else(|| "SOCKS5 端点必须是 HOST:PORT".to_string())?;
        (host, port)
    };
    if host.is_empty() {
        return Err("SOCKS5 端点主机不得为空".into());
    }
    let port: u16 = raw_port
        .parse()
        .map_err(|_| "SOCKS5 端点端口必须是 1-65535".to_string())?;
    if port == 0 {
        return Err("SOCKS5 端点端口不得为 0".into());
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub password: String,
}

impl fmt::Debug for User {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 上层配置的派生 Debug 也必须沿用此处的密码脱敏。
        formatter
            .debug_struct("User")
            .field("name", &self.name)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Snell 用户：userkey 只用于本地身份匹配，任何输出均脱敏。
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnellUser {
    #[serde(default)]
    pub name: String,
    pub userkey: Secret,
}

impl fmt::Debug for SnellUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnellUser")
            .field("name", &self.name)
            .field("userkey", &"[REDACTED]")
            .finish()
    }
}

/// TUIC v5 用户：UUID 与密码共同派生 TLS exporter token。
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TuicUser {
    pub name: String,
    pub uuid: String,
    pub password: Secret,
}

impl fmt::Debug for TuicUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TuicUser")
            .field("name", &self.name)
            .field("uuid", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Hysteria2 混淆配置；当前只支持 salamander。
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Obfs {
    #[serde(rename = "type")]
    pub kind: Hysteria2ObfsType,
    pub password: Secret,
    /// gecko 的最小线上分片长度；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_packet_size: Option<u64>,
    /// gecko 的最大线上分片长度；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packet_size: Option<u64>,
}

impl fmt::Debug for Hysteria2Obfs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2Obfs")
            .field("type", &self.kind)
            .field("password", &"[REDACTED]")
            .field("min_packet_size", &self.min_packet_size)
            .field("max_packet_size", &self.max_packet_size)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Hysteria2ObfsType {
    #[serde(rename = "salamander")]
    Salamander,
    #[serde(rename = "gecko")]
    Gecko,
}

/// Hysteria2 未认证请求的伪装响应。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Masquerade {
    #[serde(rename = "type")]
    pub kind: Hysteria2MasqueradeType,
    /// `string` 类型的响应体。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// `string` 类型的 HTTP 状态码；缺省 200。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// `file` 类型的站点根目录。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Hysteria2MasqueradeType {
    #[serde(rename = "string")]
    String,
    #[serde(rename = "file")]
    File,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum VlessFlow {
    #[default]
    #[serde(rename = "")]
    None,
    #[serde(rename = "xtls-rprx-vision")]
    Vision,
}

impl<'de> Deserialize<'de> for VlessFlow {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // 只接受字符串，不能让枚举的外部标签对象或 null 变成合法 flow。
        match String::deserialize(deserializer)?.as_str() {
            "" => Ok(Self::None),
            "xtls-rprx-vision" => Ok(Self::Vision),
            _ => Err(serde::de::Error::custom("不支持的 VLESS flow")),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VlessUser {
    pub name: String,
    pub uuid: String,
    #[serde(default)]
    pub flow: VlessFlow,
    /// Xray `users[].reverse: { tag }`：该用户的命令 4 连接成为反向隧道，
    /// 并归属到 `tag` 指向的 `reverse` 出站。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverse: Option<ReverseTag>,
}

impl VlessUser {
    /// 该用户是否被允许建立反向隧道。
    pub fn reverse_tag(&self) -> Option<&str> {
        self.reverse.as_ref().map(|reverse| reverse.tag.as_str())
    }
}

/// Xray 的 `reverse: { tag: "..." }` 结构。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseTag {
    pub tag: String,
}

impl fmt::Debug for VlessUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VlessUser")
            .field("name", &self.name)
            .field("uuid", &"[REDACTED]")
            .field("flow", &self.flow)
            .field("reverse", &self.reverse_tag())
            .finish()
    }
}

/// 仅接受标准 8-4-4-4-12 UUID 文本；大小写等价，不接受其他字符串派生身份。
pub fn parse_uuid(value: &str) -> Option<[u8; 16]> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    let mut uuid = [0; 16];
    let mut offset = 0;
    for (index, byte) in uuid.iter_mut().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            if bytes[offset] != b'-' {
                return None;
            }
            offset += 1;
        }
        *byte = (hex(bytes[offset])? << 4) | hex(bytes[offset + 1])?;
        offset += 2;
    }
    Some(uuid)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outbound {
    pub tag: String,
    // 使用字段重命名而非 flatten，确保未知字段仍被严格拒绝。
    #[serde(rename = "type")]
    pub kind: OutboundKind,
    /// `socks5`/`http` 上游地址 `HOST:PORT`；`direct`/`reject` 禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// 上游认证用户名；必须与 `password` 成对出现。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// 上游认证密码；不会出现在 `Debug` 输出中。
    ///
    /// `trojan`/`shadowsocks` 出站只用密码，不配置用户名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// `vless` 出站的用户 UUID。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// `vless` 出站的 flow；`xtls-rprx-vision` 需要 TLS 1.3 裸承载。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<VlessFlow>,
    /// `vless` 出站的 VLESS Encryption 客户端配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    /// `shadowsocks` 出站的加密方法。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<ShadowsocksMethod>,
    /// `shadowsocks` 出站是否使用 UoT（UDP over TCP，v2）。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub udp_over_tcp: bool,
    /// `vmess` 出站的正文安全类型；缺省 3（AES-128-GCM），也支持 4。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<u8>,
    /// VLESS/VMess/Trojan 出站的可选 HTTP/可靠 UDP/QUIC 承载。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<OutboundTransport>,
    /// 到上游代理的 TLS；QUIC 承载直接使用它建立 TLS 1.3。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTls>,
    /// VLESS/VMess/Trojan 出站的 REALITY 客户端参数；与 `tls` 互斥。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<OutboundReality>,
    /// 链式出站的上一跳代理 tag；该出站经它再拨出。仅 TCP 支持链式。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// `reverse` portal 的匹配域名（通常是 `v1.rvs.cool`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// `wireguard` 出站的隧道参数；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<WireguardOptions>,
    /// `hysteria2` 出站的 obfs 参数；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hysteria2: Option<Hysteria2ClientOptions>,
    /// `tuic` 出站的 UDP 承载方式；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuic: Option<TuicClientOptions>,
    /// Snell v4/v5/v6 的记录承载参数；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snell: Option<SnellClientOptions>,
    /// Naive原生HTTP/1.1、HTTP/2或HTTP/3出站；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub naive: Option<NaiveClientOptions>,
    /// AnyTLS会话池参数，省略使用固定上游默认值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anytls: Option<AnyTlsClientOptions>,
    /// `nw3-vector` 出站的 `vector://` URL。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `selector` 组的成员出站 tag；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<String>,
    /// `selector` 组的默认成员；省略时使用成员列表第一项。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// `urltest` 组的 TCP 探测目标 `HOST:PORT`；其他类型禁止配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<String>,
    /// `urltest` 探测周期（毫秒），默认 180000。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_ms: Option<u64>,
    /// `urltest` 切换容差（毫秒），默认 50。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerance_ms: Option<u64>,
    /// `urltest` 单次探测超时（毫秒），默认 2000。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_timeout_ms: Option<u64>,
}

/// WireGuard 出站的隧道参数。
///
/// `endpoint` 是 UDP 对端地址；隧道内目标由路由规则决定，不使用 AllowedIPs
/// 过滤。密钥必须是 32 字节 base64。
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardOptions {
    /// 本地静态私钥（base64）。
    pub private_key: String,
    /// 对端静态公钥（base64）。
    pub peer_public_key: String,
    /// 可选预共享密钥（base64）；必须同样是 32 字节。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    /// 隧道本地地址，支持 IPv4/IPv6 CIDR；通常使用 `/32` 或 `/128`。
    pub address: Vec<String>,
    /// IP MTU；缺省 1420，范围 576-1500。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// 持久保活间隔（秒）；缺省不保活。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u16>,
}

impl fmt::Debug for WireguardOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireguardOptions")
            .field("peer_public_key", &"[REDACTED]")
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("address", &self.address)
            .field("mtu", &self.mtu)
            .field("keepalive_secs", &self.keepalive_secs)
            .finish()
    }
}

/// WireGuard 服务端 peer 配置。
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardServerPeerOptions {
    /// 客户端静态公钥（base64，32 字节）。
    pub public_key: String,
    /// 可选预共享密钥（base64，32 字节）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    /// 该 peer 允许的隧道内源地址 CIDR；同时作为源地址 ACL。
    pub allowed_ips: Vec<String>,
    /// persistent keepalive 间隔（秒）；`0` 或缺省表示关闭。
    #[serde(
        default,
        alias = "keepalive_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub keepalive: Option<u16>,
}

impl fmt::Debug for WireguardServerPeerOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireguardServerPeerOptions")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("allowed_ips", &self.allowed_ips)
            .field("keepalive", &self.keepalive)
            .finish()
    }
}

/// Hysteria2 出站参数。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2ClientOptions {
    /// UDP 层混淆；与入站配置语法相同。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2Obfs>,
    /// 客户端上行锁定速率（Mbps）；用于请求服务端下发的 Brutal 速率。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u64>,
    /// 客户端下行能力（Mbps）；通过 `Hysteria-CC-RX` 告知服务端。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u64>,
}

/// TUIC 出站参数。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TuicClientOptions {
    /// UDP 承载：QUIC DATAGRAM（默认）或每条消息一条单向流。
    #[serde(default)]
    pub udp_relay_mode: TuicUdpRelayMode,
    /// 真实QUIC控制器：cubic（默认）、new_reno、bbr。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<String>,
    /// 默认关闭；只提前发送标准Connect元数据/Heartbeat，业务仍等待握手与认证写入。
    #[serde(default)]
    pub zero_rtt_handshake: bool,
}

/// Snell 正式出站参数；敏感字段使用统一脱敏类型。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnellClientOptions {
    pub psk: Secret,
    pub version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userkey: Option<Secret>,
    /// 仅 v6：default（缺省）、unshaped、unsafe-raw。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_uri: Option<String>,
    /// 仅TCP顺序复用；UDP仍独立建连，不是并发多路复用。
    #[serde(default)]
    pub reuse: bool,
}

impl SnellClientOptions {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(matches!(self.version, 4..=6), "Snell version 仅支持4/5/6");
        if self.version == 6 {
            ensure!(
                (12..=255).contains(&self.psk.0.len()),
                "Snell v6 PSK长度必须在12到255字节之间"
            );
            ensure!(
                self.mode
                    .as_deref()
                    .is_none_or(|mode| matches!(mode, "default" | "unshaped" | "unsafe-raw")),
                "Snell v6 mode无效"
            );
        } else {
            ensure!(
                (1..=4096).contains(&self.psk.0.len()),
                "Snell PSK长度必须在1到4096字节之间"
            );
            ensure!(self.mode.is_none(), "Snell mode仅适用于v6");
        }
        ensure!(
            self.userkey
                .as_ref()
                .is_none_or(|key| (1..=255).contains(&key.0.len())),
            "Snell userkey长度必须在1到255字节之间"
        );
        crate::transport::snell_obfs::validate(
            self.version,
            self.obfs_mode.as_deref(),
            self.obfs_host.as_deref(),
            self.obfs_uri.as_deref(),
        )?;
        Ok(())
    }

    pub(crate) fn record_mode(&self) -> crate::protocol::snell::Mode {
        if self.version != 6 {
            return crate::protocol::snell::Mode::Shaped;
        }
        match self.mode.as_deref() {
            Some("unshaped") => crate::protocol::snell::Mode::Unshaped,
            Some("unsafe-raw") => crate::protocol::snell::Mode::UnsafeRaw,
            _ => crate::protocol::snell::Mode::Default,
        }
    }
}

/// TUIC UDP 承载方式。
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TuicUdpRelayMode {
    #[default]
    Native,
    Quic,
}

/// 解析 WireGuard 的 32 字节 base64 密钥。
///
/// 同时接受标准（带 `=`）与无填充形式；长度或内容不符时返回 `None`。
pub(crate) fn parse_wireguard_key(value: &str) -> Option<[u8; 32]> {
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .ok()?;
    bytes.try_into().ok()
}

/// WireGuard 服务端入站的静态校验；运行期 `WireguardServer::new` 会再次校验。
#[allow(clippy::too_many_arguments)]
fn validate_wireguard_server(
    index: usize,
    private_key: &str,
    addresses: &[String],
    peers: &[WireguardServerPeerOptions],
    mtu: Option<u16>,
    max_peers: Option<usize>,
    max_tcp_connections: Option<usize>,
    max_udp_associations: Option<usize>,
    max_queued_datagrams: Option<usize>,
    max_handshake_inits_per_sec: Option<u32>,
    peer_idle_timeout_secs: Option<u64>,
) -> Result<()> {
    let key = parse_wireguard_key(private_key)
        .ok_or_else(|| anyhow!("inbounds[{index}].private_key 必须是 32 字节 base64"))?;
    ensure!(
        key.iter().any(|byte| *byte != 0),
        "inbounds[{index}].private_key 不得全为 0"
    );
    ensure!(
        (1..=smoltcp::config::IFACE_MAX_ADDR_COUNT).contains(&addresses.len()),
        "inbounds[{index}].address 数量必须在 1-{} 之间（当前 smoltcp 接口容量）",
        smoltcp::config::IFACE_MAX_ADDR_COUNT
    );
    for (address_index, value) in addresses.iter().enumerate() {
        let network = value
            .parse::<IpNet>()
            .map_err(|_| anyhow!("inbounds[{index}].address[{address_index}] 不是有效 CIDR"))?;
        ensure!(
            !network.addr().is_unspecified() && !network.addr().is_multicast(),
            "inbounds[{index}].address[{address_index}] 必须是非未指定/组播地址"
        );
    }
    ensure!(
        (1..=256).contains(&peers.len()),
        "inbounds[{index}].peers 数量必须在 1-256 之间"
    );
    let mut public_keys = HashSet::with_capacity(peers.len());
    let mut networks: Vec<(usize, IpNet)> = Vec::new();
    for (peer_index, peer) in peers.iter().enumerate() {
        let public_key = parse_wireguard_key(&peer.public_key).ok_or_else(|| {
            anyhow!("inbounds[{index}].peers[{peer_index}].public_key 必须是 32 字节 base64")
        })?;
        ensure!(
            public_key.iter().any(|byte| *byte != 0),
            "inbounds[{index}].peers[{peer_index}].public_key 不得全为 0"
        );
        ensure!(
            public_keys.insert(public_key),
            "inbounds[{index}].peers[{peer_index}].public_key 重复"
        );
        if let Some(preshared_key) = &peer.preshared_key {
            ensure!(
                parse_wireguard_key(preshared_key).is_some(),
                "inbounds[{index}].peers[{peer_index}].preshared_key 必须是 32 字节 base64"
            );
        }
        ensure!(
            !peer.allowed_ips.is_empty(),
            "inbounds[{index}].peers[{peer_index}].allowed_ips 不得为空"
        );
        ensure!(
            peer.allowed_ips.len() <= 16,
            "inbounds[{index}].peers[{peer_index}].allowed_ips 最多 16 条"
        );
        for (network_index, value) in peer.allowed_ips.iter().enumerate() {
            let network = value.parse::<IpNet>().map_err(|_| {
                anyhow!(
                    "inbounds[{index}].peers[{peer_index}].allowed_ips[{network_index}] 不是有效 CIDR"
                )
            })?;
            ensure!(
                !network.addr().is_multicast(),
                "inbounds[{index}].peers[{peer_index}].allowed_ips[{network_index}] 不得为组播"
            );
            networks.push((peer_index, network));
        }
    }
    // 本入口的静态 ACL 策略拒绝跨 peer 重叠；这是本地配置限制，
    // 不声称 WireGuard 协议本身禁止最长前缀匹配的 AllowedIPs。
    for left in 0..networks.len() {
        for right in left + 1..networks.len() {
            let (left_peer, left_network) = networks[left];
            let (right_peer, right_network) = networks[right];
            if left_peer == right_peer {
                continue;
            }
            let overlaps = match (&left_network, &right_network) {
                (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_)) => {
                    left_network.contains(&right_network.addr())
                        || right_network.contains(&left_network.addr())
                }
                _ => false,
            };
            ensure!(
                !overlaps,
                "inbounds[{index}].peers[{left_peer}].allowed_ips 与 peers[{right_peer}] 重叠"
            );
        }
    }
    if let Some(mtu) = mtu {
        ensure!(
            (576..=1500).contains(&mtu),
            "inbounds[{index}].mtu 必须在 576-1500 之间"
        );
    }
    let max_peers = max_peers.unwrap_or(256);
    ensure!(
        (1..=65_536).contains(&max_peers),
        "inbounds[{index}].max_peers 必须在 1-65536 之间"
    );
    ensure!(
        peers.len() <= max_peers,
        "inbounds[{index}].peers 数量超过 max_peers"
    );
    for (name, value) in [
        ("max_tcp_connections", max_tcp_connections),
        ("max_udp_associations", max_udp_associations),
    ] {
        if let Some(value) = value {
            ensure!(
                (1..=65_536).contains(&value),
                "inbounds[{index}].{name} 必须在 1-65536 之间"
            );
        }
    }
    if let Some(value) = max_queued_datagrams {
        ensure!(
            (1..=1_000_000).contains(&value),
            "inbounds[{index}].max_queued_datagrams 必须在 1-1000000 之间"
        );
    }
    if let Some(value) = max_handshake_inits_per_sec {
        ensure!(
            (1..=100_000).contains(&value),
            "inbounds[{index}].max_handshake_inits_per_sec 必须在 1-100000 之间"
        );
    }
    if let Some(value) = peer_idle_timeout_secs {
        ensure!(
            (1..=86_400).contains(&value),
            "inbounds[{index}].peer_idle_timeout_secs 必须在 1-86400 之间"
        );
    }
    Ok(())
}

/// 到上游代理的 TLS 参数。
///
/// 本内核不内置公网根证书：`ca_file` 必须是 PEM 证书链，避免把系统信任库
/// 的存在当成隐式安全默认。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundTls {
    /// 信任锚 PEM 文件路径。
    pub ca_file: String,
    /// 证书校验名/SNI；省略时使用 `endpoint` 的主机名（IP 端点按 IP 校验）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
}

/// REALITY 出站参数；公钥与 shortId 来自 Portal 服务端配置。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundReality {
    /// 服务端静态 X25519 公钥（base64，URL-safe 或标准字母表）。
    pub public_key: String,
    /// 8 字节以内十六进制 shortId；空表示未配置。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub short_id: String,
    /// SNI 与 REALITY serverName；必须是 DNS 名，不能是 IP。
    pub server_name: String,
    /// 客户端版本三元组，例如 `26.10.31`；缺省使用当前固定基线。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 可选的 ML-DSA-65 服务端临时证书公钥（base64）；启用后校验证书
    /// 第一个扩展对 raw ClientHello/ServerHello 的签名。
    #[serde(
        rename = "mldsa65Verify",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mldsa65_verify: Option<String>,
}

/// 出站传输包装；与代理协议、外层安全层分别配置。
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutboundTransport {
    #[serde(rename = "type")]
    pub kind: OutboundTransportType,
    /// HTTP 类承载的路径，缺省 `/`；gRPC 必须显式指定。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// HTTP Host/authority；缺省使用 `endpoint`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// gRPC 是否使用 MultiHunk 批量编码；缺省 false。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    /// gRPC 请求的 `:authority`；缺省按 Xray 语义从 TLS server_name/端点解析。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// gRPC 请求的 `user-agent`；支持 Xray 别名 chrome/firefox/edge/golang。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// gRPC keepalive 空闲 PING 间隔（秒）；0 或缺省表示不启用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<u32>,
    /// gRPC keepalive PING 应答超时（秒）；0 或缺省使用 20 秒。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check_timeout: Option<u32>,
    /// 无活动流时仍允许 keepalive PING；当前单 RPC 连接模型下无额外影响。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permit_without_stream: Option<bool>,
    /// h2 `SETTINGS_INITIAL_WINDOW_SIZE`；0 或缺省使用库默认值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_windows_size: Option<u32>,
    /// XHTTP 上行模式；缺省 auto。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// XHTTP 使用的 HTTP 版本；缺省 HTTP/2（明文为 h2c）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version: Option<OutboundHttpVersion>,
    /// XHTTP 请求附加头；受保护的协议头不能覆盖。
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
    /// XHTTP 请求 padding 长度范围；缺省使用协议默认范围。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding: Option<XhttpPadding>,
    /// XHTTP 单次上行块上限；缺省 64 KiB。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_post_bytes: Option<usize>,
    /// mKCP 参数；省略时使用与入站相同的默认值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kcp: Option<Kcp>,
    /// QUIC 资源参数；也可用于 XHTTP/3。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<V2rayQuic>,
}

impl fmt::Debug for OutboundTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundTransport")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field("host", &self.host)
            .field("multi", &self.multi)
            .field("authority", &self.authority)
            .field("user_agent", &self.user_agent)
            .field("idle_timeout", &self.idle_timeout)
            .field("health_check_timeout", &self.health_check_timeout)
            .field("permit_without_stream", &self.permit_without_stream)
            .field("initial_windows_size", &self.initial_windows_size)
            .field("mode", &self.mode)
            .field("http_version", &self.http_version)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("x_padding", &self.x_padding)
            .field("max_post_bytes", &self.max_post_bytes)
            .field("kcp", &self.kcp.as_ref().map(|_| "[CONFIGURED]"))
            .field("quic", &self.quic)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum OutboundHttpVersion {
    #[serde(rename = "1.1")]
    Http1,
    #[default]
    #[serde(rename = "2")]
    Http2,
    #[serde(rename = "3")]
    Http3,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum OutboundTransportType {
    #[serde(rename = "ws")]
    Ws,
    #[serde(rename = "grpc")]
    Grpc,
    #[serde(rename = "httpupgrade")]
    HttpUpgrade,
    #[serde(rename = "xhttp")]
    Xhttp,
    #[serde(rename = "kcp")]
    Kcp,
    /// sing-box `v2ray-quic` 形状；不含 Xray 旧 quicSettings 加密/混淆层。
    #[serde(rename = "quic")]
    Quic,
}

impl OutboundTransport {
    pub(crate) fn http_version(&self) -> OutboundHttpVersion {
        self.http_version.unwrap_or_default()
    }

    /// 这些承载直接使用 UDP，不能套在仅提供 TCP CONNECT 的上一跳内。
    pub(crate) fn uses_udp_socket(&self) -> bool {
        matches!(
            self.kind,
            OutboundTransportType::Kcp | OutboundTransportType::Quic
        ) || self.kind == OutboundTransportType::Xhttp
            && self.http_version() == OutboundHttpVersion::Http3
    }

    fn validate(&self, has_tls: bool, index: usize) -> Result<()> {
        ensure!(
            self.kind == OutboundTransportType::Grpc || self.multi.is_none(),
            "outbounds[{index}].transport.multi 仅适用于 grpc"
        );
        ensure!(
            self.kind == OutboundTransportType::Grpc
                || (self.authority.is_none()
                    && self.user_agent.is_none()
                    && self.idle_timeout.is_none()
                    && self.health_check_timeout.is_none()
                    && self.permit_without_stream.is_none()
                    && self.initial_windows_size.is_none()),
            "outbounds[{index}].transport 的 authority/user_agent/idle_timeout/health_check_timeout/permit_without_stream/initial_windows_size 仅适用于 grpc"
        );
        if let Some(authority) = &self.authority {
            ensure!(
                (1..=255).contains(&authority.len())
                    && authority.bytes().all(|byte| byte.is_ascii_graphic())
                    && authority.parse::<http::uri::Authority>().is_ok(),
                "outbounds[{index}].transport.authority 无效"
            );
        }
        if let Some(user_agent) = &self.user_agent {
            ensure!(
                user_agent.len() <= 512
                    && !user_agent.contains(['\r', '\n'])
                    && http::header::HeaderValue::from_str(user_agent).is_ok(),
                "outbounds[{index}].transport.user_agent 无效"
            );
        }
        for (name, value) in [
            ("idle_timeout", self.idle_timeout),
            ("health_check_timeout", self.health_check_timeout),
        ] {
            ensure!(
                value.is_none_or(|seconds| seconds <= 86_400),
                "outbounds[{index}].transport.{name} 必须在0到86400秒之间"
            );
        }
        ensure!(
            self.initial_windows_size
                .is_none_or(|size| size <= 2_147_483_647),
            "outbounds[{index}].transport.initial_windows_size 必须在0到2147483647之间"
        );
        ensure!(
            self.kind == OutboundTransportType::Xhttp
                || (self.mode.is_none()
                    && self.http_version.is_none()
                    && self.headers.is_empty()
                    && self.x_padding.is_none()
                    && self.max_post_bytes.is_none()),
            "outbounds[{index}].transport 的 mode/http_version/headers/x_padding/max_post_bytes 仅适用于 xhttp"
        );
        ensure!(
            self.kind == OutboundTransportType::Kcp || self.kcp.is_none(),
            "outbounds[{index}].transport.kcp 仅适用于 kcp"
        );
        let quic = self.kind == OutboundTransportType::Quic
            || self.kind == OutboundTransportType::Xhttp
                && self.http_version() == OutboundHttpVersion::Http3;
        ensure!(
            quic || self.quic.is_none(),
            "outbounds[{index}].transport.quic 仅适用于 quic 或 xhttp HTTP/3"
        );
        ensure!(
            !quic || has_tls,
            "outbounds[{index}] QUIC 承载必须配置 tls（含 ca_file）"
        );
        if matches!(
            self.kind,
            OutboundTransportType::Kcp | OutboundTransportType::Quic
        ) {
            ensure!(
                self.path.is_none() && self.host.is_none(),
                "outbounds[{index}].transport 的 kcp/quic 不允许 path/host"
            );
        }
        if self.kind == OutboundTransportType::Grpc {
            ensure!(
                self.path.is_some() && self.host.is_none(),
                "outbounds[{index}].transport 的 grpc 需要 path 且不允许 host"
            );
        }
        if let Some(path) = &self.path {
            ensure!(
                (1..=1024).contains(&path.len())
                    && path.starts_with('/')
                    && path.bytes().all(|byte| byte.is_ascii_graphic())
                    && !path.contains('#')
                    && (self.kind != OutboundTransportType::Grpc
                        && self.kind != OutboundTransportType::Xhttp
                        || !path.contains('?')),
                "outbounds[{index}].transport.path 必须是以 / 开头的 ASCII 路径"
            );
        }
        if let Some(host) = &self.host {
            ensure!(
                (1..=255).contains(&host.len())
                    && host.bytes().all(|byte| byte.is_ascii_graphic())
                    && host.parse::<http::uri::Authority>().is_ok(),
                "outbounds[{index}].transport.host 无效"
            );
        }
        if let Some(kcp) = &self.kcp {
            kcp.validate(index)
                .map_err(|_| anyhow!("outbounds[{index}].transport.kcp 参数无效"))?;
        }
        if let Some(quic) = &self.quic {
            quic.validate(index)
                .map_err(|_| anyhow!("outbounds[{index}].transport.quic 参数无效"))?;
        }
        if let Some(padding) = self.x_padding {
            ensure!(
                padding.from <= padding.to && padding.to <= 16_384,
                "outbounds[{index}].transport.x_padding 必须满足 from<=to<=16384"
            );
        }
        if let Some(max) = self.max_post_bytes {
            ensure!(
                (64..=65_536).contains(&max),
                "outbounds[{index}].transport.max_post_bytes 必须在64到65536之间"
            );
        }
        ensure!(
            self.headers.len() <= 16,
            "outbounds[{index}].transport.headers 最多16项"
        );
        for (name, value) in &self.headers {
            ensure!(
                name.len() <= 64
                    && http::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
                    && !matches!(
                        name.to_ascii_lowercase().as_str(),
                        "host"
                            | "connection"
                            | "content-length"
                            | "transfer-encoding"
                            | "upgrade"
                            | "te"
                            | "trailer"
                            | "cookie"
                            | "x-padding"
                            | "x-session"
                            | "x_session"
                            | "x-seq"
                            | "x_seq"
                            | "x_padding"
                    )
                    && value.len() <= 1024
                    && value.is_ascii()
                    && http::header::HeaderValue::from_str(value).is_ok(),
                "outbounds[{index}].transport.headers 含无效或受保护的头"
            );
        }
        Ok(())
    }
}

impl fmt::Debug for Outbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Outbound")
            .field("tag", &self.tag)
            .field("kind", &self.kind)
            .field("endpoint", &self.endpoint)
            .field("username", &self.username)
            .field("password", &self.password.as_deref().map(|_| "[REDACTED]"))
            .field("uuid", &self.uuid.as_deref().map(|_| "[REDACTED]"))
            .field("flow", &self.flow)
            .field("encryption", &self.encryption)
            .field("method", &self.method)
            .field("udp_over_tcp", &self.udp_over_tcp)
            .field("security", &self.security)
            .field("transport", &self.transport)
            .field("domain", &self.domain)
            .field("wireguard", &self.wireguard)
            .field("hysteria2", &self.hysteria2)
            .field("tuic", &self.tuic)
            .field("snell", &self.snell)
            .field("naive", &self.naive)
            .field("anytls", &self.anytls)
            .field("url", &self.url)
            .field("tls", &self.tls.is_some())
            .field("reality", &self.reality)
            .field("via", &self.via)
            .field("outbounds", &self.outbounds)
            .field("default", &self.default)
            .field("probe", &self.probe)
            .field("interval_ms", &self.interval_ms)
            .field("tolerance_ms", &self.tolerance_ms)
            .field("probe_timeout_ms", &self.probe_timeout_ms)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundKind {
    Direct,
    Reject,
    Socks5,
    Http,
    /// VLESS v0 上游（可选 Vision 或 Encryption，TCP/UDP）。
    Vless,
    /// VMess AEAD 上游（仅 TCP、security 3/4）。
    Vmess,
    /// Trojan 上游（必须 TLS）。
    Trojan,
    /// Shadowsocks AEAD 上游（仅 TCP）。
    Shadowsocks,
    /// AnyTLS 上游（必须 TLS，TCP only）。
    Anytls,
    /// Snell v4/v5/v6 上游（TCP 与正式 UDP-over-stream）。
    Snell,
    /// Naive普通HTTP/1.1、HTTP/2或HTTP/3 CONNECT，可选正式UoT v2。
    Naive,
    /// ShadowTLS v3 客户端；无目标，仅作为其他 TCP 代理出站的 via detour。
    ShadowTls,
    /// Hysteria2 上游（QUIC/HTTP3，TCP 与 UDP DATAGRAM）。
    Hysteria2,
    /// TUIC v5 上游（QUIC，TCP 与 UDP native/quic）。
    Tuic,
    /// Nowhere Vector 客户端（`vector://`）。
    #[serde(rename = "nw3-vector")]
    Nw3Vector,
    /// WireGuard 出站（隧道内 TCP）。
    Wireguard,
    /// 反向 Mux portal：普通流量经已注册的反向隧道转发。
    Reverse,
    /// 静态出站组：按 `default`（省略时第一项）解析到一个成员出站。
    Selector,
    /// 延迟探测组：周期性经各成员拨号 `probe`，选择延迟最低者。
    Urltest,
}

impl OutboundKind {
    /// 该出站是否通过上游代理转发。
    pub fn is_proxy(self) -> bool {
        matches!(
            self,
            Self::Socks5
                | Self::Http
                | Self::Vless
                | Self::Vmess
                | Self::Trojan
                | Self::Shadowsocks
                | Self::Anytls
                | Self::Snell
                | Self::Naive
                | Self::ShadowTls
                | Self::Hysteria2
                | Self::Tuic
                | Self::Nw3Vector
                | Self::Wireguard
        )
    }

    /// 管理接口展示用的稳定名称。
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Reject => "reject",
            Self::Socks5 => "socks5",
            Self::Http => "http",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::Anytls => "anytls",
            Self::Snell => "snell",
            Self::Naive => "naive",
            Self::ShadowTls => "shadowtls",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Nw3Vector => "nw3-vector",
            Self::Wireguard => "wireguard",
            Self::Reverse => "reverse",
            Self::Selector => "selector",
            Self::Urltest => "urltest",
        }
    }
}

/// 外部地理数据集路径。
///
/// 内核**只读取、不内置、不下载、不校验**用户提供的文件：数据正确性由数据源
/// 负责，本项目不为第三方列表背书。
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeoConfig {
    /// Xray/Mihomo 的 `geosite.dat`（protobuf）；供 `geosite:<code>` 使用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geosite: Option<PathBuf>,
    /// Xray/Mihomo 的 `geoip.dat`（protobuf）；供 `geoip:<code>` 使用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<PathBuf>,
    /// MaxMind `mmdb` 数据库；供 `mmdb:<code>` 使用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmdb: Option<PathBuf>,
    /// sing-box rule-set source JSON（非 SRS 二进制）；供 `rule_set:<tag>` 使用。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_sets: Vec<RuleSetSource>,
}

/// 一个 sing-box rule-set source JSON 文件。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSource {
    pub tag: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub default: String,
    /// 域名目标的 IP 规则匹配策略。
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// 域名目标的 IP 规则匹配策略。
///
/// `as-is`（默认）只按原始目标匹配，不在路由阶段解析域名；`ip-if-non-match`
/// 在没有任何规则命中时才解析域名并重试 IP 条件。解析失败按未命中处理，
/// 最终回落到默认出站。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
}

/// `ip_cidrs` 的一项：要么是具体 CIDR，要么是地理数据集引用。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IpEntry {
    Cidr(IpNet),
    Geo(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub inbounds: Vec<String>,
    #[serde(default)]
    pub networks: Vec<Network>,
    #[serde(default)]
    pub domains: Vec<String>,
    /// 域名后缀匹配（忽略大小写与尾点）。
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// 域名包含匹配（忽略大小写）。
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    /// 域名正则匹配（RE2 语法，作用于小写域名）；对齐 sing-box `domain_regex`。
    #[serde(default)]
    pub domain_regex: Vec<String>,
    /// IP 目标匹配：可以是 CIDR（`10.0.0.0/8`），也可以是地理数据集引用
    /// （`geoip:cn`、`mmdb:CN`）。后者在配置加载阶段展开或转为运行期匹配，
    /// 与 Xray 的 `"ip": ["geoip:cn"]` 写法一致。
    #[serde(default)]
    pub ip_cidrs: Vec<IpEntry>,
    /// `true` 时匹配私有/内网目标地址；对齐 Xray `geoip:private`、sing-box `ip_is_private`。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_is_private: bool,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    /// 反转本条规则的匹配结果；对齐 sing-box `invert`、Xray 的 `!` 前缀。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    pub outbound: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// 单个源 IP 的默认握手槽上限。
///
/// 取 `max_handshakes`(64) 的 1/8：单个 IP 仍可并发握手 8 条（足够正常客户端
/// 的并发），而占不满全局闸门，其他 IP 始终有槽可用。
fn default_per_ip_handshakes() -> usize {
    8
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_connections: usize,
    pub max_handshakes: usize,
    /// 单个源 IP 同时可占用的握手槽上限。
    ///
    /// `max_handshakes` 是每个入口的**全局**闸门：一个 IP 开满它就等于
    /// 让该入口对其他所有 IP 不可用（实测 64 条不发 ClientHello 的连接可让
    /// 合法握手 0/3）。这个字段给单个源 IP 单独设上限，保证握手机会不被
    /// 一方独占。`0` 表示不限制（退化为原行为）。
    #[serde(default = "default_per_ip_handshakes")]
    pub per_ip_handshakes: usize,
    pub max_grpc_streams: usize,
    pub max_grpc_streams_per_connection: usize,
    pub max_xhttp_sessions: usize,
    pub max_replay_entries: usize,
    pub max_vmess_replay_entries: usize,
    pub max_reality_replay_entries: usize,
    pub max_udp_associations: usize,
    pub max_udp_targets: usize,
    pub udp_queue_bytes: usize,
    pub udp_queue_packets: usize,
    pub max_udp_payload: usize,
    pub handshake_timeout_ms: u64,
    pub dial_timeout_ms: u64,
    pub dial_attempt_timeout_ms: u64,
    pub dns_timeout_ms: u64,
    pub max_dns_queries: usize,
    pub udp_idle_timeout_ms: u64,
    /// TCP 中继双向空闲超时；`0` 表示不限制。对齐 Xray `connIdle` 的默认 300 秒。
    pub idle_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
    pub stats_interval_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_handshakes: 64,
            per_ip_handshakes: 8,
            max_grpc_streams: 256,
            max_grpc_streams_per_connection: 16,
            max_xhttp_sessions: 256,
            max_replay_entries: 65536,
            max_vmess_replay_entries: 65536,
            max_reality_replay_entries: 65536,
            max_udp_associations: 256,
            max_udp_targets: 64,
            udp_queue_bytes: 262_144,
            udp_queue_packets: 64,
            max_udp_payload: 65_507,
            handshake_timeout_ms: 10_000,
            dial_timeout_ms: 10_000,
            dial_attempt_timeout_ms: 2_000,
            dns_timeout_ms: 5_000,
            max_dns_queries: 64,
            udp_idle_timeout_ms: 60_000,
            idle_timeout_ms: 300_000,
            shutdown_timeout_ms: 5_000,
            stats_interval_ms: 30_000,
        }
    }
}

#[cfg(test)]
mod tests;
