use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

impl Host {
    /// 解析配置里的主机名或 IP 字面量。
    ///
    /// 域名只接受标准的 ASCII 标签（字母、数字、`-`、`_`，长度上限 253），
    /// 并统一转成小写；非 ASCII 域名必须先写成 punycode。
    pub fn parse(value: &str) -> Option<Self> {
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Some(Self::Ip(ip));
        }
        let domain = value.trim_end_matches('.');
        if domain.is_empty() || domain.len() > 253 || !domain.is_ascii() {
            return None;
        }
        let valid = domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
        valid.then(|| Self::Domain(domain.to_ascii_lowercase()))
    }
}

/// 解析 `HOST:PORT` 或 `[IPv6]:PORT`；端口必须非 0。
///
/// 未加括号的 IPv6 存在歧义，直接拒绝，与 URL 的写法保持一致。
pub fn parse_endpoint(value: &str) -> Option<(Host, u16)> {
    let (host, raw_port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].parse::<std::net::Ipv6Addr>().ok()?;
        let port = rest[end + 1..].strip_prefix(':')?;
        (Host::Ip(host.into()), port)
    } else {
        let (host, port) = value.rsplit_once(':')?;
        (Host::parse(host)?, port)
    };
    let port: u16 = raw_port.parse().ok()?;
    (port != 0).then_some((host, port))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl From<SocketAddr> for Target {
    fn from(value: SocketAddr) -> Self {
        Self {
            host: Host::Ip(value.ip()),
            port: value.port(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Connect,
    UdpAssociate,
    /// SOCKS5 BIND：服务端监听并接受一个入站连接。
    Bind,
}

#[derive(Debug)]
pub struct Request {
    pub command: Command,
    pub target: Target,
    pub user: Option<String>,
}

// 公共会话只携带身份标识，不携带认证凭据。
#[derive(Debug)]
pub struct Session {
    pub inbound: String,
    pub user: Option<String>,
    pub source: SocketAddr,
    pub network: Network,
    pub target: Target,
}
