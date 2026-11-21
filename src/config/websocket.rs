use std::{fmt, net::Ipv6Addr, path::Path};

use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocket {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_data: Option<EarlyData>,
}

impl<'de> Deserialize<'de> for WebSocket {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            path: String,
            #[serde(default, deserialize_with = "present_host")]
            host: Option<String>,
            #[serde(default, deserialize_with = "present_early_data")]
            early_data: Option<EarlyData>,
        }

        let fields: Fields = deserialize_object(deserializer)?;
        Ok(Self {
            path: fields.path,
            host: fields.host,
            early_data: fields.early_data,
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum EarlyData {
    Header {
        max_bytes: usize,
        #[serde(default = "default_header_name")]
        header_name: String,
    },
    Path {
        max_bytes: usize,
    },
}

impl<'de> Deserialize<'de> for EarlyData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
        enum Fields {
            Header {
                max_bytes: usize,
                #[serde(default = "default_header_name")]
                header_name: String,
            },
            Path {
                max_bytes: usize,
            },
        }

        Ok(match deserialize_object(deserializer)? {
            Fields::Header {
                max_bytes,
                header_name,
            } => Self::Header {
                max_bytes,
                header_name,
            },
            Fields::Path { max_bytes } => Self::Path { max_bytes },
        })
    }
}

// Serde 派生的结构体/标签枚举也支持位置数组；新配置只接受 JSON 对象。
fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("WebSocket 配置对象")
        }

        fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

impl WebSocket {
    /// 仅作静态检查，不读取证书、监听、解析 DNS 或发起连接。
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_path(&self.path),
            "websocket.path 必须为1到1024字节的合法 ASCII 绝对路径，不得含 query、fragment 或空白"
        );
        if let Some(host) = &self.host {
            ensure!(
                valid_host(host),
                "websocket.host 必须为合法 ASCII authority"
            );
        }
        if let Some(early_data) = &self.early_data {
            ensure!(
                (1..=8192).contains(&early_data.max_bytes()),
                "websocket.early_data.max_bytes 必须在1到8192之间"
            );
            match early_data {
                EarlyData::Header { header_name, .. } => ensure!(
                    valid_header_name(header_name),
                    "websocket.early_data.header_name 必须为至多64字节的非保留 HTTP token"
                ),
                EarlyData::Path { .. } => ensure!(
                    !self.path.contains('%'),
                    "websocket.path 在 path early-data 模式下不得含百分号"
                ),
            }
        }
        Ok(())
    }
}

impl EarlyData {
    pub fn max_bytes(&self) -> usize {
        match self {
            Self::Header { max_bytes, .. } | Self::Path { max_bytes } => *max_bytes,
        }
    }

    pub fn header_name(&self) -> Option<&str> {
        match self {
            Self::Header { header_name, .. } => Some(header_name),
            Self::Path { .. } => None,
        }
    }
}

impl fmt::Debug for WebSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 配置路径也可能误含认证前缀；不能经上层派生 Debug 反射 URI 或头。
        formatter
            .debug_struct("WebSocket")
            .field("path", &"[REDACTED]")
            .field("host", &self.host.as_ref().map(|_| "[REDACTED]"))
            .field("early_data", &self.early_data)
            .finish()
    }
}

impl fmt::Debug for EarlyData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header { max_bytes, .. } => formatter
                .debug_struct("Header")
                .field("max_bytes", max_bytes)
                .field("header_name", &"[REDACTED]")
                .finish(),
            Self::Path { max_bytes } => formatter
                .debug_struct("Path")
                .field("max_bytes", max_bytes)
                .finish(),
        }
    }
}

fn default_header_name() -> String {
    "Sec-WebSocket-Protocol".to_owned()
}

fn present_host<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

fn present_early_data<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<EarlyData>, D::Error> {
    EarlyData::deserialize(deserializer).map(Some)
}

pub(super) fn validate_user_count(count: usize, inbound_index: usize) -> Result<()> {
    ensure!(
        (1..=1024).contains(&count),
        "inbounds[{inbound_index}].users 数量必须在1到1024之间"
    );
    Ok(())
}

pub(super) fn validate_tls(
    certificate: Option<&Path>,
    private_key: Option<&Path>,
    allow_plaintext: bool,
    inbound_index: usize,
) -> Result<()> {
    ensure!(
        certificate.is_some() == private_key.is_some(),
        "inbounds[{inbound_index}].certificate 和 private_key 必须成对配置"
    );
    ensure!(
        certificate.is_some() || allow_plaintext,
        "inbounds[{inbound_index}] 无 TLS 的 VLESS/Trojan WebSocket 必须显式设置 allow_insecure_transport=true"
    );
    Ok(())
}

fn valid_path(path: &str) -> bool {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = path.as_bytes();
    if !(1..=1024).contains(&bytes.len()) || !path.starts_with('/') {
        return false;
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if byte == b'%' {
            let Some(pair) = bytes.get(offset + 1..offset + 3) else {
                return false;
            };
            let (Some(high), Some(low)) = (hex(pair[0]), hex(pair[1])) else {
                return false;
            };
            let decoded = (high << 4) | low;
            // 只解码一次；%25 的字面百分号不再次当作转义序列解析。
            if !path_byte(decoded) && decoded != b'%' {
                return false;
            }
            offset += 3;
        } else {
            if !path_byte(byte) {
                return false;
            }
            offset += 1;
        }
    }
    true
}

fn path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'/' | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn valid_host(authority: &str) -> bool {
    // 成熟authority解析与窄语法策略同时执行；保留原文（包括DNS尾点）。
    // 不做DNS、trim、大小写或IP文本归一化。
    if authority.is_empty()
        || !authority.is_ascii()
        || authority.parse::<http::uri::Authority>().is_err()
    {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((address, suffix)) = rest.split_once(']') else {
            return false;
        };
        if address.parse::<Ipv6Addr>().is_err() {
            return false;
        }
        return suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port);
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    // 不接受 userinfo、通配、百分号、路径、裸 IPv6 或空的 DNS 标签。
    let labels = host.strip_suffix('.').unwrap_or(host);
    !labels.is_empty()
        && labels.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        && port.is_none_or(valid_port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn valid_header_name(name: &str) -> bool {
    if !(1..=64).contains(&name.len())
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    // 除默认子协议载体外，不允许占用握手、安全、转发或代理认证字段。
    if lower == "sec-websocket-protocol" {
        return true;
    }
    !matches!(
        lower.as_str(),
        "host"
            | "connection"
            | "upgrade"
            | "content-length"
            | "transfer-encoding"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-accept"
            | "sec-websocket-extensions"
            | "authorization"
            | "cookie"
            | "set-cookie"
            | "www-authenticate"
            | "authentication-info"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "proxy-authentication-info"
            | "proxy-connection"
            | "forwarded"
            | "via"
            | "x-forwarded"
            | "x-real-ip"
            | "x-client-ip"
    ) && !lower.starts_with("x-forwarded-")
}
