use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// VLESS 认证失败时把原始字节转发到的本地目标（Xray fallback 的稳定子集）。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fallback {
    pub dest: Dest,
    /// PROXY protocol 版本：0 不发送，1 文本，2 二进制。
    #[serde(default)]
    pub xver: u8,
    /// TLS SNI；缺省表示不限制。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 协商的 ALPN；缺省表示不限制。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// 首个 HTTP 请求路径；缺省表示不限制。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Fallback {
    /// 缺省字段视为通配；给定字段必须与观测值精确匹配（SNI 不区分大小写）。
    pub fn matches(&self, sni: Option<&str>, alpn: Option<&str>, path: Option<&str>) -> bool {
        let name_matches = match &self.name {
            None => true,
            Some(expected) => sni.is_some_and(|value| value.eq_ignore_ascii_case(expected)),
        };
        let alpn_matches = match &self.alpn {
            None => true,
            Some(expected) => alpn == Some(expected.as_str()),
        };
        let path_matches = match &self.path {
            None => true,
            Some(expected) => path == Some(expected.as_str()),
        };
        name_matches && alpn_matches && path_matches
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Dest {
    /// 仅端口号，目标固定为回环地址。
    Port(u16),
    /// `host:port`，或以 `/` 开头的 Unix 套接字绝对路径。
    Address(String),
}

/// 已解析的 fallback 目标。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Tcp { host: String, port: u16 },
    Unix(String),
}

impl Dest {
    pub fn endpoint(&self) -> Result<Endpoint> {
        match self {
            Self::Port(port) => Ok(Endpoint::Tcp {
                host: "127.0.0.1".to_owned(),
                port: *port,
            }),
            Self::Address(address) if address.starts_with('/') => {
                ensure!(address.len() > 1, "fallback.dest Unix 路径不得为根目录");
                ensure!(
                    address.len() <= 1024 && !address.contains('\0'),
                    "fallback.dest Unix 路径非法"
                );
                Ok(Endpoint::Unix(address.clone()))
            }
            Self::Address(address) => {
                let (host, port) = address
                    .rsplit_once(':')
                    .ok_or_else(|| anyhow::anyhow!("fallback.dest 必须包含端口"))?;
                ensure!(!host.is_empty(), "fallback.dest 主机不得为空");
                let port = port
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("fallback.dest 端口非法"))?;
                Ok(Endpoint::Tcp {
                    host: host.trim_matches(['[', ']']).to_owned(),
                    port,
                })
            }
        }
    }
}

pub(super) fn validate(fallbacks: &[Fallback], inbound_index: usize) -> Result<()> {
    ensure!(
        fallbacks.len() <= 16,
        "inbounds[{inbound_index}].fallbacks 最多16项"
    );
    for (index, fallback) in fallbacks.iter().enumerate() {
        ensure!(
            fallback.xver <= 2,
            "inbounds[{inbound_index}].fallbacks[{index}].xver 必须是0、1或2"
        );
        let endpoint = fallback.dest.endpoint().map_err(|error| {
            anyhow::anyhow!("inbounds[{inbound_index}].fallbacks[{index}]: {error}")
        })?;
        if let Endpoint::Tcp { port, .. } = endpoint {
            ensure!(
                port != 0,
                "inbounds[{inbound_index}].fallbacks[{index}] 端口不得为0"
            );
        }
        for (field, value) in [
            ("name", &fallback.name),
            ("alpn", &fallback.alpn),
            ("path", &fallback.path),
        ] {
            if let Some(value) = value {
                ensure!(
                    value.len() <= 255 && value.bytes().all(|byte| byte.is_ascii_graphic()),
                    "inbounds[{inbound_index}].fallbacks[{index}].{field} 必须是1到255字节的ASCII"
                );
            }
        }
        if let Some(path) = &fallback.path {
            ensure!(
                path.starts_with('/') && path.len() <= 1024,
                "inbounds[{inbound_index}].fallbacks[{index}].path 必须以/开头"
            );
        }
    }
    Ok(())
}
