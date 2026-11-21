//! Naive原生出站参数；显式区分H1裸流/填充与H2/H3，UDP只用正式UoT v2。
use std::{collections::BTreeMap, fmt};

use anyhow::{Result, ensure};
use http::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum NaiveHttpVersion {
    #[serde(rename = "1.1")]
    H1,
    #[default]
    #[serde(rename = "2")]
    H2,
    #[serde(rename = "3")]
    H3,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NaiveClientOptions {
    #[serde(default)]
    pub http_version: NaiveHttpVersion,
    /// sing-box H1首八块填充；默认裸流对齐forwardproxy，不能由响应头猜测。
    #[serde(default)]
    pub h1_padding: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_headers: BTreeMap<String, String>,
    /// 正式UoT v2，不是HTTP/3 DATAGRAM。
    #[serde(default)]
    pub udp_over_tcp: bool,
}
impl fmt::Debug for NaiveClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NaiveClientOptions")
            .field("http_version", &self.http_version)
            .field("h1_padding", &self.h1_padding)
            .field("extra_header_count", &self.extra_headers.len())
            .field("udp_over_tcp", &self.udp_over_tcp)
            .finish()
    }
}
impl NaiveClientOptions {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.h1_padding || self.http_version == NaiveHttpVersion::H1,
            "Naive h1_padding仅适用于HTTP/1.1"
        );
        ensure!(
            self.http_version != NaiveHttpVersion::H1 || !self.udp_over_tcp || self.h1_padding,
            "Naive H1 UoT需要显式h1_padding以匹配支持UoT的填充对端"
        );
        ensure!(self.extra_headers.len() <= 32, "Naive额外头超过32项");
        let mut names = std::collections::HashSet::new();
        let mut size = 0usize;
        for (name, value) in &self.extra_headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow::anyhow!("Naive额外头名称无效"))?;
            ensure!(names.insert(name.clone()), "Naive额外头不得大小写重复");
            ensure!(
                !matches!(
                    name.as_str(),
                    "proxy-authorization"
                        | "authorization"
                        | "padding"
                        | "host"
                        | "connection"
                        | "proxy-connection"
                        | "keep-alive"
                        | "upgrade"
                        | "content-length"
                        | "transfer-encoding"
                        | "te"
                        | "trailer"
                ),
                "Naive额外头不得覆盖协议/认证/连接字段"
            );
            ensure!(
                !name.as_str().starts_with('-'),
                "Naive不接受Cronet内部控制头"
            );
            ensure!(
                value.is_ascii()
                    && value.len() <= 2048
                    && !value.bytes().any(|b| b < 0x20 || b == 0x7f),
                "Naive额外头值无效"
            );
            HeaderValue::from_str(value).map_err(|_| anyhow::anyhow!("Naive额外头值无效"))?;
            size += name.as_str().len() + value.len() + 32;
        }
        ensure!(size <= 4096, "Naive额外头总量超过4096字节");
        Ok(())
    }
}
