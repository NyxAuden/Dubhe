//! dokodemo-door 入站：把裸流量固定转发到一个目标。
//!
//! 支持 `network: "tcp"`、`"udp"` 与 `"tcp,udp"`。TCP 由连接 driver 处理，
//! UDP 由固定目标关联处理（每客户端源地址一个上游套接字，受
//! `limits.max_udp_associations` 与空闲回收约束）。`follow_redirect` 等
//! 系统级透明代理选项不在服务端内核范围内。

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::session::{Host, Target};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DokodemoDoor {
    pub address: String,
    pub port: u16,
    #[serde(default = "default_network")]
    pub network: String,
    /// TCP 首包嗅探；只影响路由选择，不修改业务字节。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<Sniffing>,
}

fn default_network() -> String {
    "tcp".to_owned()
}

/// 嗅探来源；只实现 TLS ClientHello SNI 与 HTTP/1.1 Host。
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SniffKind {
    Tls,
    Http,
    /// QUIC Initial（RFC 9001）中的 TLS SNI；只用于 UDP 关联选路。
    Quic,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sniffing {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub dest_override: Vec<SniffKind>,
}

fn default_enabled() -> bool {
    true
}

impl Sniffing {
    fn validate(&self, inbound_index: usize, udp_only: bool) -> Result<()> {
        ensure!(
            !udp_only,
            "inbounds[{inbound_index}].sniffing 仅适用于 dokodemo-door 的 TCP"
        );
        if !self.enabled {
            ensure!(
                self.dest_override.is_empty(),
                "inbounds[{inbound_index}].sniffing.dest_override 在禁用嗅探时不得设置"
            );
            return Ok(());
        }
        ensure!(
            !self.dest_override.is_empty(),
            "inbounds[{inbound_index}].sniffing.dest_override 不得为空"
        );
        let mut seen = std::collections::HashSet::new();
        for kind in &self.dest_override {
            ensure!(
                seen.insert(*kind),
                "inbounds[{inbound_index}].sniffing.dest_override 不得重复"
            );
            ensure!(
                !matches!(kind, SniffKind::Quic),
                "inbounds[{inbound_index}].sniffing.dest_override 只支持 tls/http"
            );
        }
        Ok(())
    }
}

/// 解析 `network` 字段，返回 `(tcp, udp)`。
///
/// 允许大小写差异与逗号两侧空白；空项、未知项和重复项返回 `None`。
pub(crate) fn networks(value: &str) -> Option<(bool, bool)> {
    let (mut tcp, mut udp) = (false, false);
    for part in value.split(',') {
        let part = part.trim();
        if part.eq_ignore_ascii_case("tcp") {
            if tcp {
                return None;
            }
            tcp = true;
        } else if part.eq_ignore_ascii_case("udp") {
            if udp {
                return None;
            }
            udp = true;
        } else {
            return None;
        }
    }
    (tcp || udp).then_some((tcp, udp))
}

impl DokodemoDoor {
    pub fn target(&self) -> Target {
        let host = match self.address.parse::<std::net::IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(self.address.clone()),
        };
        Target {
            host,
            port: self.port,
        }
    }

    pub fn tcp(&self) -> bool {
        networks(&self.network).is_some_and(|(tcp, _)| tcp)
    }

    pub fn udp(&self) -> bool {
        networks(&self.network).is_some_and(|(_, udp)| udp)
    }

    pub fn validate(&self, inbound_index: usize) -> Result<()> {
        ensure!(
            networks(&self.network).is_some(),
            "inbounds[{inbound_index}].network 仅支持 tcp、udp 或 tcp,udp"
        );
        if let Some(sniffing) = &self.sniffing {
            let (tcp, udp) = networks(&self.network).expect("已校验 network");
            sniffing.validate(inbound_index, udp && !tcp)?;
        }
        ensure!(
            !self.address.is_empty() && self.address.len() <= 255,
            "inbounds[{inbound_index}].address 长度无效"
        );
        ensure!(self.port != 0, "inbounds[{inbound_index}].port 不得为 0");
        crate::protocol::address::encode(&self.target())
            .map_err(|_| anyhow::anyhow!("inbounds[{inbound_index}].address 无效"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::networks;

    #[test]
    fn network_parsing_accepts_supported_combinations() {
        for (value, expected) in [
            ("tcp", (true, false)),
            ("UDP", (false, true)),
            ("tcp,udp", (true, true)),
            ("udp, tcp", (true, true)),
            (" TCP , udp ", (true, true)),
        ] {
            assert_eq!(networks(value), Some(expected), "{value}");
        }
    }

    #[test]
    fn network_parsing_rejects_unknown_empty_and_duplicate_items() {
        for value in ["", "quic", "tcp,", ",udp", "tcp,udp,tcp", "tcp,tcp", "udp,"] {
            assert_eq!(networks(value), None, "{value}");
        }
    }
}
