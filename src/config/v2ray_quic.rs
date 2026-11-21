//! V2Ray QUIC 传输（sing-box `v2ray-quic` 的服务端形状）。
//!
//! QUIC 强制 TLS 1.3，ALPN 固定为 `h3`；每条双向流承载一条代理连接，
//! 没有额外的 Xray `quicSettings.security/key` 包头或流加密层。

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_STREAMS: u32 = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2rayQuic {
    /// 连接空闲上限。
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// QUIC keep-alive 间隔；0 表示禁用。
    #[serde(default)]
    pub keep_alive_ms: u64,
    /// 单个 QUIC 连接允许的并发双向流上限。
    #[serde(default = "default_max_streams")]
    pub max_bidi_streams: u32,
}

impl Default for V2rayQuic {
    fn default() -> Self {
        Self {
            idle_timeout_ms: default_idle_timeout_ms(),
            keep_alive_ms: 0,
            max_bidi_streams: default_max_streams(),
        }
    }
}

const fn default_idle_timeout_ms() -> u64 {
    DEFAULT_IDLE_TIMEOUT_MS
}

const fn default_max_streams() -> u32 {
    DEFAULT_MAX_STREAMS
}

impl V2rayQuic {
    pub fn validate(&self, inbound_index: usize) -> Result<()> {
        ensure!(
            (1_000..=600_000).contains(&self.idle_timeout_ms),
            "inbounds[{inbound_index}].quic.idle_timeout_ms 必须在1000到600000之间"
        );
        ensure!(
            self.keep_alive_ms == 0 || (1_000..=60_000).contains(&self.keep_alive_ms),
            "inbounds[{inbound_index}].quic.keep_alive_ms 必须在1000到60000之间，或为0"
        );
        ensure!(
            (1..=1_024).contains(&self.max_bidi_streams),
            "inbounds[{inbound_index}].quic.max_bidi_streams 必须在1到1024之间"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bounded() {
        let config = V2rayQuic::default();
        assert_eq!(config.idle_timeout_ms, 30_000);
        assert_eq!(config.max_bidi_streams, 128);
        config.validate(0).unwrap();
    }

    #[test]
    fn rejects_out_of_range_values() {
        let config = V2rayQuic {
            idle_timeout_ms: 0,
            ..V2rayQuic::default()
        };
        assert!(config.validate(0).is_err());
        let config = V2rayQuic {
            max_bidi_streams: 0,
            ..V2rayQuic::default()
        };
        assert!(config.validate(0).is_err());
        let config = V2rayQuic {
            keep_alive_ms: 500,
            ..V2rayQuic::default()
        };
        assert!(config.validate(0).is_err());
    }
}
