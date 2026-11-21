//! AnyTLS正式空闲会话池参数；不增加线协议字段。
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnyTlsClientOptions {
    #[serde(default)]
    pub disable_reuse: bool,
    #[serde(default = "default_interval")]
    pub idle_session_check_interval_ms: u64,
    #[serde(default = "default_interval")]
    pub idle_session_timeout_ms: u64,
    #[serde(default)]
    pub min_idle_session: usize,
}
const fn default_interval() -> u64 {
    30_000
}
impl Default for AnyTlsClientOptions {
    fn default() -> Self {
        Self {
            disable_reuse: false,
            idle_session_check_interval_ms: default_interval(),
            idle_session_timeout_ms: default_interval(),
            min_idle_session: 0,
        }
    }
}
impl AnyTlsClientOptions {
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [
            self.idle_session_check_interval_ms,
            self.idle_session_timeout_ms,
        ] {
            ensure!(
                (5001..=86_400_000).contains(&value),
                "AnyTLS空闲检查/超时必须为5001..86400000毫秒"
            );
        }
        ensure!(self.min_idle_session <= 64, "AnyTLS最少空闲会话不能超过64");
        ensure!(
            !self.disable_reuse || self.min_idle_session == 0,
            "AnyTLS禁用复用时不能保留空闲会话"
        );
        Ok(())
    }
}
