//! V2Ray HTTP 传输（sing-box `v2ray-http` / Xray `httpSettings` 的服务端形状）。
//!
//! 明文连接使用 HTTP/1.1 请求后直接切换为裸字节流；TLS 连接协商 h2，
//! 每个请求流承载一条代理连接。服务端只校验 host/path/method 与静态响应头。

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;
const MAX_PATH: usize = 4_096;
const MAX_HEAD: usize = 8_192;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2rayHttp {
    /// 允许的 Host 列表；为空表示接受任意 Host。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    #[serde(default = "default_path")]
    pub path: String,
    /// 允许的请求方法；为空表示接受任意方法。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// 附加在 200 响应上的静态头。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// HTTP/2 连接空闲上限；仅作为配置兼容字段，实际由连接与停机令牌管理。
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
}

impl Default for V2rayHttp {
    fn default() -> Self {
        Self {
            host: Vec::new(),
            path: default_path(),
            method: None,
            headers: BTreeMap::new(),
            idle_timeout_ms: default_idle_timeout_ms(),
        }
    }
}

fn default_path() -> String {
    "/".to_owned()
}

const fn default_idle_timeout_ms() -> u64 {
    DEFAULT_IDLE_TIMEOUT_MS
}

impl V2rayHttp {
    /// 规范化后的请求路径：必须以 `/` 开头。
    pub fn normalized_path(&self) -> String {
        if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        }
    }

    pub fn validate(&self, inbound_index: usize) -> Result<()> {
        let path = self.normalized_path();
        ensure!(
            (1..=MAX_PATH).contains(&path.len()),
            "inbounds[{inbound_index}].http.path 长度必须在1到{MAX_PATH}之间"
        );
        ensure!(
            path.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
            "inbounds[{inbound_index}].http.path 只能包含可见ASCII字符"
        );
        if let Some(method) = &self.method {
            ensure!(
                (1..=32).contains(&method.len()) && is_token(method),
                "inbounds[{inbound_index}].http.method 必须是合法的HTTP方法名"
            );
        }
        let mut head = 0usize;
        for host in &self.host {
            ensure!(
                (1..=253).contains(&host.len())
                    && host.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
                "inbounds[{inbound_index}].http.host 含无效值"
            );
            head = head.saturating_add(host.len());
        }
        for (name, value) in &self.headers {
            ensure!(
                !name.is_empty() && is_token(name),
                "inbounds[{inbound_index}].http.headers 含非法头名称"
            );
            ensure!(
                value.len() <= 1_024
                    && value
                        .bytes()
                        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte)),
                "inbounds[{inbound_index}].http.headers 的 {name} 含非法值"
            );
            head = head.saturating_add(name.len() + value.len());
        }
        ensure!(
            head <= MAX_HEAD,
            "inbounds[{inbound_index}].http 的 host/headers 总量不得超过{MAX_HEAD}字节"
        );
        ensure!(
            self.idle_timeout_ms == 0 || (1_000..=600_000).contains(&self.idle_timeout_ms),
            "inbounds[{inbound_index}].http.idle_timeout_ms 必须在1000到600000之间，或为0"
        );
        Ok(())
    }
}

/// RFC 9110 token 字符集。
fn is_token(value: &str) -> bool {
    value.bytes().all(|byte| {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_normalization() {
        let config = V2rayHttp::default();
        assert_eq!(config.normalized_path(), "/");
        assert_eq!(config.idle_timeout_ms, 30_000);
        config.validate(0).unwrap();
        let config = V2rayHttp {
            path: "custom".to_owned(),
            ..V2rayHttp::default()
        };
        assert_eq!(config.normalized_path(), "/custom");
        config.validate(0).unwrap();
    }

    #[test]
    fn rejects_header_injection_and_bad_methods() {
        let mut config = V2rayHttp::default();
        config.headers.insert("x-test".to_owned(), "ok".to_owned());
        config.validate(0).unwrap();
        config
            .headers
            .insert("x-test".to_owned(), "bad\r\nvalue".to_owned());
        assert!(config.validate(0).is_err());
        config.headers.clear();
        config.method = Some("GE T".to_owned());
        assert!(config.validate(0).is_err());
        config.method = Some("PUT".to_owned());
        config.validate(0).unwrap();
    }
}
