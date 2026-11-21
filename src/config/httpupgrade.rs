use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// HTTPUpgrade 入口：与 WebSocket 相同的 HTTP/1.1 Upgrade 形状，但升级后是原始字节流。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpUpgrade {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl HttpUpgrade {
    pub fn validate(&self, inbound_index: usize) -> Result<()> {
        validate(self, inbound_index)
    }
}

fn valid_path(path: &str) -> bool {
    (1..=1024).contains(&path.len())
        && path.starts_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#' && byte != b'?')
}

pub(super) fn validate(config: &HttpUpgrade, inbound_index: usize) -> Result<()> {
    ensure!(
        valid_path(&config.path),
        "inbounds[{inbound_index}].httpupgrade.path 必须是1到1024字节、以/开头的ASCII路径"
    );
    if let Some(host) = &config.host {
        ensure!(
            (1..=255).contains(&host.len()) && host.bytes().all(|b| b.is_ascii_graphic()),
            "inbounds[{inbound_index}].httpupgrade.host 必须是1到255字节的ASCII主机名"
        );
    }
    Ok(())
}

pub(super) fn validate_tls(
    certificate: Option<&std::path::Path>,
    private_key: Option<&std::path::Path>,
    allow_plaintext: bool,
    inbound_index: usize,
) -> Result<()> {
    ensure!(
        certificate.is_some() == private_key.is_some(),
        "inbounds[{inbound_index}].certificate 和 private_key 必须成对配置"
    );
    ensure!(
        certificate.is_some() || allow_plaintext,
        "inbounds[{inbound_index}] 无 TLS 的 HTTPUpgrade 入口必须显式设置 allow_insecure_transport=true"
    );
    Ok(())
}
