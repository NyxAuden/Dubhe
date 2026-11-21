use std::path::Path;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// gRPC 入口的 RPC 路径；不做 serviceName 猜测或默认值。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grpc {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_path: Option<String>,
}

impl Grpc {
    pub fn validate(&self, inbound_index: usize) -> Result<()> {
        validate(self, inbound_index)
    }

    /// 请求路径必须原样匹配配置的 single 或 multi 路径。
    pub fn mode(&self, path: &str) -> Option<bool> {
        if path == self.path {
            Some(false)
        } else if self.multi_path.as_deref() == Some(path) {
            Some(true)
        } else {
            None
        }
    }
}

fn valid_path(path: &str) -> bool {
    (1..=1024).contains(&path.len())
        && path.starts_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#' && byte != b'?')
}

pub(super) fn validate(grpc: &Grpc, inbound_index: usize) -> Result<()> {
    ensure!(
        valid_path(&grpc.path),
        "inbounds[{inbound_index}].grpc.path 必须是1到1024字节、以/开头的ASCII路径"
    );
    if let Some(multi_path) = &grpc.multi_path {
        ensure!(
            valid_path(multi_path),
            "inbounds[{inbound_index}].grpc.multi_path 必须是1到1024字节、以/开头的ASCII路径"
        );
        ensure!(
            multi_path != &grpc.path,
            "inbounds[{inbound_index}].grpc.multi_path 不得与 path 相同"
        );
    }
    Ok(())
}

/// gRPC 承载的 TLS 策略：VLESS/Trojan 允许显式明文，VMess 必须真实 TLS。
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
        "inbounds[{inbound_index}] 无 TLS 的 gRPC 入口必须显式设置 allow_insecure_transport=true"
    );
    Ok(())
}
