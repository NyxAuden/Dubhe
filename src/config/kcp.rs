use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// mKCP 传输参数；字段名与 Xray `kcpSettings` 保持一致。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kcp {
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default = "default_tti")]
    pub tti: u32,
    #[serde(default = "default_uplink")]
    pub uplink_capacity: u32,
    #[serde(default = "default_downlink")]
    pub downlink_capacity: u32,
    #[serde(default = "default_cwnd_multiplier")]
    pub cwnd_multiplier: u32,
    #[serde(default = "default_max_sending_window")]
    pub max_sending_window: u32,
    /// 老版 Xray/Clash 的 `kcpSettings.header` 混淆头。
    #[serde(default)]
    pub header: KcpHeader,
    /// 老版 Xray 的 `kcpSettings.seed`；只替换数据包认证层为 AES-128-GCM。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    /// 数据包认证层；`legacy` 对应 Xray 25 及更早版本的默认 6 字节认证。
    #[serde(default)]
    pub security: KcpSecurity,
}

impl Default for Kcp {
    fn default() -> Self {
        Self {
            mtu: default_mtu(),
            tti: default_tti(),
            uplink_capacity: default_uplink(),
            downlink_capacity: default_downlink(),
            cwnd_multiplier: default_cwnd_multiplier(),
            max_sending_window: default_max_sending_window(),
            header: KcpHeader::None,
            seed: None,
            security: KcpSecurity::Legacy,
        }
    }
}

impl Kcp {
    pub fn validate(&self, inbound_index: usize) -> Result<()> {
        ensure!(
            (21..=9000).contains(&self.mtu),
            "inbounds[{inbound_index}].kcp.mtu 必须在21到9000之间"
        );
        ensure!(
            (10..=1000).contains(&self.tti),
            "inbounds[{inbound_index}].kcp.tti 必须在10到1000之间"
        );
        ensure!(
            (1..=1024).contains(&self.uplink_capacity),
            "inbounds[{inbound_index}].kcp.uplink_capacity 必须在1到1024之间"
        );
        ensure!(
            (1..=1024).contains(&self.downlink_capacity),
            "inbounds[{inbound_index}].kcp.downlink_capacity 必须在1到1024之间"
        );
        ensure!(
            (1..=64).contains(&self.cwnd_multiplier),
            "inbounds[{inbound_index}].kcp.cwnd_multiplier 必须在1到64之间"
        );
        ensure!(
            self.max_sending_window / self.mtu >= 1,
            "inbounds[{inbound_index}].kcp.max_sending_window 必须至少为 mtu"
        );
        ensure!(
            self.sending_buffer_segments() <= MAX_WINDOW_SEGMENTS,
            "inbounds[{inbound_index}].kcp.max_sending_window 过大"
        );
        ensure!(
            self.sending_in_flight() <= MAX_WINDOW_SEGMENTS
                && self.receiving_in_flight() <= MAX_WINDOW_SEGMENTS,
            "inbounds[{inbound_index}].kcp 容量与 mtu/tti 组合产生过大的窗口"
        );
        if let Some(seed) = &self.seed {
            ensure!(
                self.security == KcpSecurity::Legacy,
                "inbounds[{inbound_index}].kcp.seed 不能与 security=none 并存"
            );
            ensure!(
                (1..=1024).contains(&seed.len()),
                "inbounds[{inbound_index}].kcp.seed 长度必须在1到1024字节之间"
            );
        }
        self.header.validate(inbound_index)?;
        Ok(())
    }

    /// Xray 语义：发送在途窗口按上行容量、MTU 与 TTI 换算，最少 8 段。
    pub fn sending_in_flight(&self) -> u32 {
        self.in_flight(self.uplink_capacity)
    }

    pub fn receiving_in_flight(&self) -> u32 {
        self.in_flight(self.downlink_capacity)
    }

    pub fn sending_buffer_segments(&self) -> u32 {
        self.max_sending_window / self.mtu
    }

    fn in_flight(&self, capacity: u32) -> u32 {
        let size = u64::from(capacity) * 1024 * 1024
            / u64::from(self.mtu)
            / u64::from(1000 / self.tti.max(1));
        u32::try_from(size.max(8)).unwrap_or(MAX_WINDOW_SEGMENTS)
    }

    /// Xray 兼容的 KCP 单段正文预算：MTU 减去 18 字节 KCP 数据头。
    /// 混淆头与认证层是 KCP 之外的外层封装，不改变该配置语义。
    pub fn mss(&self) -> usize {
        (self.mtu as usize).saturating_sub(crate::transport::kcp::segment::DATA_OVERHEAD)
    }
}

/// 窗口上限，避免异常配置把单连接内存放大到不可控。
const MAX_WINDOW_SEGMENTS: u32 = 65_536;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KcpSecurity {
    /// 4 字节 FNV-1a 校验 + 2 字节长度 + 字级 XOR。
    #[default]
    Legacy,
    /// 裸 KCP 分段（Xray 26 默认）。
    None,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum KcpHeader {
    #[default]
    None,
    Dns {
        #[serde(default = "default_domain")]
        domain: String,
    },
    Dtls,
    Srtp,
    Utp,
    Wechat,
    Wireguard,
}

impl KcpHeader {
    fn validate(&self, inbound_index: usize) -> Result<()> {
        if let Self::Dns { domain } = self {
            ensure!(
                (1..=253).contains(&domain.len()),
                "inbounds[{inbound_index}].kcp.header.domain 长度必须在1到253字节之间"
            );
            let mut encoded = 0usize;
            for label in domain.trim_end_matches('.').split('.') {
                ensure!(
                    !label.is_empty() && label.len() <= 63,
                    "inbounds[{inbound_index}].kcp.header.domain 标签长度无效"
                );
                ensure!(
                    label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
                    "inbounds[{inbound_index}].kcp.header.domain 含非法字符"
                );
                encoded += 1 + label.len();
            }
            ensure!(
                encoded < 255,
                "inbounds[{inbound_index}].kcp.header.domain 编码后超过255字节"
            );
        }
        Ok(())
    }
}

fn default_mtu() -> u32 {
    1350
}
fn default_tti() -> u32 {
    50
}
fn default_uplink() -> u32 {
    5
}
fn default_downlink() -> u32 {
    20
}
fn default_cwnd_multiplier() -> u32 {
    1
}
fn default_max_sending_window() -> u32 {
    2 * 1024 * 1024
}
fn default_domain() -> String {
    "www.baidu.com".to_owned()
}

/// mKCP 的 TLS 策略。
///
/// mKCP 自带 AES-128-GCM 数据包认证层，不属于明文承载，因此不像 WebSocket/gRPC
/// 那样要求 `allow_insecure_transport`；只校验证书与私钥成对出现。
pub(super) fn validate_tls(
    certificate: Option<&std::path::Path>,
    private_key: Option<&std::path::Path>,
    inbound_index: usize,
) -> Result<()> {
    ensure!(
        certificate.is_some() == private_key.is_some(),
        "inbounds[{inbound_index}].certificate 和 private_key 必须成对配置"
    );
    Ok(())
}
