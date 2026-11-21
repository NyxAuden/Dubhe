//! VLESS Encryption（`mlkem768x25519plus`）配置解析。
//!
//! 语法（服务端 `decryption`）：`mlkem768x25519plus.<mode>.<time>[.<padding>].<key>[.<key>...]`
//!
//! - `mode`：`native` / `xorpub` / `random`
//! - `time`：`0`、`600s` 或 `30-600s`；大于 0 时启用 0-RTT 票据
//! - `padding`：`概率-最小-最大` 的若干段，偶数段是长度、奇数段是发送间隔
//! - `key`：base64url（无 padding）的 32 字节 X25519 私钥或 64 字节 ML-KEM-768 种子
//!
//! 解析规则与 Xray-core v26.10.31 `infra/conf/vless.go` 保持一致，包括
//! “长度小于 20 的字段都计入 padding 前缀”的既有行为。

use std::fmt;

use anyhow::{Result, bail, ensure};
use base64::Engine as _;

/// 线路上对握手公钥与记录头的额外混淆方式。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XorMode {
    /// 不做额外 XOR。
    Native,
    /// 只对握手公钥/密文做 XOR。
    Public,
    /// 握手与记录头都做 XOR。
    Random,
}

/// 认证密钥：X25519 私钥或 ML-KEM-768 种子。
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum AuthenticationKey {
    X25519([u8; 32]),
    MlKem768([u8; 64]),
}

impl fmt::Debug for AuthenticationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 私钥材料不进入任何输出。
        formatter
            .debug_tuple(match self {
                Self::X25519(_) => "X25519([REDACTED])",
                Self::MlKem768(_) => "MlKem768([REDACTED])",
            })
            .finish()
    }
}

/// 一个入站的 VLESS Encryption 配置。
#[derive(Clone, Debug)]
pub(crate) struct Decryption {
    pub(crate) keys: Vec<AuthenticationKey>,
    pub(crate) xor_mode: XorMode,
    pub(crate) seconds_from: u64,
    pub(crate) seconds_to: u64,
    /// 偶数位：padding 长度分组 `[概率, 最小, 最大]`。
    pub(crate) padding_lens: Vec<[u32; 3]>,
    /// 奇数位：发送间隔分组 `[概率, 最小毫秒, 最大毫秒]`。
    pub(crate) padding_gaps: Vec<[u32; 3]>,
}

const PREFIX: &str = "mlkem768x25519plus";
/// 单个 padding 分组的最大长度；达到该长度的字段被视为认证密钥。
const SHORT_FIELD: usize = 20;
/// 首组 padding 的最小长度：必须覆盖其自身 18 字节长度记录与 17 字节最小密文。
const MIN_FIRST_PADDING: u32 = 18 + 17;
/// padding 总长度的上限：18 + 65535。
const MAX_PADDING_TOTAL: u32 = 18 + 65535;
/// 票据有效期上限：长度字段只有 2 字节。
const MAX_SECONDS: u64 = u16::MAX as u64;

/// 客户端认证公钥：32 字节 X25519 公钥或 1184 字节 ML-KEM-768 封装公钥。
#[derive(Clone, Debug)]
pub(crate) struct ClientKey(pub(crate) Vec<u8>);

/// 一个出站的 VLESS Encryption 配置。
#[derive(Clone, Debug)]
pub(crate) struct ClientEncryption {
    pub(crate) keys: Vec<ClientKey>,
    pub(crate) xor_mode: XorMode,
    /// `0rtt` 为 true；`1rtt` 为 false。
    pub(crate) zero_rtt: bool,
    pub(crate) padding_lens: Vec<[u32; 3]>,
    pub(crate) padding_gaps: Vec<[u32; 3]>,
}

/// 解析出站 `encryption` 字段；与入站共享语法，但密钥是公钥。
pub(crate) fn parse_client(value: &str) -> Result<Option<ClientEncryption>> {
    let value = value.trim();
    if value.is_empty() || value == "none" {
        return Ok(None);
    }
    ensure!(value.is_ascii(), "VLESS Encryption 配置必须是 ASCII 字符串");
    let fields: Vec<&str> = value.split('.').collect();
    ensure!(
        fields.len() >= 4 && fields[0] == PREFIX,
        "VLESS Encryption 必须以 {PREFIX}.<mode>.<time> 开头"
    );
    let xor_mode = match fields[1] {
        "native" => XorMode::Native,
        "xorpub" => XorMode::Public,
        "random" => XorMode::Random,
        other => bail!("VLESS Encryption 不支持的模式 {other}（native/xorpub/random）"),
    };
    let zero_rtt = match fields[2] {
        "1rtt" => false,
        "0rtt" => true,
        other => bail!("VLESS Encryption 客户端时间字段只支持 1rtt 或 0rtt，实际 {other}"),
    };
    let mut padding_prefix = 0usize;
    for field in &fields[3..] {
        if field.len() < SHORT_FIELD {
            padding_prefix += field.len() + 1;
        }
    }
    let header_end = PREFIX.len() + 1 + fields[1].len() + 1 + fields[2].len() + 1;
    let rest = &value[header_end..];
    ensure!(
        padding_prefix <= rest.len(),
        "VLESS Encryption padding 前缀与配置长度不一致"
    );
    let padding = if padding_prefix == 0 {
        ""
    } else {
        rest.get(..padding_prefix - 1)
            .ok_or_else(|| anyhow::anyhow!("VLESS Encryption padding 前缀无效"))?
    };
    let keys_field = rest
        .get(padding_prefix..)
        .ok_or_else(|| anyhow::anyhow!("VLESS Encryption 缺少认证密钥"))?;
    let (padding_lens, padding_gaps) = parse_padding(padding)?;
    let mut keys = Vec::new();
    for field in keys_field.split('.') {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(field)
            .map_err(|_| anyhow::anyhow!("VLESS Encryption 认证密钥不是合法的 base64url"))?;
        ensure!(
            bytes.len() == 32 || bytes.len() == 1184,
            "VLESS Encryption 客户端认证密钥必须是 32 字节 X25519 公钥或 1184 字节 ML-KEM-768 公钥，实际 {} 字节",
            bytes.len()
        );
        keys.push(ClientKey(bytes));
    }
    ensure!(!keys.is_empty(), "VLESS Encryption 至少需要一个认证密钥");
    Ok(Some(ClientEncryption {
        keys,
        xor_mode,
        zero_rtt,
        padding_lens,
        padding_gaps,
    }))
}

/// 解析 `decryption` 字段；`none` 或空串表示不启用。
pub(crate) fn parse(value: &str) -> Result<Option<Decryption>> {
    let value = value.trim();
    if value.is_empty() || value == "none" {
        return Ok(None);
    }
    ensure!(value.is_ascii(), "VLESS Encryption 配置必须是 ASCII 字符串");
    let fields: Vec<&str> = value.split('.').collect();
    ensure!(
        fields.len() >= 4 && fields[0] == PREFIX,
        "VLESS Encryption 必须以 {PREFIX}.<mode>.<time> 开头"
    );
    let xor_mode = match fields[1] {
        "native" => XorMode::Native,
        "xorpub" => XorMode::Public,
        "random" => XorMode::Random,
        other => bail!("VLESS Encryption 不支持的模式 {other}（native/xorpub/random）"),
    };
    let (seconds_from, seconds_to) = parse_time(fields[2])?;

    // 与上游一致：所有短字段都计入 padding 前缀，其余视为认证密钥。
    let mut padding_prefix = 0usize;
    for field in &fields[3..] {
        if field.len() < SHORT_FIELD {
            padding_prefix += field.len() + 1;
        }
    }
    // 跳过 `PREFIX.<mode>.<time>.`，其余部分才是 padding 与认证密钥。
    let header_end = PREFIX.len() + 1 + fields[1].len() + 1 + fields[2].len() + 1;
    let rest = &value[header_end..];
    ensure!(
        padding_prefix <= rest.len(),
        "VLESS Encryption padding 前缀与配置长度不一致"
    );
    let padding = if padding_prefix == 0 {
        ""
    } else {
        rest.get(..padding_prefix - 1)
            .ok_or_else(|| anyhow::anyhow!("VLESS Encryption padding 前缀无效"))?
    };
    let keys_field = rest
        .get(padding_prefix..)
        .ok_or_else(|| anyhow::anyhow!("VLESS Encryption 缺少认证密钥"))?;

    let (padding_lens, padding_gaps) = parse_padding(padding)?;
    let mut keys = Vec::new();
    for field in keys_field.split('.') {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(field)
            .map_err(|_| anyhow::anyhow!("VLESS Encryption 认证密钥不是合法的 base64url"))?;
        match bytes.len() {
            32 => keys.push(AuthenticationKey::X25519(
                bytes.try_into().expect("长度已校验"),
            )),
            64 => keys.push(AuthenticationKey::MlKem768(
                bytes.try_into().expect("长度已校验"),
            )),
            other => bail!(
                "VLESS Encryption 服务端认证密钥必须是 32 字节 X25519 私钥或 64 字节 ML-KEM-768 种子，实际 {other} 字节"
            ),
        }
    }
    ensure!(!keys.is_empty(), "VLESS Encryption 至少需要一个认证密钥");

    Ok(Some(Decryption {
        keys,
        xor_mode,
        seconds_from,
        seconds_to,
        padding_lens,
        padding_gaps,
    }))
}

fn parse_time(field: &str) -> Result<(u64, u64)> {
    let field = field.strip_suffix('s').unwrap_or(field);
    let (from, to) = match field.split_once('-') {
        Some((from, to)) => (from, Some(to)),
        None => (field, None),
    };
    let from = parse_seconds(from, field)?;
    let to = match to {
        Some(to) => parse_seconds(to, field)?,
        None => 0,
    };
    ensure!(
        to == 0 || from <= to,
        "VLESS Encryption 时间范围 {field} 的起点大于终点"
    );
    // 票据有效期以 2 字节大端写入，超过 65535 秒会在客户端的截断中失真。
    ensure!(
        from <= MAX_SECONDS && to <= MAX_SECONDS,
        "VLESS Encryption 票据有效期不得超过 {MAX_SECONDS} 秒"
    );
    Ok((from, to))
}

fn parse_seconds(value: &str, original: &str) -> Result<u64> {
    value.parse::<u64>().map_err(|_| {
        anyhow::anyhow!("VLESS Encryption 服务端时间字段 {original} 无效（0rtt 仅供客户端使用）")
    })
}

/// padding 解析结果：长度项与间隔项各一组三元组。
type PaddingGroups = (Vec<[u32; 3]>, Vec<[u32; 3]>);

fn parse_padding(padding: &str) -> Result<PaddingGroups> {
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    if padding.is_empty() {
        return Ok((lens, gaps));
    }
    let mut total = 0u32;
    for (index, group) in padding.split('.').enumerate() {
        let parts: Vec<&str> = group.split('-').collect();
        ensure!(
            parts.len() == 3 && parts.iter().all(|part| !part.is_empty()),
            "VLESS Encryption padding 分组 {group} 必须是 概率-最小-最大"
        );
        let mut values = [0u32; 3];
        for (slot, part) in values.iter_mut().zip(&parts) {
            *slot = part.parse::<u32>().map_err(|_| {
                anyhow::anyhow!("VLESS Encryption padding 分组 {group} 含非数字字段")
            })?;
        }
        ensure!(
            values[0] <= 100,
            "VLESS Encryption padding 分组 {group} 的概率必须在 0 到 100 之间"
        );
        ensure!(
            values[1] <= values[2],
            "VLESS Encryption padding 分组 {group} 的最小值大于最大值"
        );
        if index == 0 {
            ensure!(
                values[0] >= 100
                    && values[1] >= MIN_FIRST_PADDING
                    && values[2] >= MIN_FIRST_PADDING,
                "VLESS Encryption 首个 padding 分组必须为 100-{MIN_FIRST_PADDING}-N 或更大"
            );
        }
        if index % 2 == 0 {
            total = total.saturating_add(values[2]);
            lens.push(values);
        } else {
            gaps.push(values);
        }
    }
    ensure!(
        total <= MAX_PADDING_TOTAL,
        "VLESS Encryption padding 总长度不得超过 {MAX_PADDING_TOTAL}"
    );
    Ok((lens, gaps))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY32: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const KEY64: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw";

    fn key(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn none_and_empty_disable() {
        assert!(parse("").unwrap().is_none());
        assert!(parse("none").unwrap().is_none());
        assert!(parse(" none ").unwrap().is_none());
    }

    #[test]
    fn parses_minimal_x25519_config() {
        let value = format!("mlkem768x25519plus.native.600s.{KEY32}");
        let parsed = parse(&value).unwrap().unwrap();
        assert_eq!(parsed.xor_mode, XorMode::Native);
        assert_eq!((parsed.seconds_from, parsed.seconds_to), (600, 0));
        let expected: [u8; 32] = core::array::from_fn(|index| index as u8);
        assert_eq!(parsed.keys, vec![AuthenticationKey::X25519(expected)]);
    }

    #[test]
    fn parses_range_time_and_mlkem_key() {
        let value = format!("mlkem768x25519plus.random.30-600s.{KEY64}");
        let parsed = parse(&value).unwrap().unwrap();
        assert_eq!(parsed.xor_mode, XorMode::Random);
        assert_eq!((parsed.seconds_from, parsed.seconds_to), (30, 600));
        assert!(matches!(parsed.keys[0], AuthenticationKey::MlKem768(_)));
    }

    #[test]
    fn parses_padding_then_keys() {
        let value = format!("mlkem768x25519plus.xorpub.0.100-111-1111.75-0-111.{KEY32}");
        let parsed = parse(&value).unwrap().unwrap();
        assert_eq!(parsed.xor_mode, XorMode::Public);
        assert_eq!(parsed.padding_lens, vec![[100, 111, 1111]]);
        assert_eq!(parsed.padding_gaps, vec![[75, 0, 111]]);
        assert_eq!(parsed.keys.len(), 1);
    }

    #[test]
    fn rejects_client_only_0rtt_time() {
        let value = format!("mlkem768x25519plus.native.0rtt.{KEY32}");
        assert!(parse(&value).is_err());
    }

    #[test]
    fn rejects_first_padding_group_below_minimum() {
        let value = format!("mlkem768x25519plus.native.0.100-0-0.{KEY32}");
        assert!(parse(&value).is_err());
    }

    #[test]
    fn rejects_oversized_padding_total() {
        let value = format!("mlkem768x25519plus.native.0.100-70000-70000.75-0-0.{KEY32}");
        assert!(parse(&value).is_err());
    }

    #[test]
    fn rejects_unexpected_key_length() {
        let value = format!("mlkem768x25519plus.native.0.{}", key(&[7u8; 31]));
        assert!(parse(&value).is_err());
    }

    #[test]
    fn rejects_oversized_ticket_seconds() {
        let value = format!("mlkem768x25519plus.native.65536s.{KEY32}");
        assert!(parse(&value).is_err());
        let value = format!("mlkem768x25519plus.native.30-65536s.{KEY32}");
        assert!(parse(&value).is_err());
        let value = format!("mlkem768x25519plus.native.65535s.{KEY32}");
        assert!(parse(&value).unwrap().is_some());
    }

    #[test]
    fn rejects_wrong_prefix_and_mode() {
        assert!(parse(&format!("mlkem1024x25519plus.native.0.{KEY32}")).is_err());
        assert!(parse(&format!("mlkem768x25519plus.stealth.0.{KEY32}")).is_err());
    }
}
