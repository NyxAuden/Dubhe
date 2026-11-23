//! 外部地理数据集的解析与规则展开。
//!
//! 支持三种数据源（内核只读取用户提供的文件，不内置、不下载、不校验）：
//!
//! - Xray / Mihomo 的 `geosite.dat` / `geoip.dat`（protobuf，见
//!   `xray.common.geodata`）
//! - MaxMind `mmdb`（Mihomo 的 IP 分流、sing-box 也支持）
//! - sing-box rule-set **source JSON**（不是 `.srs` 二进制）
//!
//! 路由规则里的 `geosite:<code>`、`geoip:<code>`、`mmdb:<code>`、
//! `rule_set:<tag>` 在**配置加载阶段**展开成具体域名/CIDR，之后走既有的
//! 匹配逻辑，不改变运行期行为。

use std::{collections::HashMap, net::IpAddr, path::Path};

use anyhow::{Context, Result, bail, ensure};

use crate::config::GeoConfig;

/// Xray `xray.common.geodata.Domain.Type`。
const DOMAIN_PLAIN: i32 = 0;
const DOMAIN_REGEX: i32 = 1;
const DOMAIN_DOMAIN: i32 = 2;
const DOMAIN_FULL: i32 = 3;

/// 展开后的域名匹配项。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainMatcher {
    /// 完整域名相等（Xray `Full`、`domain:` 的精确项）。
    Full(String),
    /// 域名及其子域（Xray `Domain`、`domain:` 的后缀语义）。
    Suffix(String),
    /// 子串（Xray `Substr`、`keyword:`）。
    Keyword(String),
    /// 正则（Xray `Regex`、`regexp:`）。
    Regex(String),
}

/// 展开后的 IP 匹配项。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

/// 一个地理数据集：已解析的域名与 CIDR。
#[derive(Default)]
pub struct GeoData {
    sites: HashMap<String, Vec<DomainMatcher>>,
    ips: HashMap<String, Vec<Cidr>>,
    /// MaxMind 数据库：只能「输入 IP → 查国家码」，无法反向列出某国的
    /// 全部网段。因此它走**运行期匹配**，不像 dat 那样在加载期展开。
    mmdb: Option<maxminddb::Reader<Vec<u8>>>,
}

impl std::fmt::Debug for GeoData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // maxminddb::Reader 不实现 Debug，只暴露规模信息。
        formatter
            .debug_struct("GeoData")
            .field("sites", &self.sites.len())
            .field("ips", &self.ips.len())
            .field("mmdb", &self.mmdb.is_some())
            .finish()
    }
}

impl GeoData {
    /// 按国家码（不区分大小写）匹配 IP；没有加载 mmdb 时返回 `None`。
    pub fn mmdb_matches(&self, code: &str, ip: IpAddr) -> Option<bool> {
        let reader = self.mmdb.as_ref()?;
        // MaxMind 的 GeoLite2-Country 结构：country.iso_code。
        // 查不到（地址不在库内）时 `decode` 返回 None，按不匹配处理。
        let iso = reader
            .lookup(ip)
            .ok()
            .and_then(|result| result.decode::<MmdbCountry>().ok().flatten())
            .and_then(|record| record.country)
            .and_then(|country| country.iso_code)
            .unwrap_or_default();
        Some(iso.eq_ignore_ascii_case(code))
    }
}

#[derive(serde::Deserialize)]
struct MmdbCountry {
    #[serde(default)]
    country: Option<MmdbCountryInner>,
}

#[derive(serde::Deserialize)]
struct MmdbCountryInner {
    #[serde(default)]
    iso_code: Option<String>,
}

impl GeoData {
    fn sites(&self, code: &str) -> Option<&[DomainMatcher]> {
        self.sites
            .get(&code.to_ascii_lowercase())
            .map(Vec::as_slice)
    }

    fn ips(&self, code: &str) -> Option<&[Cidr]> {
        self.ips.get(&code.to_ascii_lowercase()).map(Vec::as_slice)
    }
}

/// 加载一个配置对应的数据集。
///
/// **不做全局缓存**：热重载换了数据文件时必须生效，全局单例会让新配置
/// 沿用旧数据；并发测试也会互相污染。
pub fn load(config: &GeoConfig) -> Result<GeoData> {
    let mut data = GeoData::default();
    if let Some(path) = &config.geosite {
        data.sites.extend(parse_geosite(path)?);
    }
    if let Some(path) = &config.geoip {
        data.ips.extend(parse_geoip(path)?);
    }
    if let Some(path) = &config.mmdb {
        data.mmdb = Some(
            maxminddb::Reader::open_readfile(path)
                .with_context(|| format!("打开 mmdb 失败: {}", path.display()))?,
        );
    }
    for source in &config.rule_sets {
        let (sites, ips) = parse_rule_set(&source.path)?;
        if !sites.is_empty() {
            data.sites.insert(source.tag.to_ascii_lowercase(), sites);
        }
        if !ips.is_empty() {
            data.ips.insert(source.tag.to_ascii_lowercase(), ips);
        }
    }
    Ok(data)
}

/// 展开一条路由规则里的 `geosite:` / `geoip:` / `mmdb:` / `rule_set:` 引用。
///
/// 返回 `(额外的域名匹配项, 额外的 CIDR)`。
pub fn expand(
    data: &GeoData,
    domains: &[String],
    ips: &[String],
) -> Result<(Vec<DomainMatcher>, Vec<Cidr>, Vec<String>)> {
    let mut extra_domains = Vec::new();
    for value in domains {
        let Some(code) = geo_code(value) else {
            continue;
        };
        let (kind, code) = code;
        match kind {
            GeoKind::Site => {
                let items = data
                    .sites(code)
                    .ok_or_else(|| anyhow::anyhow!("geosite:{code} 不在已加载的 geosite 数据里"))?;
                extra_domains.extend_from_slice(items);
            }
            GeoKind::Ip | GeoKind::Mmdb => {
                bail!("{value} 是 IP 数据集，不能出现在 domains 里；请改用 ip_cidrs")
            }
        }
    }
    let mut extra_ips = Vec::new();
    let mut mmdb_codes = Vec::new();
    for value in ips {
        let Some((kind, code)) = geo_code(value) else {
            continue;
        };
        match kind {
            GeoKind::Ip => {
                let items = data
                    .ips(code)
                    .ok_or_else(|| anyhow::anyhow!("{value} 不在已加载的 GeoIP 数据里"))?;
                extra_ips.extend_from_slice(items);
            }
            // mmdb 不能反查：交给运行期按国家码匹配，这里只做可用性检查。
            GeoKind::Mmdb => {
                ensure!(data.mmdb.is_some(), "{value} 需要配置 geo.mmdb 才能使用");
                mmdb_codes.push(code.to_owned());
            }
            GeoKind::Site => bail!("{value} 是域名数据集，不能出现在 ip_cidrs 里；请改用 domains"),
        }
    }
    Ok((extra_domains, extra_ips, mmdb_codes))
}

#[derive(Clone, Copy)]
enum GeoKind {
    Site,
    Ip,
    Mmdb,
}

/// 该值是否是地理数据引用（`geosite:` / `geoip:` / `mmdb:` / `rule_set:`）。
pub fn code_of(value: &str) -> Option<&str> {
    geo_code(value).map(|(_, code)| code)
}

/// 该值是否是 mmdb 引用；是则返回国家码。
pub fn mmdb_code(value: &str) -> Option<&str> {
    match geo_code(value) {
        Some((GeoKind::Mmdb, code)) => Some(code),
        _ => None,
    }
}

/// 识别 `geosite:` / `geoip:` / `mmdb:` / `rule_set:` 前缀。
fn geo_code(value: &str) -> Option<(GeoKind, &str)> {
    let (kind, code) = if let Some(code) = value.strip_prefix("geosite:") {
        (GeoKind::Site, code)
    } else if let Some(code) = value.strip_prefix("rule_set:") {
        (GeoKind::Site, code)
    } else if let Some(code) = value.strip_prefix("geoip:") {
        (GeoKind::Ip, code)
    } else if let Some(code) = value.strip_prefix("mmdb:") {
        (GeoKind::Mmdb, code)
    } else {
        return None;
    };
    (!code.is_empty()).then_some((kind, code))
}

// ---------------------------------------------------------------------------
// Xray geosite.dat / geoip.dat（protobuf）
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
struct GeoDomain {
    #[prost(enumeration = "DomainType", tag = "1")]
    r#type: i32,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum DomainType {
    Substr = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<GeoDomain>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GeoCidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GeoIpEntry {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<GeoCidr>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIpEntry>,
}

fn parse_geosite(path: &Path) -> Result<HashMap<String, Vec<DomainMatcher>>> {
    use prost::Message as _;
    let bytes = std::fs::read(path)
        .with_context(|| format!("读取 geosite 数据失败: {}", path.display()))?;
    let list = GeoSiteList::decode(bytes.as_slice())
        .with_context(|| format!("geosite 数据不是合法的 protobuf: {}", path.display()))?;
    let mut out = HashMap::new();
    for entry in list.entry {
        let mut items = Vec::with_capacity(entry.domain.len());
        for domain in entry.domain {
            let value = domain.value.trim().to_ascii_lowercase();
            if value.is_empty() {
                continue;
            }
            let item = match domain.r#type {
                DOMAIN_FULL => DomainMatcher::Full(value),
                DOMAIN_DOMAIN | DOMAIN_PLAIN => DomainMatcher::Suffix(value),
                DOMAIN_REGEX => DomainMatcher::Regex(domain.value),
                other => bail!("geosite 数据里出现未知的域名类型 {other}"),
            };
            items.push(item);
        }
        out.insert(entry.code.to_ascii_lowercase(), items);
    }
    ensure!(!out.is_empty(), "geosite 数据为空: {}", path.display());
    Ok(out)
}

fn parse_geoip(path: &Path) -> Result<HashMap<String, Vec<Cidr>>> {
    use prost::Message as _;
    let bytes =
        std::fs::read(path).with_context(|| format!("读取 geoip 数据失败: {}", path.display()))?;
    let list = GeoIpList::decode(bytes.as_slice())
        .with_context(|| format!("geoip 数据不是合法的 protobuf: {}", path.display()))?;
    let mut out = HashMap::new();
    for entry in list.entry {
        let mut items = Vec::with_capacity(entry.cidr.len());
        for cidr in entry.cidr {
            items.push(cidr_from_bytes(&cidr.ip, cidr.prefix)?);
        }
        out.insert(entry.code.to_ascii_lowercase(), items);
    }
    ensure!(!out.is_empty(), "geoip 数据为空: {}", path.display());
    Ok(out)
}

fn cidr_from_bytes(ip: &[u8], prefix: u32) -> Result<Cidr> {
    let (addr, bits) = match ip.len() {
        4 => (
            IpAddr::from(<[u8; 4]>::try_from(ip).expect("长度已校验")),
            32,
        ),
        16 => (
            IpAddr::from(<[u8; 16]>::try_from(ip).expect("长度已校验")),
            128,
        ),
        other => bail!("geoip 的 CIDR 长度必须是 4 或 16 字节，实际 {other}"),
    };
    ensure!(prefix <= bits, "geoip 的 CIDR 前缀 {prefix} 超过 {bits} 位");
    Ok(Cidr {
        addr,
        prefix: prefix as u8,
    })
}

// ---------------------------------------------------------------------------
// MaxMind mmdb
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// sing-box rule-set source JSON
// ---------------------------------------------------------------------------

fn parse_rule_set(path: &Path) -> Result<(Vec<DomainMatcher>, Vec<Cidr>)> {
    let bytes =
        std::fs::read(path).with_context(|| format!("读取 rule-set 失败: {}", path.display()))?;
    // `.srs` 是 sing-box 的编译产物（魔数 `SRS`）；本实现只吃 source JSON。
    // 提前识别能给出可操作的提示，而不是笼统的「不是合法 JSON」。
    if bytes.starts_with(b"SRS") || path.extension().is_some_and(|ext| ext == "srs") {
        bail!(
            "{} 是 sing-box 的二进制 rule-set（.srs），本实现只支持 source JSON；             请用 `sing-box rule-set compile --output <名字>.json` 反向导出，             或直接引用 .srs 对应的 source 文件",
            path.display()
        );
    }
    let raw = String::from_utf8(bytes)
        .with_context(|| format!("rule-set 不是 UTF-8 文本: {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("rule-set 不是合法 JSON: {}", path.display()))?;
    ensure!(
        value.get("version").is_some(),
        "rule-set 缺少 version 字段（本实现只支持 source JSON，不支持 .srs 二进制）"
    );
    let rules = value
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .context("rule-set 缺少 rules 数组")?;
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    for rule in rules {
        collect_strings(rule, "domain", &mut domains, DomainMatcher::Full);
        collect_strings(rule, "domain_suffix", &mut domains, DomainMatcher::Suffix);
        collect_strings(rule, "domain_keyword", &mut domains, DomainMatcher::Keyword);
        collect_strings(rule, "domain_regex", &mut domains, DomainMatcher::Regex);
        if let Some(list) = rule.get("ip_cidr").and_then(serde_json::Value::as_array) {
            for item in list.iter().filter_map(serde_json::Value::as_str) {
                ips.push(parse_cidr_text(item)?);
            }
        }
    }
    Ok((domains, ips))
}

fn collect_strings(
    rule: &serde_json::Value,
    key: &str,
    out: &mut Vec<DomainMatcher>,
    wrap: fn(String) -> DomainMatcher,
) {
    let Some(list) = rule.get(key).and_then(serde_json::Value::as_array) else {
        return;
    };
    for item in list.iter().filter_map(serde_json::Value::as_str) {
        let value = item.trim().to_ascii_lowercase();
        if !value.is_empty() {
            out.push(wrap(value));
        }
    }
}

fn parse_cidr_text(value: &str) -> Result<Cidr> {
    let (addr, prefix) = value
        .split_once('/')
        .with_context(|| format!("CIDR 缺少前缀长度: {value}"))?;
    let addr: IpAddr = addr
        .parse()
        .with_context(|| format!("CIDR 地址无效: {value}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("CIDR 前缀无效: {value}"))?;
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    ensure!(prefix <= bits, "CIDR 前缀超过 {bits} 位: {value}");
    Ok(Cidr { addr, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    type SiteEntries<'a> = &'a [(&'a str, &'a [(DomainType, &'a str)])];

    fn encode_geosite(entries: SiteEntries<'_>) -> Vec<u8> {
        let list = GeoSiteList {
            entry: entries
                .iter()
                .map(|(code, domains)| GeoSite {
                    code: (*code).to_owned(),
                    domain: domains
                        .iter()
                        .map(|(kind, value)| GeoDomain {
                            r#type: *kind as i32,
                            value: (*value).to_owned(),
                        })
                        .collect(),
                })
                .collect(),
        };
        list.encode_to_vec()
    }

    type IpEntries<'a> = &'a [(&'a str, &'a [(&'a [u8], u32)])];

    fn encode_geoip(entries: IpEntries<'_>) -> Vec<u8> {
        let list = GeoIpList {
            entry: entries
                .iter()
                .map(|(code, cidrs)| GeoIpEntry {
                    code: (*code).to_owned(),
                    cidr: cidrs
                        .iter()
                        .map(|(ip, prefix)| GeoCidr {
                            ip: ip.to_vec(),
                            prefix: *prefix,
                        })
                        .collect(),
                })
                .collect(),
        };
        list.encode_to_vec()
    }

    #[test]
    fn parses_xray_geosite_types() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.dat");
        std::fs::write(
            &path,
            encode_geosite(&[(
                "TEST",
                &[
                    (DomainType::Full, "Exact.Example"),
                    (DomainType::Domain, "suffix.example"),
                    (DomainType::Substr, "keyword"),
                    (DomainType::Regex, "^regex\\.example$"),
                ],
            )]),
        )
        .unwrap();
        let sites = parse_geosite(&path).unwrap();
        let items = sites.get("test").expect("code 应统一小写");
        assert_eq!(
            items,
            &[
                DomainMatcher::Full("exact.example".into()),
                DomainMatcher::Suffix("suffix.example".into()),
                DomainMatcher::Suffix("keyword".into()),
                DomainMatcher::Regex("^regex\\.example$".into()),
            ]
        );
    }

    #[test]
    fn parses_xray_geoip_cidrs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip.dat");
        std::fs::write(
            &path,
            encode_geoip(&[("CN", &[(&[10, 0, 0, 0], 8)]), ("V6", &[(&[0u8; 16], 16)])]),
        )
        .unwrap();
        let ips = parse_geoip(&path).unwrap();
        assert_eq!(
            ips.get("cn").unwrap(),
            &[Cidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8
            }]
        );
        assert_eq!(ips.get("v6").unwrap()[0].prefix, 16);
    }

    #[test]
    fn rejects_bad_protobuf_and_empty_data() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.dat");
        std::fs::write(&bad, b"not protobuf at all").unwrap();
        assert!(parse_geosite(&bad).is_err());
        let empty = dir.path().join("empty.dat");
        std::fs::write(&empty, GeoSiteList { entry: vec![] }.encode_to_vec()).unwrap();
        assert!(parse_geosite(&empty).is_err());
    }

    #[test]
    fn parses_rule_set_source_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "version": 3,
                "rules": [{
                    "domain_suffix": ["Example.COM"],
                    "domain_keyword": ["ads"],
                    "ip_cidr": ["192.0.2.0/24", "2001:db8::/32"]
                }]
            })
            .to_string(),
        )
        .unwrap();
        let (domains, ips) = parse_rule_set(&path).unwrap();
        assert_eq!(
            domains,
            vec![
                DomainMatcher::Suffix("example.com".into()),
                DomainMatcher::Keyword("ads".into())
            ]
        );
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].prefix, 24);
    }

    #[test]
    fn rejects_srs_binary_with_actionable_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.srs");
        std::fs::write(&path, b"SRS\x01\x00\x00\x00").unwrap();
        let error = parse_rule_set(&path).unwrap_err().to_string();
        assert!(error.contains("source JSON"), "{error}");
    }

    #[test]
    fn geo_code_rejects_wrong_field_placement() {
        let data = GeoData::default();
        let error = expand(&data, &["geoip:cn".into()], &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("ip_cidrs"), "{error}");
        let error = expand(&data, &[], &["geosite:cn".into()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("domains"), "{error}");
    }

    #[test]
    fn missing_code_is_reported_not_ignored() {
        let data = GeoData::default();
        let error = expand(&data, &["geosite:absent".into()], &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("geosite:absent"), "{error}");
    }

    #[test]
    fn plain_values_are_left_alone() {
        let data = GeoData::default();
        let (domains, ips, mmdb) = expand(
            &data,
            &["example.org".into(), "domain:example.net".into()],
            &[],
        )
        .unwrap();
        assert!(domains.is_empty() && ips.is_empty() && mmdb.is_empty());
    }
}
