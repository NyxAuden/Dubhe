//! 外部地理数据集的解析与规则展开。
//!
//! 四类数据源（内核只读取用户提供的文件，不内置、不下载、不校验）：
//!
//! - Xray / Mihomo 的 `geosite.dat` / `geoip.dat`（protobuf，见
//!   `xray.common.geodata`）
//! - MaxMind `mmdb`（Mihomo 的 IP 分流、sing-box 也支持）
//! - sing-box rule-set **source JSON**（不是 `.srs` 二进制）
//!
//! 展开时机按数据形态区分：
//!
//! - `geosite:` / `geoip:` / `rule_set:` 在**配置加载阶段**展开成具体
//!   域名与 CIDR，之后走既有匹配逻辑；
//! - `mmdb:` **不展开**：`maxminddb` 虽然提供 `networks()` 遍历接口，
//!   但全库展开在启动时更慢、占用更大；本项目选择运行期按 IP 查询。

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
    /// **仅子域**，不含根域。sing-box 的 `domain_suffix` 用前导点表达此意
    /// （`.a.test` 匹配 `sub.a.test` 但不匹配 `a.test`），与 Xray/本项目
    /// 原生后缀语义不同，因此单独一类。
    Subdomain(String),
    /// 子串（Xray `Substr`、`keyword:`）。
    Keyword(String),
    /// 正则（Xray `Regex`、`regexp:`）。
    Regex(String),
}

impl DomainMatcher {
    /// 该域名是否命中本项。
    ///
    /// 语义对齐 Xray：`Full` 整域相等、`Suffix` 匹配自身及子域、
    /// `Keyword` 子串、`Regex` 正则。调用方拿到的 `domain` 已归一化
    /// （小写、去掉尾点），这里不再重复处理。
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Full(value) => domain == value,
            Self::Suffix(value) => {
                let core = value.trim_start_matches('.');
                !core.is_empty()
                    && (domain == core
                        || domain
                            .strip_suffix(core)
                            .is_some_and(|prefix| prefix.ends_with('.')))
            }
            Self::Subdomain(value) => domain
                .strip_suffix(value.as_str())
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1),
            Self::Keyword(value) => domain.contains(value.as_str()),
            Self::Regex(value) => regex::Regex::new(value).is_ok_and(|re| re.is_match(domain)),
        }
    }
}

/// 展开后的 IP 匹配项。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// 该地址是否落在本网段内（仅在地址族相同时比较）。
    pub fn contains(&self, ip: IpAddr) -> bool {
        fn bits(ip: IpAddr) -> Option<u128> {
            match ip {
                IpAddr::V4(v4) => Some(u128::from(u32::from(v4))),
                IpAddr::V6(v6) => Some(u128::from(v6)),
            }
        }
        let (Some(network), Some(candidate)) = (bits(self.addr), bits(ip)) else {
            return false;
        };
        let width: u32 = if self.addr.is_ipv4() { 32 } else { 128 };
        if u32::from(self.prefix) > width {
            return false;
        }
        if self.addr.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        // 地址族已确认一致，`/0` 覆盖该族全部地址；直接返回可避免
        // `u128 >> 128` 的右移溢出（debug 构建会 panic）。
        if self.prefix == 0 {
            return true;
        }
        let shift = width - u32::from(self.prefix);
        if shift == 0 {
            return network == candidate;
        }
        (network >> shift) == (candidate >> shift)
    }
}

/// 一个 sing-box rule-set source JSON 里我们支持的子集。
#[derive(Debug, Default)]
struct RuleSetData {
    domains: Vec<DomainMatcher>,
    ips: Vec<Cidr>,
}

/// 一个地理数据集：已解析的域名与 CIDR。
#[derive(Default)]
pub struct GeoData {
    sites: HashMap<String, Vec<DomainMatcher>>,
    ips: HashMap<String, Vec<Cidr>>,
    /// rule-set 独立命名空间：不与 geosite/geoip 的 code 混用，避免
    /// 「tag=cn 覆盖 geosite 的 cn」这类静默覆盖。
    rule_sets: HashMap<String, RuleSetData>,
    /// MaxMind 数据库。
    ///
    /// `maxminddb` 提供 `networks()` 可以遍历网段，但本项目**选择**运行期
    /// 按 IP 查询：全库展开在启动时更慢、占用更大，而单次查询本身很便宜。
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

/// 数据文件的读取与展开预算。
///
/// 目的是给启动/热重载的内存一个明确上界，**超限直接失败，不截断**：
/// 截断会改变规则集合，反向规则的含义随之改变。
struct Budget {
    remaining_bytes: usize,
    remaining_entries: usize,
}

/// 单个数据文件的读取上限。
const MAX_FILE_BYTES: usize = 128 * 1024 * 1024;
/// 一次加载里所有数据文件的累计读取上限。
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
/// 解码后的条目总数上限（分类 + 域名/CIDR 项）。
const MAX_ENTRIES: usize = 3_000_000;

impl Default for Budget {
    fn default() -> Self {
        Self {
            remaining_bytes: MAX_TOTAL_BYTES,
            remaining_entries: MAX_ENTRIES,
        }
    }
}

impl Budget {
    /// 按剩余额度读取文件；超出即报错，不返回被截断的内容。
    fn read(&mut self, path: &Path) -> Result<Vec<u8>> {
        use std::io::Read as _;
        let limit = MAX_FILE_BYTES.min(self.remaining_bytes);
        let file = std::fs::File::open(path)
            .with_context(|| format!("打开数据文件失败: {}", path.display()))?;
        let mut buffer = Vec::new();
        // `take` 保证不会因为文件变大而读超：最多读 limit + 1 字节，
        // 多出 1 字节就说明超限。
        file.take(limit as u64 + 1)
            .read_to_end(&mut buffer)
            .with_context(|| format!("读取数据文件失败: {}", path.display()))?;
        if buffer.len() > limit {
            bail!(
                "数据文件超出预算: {}（上限 {} 字节，累计剩余 {} 字节）",
                path.display(),
                limit,
                self.remaining_bytes
            );
        }
        self.remaining_bytes -= buffer.len();
        Ok(buffer)
    }

    fn take_entries(&mut self, count: usize, source: &Path) -> Result<()> {
        if count > self.remaining_entries {
            bail!(
                "数据条目超出预算: {}（本次 {count} 项，剩余 {} 项）",
                source.display(),
                self.remaining_entries
            );
        }
        self.remaining_entries -= count;
        Ok(())
    }
}

/// 规则展开的预算：跨所有规则累计，不按规则重置。
pub struct ExpansionBudget {
    remaining_items: usize,
    remaining_bytes: usize,
}

/// 展开项总数上限。
const MAX_EXPANDED_ITEMS: usize = 2_000_000;
/// 展开出的文本累计上限。
const MAX_EXPANDED_BYTES: usize = 128 * 1024 * 1024;

impl Default for ExpansionBudget {
    fn default() -> Self {
        Self {
            remaining_items: MAX_EXPANDED_ITEMS,
            remaining_bytes: MAX_EXPANDED_BYTES,
        }
    }
}

impl ExpansionBudget {
    /// 在真正复制之前扣减额度。
    fn reserve(&mut self, items: usize, bytes: usize, rule: usize) -> Result<()> {
        if items > self.remaining_items {
            bail!(
                "route.rules[{rule}] 的地理展开超出预算（本次 {items} 项，剩余 {} 项）；\
                 请减少引用或调高上限",
                self.remaining_items
            );
        }
        if bytes > self.remaining_bytes {
            bail!(
                "route.rules[{rule}] 的地理展开文本超出预算（本次 {bytes} 字节，剩余 {} 字节）",
                self.remaining_bytes
            );
        }
        self.remaining_items -= items;
        self.remaining_bytes -= bytes;
        Ok(())
    }
}

/// 加载一个配置对应的数据集。
///
/// **不做全局缓存**：热重载换了数据文件时必须生效，全局单例会让新配置
/// 沿用旧数据；并发测试也会互相污染。
pub fn load(config: &GeoConfig) -> Result<GeoData> {
    let mut data = GeoData::default();
    let mut budget = Budget::default();
    if let Some(path) = &config.geosite {
        data.sites.extend(parse_geosite(path, &mut budget)?);
    }
    if let Some(path) = &config.geoip {
        data.ips.extend(parse_geoip(path, &mut budget)?);
    }
    if let Some(path) = &config.mmdb {
        // 用同一份字节构造，避免 `open_readfile` 再读一遍。
        let bytes = budget.read(path)?;
        data.mmdb = Some(
            maxminddb::Reader::from_source(bytes)
                .with_context(|| format!("解析 mmdb 失败: {}", path.display()))?,
        );
    }
    for source in &config.rule_sets {
        let tag = source.tag.trim();
        ensure!(!tag.is_empty(), "geo.rule_sets[].tag 不能为空");
        let key = tag.to_ascii_lowercase();
        ensure!(
            !data.rule_sets.contains_key(&key),
            "geo.rule_sets 的 tag 重复（忽略大小写）: {tag}"
        );
        let parsed = parse_rule_set(&source.path, &mut budget)?;
        data.rule_sets.insert(key, parsed);
    }
    Ok(data)
}

/// 一条规则展开后的地理条件。
///
/// `domain_used` / `ip_used` 记录「配置里出现过该维度的地理引用」，
/// 即使展开结果为 0 条也必须算作**有限制**——否则空分类会被当成
/// 「没有条件」，从「什么域名都不匹配」变成「匹配一切」。
#[derive(Default, Debug)]
pub struct Expanded {
    pub domains: Vec<DomainMatcher>,
    pub ips: Vec<Cidr>,
    pub mmdb_codes: Vec<String>,
    pub domain_used: bool,
    pub ip_used: bool,
}

/// 展开一条路由规则里的 `geosite:` / `geoip:` / `mmdb:` / `rule_set:` 引用。
pub fn expand(
    data: &GeoData,
    domains: &[String],
    ips: &[String],
    rule: usize,
    budget: &mut ExpansionBudget,
) -> Result<Expanded> {
    let mut out = Expanded::default();
    for value in domains {
        let Some((kind, code)) = geo_code(value) else {
            continue;
        };
        out.domain_used = true;
        match kind {
            GeoKind::Site => {
                let items = data
                    .sites(code)
                    .ok_or_else(|| anyhow::anyhow!("{value} 不在已加载的 geosite 数据里"))?;
                budget.reserve(items.len(), domain_bytes(items), rule)?;
                out.domains.extend_from_slice(items);
            }
            GeoKind::RuleSet => {
                let set = data
                    .rule_sets
                    .get(&code.to_ascii_lowercase())
                    .ok_or_else(|| anyhow::anyhow!("{value} 不在已加载的 rule_sets 里"))?;
                // 与 IP 侧对称：只含 IP 的集合用在域名侧会让阻断规则
                // 永不命中，必须报错而不是静默失效。
                ensure!(
                    !set.domains.is_empty(),
                    "{value} 不含域名项，不能用在 domains 里"
                );
                budget.reserve(set.domains.len(), domain_bytes(&set.domains), rule)?;
                out.domains.extend_from_slice(&set.domains);
            }
            GeoKind::Ip | GeoKind::Mmdb => {
                bail!("{value} 是 IP 数据集，不能出现在 domains 里；请改用 ip_cidrs")
            }
        }
    }
    for value in ips {
        let Some((kind, code)) = geo_code(value) else {
            continue;
        };
        out.ip_used = true;
        match kind {
            GeoKind::Ip => {
                let items = data
                    .ips(code)
                    .ok_or_else(|| anyhow::anyhow!("{value} 不在已加载的 GeoIP 数据里"))?;
                budget.reserve(items.len(), 0, rule)?;
                out.ips.extend_from_slice(items);
            }
            GeoKind::RuleSet => {
                let set = data
                    .rule_sets
                    .get(&code.to_ascii_lowercase())
                    .ok_or_else(|| anyhow::anyhow!("{value} 不在已加载的 rule_sets 里"))?;
                ensure!(
                    !set.ips.is_empty(),
                    "{value} 不含 ip_cidr 项，不能用在 ip_cidrs 里"
                );
                budget.reserve(set.ips.len(), 0, rule)?;
                out.ips.extend_from_slice(&set.ips);
            }
            // mmdb 不展开：交给运行期按国家码匹配（实现取舍，不是格式限制）。
            GeoKind::Mmdb => {
                ensure!(data.mmdb.is_some(), "{value} 需要配置 geo.mmdb 才能使用");
                out.mmdb_codes.push(code.to_owned());
            }
            GeoKind::Site => bail!("{value} 是域名数据集，不能出现在 ip_cidrs 里；请改用 domains"),
        }
    }
    Ok(out)
}

#[derive(Clone, Copy)]
enum GeoKind {
    Site,
    Ip,
    Mmdb,
    RuleSet,
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
        (GeoKind::RuleSet, code)
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
    /// Xray `reverse_match`：语义是该集合取反。本项目不支持，必须显式拒绝，
    /// 否则会把「反向集合」当成正向集合用，匹配结果完全相反。
    #[prost(bool, tag = "3")]
    reverse_match: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIpEntry>,
}

fn parse_geosite(path: &Path, budget: &mut Budget) -> Result<HashMap<String, Vec<DomainMatcher>>> {
    use prost::Message as _;
    let bytes = budget.read(path)?;
    let list = GeoSiteList::decode(bytes.as_slice())
        .with_context(|| format!("geosite 数据不是合法的 protobuf: {}", path.display()))?;
    let mut out = HashMap::new();
    let total: usize = list.entry.iter().map(|entry| 1 + entry.domain.len()).sum();
    budget.take_entries(total, path)?;
    for entry in list.entry {
        let mut items = Vec::with_capacity(entry.domain.len());
        for domain in entry.domain {
            let value = domain.value.trim().to_ascii_lowercase();
            if value.is_empty() {
                continue;
            }
            let item = match domain.r#type {
                DOMAIN_FULL => DomainMatcher::Full(value),
                DOMAIN_DOMAIN => DomainMatcher::Suffix(value),
                // type 0 是 Substr（子串），不是后缀；早期错映射为 Suffix。
                DOMAIN_PLAIN => DomainMatcher::Keyword(value),
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

fn parse_geoip(path: &Path, budget: &mut Budget) -> Result<HashMap<String, Vec<Cidr>>> {
    use prost::Message as _;
    let bytes = budget.read(path)?;
    let list = GeoIpList::decode(bytes.as_slice())
        .with_context(|| format!("geoip 数据不是合法的 protobuf: {}", path.display()))?;
    let mut out = HashMap::new();
    let total: usize = list.entry.iter().map(|entry| 1 + entry.cidr.len()).sum();
    budget.take_entries(total, path)?;
    for entry in list.entry {
        ensure!(
            !entry.reverse_match,
            "geoip 分类 {} 使用 reverse_match（反向集合），本项目不支持；\
             请在数据源侧换成显式网段",
            entry.code
        );
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

/// 解析 sing-box rule-set 的 **source JSON 子集**。
///
/// 只接受纯域名/IP 列表；任何会改变语义的字段（`invert`、`type: logical`、
/// `port`、`network`、`rule_set` 等）都**显式拒绝**，而不是解析后静默丢弃——
/// 丢弃条件会让规则的匹配范围变大。
fn parse_rule_set(path: &Path, budget: &mut Budget) -> Result<RuleSetData> {
    const ALLOWED: &[&str] = &[
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
    ];
    let bytes = budget.read(path)?;
    // `.srs` 是 sing-box 的编译产物（魔数 `SRS`）；本实现只吃 source JSON。
    if bytes.starts_with(b"SRS") || path.extension().is_some_and(|ext| ext == "srs") {
        bail!(
            "{} 是 sing-box 的二进制 rule-set（.srs），本实现只支持 source JSON；\
             请用 `sing-box rule-set decompile <文件>.srs` 导出 source JSON，\
             或直接引用 .srs 对应的 source 文件",
            path.display()
        );
    }
    let raw = String::from_utf8(bytes)
        .with_context(|| format!("rule-set 不是 UTF-8 文本: {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("rule-set 不是合法 JSON: {}", path.display()))?;

    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .context("rule-set 的 version 必须是整数（本实现只支持 source JSON）")?;
    ensure!(
        (1..=5).contains(&version),
        "rule-set 的 version {version} 不在已知范围 1..=5"
    );
    let rules = value
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .context("rule-set 缺少 rules 数组")?;

    let mut data = RuleSetData::default();
    for (index, rule) in rules.iter().enumerate() {
        let object = rule
            .as_object()
            .with_context(|| format!("rule-set 的 rules[{index}] 必须是对象"))?;
        // 拒绝任何我们不支持的字段：静默忽略会扩大匹配范围。
        for (key, value) in object {
            if key == "type" {
                // 只放行默认规则的显式写法。
                ensure!(
                    value.as_str() == Some("default"),
                    "rule-set 的 rules[{index}].type 只支持 \"default\"，实际 {value}"
                );
                continue;
            }
            if key == "invert" {
                // 只放行「不取反」的显式写法。
                ensure!(
                    value == &serde_json::Value::Bool(false),
                    "rule-set 的 rules[{index}].invert 只支持 false；取反规则请先在 sing-box 侧展开"
                );
                continue;
            }
            ensure!(
                ALLOWED.contains(&key.as_str()),
                "rule-set 的 rules[{index}] 含不支持的条件 {key:?}；本实现只接受纯域名/IP 列表（{ALLOWED:?}），\
                 逻辑规则、invert: true、port、network 等请先在 sing-box 侧展开"
            );
        }
        collect_domains(object, "domain", &mut data.domains)?;
        collect_domains(object, "domain_suffix", &mut data.domains)?;
        collect_domains(object, "domain_keyword", &mut data.domains)?;
        // 正则保留原文（大小写与首尾空白都可能是语义的一部分）。
        collect_domains(object, "domain_regex", &mut data.domains)?;
        if let Some(list) = object.get("ip_cidr").and_then(serde_json::Value::as_array) {
            for item in list {
                let text = item
                    .as_str()
                    .with_context(|| format!("rule-set 的 rules[{index}].ip_cidr 必须是字符串"))?;
                data.ips.push(parse_cidr_text(text)?);
            }
        }
    }
    ensure!(
        !data.domains.is_empty() || !data.ips.is_empty(),
        "rule-set 为空或没有可支持的条目: {}",
        path.display()
    );
    budget.take_entries(data.domains.len() + data.ips.len(), path)?;
    Ok(data)
}

/// 读取一个域名字段。sing-box 允许**字符串或字符串数组**两种写法，
/// 两者都必须支持；其它类型必须报错，不能当作字段不存在而静默丢弃。
fn collect_domains(
    rule: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    out: &mut Vec<DomainMatcher>,
) -> Result<()> {
    let Some(value) = rule.get(key) else {
        return Ok(());
    };
    let items: Vec<&serde_json::Value> = match value {
        serde_json::Value::String(_) => vec![value],
        serde_json::Value::Array(items) => items.iter().collect(),
        other => bail!("rule-set 的 {key} 必须是字符串或字符串数组，实际 {other}"),
    };
    for item in items {
        let text = item
            .as_str()
            .with_context(|| format!("rule-set 的 {key} 必须是字符串，实际 {item}"))?;
        // 正则保留原文（含首尾空白与大小写）：`\D` 与 `\d` 不同，
        // 首尾空格可能是有意的锚点。
        if key == "domain_regex" {
            ensure!(!text.is_empty(), "rule-set 的 {key} 含空字符串");
            out.push(DomainMatcher::Regex(text.to_owned()));
            continue;
        }
        let value = text.trim().to_ascii_lowercase();
        ensure!(!value.is_empty(), "rule-set 的 {key} 含空字符串");
        let item = match key {
            "domain" => DomainMatcher::Full(value),
            "domain_suffix" => {
                // 前导点是 sing-box 的「仅子域」写法，不能当普通后缀处理，
                // 否则根域也会命中（与上游实测不符）。
                if let Some(core) = value.strip_prefix('.') {
                    ensure!(!core.is_empty(), "rule-set 的 {key} 只有点");
                    DomainMatcher::Subdomain(core.to_owned())
                } else {
                    DomainMatcher::Suffix(value)
                }
            }
            "domain_keyword" => DomainMatcher::Keyword(value),
            other => bail!("内部错误：未知域名字段 {other}"),
        };
        out.push(item);
    }
    Ok(())
}

/// 域名匹配项的文本字节数估算（用于展开预算）。
fn domain_bytes(items: &[DomainMatcher]) -> usize {
    items
        .iter()
        .map(|item| match item {
            DomainMatcher::Full(value)
            | DomainMatcher::Suffix(value)
            | DomainMatcher::Subdomain(value)
            | DomainMatcher::Keyword(value)
            | DomainMatcher::Regex(value) => value.len(),
        })
        .sum()
}

fn parse_cidr_text(value: &str) -> Result<Cidr> {
    // sing-box 允许裸地址，等价于 /32 或 /128（实测 `rule-set match`
    // 对 `ip_cidr: ["192.0.2.1"]` 能命中该地址）。
    let Some((addr, prefix)) = value.split_once('/') else {
        let addr: IpAddr = value
            .parse()
            .with_context(|| format!("IP 地址无效: {value}"))?;
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        return Ok(Cidr { addr, prefix });
    };
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
                    reverse_match: false,
                })
                .collect(),
        };
        list.encode_to_vec()
    }

    /// 读取上限是**包含**的：恰好等于上限通过，多一字节失败。
    #[test]
    fn geo_read_limit_is_inclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, b"12345").unwrap();
        let mut exact = Budget {
            remaining_bytes: 5,
            remaining_entries: 10,
        };
        assert_eq!(exact.read(&path).unwrap(), b"12345");
        let mut over = Budget {
            remaining_bytes: 4,
            remaining_entries: 10,
        };
        let error = over.read(&path).unwrap_err().to_string();
        assert!(error.contains("数据文件超出预算"), "{error}");
    }

    /// 累计读取预算跨文件生效：两份各自合法的文件合计仍可能超限。
    #[test]
    fn geo_total_budget_spans_files() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        std::fs::write(&a, b"0123456789").unwrap();
        std::fs::write(&b, b"0123456789").unwrap();
        let mut budget = Budget {
            remaining_bytes: 15,
            remaining_entries: 10,
        };
        assert!(budget.read(&a).is_ok());
        let error = budget.read(&b).unwrap_err().to_string();
        assert!(error.contains("数据文件超出预算"), "{error}");
    }

    /// 展开预算跨引用累计；超限要报出规则序号。
    #[test]
    fn expansion_budget_spans_references() {
        let mut budget = ExpansionBudget {
            remaining_items: 5,
            remaining_bytes: 100,
        };
        budget.reserve(3, 10, 0).unwrap();
        let error = budget.reserve(3, 10, 1).unwrap_err().to_string();
        assert!(error.contains("route.rules[1]"), "{error}");
        // 扣减后不会因为失败而被部分消耗：3 + 2 仍可放行。
        budget.reserve(2, 10, 1).unwrap();
        assert_eq!(budget.remaining_items, 0);
    }

    /// `expand` 使用调用方传入的同一份预算，不是每次调用重置。
    #[test]
    fn expansion_budget_is_shared_across_expand_calls() {
        let mut sites = std::collections::HashMap::new();
        sites.insert(
            "test".to_owned(),
            vec![DomainMatcher::Full("a.test".into())],
        );
        let data = GeoData {
            sites,
            ..GeoData::default()
        };
        let mut budget = ExpansionBudget {
            remaining_items: 1,
            remaining_bytes: 1000,
        };
        expand(&data, &["geosite:test".into()], &[], 0, &mut budget).unwrap();
        let error = expand(&data, &["geosite:test".into()], &[], 1, &mut budget)
            .unwrap_err()
            .to_string();
        assert!(error.contains("route.rules[1]"), "{error}");
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
        let sites = parse_geosite(&path, &mut Budget::default()).unwrap();
        let items = sites.get("test").expect("code 应统一小写");
        assert_eq!(
            items,
            &[
                // type 3 = Full
                DomainMatcher::Full("exact.example".into()),
                // type 2 = Domain（后缀）
                DomainMatcher::Suffix("suffix.example".into()),
                // type 0 = Substr（子串），早期错映射为 Suffix
                DomainMatcher::Keyword("keyword".into()),
                // type 1 = Regex；保留原文大小写
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
        let ips = parse_geoip(&path, &mut Budget::default()).unwrap();
        assert_eq!(
            ips.get("cn").unwrap(),
            &[Cidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8
            }]
        );
        assert_eq!(ips.get("v6").unwrap()[0].prefix, 16);
    }

    /// `reverse_match`（Xray 的反向集合）必须显式拒绝，不能当正向集合用。
    #[test]
    fn rejects_reverse_match_geoip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip.dat");
        let list = GeoIpList {
            entry: vec![GeoIpEntry {
                code: "rev".into(),
                cidr: vec![GeoCidr {
                    ip: vec![10, 0, 0, 0],
                    prefix: 8,
                }],
                reverse_match: true,
            }],
        };
        std::fs::write(&path, list.encode_to_vec()).unwrap();
        let error = parse_geoip(&path, &mut Budget::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("reverse_match"), "{error}");
    }

    #[test]
    fn rejects_bad_protobuf_and_empty_data() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.dat");
        std::fs::write(&bad, b"not protobuf at all").unwrap();
        assert!(parse_geosite(&bad, &mut Budget::default()).is_err());
        let empty = dir.path().join("empty.dat");
        std::fs::write(&empty, GeoSiteList { entry: vec![] }.encode_to_vec()).unwrap();
        assert!(parse_geosite(&empty, &mut Budget::default()).is_err());
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
        let parsed = parse_rule_set(&path, &mut Budget::default()).unwrap();
        assert_eq!(
            parsed.domains,
            vec![
                DomainMatcher::Suffix("example.com".into()),
                DomainMatcher::Keyword("ads".into())
            ]
        );
        assert_eq!(parsed.ips.len(), 2);
        assert_eq!(parsed.ips[0].prefix, 24);
    }

    #[test]
    fn rejects_srs_binary_with_actionable_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.srs");
        std::fs::write(&path, b"SRS\x01\x00\x00\x00").unwrap();
        let error = parse_rule_set(&path, &mut Budget::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("source JSON"), "{error}");
    }

    #[test]
    fn geo_code_rejects_wrong_field_placement() {
        let data = GeoData::default();
        let error = expand(
            &data,
            &["geoip:cn".into()],
            &[],
            0,
            &mut ExpansionBudget::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("ip_cidrs"), "{error}");
        let error = expand(
            &data,
            &[],
            &["geosite:cn".into()],
            0,
            &mut ExpansionBudget::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("domains"), "{error}");
    }

    #[test]
    fn missing_code_is_reported_not_ignored() {
        let data = GeoData::default();
        let error = expand(
            &data,
            &["geosite:absent".into()],
            &[],
            0,
            &mut ExpansionBudget::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("geosite:absent"), "{error}");
    }

    /// 真实数据集冒烟：确认解析层能读出预期项。
    ///
    /// 数据集缺失时跳过（不静默通过）：CI 不下载数据，本地跑才有意义。
    #[test]
    fn real_geosite_parses_google_entry() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".test-artifacts/geodata/geosite.dat");
        if !path.is_file() {
            eprintln!("跳过：未下载真实数据集");
            return;
        }
        let sites = parse_geosite(&path, &mut Budget::default()).unwrap();
        let google = sites.get("google").expect("应有 GOOGLE 分类");
        // 实测该版本：GOOGLE 共 1080 项，`google.com` 是 Domain（后缀）而非 Full。
        // 这个事实决定 `www.google.com` 会命中而 `google.com` 的整域匹配来自
        // 后缀语义——两者都要在路由用例里体现。
        assert!(google.len() > 100, "GOOGLE 分类项数异常: {}", google.len());
        let suffix = google
            .iter()
            .filter(|item| matches!(item, DomainMatcher::Suffix(value) if value == "google.com"))
            .count();
        assert_eq!(suffix, 1, "google.com 应作为唯一的 Suffix 项存在");
    }

    /// 真实数据里 `geoip:cn` 必须包含集成用例依赖的地址。
    ///
    /// 这条断言把「测试假设」变成显式的：如果数据更新后不再包含
    /// 223.5.5.5，这里先失败，而不是让集成用例以「连接失败」的假象通过。
    #[test]
    fn real_geoip_contains_the_cn_sample_address() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".test-artifacts/geodata/geoip.dat");
        if !path.is_file() {
            eprintln!("跳过：未下载真实数据集");
            return;
        }
        let ips = parse_geoip(&path, &mut Budget::default()).unwrap();
        let cn = ips.get("cn").expect("应有 cn 分类");
        let sample: IpAddr = "223.5.5.5".parse().unwrap();
        assert!(
            cn.iter().any(|cidr| cidr.contains(sample)),
            "geoip:cn 未包含 223.5.5.5，集成用例的样本已失效，需重新挑选"
        );
        assert!(
            !cn.iter()
                .any(|cidr| cidr.contains("8.8.8.8".parse().unwrap()))
        );
    }

    /// IPv6 `/0` 必须匹配任意 IPv6 地址，且不能右移溢出。
    #[test]
    fn cidr_v6_zero_prefix_matches_any_v6() {
        let any: Cidr = Cidr {
            addr: "::".parse().unwrap(),
            prefix: 0,
        };
        assert!(any.contains("2001:db8::1".parse().unwrap()));
        assert!(!any.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn plain_values_are_left_alone() {
        let data = GeoData::default();
        let expanded = expand(
            &data,
            &["example.org".into(), "domain:example.net".into()],
            &[],
            0,
            &mut ExpansionBudget::default(),
        )
        .unwrap();
        assert!(expanded.domains.is_empty());
        assert!(expanded.ips.is_empty());
        assert!(expanded.mmdb_codes.is_empty());
        assert!(!expanded.domain_used && !expanded.ip_used);
    }
}
